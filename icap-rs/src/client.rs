use crate::HttpMessageTrait;
use crate::error::IcapResult;
use crate::http::HttpMessage;
use crate::response::Response;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
pub struct Client {
    host: String,
    port: u16,
    host_override: Option<String>,
    default_headers: Vec<(String, String)>,
}

impl Client {
    /// Создать клиента по host/port
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.to_string(),
            port,
            host_override: None,
            default_headers: vec![("User-Agent".into(), "rs-icap-client/0.1.0".into())],
        }
    }

    /// Создать клиента из icap://host[:port] (без service)
    pub fn from_uri(uri: &str) -> IcapResult<Self> {
        let (host, port) = parse_authority(uri)?;
        Ok(Self {
            host,
            port,
            host_override: None,
            default_headers: vec![("User-Agent".into(), "rs-icap-client/0.1.0".into())],
        })
    }

    /// Переопределить значение заголовка ICAP `Host` (TCP-адрес не меняем)
    pub fn host_override(mut self, host: &str) -> Self {
        self.host_override = Some(host.to_string());
        self
    }

    /// Добавить дефолтный ICAP-заголовок (для всех запросов)
    pub fn default_header(mut self, name: &str, value: &str) -> Self {
        self.default_headers
            .push((name.to_string(), value.to_string()));
        self
    }

    /// Получить «сырые» байты ICAP-запроса с превью (без досылки остатка)
    /// Полезно для отладки/дампа.
    pub fn get_request(&self, req: &Request) -> IcapResult<Vec<u8>> {
        let built = self.build_icap_request_bytes(req)?;
        Ok(built.bytes)
    }

    /// Выполнить ICAP-запрос целиком (с обработкой 100 Continue и досылкой)
    pub async fn send(&self, req: &Request) -> IcapResult<Response> {
        // Сборка стартового ICAP-запроса (заголовки + encapsulated HTTP headers + превью-чанки)
        let built = self.build_icap_request_bytes(req)?;

        // Подключаемся
        let addr = format!("{}:{}", self.host, self.port);
        let mut stream = TcpStream::connect(&addr).await?;

        // Отправляем стартовую часть
        stream.write_all(&built.bytes).await?;
        stream.flush().await?;

        // ─────────────────────────────────────────────────────────────────────────
        // OPTIONS: читаем только заголовки и возвращаем ответ (без ожидания EOF),
        // чтобы не зависать на keep-alive.
        // ─────────────────────────────────────────────────────────────────────────
        if req.method.eq_ignore_ascii_case("OPTIONS") {
            let (_code, hdr_buf) = read_icap_headers(&mut stream).await?;
            return crate::parser::parse_icap_response(&hdr_buf);
        }

        // ─────────────────────────────────────────────────────────────────────────
        // REQMOD / RESPMOD:
        // Если отправляли превью без IEoF — ждём промежуточный 100 Continue.
        // Если вместо 100 пришёл финальный ответ (200/204/4xx/5xx) — дочитываем до EOF.
        // Если пришёл 100 — досылаем остаток и затем читаем финальный ответ до EOF.
        // ─────────────────────────────────────────────────────────────────────────
        if built.expect_continue {
            // Ждём промежуточные заголовки (обычно 100 Continue)
            let (code, hdr_buf) = read_icap_headers(&mut stream).await?;
            if code == 100 {
                // Сервер просит остаток тела
                if let Some(rest) = built.remaining_body {
                    if !rest.is_empty() {
                        // Досылаем остаток единым чанком
                        write_chunk(&mut stream, &rest).await?;
                    }
                    // Закрываем поток чанков
                    stream.write_all(b"0\r\n\r\n").await?;
                    stream.flush().await?;
                }
                // Падаем ниже — читать финальный ответ целиком
            } else {
                // Это уже финальный ответ (например, 204/4xx). Добавляем уже прочитанные заголовки.
                let mut response = hdr_buf;
                // Дочитываем оставшееся (если сервер закроет соединение)
                read_to_end(&mut stream, &mut response).await?;
                return crate::parser::parse_icap_response(&response);
            }
        }

        // Финальный ответ (после 100 Continue или когда превью было с IEoF/без превью)
        let mut response = Vec::new();
        read_to_end(&mut stream, &mut response).await?;
        if response.is_empty() {
            return Err("No response received from server".into());
        }
        crate::parser::parse_icap_response(&response)
    }

    /// Построить ICAP-запрос. Возвращает:
    /// - bytes: стартовая часть + encapsulated HTTP headers + превью-чанки (+ закрытие превью)
    /// - expect_continue: нужно ли ждать `100 Continue`
    /// - remaining_body: остаток тела для досылки после `100 Continue`
    fn build_icap_request_bytes(&self, req: &Request) -> IcapResult<BuiltIcap> {
        let mut out = Vec::new();

        let full_uri = format!(
            "icap://{}:{}/{}",
            self.host,
            self.port,
            trim_leading_slash(&req.service)
        );
        out.extend_from_slice(format!("{} {} ICAP/1.0\r\n", req.method, full_uri).as_bytes());

        // Собираем заголовки
        let mut headers = Vec::<(String, String)>::new();
        headers.extend(self.default_headers.iter().cloned());
        headers.extend(req.icap_headers.iter().cloned()); // см. Request::header — он не добавит дублирующий Preview

        // Host
        let host_header_value = self
            .host_override
            .clone()
            .unwrap_or_else(|| self.host.clone());
        upsert_header(&mut headers, "Host", &host_header_value);

        // Полезный служебный (для трассировки)
        if !contains_header(&headers, "x-icap-url") {
            headers.push(("x-icap-url".into(), full_uri.clone()));
        }

        // Allow / Connection — только для REQMOD/RESPMOD
        // Allow — только для REQMOD/RESPMOD
        if req.is_mod() {
            if req.allow_204 && !contains_header(&headers, "Allow") {
                headers.push(("Allow".into(), "204".into()));
            }
            if req.allow_206 {
                append_to_allow(&mut headers, "206");
            }
        }

        // ToDo убрать это но надо подумать как лучше сделать
        if !contains_header(&headers, "Connection") {
            headers.push(("Connection".into(), "close".into()));
        }

        // Готовим вложенный HTTP
        let http_raw = req.http.as_ref().map(|m| m.to_raw());
        let (http_headers_bytes, http_body_bytes) = split_http(&http_raw);

        // Проставим Preview только на основе Request::preview_size
        if let Some(ps) = req.preview_size {
            headers.push(("Preview".into(), ps.to_string()));
        }

        // Encapsulated
        if req.is_mod() {
            if let Some(_) = http_raw {
                let (hdr_key, body_key) = if req.method == "REQMOD" {
                    ("req-hdr", "req-body")
                } else {
                    ("res-hdr", "res-body")
                };
                if http_body_bytes.is_some() {
                    out.extend_from_slice(
                        format!(
                            "Encapsulated: {}=0, {}={}\r\n",
                            hdr_key,
                            body_key,
                            http_headers_bytes.len()
                        )
                        .as_bytes(),
                    );
                } else {
                    out.extend_from_slice(format!("Encapsulated: {}=0\r\n", hdr_key).as_bytes());
                }
            } else {
                out.extend_from_slice(b"Encapsulated: null-body=0\r\n");
            }
        }

        // Сериализация ICAP-заголовков
        for (k, v) in &headers {
            out.extend_from_slice(format!("{}: {}\r\n", k, v).as_bytes());
        }

        // Конец ICAP заголовков
        out.extend_from_slice(b"\r\n");

        // Вложенные HTTP-заголовки (если есть)
        if !http_headers_bytes.is_empty() {
            out.extend_from_slice(&http_headers_bytes);
        }

        // Далее — превью-чанки/тело (только для REQMOD/RESPMOD и когда есть body)
        if req.is_mod() {
            // Если тела нет — ничего не шлём (даже нулевой чанк не обязателен при null-body)
            if let Some(body) = http_body_bytes {
                let (bytes, expect_continue, remaining) =
                    build_preview_and_chunks(req.preview_size, body)?;

                out.extend_from_slice(&bytes);
                return Ok(BuiltIcap {
                    bytes: out,
                    expect_continue,
                    remaining_body: remaining,
                });
            }
        }

        // По умолчанию — ничего досылать не надо
        Ok(BuiltIcap {
            bytes: out,
            expect_continue: false,
            remaining_body: None,
        })
    }
}

/// Построенный ICAP-запрос и метаданные для диалога
#[derive(Debug, Clone)]
struct BuiltIcap {
    /// Стартовая часть запроса: ICAP заголовки + HTTP-заголовки + превью-чанки (+ закрытие превью)
    bytes: Vec<u8>,
    /// Нужно ли ждать 100 Continue
    expect_continue: bool,
    /// Остаток тела для досылки после 100 Continue
    remaining_body: Option<Vec<u8>>,
}

/// Описание ICAP-запроса (семантика — тут)
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,  // "OPTIONS" | "REQMOD" | "RESPMOD"
    pub service: String, // "/reqmod", "/respmod" или другой путь
    pub icap_headers: Vec<(String, String)>,
    pub http: Option<HttpMessage>,   // вложенное HTTP
    pub preview_size: Option<usize>, // если Some(n) — включаем Preview: n
    pub allow_204: bool,
    pub allow_206: bool,
}

impl Request {
    pub fn new(method: &str, service: &str) -> Self {
        Self {
            method: method.to_string(),
            service: service.to_string(),
            icap_headers: Vec::new(),
            http: None,
            preview_size: None,
            allow_204: false,
            allow_206: false,
        }
    }

    #[inline]
    fn is_mod(&self) -> bool {
        self.method == "REQMOD" || self.method == "RESPMOD"
    }

    pub fn options(service: &str) -> Self {
        Self::new("OPTIONS", service)
    }
    pub fn reqmod(service: &str) -> Self {
        Self::new("REQMOD", service)
    }
    pub fn respmod(service: &str) -> Self {
        Self::new("RESPMOD", service)
    }

    /// Добавить ICAP-заголовок. Если это `Preview`, он будет мапплен в `preview_size`.
    /// Последний вызов имеет приоритет.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        if name.eq_ignore_ascii_case("Preview") {
            if let Ok(n) = value.trim().parse::<usize>() {
                self.preview_size = Some(n);
                return self;
            }
            // Невалидное значение — сохраняем как обычный заголовок (или можно проигнорировать)
        }
        self.icap_headers
            .push((name.to_string(), value.to_string()));
        self
    }

    pub fn http(mut self, msg: HttpMessage) -> Self {
        self.http = Some(msg);
        self
    }

    /// Настроить размер превью (в байтах)
    pub fn preview(mut self, n: usize) -> Self {
        self.preview_size = Some(n);
        self
    }

    pub fn allow_204(mut self, yes: bool) -> Self {
        self.allow_204 = yes;
        self
    }

    pub fn allow_206(mut self, yes: bool) -> Self {
        self.allow_206 = yes;
        self
    }
}

fn parse_authority(uri: &str) -> IcapResult<(String, u16)> {
    let s = uri.trim();
    let rest = s
        .strip_prefix("icap://")
        .ok_or("Authority URI must start with icap://")?;
    // допускаем и с /..., отрежем путь если есть
    let authority = rest.split('/').next().unwrap_or(rest);
    let (host, port) = if let Some(i) = authority.rfind(':') {
        let h = &authority[..i];
        let p: u16 = authority[i + 1..].parse().map_err(|_| "Invalid port")?;
        (h.to_string(), p)
    } else {
        (authority.to_string(), 1344)
    };
    if host.is_empty() {
        return Err("Empty host in authority".into());
    }
    Ok((host, port))
}

fn contains_header(headers: &[(String, String)], name_lc: &str) -> bool {
    headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name_lc))
}

fn upsert_header(headers: &mut Vec<(String, String)>, name: &str, value: &str) {
    if let Some((_, v)) = headers
        .iter_mut()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
    {
        *v = value.to_string();
    } else {
        headers.push((name.to_string(), value.to_string()));
    }
}

fn append_to_allow(headers: &mut Vec<(String, String)>, code: &str) {
    if let Some((_, v)) = headers
        .iter_mut()
        .find(|(k, _)| k.eq_ignore_ascii_case("Allow"))
    {
        if !v.split(',').any(|p| p.trim() == code) {
            v.push_str(", ");
            v.push_str(code);
        }
    } else {
        headers.push(("Allow".into(), code.into()));
    }
}

fn trim_leading_slash(s: &str) -> &str {
    s.strip_prefix('/').unwrap_or(s)
}

/// Разделить «сырой» HTTP (headers + body). Возвращает (headers_bytes, Some(body_bytes)).
/// Если тела нет — body = None. Если http_raw == None — вернёт ([], None).
fn split_http(http_raw: &Option<Vec<u8>>) -> (Vec<u8>, Option<Vec<u8>>) {
    if let Some(raw) = http_raw {
        if let Some(hdr_end) = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|pos| pos + 4)
        {
            let headers = raw[..hdr_end].to_vec();
            if hdr_end < raw.len() {
                let body = raw[hdr_end..].to_vec();
                (headers, Some(body))
            } else {
                (headers, None)
            }
        } else {
            // Нет \r\n\r\n — считаем, что это только заголовки (или сломанный HTTP)
            (raw.clone(), None)
        }
    } else {
        (Vec::new(), None)
    }
}

/// Сформировать превью-чанки и определить необходимость 100 Continue.
/// Возвращает (bytes, expect_continue, remaining_body)
fn build_preview_and_chunks(
    preview_size: Option<usize>,
    body: Vec<u8>,
) -> IcapResult<(Vec<u8>, bool, Option<Vec<u8>>)> {
    let mut out = Vec::new();
    match preview_size {
        None => {
            if !body.is_empty() {
                write_chunk_into(&mut out, &body);
            }
            out.extend_from_slice(b"0\r\n\r\n");
            Ok((out, false, None))
        }
        Some(ps) if ps == 0 => {
            if body.is_empty() {
                // весь «месседж» умещается в превью 0 → IEoF
                out.extend_from_slice(b"0; ieof\r\n\r\n");
                Ok((out, false, None))
            } else {
                // только заголовки как превью → ждём 100
                out.extend_from_slice(b"0\r\n\r\n");
                Ok((out, true, Some(body)))
            }
        }
        Some(ps) => {
            let send_n = body.len().min(ps);
            if send_n > 0 {
                write_chunk_into(&mut out, &body[..send_n]);
            }
            let rest = body.len().saturating_sub(send_n);
            if rest == 0 {
                out.extend_from_slice(b"0; ieof\r\n\r\n");
                Ok((out, false, None))
            } else {
                out.extend_from_slice(b"0\r\n\r\n");
                Ok((out, true, Some(body[send_n..].to_vec())))
            }
        }
    }
}

/// Записать один chunk в поток
async fn write_chunk(stream: &mut TcpStream, data: &[u8]) -> IcapResult<()> {
    stream
        .write_all(format!("{:X}\r\n", data.len()).as_bytes())
        .await?;
    if !data.is_empty() {
        stream.write_all(data).await?;
    }
    stream.write_all(b"\r\n").await?;
    Ok(())
}

/// Записать один chunk в вектор
fn write_chunk_into(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(format!("{:X}\r\n", data.len()).as_bytes());
    if !data.is_empty() {
        out.extend_from_slice(data);
    }
    out.extend_from_slice(b"\r\n");
}

/// Прочитать ICAP-заголовки (до \r\n\r\n) и вернуть (status_code, буфер_с_заголовками)
async fn read_icap_headers(stream: &mut TcpStream) -> IcapResult<(u16, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(idx) = find_double_crlf(&buf) {
            // Разбираем статус-линию
            let line_end = buf
                .windows(2)
                .position(|w| w == b"\r\n")
                .unwrap_or(buf.len());
            let status_line = &buf[..line_end];
            let code = parse_status_code(status_line).ok_or("Failed to parse ICAP status code")?;
            // Отрезать лишнее не обязательно — пусть вызывающий решает, что делать с буфером.
            // Здесь возвращаем всё, что накопили (включая, возможно, начало тела/следующих данных).
            return Ok((code, buf));
        }
    }
    Err("Unexpected EOF while reading ICAP headers".into())
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_status_code(line: &[u8]) -> Option<u16> {
    // Ожидаем "ICAP/1.0 100 Continue" или подобное
    let s = std::str::from_utf8(line).ok()?;
    let mut parts = s.split_whitespace();
    let _ver = parts.next()?; // "ICAP/1.0"
    let code_str = parts.next()?; // "100"
    code_str.parse::<u16>().ok()
}

/// Дочитать поток до EOF в буфер
async fn read_to_end(stream: &mut TcpStream, out: &mut Vec<u8>) -> IcapResult<()> {
    let mut buf = [0u8; 8192];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(())
}
