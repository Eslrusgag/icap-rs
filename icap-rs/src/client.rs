use crate::error::IcapResult;
use crate::response::Response;
use http::{
    HeaderMap, HeaderName, HeaderValue, Request as HttpRequest, Response as HttpResponse,
    StatusCode, Version,
};
use std::fmt::Write;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct Client {
    inner: Arc<ClientRef>,
}

impl Client {
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    pub fn from_uri(uri: &str) -> IcapResult<Self> {
        Ok(ClientBuilder::new().from_uri(uri)?.build())
    }

    /// Получить «сырые» байты ICAP-запроса (для отладки/дампа)
    pub fn get_request(&self, req: &Request) -> IcapResult<Vec<u8>> {
        let built = self.build_icap_request_bytes(req)?;
        Ok(built.bytes)
    }

    /// Выполнить ICAP-запрос целиком
    pub async fn send(&self, req: &Request) -> IcapResult<Response> {
        // 1) Берём соединение (reuse если KeepAlive)
        let mut stream = match self.inner.connection_policy {
            ConnectionPolicy::KeepAlive => {
                if let Some(s) = self.inner.idle_conn.lock().await.take() {
                    s
                } else {
                    TcpStream::connect((&*self.inner.host, self.inner.port)).await?
                }
            }
            ConnectionPolicy::Close => {
                TcpStream::connect((&*self.inner.host, self.inner.port)).await?
            }
        };

        // 2) Собираем ICAP-запрос в байты
        let built = self.build_icap_request_bytes(req)?;

        // 3) Отправляем стартовую часть
        stream.write_all(&built.bytes).await?;
        stream.flush().await?;

        // 4) OPTIONS — читаем только заголовки и возвращаем
        if req.method.eq_ignore_ascii_case("OPTIONS") {
            let (_code, hdr_buf) = read_icap_headers(&mut stream).await?;
            maybe_put_back(self.inner.connection_policy, &self.inner.idle_conn, stream).await;
            return crate::parser::parse_icap_response(&hdr_buf);
        }

        // 5) REQMOD/RESPMOD: превью/100 Continue/досылка остатка
        if built.expect_continue {
            let (code, hdr_buf) = read_icap_headers(&mut stream).await?;
            if code == 100 {
                if let Some(rest) = built.remaining_body {
                    if !rest.is_empty() {
                        write_chunk(&mut stream, &rest).await?;
                    }
                    stream.write_all(b"0\r\n\r\n").await?;
                    stream.flush().await?;
                }
                // далее читаем финальный ответ
            } else {
                // уже финальный ответ (напр., 204/4xx)
                let mut response = hdr_buf;
                read_to_end(&mut stream, &mut response, self.inner.read_timeout).await?;
                maybe_put_back(self.inner.connection_policy, &self.inner.idle_conn, stream).await;
                return crate::parser::parse_icap_response(&response);
            }
        }

        // 6) Финальный ответ
        let mut response = Vec::new();
        read_to_end(&mut stream, &mut response, self.inner.read_timeout).await?;
        maybe_put_back(self.inner.connection_policy, &self.inner.idle_conn, stream).await;

        if response.is_empty() {
            return Err("No response received from server".into());
        }
        crate::parser::parse_icap_response(&response)
    }

    fn build_icap_request_bytes(&self, req: &Request) -> IcapResult<BuiltIcap> {
        let mut out = Vec::new();

        // Стартовая строка ICAP
        let full_uri = format!(
            "icap://{}:{}/{}",
            self.inner.host,
            self.inner.port,
            trim_leading_slash(&req.service)
        );
        out.extend_from_slice(format!("{} {} ICAP/1.0\r\n", req.method, full_uri).as_bytes());

        // ── ICAP headers: default + per-request ────────────────────────────────
        let mut headers = self.inner.default_headers.clone();

        // Host (обязателен)
        let host_value = self
            .inner
            .host_override
            .clone()
            .unwrap_or_else(|| self.inner.host.clone());
        headers.insert(
            HeaderName::from_static("host"),
            HeaderValue::from_str(&host_value).unwrap(),
        );

        // Трассировка (опционально)
        if !headers.contains_key("x-icap-url") {
            headers.insert(
                HeaderName::from_static("x-icap-url"),
                HeaderValue::from_str(&full_uri).unwrap(),
            );
        }

        // Приоритет заголовков запроса над дефолтными
        for (name, value) in req.icap_headers.iter() {
            headers.insert(name.clone(), value.clone());
        }

        // Allow/Connection/Preview только для REQMOD/RESPMOD
        if req.is_mod() {
            if req.allow_204 && !headers.contains_key("allow") {
                headers.insert(
                    HeaderName::from_static("allow"),
                    HeaderValue::from_static("204"),
                );
            }
            if req.allow_206 {
                append_to_allow(&mut headers, "206");
            }
            if !headers.contains_key("connection") {
                headers.insert(
                    HeaderName::from_static("connection"),
                    HeaderValue::from_static("close"),
                );
            }
        }

        if let Some(ps) = req.preview_size {
            headers.insert(
                HeaderName::from_static("preview"),
                HeaderValue::from_str(&ps.to_string()).unwrap(),
            );
        }

        // ── Encapsulated ───────────────────────────────────────────────────────
        let (http_headers_bytes, http_body_bytes, enc_header) = if req.is_mod() {
            if let Some(ref emb) = req.embedded {
                let (hdrs, body) = serialize_embedded_http(emb);
                let (hdr_key, body_key) = match req.method.as_str() {
                    "REQMOD" => ("req-hdr", "req-body"),
                    _ => ("res-hdr", "res-body"),
                };
                if body.is_some() {
                    let enc = format!(
                        "Encapsulated: {}=0, {}={}\r\n",
                        hdr_key,
                        body_key,
                        hdrs.len()
                    );
                    (hdrs, body, enc)
                } else {
                    let enc = format!("Encapsulated: {}=0\r\n", hdr_key);
                    (hdrs, None, enc)
                }
            } else {
                (
                    Vec::new(),
                    None,
                    "Encapsulated: null-body=0\r\n".to_string(),
                )
            }
        } else {
            (
                Vec::new(),
                None,
                "Encapsulated: null-body=0\r\n".to_string(),
            )
        };

        out.extend_from_slice(enc_header.as_bytes());

        // Сериализация ICAP-заголовков
        for (name, value) in headers.iter() {
            out.extend_from_slice(name.as_str().as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");

        // Вложенные HTTP-заголовки (если есть)
        if !http_headers_bytes.is_empty() {
            out.extend_from_slice(&http_headers_bytes);
        }

        // Превью/тело для REQMOD/RESPMOD
        if req.is_mod()
            && let Some(body) = http_body_bytes
        {
            let (bytes, expect_continue, remaining) =
                build_preview_and_chunks(req.preview_size, body)?;
            out.extend_from_slice(&bytes);
            return Ok(BuiltIcap {
                bytes: out,
                expect_continue,
                remaining_body: remaining,
            });
        }

        Ok(BuiltIcap {
            bytes: out,
            expect_continue: false,
            remaining_body: None,
        })
    }
}

#[derive(Debug)]
struct ClientRef {
    host: String,
    port: u16,
    host_override: Option<String>,
    default_headers: HeaderMap, // ICAP default headers (не HTTP!)
    connection_policy: ConnectionPolicy,
    read_timeout: Option<Duration>,
    // Простейший keep-alive: одно «горячее» соединение на хост:порт
    idle_conn: Mutex<Option<TcpStream>>,
}

#[derive(Debug, Clone, Copy, Default)]
pub enum ConnectionPolicy {
    #[default]
    Close,
    KeepAlive,
}

/// Вернуть соединение в idle, если включён keep-alive
async fn maybe_put_back(
    policy: ConnectionPolicy,
    slot: &Mutex<Option<TcpStream>>,
    stream: TcpStream,
) {
    if let ConnectionPolicy::KeepAlive = policy
        && stream.peer_addr().is_ok()
    {
        *slot.lock().await = Some(stream);
    }
}

#[derive(Debug, Default)]
pub struct ClientBuilder {
    host: Option<String>,
    port: Option<u16>,
    host_override: Option<String>,
    default_headers: HeaderMap, // ICAP default headers
    connection_policy: ConnectionPolicy,
    read_timeout: Option<Duration>,
}

impl ClientBuilder {
    pub fn new() -> Self {
        let mut b = Self::default();
        b.connection_policy = ConnectionPolicy::Close;
        b.default_headers.insert(
            HeaderName::from_static("user-agent"),
            HeaderValue::from_static("rs-icap-client/0.1.0"),
        );
        b
    }

    pub fn host(mut self, host: &str) -> Self {
        self.host = Some(host.to_string());
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Переопределяет ICAP `Host` заголовок (адрес TCP остаётся как в host/port)
    pub fn host_override(mut self, host: &str) -> Self {
        self.host_override = Some(host.to_string());
        self
    }

    /// Добавляет дефолтный ICAP заголовок (upsert)
    pub fn default_header(mut self, name: &str, value: &str) -> Self {
        let n: HeaderName = name.parse().expect("invalid header name");
        let v: HeaderValue = HeaderValue::from_str(value).expect("invalid header value");
        self.default_headers.insert(n, v);
        self
    }

    /// Включить/выключить keep-alive (переиспользование одного соединения)
    pub fn keep_alive(mut self, yes: bool) -> Self {
        self.connection_policy = if yes {
            ConnectionPolicy::KeepAlive
        } else {
            ConnectionPolicy::Close
        };
        self
    }

    pub fn read_timeout(mut self, dur: Option<Duration>) -> Self {
        self.read_timeout = dur;
        self
    }

    /// Ускоренный конструктор из URI вида icap://host[:port]
    pub fn from_uri(mut self, uri: &str) -> IcapResult<Self> {
        let (host, port) = parse_authority(uri)?;
        self.host = Some(host);
        self.port = Some(port);
        Ok(self)
    }

    pub fn build(self) -> Client {
        let host = self.host.expect("ClientBuilder: host is required");
        let port = self.port.unwrap_or(1344);

        let inner = ClientRef {
            host,
            port,
            host_override: self.host_override,
            default_headers: self.default_headers,
            connection_policy: self.connection_policy,
            read_timeout: self.read_timeout,
            idle_conn: Mutex::new(None), // runtime-состояние создаётся при build()
        };
        Client {
            inner: Arc::new(inner),
        }
    }
}

/// ─────────────────────────────────────────────────────────────────────────────
/// Вложенный HTTP: запрос или ответ
/// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub enum EmbeddedHttp {
    Req(HttpRequest<Vec<u8>>),
    Resp(HttpResponse<Vec<u8>>),
}

/// Описание ICAP-запроса (внешний API)
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,                 // "OPTIONS" | "REQMOD" | "RESPMOD"
    pub service: String,                // "/reqmod" | "/respmod" | ...
    pub icap_headers: HeaderMap,        // ICAP-заголовки
    pub embedded: Option<EmbeddedHttp>, // вложенный HTTP
    pub preview_size: Option<usize>,    // Preview: n
    pub allow_204: bool,
    pub allow_206: bool,
}

impl Request {
    pub fn new(method: &str, service: &str) -> Self {
        Self {
            method: method.to_string(),
            service: service.to_string(),
            icap_headers: HeaderMap::new(),
            embedded: None,
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

    pub fn icap_header(mut self, name: &str, value: &str) -> Self {
        let n: HeaderName = name.parse().expect("invalid ICAP header name");
        let v: HeaderValue = HeaderValue::from_str(value).expect("invalid ICAP header value");
        self.icap_headers.insert(n, v);
        self
    }

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

    pub fn with_http_request(mut self, req: HttpRequest<Vec<u8>>) -> Self {
        self.embedded = Some(EmbeddedHttp::Req(req));
        self
    }

    pub fn with_http_response(mut self, resp: HttpResponse<Vec<u8>>) -> Self {
        self.embedded = Some(EmbeddedHttp::Resp(resp));
        self
    }
}

#[derive(Debug, Clone)]
struct BuiltIcap {
    bytes: Vec<u8>,
    expect_continue: bool,
    remaining_body: Option<Vec<u8>>,
}

fn serialize_embedded_http(e: &EmbeddedHttp) -> (Vec<u8>, Option<Vec<u8>>) {
    match e {
        EmbeddedHttp::Req(r) => split_http_bytes(&serialize_http_request(r)),
        EmbeddedHttp::Resp(r) => split_http_bytes(&serialize_http_response(r)),
    }
}

fn split_http_bytes(raw: &[u8]) -> (Vec<u8>, Option<Vec<u8>>) {
    if let Some(hdr_end) = raw.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4) {
        let headers = raw[..hdr_end].to_vec();
        if hdr_end < raw.len() {
            (headers, Some(raw[hdr_end..].to_vec()))
        } else {
            (headers, None)
        }
    } else {
        (raw.to_vec(), None)
    }
}

fn http_version_str(v: Version) -> &'static str {
    match v {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    }
}

fn serialize_http_request(req: &HttpRequest<Vec<u8>>) -> Vec<u8> {
    let mut out = String::new();

    // Request-Line
    write!(
        out,
        "{} {} {}\r\n",
        req.method(),
        req.uri(),
        http_version_str(req.version())
    )
    .unwrap();

    for (name, value) in req.headers().iter() {
        write!(out, "{}: ", name.as_str()).unwrap();
        out.push_str(value.to_str().unwrap_or_default());
        out.push_str("\r\n");
    }
    out.push_str("\r\n");

    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(req.body());
    bytes
}

fn serialize_http_response(resp: &HttpResponse<Vec<u8>>) -> Vec<u8> {
    let mut out = String::new();
    let code: StatusCode = resp.status();

    // Status-Line
    write!(
        out,
        "{} {} {}\r\n",
        http_version_str(resp.version()),
        code.as_u16(),
        code.canonical_reason().unwrap_or("")
    )
    .unwrap();

    for (name, value) in resp.headers().iter() {
        write!(out, "{}: ", name.as_str()).unwrap();
        out.push_str(value.to_str().unwrap_or_default());
        out.push_str("\r\n");
    }
    out.push_str("\r\n");

    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(resp.body());
    bytes
}

/// ICAP превью/чанки
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
                out.extend_from_slice(b"0; ieof\r\n\r\n");
                Ok((out, false, None))
            } else {
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

fn write_chunk_into(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(format!("{:X}\r\n", data.len()).as_bytes());
    if !data.is_empty() {
        out.extend_from_slice(data);
    }
    out.extend_from_slice(b"\r\n");
}

async fn read_icap_headers(stream: &mut TcpStream) -> IcapResult<(u16, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(_idx) = find_double_crlf(&buf) {
            let line_end = buf
                .windows(2)
                .position(|w| w == b"\r\n")
                .unwrap_or(buf.len());
            let status_line = &buf[..line_end];
            let code = parse_status_code(status_line).ok_or("Failed to parse ICAP status code")?;
            return Ok((code, buf));
        }
    }
    Err("Unexpected EOF while reading ICAP headers".into())
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_status_code(line: &[u8]) -> Option<u16> {
    let s = std::str::from_utf8(line).ok()?;
    let mut parts = s.split_whitespace();
    let _ver = parts.next()?; // "ICAP/1.0"
    let code_str = parts.next()?; // "100"
    code_str.parse::<u16>().ok()
}

async fn read_to_end(
    stream: &mut TcpStream,
    out: &mut Vec<u8>,
    _timeout: Option<Duration>,
) -> IcapResult<()> {
    // TODO: если нужен жёсткий таймаут чтения — обернуть в tokio::time::timeout
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

/// ─────────────────────────────────────────────────────────────────────────────
/// Утилиты
/// ─────────────────────────────────────────────────────────────────────────────
fn trim_leading_slash(s: &str) -> &str {
    s.strip_prefix('/').unwrap_or(s)
}

fn parse_authority(uri: &str) -> IcapResult<(String, u16)> {
    let s = uri.trim();
    let rest = s
        .strip_prefix("icap://")
        .ok_or("Authority URI must start with icap://")?;
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

fn append_to_allow(headers: &mut HeaderMap, code: &str) {
    let name = HeaderName::from_static("allow");
    match headers.get_mut(&name) {
        Some(v) => {
            let mut s = v.to_str().unwrap_or("").to_string();
            if !s.split(',').any(|p| p.trim() == code) {
                if !s.is_empty() {
                    s.push_str(", ");
                }
                s.push_str(code);
                *v = HeaderValue::from_str(&s).unwrap();
            }
        }
        None => {
            headers.insert(name, HeaderValue::from_str(code).unwrap());
        }
    }
}
