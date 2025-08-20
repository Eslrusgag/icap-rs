//! ICAP Client implementation in Rust.
//!
//! Features:
//! - Client with builder (`ClientBuilder`).
//! - ICAP requests: OPTIONS, REQMOD, RESPMOD.
//! - Embedded HTTP requests/responses (serialize on wire).
//! - ICAP Preview (including `ieof`) and streaming upload.
//! - Keep-Alive reuse of a single idle connection.
//! - Encapsulated header calculation and chunked bodies.
use crate::error::IcapResult;
use crate::parser;
use crate::response::Response;

use crate::parser::http_version_str;
use crate::request::{EmbeddedHttp, Request};
use http::{
    HeaderMap, HeaderName, HeaderValue, Request as HttpRequest, Response as HttpResponse,
    StatusCode,
};
use std::fmt::Write as FmtWrite;
use std::io::Write as IoWrite;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::File as TokioFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, trace};

#[derive(Debug, Clone)]
pub struct Client {
    inner: Arc<ClientRef>,
}

#[derive(Debug)]
struct ClientRef {
    host: String,
    port: u16,
    host_override: Option<String>,
    default_headers: HeaderMap,
    connection_policy: ConnectionPolicy,
    read_timeout: Option<Duration>,
    idle_conn: Mutex<Option<TcpStream>>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub enum ConnectionPolicy {
    #[default]
    Close,
    KeepAlive,
}

#[derive(Debug)]
pub struct ClientBuilder {
    host: Option<String>,
    port: Option<u16>,
    host_override: Option<String>,
    default_headers: HeaderMap,
    connection_policy: ConnectionPolicy,
    read_timeout: Option<Duration>,
}

impl ClientBuilder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn host(mut self, host: &str) -> Self {
        self.host = Some(host.to_string());
        self
    }
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }
    pub fn host_override(mut self, host: &str) -> Self {
        self.host_override = Some(host.to_string());
        self
    }
    pub fn default_header(mut self, name: &str, value: &str) -> Self {
        let n: HeaderName = name.parse().expect("invalid header name");
        let v: HeaderValue = HeaderValue::from_str(value).expect("invalid header value");
        self.default_headers.insert(n, v);
        self
    }
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
    pub fn from_uri(mut self, uri: &str) -> IcapResult<Self> {
        let (host, port) = parse_authority(uri)?;
        self.host = Some(host);
        self.port = Some(port);
        Ok(self)
    }
    pub fn build(self) -> Client {
        let host = self.host.expect("ClientBuilder: host is required");
        let port = self.port.unwrap_or(1344);
        let mut default_headers = self.default_headers;
        //ToDo set version on CARGO_PKG
        if !default_headers.contains_key("user-agent") {
            default_headers.insert(
                HeaderName::from_static("user-agent"),
                HeaderValue::from_static("rs-icap-client/0.1.0"),
            );
        }
        Client {
            inner: Arc::new(ClientRef {
                host,
                port,
                host_override: self.host_override,
                default_headers,
                connection_policy: self.connection_policy,
                read_timeout: self.read_timeout,
                idle_conn: Mutex::new(None),
            }),
        }
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        let mut b = Self {
            host: None,
            port: None,
            host_override: None,
            default_headers: HeaderMap::new(),
            connection_policy: ConnectionPolicy::Close,
            read_timeout: None,
        };
        b.default_headers.insert(
            HeaderName::from_static("user-agent"),
            HeaderValue::from_static("rs-icap-client/0.1.0"),
        );
        b
    }
}

impl Client {
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    /// Returns raw ICAP request bytes (for debugging).
    pub fn get_request(&self, req: &Request) -> IcapResult<Vec<u8>> {
        let built = self.build_icap_request_bytes(req, false, req.preview_ieof)?;
        Ok(built.bytes)
    }

    /// Send an ICAP request with full in-memory body (embedded HTTP).
    pub async fn send(&self, req: &Request) -> IcapResult<Response> {
        trace!(
            "client.send: method={}, service={}",
            req.method, req.service
        );

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

        let built = self.build_icap_request_bytes(req, false, req.preview_ieof)?;
        stream.write_all(&built.bytes).await?;
        stream.flush().await?;

        // OPTIONS is always final (no preview/body)
        if req.method.eq_ignore_ascii_case("OPTIONS") {
            let (_code, mut buf) = read_icap_headers(&mut stream).await?;
            read_icap_body_if_any(&mut stream, &mut buf).await?;
            maybe_put_back(self.inner.connection_policy, &self.inner.idle_conn, stream).await;
            return parser::parse_icap_response(&buf);
        }

        // Handle 100-Continue for Preview
        if built.expect_continue {
            let (code, hdr_buf) = read_icap_headers(&mut stream).await?;
            if code == 100 {
                if let Some(rest) = built.remaining_body
                    && !rest.is_empty()
                {
                    write_chunk(&mut stream, &rest).await?;
                }
                stream.write_all(b"0\r\n\r\n").await?;
                stream.flush().await?;

                let (_code2, mut response) = read_icap_headers(&mut stream).await?;
                read_icap_body_if_any(&mut stream, &mut response).await?;
                maybe_put_back(self.inner.connection_policy, &self.inner.idle_conn, stream).await;
                return parser::parse_icap_response(&response);
            } else {
                // server decided final without continue (e.g., 204)
                let mut response = hdr_buf;
                read_icap_body_if_any(&mut stream, &mut response).await?;
                maybe_put_back(self.inner.connection_policy, &self.inner.idle_conn, stream).await;
                return parser::parse_icap_response(&response);
            }
        }

        // No preview — read final
        let (_code, mut response) = read_icap_headers(&mut stream).await?;
        read_icap_body_if_any(&mut stream, &mut response).await?;
        maybe_put_back(self.inner.connection_policy, &self.inner.idle_conn, stream).await;
        parser::parse_icap_response(&response)
    }

    /// Send ICAP request with streaming body (file → chunks after 100 Continue).
    pub async fn send_streaming<P: AsRef<Path>>(
        &self,
        req: &Request,
        file_path: P,
    ) -> IcapResult<Response> {
        trace!(
            "client.send_streaming: method={} service={} file={:?}",
            req.method,
            req.service,
            file_path.as_ref()
        );

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

        // force_has_body=true (body will be streamed), preview0_ieof=false (classic)
        let built = self.build_icap_request_bytes(req, true, false)?;
        stream.write_all(&built.bytes).await?;
        stream.flush().await?;

        // If Preview:0 — close preview immediately, otherwise server may hang waiting.
        if matches!(req.preview_size, Some(0)) {
            if req.preview_ieof {
                stream.write_all(b"0; ieof\r\n\r\n").await?;
            } else {
                stream.write_all(b"0\r\n\r\n").await?;
            }
            stream.flush().await?;
        }

        let (code, hdr_buf) = read_icap_headers(&mut stream).await?;
        if code == 100 {
            let mut f = TokioFile::open(file_path).await?;
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = f.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                write_chunk(&mut stream, &buf[..n]).await?;
            }
            stream.write_all(b"0\r\n\r\n").await?;
            stream.flush().await?;

            let (_code2, mut response) = read_icap_headers(&mut stream).await?;
            read_icap_body_if_any(&mut stream, &mut response).await?;
            maybe_put_back(self.inner.connection_policy, &self.inner.idle_conn, stream).await;
            parser::parse_icap_response(&response)
        } else {
            // final immediately (e.g., 204)
            let mut response = hdr_buf;
            read_icap_body_if_any(&mut stream, &mut response).await?;
            maybe_put_back(self.inner.connection_policy, &self.inner.idle_conn, stream).await;
            parser::parse_icap_response(&response)
        }
    }

    /// Build ICAP request as it would appear on the wire.
    /// If `streaming=true` or `Preview:0`, Encapsulated contains `*-body`
    /// and a leading zero-chunk is appended to close the preview.
    pub fn get_request_wire(&self, req: &Request, streaming: bool) -> IcapResult<Vec<u8>> {
        let built = self.build_icap_request_bytes(
            req,
            streaming || matches!(req.preview_size, Some(0)),
            req.preview_ieof,
        )?;
        let mut out = built.bytes;
        if req.is_mod() && matches!(req.preview_size, Some(0)) {
            if req.preview_ieof {
                out.extend_from_slice(b"0; ieof\r\n\r\n");
            } else {
                out.extend_from_slice(b"0\r\n\r\n");
            }
        }
        Ok(out)
    }

    /// Build ICAP request bytes (headers + embedded HTTP + initial preview/chunks).
    ///
    /// - `force_has_body=true` → Encapsulated will contain `*-body` even if body is currently empty.
    /// - `preview0_ieof=true` → when `Preview: 0`, use `0; ieof` (fast-204 hint).
    fn build_icap_request_bytes(
        &self,
        req: &Request,
        force_has_body: bool,
        preview0_ieof: bool,
    ) -> IcapResult<BuiltIcap> {
        trace!(
            "build_icap_request_bytes: method={} service={} preview={:?} allow_204={} allow_206={} force_has_body={} preview0_ieof={}",
            req.method,
            req.service,
            req.preview_size,
            req.allow_204,
            req.allow_206,
            force_has_body,
            preview0_ieof
        );

        let mut out = Vec::new();

        // Start-line
        let full_uri = format!(
            "icap://{}:{}/{}",
            self.inner.host,
            self.inner.port,
            trim_leading_slash(&req.service)
        );
        out.extend_from_slice(format!("{} {} ICAP/1.0\r\n", req.method, full_uri).as_bytes());

        // ICAP headers
        let mut headers = self.inner.default_headers.clone();
        let host_value = self
            .inner
            .host_override
            .clone()
            .unwrap_or_else(|| self.inner.host.clone());
        headers.insert(
            HeaderName::from_static("host"),
            HeaderValue::from_str(&host_value).unwrap(),
        );

        for (n, v) in req.icap_headers.iter() {
            headers.insert(n.clone(), v.clone());
        }
        if req.allow_204 {
            append_to_allow(&mut headers, "204");
        }
        if req.allow_206 {
            append_to_allow(&mut headers, "206");
        }
        if let Some(ps) = req.preview_size {
            headers.insert(
                HeaderName::from_static("preview"),
                HeaderValue::from_str(&ps.to_string()).unwrap(),
            );
        }

        // Encapsulated
        let (http_headers_bytes, http_body_bytes, enc_header) = if req.is_mod() {
            if let Some(ref emb) = req.embedded {
                let (hdrs, body_from_emb) = serialize_embedded_http(emb);
                let (hdr_key, body_key) = match req.method.as_str() {
                    "REQMOD" => ("req-hdr", "req-body"),
                    _ => ("res-hdr", "res-body"),
                };
                let will_send_body = force_has_body || body_from_emb.is_some();
                if will_send_body {
                    let enc = format!(
                        "Encapsulated: {}=0, {}={}\r\n",
                        hdr_key,
                        body_key,
                        hdrs.len()
                    );
                    (hdrs, body_from_emb, enc)
                } else {
                    (hdrs, None, format!("Encapsulated: {}=0\r\n", hdr_key))
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

        // Write ICAP headers (except Encapsulated)
        for (name, value) in headers.iter() {
            if name.as_str().eq_ignore_ascii_case("encapsulated") {
                continue;
            }
            let cname = canon_icap_header_name(name.as_str());
            out.extend_from_slice(cname.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        // Encapsulated last + CRLF
        out.extend_from_slice(enc_header.as_bytes());
        out.extend_from_slice(b"\r\n");

        // Embedded HTTP headers
        if !http_headers_bytes.is_empty() {
            out.extend_from_slice(&http_headers_bytes);
        }

        // Initial body/preview
        if req.is_mod()
            && let Some(body_now) = http_body_bytes
        {
            let (bytes, expect_continue, remaining) =
                build_preview_and_chunks(req.preview_size, body_now, preview0_ieof)?;
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

fn canon_icap_header_name(name: &str) -> String {
    let mut out = String::new();
    for (i, part) in name.split('-').enumerate() {
        if i > 0 {
            out.push('-');
        }
        let mut chars = part.chars();
        if let Some(f) = chars.next() {
            out.push(f.to_ascii_uppercase());
            for c in chars {
                out.push(c.to_ascii_lowercase());
            }
        }
    }
    out
}

/// Return connection back to idle slot if keep-alive is enabled.
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

pub fn serialize_http_request(req: &HttpRequest<Vec<u8>>) -> Vec<u8> {
    let mut out = String::new();
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

pub fn serialize_http_response(resp: &HttpResponse<Vec<u8>>) -> Vec<u8> {
    let mut out = String::new();
    let code: StatusCode = resp.status();
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

fn build_preview_and_chunks(
    preview_size: Option<usize>,
    body: Vec<u8>,
    preview0_ieof: bool,
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
                if preview0_ieof {
                    out.extend_from_slice(b"0; ieof\r\n\r\n");
                    Ok((out, false, None))
                } else {
                    out.extend_from_slice(b"0\r\n\r\n"); // expect 100 Continue
                    Ok((out, true, Some(Vec::new())))
                }
            } else {
                out.extend_from_slice(b"0\r\n\r\n"); // expect 100 Continue
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
    let mut buf = Vec::with_capacity(16 + data.len() + 2);
    write!(&mut buf, "{:X}\r\n", data.len()).unwrap();
    if !data.is_empty() {
        buf.extend_from_slice(data);
    }
    buf.extend_from_slice(b"\r\n");
    stream.write_all(&buf).await?;
    Ok(())
}

fn write_chunk_into(out: &mut Vec<u8>, data: &[u8]) {
    write!(out, "{:X}\r\n", data.len()).unwrap();
    if !data.is_empty() {
        out.extend_from_slice(data);
    }
    out.extend_from_slice(b"\r\n");
}

async fn read_icap_headers(stream: &mut TcpStream) -> IcapResult<(u16, Vec<u8>)> {
    trace!("read_icap_headers: start");
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err("Unexpected EOF while reading ICAP headers".into());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(_idx0) = find_double_crlf(&buf) {
            // status line
            let line_end = buf
                .windows(2)
                .position(|w| w == b"\r\n")
                .unwrap_or(buf.len());
            let status_line = &buf[..line_end];
            let code = parse_status_code(status_line).ok_or("Failed to parse ICAP status code")?;
            trace!("read_icap_headers: code={}", code);
            return Ok((code, buf));
        }
    }
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_status_code(line: &[u8]) -> Option<u16> {
    let s = std::str::from_utf8(line).ok()?;
    let mut parts = s.split_whitespace();
    let _ver = parts.next()?; // ICAP/1.0
    let code_str = parts.next()?; // 100, 200, 204, ...
    code_str.parse::<u16>().ok()
}

fn headers_end(buf: &[u8]) -> Option<usize> {
    find_double_crlf(buf).map(|i| i + 4)
}

#[derive(Debug, Clone, Copy, Default)]
struct Encapsulated {
    req_hdr: Option<usize>,
    res_hdr: Option<usize>,
    req_body: Option<usize>,
    res_body: Option<usize>,
    null_body: Option<usize>,
}

fn parse_encapsulated_header(headers_text: &str) -> Encapsulated {
    let mut enc = Encapsulated::default();
    for line in headers_text.lines() {
        let Some((name, val)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("Encapsulated") {
            continue;
        }
        for part in val.split(',') {
            let part = part.trim();
            let mut it = part.split('=');
            let key = it.next().unwrap_or("").trim().to_ascii_lowercase();
            let off = it.next().and_then(|s| s.trim().parse::<usize>().ok());
            match (key.as_str(), off) {
                ("req-hdr", Some(o)) => enc.req_hdr = Some(o),
                ("res-hdr", Some(o)) => enc.res_hdr = Some(o),
                ("req-body", Some(o)) => enc.req_body = Some(o),
                ("res-body", Some(o)) => enc.res_body = Some(o),
                ("null-body", Some(o)) => enc.null_body = Some(o),
                _ => {}
            }
        }
        break;
    }
    enc
}

// Returns (next_pos, is_final, size_of_chunk)
fn parse_one_chunk(buf: &[u8], from: usize) -> Option<(usize, bool, usize)> {
    let mut i = from;
    while i + 1 < buf.len() {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' {
            let size_line = &buf[from..i];
            let size_hex = size_line.split(|&b| b == b';').next().unwrap_or(size_line);
            let size_str = std::str::from_utf8(size_hex).ok()?.trim();
            let size = usize::from_str_radix(size_str, 16).ok()?;
            let after_size = i + 2;
            let need = after_size + size + 2;
            if buf.len() < need {
                return None;
            }
            if size == 0 {
                if buf.len() < after_size + 2 {
                    return None;
                }
                return Some((after_size, true, 0));
            }
            return Some((need, false, size));
        }
        i += 1;
    }
    None
}

async fn read_chunked_to_end(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    mut pos: usize,
) -> IcapResult<()> {
    loop {
        match parse_one_chunk(buf, pos) {
            Some((new_pos, done, _size)) => {
                if done {
                    pos = new_pos;
                    while buf.len() < pos + 2 {
                        let mut tmp = [0u8; 4096];
                        let n = stream.read(&mut tmp).await?;
                        if n == 0 {
                            return Err("Unexpected EOF after zero chunk".into());
                        }
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    if &buf[pos..pos + 2] != b"\r\n" {
                        return Err("Invalid chunked terminator".into());
                    }
                    break;
                } else {
                    pos = new_pos;
                }
            }
            None => {
                let mut tmp = [0u8; 4096];
                let n = stream.read(&mut tmp).await?;
                if n == 0 {
                    return Err("Unexpected EOF while reading ICAP chunked body".into());
                }
                buf.extend_from_slice(&tmp[..n]);
            }
        }
    }
    Ok(())
}

async fn read_icap_body_if_any(stream: &mut TcpStream, buf: &mut Vec<u8>) -> IcapResult<()> {
    let Some(h_end) = headers_end(buf) else {
        return Err("Corrupted ICAP headers".into());
    };

    let hdr_text = std::str::from_utf8(&buf[..h_end]).map_err(|_| "Invalid headers utf8")?;
    let enc = parse_encapsulated_header(hdr_text);

    let body_off_rel = enc.req_body.or(enc.res_body);
    let hdr_off_rel = enc.req_hdr.or(enc.res_hdr);

    if let Some(body_rel) = body_off_rel {
        let body_abs = h_end + body_rel;

        while buf.len() < body_abs {
            let mut tmp = [0u8; 4096];
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err("Unexpected EOF before start of ICAP body".into());
            }
            buf.extend_from_slice(&tmp[..n]);
        }

        if let Some(hrel) = hdr_off_rel
            && hrel <= body_rel
            && h_end + body_rel <= buf.len()
        {
            let http_hdr_len = body_rel - hrel;
            debug!(
                "read_icap_body_if_any: embedded HTTP headers len={} (offset {}..{})",
                http_hdr_len,
                h_end + hrel,
                h_end + body_rel
            );
        }

        read_chunked_to_end(stream, buf, body_abs).await
    } else if enc.null_body.is_some() {
        Ok(())
    } else {
        Ok(())
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use http::{Request as HttpReq, Response as HttpResp, StatusCode, Version, header};

    fn bytes_to_string_prefix(v: &[u8], n: usize) -> String {
        String::from_utf8_lossy(&v[..v.len().min(n)]).to_string()
    }

    fn extract_headers_text(wire: &[u8]) -> String {
        let end = wire.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        String::from_utf8_lossy(&wire[..end]).to_string()
    }

    fn find_header_line(hdrs: &str, name_ci: &str) -> Option<String> {
        hdrs.lines()
            .find(|l| {
                l.to_ascii_lowercase()
                    .starts_with(&format!("{}:", name_ci.to_ascii_lowercase()))
            })
            .map(|s| s.to_string())
    }

    #[test]
    fn parse_authority_default_port() {
        let (h, p) = parse_authority("icap://proxy.local/service").unwrap();
        assert_eq!(h, "proxy.local");
        assert_eq!(p, 1344);
    }

    #[test]
    fn parse_authority_with_port() {
        let (h, p) = parse_authority("icap://proxy.local:1345/respmod").unwrap();
        assert_eq!(h, "proxy.local");
        assert_eq!(p, 1345);
    }

    #[test]
    fn parse_authority_errors() {
        assert!(parse_authority("http://wrong").is_err());
        assert!(parse_authority("icap://:1344/").is_err());
        assert!(parse_authority("icap://proxy:bad/").is_err());
    }

    #[test]
    fn canon_icap_header_name_cases() {
        assert_eq!(canon_icap_header_name("user-agent"), "User-Agent");
        assert_eq!(canon_icap_header_name("preview"), "Preview");
        assert_eq!(canon_icap_header_name("x-foo-bar"), "X-Foo-Bar");
    }

    #[test]
    fn trim_leading_slash_works() {
        assert_eq!(trim_leading_slash("/icap/full"), "icap/full");
        assert_eq!(trim_leading_slash("icap/full"), "icap/full");
    }

    #[test]
    fn append_to_allow_no_duplicates() {
        let mut h = HeaderMap::new();
        append_to_allow(&mut h, "204");
        append_to_allow(&mut h, "206");
        append_to_allow(&mut h, "204"); // duplicate
        let s = h.get("allow").unwrap().to_str().unwrap().to_string();
        assert!(s.contains("204"));
        assert!(s.contains("206"));
        assert_eq!(s.matches("204").count(), 1);
    }

    #[test]
    #[ignore]
    fn serialize_http_request_basic() {
        let req = HttpReq::builder()
            .method("GET")
            .uri("http://example.com/path?q=1")
            .version(Version::HTTP_11)
            .header("Host", "example.com")
            .header("Accept", "*/*")
            .body(Vec::<u8>::new())
            .unwrap();

        let bytes = serialize_http_request(&req);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("GET http://example.com/path?q=1 HTTP/1.1\r\n"));
        assert!(text.contains("Host: example.com\r\n"));
        assert!(text.contains("\r\n\r\n"));
    }

    #[test]
    #[ignore]
    fn serialize_http_response_basic() {
        let resp = HttpResp::builder()
            .status(StatusCode::OK)
            .version(Version::HTTP_11)
            .header("Content-Type", "text/plain")
            .body(b"ok".to_vec())
            .unwrap();

        let bytes = serialize_http_response(&resp);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Content-Type: text/plain\r\n"));
        assert!(text.ends_with("\r\nok"));
    }

    #[test]
    fn split_http_bytes_with_and_without_body() {
        let req = HttpReq::builder()
            .method("POST")
            .uri("/upload")
            .version(Version::HTTP_11)
            .header(header::HOST, "x")
            .header("Content-Length", "4")
            .body(b"DATA".to_vec())
            .unwrap();
        let raw = serialize_http_request(&req);
        let (hdrs, body) = split_http_bytes(&raw);
        assert!(
            String::from_utf8(hdrs.clone())
                .unwrap()
                .ends_with("\r\n\r\n")
        );
        assert_eq!(body.unwrap(), b"DATA".to_vec());

        let req2 = HttpReq::builder()
            .method("HEAD")
            .uri("/")
            .version(Version::HTTP_11)
            .header(header::HOST, "x")
            .body(Vec::<u8>::new())
            .unwrap();
        let raw2 = serialize_http_request(&req2);
        let (_hdrs2, body2) = split_http_bytes(&raw2);
        assert!(body2.is_none());
    }

    #[test]
    fn parse_encapsulated_header_variants() {
        let t = "Encapsulated: req-hdr=0, req-body=123\r\n";
        let e = parse_encapsulated_header(t);
        assert_eq!(e.req_hdr, Some(0));
        assert_eq!(e.req_body, Some(123));
        assert_eq!(e.res_hdr, None);

        let t2 = "Some: x\r\nEncapsulated: res-hdr=0, res-body=42\r\nFoo: y\r\n";
        let e2 = parse_encapsulated_header(t2);
        assert_eq!(e2.res_hdr, Some(0));
        assert_eq!(e2.res_body, Some(42));
        assert!(e2.req_hdr.is_none());
    }

    #[test]
    fn build_preview_none_body_empty() {
        let (bytes, expect_cont, rest) = build_preview_and_chunks(None, Vec::new(), false).unwrap();
        assert_eq!(bytes, b"0\r\n\r\n");
        assert!(!expect_cont);
        assert!(rest.is_none());
    }

    #[test]
    fn build_preview_none_with_body() {
        let (bytes, expect_cont, rest) =
            build_preview_and_chunks(None, b"abcd".to_vec(), false).unwrap();
        let s = String::from_utf8(bytes.clone()).unwrap();
        assert!(s.starts_with("4\r\nabcd\r\n0\r\n\r\n"));
        assert!(!expect_cont);
        assert!(rest.is_none());
    }

    #[test]
    fn build_preview_zero_ieof_true_empty_body() {
        let (bytes, expect_cont, rest) =
            build_preview_and_chunks(Some(0), Vec::new(), true).unwrap();
        assert_eq!(bytes, b"0; ieof\r\n\r\n");
        assert!(!expect_cont);
        assert!(rest.is_none());
    }

    #[test]
    fn build_preview_zero_ieof_false_with_body_buffered() {
        let (bytes, expect_cont, rest) =
            build_preview_and_chunks(Some(0), b"DATA".to_vec(), false).unwrap();
        assert_eq!(bytes, b"0\r\n\r\n");
        assert!(expect_cont);
        assert_eq!(rest.unwrap(), b"DATA".to_vec());
    }

    #[test]
    fn build_preview_n_sends_prefix_and_waits_rest() {
        let body = b"ABCDEFG".to_vec();
        let (bytes, expect_cont, rest) =
            build_preview_and_chunks(Some(4), body.clone(), false).unwrap();
        let s = String::from_utf8(bytes.clone()).unwrap();
        assert!(s.starts_with("4\r\nABCD\r\n0\r\n\r\n"));
        assert!(expect_cont);
        assert_eq!(rest.unwrap(), b"EFG".to_vec());
    }

    #[test]
    fn build_preview_n_all_fits_ieof() {
        let body = b"ABC".to_vec();
        let (bytes, expect_cont, rest) =
            build_preview_and_chunks(Some(8), body.clone(), false).unwrap();
        let s = String::from_utf8(bytes.clone()).unwrap();
        assert!(s.starts_with("3\r\nABC\r\n0; ieof\r\n\r\n"));
        assert!(!expect_cont);
        assert!(rest.is_none());
    }

    fn mk_client() -> Client {
        Client::builder()
            .host("icap.example")
            .port(1344)
            .default_header("x-trace-id", "test-123")
            .keep_alive(true)
            .build()
    }

    #[test]
    fn options_has_null_body_and_headers() {
        let c = mk_client();
        let req = Request::options("options");
        let wire = c.get_request_wire(&req, false).unwrap();
        let head = extract_headers_text(&wire);
        assert!(head.starts_with("OPTIONS icap://icap.example:1344/options ICAP/1.0\r\n"));
        assert!(find_header_line(&head, "Host").is_some());
        assert!(find_header_line(&head, "User-Agent").is_some());
        assert!(find_header_line(&head, "X-Trace-Id").is_some());
        let enc = find_header_line(&head, "Encapsulated").unwrap();
        assert!(enc.contains("null-body=0"));
    }

    #[test]
    fn reqmod_with_embedded_and_preview_offsets() {
        let c = mk_client();
        let http = HttpReq::builder()
            .method("POST")
            .uri("/scan")
            .version(Version::HTTP_11)
            .header(header::HOST, "app")
            .header(header::CONTENT_LENGTH, "7")
            .body(b"PAYLOAD".to_vec())
            .unwrap();

        let req = Request::reqmod("icap/full")
            .preview(4)
            .allow_204(true)
            .icap_header("x-foo", "bar")
            .with_http_request(http);

        let wire = c.get_request_wire(&req, false).unwrap();
        let head = extract_headers_text(&wire);
        let enc_line = find_header_line(&head, "Encapsulated").unwrap();
        assert!(enc_line.contains("req-hdr=0"));
        let off = enc_line.split('=').last().unwrap().trim();
        let off_num: usize = off.parse().unwrap();

        let icap_headers_end = head.len();
        let http_start = icap_headers_end;
        assert_eq!(
            &wire[http_start + off_num..http_start + off_num + 2],
            b"4\r"
        ); // first chunk of preview
        let tail_str = bytes_to_string_prefix(&wire[http_start + off_num..], 64);
        assert!(tail_str.contains("\r\n0\r\n\r\n"));
    }

    #[test]
    fn reqmod_preview_zero_appends_zero_chunk_in_wire() {
        let c = mk_client();
        let http = HttpReq::builder()
            .method("POST")
            .uri("/scan")
            .header(header::HOST, "x")
            .body(Vec::<u8>::new())
            .unwrap();

        let req = Request::reqmod("icap/full")
            .preview(0)
            .with_http_request(http);

        let wire = c.get_request_wire(&req, false).unwrap();
        let all = String::from_utf8(wire.clone()).unwrap();
        assert!(all.contains("\r\n\r\n0\r\n\r\n"));
    }

    #[test]
    fn reqmod_preview_zero_ieof_true_appends_ieof_zero_chunk() {
        let c = mk_client();
        let http = HttpReq::builder()
            .method("POST")
            .uri("/scan")
            .header(header::HOST, "x")
            .body(Vec::<u8>::new())
            .unwrap();

        let req = Request::reqmod("icap/full")
            .preview(0)
            .preview_ieof(true)
            .with_http_request(http);

        let wire = c.get_request_wire(&req, false).unwrap();
        let all = String::from_utf8(wire.clone()).unwrap();
        assert!(all.contains("\r\n\r\n0; ieof\r\n\r\n"));
    }

    #[test]
    fn streaming_true_forces_body_marker_in_encapsulated() {
        let c = mk_client();
        let http = HttpReq::builder()
            .method("POST")
            .uri("/scan")
            .header(header::HOST, "x")
            .body(Vec::<u8>::new())
            .unwrap();

        let req = Request::reqmod("icap/full")
            .preview(0)
            .with_http_request(http);

        let wire = c.get_request_wire(&req, true).unwrap();
        let head = extract_headers_text(&wire);
        let enc = find_header_line(&head, "Encapsulated").unwrap();
        assert!(enc.to_ascii_lowercase().contains("req-hdr=0"));
        assert!(enc.to_ascii_lowercase().contains("req-body="));
        let all = String::from_utf8(wire).unwrap();
        assert!(all.contains("\r\n\r\n0\r\n\r\n"));
    }

    #[test]
    fn host_override_is_used() {
        let c = Client::builder()
            .host("icap.internal")
            .port(1344)
            .host_override("icap.external.name")
            .build();

        let req = Request::options("options");
        let wire = c.get_request_wire(&req, false).unwrap();
        let head = extract_headers_text(&wire);
        let host_line = find_header_line(&head, "Host").unwrap();
        assert!(host_line.contains("icap.external.name"));
    }

    #[test]
    fn user_agent_is_present_by_default() {
        let c = Client::builder().host("h").port(1344).build();
        let req = Request::options("s");
        let wire = c.get_request_wire(&req, false).unwrap();
        let head = extract_headers_text(&wire);
        assert!(find_header_line(&head, "User-Agent").is_some());
    }
}
