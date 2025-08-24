//! ICAP Client implementation in Rust.
//!
//! Features:
//! - Client with builder (`ClientBuilder`).
//! - ICAP requests: OPTIONS, REQMOD, RESPMOD.
//! - Embedded HTTP requests/responses (serialize on wire).
//! - ICAP Preview (including `ieof`) and streaming upload.
//! - Keep-Alive reuse of a single idle connection.
//! - Encapsulated header calculation and chunked bodies.
use crate::error::{Error, IcapResult};
use crate::parser::parse_encapsulated_header;
use crate::parser::{
    canon_icap_header, find_double_crlf, read_chunked_to_end, write_chunk, write_chunk_into,
};
use crate::request::{Request, serialize_embedded_http};
use crate::response::{Response, parse_icap_response};

use crate::Method;
use http::{HeaderMap, HeaderName, HeaderValue};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::File as TokioFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::trace;

/// High-level ICAP client with connection reuse and Preview negotiation.
///
/// Construct via [`Client::builder()`] and send requests using [`Client::send`]
/// or [`Client::send_streaming`]. You can also generate the exact wire bytes
/// without sending using [`Client::get_request`] / [`Client::get_request_wire`].
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

/// Policy for connection lifetime management.
///
/// - [`ConnectionPolicy::Close`] — close the TCP connection after every request.
/// - [`ConnectionPolicy::KeepAlive`] — keep a single idle connection and reuse it.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub enum ConnectionPolicy {
    /// Close the connection after each request (no reuse).
    #[default]
    Close,
    /// Reuse a single idle connection when possible.
    KeepAlive,
}

/// Builder for [`Client`]. Use it to configure host/port, headers, keep-alive,
/// read timeouts, and other options before creating a client instance.
///
/// By default:
/// - `ConnectionPolicy` is `Close`;
/// - no host/port are set until you call [`ClientBuilder::host`] / [`ClientBuilder::port`]
///   or [`ClientBuilder::from_uri`].
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
    /// Create a new `ClientBuilder` with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set ICAP server host (hostname or IP).
    pub fn host(mut self, host: &str) -> Self {
        self.host = Some(host.to_string());
        self
    }

    /// Set ICAP server TCP port (default 1344 if not set).
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Override the `Host:` header value sent in ICAP requests.
    ///
    /// This does not change the actual remote address used for the TCP connection,
    /// only the value of the `Host` ICAP header.
    pub fn host_override(mut self, host: &str) -> Self {
        self.host_override = Some(host.to_string());
        self
    }

    /// Insert a default ICAP header that will be sent with every request.
    ///
    /// If the same header is set later on a particular request, that per-request
    /// value takes precedence.
    pub fn default_header(mut self, name: &str, value: &str) -> Self {
        let n: HeaderName = name.parse().expect("invalid header name");
        let v: HeaderValue = HeaderValue::from_str(value).expect("invalid header value");
        self.default_headers.insert(n, v);
        self
    }

    /// Sets the ICAP `User-Agent` header for all requests created by this client.
    ///
    /// A per-request override via `Request::icap_header("User-Agent", "...")`
    /// takes precedence over the value set here.
    ///
    /// # Example
    /// ```
    /// use icap_rs::Client;
    /// let client = Client::builder()
    ///     .host("icap.example")
    ///     .port(1344)
    ///     .user_agent("my-app/1.2.3")
    ///     .build();
    /// ```
    pub fn user_agent(mut self, user_agent: &str) -> Self {
        self.default_headers.insert(
            HeaderName::from_static("user-agent"),
            HeaderValue::from_str(user_agent).expect("invalid User-Agent header value"),
        );
        self
    }

    /// Enable or disable connection reuse (keep-alive).
    ///
    /// When enabled, the client will store a single idle connection and reuse it
    /// for subsequent requests, reducing handshake overhead.
    pub fn keep_alive(mut self, yes: bool) -> Self {
        self.connection_policy = if yes {
            ConnectionPolicy::KeepAlive
        } else {
            ConnectionPolicy::Close
        };
        self
    }

    /// Set a read timeout for network operations.
    ///
    /// If `None`, operations have no explicit read timeout and rely on OS defaults.
    pub fn read_timeout(mut self, dur: Option<Duration>) -> Self {
        self.read_timeout = dur;
        self
    }

    /// Configure the builder from an ICAP authority URI (`icap://host[:port]`).
    ///
    /// This extracts `host` and `port` for use in the TCP connection. The service path,
    /// if present in the URI, is ignored here and should be set on the request itself.
    pub fn from_uri(mut self, uri: &str) -> IcapResult<Self> {
        let (host, port) = parse_authority(uri)?;
        self.host = Some(host);
        self.port = Some(port);
        Ok(self)
    }

    /// Build a [`Client`] from this builder.
    ///
    /// # Panics
    /// Panics if the host is not set prior to calling `build()`.
    pub fn build(self) -> Client {
        let host = self.host.expect("ClientBuilder: host is required");
        let port = self.port.unwrap_or(1344);
        Client {
            inner: Arc::new(ClientRef {
                host,
                port,
                host_override: self.host_override,
                default_headers: self.default_headers,
                connection_policy: self.connection_policy,
                read_timeout: self.read_timeout,
                idle_conn: Mutex::new(None),
            }),
        }
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self {
            host: None,
            port: None,
            host_override: None,
            default_headers: HeaderMap::new(),
            connection_policy: ConnectionPolicy::Close,
            read_timeout: None,
        }
    }
}

impl Client {
    /// Create a new [`ClientBuilder`] to configure and build a [`Client`].
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    /// Return the raw ICAP request as wire-format bytes (no I/O).
    ///
    /// Useful for debugging or for printing what would be sent without
    /// actually opening a connection.
    pub fn get_request(&self, req: &Request) -> IcapResult<Vec<u8>> {
        let built = self.build_icap_request_bytes(req, false, req.preview_ieof)?;
        Ok(built.bytes)
    }

    /// Send an ICAP request with a embedded HTTP message.
    ///
    /// This method:
    /// - writes ICAP headers and the embedded HTTP headers/body,
    /// - handles `Preview` and `100 Continue` negotiation when applicable,
    /// - and returns the parsed ICAP [`Response`].
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

        // non-blocking early probe (e.g., ICAP/1.0 503) before writing anything
        if let Some(resp) = Self::try_read_early_response_now(&mut stream).await? {
            // Do not return this connection to idle pool — server likely closed it.
            return Ok(resp);
        }

        let built = self.build_icap_request_bytes(req, false, req.preview_ieof)?;
        stream.write_all(&built.bytes).await?;
        stream.flush().await?;

        if req.method == Method::Options {
            let (_code, mut buf) =
                Self::with_timeout(self.inner.read_timeout, read_icap_headers(&mut stream)).await?;
            Self::with_timeout(
                self.inner.read_timeout,
                read_icap_body_if_any(&mut stream, &mut buf),
            )
            .await?;
            maybe_put_back(self.inner.connection_policy, &self.inner.idle_conn, stream).await;
            return parse_icap_response(&buf);
        }

        // Handle 100-Continue for Preview
        if built.expect_continue {
            let (code, hdr_buf) =
                Self::with_timeout(self.inner.read_timeout, read_icap_headers(&mut stream)).await?;
            return if code == 100 {
                if let Some(rest) = built.remaining_body
                    && !rest.is_empty()
                {
                    write_chunk(&mut stream, &rest).await?;
                }
                stream.write_all(b"0\r\n\r\n").await?;
                stream.flush().await?;

                let (_code2, mut response) =
                    Self::with_timeout(self.inner.read_timeout, read_icap_headers(&mut stream))
                        .await?;
                Self::with_timeout(
                    self.inner.read_timeout,
                    read_icap_body_if_any(&mut stream, &mut response),
                )
                .await?;
                maybe_put_back(self.inner.connection_policy, &self.inner.idle_conn, stream).await;
                parse_icap_response(&response)
            } else {
                // server decided final without continue (e.g., 204)
                let mut response = hdr_buf;
                Self::with_timeout(
                    self.inner.read_timeout,
                    read_icap_body_if_any(&mut stream, &mut response),
                )
                .await?;
                maybe_put_back(self.inner.connection_policy, &self.inner.idle_conn, stream).await;
                parse_icap_response(&response)
            };
        }

        // No preview — read final
        let (_code, mut response) =
            Self::with_timeout(self.inner.read_timeout, read_icap_headers(&mut stream)).await?;
        Self::with_timeout(
            self.inner.read_timeout,
            read_icap_body_if_any(&mut stream, &mut response),
        )
        .await?;
        maybe_put_back(self.inner.connection_policy, &self.inner.idle_conn, stream).await;
        parse_icap_response(&response)
    }

    /// Send an ICAP request where the embedded HTTP body is streamed from disk.
    ///
    /// Use this for large payloads: the file is sent in chunks after a `100 Continue`
    /// is received from the server.
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

        // non-blocking early probe (e.g., ICAP/1.0 503)
        if let Some(resp) = Self::try_read_early_response_now(&mut stream).await? {
            return Ok(resp);
        }

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

        let (code, hdr_buf) =
            Self::with_timeout(self.inner.read_timeout, read_icap_headers(&mut stream)).await?;
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

            let (_code2, mut response) =
                Self::with_timeout(self.inner.read_timeout, read_icap_headers(&mut stream)).await?;
            Self::with_timeout(
                self.inner.read_timeout,
                read_icap_body_if_any(&mut stream, &mut response),
            )
            .await?;
            maybe_put_back(self.inner.connection_policy, &self.inner.idle_conn, stream).await;
            parse_icap_response(&response)
        } else {
            // final immediately (e.g., 204)
            let mut response = hdr_buf;
            Self::with_timeout(
                self.inner.read_timeout,
                read_icap_body_if_any(&mut stream, &mut response),
            )
            .await?;
            maybe_put_back(self.inner.connection_policy, &self.inner.idle_conn, stream).await;
            parse_icap_response(&response)
        }
    }

    /// Return the full ICAP request as it would appear on the wire (no I/O).
    ///
    /// If `streaming` is `true` or the request uses `Preview: 0`, the `Encapsulated`
    /// header will include `*-body`, and a zero-chunk will be appended.
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

    async fn with_timeout<T, F>(dur: Option<Duration>, fut: F) -> Result<T, Error>
    where
        F: std::future::Future<Output = Result<T, Error>>,
    {
        if let Some(d) = dur {
            match timeout(d, fut).await {
                Ok(res) => res,
                Err(_) => Err(Error::ClientTimeout(d)),
            }
        } else {
            fut.await
        }
    }

    /// Build ICAP request bytes (headers + embedded HTTP + initial preview/chunks).
    ///
    /// - `force_has_body = true` → `Encapsulated` will contain `*-body`
    ///   even if the current body is empty.
    /// - `preview0_ieof = true` → when `Preview: 0`, use `0; ieof` (fast-204 hint).
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
            Self::trim_leading_slash(&req.service)
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
            HeaderValue::from_str(&host_value)?,
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
                HeaderValue::from_str(&ps.to_string())?,
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
            let cname = canon_icap_header(name.as_str());
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

    fn trim_leading_slash(s: &str) -> &str {
        s.strip_prefix('/').unwrap_or(s)
    }

    /// Try to read an immediate ICAP response (e.g., `503 Service Unavailable`)
    /// from the server before sending the request.
    ///
    /// Some ICAP servers (including this crate's server implementation) may send
    /// a `503` response right after `connect()` when the global connection limit
    /// is exceeded. If the client blindly starts writing its request, this can
    /// result in OS errors like `os error 10053` ("Software caused connection abort")
    /// on Windows when writing into a socket that has already been closed.
    ///
    /// This helper performs a **non-blocking** best-effort probe:
    /// - If kernel buffers already contain a full header block (`\r\n\r\n`),
    ///   it finishes reading the body if present (chunked) and returns the parsed response.
    /// - If there are no bytes ready (`WouldBlock`), it returns `Ok(None)` immediately,
    ///   and the caller proceeds with writing the ICAP request.
    async fn try_read_early_response_now(stream: &mut TcpStream) -> IcapResult<Option<Response>> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];

        loop {
            match stream.try_read(&mut tmp) {
                Ok(0) => {
                    // Peer closed without headers — treat as no early response.
                    return Ok(None);
                }
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if find_double_crlf(&buf).is_some() {
                        // There are headers. We'll finish reading the body if Encapsulated points to it.
                        // read_icap_body_if_any will only wait if there really is a body.
                        let _ = read_icap_body_if_any(stream, &mut buf).await;
                        return parse_icap_response(&buf).map(Some);
                    }
                    // Continue reading while the core gives out data in one fell swoop.
                    continue;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return Ok(None); // Nothing ready - we write a request.
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
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

async fn read_icap_body_if_any(stream: &mut TcpStream, buf: &mut Vec<u8>) -> IcapResult<()> {
    let Some(h_end) = find_double_crlf(buf) else {
        return Err("Corrupted ICAP headers".into());
    };

    let hdr_text = std::str::from_utf8(&buf[..h_end]).map_err(|_| "Invalid headers utf8")?;
    let enc = parse_encapsulated_header(hdr_text);

    if let Some(body_rel) = enc.req_body.or(enc.res_body) {
        let body_abs = h_end + body_rel;

        while buf.len() < body_abs {
            let mut tmp = [0u8; 4096];
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err("EOF before body".into());
            }
            buf.extend_from_slice(&tmp[..n]);
        }

        read_chunked_to_end(stream, buf, body_abs).await.map(|_| ())
    } else {
        Ok(())
    }
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

async fn read_icap_headers(stream: &mut TcpStream) -> IcapResult<(u16, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];

    // Returns true if we already have the canonical end-of-headers marker.
    let has_double_crlf = |b: &Vec<u8>| b.windows(4).any(|w| w == b"\r\n\r\n");
    // Returns the position of the first CRLF (end of the status line).
    let first_crlf_pos = |b: &Vec<u8>| b.windows(2).position(|w| w == b"\r\n");

    // Helper: try to parse status code if we have at least one CRLF (status line complete).
    let parse_status_if_possible = |b: &Vec<u8>| -> Result<Option<u16>, &'static str> {
        if let Some(line_end) = first_crlf_pos(b) {
            let status_line = &b[..line_end];
            let s = std::str::from_utf8(status_line).map_err(|_| "bad utf8 in status line")?;
            let mut parts = s.split_whitespace();
            let _ver = parts.next(); // "ICAP/1.0"
            let code_str = parts.next().ok_or("missing status code")?;
            let code = code_str.parse::<u16>().map_err(|_| "bad status code")?;
            Ok(Some(code))
        } else {
            Ok(None)
        }
    };

    loop {
        let n = stream.read(&mut tmp).await.map_err(Error::Network)?;

        if n == 0 {
            // Peer closed before we saw \r\n\r\n.
            // Some non-strict servers send only a single CRLF and then close.
            // If we already have a status line, normalize to \r\n\r\n for compatibility.
            if first_crlf_pos(&buf).is_some() && !has_double_crlf(&buf) {
                buf.extend_from_slice(b"\r\n"); // synthesize the missing empty line
            } else {
                return Err(Error::EarlyCloseWithoutHeaders);
            }
        } else {
            buf.extend_from_slice(&tmp[..n]);
        }

        // 1) Fast path: canonical end-of-headers found.
        if has_double_crlf(&buf) {
            let line_end = first_crlf_pos(&buf).unwrap_or(buf.len());
            let status_line = &buf[..line_end];

            let code = {
                let s = std::str::from_utf8(status_line).map_err(|_| "bad utf8 in status line")?;
                let mut parts = s.split_whitespace();
                let _ver = parts.next(); // "ICAP/1.0"
                let code_str = parts.next().ok_or("missing status code")?;
                code_str.parse::<u16>().map_err(|_| "bad status code")?
            };

            return Ok((code, buf));
        }

        // 2) Lenient error handling:
        // If we have a complete status line and it's an error (4xx/5xx),
        // some servers send only one CRLF and keep the connection open.
        // To avoid hanging forever, accept a single-CRLF terminator for error responses
        // by normalizing it to \r\n\r\n and returning immediately.
        if let Some(code) = parse_status_if_possible(&buf).map_err(|e| e.to_string())?
            && (400..=599).contains(&code)
        {
            if !has_double_crlf(&buf) {
                buf.extend_from_slice(b"\r\n"); // synthesize the missing empty line
            }
            return Ok((code, buf));
        }

        if buf.len() > crate::MAX_HDR_BYTES {
            // Defensive bound: prevent unbounded growth if peer never terminates headers.
            return Err("ICAP headers too large".into());
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use http::{Request as HttpReq, Version, header};
    use tokio::net::TcpListener;
    use tokio::time::timeout;

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

        let req = Request::reqmod("icap/test")
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

        let req = Request::reqmod("icap/test")
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

        let req = Request::reqmod("icap/test")
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

    async fn connect_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    /// Server helper to write bytes and optionally keep the socket open (no close).
    async fn server_write_and_optionally_hang(
        mut server: TcpStream,
        bytes: &[u8],
        keep_open_ms: u64,
    ) {
        server.write_all(bytes).await.unwrap();
        server.flush().await.unwrap();
        if keep_open_ms > 0 {
            tokio::time::sleep(Duration::from_millis(keep_open_ms)).await;
        } else {
            // drop closes the socket
        }
    }

    /// 1) 404 + single CRLF, connection kept open.
    /// Expectation: read_icap_headers returns quickly with code=404 and buffer normalized to CRLFCRLF.
    #[tokio::test]
    async fn error_404_single_crlf_kept_open_returns_quickly() {
        let (mut client, server) = connect_pair().await;

        // Spawn server: send status + single CRLF and keep connection open for a while.
        tokio::spawn(server_write_and_optionally_hang(
            server,
            b"ICAP/1.0 404 ICAP Service not found\r\n",
            1500, // keep open long enough; client must not wait for this
        ));

        // Client must finish fast; we protect with a small timeout.
        let (code, buf) = timeout(Duration::from_millis(300), read_icap_headers(&mut client))
            .await
            .expect("client hung on single-CRLF 404")
            .expect("read_icap_headers failed");

        assert_eq!(code, 404, "status code should be 404");
        // Buffer should end with CRLFCRLF after normalization.
        assert!(
            buf.ends_with(b"\r\n\r\n"),
            "buffer should be normalized to CRLFCRLF"
        );
    }

    /// 2) 404 with headers and proper CRLFCRLF.
    #[tokio::test]
    async fn error_404_with_headers_and_double_crlf() {
        let (mut client, server) = connect_pair().await;

        let wire = b"ICAP/1.0 404 ICAP Service not found\r\nISTag: x\r\nDate: Thu, 21 Aug 2025 17:00:00 GMT\r\n\r\n";
        tokio::spawn(server_write_and_optionally_hang(server, wire, 0));

        let (code, buf) = timeout(Duration::from_millis(300), read_icap_headers(&mut client))
            .await
            .expect("client hung on proper 404")
            .expect("read_icap_headers failed");

        assert_eq!(code, 404);
        assert!(buf.ends_with(b"\r\n\r\n"));
        let text = String::from_utf8(buf.clone()).unwrap();
        assert!(text.contains("ISTag: x"));
        assert!(text.contains("Date: "));
    }

    /// 3) 404 with headers but EOF before CRLFCRLF.
    /// Expectation: method normalizes on EOF and returns.
    #[tokio::test]
    async fn error_404_headers_then_eof_before_double_crlf() {
        let (mut client, server) = connect_pair().await;

        // Status + one header + CRLF, then EOF (socket close)
        let wire = b"ICAP/1.0 404 ICAP Service not found\r\nISTag: y\r\n";
        tokio::spawn(server_write_and_optionally_hang(server, wire, 0)); // close immediately

        let (code, buf) = timeout(Duration::from_millis(300), read_icap_headers(&mut client))
            .await
            .expect("client hung on 404 with EOF")
            .expect("read_icap_headers failed");

        assert_eq!(code, 404);
        assert!(
            buf.ends_with(b"\r\n\r\n"),
            "buffer should be normalized to CRLFCRLF on EOF"
        );
        let text = String::from_utf8(buf.clone()).unwrap();
        assert!(
            text.contains("ISTag: y"),
            "header bytes should be preserved"
        );
    }

    /// 4) Non-error: 200 OK + single CRLF, connection kept open.
    /// Expectation: in strict mode for non-errors, method should NOT return quickly (we expect timeout).
    #[tokio::test]
    async fn non_error_200_single_crlf_kept_open_times_out() {
        let (mut client, server) = connect_pair().await;

        tokio::spawn(server_write_and_optionally_hang(
            server,
            b"ICAP/1.0 200 OK\r\n",
            1200, // keep open; client should wait for \r\n\r\n and thus time out in test
        ));

        // We expect timeout here because the parser should wait for CRLFCRLF on non-error.
        let res = timeout(Duration::from_millis(250), read_icap_headers(&mut client)).await;
        assert!(
            res.is_err(),
            "non-error single-CRLF should not complete; expected timeout"
        );
    }
}
