//! ICAP Client implementation in Rust.
//!
//! Features:
//! - Client with builder (`ClientBuilder`).
//! - ICAP requests: OPTIONS, REQMOD, RESPMOD.
//! - Embedded HTTP requests/responses (serialize on wire).
//! - ICAP Preview (including `ieof`) and streaming upload.
//! - Keep-Alive reuse of a single idle connection.
//! - Encapsulated header calculation and chunked bodies.
//!
//! TLS backends:
//! - Plain TCP by default.
//! - Enable `tls-rustls` to use TLS.
//! - `icaps://` URIs automatically switch to TLS; which backend is used
//!   depends on enabled features or explicit selection in the builder.

mod tls;

use crate::error::{Error, IcapResult};
use crate::parser::parse_encapsulated_header;
use crate::parser::{canon_icap_header, read_chunked_to_end, write_chunk, write_chunk_into};
use crate::request::{Request, serialize_embedded_http};
use crate::response::{Response, parse_icap_response};

use crate::Method;
use crate::client::tls::{AnyTlsConnector, TlsBackend, TlsConnector};
use crate::parser::icap::find_double_crlf;

use http::{HeaderMap, HeaderName, HeaderValue};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "tls-rustls")]
use rustls::pki_types::CertificateDer;

use crate::net::Conn;
use tokio::fs::File as TokioFile;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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
    tls: AnyTlsConnector,
    idle_conn: Mutex<Option<Conn>>,
    sni_hostname: Option<String>,
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
///   or [`ClientBuilder::with_uri`].
#[derive(Debug)]
pub struct ClientBuilder {
    host: Option<String>,
    port: Option<u16>,
    host_override: Option<String>,
    default_headers: HeaderMap,
    connection_policy: ConnectionPolicy,
    read_timeout: Option<Duration>,

    // TLS (plain by default)
    tls_backend: Option<TlsBackend>, // None => plain
    danger_disable_verify: bool,
    sni_hostname: Option<String>,

    #[cfg(feature = "tls-rustls")]
    extra_roots: Vec<CertificateDer<'static>>,
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
    /// Configure from `icap://` or `icaps://` (`icaps` enables TLS).
    pub fn with_uri(mut self, uri: &str) -> IcapResult<Self> {
        let (host, port, tls) = parse_authority_with_scheme(uri)?;
        self.host = Some(host);
        self.port = Some(port);
        if tls {
            #[cfg(feature = "tls-rustls")]
            {
                self = self.use_rustls();
            }
            // #[cfg(all(not(feature = "tls-rustls"), feature = "tls-openssl"))]
            // {
            //     self = self.use_openssl();
            // }
            //#[cfg(all(not(feature = "tls-rustls"), not(feature = "tls-openssl")))]
            #[cfg(all(not(feature = "tls-rustls")))]
            {
                return Err("`icaps://` requested but crate built without TLS features".into());
            }
        }
        Ok(self)
    }

    #[cfg(feature = "tls-rustls")]
    pub fn use_rustls(mut self) -> Self {
        self.tls_backend = Some(TlsBackend::Rustls);
        self
    }

    // #[cfg(feature = "tls-openssl")]
    // pub fn use_openssl(mut self) -> Self {
    //     self.tls_backend = Some(TlsBackend::Openssl);
    //     self
    // }

    /// Custom SNI hostname to use for TLS handshakes.
    pub fn sni_hostname(mut self, s: &str) -> Self {
        self.sni_hostname = Some(s.into());
        self
    }

    /// Disable certificate verification
    pub fn danger_disable_cert_verify(mut self, yes: bool) -> Self {
        self.danger_disable_verify = yes;
        self
    }

    /// Add root CAs from a PEM file (rustls only).
    #[cfg(feature = "tls-rustls")]
    pub fn add_root_ca_pem_file(mut self, path: impl AsRef<std::path::Path>) -> IcapResult<Self> {
        use std::fs::File;
        use std::io::BufReader;

        let f = File::open(path.as_ref())?;
        let mut rdr = BufReader::new(f);

        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut rdr)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("PEM parse error: {e}"))?;

        self.extra_roots.extend(certs);
        Ok(self)
    }

    pub fn build(self) -> Client {
        let host = self.host.expect("ClientBuilder: host is required");
        let port = self.port.unwrap_or(1344);

        let any_tls = match self.tls_backend {
            None => AnyTlsConnector::plain(),
            Some(TlsBackend::Rustls) => {
                #[cfg(feature = "tls-rustls")]
                {
                    use crate::client::tls::rustls::RustlsConfig;
                    AnyTlsConnector::rustls(RustlsConfig {
                        danger_disable_verify: self.danger_disable_verify,
                        extra_roots: self.extra_roots,
                    })
                }
                #[cfg(not(feature = "tls-rustls"))]
                {
                    panic!("enable `tls-rustls` feature")
                }
            } // Some(TlsBackend::Openssl) => {
              //     #[cfg(feature = "tls-openssl")]
              //     {
              //         use crate::client::tls::openssl::OpensslConfig;
              //         AnyTlsConnector::openssl(OpensslConfig {
              //             danger_disable_verify: self.danger_disable_verify,
              //         })
              //     }
              //     #[cfg(not(feature = "tls-openssl"))]
              //     {
              //         panic!("enable `tls-openssl` feature")
              //     }
              // }
        };

        Client {
            inner: Arc::new(ClientRef {
                host,
                port,
                host_override: self.host_override,
                default_headers: self.default_headers,
                connection_policy: self.connection_policy,
                read_timeout: self.read_timeout,
                tls: any_tls,
                idle_conn: Mutex::new(None),
                sni_hostname: self.sni_hostname,
            }),
        }
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self {
            host: Some("localhost".to_string()),
            port: Some(1344),
            host_override: None,
            default_headers: HeaderMap::new(),
            connection_policy: ConnectionPolicy::Close,
            read_timeout: None,
            tls_backend: None, // plain by default
            danger_disable_verify: false,
            sni_hostname: None,
            #[cfg(feature = "tls-rustls")]
            extra_roots: Vec::new(),
        }
    }
}

impl Client {
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
                    self.inner.connect().await?
                }
            }
            ConnectionPolicy::Close => self.inner.connect().await?,
        };

        // If the server already sent a response on a kept-alive *plain* TCP socket,
        // consume it now and return early.
        if let Conn::Plain { inner } = &mut stream
            && let Some(resp) = Self::try_read_early_response_now(inner).await?
        {
            return Ok(resp);
        }

        let built = self.build_icap_request_bytes(req, false, req.preview_ieof)?;
        AsyncWriteExt::write_all(&mut stream, &built.bytes).await?;
        AsyncWriteExt::flush(&mut stream).await?;

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

        if built.expect_continue {
            let (code, hdr_buf) =
                Self::with_timeout(self.inner.read_timeout, read_icap_headers(&mut stream)).await?;
            return if code == 100 {
                if let Some(rest) = built.remaining_body
                    && !rest.is_empty()
                {
                    write_chunk(&mut stream, &rest).await?;
                }
                AsyncWriteExt::write_all(&mut stream, b"0\r\n\r\n").await?;
                AsyncWriteExt::flush(&mut stream).await?;

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

    /// Send a request and stream the body from a file using ICAP chunked encoding.
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
                    self.inner.connect().await?
                }
            }
            ConnectionPolicy::Close => self.inner.connect().await?,
        };

        if let Conn::Plain { inner } = &mut stream
            && let Some(resp) = Self::try_read_early_response_now(inner).await?
        {
            return Ok(resp);
        }

        // force_has_body=true (body will be streamed), preview0_ieof=false
        let built = self.build_icap_request_bytes(req, true, false)?;
        AsyncWriteExt::write_all(&mut stream, &built.bytes).await?;
        AsyncWriteExt::flush(&mut stream).await?;

        if matches!(req.preview_size, Some(0)) {
            if req.preview_ieof {
                AsyncWriteExt::write_all(&mut stream, b"0; ieof\r\n\r\n").await?;
            } else {
                AsyncWriteExt::write_all(&mut stream, b"0\r\n\r\n").await?;
            }
            AsyncWriteExt::flush(&mut stream).await?;
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
            AsyncWriteExt::write_all(&mut stream, b"0\r\n\r\n").await?;
            AsyncWriteExt::flush(&mut stream).await?;

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

    /// Build the exact wire representation of a request, including preview tail when applicable.
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
                    return Ok(None);
                }
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if find_double_crlf(&buf).is_some() {
                        let _ = read_icap_body_if_any(stream, &mut buf).await;
                        return parse_icap_response(&buf).map(Some);
                    }
                    continue;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return Ok(None);
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
}

impl ClientRef {
    async fn connect(&self) -> IcapResult<Conn> {
        let tcp = TcpStream::connect((&*self.host, self.port)).await?;
        // Priority order for SNI selection: user-provided SNI → host_override → host
        let sni = self
            .sni_hostname
            .as_ref()
            .cloned()
            .or_else(|| self.host_override.clone())
            .unwrap_or_else(|| self.host.clone());
        self.tls.connect(tcp, &sni).await
    }
}

async fn maybe_put_back(policy: ConnectionPolicy, slot: &Mutex<Option<Conn>>, stream: Conn) {
    if let ConnectionPolicy::KeepAlive = policy {
        *slot.lock().await = Some(stream);
    }
}

#[derive(Debug, Clone)]
struct BuiltIcap {
    bytes: Vec<u8>,
    expect_continue: bool,
    remaining_body: Option<Vec<u8>>,
}

fn http_content_length(http_head: &[u8]) -> Option<usize> {
    for line in http_head.split(|&b| b == b'\n') {
        let line = if let Some(b) = line.strip_suffix(b"\r") {
            b
        } else {
            line
        };
        let lower = line
            .iter()
            .map(|c| c.to_ascii_lowercase())
            .collect::<Vec<_>>();
        if lower.starts_with(b"content-length:") {
            let v = &line[b"Content-Length:".len()..].trim_ascii();
            return std::str::from_utf8(v).ok()?.trim().parse::<usize>().ok();
        }
    }
    None
}

fn http_has_te_chunked(http_head: &[u8]) -> bool {
    for line in http_head.split(|&b| b == b'\n') {
        let line = if let Some(b) = line.strip_suffix(b"\r") {
            b
        } else {
            line
        };
        let lower = line
            .iter()
            .map(|c| c.to_ascii_lowercase())
            .collect::<Vec<_>>();
        if lower.starts_with(b"transfer-encoding:")
            && std::str::from_utf8(&line[b"Transfer-Encoding:".len()..])
                .ok()
                .map(|v| v.to_ascii_lowercase().contains("chunked"))
                .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

async fn read_until_len<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    need: usize,
) -> IcapResult<()> {
    let mut tmp = [0u8; 4096];
    while buf.len() < need {
        let n = AsyncReadExt::read(stream, &mut tmp).await?;
        if n == 0 {
            return Err("Unexpected EOF while reading response body".into());
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    Ok(())
}

/// If the ICAP response has an encapsulated body (req-body or res-body),
/// read it to the end (chunked) and append to `buf`.
async fn read_icap_body_if_any<S>(stream: &mut S, buf: &mut Vec<u8>) -> IcapResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(h_end) = find_double_crlf(buf) else {
        return Err("Corrupted ICAP headers".into());
    };

    let hdr_text = std::str::from_utf8(&buf[..h_end]).map_err(|_| "Invalid headers utf8")?;
    let enc = parse_encapsulated_header(hdr_text);

    if let Some(http_rel) = enc.req_hdr.or(enc.res_hdr) {
        let http_abs = h_end + http_rel;

        let http_hdr_end_abs = loop {
            if let Some(rel) = find_double_crlf(&buf[http_abs..]) {
                break http_abs + rel;
            }
            let mut tmp = [0u8; 4096];
            let n = AsyncReadExt::read(stream, &mut tmp).await?;
            if n == 0 {
                return Err("Unexpected EOF before end of embedded HTTP headers".into());
            }
            buf.extend_from_slice(&tmp[..n]);
        };

        let has_http_body = enc.req_body.is_some() || enc.res_body.is_some();
        if !has_http_body {
            return Ok(());
        }

        let http_head = &buf[http_abs..http_hdr_end_abs];
        if let Some(cl) = http_content_length(http_head) {
            let want = http_hdr_end_abs + cl;
            read_until_len(stream, buf, want).await?;
            return Ok(());
        }

        if http_has_te_chunked(http_head) {
            let _end = read_chunked_to_end(stream, buf, http_hdr_end_abs).await?;
            return Ok(());
        }

        return Ok(());
    }

    if let Some(body_rel) = enc.req_body.or(enc.res_body) {
        let body_abs = h_end + body_rel;
        if buf.len() < body_abs {
            read_until_len(stream, buf, body_abs).await?;
        }
        let _end = read_chunked_to_end(stream, buf, body_abs).await?;
    }

    Ok(())
}
fn parse_authority_with_scheme(uri: &str) -> IcapResult<(String, u16, bool)> {
    let s = uri.trim();
    let (tls, rest) = if let Some(r) = s.strip_prefix("icaps://") {
        (true, r)
    } else if let Some(r) = s.strip_prefix("icap://") {
        (false, r)
    } else {
        return Err("URI must start with icap:// or icaps://".into());
    };

    let authority = rest.split('/').next().unwrap_or(rest);
    let (host, port) = if let Some(i) = authority.rfind(':') {
        let h = &authority[..i];
        let p: u16 = authority[i + 1..].parse().map_err(|_| "Invalid port")?;
        (h.to_string(), p)
    } else {
        (authority.to_string(), if tls { 11344 } else { 1344 })
    };

    if host.is_empty() {
        return Err("Empty host in authority".into());
    }
    Ok((host, port, tls))
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

async fn read_icap_headers<S>(stream: &mut S) -> IcapResult<(u16, Vec<u8>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];

    let first_crlf_pos = |b: &Vec<u8>| b.windows(2).position(|w| w == b"\r\n");

    let parse_status_if_possible = |b: &Vec<u8>| -> Result<Option<u16>, &'static str> {
        if let Some(line_end) = first_crlf_pos(b) {
            let status_line = &b[..line_end];
            let s = std::str::from_utf8(status_line).map_err(|_| "bad utf8 in status line")?;
            let mut parts = s.split_whitespace();
            let _ver = parts.next();
            let code_str = parts.next().ok_or("missing status code")?;
            let code = code_str.parse::<u16>().map_err(|_| "bad status code")?;
            Ok(Some(code))
        } else {
            Ok(None)
        }
    };

    loop {
        let n = AsyncReadExt::read(stream, &mut tmp)
            .await
            .map_err(Error::Network)?;

        if n == 0 {
            if first_crlf_pos(&buf).is_some() && find_double_crlf(&buf).is_none() {
                buf.extend_from_slice(b"\r\n");
            } else {
                return Err(Error::EarlyCloseWithoutHeaders);
            }
        } else {
            buf.extend_from_slice(&tmp[..n]);
        }

        if let Some(_hdr_end) = find_double_crlf(&buf) {
            let line_end = first_crlf_pos(&buf).unwrap_or(buf.len());
            let status_line = &buf[..line_end];

            let code = {
                let s = std::str::from_utf8(status_line).map_err(|_| "bad utf8 in status line")?;
                let mut parts = s.split_whitespace();
                let _ver = parts.next();
                let code_str = parts.next().ok_or("missing status code")?;
                code_str.parse::<u16>().map_err(|_| "bad status code")?
            };

            return Ok((code, buf));
        }

        if let Some(code) = parse_status_if_possible(&buf).map_err(|e| e.to_string())?
            && (400..=599).contains(&code)
        {
            if find_double_crlf(&buf).is_none() {
                buf.extend_from_slice(b"\r\n");
            }
            return Ok((code, buf));
        }

        if buf.len() > crate::MAX_HDR_BYTES {
            return Err(Error::Header(format!(
                "Headers too large: {} bytes (max {})",
                buf.len(),
                crate::MAX_HDR_BYTES
            )));
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
        Some(0) => {
            if body.is_empty() {
                if preview0_ieof {
                    out.extend_from_slice(b"0; ieof\r\n\r\n");
                    Ok((out, false, None))
                } else {
                    out.extend_from_slice(b"0\r\n\r\n");
                    Ok((out, true, Some(Vec::new())))
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::icap::find_double_crlf;
    use http::{Request as HttpReq, Version, header};
    use rstest::{fixture, rstest};
    use std::future;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::{Duration, timeout};

    fn bytes_to_string_prefix(v: &[u8], n: usize) -> String {
        String::from_utf8_lossy(&v[..v.len().min(n)]).to_string()
    }

    fn extract_headers_text(wire: &[u8]) -> String {
        let end = find_double_crlf(wire).expect("headers terminator not found");
        String::from_utf8_lossy(&wire[..end]).to_string()
    }

    fn find_header_line(hdrs: &str, name_ci: &str) -> Option<String> {
        let needle = format!("{}:", name_ci.to_ascii_lowercase());
        hdrs.lines()
            .find(|l| l.to_ascii_lowercase().starts_with(&needle))
            .map(|s| s.to_string())
    }

    #[fixture]
    fn client() -> Client {
        Client::builder()
            .host("icap.example")
            .port(1344)
            .default_header("x-trace-id", "test-123")
            .keep_alive(true)
            .build()
    }

    async fn connect_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    async fn server_write(server: TcpStream, bytes: &[u8], keep_open: bool) {
        use tokio::io::AsyncWriteExt;
        let mut s = server;
        if !bytes.is_empty() {
            s.write_all(bytes).await.unwrap();
            let _ = s.flush().await;
        }
        if keep_open {
            let _ = future::pending::<()>().await;
        }
    }

    #[rstest]
    #[case("icap://proxy.local/service", Ok(("proxy.local".to_string(), 1344, false)))]
    #[case("icap://proxy.local:1345/respmod", Ok(("proxy.local".to_string(), 1345, false)))]
    #[case("icaps://proxy.local/service",
        Ok(("proxy.local".to_string(), 11344, true))
    )] // default icaps port
    #[case("icaps://proxy.local:2346/svc", Ok(("proxy.local".to_string(), 2346, true)))]
    #[case("http://wrong", Err(()))]
    #[case("icap://:1344/", Err(()))]
    #[case("icap://proxy:bad/", Err(()))]
    fn parse_authority_cases(
        #[case] input: &str,
        #[case] expected: Result<(String, u16, bool), ()>,
    ) {
        match (parse_authority_with_scheme(input), expected) {
            (Ok((h, p, t)), Ok((eh, ep, et))) => assert_eq!((h, p, t), (eh, ep, et)),
            (Err(_), Err(_)) => {}
            other => panic!("mismatch: {:?}", other),
        }
    }

    #[test]
    fn append_to_allow_no_duplicates() {
        let mut h = HeaderMap::new();
        append_to_allow(&mut h, "204");
        append_to_allow(&mut h, "206");
        append_to_allow(&mut h, "204");
        let s = h.get("allow").unwrap().to_str().unwrap().to_string();
        assert!(s.contains("204"));
        assert!(s.contains("206"));
        assert_eq!(s.matches("204").count(), 1);
    }

    #[rstest]
    #[case(None, b"" as &[u8], false, b"0\r\n\r\n".as_ref(), false, None)]
    #[case(None, b"abcd".as_ref(), false, b"4\r\nabcd\r\n0\r\n\r\n".as_ref(), false, None)]
    #[case(Some(0), b"".as_ref(), true, b"0; ieof\r\n\r\n".as_ref(), false, None)]
    #[case(Some(0), b"DATA".as_ref(), false, b"0\r\n\r\n".as_ref(), true, Some(b"DATA".as_ref()))]
    #[case(Some(4), b"ABCDEFG".as_ref(), false, b"4\r\nABCD\r\n0\r\n\r\n".as_ref(), true, Some(b"EFG".as_ref())
    )]
    #[case(Some(8), b"ABC".as_ref(), false, b"3\r\nABC\r\n0; ieof\r\n\r\n".as_ref(), false, None)]
    fn build_preview(
        #[case] preview: Option<usize>,
        #[case] body: &[u8],
        #[case] ieof: bool,
        #[case] expected_prefix: &[u8],
        #[case] expect_continue: bool,
        #[case] rest: Option<&[u8]>,
    ) {
        let (bytes, got_expect_continue, rest_opt) =
            build_preview_and_chunks(preview, body.to_vec(), ieof).unwrap();

        assert!(bytes.starts_with(expected_prefix));
        assert_eq!(got_expect_continue, expect_continue);

        match (rest_opt.as_deref(), rest) {
            (None, None) => {}
            (Some(a), Some(b)) => assert_eq!(a, b),
            other => panic!("rest mismatch: {:?}", other),
        }
    }

    #[test]
    fn options_has_null_body_and_headers() {
        let c = client();
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
        let c = client();
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
            .allow_204()
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
        );
        let tail_str = bytes_to_string_prefix(&wire[http_start + off_num..], 64);
        assert!(tail_str.contains("\r\n0\r\n\r\n"));
    }

    #[rstest]
    #[case::preview0(false, false, "\r\n\r\n0\r\n\r\n")]
    #[case::preview0_ieof(true, false, "\r\n\r\n0; ieof\r\n\r\n")]
    //#[case::streaming(true, true, "\r\n\r\n0\r\n\r\n")] // streaming=true, preview(0)
    fn reqmod_wire_variants(
        client: Client,
        #[case] ieof: bool,
        #[case] streaming: bool,
        #[case] must_contain: &'static str,
    ) {
        let http = HttpReq::builder()
            .method("POST")
            .uri("/scan")
            .header(header::HOST, "x")
            .body(Vec::<u8>::new())
            .unwrap();

        let mut req = Request::reqmod("icap/test")
            .preview(0)
            .with_http_request(http);
        if ieof {
            req = req.preview_ieof();
        }

        let wire = client.get_request_wire(&req, streaming).unwrap();
        let all = std::str::from_utf8(&wire).unwrap();
        assert!(all.contains(must_contain));

        let head = extract_headers_text(&wire);
        let enc = find_header_line(&head, "Encapsulated").unwrap();
        assert!(enc.to_ascii_lowercase().contains("req-hdr=0"));
        if streaming {
            assert!(enc.to_ascii_lowercase().contains("req-body="));
        }
    }

    #[rstest]
    #[case("icap.example", None, "icap://icap.example:1344/options")]
    #[case(
        "icap.internal",
        Some("icap.external.name"),
        "icap://icap.internal:1344/options"
    )]
    fn options_and_host_header(
        #[case] client_host: &'static str,
        #[case] host_override: Option<&'static str>,
        #[case] uri_prefix: &'static str,
    ) {
        let mut b = Client::builder().host(client_host).port(1344);
        if let Some(ho) = host_override {
            b = b.host_override(ho);
        }
        let c = b.build();

        let req = Request::options("options");
        let wire = c.get_request_wire(&req, false).unwrap();
        let head = extract_headers_text(&wire);

        assert!(head.starts_with(&format!("OPTIONS {uri_prefix} ICAP/1.0\r\n")));
        let host_line = find_header_line(&head, "Host").unwrap();
        let expected_host = host_override.unwrap_or(client_host);
        assert!(host_line.contains(expected_host));
    }

    /// 1) 404 + single CRLF, connection kept open.
    /// Expectation: read_icap_headers returns quickly with code=404 and buffer normalized to CRLFCRLF.
    #[tokio::test]
    async fn error_404_single_crlf_kept_open_returns_quickly() {
        let (mut client, server) = connect_pair().await;

        tokio::spawn(server_write(
            server,
            b"ICAP/1.0 404 ICAP Service not found\r\n",
            true,
        ));

        let (code, buf) = timeout(Duration::from_millis(300), read_icap_headers(&mut client))
            .await
            .expect("client hung on single-CRLF 404")
            .expect("read_icap_headers failed");

        assert_eq!(code, 404);
        assert!(buf.ends_with(b"\r\n\r\n"));
    }

    /// 2) 404 with headers and proper CRLFCRLF.
    #[tokio::test]
    async fn error_404_with_headers_and_double_crlf() {
        let (mut client, server) = connect_pair().await;

        let wire = b"ICAP/1.0 404 ICAP Service not found\r\nISTag: x\r\nDate: Thu, 21 Aug 2025 17:00:00 GMT\r\n\r\n";
        tokio::spawn(server_write(server, wire, false));

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
    #[tokio::test]
    async fn error_404_headers_then_eof_before_double_crlf() {
        let (mut client, server) = connect_pair().await;

        // Status + one header + CRLF, then EOF (socket close)
        let wire = b"ICAP/1.0 404 ICAP Service not found\r\nISTag: y\r\n";
        tokio::spawn(server_write(server, wire, false));

        let (code, buf) = timeout(Duration::from_millis(300), read_icap_headers(&mut client))
            .await
            .expect("client hung on 404 with EOF")
            .expect("read_icap_headers failed");

        assert_eq!(code, 404);
        assert!(buf.ends_with(b"\r\n\r\n"), "normalized to CRLFCRLF on EOF");
        let text = String::from_utf8(buf.clone()).unwrap();
        assert!(
            text.contains("ISTag: y"),
            "header bytes should be preserved"
        );
    }

    /// 4) Non-error: 200 OK + single CRLF, connection kept open.
    /// Expectation: in strict mode for non-errors, method should NOT return     #[tokio::test]
    #[tokio::test]
    async fn non_error_200_single_crlf_kept_open_times_out() {
        let (mut client, server) = connect_pair().await;

        tokio::spawn(server_write(server, b"ICAP/1.0 200 OK\r\n", true));
        let res = timeout(Duration::from_millis(50), read_icap_headers(&mut client)).await;
        assert!(res.is_err());
    }
}
