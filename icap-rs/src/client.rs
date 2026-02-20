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
use crate::response::{Response, parse_icap_response, parse_icap_response_head};

use crate::Method;
use crate::client::tls::{AnyTlsConnector, TlsBackend, TlsConnector};
use crate::parser::icap::find_double_crlf;

use http::{HeaderMap, HeaderName, HeaderValue};
use std::collections::HashSet;
use std::io::Write as _;
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
/// / [`Client::send_streaming`] / [`Client::send_streaming_reader_into_writer`].
/// You can also generate the exact wire bytes
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
    #[default]
    Close,
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
    pub fn default_header(mut self, name: &str, value: &str) -> IcapResult<Self> {
        let n: HeaderName = name.parse()?;
        let v: HeaderValue = HeaderValue::from_str(value)?;
        self.default_headers.insert(n, v);
        Ok(self)
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
            #[cfg(not(feature = "tls-rustls"))]
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
            #[cfg(feature = "tls-rustls")]
            Some(TlsBackend::Rustls) => {
                use crate::client::tls::rustls::RustlsConfig;
                AnyTlsConnector::rustls(RustlsConfig {
                    danger_disable_verify: self.danger_disable_verify,
                    extra_roots: self.extra_roots,
                })
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
            #[cfg(not(feature = "tls-rustls"))]
            Some(_) => panic!("enable `tls-rustls` feature"),
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
        if let Some(inner) = stream.plain_mut()
            && let Some(resp) = Self::try_read_early_response_now(inner).await?
        {
            return Ok(resp);
        }

        let built = self.build_icap_request_bytes(req, false, req.preview_ieof)?;
        AsyncWriteExt::write_all(&mut stream, &built.bytes).await?;
        AsyncWriteExt::flush(&mut stream).await?;

        // OPTIONS: read headers + optional body, then parse, then decide reuse
        if req.method == Method::Options {
            let buf = self.read_response_buffer(&mut stream).await?;
            return self.finalize_response(stream, buf).await;
        }

        // Preview/100-continue negotiation
        if built.expect_continue {
            let (code, hdr_buf) =
                Self::with_timeout(self.inner.read_timeout, read_icap_headers(&mut stream)).await?;

            if code == 100 {
                // send remaining body, then terminating chunk
                if let Some(rest) = built.remaining_body
                    && !rest.is_empty()
                {
                    write_chunk(&mut stream, &rest).await?;
                }
                AsyncWriteExt::write_all(&mut stream, b"0\r\n\r\n").await?;
                AsyncWriteExt::flush(&mut stream).await?;

                // read final response
                let response_buf = self.read_response_buffer(&mut stream).await?;
                return self.finalize_response(stream, response_buf).await;
            } else {
                // non-100 early final response
                let response_buf = self
                    .read_response_buffer_with_headers(&mut stream, hdr_buf)
                    .await?;
                return self.finalize_response(stream, response_buf).await;
            }
        }

        // Normal request: read response, parse, then decide reuse
        let response_buf = self.read_response_buffer(&mut stream).await?;
        self.finalize_response(stream, response_buf).await
    }

    /// Send a request and stream the body from a file using ICAP chunked encoding.
    pub async fn send_streaming<P: AsRef<Path>>(
        &self,
        req: &Request,
        file_path: P,
    ) -> IcapResult<Response> {
        let file = TokioFile::open(file_path).await?;
        self.send_streaming_reader(req, file).await
    }

    /// Send a request and stream body bytes from any `AsyncRead` source using ICAP chunked encoding.
    ///
    /// This API avoids requiring an in-memory `Vec<u8>` body in the request object.
    /// Pair it with `Request::with_http_request_head(...)` / `with_http_response_head(...)`
    /// for head-only embedded HTTP.
    pub async fn send_streaming_reader<R>(&self, req: &Request, mut reader: R) -> IcapResult<Response>
    where
        R: AsyncRead + Unpin + Send,
    {
        trace!(
            "client.send_streaming_reader: method={} service={}",
            req.method,
            req.service
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

        if let Some(inner) = stream.plain_mut()
            && let Some(resp) = Self::try_read_early_response_now(inner).await?
        {
            return Ok(resp);
        }

        // force_has_body=true (body will be streamed), preview0_ieof=false
        let built = self.build_icap_request_bytes(req, true, false)?;
        AsyncWriteExt::write_all(&mut stream, &built.bytes).await?;
        AsyncWriteExt::flush(&mut stream).await?;

        // If Preview: 0, send zero chunk now (optionally ieof)
        if matches!(req.preview_size, Some(0)) {
            if req.preview_ieof {
                AsyncWriteExt::write_all(&mut stream, b"0; ieof\r\n\r\n").await?;
            } else {
                AsyncWriteExt::write_all(&mut stream, b"0\r\n\r\n").await?;
            }
            AsyncWriteExt::flush(&mut stream).await?;
        }

        // Read server decision (100 Continue or final)
        let (code, hdr_buf) =
            Self::with_timeout(self.inner.read_timeout, read_icap_headers(&mut stream)).await?;

        if code == 100 {
            // Stream source as chunked
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = reader.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                write_chunk(&mut stream, &buf[..n]).await?;
            }

            // terminating chunk
            AsyncWriteExt::write_all(&mut stream, b"0\r\n\r\n").await?;
            AsyncWriteExt::flush(&mut stream).await?;

            // read final response
            let response_buf = self.read_response_buffer(&mut stream).await?;
            self.finalize_response(stream, response_buf).await
        } else {
            // final response without 100
            let response_buf = self
                .read_response_buffer_with_headers(&mut stream, hdr_buf)
                .await?;
            self.finalize_response(stream, response_buf).await
        }
    }

    /// Send a request with streamed request body and stream response body into `writer`.
    ///
    /// Returned [`Response`] contains status line and headers, while `body` is empty because
    /// response payload is forwarded directly to `writer`.
    pub async fn send_streaming_reader_into_writer<R, W>(
        &self,
        req: &Request,
        mut reader: R,
        writer: &mut W,
    ) -> IcapResult<Response>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
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

        if let Some(inner) = stream.plain_mut()
            && let Some(resp) = Self::try_read_early_response_now(inner).await?
        {
            return Ok(resp);
        }

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

        let mut response_buf = if code == 100 {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = reader.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                write_chunk(&mut stream, &buf[..n]).await?;
            }
            AsyncWriteExt::write_all(&mut stream, b"0\r\n\r\n").await?;
            AsyncWriteExt::flush(&mut stream).await?;

            let (_code2, final_hdr_buf) =
                Self::with_timeout(self.inner.read_timeout, read_icap_headers(&mut stream)).await?;
            final_hdr_buf
        } else {
            hdr_buf
        };

        let head = parse_icap_response_head(&response_buf)?;
        Self::with_timeout(
            self.inner.read_timeout,
            read_icap_body_if_any_into(&mut stream, &mut response_buf, writer),
        )
        .await?;
        AsyncWriteExt::flush(writer).await?;

        let can_reuse = !response_wants_close(&head);
        maybe_put_back(
            self.inner.connection_policy,
            &self.inner.idle_conn,
            stream,
            can_reuse,
        )
        .await;

        Ok(head)
    }

    /// Convenience wrapper over [`Client::send_streaming_reader_into_writer`] for file sources.
    pub async fn send_streaming_into_writer<P, W>(
        &self,
        req: &Request,
        file_path: P,
        writer: &mut W,
    ) -> IcapResult<Response>
    where
        P: AsRef<Path>,
        W: AsyncWrite + Unpin + Send,
    {
        let file = TokioFile::open(file_path).await?;
        self.send_streaming_reader_into_writer(req, file, writer).await
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

    async fn read_response_buffer(&self, stream: &mut Conn) -> IcapResult<Vec<u8>> {
        let (_code, mut response_buf) =
            Self::with_timeout(self.inner.read_timeout, read_icap_headers(stream)).await?;
        Self::with_timeout(
            self.inner.read_timeout,
            read_icap_body_if_any(stream, &mut response_buf),
        )
        .await?;
        Ok(response_buf)
    }

    async fn read_response_buffer_with_headers(
        &self,
        stream: &mut Conn,
        mut response_buf: Vec<u8>,
    ) -> IcapResult<Vec<u8>> {
        Self::with_timeout(
            self.inner.read_timeout,
            read_icap_body_if_any(stream, &mut response_buf),
        )
        .await?;
        Ok(response_buf)
    }

    async fn finalize_response(&self, stream: Conn, response_buf: Vec<u8>) -> IcapResult<Response> {
        let resp = parse_icap_response(&response_buf)?;
        let can_reuse = !response_wants_close(&resp);
        maybe_put_back(
            self.inner.connection_policy,
            &self.inner.idle_conn,
            stream,
            can_reuse,
        )
        .await;
        Ok(resp)
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

        let mut out = Vec::with_capacity(512);

        // Start-line
        write!(
            &mut out,
            "{} icap://{}:{}/{} ICAP/1.0\r\n",
            req.method,
            self.inner.host,
            self.inner.port,
            Self::trim_leading_slash(&req.service)
        )
        .map_err(Error::Network)?;

        // ICAP headers
        let host_value = self
            .inner
            .host_override
            .clone()
            .unwrap_or_else(|| self.inner.host.clone());

        // Encapsulated
        let (http_headers_bytes, http_body_bytes, enc_head_key, enc_body_key) = if req.is_mod() {
            if let Some(ref emb) = req.embedded {
                let (hdrs, body_from_emb) = serialize_embedded_http(emb);
                let hdr_len = hdrs.len();
                let (hdr_key, body_key) = match req.method.as_str() {
                    "REQMOD" => ("req-hdr", "req-body"),
                    _ => ("res-hdr", "res-body"),
                };
                let will_send_body = force_has_body || body_from_emb.is_some();
                if will_send_body && !hdrs.is_empty() {
                    (hdrs, body_from_emb, Some((hdr_key, hdr_len)), Some(body_key))
                } else if !hdrs.is_empty() {
                    (hdrs, None, Some((hdr_key, 0usize)), None)
                } else {
                    (hdrs, None, None, None)
                }
            } else {
                (Vec::new(), None, None, None)
            }
        } else {
            (Vec::new(), None, None, None)
        };

        // Write ICAP headers (except Encapsulated)
        write_icap_headers(
            &mut out,
            &self.inner.default_headers,
            &req.icap_headers,
            &host_value,
            req.allow_204,
            req.allow_206,
            req.preview_size,
        )?;
        // Encapsulated last + CRLF
        if let Some((hdr_key, hdr_len)) = enc_head_key {
            if let Some(body_key) = enc_body_key {
                write!(
                    &mut out,
                    "Encapsulated: {}=0, {}={}\r\n",
                    hdr_key, body_key, hdr_len
                )
                .map_err(Error::Network)?;
            } else {
                write!(&mut out, "Encapsulated: {}=0\r\n", hdr_key).map_err(Error::Network)?;
            }
        } else {
            out.extend_from_slice(b"Encapsulated: null-body=0\r\n");
        }
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

async fn maybe_put_back(
    policy: ConnectionPolicy,
    slot: &Mutex<Option<Conn>>,
    stream: Conn,
    can_reuse: bool,
) {
    if matches!(policy, ConnectionPolicy::KeepAlive) && can_reuse {
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

async fn read_icap_body_if_any_into<S, W>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    writer: &mut W,
) -> IcapResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    W: AsyncWrite + Unpin,
{
    let Some(h_end) = find_double_crlf(buf) else {
        return Err("Corrupted ICAP headers".into());
    };

    let hdr_text = std::str::from_utf8(&buf[..h_end]).map_err(|_| "Invalid headers utf8")?;
    let enc = parse_encapsulated_header(hdr_text);

    // Fast path: embedded HTTP message with known Content-Length (or header-only) can be streamed directly.
    if let Some(http_rel) = enc.req_hdr.or(enc.res_hdr) {
        let http_abs = h_end + http_rel;
        while buf.len() < http_abs {
            let mut tmp = [0u8; 4096];
            let n = AsyncReadExt::read(stream, &mut tmp).await?;
            if n == 0 {
                return Err("Unexpected EOF before start of embedded HTTP".into());
            }
            buf.extend_from_slice(&tmp[..n]);
        }

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
        let target_end = if !has_http_body {
            Some(http_hdr_end_abs)
        } else {
            let http_head = &buf[http_abs..http_hdr_end_abs];
            http_content_length(http_head).map(|cl| http_hdr_end_abs + cl)
        };

        if let Some(target_end) = target_end {
            let initial_end = buf.len().min(target_end);
            if initial_end > h_end {
                AsyncWriteExt::write_all(writer, &buf[h_end..initial_end]).await?;
            }
            let mut written = initial_end;
            let mut tmp = [0u8; 8192];
            while written < target_end {
                let n = AsyncReadExt::read(stream, &mut tmp).await?;
                if n == 0 {
                    return Err("Unexpected EOF while streaming response body".into());
                }
                let take = (target_end - written).min(n);
                AsyncWriteExt::write_all(writer, &tmp[..take]).await?;
                written += take;
                if take < n {
                    buf.clear();
                    buf.extend_from_slice(&tmp[take..n]);
                }
            }
            buf.truncate(h_end);
            return Ok(());
        }
    }

    // Fallback for chunked/unknown-length variants: use buffered reader, then forward payload.
    read_icap_body_if_any(stream, buf).await?;
    if buf.len() > h_end {
        AsyncWriteExt::write_all(writer, &buf[h_end..]).await?;
        buf.truncate(h_end);
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

#[cfg(test)]
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

#[inline]
fn is_virtual_icap_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("host")
        || name.eq_ignore_ascii_case("encapsulated")
        || name.eq_ignore_ascii_case("allow")
        || name.eq_ignore_ascii_case("preview")
}

fn write_icap_headers(
    out: &mut Vec<u8>,
    default_headers: &HeaderMap,
    req_headers: &HeaderMap,
    host_value: &str,
    allow_204: bool,
    allow_206: bool,
    preview_size: Option<usize>,
) -> IcapResult<()> {
    // Host is always emitted; request-level Host overrides computed host.
    out.extend_from_slice(canon_icap_header("host").as_bytes());
    out.extend_from_slice(b": ");
    if let Some(v) = req_headers.get("Host") {
        out.extend_from_slice(v.as_bytes());
    } else {
        out.extend_from_slice(host_value.as_bytes());
    }
    out.extend_from_slice(b"\r\n");

    let req_names: HashSet<&str> = req_headers.keys().map(|n| n.as_str()).collect();

    // Default headers first, unless overridden by request-level headers.
    for (name, value) in default_headers.iter() {
        let key = name.as_str();
        if is_virtual_icap_header(key) || req_names.contains(key) {
            continue;
        }
        let cname = canon_icap_header(key);
        out.extend_from_slice(cname.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }

    // Request-level headers override defaults.
    for (name, value) in req_headers.iter() {
        let key = name.as_str();
        if is_virtual_icap_header(key) {
            continue;
        }
        let cname = canon_icap_header(key);
        out.extend_from_slice(cname.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }

    // Allow merge logic preserving request-over-default precedence.
    if let Some(mut allow) = req_headers
        .get("Allow")
        .or_else(|| default_headers.get("Allow"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
    {
        if allow_204 && !allow.split(',').any(|p| p.trim().eq_ignore_ascii_case("204")) {
            if !allow.is_empty() {
                allow.push_str(", ");
            }
            allow.push_str("204");
        }
        if allow_206 && !allow.split(',').any(|p| p.trim().eq_ignore_ascii_case("206")) {
            if !allow.is_empty() {
                allow.push_str(", ");
            }
            allow.push_str("206");
        }
        if !allow.is_empty() {
            out.extend_from_slice(canon_icap_header("allow").as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(allow.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
    } else if allow_204 || allow_206 {
        let allow = match (allow_204, allow_206) {
            (true, true) => "204, 206",
            (true, false) => "204",
            (false, true) => "206",
            (false, false) => "",
        };
        if !allow.is_empty() {
            out.extend_from_slice(canon_icap_header("allow").as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(allow.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
    }

    if let Some(ps) = preview_size {
        out.extend_from_slice(canon_icap_header("preview").as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(ps.to_string().as_bytes());
        out.extend_from_slice(b"\r\n");
    } else if let Some(v) = req_headers
        .get("Preview")
        .or_else(|| default_headers.get("Preview"))
    {
        out.extend_from_slice(canon_icap_header("preview").as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }

    Ok(())
}

fn response_wants_close(resp: &Response) -> bool {

    let Some(v) = resp.headers().get(http::header::CONNECTION) else {
        return false;
    };

    let Ok(s) = v.to_str() else {
        return true;
    };

    s.split(',')
        .any(|t| t.trim().eq_ignore_ascii_case("close"))
}

async fn read_icap_headers<S>(stream: &mut S) -> IcapResult<(u16, Vec<u8>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];

    let mut status_line_end: Option<usize> = None;
    let mut hdr_end: Option<usize> = None;

    let mut code: Option<u16> = None;

    let mut win: u32 = 0;
    const CRLFCRLF: u32 = 0x0D0A0D0A;

    let mut prev: Option<u8> = None;

    fn parse_status_code_from_status_line(line: &[u8]) -> Option<u16> {
        let sp1 = line.iter().position(|&b| b == b' ')?;
        let mut i = sp1;
        while i < line.len() && line[i] == b' ' {
            i += 1;
        }
        if i + 3 > line.len() {
            return None;
        }
        let d0 = line[i];
        let d1 = line[i + 1];
        let d2 = line[i + 2];
        if !d0.is_ascii_digit() || !d1.is_ascii_digit() || !d2.is_ascii_digit() {
            return None;
        }
        Some((d0 - b'0') as u16 * 100 + (d1 - b'0') as u16 * 10 + (d2 - b'0') as u16)
    }

    loop {
        let n = AsyncReadExt::read(stream, &mut tmp)
            .await
            .map_err(Error::Network)?;

        if n == 0 {
            // EOF
            if buf.is_empty() {
                return Err(Error::EarlyCloseWithoutHeaders);
            }

            if let Some(c) = code
                && (400..=599).contains(&c)
                && hdr_end.is_none()
            {
                if !buf.ends_with(b"\r\n\r\n") {
                    if buf.ends_with(b"\r\n") {
                        buf.extend_from_slice(b"\r\n");
                    } else {
                        buf.extend_from_slice(b"\r\n\r\n");
                    }
                }
                return Ok((c, buf));
            }

            if hdr_end.is_none() && status_line_end.is_some() {
                if !buf.ends_with(b"\r\n\r\n") {
                    if buf.ends_with(b"\r\n") {
                        buf.extend_from_slice(b"\r\n");
                    } else {
                        buf.extend_from_slice(b"\r\n\r\n");
                    }
                }
                return Err(Error::EarlyCloseWithoutHeaders);
            }
        } else {
            let old_len = buf.len();
            buf.extend_from_slice(&tmp[..n]);

            for (j, &b) in tmp[..n].iter().enumerate() {
                let i = old_len + j;

                if status_line_end.is_none() && prev == Some(b'\r') && b == b'\n' {
                    status_line_end = Some(i - 1);
                    let line = &buf[..(i - 1)];
                    if let Some(c) = parse_status_code_from_status_line(line) {
                        code = Some(c);
                    }
                }

                win = (win << 8) | (b as u32);
                if hdr_end.is_none() && win == CRLFCRLF {
                    hdr_end = Some(i - 3);
                }

                prev = Some(b);
            }
        }

        if code.is_none() && let Some(end) = status_line_end {
            let line = &buf[..end];
            if let Some(c) = parse_status_code_from_status_line(line) {
                code = Some(c);
            }
        }

        if let Some(c) = code
            && (400..=599).contains(&c)
            && hdr_end.is_none()
        {
            if !buf.ends_with(b"\r\n\r\n") {
                if buf.ends_with(b"\r\n") {
                    buf.extend_from_slice(b"\r\n");
                } else {
                    buf.extend_from_slice(b"\r\n\r\n");
                }
            }
            return Ok((c, buf));
        }

        if hdr_end.is_some() {
            let c = code.ok_or("missing/bad status code")?;
            return Ok((c, buf));
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
            .default_header("x-trace-id", "test-123").unwrap()
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
        let off = enc_line.split('=').next_back().unwrap().trim();
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
