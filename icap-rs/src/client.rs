//! ICAP Client implementation in Rust.
//!
//! Features:
//! - Client with builder ([`ClientBuilder`]).
//! - ICAP requests: OPTIONS, REQMOD, RESPMOD.
//! - Embedded HTTP requests/responses (serialize on wire).
//! - ICAP Preview (including `ieof`) and streaming upload.
//! - Keep-Alive reuse of a single idle connection.
//! - Encapsulated header calculation and chunked bodies.
//!
//! TLS:
//! - Plain TCP by default.
//! - Enable `tls-rustls` to use TLS (rustls backend).
//! - `icaps://` URIs automatically switch to TLS using
//!   `ClientTlsConfig::with_native_roots`; supply a custom `ClientTlsConfig`
//!   via `ClientBuilder::with_tls` to override.

pub mod builder;
pub mod options_cache;
pub mod timeouts;

#[cfg(test)]
use crate::error::ProtocolError;
use crate::error::{Error, IcapResult, TimeoutError, TimeoutKind};
use crate::protocol::{
    canon_icap_header, find_double_crlf, parse_encapsulated_header, read_chunked_to_end,
    write_chunk, write_chunk_into,
};
use crate::request::{Request, normalize_service_path, serialize_embedded_http};
use crate::response::{ParsedResponse, parse_icap_response};

use crate::Method;
#[cfg(feature = "tls-rustls")]
use crate::tls::client::ClientTlsConnector;

use http::HeaderMap;
use std::collections::HashSet;
use std::io::Write as _;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::client::builder::{ClientBuilder, ConnectionPolicy, ProxyAuth};
use crate::client::options_cache::{CachedOptions, OptionsCache, TransferAction};
use crate::client::timeouts::ClientTimeouts;
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
/// / [`Client::send_streaming`] / [`Client::send_streaming_reader`].
/// You can also generate the exact wire bytes
/// without sending using [`Client::get_request`] / [`Client::get_request_wire`].
#[derive(Debug, Clone)]
#[must_use]
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
    timeouts: ClientTimeouts,
    max_response_header_bytes: usize,
    #[cfg(feature = "tls-rustls")]
    tls: Option<ClientTlsConnector>,
    idle_conn: Mutex<Option<Conn>>,
    options_cache: Option<OptionsCache>,
    proxy_auth: Option<ProxyAuth>,
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
        let built = self.build_icap_request_bytes(
            req,
            EffectivePreview::Inherit,
            None,
            false,
            req.preview_ieof,
            true,
        )?;
        Ok(built.bytes)
    }

    /// Send an prepared ICAP request with an embedded HTTP message.
    ///
    /// This method:
    /// - writes ICAP headers and the embedded HTTP headers/body,
    /// - handles `Preview` and `100 Continue` negotiation when applicable,
    /// - and returns the parsed ICAP [`ParsedResponse`].
    pub async fn send(&self, req: &Request) -> IcapResult<ParsedResponse> {
        if self.inner.options_cache.is_some() && req.is_mod() {
            self.ensure_options_cached(req).await;
        }

        // RFC 3507 §4.10.2: apply server-advertised Transfer-* policy.
        let effective_preview = self.resolve_effective_preview(req).await;
        if matches!(effective_preview, EffectivePreview::Skip) {
            // Transfer-Ignore: skip ICAP entirely, return a synthetic pass-through.
            return synthetic_204();
        }

        let response = Box::pin(Self::with_timeout_as(
            self.inner.timeouts.operation,
            self.send_inner(req, effective_preview, None),
            Error::client_total_timeout,
        ))
        .await?;

        // RFC 3507 §7.1: retry once with Proxy-Authorization on 407.
        let response = if response.status_code() == http::StatusCode::PROXY_AUTHENTICATION_REQUIRED
        {
            if let Some(auth) = &self.inner.proxy_auth {
                let auth_value = basic_auth_value(&auth.username, &auth.password);
                Box::pin(Self::with_timeout_as(
                    self.inner.timeouts.operation,
                    self.send_inner(req, effective_preview, Some(auth_value.as_str())),
                    Error::client_total_timeout,
                ))
                .await?
            } else {
                response
            }
        } else {
            response
        };

        if let Some(cache) = &self.inner.options_cache
            && req.is_mod()
        {
            let path = normalize_service_path(&req.service);
            let observed = response.get_header("ISTag").and_then(|v| v.to_str().ok());
            cache
                .reconcile_istag(&self.inner.host, self.inner.port, &path, observed)
                .await;
        }

        Ok(response)
    }

    /// Drop all cached `OPTIONS` results, forcing a re-fetch on the next request.
    ///
    /// No-op when the OPTIONS cache (see
    /// [`ClientBuilder::with_options_cache`](crate::ClientBuilder::with_options_cache))
    /// is not enabled.
    pub async fn invalidate_options_cache(&self) {
        if let Some(cache) = &self.inner.options_cache {
            cache.clear().await;
        }
    }

    /// Fetch and cache `OPTIONS` for a modification request's service when the
    /// cache is enabled and no fresh entry exists.
    ///
    /// Failures to obtain or cache `OPTIONS` are non-fatal: the caller proceeds
    /// with the modification request regardless.
    async fn ensure_options_cached(&self, req: &Request) {
        let Some(cache) = &self.inner.options_cache else {
            return;
        };
        let path = normalize_service_path(&req.service);
        if cache
            .has_fresh(&self.inner.host, self.inner.port, &path)
            .await
        {
            return;
        }
        let options_req = Request::options(path.as_str());
        let Ok(response) = Box::pin(self.send(&options_req)).await else {
            return;
        };
        if !response.is_success() {
            return;
        }
        if let Some(entry) = CachedOptions::from_response(&response, cache.config()) {
            cache
                .store(&self.inner.host, self.inner.port, &path, entry)
                .await;
        }
    }

    /// Resolve the server-advertised `Transfer-*` policy for a modification
    /// request from the cached OPTIONS response (RFC 3507 §4.10.2).
    ///
    /// Returns [`EffectivePreview::Inherit`] when the OPTIONS cache is disabled,
    /// the request is not a modification, or no `Transfer-*` rule matches the
    /// request's file extension — the caller then uses `req.preview_size`
    /// unchanged.
    async fn resolve_effective_preview(&self, req: &Request) -> EffectivePreview {
        let Some(cache) = self.inner.options_cache.as_ref() else {
            return EffectivePreview::Inherit;
        };
        if !req.is_mod() {
            return EffectivePreview::Inherit;
        }
        let path = normalize_service_path(&req.service);
        let ext = file_ext_from_request(req);
        match cache
            .resolve_transfer(&self.inner.host, self.inner.port, &path, &ext)
            .await
        {
            Some(TransferAction::Skip) => EffectivePreview::Skip,
            Some(TransferAction::Full) => EffectivePreview::FullBody,
            Some(TransferAction::Preview(n)) => EffectivePreview::Preview(n),
            None => EffectivePreview::Inherit,
        }
    }

    /// Low-level send; called by [`send`](Self::send) and the streaming variant.
    ///
    /// `effective_preview` carries the resolved `Transfer-*` policy;
    /// [`EffectivePreview::Skip`] is handled by [`send`](Self::send) and never
    /// reaches here. `proxy_auth_value`, when `Some`, is written verbatim as the
    /// `Proxy-Authorization` ICAP header value (RFC 3507 §7.1 retry path).
    async fn send_inner(
        &self,
        req: &Request,
        effective_preview: EffectivePreview,
        proxy_auth_value: Option<&str>,
    ) -> IcapResult<ParsedResponse> {
        trace!(
            "client.send: method={}, service={}",
            req.method, req.service
        );

        let (mut stream, early) = self.acquire_conn().await?;
        if let Some(resp) = early {
            return Ok(resp);
        }

        let built = self.build_icap_request_bytes(
            req,
            effective_preview,
            proxy_auth_value,
            false,
            req.preview_ieof,
            false,
        )?;
        if let Err(write_err) = self.write_all(&mut stream, &built.bytes).await {
            if matches!(
                write_err,
                Error::Timeout(TimeoutError {
                    kind: TimeoutKind::ClientWrite,
                    ..
                })
            ) {
                return Err(write_err);
            }
            if let Ok((_code, hdr_buf)) =
                read_icap_headers(&mut stream, self.inner.max_response_header_bytes).await
                && let Ok(response_buf) = self
                    .read_response_buffer_with_headers(&mut stream, hdr_buf)
                    .await
            {
                return self.finalize_response(stream, response_buf).await;
            }
            return Err(write_err);
        }

        if let Err(flush_err) = self.flush(&mut stream).await {
            if matches!(
                flush_err,
                Error::Timeout(TimeoutError {
                    kind: TimeoutKind::ClientWrite,
                    ..
                })
            ) {
                return Err(flush_err);
            }
            if let Ok((_code, hdr_buf)) =
                read_icap_headers(&mut stream, self.inner.max_response_header_bytes).await
                && let Ok(response_buf) = self
                    .read_response_buffer_with_headers(&mut stream, hdr_buf)
                    .await
            {
                return self.finalize_response(stream, response_buf).await;
            }
            return Err(flush_err);
        }

        // OPTIONS: read headers + optional body, then parse, then decide reuse
        if req.method == Method::Options {
            let buf = self.read_response_buffer(&mut stream).await?;
            return self.finalize_response(stream, buf).await;
        }

        // Preview/100-continue negotiation
        if built.expect_continue {
            let (code, hdr_buf) = Self::with_timeout_as(
                self.continue_timeout(),
                read_icap_headers(&mut stream, self.inner.max_response_header_bytes),
                Error::client_continue_timeout,
            )
            .await?;

            if code == 100 {
                // send remaining body, then terminating chunk
                if let Some(rest) = built.remaining_body
                    && !rest.is_empty()
                {
                    self.write_chunk(&mut stream, &rest).await?;
                }
                self.write_all(&mut stream, b"0\r\n\r\n").await?;
                self.flush(&mut stream).await?;

                // read final response
                let response_buf = self.read_response_buffer(&mut stream).await?;
                return self.finalize_response(stream, response_buf).await;
            }
            // non-100 early final response
            let response_buf = self
                .read_response_buffer_with_headers(&mut stream, hdr_buf)
                .await?;
            return self.finalize_response(stream, response_buf).await;
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
    ) -> IcapResult<ParsedResponse> {
        let file = TokioFile::open(file_path).await?;
        Box::pin(self.send_streaming_reader(req, file)).await
    }

    /// Send a pre-formatted ICAP session as raw bytes.
    ///
    /// The bytes are written to the server verbatim — no ICAP headers are added,
    /// no `Encapsulated` offset is computed, and no preview negotiation takes
    /// place. The server's response is read back and returned as a
    /// [`ParsedResponse`] exactly like [`Client::send`].
    ///
    /// Use this when you want to hand-craft the wire bytes yourself, reproduce
    /// a specific packet capture, or send an unusual request that the [`Request`]
    /// builder does not support.
    ///
    /// Connection-policy (keep-alive / close) and the global operation timeout
    /// configured on the [`ClientBuilder`] still apply.
    ///
    /// # Example
    ///
    /// The HTTP request head and body are formatted manually, including the
    /// chunked body framing (`5\r\nHello\r\n0\r\n\r\n`) required by ICAP.
    /// The `Encapsulated` offsets must be correct: `req-hdr=0` means the
    /// HTTP request headers start at byte 0 of the encapsulated section, and
    /// `req-body=N` is the byte offset where the chunked body begins (i.e.
    /// the length of the HTTP request head block).
    ///
    /// ```no_run
    /// use icap_rs::Client;
    ///
    /// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::builder().host("127.0.0.1").port(1344).build();
    ///
    /// // Hand-crafted REQMOD: scan a small POST body.
    /// // `req-body` equals the byte length of the HTTP request head (`http_head_len`).
    /// let http_head = b"POST /upload HTTP/1.1\r\nHost: app\r\n\r\n";  // 36 bytes
    /// let http_head_len = http_head.len();  // must match the req-body offset below
    ///
    /// let raw = format!(
    ///     "REQMOD icap://127.0.0.1:1344/scan ICAP/1.0\r\n\
    ///      Host: 127.0.0.1\r\n\
    ///      Encapsulated: req-hdr=0, req-body={http_head_len}\r\n\r\n\
    ///      POST /upload HTTP/1.1\r\nHost: app\r\n\r\n\
    ///      5\r\nHello\r\n0\r\n\r\n"
    /// );
    ///
    /// let resp = client.send_raw_str(&raw).await?;
    /// println!("status: {}", resp.status_code());
    /// # Ok(()) }
    /// ```
    pub async fn send_raw(&self, raw: &[u8]) -> IcapResult<ParsedResponse> {
        let fut = async {
            let (mut stream, early) = self.acquire_conn().await?;
            if let Some(resp) = early {
                return Ok(resp);
            }
            self.write_all(&mut stream, raw).await?;
            self.flush(&mut stream).await?;
            let response_buf = self.read_response_buffer(&mut stream).await?;
            self.finalize_response(stream, response_buf).await
        };
        Box::pin(Self::with_timeout_as(
            self.inner.timeouts.operation,
            fut,
            Error::client_total_timeout,
        ))
        .await
    }

    /// Convenience wrapper around [`Client::send_raw`] that accepts a `&str`.
    ///
    /// Equivalent to `client.send_raw(raw.as_bytes())`.
    pub async fn send_raw_str(&self, raw: &str) -> IcapResult<ParsedResponse> {
        self.send_raw(raw.as_bytes()).await
    }

    /// Send a request and stream body bytes from any `AsyncRead` source using ICAP chunked encoding.
    ///
    /// This API avoids requiring an in-memory `Vec<u8>` body in the request object.
    /// Pair it with `Request::with_http_request_head(...)` / `with_http_response_head(...)`
    /// for head-only embedded HTTP.
    pub async fn send_streaming_reader<R>(
        &self,
        req: &Request,
        mut reader: R,
    ) -> IcapResult<ParsedResponse>
    where
        R: AsyncRead + Unpin + Send,
    {
        Box::pin(Self::with_timeout_as(
            self.inner.timeouts.operation,
            self.send_streaming_reader_inner(req, &mut reader),
            Error::client_total_timeout,
        ))
        .await
    }

    async fn send_streaming_reader_inner<R>(
        &self,
        req: &Request,
        reader: &mut R,
    ) -> IcapResult<ParsedResponse>
    where
        R: AsyncRead + Unpin + Send,
    {
        trace!(
            "client.send_streaming_reader: method={} service={}",
            req.method, req.service
        );

        let (mut stream, early) = self.acquire_conn().await?;
        if let Some(resp) = early {
            return Ok(resp);
        }

        let built = self.build_icap_request_bytes(
            req,
            EffectivePreview::Inherit,
            None,
            true,
            false,
            false,
        )?;
        self.write_all(&mut stream, &built.bytes).await?;

        match req.preview_size {
            None => {
                write_reader_chunks(&mut stream, reader, self.inner.timeouts.write).await?;
                self.write_all(&mut stream, b"0\r\n\r\n").await?;
                self.flush(&mut stream).await?;

                let response_buf = self.read_response_buffer(&mut stream).await?;
                return self.finalize_response(stream, response_buf).await;
            }
            Some(0) => {
                if req.preview_ieof {
                    self.write_all(&mut stream, b"0; ieof\r\n\r\n").await?;
                } else {
                    self.write_all(&mut stream, b"0\r\n\r\n").await?;
                }
            }
            Some(preview_size) => {
                let (preview, eof) = read_preview_bytes(reader, preview_size).await?;
                if !preview.is_empty() {
                    self.write_chunk(&mut stream, &preview).await?;
                }
                if eof {
                    self.write_all(&mut stream, b"0; ieof\r\n\r\n").await?;
                } else {
                    self.write_all(&mut stream, b"0\r\n\r\n").await?;
                }
            }
        }
        self.flush(&mut stream).await?;

        // Read server decision (100 Continue or final)
        let (code, hdr_buf) = Self::with_timeout_as(
            self.continue_timeout(),
            read_icap_headers(&mut stream, self.inner.max_response_header_bytes),
            Error::client_continue_timeout,
        )
        .await?;

        if code == 100 {
            write_reader_chunks(&mut stream, reader, self.inner.timeouts.write).await?;
            self.write_all(&mut stream, b"0\r\n\r\n").await?;
            self.flush(&mut stream).await?;

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

    /// Build the exact wire representation of a request, including preview tail when applicable.
    ///
    /// Set `streaming=true` when the body will be supplied later through a
    /// streaming API. This makes the generated wire advertise an encapsulated
    /// body offset without embedding body bytes in the returned buffer.
    pub fn get_request_wire(&self, req: &Request, streaming: bool) -> IcapResult<Vec<u8>> {
        let built = self.build_icap_request_bytes(
            req,
            EffectivePreview::Inherit,
            None,
            streaming || matches!(req.preview_size, Some(0)),
            req.preview_ieof,
            true,
        )?;
        let mut out = built.bytes;
        if req.is_mod()
            && matches!(req.preview_size, Some(0))
            && !request_has_non_empty_buffered_body(req)
        {
            if req.preview_ieof {
                out.extend_from_slice(b"0; ieof\r\n\r\n");
            } else {
                out.extend_from_slice(b"0\r\n\r\n");
            }
        }
        Ok(out)
    }

    async fn with_timeout_as<T, F>(
        dur: Option<Duration>,
        fut: F,
        timeout_error: fn(Duration) -> Error,
    ) -> Result<T, Error>
    where
        F: std::future::Future<Output = Result<T, Error>>,
    {
        if let Some(timeout_duration) = dur {
            timeout(timeout_duration, fut)
                .await
                .unwrap_or_else(|_| Err(timeout_error(timeout_duration)))
        } else {
            fut.await
        }
    }

    async fn with_io_timeout<T, F>(
        dur: Option<Duration>,
        fut: F,
        timeout_error: fn(Duration) -> Error,
    ) -> IcapResult<T>
    where
        F: std::future::Future<Output = std::io::Result<T>>,
    {
        Self::with_timeout_as(dur, async { fut.await.map_err(Error::Io) }, timeout_error).await
    }

    async fn write_all(&self, stream: &mut Conn, bytes: &[u8]) -> IcapResult<()> {
        Self::with_io_timeout(
            self.inner.timeouts.write,
            AsyncWriteExt::write_all(stream, bytes),
            Error::client_write_timeout,
        )
        .await
    }

    async fn flush(&self, stream: &mut Conn) -> IcapResult<()> {
        Self::with_io_timeout(
            self.inner.timeouts.write,
            AsyncWriteExt::flush(stream),
            Error::client_write_timeout,
        )
        .await
    }

    async fn write_chunk(&self, stream: &mut Conn, bytes: &[u8]) -> IcapResult<()> {
        Self::with_timeout_as(
            self.inner.timeouts.write,
            write_chunk(stream, bytes),
            Error::client_write_timeout,
        )
        .await
    }

    fn continue_timeout(&self) -> Option<Duration> {
        self.inner.timeouts.continue_after_preview
    }

    async fn read_response_buffer(&self, stream: &mut Conn) -> IcapResult<Vec<u8>> {
        let (_code, mut response_buf) =
            read_icap_headers(stream, self.inner.max_response_header_bytes).await?;
        read_icap_body_if_any(stream, &mut response_buf).await?;
        Ok(response_buf)
    }

    async fn read_response_buffer_with_headers(
        &self,
        stream: &mut Conn,
        mut response_buf: Vec<u8>,
    ) -> IcapResult<Vec<u8>> {
        read_icap_body_if_any(stream, &mut response_buf).await?;
        Ok(response_buf)
    }

    async fn finalize_response(
        &self,
        stream: Conn,
        response_buf: Vec<u8>,
    ) -> IcapResult<ParsedResponse> {
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
        effective_preview: EffectivePreview,
        proxy_auth_value: Option<&str>,
        force_has_body: bool,
        preview0_ieof: bool,
        limit_body_to_preview: bool,
    ) -> IcapResult<BuiltIcap> {
        req.validate_for_send()?;

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

        // Start-line. `normalize_service_path` yields a leading-slash path
        // (e.g. `/v1/scan`), matching the form the server parses and routes by.
        let service_path = normalize_service_path(&req.service);
        write!(
            &mut out,
            "{} icap://{}:{}{} ICAP/1.0\r\n",
            req.method, self.inner.host, self.inner.port, service_path
        )
        .map_err(Error::Io)?;

        // ICAP headers
        let host_value = self
            .inner
            .host_override
            .clone()
            .unwrap_or_else(|| self.inner.host.clone());

        // Encapsulated
        // When only building wire bytes (get_request / get_request_wire) we can
        // truncate the body copy to at most preview_size bytes.  The real send
        // path must keep the full body so that remaining_body is correct.
        let body_limit = limit_body_to_preview.then_some(req.preview_size).flatten();

        let (http_headers_bytes, http_body_bytes, enc_head_key, enc_body_key, original_body_len) =
            if req.is_mod() {
                req.embedded.as_ref().map_or_else(
                    || (Vec::new(), None, None, None, 0usize),
                    |emb| {
                        let (hdrs, body_from_emb, orig_len) =
                            serialize_embedded_http(emb, body_limit);
                        let hdr_len = hdrs.len();
                        let (hdr_key, body_key) = match req.method.as_str() {
                            "REQMOD" => ("req-hdr", "req-body"),
                            _ => ("res-hdr", "res-body"),
                        };
                        let will_send_body = force_has_body || body_from_emb.is_some();
                        if will_send_body && !hdrs.is_empty() {
                            (
                                hdrs,
                                body_from_emb,
                                Some((hdr_key, hdr_len)),
                                Some(body_key),
                                orig_len,
                            )
                        } else if !hdrs.is_empty() {
                            (hdrs, None, Some((hdr_key, hdr_len)), None, orig_len)
                        } else {
                            (hdrs, None, None, None, orig_len)
                        }
                    },
                )
            } else {
                (Vec::new(), None, None, None, 0usize)
            };

        let preview_for_wire = match effective_preview {
            EffectivePreview::Inherit => req.preview_size,
            EffectivePreview::FullBody => None,
            EffectivePreview::Preview(n) => Some(n),
            EffectivePreview::Skip => unreachable!("Skip must be handled before send_inner"),
        };

        // Write ICAP headers (except Encapsulated)
        write_icap_headers(
            &mut out,
            &self.inner.default_headers,
            &req.icap_headers,
            &host_value,
            req.allow_204,
            req.allow_206,
            preview_for_wire,
            matches!(self.inner.connection_policy, ConnectionPolicy::Close),
        );
        // Optional extra header (e.g. Proxy-Authorization for §7.1 retry).
        if let Some(auth) = proxy_auth_value {
            write!(&mut out, "Proxy-Authorization: {auth}\r\n").map_err(Error::Io)?;
        }
        // Encapsulated last + CRLF
        if let Some((hdr_key, hdr_len)) = enc_head_key {
            if let Some(body_key) = enc_body_key {
                write!(
                    &mut out,
                    "Encapsulated: {hdr_key}=0, {body_key}={hdr_len}\r\n"
                )
                .map_err(Error::Io)?;
            } else {
                write!(
                    &mut out,
                    "Encapsulated: {hdr_key}=0, null-body={hdr_len}\r\n"
                )
                .map_err(Error::Io)?;
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
            let (bytes, expect_continue, remaining) = build_preview_and_chunks(
                preview_for_wire,
                body_now,
                preview0_ieof,
                original_body_len,
            );
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

    /// Acquire a connection according to the configured policy and check for an
    /// early server response on keep-alive sockets.
    ///
    /// Returns `(conn, Some(resp))` when the server already sent a response
    /// before the client wrote anything (e.g. a `503` on connection limit).
    /// Returns `(conn, None)` in the normal case.
    async fn acquire_conn(&self) -> IcapResult<(Conn, Option<ParsedResponse>)> {
        let mut stream = match self.inner.connection_policy {
            ConnectionPolicy::KeepAlive => {
                let idle = self.inner.idle_conn.lock().await.take();
                if let Some(s) = idle {
                    s
                } else {
                    self.inner.connect().await?
                }
            }
            ConnectionPolicy::Close => self.inner.connect().await?,
        };

        // If the server already sent a response on a kept-alive *plain* TCP
        // socket, consume it now so callers never write into a closed pipe.
        if let Some(inner) = stream.plain_mut()
            && let Some(resp) =
                Self::try_read_early_response_now(inner, self.inner.max_response_header_bytes)
                    .await?
        {
            return Ok((stream, Some(resp)));
        }

        Ok((stream, None))
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
    async fn try_read_early_response_now(
        stream: &mut TcpStream,
        max_response_header_bytes: usize,
    ) -> IcapResult<Option<ParsedResponse>> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];

        loop {
            match stream.try_read(&mut tmp) {
                Ok(0) => {
                    return Ok(None);
                }
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(header_len) = find_double_crlf(&buf) {
                        check_icap_response_header_limit(header_len, max_response_header_bytes)?;
                        let _ = read_icap_body_if_any(stream, &mut buf).await;
                        return parse_icap_response(&buf).map(Some);
                    }
                    check_icap_response_header_limit(buf.len(), max_response_header_bytes)?;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return Ok(None);
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
}

const fn request_has_non_empty_buffered_body(req: &Request) -> bool {
    match &req.embedded {
        Some(
            crate::request::EmbeddedHttp::Req {
                body: crate::request::Body::Full { reader },
                ..
            }
            | crate::request::EmbeddedHttp::Resp {
                body: crate::request::Body::Full { reader },
                ..
            },
        ) => !reader.is_empty(),
        _ => false,
    }
}

impl ClientRef {
    async fn connect(&self) -> IcapResult<Conn> {
        let tcp = Client::with_timeout_as(
            self.timeouts.connect,
            async {
                TcpStream::connect((&*self.host, self.port))
                    .await
                    .map_err(Error::Io)
            },
            Error::client_connect_timeout,
        )
        .await?;

        #[cfg(feature = "tls-rustls")]
        if let Some(tls) = &self.tls {
            // Fallback SNI: explicit host_override, otherwise the connection host.
            let fallback = self.host_override.as_deref().unwrap_or(&self.host);
            let sni = tls.resolve_sni(fallback).to_string();
            let stream = tls.connect(tcp, &sni).await?;
            return Ok(Conn::Rustls { inner: stream });
        }

        Ok(Conn::Plain { inner: tcp })
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EffectivePreview {
    Inherit,
    Skip,
    FullBody,
    Preview(usize),
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
            return Err(Error::body("Unexpected EOF while reading response body"));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    Ok(())
}

async fn read_until_double_crlf_from<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    start: usize,
) -> IcapResult<usize> {
    let mut tmp = [0u8; 4096];
    loop {
        if start <= buf.len()
            && let Some(pos) = memchr::memmem::find(&buf[start..], b"\r\n\r\n")
        {
            return Ok(start + pos + 4);
        }

        let n = AsyncReadExt::read(stream, &mut tmp).await?;
        if n == 0 {
            return Err(Error::body(
                "Unexpected EOF while reading encapsulated HTTP headers",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

async fn write_reader_chunks<S, R>(
    stream: &mut S,
    reader: &mut R,
    write_timeout: Option<Duration>,
) -> IcapResult<()>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        Client::with_timeout_as(
            write_timeout,
            write_chunk(stream, &buf[..n]),
            Error::client_write_timeout,
        )
        .await?;
    }
}

async fn read_preview_bytes<R>(reader: &mut R, preview_size: usize) -> IcapResult<(Vec<u8>, bool)>
where
    R: AsyncRead + Unpin,
{
    let mut preview = vec![0u8; preview_size];
    let mut filled = 0;
    while filled < preview_size {
        let n = reader.read(&mut preview[filled..]).await?;
        if n == 0 {
            preview.truncate(filled);
            return Ok((preview, true));
        }
        filled += n;
    }
    Ok((preview, false))
}

/// If the ICAP response has an encapsulated body (`req-body`/`res-body`/`opt-body`),
/// read it to the end on the wire and append it to `buf`.
async fn read_icap_body_if_any<S>(stream: &mut S, buf: &mut Vec<u8>) -> IcapResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(h_end) = find_double_crlf(buf) else {
        return Err(Error::parse("Corrupted ICAP headers"));
    };

    let hdr_text = std::str::from_utf8(&buf[..h_end])
        .map_err(|_| Error::http_parse("Invalid headers utf8"))?;
    let enc = parse_encapsulated_header(hdr_text)?;

    if let Some(body_rel) = enc.req_body.or(enc.res_body).or(enc.opt_body) {
        let body_abs = h_end + body_rel;
        if buf.len() < body_abs {
            read_until_len(stream, buf, body_abs).await?;
        }
        let _ = read_chunked_to_end(stream, buf, body_abs).await?;
    } else if let Some(hdr_rel) = enc.req_hdr.or(enc.res_hdr) {
        let hdr_abs = h_end + hdr_rel;
        if buf.len() < hdr_abs {
            read_until_len(stream, buf, hdr_abs).await?;
        }
        let _ = read_until_double_crlf_from(stream, buf, hdr_abs).await?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// §4.10.2 helpers
// ---------------------------------------------------------------------------

/// Extract the file extension (lowercase, no leading dot) from the embedded
/// HTTP request URI in a REQMOD request.
///
/// Returns an empty string when there is no embedded HTTP request or the URI
/// path has no recognisable extension (e.g. bare API paths).
fn file_ext_from_request(req: &Request) -> String {
    let Some(crate::request::EmbeddedHttp::Req { head, .. }) = req.embedded() else {
        return String::new();
    };
    let path = head.uri().path();
    path.rsplit('.')
        .next()
        .filter(|e| !e.is_empty() && !e.contains('/'))
        .map(str::to_lowercase)
        .unwrap_or_default()
}

/// Return a synthetic `ICAP/1.0 204 No Content` response.
///
/// Used by the Transfer-Ignore code path to indicate that the ICAP server
/// approved pass-through without the client actually contacting it.
fn synthetic_204() -> IcapResult<ParsedResponse> {
    const BYTES: &[u8] =
        b"ICAP/1.0 204 No Content\r\nISTag: \"bypass\"\r\nEncapsulated: null-body=0\r\n\r\n";
    ParsedResponse::from_raw(BYTES)
        .map_err(|_| crate::error::Error::unexpected("failed to build synthetic 204"))
}

// ---------------------------------------------------------------------------
// §7.1 helpers
// ---------------------------------------------------------------------------

/// Encode `username:password` as an HTTP Basic authentication header value.
fn basic_auth_value(username: &str, password: &str) -> String {
    let credentials = format!("{username}:{password}");
    format!("Basic {}", base64_encode(credentials.as_bytes()))
}

/// Minimal standard-conforming RFC 4648 Base64 encoder (no external crate).
fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(TABLE[(n >> 18) as usize]);
        out.push(TABLE[((n >> 12) & 0x3f) as usize]);
        out.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 0x3f) as usize]
        } else {
            b'='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 0x3f) as usize]
        } else {
            b'='
        });
    }
    // SAFETY: TABLE contains only ASCII.
    String::from_utf8(out).unwrap_or_default()
}

// ---------------------------------------------------------------------------

fn parse_authority_with_scheme(uri: &str) -> IcapResult<(String, u16, bool)> {
    let s = uri.trim();
    let (tls, rest) = if let Some(r) = s.strip_prefix("icaps://") {
        (true, r)
    } else if let Some(r) = s.strip_prefix("icap://") {
        (false, r)
    } else {
        return Err(Error::invalid_uri(
            "URI must start with icap:// or icaps://",
        ));
    };

    let authority = rest.split('/').next().unwrap_or(rest);
    let (host, port) = if let Some(i) = authority.rfind(':') {
        let h = &authority[..i];
        let p: u16 = authority[i + 1..]
            .parse()
            .map_err(|_| Error::invalid_uri("Invalid port"))?;
        (h.to_string(), p)
    } else {
        (authority.to_string(), if tls { 11344 } else { 1344 })
    };

    if host.is_empty() {
        return Err(Error::invalid_uri("Empty host in authority"));
    }
    Ok((host, port, tls))
}

#[cfg(test)]
fn append_to_allow(headers: &mut HeaderMap, code: &str) {
    use http::{HeaderName, HeaderValue};

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
const fn is_virtual_icap_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("host")
        || name.eq_ignore_ascii_case("encapsulated")
        || name.eq_ignore_ascii_case("allow")
        || name.eq_ignore_ascii_case("preview")
        || name.eq_ignore_ascii_case("connection")
}

#[allow(clippy::too_many_arguments)]
fn write_icap_headers(
    out: &mut Vec<u8>,
    default_headers: &HeaderMap,
    req_headers: &HeaderMap,
    host_value: &str,
    allow_204: bool,
    allow_206: bool,
    preview_size: Option<usize>,
    connection_close: bool,
) {
    // Host is always emitted; request-level Host overrides computed host.
    out.extend_from_slice(canon_icap_header("host").as_bytes());
    out.extend_from_slice(b": ");
    if let Some(v) = req_headers.get("Host") {
        out.extend_from_slice(v.as_bytes());
    } else {
        out.extend_from_slice(host_value.as_bytes());
    }
    out.extend_from_slice(b"\r\n");

    // RFC 3507 §4.2: signal graceful shutdown to the server.
    if connection_close {
        out.extend_from_slice(b"Connection: close\r\n");
    }

    let req_names: HashSet<&str> = req_headers.keys().map(http::HeaderName::as_str).collect();

    // Default headers first, unless overridden by request-level headers.
    for (name, value) in default_headers {
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
    for (name, value) in req_headers {
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
        if allow_204
            && !allow
                .split(',')
                .any(|p| p.trim().eq_ignore_ascii_case("204"))
        {
            if !allow.is_empty() {
                allow.push_str(", ");
            }
            allow.push_str("204");
        }
        if allow_206
            && !allow
                .split(',')
                .any(|p| p.trim().eq_ignore_ascii_case("206"))
        {
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
}

fn response_wants_close(resp: &ParsedResponse) -> bool {
    let Some(v) = resp.headers().get(http::header::CONNECTION) else {
        return false;
    };

    let Ok(s) = v.to_str() else {
        return true;
    };

    s.split(',').any(|t| t.trim().eq_ignore_ascii_case("close"))
}

const CRLFCRLF: u32 = 0x0D0A_0D0A;

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
    Some(u16::from(d0 - b'0') * 100 + u16::from(d1 - b'0') * 10 + u16::from(d2 - b'0'))
}

fn check_icap_response_header_limit(size: usize, max: usize) -> IcapResult<()> {
    if size > max {
        return Err(Error::header(format!(
            "ICAP response headers too large: {size} bytes (max {max})"
        )));
    }
    Ok(())
}

async fn read_icap_headers<S>(stream: &mut S, max_header_bytes: usize) -> IcapResult<(u16, Vec<u8>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];

    let mut status_line_end: Option<usize> = None;
    let mut hdr_end: Option<usize> = None;

    let mut code: Option<u16> = None;

    let mut win: u32 = 0;
    let mut prev: Option<u8> = None;

    loop {
        let n = AsyncReadExt::read(stream, &mut tmp)
            .await
            .map_err(Error::Io)?;

        if n == 0 {
            // EOF
            if buf.is_empty() {
                return Err(Error::Protocol(crate::error::ProtocolError::EarlyClose));
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
                return Err(Error::Protocol(crate::error::ProtocolError::EarlyClose));
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

                win = (win << 8) | u32::from(b);
                if hdr_end.is_none() && win == CRLFCRLF {
                    hdr_end = Some(i + 1);
                }

                prev = Some(b);
            }
        }

        if code.is_none()
            && let Some(end) = status_line_end
        {
            let line = &buf[..end];
            if let Some(c) = parse_status_code_from_status_line(line) {
                code = Some(c);
            }
        }

        // Legacy shortcut intentionally disabled.
        //
        // Previous behavior treated any parsed 4xx/5xx status line as a
        // complete ICAP response, normalized the buffer to end with CRLFCRLF,
        // and returned immediately even while the TCP connection stayed open.
        // That makes single-line legacy errors complete quickly, but it also
        // truncates valid error responses whose headers arrive in a later TCP
        // read. EOF handling above is the active compatibility path for peers
        // that actually close after a single-line error.
        //
        // if let Some(c) = code
        //     && (400..=599).contains(&c)
        //     && hdr_end.is_none()
        // {
        //     if !buf.ends_with(b"\r\n\r\n") {
        //         if buf.ends_with(b"\r\n") {
        //             buf.extend_from_slice(b"\r\n");
        //         } else {
        //             buf.extend_from_slice(b"\r\n\r\n");
        //         }
        //     }
        //     return Ok((c, buf));
        // }

        if let Some(header_len) = hdr_end {
            check_icap_response_header_limit(header_len, max_header_bytes)?;
            let c = code.ok_or_else(|| Error::parse("missing/bad status code"))?;
            return Ok((c, buf));
        }

        check_icap_response_header_limit(buf.len(), max_header_bytes)?;
    }
}

/// Encode body bytes into ICAP chunked preview wire format.
///
/// `original_body_len` is the **true** full body length and may be larger than
/// `body.len()` when `body` was truncated to `preview_size` by the caller (the
/// dry-run `get_request` path).  It is used to determine whether a `0; ieof`
/// or a plain `0\r\n\r\n` terminator is correct — i.e. whether there is
/// remaining data beyond the preview window — without requiring the full body
/// bytes to be in memory.
fn build_preview_and_chunks(
    preview_size: Option<usize>,
    body: Vec<u8>,
    preview0_ieof: bool,
    original_body_len: usize,
) -> (Vec<u8>, bool, Option<Vec<u8>>) {
    let mut out = Vec::new();
    match preview_size {
        None => {
            if !body.is_empty() {
                write_chunk_into(&mut out, &body);
            }
            out.extend_from_slice(b"0\r\n\r\n");
            (out, false, None)
        }
        Some(0) => {
            // body is empty after a body_limit=Some(0) truncation even when the
            // original had bytes.  Use original_body_len to decide the terminator.
            let has_body = original_body_len > 0;
            if has_body {
                out.extend_from_slice(b"0\r\n\r\n");
                (out, true, Some(body))
            } else if preview0_ieof {
                out.extend_from_slice(b"0; ieof\r\n\r\n");
                (out, false, None)
            } else {
                out.extend_from_slice(b"0\r\n\r\n");
                (out, true, Some(Vec::new()))
            }
        }
        Some(ps) => {
            // How many preview bytes we would send in a full (non-truncated) pass.
            let send_n = original_body_len.min(ps);
            // How many we actually have (body may be a truncated slice).
            let actual_send = body.len().min(send_n);
            if actual_send > 0 {
                write_chunk_into(&mut out, &body[..actual_send]);
            }
            // Remaining bytes beyond the preview window (by original length).
            let rest = original_body_len.saturating_sub(send_n);
            if rest == 0 {
                out.extend_from_slice(b"0; ieof\r\n\r\n");
                (out, false, None)
            } else {
                out.extend_from_slice(b"0\r\n\r\n");
                // body[actual_send..] is the remainder we actually have in memory;
                // may be empty when body was truncated (get_request path).
                (out, true, Some(body[actual_send..].to_vec()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::find_double_crlf;
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
            .map(std::string::ToString::to_string)
    }

    #[fixture]
    fn client() -> Client {
        Client::builder()
            .host("icap.example")
            .port(1344)
            .default_header("x-trace-id", "test-123")
            .unwrap()
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

    async fn read_until_contains(stream: &mut TcpStream, needle: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        loop {
            if memchr::memmem::find(&buf, needle).is_some() {
                return buf;
            }
            let n = stream.read(&mut tmp).await.unwrap();
            assert!(n > 0, "connection closed before expected bytes arrived");
            buf.extend_from_slice(&tmp[..n]);
        }
    }

    fn streaming_req(preview: Option<usize>) -> Request {
        let http = HttpReq::builder()
            .method("POST")
            .uri("/scan")
            .version(Version::HTTP_11)
            .header(header::HOST, "app")
            .header(header::CONTENT_LENGTH, "7")
            .body(())
            .unwrap();

        let req = Request::reqmod("scan")
            .with_http_request_head(http)
            .unwrap();
        if let Some(preview_size) = preview {
            req.preview(preview_size)
        } else {
            req
        }
    }

    async fn spawn_raw_icap_server<F, Fut>(handler: F) -> u16
    where
        F: FnOnce(TcpStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handler(stream).await;
        });
        port
    }

    async fn server_write(server: TcpStream, bytes: &[u8], keep_open: bool) {
        use tokio::io::AsyncWriteExt;
        let mut s = server;
        if !bytes.is_empty() {
            s.write_all(bytes).await.unwrap();
            let _ = s.flush().await;
        }
        if keep_open {
            let () = future::pending::<()>().await;
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
            (Err(_), Err(())) => {}
            other => panic!("mismatch: {other:?}"),
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

    #[test]
    fn try_user_agent_rejects_invalid_header_value() {
        let err = Client::builder()
            .try_user_agent("bad\r\nvalue")
            .expect_err("invalid header value should be rejected");

        assert!(matches!(
            err,
            Error::Protocol(ProtocolError::HeaderValue(_))
        ));
    }

    #[tokio::test]
    async fn timeout_caps_whole_send_operation() {
        let port = spawn_raw_icap_server(|mut stream| async move {
            let _request = read_until_contains(&mut stream, b"\r\n\r\n").await;
            let () = future::pending::<()>().await;
        })
        .await;

        let client = Client::builder()
            .host("127.0.0.1")
            .port(port)
            .timeout(Some(Duration::from_millis(50)))
            .build();

        let err = client
            .send(&Request::options("scan"))
            .await
            .expect_err("operation timeout should fire");

        assert!(
            matches!(err, Error::Timeout(TimeoutError { kind: TimeoutKind::ClientTotal, duration: d }) if d == Duration::from_millis(50))
        );
    }

    #[tokio::test]
    async fn continue_timeout_applies_to_preview_decision() {
        let port = spawn_raw_icap_server(|mut stream| async move {
            let _preview = read_until_contains(&mut stream, b"0\r\n\r\n").await;
            let () = future::pending::<()>().await;
        })
        .await;

        let client = Client::builder()
            .host("127.0.0.1")
            .port(port)
            .continue_timeout(Some(Duration::from_millis(50)))
            .build();

        let err = client
            .send_streaming_reader(&streaming_req(Some(0)), &b"ABCDEFG"[..])
            .await
            .expect_err("continue timeout should fire");

        assert!(
            matches!(err, Error::Timeout(TimeoutError { kind: TimeoutKind::ClientContinue, duration: d }) if d == Duration::from_millis(50))
        );
    }

    #[tokio::test]
    async fn write_timeout_applies_to_streaming_body_chunks() {
        let (mut client, _server) = tokio::io::duplex(1);
        let mut reader = tokio::io::repeat(0x61).take(1024 * 1024);

        let err = write_reader_chunks(&mut client, &mut reader, Some(Duration::from_millis(50)))
            .await
            .expect_err("write timeout should fire");

        assert!(
            matches!(err, Error::Timeout(TimeoutError { kind: TimeoutKind::ClientWrite, duration: d }) if d == Duration::from_millis(50))
        );
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
        let body_vec = body.to_vec();
        let orig_len = body_vec.len();
        let (bytes, got_expect_continue, rest_opt) =
            build_preview_and_chunks(preview, body_vec, ieof, orig_len);

        assert!(bytes.starts_with(expected_prefix));
        assert_eq!(got_expect_continue, expect_continue);

        match (rest_opt.as_deref(), rest) {
            (None, None) => {}
            (Some(a), Some(b)) => assert_eq!(a, b),
            other => panic!("rest mismatch: {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_raw_delivers_verbatim_bytes_and_parses_response() {
        let port = spawn_raw_icap_server(|mut stream| async move {
            let wire = read_until_contains(&mut stream, b"\r\n\r\n").await;
            let text = String::from_utf8_lossy(&wire);
            assert!(text.starts_with("OPTIONS icap://127.0.0.1:"));
            assert!(text.contains("X-Custom: yes"));

            stream
                .write_all(
                    b"ICAP/1.0 200 OK\r\n\
                      ISTag: \"raw-test\"\r\n\
                      Methods: REQMOD\r\n\
                      Encapsulated: null-body=0\r\n\r\n",
                )
                .await
                .unwrap();
        })
        .await;

        let client = Client::builder().host("127.0.0.1").port(port).build();

        let raw = format!(
            "OPTIONS icap://127.0.0.1:{port}/echo ICAP/1.0\r\n\
             Host: 127.0.0.1:{port}\r\n\
             X-Custom: yes\r\n\
             Encapsulated: null-body=0\r\n\r\n"
        );

        let resp = timeout(Duration::from_millis(500), client.send_raw(raw.as_bytes()))
            .await
            .expect("send_raw timed out")
            .expect("send_raw returned error");

        assert_eq!(resp.status_code, http::StatusCode::OK);
        assert_eq!(
            resp.headers().get("istag").map(|v| v.to_str().unwrap()),
            Some("\"raw-test\"")
        );
    }

    #[tokio::test]
    async fn send_raw_str_is_equivalent_to_send_raw() {
        let port = spawn_raw_icap_server(|mut stream| async move {
            let _ = read_until_contains(&mut stream, b"\r\n\r\n").await;
            stream
                .write_all(
                    b"ICAP/1.0 200 OK\r\n\
                      ISTag: \"str-test\"\r\n\
                      Methods: REQMOD\r\n\
                      Encapsulated: null-body=0\r\n\r\n",
                )
                .await
                .unwrap();
        })
        .await;

        let client = Client::builder().host("127.0.0.1").port(port).build();

        let raw = format!(
            "OPTIONS icap://127.0.0.1:{port}/echo ICAP/1.0\r\n\
             Host: 127.0.0.1:{port}\r\n\
             Encapsulated: null-body=0\r\n\r\n"
        );

        let resp = timeout(Duration::from_millis(500), client.send_raw_str(&raw))
            .await
            .expect("send_raw_str timed out")
            .expect("send_raw_str returned error");

        assert_eq!(resp.status_code, http::StatusCode::OK);
    }

    #[tokio::test]
    async fn rfc_streaming_without_preview_sends_body_before_reading_response() {
        let port = spawn_raw_icap_server(|mut stream| async move {
            let wire = read_until_contains(&mut stream, b"5\r\nHELLO\r\n0\r\n\r\n").await;
            let text = String::from_utf8_lossy(&wire);
            assert!(text.contains("Encapsulated: req-hdr=0, req-body="));
            assert!(!text.contains("\r\nPreview:"));

            stream
                .write_all(
                    b"ICAP/1.0 204 No Content\r\n\
                      ISTag: \"stream-test\"\r\n\
                      Encapsulated: null-body=0\r\n\r\n",
                )
                .await
                .unwrap();
        })
        .await;

        let client = Client::builder().host("127.0.0.1").port(port).build();
        let resp = timeout(
            Duration::from_millis(500),
            client.send_streaming_reader(&streaming_req(None), &b"HELLO"[..]),
        )
        .await
        .expect("client waited for response before streaming body")
        .unwrap();

        assert_eq!(resp.status_code, http::StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn rfc_streaming_preview_sends_remainder_after_100_continue() {
        let port = spawn_raw_icap_server(|mut stream| async move {
            let preview = read_until_contains(&mut stream, b"4\r\nABCD\r\n0\r\n\r\n").await;
            let text = String::from_utf8_lossy(&preview);
            assert!(text.contains("\r\nPreview: 4\r\n"));

            stream
                .write_all(b"ICAP/1.0 100 Continue\r\n\r\n")
                .await
                .unwrap();

            let remainder = read_until_contains(&mut stream, b"3\r\nEFG\r\n0\r\n\r\n").await;
            assert!(
                String::from_utf8_lossy(&remainder).contains("3\r\nEFG\r\n0\r\n\r\n"),
                "missing chunked remainder"
            );

            stream
                .write_all(
                    b"ICAP/1.0 204 No Content\r\n\
                      ISTag: \"stream-test\"\r\n\
                      Encapsulated: null-body=0\r\n\r\n",
                )
                .await
                .unwrap();
        })
        .await;

        let client = Client::builder().host("127.0.0.1").port(port).build();
        let resp = client
            .send_streaming_reader(&streaming_req(Some(4)), &b"ABCDEFG"[..])
            .await
            .unwrap();

        assert_eq!(resp.status_code, http::StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn rfc_streaming_preview_marks_ieof_when_reader_ends_inside_preview() {
        let port = spawn_raw_icap_server(|mut stream| async move {
            let preview = read_until_contains(&mut stream, b"3\r\nABC\r\n0; ieof\r\n\r\n").await;
            let text = String::from_utf8_lossy(&preview);
            assert!(text.contains("\r\nPreview: 8\r\n"));

            stream
                .write_all(
                    b"ICAP/1.0 204 No Content\r\n\
                      ISTag: \"stream-test\"\r\n\
                      Encapsulated: null-body=0\r\n\r\n",
                )
                .await
                .unwrap();
        })
        .await;

        let client = Client::builder().host("127.0.0.1").port(port).build();
        let resp = client
            .send_streaming_reader(&streaming_req(Some(8)), &b"ABC"[..])
            .await
            .unwrap();

        assert_eq!(resp.status_code, http::StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn rfc_streaming_preview0_sends_body_after_100_continue() {
        let port = spawn_raw_icap_server(|mut stream| async move {
            let preview = read_until_contains(&mut stream, b"0\r\n\r\n").await;
            let text = String::from_utf8_lossy(&preview);
            assert!(text.contains("\r\nPreview: 0\r\n"));
            assert!(!text.contains("5\r\nHELLO\r\n"));

            stream
                .write_all(b"ICAP/1.0 100 Continue\r\n\r\n")
                .await
                .unwrap();

            let body = read_until_contains(&mut stream, b"5\r\nHELLO\r\n0\r\n\r\n").await;
            assert!(
                String::from_utf8_lossy(&body).contains("5\r\nHELLO\r\n0\r\n\r\n"),
                "missing full body after 100 Continue"
            );

            stream
                .write_all(
                    b"ICAP/1.0 204 No Content\r\n\
                      ISTag: \"stream-test\"\r\n\
                      Encapsulated: null-body=0\r\n\r\n",
                )
                .await
                .unwrap();
        })
        .await;

        let client = Client::builder().host("127.0.0.1").port(port).build();
        let resp = client
            .send_streaming_reader(&streaming_req(Some(0)), &b"HELLO"[..])
            .await
            .unwrap();

        assert_eq!(resp.status_code, http::StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn rfc_streaming_preview0_final_response_skips_body_upload() {
        let port = spawn_raw_icap_server(|mut stream| async move {
            let preview = read_until_contains(&mut stream, b"0\r\n\r\n").await;
            let text = String::from_utf8_lossy(&preview);
            assert!(text.contains("\r\nPreview: 0\r\n"));
            assert!(!text.contains("5\r\nHELLO\r\n"));

            stream
                .write_all(
                    b"ICAP/1.0 204 No Content\r\n\
                      ISTag: \"stream-test\"\r\n\
                      Encapsulated: null-body=0\r\n\r\n",
                )
                .await
                .unwrap();
        })
        .await;

        let client = Client::builder().host("127.0.0.1").port(port).build();
        let resp = client
            .send_streaming_reader(&streaming_req(Some(0)), &b"HELLO"[..])
            .await
            .unwrap();

        assert_eq!(resp.status_code, http::StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn rfc_streaming_preview0_ieof_sends_ieof_and_reads_final_response() {
        let port = spawn_raw_icap_server(|mut stream| async move {
            let preview = read_until_contains(&mut stream, b"0; ieof\r\n\r\n").await;
            let text = String::from_utf8_lossy(&preview);
            assert!(text.contains("\r\nPreview: 0\r\n"));

            stream
                .write_all(
                    b"ICAP/1.0 204 No Content\r\n\
                      ISTag: \"stream-test\"\r\n\
                      Encapsulated: null-body=0\r\n\r\n",
                )
                .await
                .unwrap();
        })
        .await;

        let client = Client::builder().host("127.0.0.1").port(port).build();
        let req = streaming_req(Some(0)).preview_ieof();
        let resp = client
            .send_streaming_reader(&req, tokio::io::empty())
            .await
            .unwrap();

        assert_eq!(resp.status_code, http::StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn rfc_streaming_preview_final_response_skips_remainder_upload() {
        let port = spawn_raw_icap_server(|mut stream| async move {
            let preview = read_until_contains(&mut stream, b"4\r\nABCD\r\n0\r\n\r\n").await;
            let text = String::from_utf8_lossy(&preview);
            assert!(text.contains("\r\nPreview: 4\r\n"));
            assert!(!text.contains("3\r\nEFG\r\n"));

            stream
                .write_all(
                    b"ICAP/1.0 204 No Content\r\n\
                      ISTag: \"stream-test\"\r\n\
                      Encapsulated: null-body=0\r\n\r\n",
                )
                .await
                .unwrap();
        })
        .await;

        let client = Client::builder().host("127.0.0.1").port(port).build();
        let resp = client
            .send_streaming_reader(&streaming_req(Some(4)), &b"ABCDEFG"[..])
            .await
            .unwrap();

        assert_eq!(resp.status_code, http::StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn rfc_streaming_preview_empty_reader_sends_ieof() {
        let port = spawn_raw_icap_server(|mut stream| async move {
            let preview = read_until_contains(&mut stream, b"0; ieof\r\n\r\n").await;
            let text = String::from_utf8_lossy(&preview);
            assert!(text.contains("\r\nPreview: 8\r\n"));

            stream
                .write_all(
                    b"ICAP/1.0 204 No Content\r\n\
                      ISTag: \"stream-test\"\r\n\
                      Encapsulated: null-body=0\r\n\r\n",
                )
                .await
                .unwrap();
        })
        .await;

        let client = Client::builder().host("127.0.0.1").port(port).build();
        let resp = client
            .send_streaming_reader(&streaming_req(Some(8)), tokio::io::empty())
            .await
            .unwrap();

        assert_eq!(resp.status_code, http::StatusCode::NO_CONTENT);
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
            .with_http_request(http)
            .unwrap();

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

    #[test]
    fn reqmod_header_only_uses_null_body_offset() {
        let http = HttpReq::builder()
            .method("GET")
            .uri("http://origin.example/")
            .header(header::HOST, "origin.example")
            .body(Vec::<u8>::new())
            .unwrap();

        let req = Request::reqmod("echo").with_http_request(http).unwrap();
        let wire = client().get_request_wire(&req, false).unwrap();
        let head = extract_headers_text(&wire);
        let enc = find_header_line(&head, "Encapsulated").unwrap();

        assert!(enc.contains("req-hdr=0"));
        assert!(
            enc.contains("null-body="),
            "header-only REQMOD must delimit the embedded HTTP head for strict servers: {enc}"
        );
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
            .with_http_request(http)
            .unwrap();
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

    #[test]
    fn preview_zero_wire_for_buffered_body_has_single_preview_marker() {
        let http = HttpReq::builder()
            .method("POST")
            .uri("/scan")
            .header(header::HOST, "x")
            .body(b"PAYLOAD".to_vec())
            .unwrap();

        let req = Request::reqmod("icap/test")
            .preview(0)
            .with_http_request(http)
            .unwrap();

        let wire = client().get_request_wire(&req, false).unwrap();
        let marker_count = wire
            .windows(b"0\r\n\r\n".len())
            .filter(|w| *w == b"0\r\n\r\n")
            .count();

        assert_eq!(marker_count, 1);
    }

    #[test]
    fn mismatched_embedded_message_is_rejected_before_serialization() {
        let http = http::Response::builder()
            .status(http::StatusCode::OK)
            .body(Vec::<u8>::new())
            .unwrap();

        let err = Request::reqmod("icap/test")
            .with_http_response(http)
            .expect_err("REQMOD must reject embedded HTTP responses");

        assert!(matches!(
            err,
            Error::Protocol(ProtocolError::Serialization(_))
        ));
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
    /// Expectation: keep reading until the full header terminator or EOF.
    #[tokio::test]
    async fn error_404_single_crlf_kept_open_times_out() {
        let (mut client, server) = connect_pair().await;

        tokio::spawn(server_write(
            server,
            b"ICAP/1.0 404 ICAP Service not found\r\n",
            true,
        ));

        let res = timeout(
            Duration::from_millis(50),
            read_icap_headers(&mut client, crate::DEFAULT_ICAP_HEADER_BYTES),
        )
        .await;
        assert!(res.is_err());
    }

    /// 2) 404 with headers and proper CRLFCRLF.
    #[tokio::test]
    async fn error_404_with_headers_and_double_crlf() {
        let (mut client, server) = connect_pair().await;

        let wire = b"ICAP/1.0 404 ICAP Service not found\r\nISTag: x\r\nDate: Thu, 21 Aug 2025 17:00:00 GMT\r\n\r\n";
        tokio::spawn(server_write(server, wire, false));

        let (code, buf) = timeout(
            Duration::from_millis(300),
            read_icap_headers(&mut client, crate::DEFAULT_ICAP_HEADER_BYTES),
        )
        .await
        .expect("client hung on proper 404")
        .expect("read_icap_headers failed");

        assert_eq!(code, 404);
        assert!(buf.ends_with(b"\r\n\r\n"));
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("ISTag: x"));
        assert!(text.contains("Date: "));
    }

    #[tokio::test]
    async fn error_404_split_headers_are_preserved() {
        let (mut client, mut server) = connect_pair().await;

        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;

            server
                .write_all(b"ICAP/1.0 404 ICAP Service not found\r\n")
                .await
                .unwrap();
            server.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(25)).await;
            server
                .write_all(b"ISTag: split-test\r\nX-Late: yes\r\n\r\n")
                .await
                .unwrap();
            server.flush().await.unwrap();
        });

        let (code, buf) = timeout(
            Duration::from_millis(300),
            read_icap_headers(&mut client, crate::DEFAULT_ICAP_HEADER_BYTES),
        )
        .await
        .expect("client hung on split 404")
        .expect("read_icap_headers failed");

        assert_eq!(code, 404);
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("ISTag: split-test"));
        assert!(text.contains("X-Late: yes"));
    }

    /// 3) 404 with headers but EOF before CRLFCRLF.
    #[tokio::test]
    async fn error_404_headers_then_eof_before_double_crlf() {
        let (mut client, server) = connect_pair().await;

        // Status + one header + CRLF, then EOF (socket close)
        let wire = b"ICAP/1.0 404 ICAP Service not found\r\nISTag: y\r\n";
        tokio::spawn(server_write(server, wire, false));

        let (code, buf) = timeout(
            Duration::from_millis(300),
            read_icap_headers(&mut client, crate::DEFAULT_ICAP_HEADER_BYTES),
        )
        .await
        .expect("client hung on 404 with EOF")
        .expect("read_icap_headers failed");

        assert_eq!(code, 404);
        assert!(buf.ends_with(b"\r\n\r\n"), "normalized to CRLFCRLF on EOF");
        let text = String::from_utf8(buf).unwrap();
        assert!(
            text.contains("ISTag: y"),
            "header bytes should be preserved"
        );
    }

    /// 4) Non-error: 200 OK + single CRLF, connection kept open.
    /// Expectation: in strict mode for non-errors, method should not return.
    #[tokio::test]
    async fn non_error_200_single_crlf_kept_open_times_out() {
        let (mut client, server) = connect_pair().await;

        tokio::spawn(server_write(server, b"ICAP/1.0 200 OK\r\n", true));
        let res = timeout(
            Duration::from_millis(50),
            read_icap_headers(&mut client, crate::DEFAULT_ICAP_HEADER_BYTES),
        )
        .await;
        assert!(res.is_err());
    }
}
