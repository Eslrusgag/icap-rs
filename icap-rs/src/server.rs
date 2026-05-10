//! # ICAP server implementation in Rust.
//!
//! ICAP server with per-service routing and **one handler that can serve multiple
//! ICAP methods** (`REQMOD`, `RESPMOD`). The server:
//!
//! - Supports `OPTIONS`, `REQMOD`, `RESPMOD`;
//! - Lets you register services with **one handler** and a **list of allowed methods** via
//!   [`ServerBuilder::route`];
//! - **Supports internal rerouting** via [`ServerBuilder::alias`] and [`ServerBuilder::default_service`]:
//!   map one service name to another (e.g. `/` → `scan`) and choose the default service for empty or `/` path;
//! - Automatically answers `OPTIONS` per service using the allowed methods;
//! - Returns `404` for unknown services and `405` for unsupported methods;
//! - Reads encapsulated **chunked bodies to completion** before parsing (avoids premature close
//!   observed by clients like `c-icap-client`);
//! - Can limit concurrent connections via a semaphore.
//! ## Quick example
//!
//! ```rust,no_run
//! use icap_rs::{Server, Method, Request, Response, StatusCode};
//! use icap_rs::error::IcapResult;
//! use icap_rs::server::options::ServiceOptions;
//!
//! const ISTAG: &str = "scan-1.0";
//!
//! #[tokio::main]
//! async fn main() -> IcapResult<()> {
//!     let server = Server::builder()
//!         .bind("127.0.0.1:1344")
//!         // One handler for REQMOD and RESPMOD of the "scan" service.
//!         .route(
//!             "scan",
//!             [Method::ReqMod, Method::RespMod],
//!             |req: Request| async move {
//!                 match req.method {
//!                     Method::ReqMod => Ok(Response::no_content().try_set_istag(ISTAG)?),
//!                     Method::RespMod => Ok(Response::no_content().try_set_istag(ISTAG)?),
//!                     Method::Options => unreachable!("OPTIONS is handled automatically by the server"),
//!                 }
//!             },
//!             Some(ServiceOptions::new().with_static_istag(ISTAG)
//!                 .with_service("Scan Service")
//!                 .add_allow("204")
//!                 .with_preview(2048))
//!         )
//!         // If a client uses `icap://host/`, internally route it to the "scan" service.
//!         .default_service("scan")
//!         .alias("/", "scan")
//!         .with_max_connections(128)
//!         .build()
//!         .await?;
//!
//!     server.run().await
//! }
//! ```
//!
//! When a client sends `OPTIONS icap://host/scan`, the server responds with
//! `Methods: REQMOD, RESPMOD` based on the registration above. If a method not in
//! the list is used, `405 Method Not Allowed` is returned; unknown services yield `404`.

pub mod options;

use memchr::{memchr, memmem};
#[cfg(feature = "tls-rustls")]
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
#[cfg(feature = "tls-rustls")]
use rustls::{RootCertStore, ServerConfig};
use std::borrow::Cow;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::future::Future;
#[cfg(feature = "tls-rustls")]
use std::path::PathBuf;
use std::str;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{error, trace, warn};

use crate::error::IcapResult;
use crate::parser::icap::find_double_crlf;
use crate::parser::read_chunked_to_end;
use crate::request::{Body, Remainder, parse_icap_request};
pub use crate::server::options::{ServiceOptions, TransferBehavior};
use crate::{EmbeddedHttp, Method, Request, Response, StatusCode};
use bytes::Bytes;
use smallvec::SmallVec;
#[cfg(feature = "tls-rustls")]
use tokio_rustls::TlsAcceptor;

/// A per-service ICAP handler.
///
/// One handler can serve multiple ICAP methods declared for a service via
/// [`ServerBuilder::route`].
type RequestHandler = Box<
    dyn Fn(Request) -> std::pin::Pin<Box<dyn Future<Output = IcapResult<PreviewDecision>> + Send>>
        + Send
        + Sync,
>;

/// Decision returned by a preview-aware route handler.
///
/// Returning [`PreviewDecision::Respond`] lets a service send a final ICAP
/// response after seeing only preview bytes, before the server emits
/// `ICAP/1.0 100 Continue` and before the client uploads the remainder.
#[derive(Debug)]
#[must_use]
pub enum PreviewDecision {
    Continue,
    Respond(Response),
}

/// Return type adapter for route handlers.
///
/// Handlers returning `IcapResult<Response>` keep the full-body behavior: the
/// server reads the whole request body before invoking them. Handlers returning
/// `IcapResult<PreviewDecision>` are preview-aware and may be invoked before
/// `100 Continue`. If a preview-aware handler returns
/// [`PreviewDecision::Continue`], the server sends `100 Continue`, reads the
/// remainder, and invokes the same route again with `Body::Full`.
pub trait RouteOutput: Send + 'static {
    const PREVIEW_AWARE: bool;

    fn into_preview_decision(self) -> IcapResult<PreviewDecision>;
}

impl RouteOutput for IcapResult<Response> {
    const PREVIEW_AWARE: bool = false;

    fn into_preview_decision(self) -> IcapResult<PreviewDecision> {
        self.map(PreviewDecision::Respond)
    }
}

impl RouteOutput for IcapResult<PreviewDecision> {
    const PREVIEW_AWARE: bool = true;

    fn into_preview_decision(self) -> IcapResult<PreviewDecision> {
        self
    }
}

struct HandlerEntry {
    handler: RequestHandler,
    preview_aware: bool,
}

/// Route entry for a service: **per-method** handlers + optional OPTIONS config.
///
/// Internal structure stored by the server/router.
struct RouteEntry {
    /// Map of method → handler. This enables duplicate-method detection and
    /// allows different handlers per method if desired.
    handlers: HashMap<Method, HandlerEntry>,
    options: Option<ServiceOptions>,
}

/// ICAP server.
///
/// Use [`Server::builder`] to construct and run an instance.
///
/// # Example
///
/// ```rust,no_run
/// use icap_rs::{Server, Method, Request, Response};
/// use icap_rs::error::IcapResult;
/// use icap_rs::server::options::ServiceOptions;
///
/// const ISTAG: &str = "scan-1.0";
///
/// #[tokio::main]
/// async fn main() -> IcapResult<()> {
///     let server = Server::builder()
///         .bind("127.0.0.1:1344")
///         .route(
///             "scan",
///             [Method::ReqMod],
///             |_req: Request| async move {
///                 Ok(Response::no_content().try_set_istag(ISTAG)?)
///             },
///             Some(ServiceOptions::new().with_static_istag(ISTAG).with_preview(1024)),
///         )
///         .build()
///         .await?;
///
///     server.run().await
/// }
/// ```
pub struct Server {
    listener: TcpListener,
    routes: Arc<HashMap<String, RouteEntry>>,
    conn_limit: Option<Arc<Semaphore>>,
    advertised_max_conn: Option<usize>,
    aliases: Arc<HashMap<String, String>>,
    default_service: Option<String>,
    #[cfg(feature = "tls-rustls")]
    tls: Option<TlsAcceptor>,
}
impl Server {
    /// Create a new [`ServerBuilder`].
    pub fn builder() -> ServerBuilder {
        ServerBuilder::default()
    }

    /// Accept loop:
    /// - Accepts TCP connections and enforces an optional global limit (semaphore).
    ///   If the limit is reached, send an early `ICAP/1.0 503 Service Unavailable`
    ///   with `Connection: close`; `to_raw()` auto-adds `Encapsulated: null-body=0`
    ///   (no `ISTag` on errors). Set `SO_LINGER(1s)`, non-blocking `try_read` drain,
    ///   then drop the socket (graceful FIN, fewer RSTs).
    /// - Otherwise, move the permit into a spawned task and call `handle_connection(...)`
    ///   which reads full ICAP messages (incl. chunked bodies) and dispatches to
    ///   registered handlers (`OPTIONS`, `REQMOD`, `RESPMOD`).
    /// - Shared routing/alias/default/max-conn state is passed via `Arc`.
    pub async fn run(self) -> IcapResult<()> {
        let local_addr = self.listener.local_addr()?;
        trace!(addr=%local_addr, "ICAP server started");

        loop {
            let (socket, addr) = self.listener.accept().await?;
            trace!(client=%addr, "new connection");

            let (permit_opt, over_limit) = self.conn_limit.as_ref().map_or_else(
                || (None, false),
                |sem| {
                    sem.clone()
                        .try_acquire_owned()
                        .map_or_else(|_| (None, true), |p| (Some(p), false))
                },
            );

            let routes = Arc::clone(&self.routes);
            let aliases = Arc::clone(&self.aliases);
            let default_service = self.default_service.clone();
            let advertised_max = self.advertised_max_conn;

            #[cfg(feature = "tls-rustls")]
            let tls = self.tls.clone();

            tokio::spawn(async move {
                let _permit = permit_opt;

                if over_limit {
                    let resp =
                        Response::new(StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable")
                            .add_header("Connection", "close");
                    match resp.to_raw() {
                        Ok(bytes) => {
                            #[cfg(feature = "tls-rustls")]
                            {
                                if let Some(acceptor) = tls {
                                    match acceptor.accept(socket).await {
                                        Ok(mut tls_stream) => {
                                            let _ = tls_stream.write_all(&bytes).await;
                                            let _ = tls_stream.shutdown().await;
                                        }
                                        Err(e) => {
                                            warn!(client=%addr, error=%e, "TLS handshake failed on overload");
                                        }
                                    }
                                    return;
                                }
                            }
                            let mut sock = socket;
                            if let Err(e) = sock.write_all(&bytes).await {
                                warn!(client=%addr, error=%e, "failed to send 503");
                            } else {
                                let _ = sock.shutdown().await;
                            }
                        }
                        Err(e) => warn!(client=%addr, error=%e, "failed to serialize 503"),
                    }
                    return;
                }

                #[cfg(feature = "tls-rustls")]
                {
                    if let Some(acceptor) = tls {
                        match acceptor.accept(socket).await {
                            Ok(stream) => {
                                if let Err(e) = Box::pin(Self::handle_connection(
                                    stream,
                                    routes,
                                    aliases,
                                    default_service,
                                    advertised_max,
                                    addr,
                                ))
                                .await
                                {
                                    error!(client=%addr, error=%e, "error handling TLS connection");
                                }
                            }
                            Err(e) => {
                                warn!(client=%addr, error=%e, "TLS handshake failed");
                            }
                        }
                        return;
                    }
                }

                // Plain TCP
                if let Err(e) = Box::pin(Self::handle_connection(
                    socket,
                    routes,
                    aliases,
                    default_service,
                    advertised_max,
                    addr,
                ))
                .await
                {
                    error!(client=%addr, error=%e, "error handling connection");
                }
            });
        }
    }

    ///
    /// Rules:
    /// - If `raw` is empty or exactly "/", use `default_service` (when set).
    /// - Apply up to 4 alias rewrites (`from` → `to`) to avoid cycles.
    fn resolve_service<'a>(
        raw: &'a str,
        aliases: &'a HashMap<String, String>,
        default_service: Option<&'a str>,
    ) -> Cow<'a, str> {
        let mut cur: Cow<'a, str> = if raw.is_empty() || raw == "/" {
            default_service.map_or(Cow::Borrowed(raw), Cow::Borrowed)
        } else {
            Cow::Borrowed(raw)
        };

        for _ in 0..4 {
            if let Some(next) = aliases.get(cur.as_ref()) {
                cur = Cow::Borrowed(next.as_str());
            } else {
                break;
            }
        }

        cur
    }

    /// Handle a single client connection (persistent / keep-alive).
    ///
    /// Reads one full ICAP message (headers + chunked body if any), parses and dispatches it,
    /// writes the response, then repeats until the peer closes the connection.
    async fn handle_connection<S>(
        mut socket: S,
        routes: Arc<HashMap<String, RouteEntry>>,
        aliases: Arc<HashMap<String, String>>,
        default_service: Option<String>,
        advertised_max_conn: Option<usize>,
        addr: std::net::SocketAddr,
    ) -> IcapResult<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut buf: Vec<u8> = Vec::with_capacity(16 * 1024);
        let mut tmp = [0u8; 8192];

        loop {
            // === Read headers ===
            let h_end = loop {
                if let Some(end) = find_double_crlf(&buf) {
                    break end;
                }

                let n = match socket.read(&mut tmp).await {
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        return if buf.is_empty() {
                            Ok(())
                        } else {
                            Err("EOF before complete ICAP headers".into())
                        };
                    }
                    Err(e) => return Err(e.into()),
                };

                if n == 0 {
                    return if buf.is_empty() {
                        Ok(())
                    } else {
                        Err("EOF before complete ICAP headers".into())
                    };
                }
                buf.extend_from_slice(&tmp[..n]);
            };

            let hdr_text = std::str::from_utf8(&buf[..h_end])
                .map_err(|_| "Invalid ICAP headers utf8")?
                .to_string();
            let enc = crate::parser::parse_encapsulated_header(&hdr_text)?;
            let mut msg_end = h_end;

            if let Some(body_rel) = enc.req_body.or(enc.res_body) {
                let body_abs = h_end + body_rel;
                while buf.len() < body_abs {
                    let n = socket.read(&mut tmp).await?;
                    if n == 0 {
                        return Err("Unexpected EOF before start of ICAP body".into());
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }

                let preview_size = parse_preview_header_value(&hdr_text);
                if preview_size.is_some() {
                    let (preview_end, preview_ieof) =
                        read_chunked_until_zero(&mut socket, &mut buf, body_abs).await?;

                    let mut preview_slice = &buf[body_abs..preview_end];
                    let (mut decoded, _ieof_seen) =
                        dechunk_icap_entity_with_ieof(&mut preview_slice)
                            .map_err(|e| format!("dechunk ICAP preview entity: {e}"))?;

                    if preview_ieof {
                        msg_end = preview_end;
                    } else {
                        let mut preview_buf = buf.clone();
                        let preview_len = decoded.len();
                        preview_buf.splice(body_abs..preview_end, decoded.clone());
                        let preview_msg_end = body_abs + preview_len;
                        let mut preview_req = parse_icap_request(&preview_buf[..preview_msg_end])?;
                        let preview_method = preview_req.method;
                        let preview_raw_service = preview_req
                            .service
                            .rsplit('/')
                            .next()
                            .unwrap_or(&preview_req.service);
                        let preview_service_resolved = Self::resolve_service(
                            preview_raw_service,
                            &aliases,
                            default_service.as_deref(),
                        );

                        if let Some(entry) = routes.get(preview_service_resolved.as_ref())
                            && let Some(handler_entry) = entry.handlers.get(&preview_method)
                            && handler_entry.preview_aware
                        {
                            mark_request_body_as_preview(&mut preview_req, false);
                            match (handler_entry.handler)(preview_req).await? {
                                PreviewDecision::Continue => {}
                                PreviewDecision::Respond(resp) => {
                                    let should_close = !matches!(
                                        resp.status_code,
                                        StatusCode::OK | StatusCode::NO_CONTENT
                                    );
                                    let resp = if should_close {
                                        resp.add_header("Connection", "close")
                                    } else {
                                        resp
                                    };
                                    let bytes = resp.to_raw()?;
                                    socket.write_all(&bytes).await?;
                                    trace!(
                                        client = %addr,
                                        "Preview final response sent with status {}",
                                        resp.status_code
                                    );

                                    if should_close {
                                        let _ = socket.shutdown().await;
                                        return Ok(());
                                    }

                                    buf.drain(..preview_end);
                                    continue;
                                }
                            }
                        }

                        socket.write_all(b"ICAP/1.0 100 Continue\r\n\r\n").await?;
                        socket.flush().await?;

                        let rest_end =
                            read_chunked_to_end(&mut socket, &mut buf, preview_end).await?;
                        let mut rest_slice = &buf[preview_end..rest_end];
                        let (rest_decoded, _) = dechunk_icap_entity_with_ieof(&mut rest_slice)
                            .map_err(|e| format!("dechunk ICAP remainder entity: {e}"))?;
                        decoded.extend_from_slice(&rest_decoded);
                        msg_end = rest_end;
                    }

                    let decoded_len = decoded.len();
                    buf.splice(body_abs..msg_end, decoded);
                    msg_end = body_abs + decoded_len;
                } else {
                    msg_end = read_chunked_to_end(&mut socket, &mut buf, body_abs).await?;
                    if msg_end > body_abs {
                        let mut chunked_slice = &buf[body_abs..msg_end];
                        let decoded = dechunk_icap_entity(&mut chunked_slice)
                            .map_err(|e| format!("dechunk ICAP entity: {e}"))?;
                        let decoded_len = decoded.len();
                        buf.splice(body_abs..msg_end, decoded);
                        msg_end = body_abs + decoded_len;
                    }
                }
            } else if let Some(end_rel) = enc.null_body {
                let end_abs = h_end + end_rel;
                while buf.len() < end_abs {
                    let n = socket.read(&mut tmp).await?;
                    if n == 0 {
                        return Err("Unexpected EOF before null-body boundary".into());
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                msg_end = end_abs;
            }

            // === Parse + route ===
            let req = parse_icap_request(&buf[..msg_end])?;
            let method = req.method;
            let raw_service: &str = req.service.rsplit('/').next().unwrap_or(&req.service);
            let service_resolved =
                Self::resolve_service(raw_service, &aliases, default_service.as_deref());
            trace!(
                client = %addr,
                method = ?method,
                service = %service_resolved,
                "received request"
            );

            let resp = if let Some(entry) = routes.get(service_resolved.as_ref()) {
                if method == Method::Options {
                    let mut allowed: SmallVec<Method, 2> = entry.handlers.keys().copied().collect();
                    allowed.sort_unstable();
                    let mut cfg = entry.options.as_ref().map_or_else(
                        || {
                            ServiceOptions::new()
                                .with_static_istag(&format!("{service_resolved}-default-1.0"))
                                .with_options_ttl(3600)
                                .add_allow("204")
                        },
                        Clone::clone,
                    );
                    cfg.set_methods(allowed);
                    if cfg.service.is_none() {
                        cfg = cfg
                            .with_service(&format!("ICAP Service {}", service_resolved.as_ref()));
                    }
                    if let (Some(n), None) = (advertised_max_conn, cfg.max_connections) {
                        cfg.with_max_connections(n);
                    }
                    cfg.build_response_for(&req)
                } else {
                    let allow_204 = req
                        .icap_headers
                        .get("Allow")
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(|s| s.split(',').any(|t| t.trim() == "204"));
                    let has_preview = req.icap_headers.get("Preview").is_some();

                    if !allow_204 && !has_preview {
                        let istag_now = entry.options.as_ref().map_or_else(
                            || format!("{service_resolved}-default-1.0"),
                            |opts| opts.istag_for(&req),
                        );

                        let mut out =
                            Response::new(StatusCode::OK, "OK").try_set_istag(&istag_now)?;

                        match (&req.embedded, method) {
                            (
                                Some(EmbeddedHttp::Resp {
                                    head,
                                    body: Body::Full { reader },
                                }),
                                Method::RespMod,
                            ) => {
                                let mut builder = http::Response::builder()
                                    .status(head.status())
                                    .version(head.version());
                                if let Some(h) = builder.headers_mut() {
                                    h.extend(head.headers().clone());
                                }
                                let http_resp = builder.body(reader.clone()).map_err(|e| {
                                    format!("build http::Response from embedded: {e}")
                                })?;
                                out = out.with_http_response(&http_resp)?;
                            }
                            (
                                Some(EmbeddedHttp::Req {
                                    head,
                                    body: Body::Full { reader },
                                }),
                                Method::ReqMod,
                            ) => {
                                let mut builder = http::Request::builder()
                                    .method(head.method().clone())
                                    .uri(head.uri().clone())
                                    .version(head.version());
                                if let Some(h) = builder.headers_mut() {
                                    h.extend(head.headers().clone());
                                }
                                let http_req = builder.body(reader.clone()).map_err(|e| {
                                    format!("build http::Request from embedded: {e}")
                                })?;
                                out = out.with_http_request(&http_req)?;
                            }
                            _ => {}
                        }

                        out
                    } else if let Some(handler_entry) = entry.handlers.get(&method) {
                        match (handler_entry.handler)(req).await? {
                            PreviewDecision::Respond(resp) => resp,
                            PreviewDecision::Continue => {
                                return Err(
                                    "Route handler returned Continue after full body was read"
                                        .into(),
                                );
                            }
                        }
                    } else {
                        Response::new(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed")
                    }
                }
            } else if method == Method::Options {
                Self::build_default_options_response(
                    service_resolved.as_ref(),
                    advertised_max_conn,
                    &req,
                )
            } else {
                trace!(client=%addr, service=%service_resolved, "service not found");
                Response::new(StatusCode::NOT_FOUND, "Service Not Found")
            };

            let should_close = !matches!(resp.status_code, StatusCode::OK | StatusCode::NO_CONTENT);
            let resp = if should_close {
                resp.add_header("Connection", "close")
            } else {
                resp
            };

            let bytes = resp.to_raw()?;
            socket.write_all(&bytes).await?;
            trace!(
                client = %addr,
                "Response sent with status {}",
                resp.status_code
            );

            if should_close {
                let _ = socket.shutdown().await;
                return Ok(());
            }
            buf.drain(..msg_end);
        }
    }

    fn build_default_options_response(
        service_name: &str,
        advertised_max: Option<usize>,
        req: &Request,
    ) -> Response {
        let mut cfg = ServiceOptions::new().with_static_istag(service_name);

        cfg.set_methods([Method::RespMod]);
        cfg = cfg.with_service(&format!("ICAP Service {service_name}"));

        if let Some(n) = advertised_max {
            cfg.with_max_connections(n);
        }

        cfg.build_response_for(req)
    }
}

fn mark_request_body_as_preview(req: &mut Request, ieof: bool) {
    let Some(embedded) = req.embedded.as_mut() else {
        return;
    };

    let body = match embedded {
        EmbeddedHttp::Req { body, .. } | EmbeddedHttp::Resp { body, .. } => body,
    };

    let Body::Full { reader } = body else {
        return;
    };

    let preview = std::mem::take(reader);
    *body = Body::Preview {
        bytes: Bytes::from(preview),
        ieof,
        remainder: Remainder::new(Vec::new(), None),
    };
}

// Dechunk ICAP entity-body (HTTP chunked framing) in-place-like.
// - Consumes from the input slice by advancing `*data`.
// - Returns a Vec with the dechunked payload.
// - On success, `*data` points to the first byte after the entity (usually CRLF/next part).
fn dechunk_icap_entity(data: &mut &[u8]) -> Result<Vec<u8>, String> {
    // Pre-size result to the remaining input upper bound (cheap heuristic).
    let mut out = Vec::with_capacity((*data).len());
    // Work on a local moving window, then publish the final position back to caller.
    let mut d = *data;

    loop {
        // Find the CRLF ending the chunk-size line.
        let crlf_pos = memmem::find(d, b"\r\n").ok_or("chunk size line without CRLF")?;
        let (size_line, rest) = d.split_at(crlf_pos);
        // Skip the CRLF
        d = &rest[2..];

        // Strip optional chunk extensions starting with ';'
        let size_hex = memchr(b';', size_line).map_or(size_line, |i| &size_line[..i]);

        let size_str = core::str::from_utf8(size_hex).map_err(|_| "chunk size not utf8")?;
        let size = usize::from_str_radix(size_str.trim(), 16).map_err(|_| "chunk size not hex")?;

        if size == 0 {
            // Trailing CRLF after the 0-size chunk is optional in some impls; tolerate both.
            if d.starts_with(b"\r\n") {
                d = &d[2..];
            }
            // Publish how much we consumed back to the caller.
            *data = d;
            break;
        }

        // Need at least `size` bytes of data + CRLF
        if d.len() < size + 2 {
            return Err("incomplete chunk data".into());
        }

        out.extend_from_slice(&d[..size]);

        if &d[size..size + 2] != b"\r\n" {
            return Err("missing CRLF after chunk".into());
        }

        // Advance past data and its CRLF.
        d = &d[size + 2..];
    }

    Ok(out)
}

fn parse_preview_header_value(hdr_text: &str) -> Option<usize> {
    for line in hdr_text.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("Preview") {
            return value.trim().parse::<usize>().ok();
        }
    }
    None
}

async fn read_chunked_until_zero<S>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    mut pos: usize,
) -> IcapResult<(usize, bool)>
where
    S: AsyncRead + Unpin,
{
    loop {
        if let Some((next_pos, is_zero, has_ieof, _size)) = parse_one_chunk_meta(buf, pos)? {
            if is_zero {
                return Ok((next_pos, has_ieof));
            }
            pos = next_pos;
        } else {
            let mut tmp = [0u8; 4096];
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err("Unexpected EOF while reading ICAP preview body".into());
            }
            buf.extend_from_slice(&tmp[..n]);
        }
    }
}

fn parse_one_chunk_meta(
    buf: &[u8],
    from: usize,
) -> Result<Option<(usize, bool, bool, usize)>, String> {
    if from >= buf.len() {
        return Ok(None);
    }

    let rel = memmem::find(&buf[from..], b"\r\n");
    let Some(line_end_rel) = rel else {
        return Ok(None);
    };
    let line_end = from + line_end_rel;
    let size_line = &buf[from..line_end];
    let after_size = line_end + 2;

    let (size_hex, ext_part) = memchr(b';', size_line).map_or((size_line, None), |i| {
        (&size_line[..i], Some(&size_line[i + 1..]))
    });

    let size_str = std::str::from_utf8(size_hex)
        .map_err(|_| "chunk size not utf8".to_string())?
        .trim();
    let size = usize::from_str_radix(size_str, 16).map_err(|_| "chunk size not hex".to_string())?;

    let has_ieof = ext_part
        .and_then(|b| std::str::from_utf8(b).ok())
        .is_some_and(|s| s.split(';').any(|t| t.trim().eq_ignore_ascii_case("ieof")));

    if size == 0 {
        if buf.len() < after_size + 2 {
            return Ok(None);
        }
        if &buf[after_size..after_size + 2] != b"\r\n" {
            return Err("Invalid chunked terminator".into());
        }
        return Ok(Some((after_size + 2, true, has_ieof, 0)));
    }

    let need = after_size + size + 2;
    if buf.len() < need {
        return Ok(None);
    }
    if &buf[after_size + size..need] != b"\r\n" {
        return Err("missing CRLF after chunk".into());
    }
    Ok(Some((need, false, false, size)))
}

fn dechunk_icap_entity_with_ieof(data: &mut &[u8]) -> Result<(Vec<u8>, bool), String> {
    let mut out = Vec::with_capacity((*data).len());
    let mut d = *data;
    let ieof = loop {
        let rel = memmem::find(d, b"\r\n").ok_or("chunk size line without CRLF")?;
        let line = &d[..rel];
        d = &d[rel + 2..];

        let (size_hex, ext_part) =
            memchr(b';', line).map_or((line, None), |i| (&line[..i], Some(&line[i + 1..])));

        let size_str = std::str::from_utf8(size_hex).map_err(|_| "chunk size not utf8")?;
        let size = usize::from_str_radix(size_str.trim(), 16).map_err(|_| "chunk size not hex")?;

        let has_ieof = ext_part
            .and_then(|b| std::str::from_utf8(b).ok())
            .is_some_and(|s| s.split(';').any(|t| t.trim().eq_ignore_ascii_case("ieof")));

        if size == 0 {
            if d.starts_with(b"\r\n") {
                d = &d[2..];
            } else {
                return Err("missing final CRLF after zero chunk".into());
            }
            *data = d;
            break has_ieof;
        }

        if d.len() < size + 2 {
            return Err("incomplete chunk data".into());
        }
        out.extend_from_slice(&d[..size]);
        if &d[size..size + 2] != b"\r\n" {
            return Err("missing CRLF after chunk".into());
        }
        d = &d[size + 2..];
    };

    Ok((out, ieof))
}

#[cfg(feature = "tls-rustls")]
#[derive(Clone)]
struct TlsParams {
    cert_path: PathBuf,
    key_path: PathBuf,
    ca_path: Option<PathBuf>,
    require_client_auth: bool,
    alpn_icap: bool,
}

/// Builder for [`Server`].
///
/// Construct with [`Server::builder`], register routes, then call [`ServerBuilder::build`].
///
/// Duplicate registration of the **same (service, method)** panics with a clear error,
/// like axum.
#[derive(Default)]
#[must_use]
pub struct ServerBuilder {
    bind_addr: Option<String>,
    routes: HashMap<String, RouteEntry>,
    max_connections_global: Option<usize>,
    aliases: HashMap<String, String>,
    default_service: Option<String>,
    #[cfg(feature = "tls-rustls")]
    tls: Option<TlsParams>,
}

impl ServerBuilder {
    #[cfg(feature = "tls-rustls")]
    /// Enables ICAPS (ICAP over TLS) using Rustls by loading the server certificate
    /// chain and private key from PEM files.
    ///
    /// The TLS handshake is terminated inside the server via Rustls. By default,
    /// the server advertises the `icap` ALPN identifier (clients that ignore ALPN
    /// remain compatible). **Client authentication is not required**; for mTLS use
    /// [`ServerBuilder::with_mtls_from_pem_files`].
    ///
    /// This method is only available when the `tls-rustls` feature is enabled.
    ///
    /// # Parameters
    /// - `cert_pem`: Path to a PEM file containing the server certificate chain
    ///   (leaf first, followed by intermediates if any).
    /// - `key_pem`: Path to a PEM file containing the server’s private key
    ///   (PKCS#8 or legacy RSA formats are supported).
    ///
    /// # Example
    /// ```no_run
    /// use icap_rs::{Server, Method, Request, Response};
    /// use icap_rs::error::IcapResult;
    /// use icap_rs::server::options::ServiceOptions;
    ///
    /// const ISTAG: &str = "scan-1.0";
    ///
    /// #[tokio::main]
    /// async fn main() -> IcapResult<()> {
    ///     let server = Server::builder()
    ///         .bind("0.0.0.0:13443") // ICAPS port
    ///         .with_tls_from_pem_files("certs/server.crt", "certs/server.key")
    ///         .route(
    ///             "test",
    ///             [Method::ReqMod, Method::RespMod],
    ///             |_req: Request| async move {
    ///                 Ok(Response::no_content().try_set_istag(ISTAG)?)
    ///             },
    ///             Some(ServiceOptions::new()
    ///                 .with_static_istag(ISTAG)
    ///                 .with_preview(2048)
    ///                 .add_allow("204")),
    ///         )
    ///         .build().await?;
    ///
    ///     server.run().await
    /// }
    /// ```
    pub fn with_tls_from_pem_files(
        mut self,
        cert_pem: impl Into<PathBuf>,
        key_pem: impl Into<PathBuf>,
    ) -> Self {
        self.tls = Some(TlsParams {
            cert_path: cert_pem.into(),
            key_path: key_pem.into(),
            ca_path: None,
            require_client_auth: false,
            alpn_icap: true,
        });
        self
    }

    #[cfg(feature = "tls-rustls")]
    /// Enables **mutual TLS (mTLS)** using Rustls: clients must present a certificate
    /// that validates against the provided CA bundle.
    ///
    /// The server performs client-certificate validation using the given CA(s).
    /// By default, the server advertises the `icap` ALPN identifier.
    ///
    /// This method is only available when the `tls-rustls` feature is enabled.
    ///
    /// # Parameters
    /// - `cert_pem`: Path to the server certificate chain in PEM (leaf → intermediates).
    /// - `key_pem`: Path to the server private key in PEM (PKCS#8 or RSA).
    /// - `ca_pem`: Path to a PEM file containing one or more CA roots used to verify
    ///   client certificates.
    ///
    /// # Example
    /// ```no_run
    /// use icap_rs::{Server, Method, Request, Response};
    /// use icap_rs::error::IcapResult;
    /// use icap_rs::server::options::ServiceOptions;
    ///
    /// const ISTAG: &str = "scan-1.0";
    ///
    /// #[tokio::main]
    /// async fn main() -> IcapResult<()> {
    ///     let server = Server::builder()
    ///         .bind("0.0.0.0:13443")
    ///         .with_mtls_from_pem_files(
    ///             "certs/server.crt",
    ///             "certs/server.key",
    ///             "certs/ca.pem", // trusted CA(s) for client-auth verification
    ///         )
    ///         .route(
    ///             "scan",
    ///             [Method::ReqMod, Method::RespMod],
    ///             |_req: Request| async move {
    ///                 Ok(Response::no_content().try_set_istag(ISTAG)?)
    ///             },
    ///             Some(ServiceOptions::new()
    ///                 .with_static_istag(ISTAG)
    ///                 .with_preview(2048)
    ///                 .add_allow("204")),
    ///         )
    ///         .build().await?;
    ///
    ///     server.run().await
    /// }
    /// ```
    pub fn with_mtls_from_pem_files(
        mut self,
        cert_pem: impl Into<PathBuf>,
        key_pem: impl Into<PathBuf>,
        ca_pem: impl Into<PathBuf>,
    ) -> Self {
        self.tls = Some(TlsParams {
            cert_path: cert_pem.into(),
            key_path: key_pem.into(),
            ca_path: Some(ca_pem.into()),
            require_client_auth: true,
            alpn_icap: true,
        });
        self
    }

    /// Set the bind address, e.g. `"127.0.0.1:1344"`.
    pub fn bind(mut self, addr: &str) -> Self {
        self.bind_addr = Some(addr.to_string());
        self
    }

    /// Limit the number of concurrent connections accepted by the server.
    ///
    /// The value is also advertised in `OPTIONS` as `Max-Connections` if
    /// not explicitly configured on the per-service options.
    pub fn with_max_connections(mut self, n: usize) -> Self {
        self.max_connections_global = Some(n.max(1));
        self
    }

    /// Register a **service route** for one or more ICAP methods (with optional per-service options).
    ///
    /// - Multiple calls to `.route(..)` for the **same service** are allowed as long as methods do not overlap.
    /// - Registering the **same method** for the same service twice will `panic!` with a clear message.
    /// - The same handler can be reused for multiple methods in a single call.
    /// - Return `IcapResult<PreviewDecision>` from the handler to make the route
    ///   preview-aware. Such handlers are called with `Body::Preview` after
    ///   preview bytes arrive and before the server sends `100 Continue`.
    ///   Returning `PreviewDecision::Continue` resumes the RFC preview flow; the
    ///   same handler is called again with `Body::Full` after the remainder is read.
    pub fn route<MIt, MItem, F, Fut>(
        mut self,
        service: &str,
        methods: MIt,
        handler: F,
        options: Option<ServiceOptions>,
    ) -> Self
    where
        MIt: IntoIterator<Item = MItem>,
        MItem: Into<Method>,
        F: Fn(Request) -> Fut + Send + Sync + 'static,
        Fut: Future + Send + 'static,
        Fut::Output: RouteOutput,
    {
        let entry = match self.routes.entry(service.to_owned()) {
            Entry::Occupied(o) => o.into_mut(),
            Entry::Vacant(v) => v.insert(RouteEntry {
                handlers: HashMap::new(),
                options: None,
            }),
        };

        // Wrap handler in Arc so we can reuse it for multiple methods
        let h_arc = Arc::new(handler);

        for item in methods {
            let m: Method = item.into();

            assert_ne!(
                m,
                Method::Options,
                "OPTIONS cannot have a handler; it's answered automatically for '{service}'"
            );
            assert!(
                !entry.handlers.contains_key(&m),
                "Overlapping method route. Handler for '{m} {service}' already exists"
            );

            let h_clone = h_arc.clone();
            let h: RequestHandler = Box::new(move |req| {
                let h = h_clone.clone();
                Box::pin(async move { h(req).await.into_preview_decision() })
            });
            entry.handlers.insert(
                m,
                HandlerEntry {
                    handler: h,
                    preview_aware: Fut::Output::PREVIEW_AWARE,
                },
            );
        }

        // Attach options if provided for this route
        if let Some(cfg) = options {
            assert!(
                entry.options.is_none(),
                "Options already set for service '{service}'"
            );
            entry.options = Some(cfg);
        }

        self
    }

    /// Register a route for `REQMOD` only
    pub fn route_reqmod<F, Fut>(
        self,
        service: &str,
        handler: F,
        options: Option<ServiceOptions>,
    ) -> Self
    where
        F: Fn(Request) -> Fut + Send + Sync + 'static,
        Fut: Future + Send + 'static,
        Fut::Output: RouteOutput,
    {
        self.route(service, [Method::ReqMod], handler, options)
    }

    /// Register a route for `RESPMOD` only.
    pub fn route_respmod<F, Fut>(
        self,
        service: &str,
        handler: F,
        options: Option<ServiceOptions>,
    ) -> Self
    where
        F: Fn(Request) -> Fut + Send + Sync + 'static,
        Fut: Future + Send + 'static,
        Fut::Output: RouteOutput,
    {
        self.route(service, [Method::RespMod], handler, options)
    }

    /// Add an alias for a service name: `from` → `to`.
    ///
    /// Useful to make root path behave like an existing service:
    /// ```
    /// # use icap_rs::Server;
    /// let builder = Server::builder()
    ///     .alias("/", "scan"); // "icap://host:1344/" will be treated as "scan"
    /// ```
    ///
    /// Notes:
    /// - Aliases are applied *after* [`default_service`](Self::default_service) is considered
    ///   for empty or "/" path.
    /// - Up to 4 alias rewrites are applied to avoid cycles.
    pub fn alias(mut self, from: &str, to: &str) -> Self {
        self.aliases.insert(from.to_string(), to.to_string());
        self
    }

    /// Set a default service for empty or "/" path (e.g. `"scan"`).
    ///
    /// Example:
    /// ```
    /// # use icap_rs::Server;
    /// let builder = Server::builder()
    ///     .default_service("scan");
    /// ```
    ///
    /// If a client sends `icap://host:1344/` or an empty service, requests are internally
    /// routed to the specified service name.
    pub fn default_service(mut self, svc: &str) -> Self {
        self.default_service = Some(svc.to_string());
        self
    }

    /// Finalize the builder and create a [`Server`].
    pub async fn build(self) -> IcapResult<Server> {
        validate_builder_config(&self.routes, &self.aliases, self.default_service.as_deref())?;

        let bind_addr = self
            .bind_addr
            .unwrap_or_else(|| "127.0.0.1:1344".to_string());
        let listener = TcpListener::bind(&bind_addr).await?;

        let conn_limit = self
            .max_connections_global
            .map(|n| Arc::new(Semaphore::new(n)));
        let advertised_max_conn = self.max_connections_global;

        // TLS (only when feature is enabled)
        #[cfg(feature = "tls-rustls")]
        let tls_acceptor: Option<TlsAcceptor> = if let Some(tls) = &self.tls {
            Some(load_rustls_acceptor(tls)?)
        } else {
            None
        };

        Ok(Server {
            listener,
            routes: Arc::new(self.routes),
            conn_limit,
            advertised_max_conn,
            aliases: Arc::new(self.aliases),
            default_service: self.default_service,

            #[cfg(feature = "tls-rustls")]
            tls: tls_acceptor,
        })
    }
}

fn validate_builder_config(
    routes: &HashMap<String, RouteEntry>,
    aliases: &HashMap<String, String>,
    default_service: Option<&str>,
) -> IcapResult<()> {
    for (service, entry) in routes {
        if entry.handlers.is_empty() {
            return Err(crate::error::Error::service(format!(
                "Service '{service}' has no handlers"
            )));
        }
        if let Some(options) = &entry.options
            && let Err(err) = options.validate()
        {
            return Err(crate::error::Error::service(format!(
                "Invalid options for service '{service}': {err}"
            )));
        }
    }

    if let Some(default) = default_service {
        let resolved = Server::resolve_service(default, aliases, None);
        if !routes.contains_key(resolved.as_ref()) {
            return Err(crate::error::Error::service(format!(
                "Default service '{default}' resolves to unknown service '{}'",
                resolved.as_ref()
            )));
        }
    }

    for (from, to) in aliases {
        let resolved = Server::resolve_service(to, aliases, None);
        if !routes.contains_key(resolved.as_ref()) {
            return Err(crate::error::Error::service(format!(
                "Alias '{from}' resolves to unknown service '{}'",
                resolved.as_ref()
            )));
        }
    }

    Ok(())
}

#[cfg(feature = "tls-rustls")]
fn load_rustls_acceptor(tls: &TlsParams) -> Result<TlsAcceptor, String> {
    use std::io::BufReader;

    // Certificates
    let mut cert_r = BufReader::new(
        std::fs::File::open(&tls.cert_path).map_err(|e| format!("TLS: open cert: {e}"))?,
    );
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_r)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("TLS: parse certs: {e}"))?;

    // Private key: try PKCS#8 first, then RSA
    let mut key_r = BufReader::new(
        std::fs::File::open(&tls.key_path).map_err(|e| format!("TLS: open key: {e}"))?,
    );

    let mut keys: Vec<PrivateKeyDer<'static>> = rustls_pemfile::pkcs8_private_keys(&mut key_r)
        .map(|res| res.map(Into::into))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("TLS: parse pkcs8 key: {e}"))?;

    if keys.is_empty() {
        let mut key_r = BufReader::new(
            std::fs::File::open(&tls.key_path)
                .map_err(|e| format!("TLS: reopen key (rsa): {e}"))?,
        );
        keys = rustls_pemfile::rsa_private_keys(&mut key_r)
            .map(|res| res.map(Into::into))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("TLS: parse rsa key: {e}"))?;
    }
    let key = keys.into_iter().next().ok_or("TLS: no private key found")?;

    // Server config (+ optional mTLS)
    let server_config = if tls.require_client_auth {
        // Load client CA(s)
        let ca_path = tls
            .ca_path
            .clone()
            .ok_or("TLS: ca_pem path is required for mTLS")?;
        let mut ca_r = BufReader::new(
            std::fs::File::open(&ca_path).map_err(|e| format!("TLS: open ca: {e}"))?,
        );
        let cas: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut ca_r)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("TLS: parse ca: {e}"))?;

        let mut roots = RootCertStore::empty();
        for c in cas {
            roots.add(c).map_err(|e| format!("TLS: add CA: {e}"))?;
        }

        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| format!("TLS: build client verifier: {e}"))?;

        let mut cfg = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(|e| format!("TLS: build server config (mtls): {e}"))?;

        if tls.alpn_icap {
            cfg.alpn_protocols.push(b"icap".to_vec());
        }
        cfg
    } else {
        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| format!("TLS: build server config: {e}"))?;
        if tls.alpn_icap {
            cfg.alpn_protocols.push(b"icap".to_vec());
        }
        cfg
    };

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    async fn handler_ok(_: Request) -> IcapResult<Response> {
        Ok(Response::new(StatusCode::OK, "OK")
            .add_header("Encapsulated", "null-body=0")
            .add_header("Content-Length", "0"))
    }

    fn panic_str(res: Result<(), Box<dyn std::any::Any + Send>>) -> String {
        match res {
            Ok(()) => String::new(),
            Err(e) => e.downcast_ref::<&str>().map_or_else(
                || {
                    e.downcast_ref::<String>()
                        .map_or_else(|| "<non-string panic>".to_string(), Clone::clone)
                },
                |s| (*s).to_string(),
            ),
        }
    }

    fn assert_panics_with<F>(f: F, needles: &[&str])
    where
        F: FnOnce() + std::panic::UnwindSafe,
    {
        let res = catch_unwind(AssertUnwindSafe(f));
        assert!(res.is_err(), "expected panic, but code did not panic");
        let msg = panic_str(res);
        for n in needles {
            assert!(
                msg.contains(n),
                "expected panic message to contain {n:?}, got: {msg}",
            );
        }
    }

    #[test]
    fn route_allows_different_methods_same_service() {
        let h1 = handler_ok;
        let h2 = handler_ok;

        let _builder = Server::builder()
            .route("/spool", [Method::ReqMod], h1, None)
            .route("/spool", [Method::RespMod], h2, None);
    }

    #[rstest]
    #[case("/spool")]
    #[case("/svc")]
    fn route_panics_on_duplicate_method_same_service(#[case] path: &str) {
        assert_panics_with(
            || {
                let h1 = handler_ok;
                let h2 = handler_ok;

                let builder = Server::builder().route(path, [Method::ReqMod], h1, None);
                let _ = builder.route(path, [Method::ReqMod], h2, None);
            },
            &["Overlapping method route", "REQMOD", path],
        );
    }

    #[rstest]
    #[case(Method::RespMod, "RESPMOD")]
    #[case(Method::ReqMod, "REQMOD")]
    fn panics_when_overlapping_multiple_methods(
        #[case] overlap: Method,
        #[case] overlap_str: &str,
    ) {
        let path = "/svc";
        assert_panics_with(
            || {
                let h = handler_ok;
                let h2 = handler_ok;

                let builder =
                    Server::builder().route(path, [Method::ReqMod, Method::RespMod], h, None);
                let _ = builder.route(path, [overlap], h2, None);
            },
            &["Overlapping method route", overlap_str, path],
        );
    }

    #[rstest]
    #[case("reqmod", "RESPMOD")]
    #[case("REQMOD", "respmod")]
    #[case("  ReqMod  ", " ReSpMoD ")]
    fn route_accepts_methods_case_insensitive(#[case] a: &str, #[case] b: &str) {
        let h = handler_ok;
        let _b = Server::builder().route("/svc", [a, b], h, None);
    }

    #[test]
    fn route_accepts_mixed_enum_and_string() {
        let h = handler_ok;
        let _b = Server::builder().route("/svc", vec![Method::ReqMod, "respmod".into()], h, None);
    }

    #[rstest]
    #[case("FOO")]
    #[case("BAR")]
    fn route_panics_on_unknown_method(#[case] bad: &str) {
        assert_panics_with(
            || {
                let h = handler_ok;
                let _ = Server::builder().route("/svc", [bad], h, None);
            },
            &["Unknown ICAP method string"],
        );
    }

    #[rstest]
    #[case("OPTIONS")]
    #[case("options")]
    #[case("  Options  ")]
    fn route_panics_on_options(#[case] opt: &str) {
        assert_panics_with(
            || {
                let h = handler_ok;
                let _ = Server::builder().route("/svc", [opt], h, None);
            },
            &["OPTIONS"],
        );
    }

    #[tokio::test]
    async fn build_errors_when_default_service_is_unknown() {
        let result = Server::builder().default_service("missing").build().await;
        let err = result
            .err()
            .expect("unknown default service should fail at build time");

        let msg = err.to_string();
        assert!(msg.contains("Default service"), "unexpected error: {msg}");
        assert!(msg.contains("missing"), "unexpected error: {msg}");
    }

    #[tokio::test]
    async fn build_errors_when_alias_target_is_unknown() {
        let result = Server::builder()
            .route_reqmod("svc", handler_ok, None)
            .alias("alt", "missing")
            .build()
            .await;
        let err = result
            .err()
            .expect("unknown alias target should fail at build time");

        let msg = err.to_string();
        assert!(msg.contains("Alias"), "unexpected error: {msg}");
        assert!(msg.contains("missing"), "unexpected error: {msg}");
    }

    #[tokio::test]
    async fn build_errors_when_service_options_are_invalid() {
        let options = ServiceOptions::new().add_transfer_rule("exe", TransferBehavior::Preview);
        let result = Server::builder()
            .route_reqmod("svc", handler_ok, Some(options))
            .build()
            .await;
        let err = result
            .err()
            .expect("invalid service options should fail at build time");

        let msg = err.to_string();
        assert!(msg.contains("Invalid options"), "unexpected error: {msg}");
        assert!(
            msg.contains("Default transfer behavior"),
            "unexpected error: {msg}"
        );
    }
}
