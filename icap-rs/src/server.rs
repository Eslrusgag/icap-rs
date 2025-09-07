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
//!
//! **Status:** experimental; APIs may change.
//!
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

use std::borrow::Cow;
use std::collections::HashMap;
use std::future::Future;
use std::str;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{error, trace, warn};

use crate::error::IcapResult;
use crate::parser::icap::find_double_crlf;
use crate::parser::read_chunked_to_end;
use crate::request::parse_icap_request;
pub use crate::server::options::{ServiceOptions, TransferBehavior};
use crate::{EmbeddedHttp, Method, Request, Response, StatusCode};
use smallvec::SmallVec;

/// A per-service ICAP handler.
///
/// One handler can serve multiple ICAP methods declared for a service via
/// [`ServerBuilder::route`].
type RequestHandler = Box<
    dyn Fn(Request) -> std::pin::Pin<Box<dyn Future<Output = IcapResult<Response>> + Send + Sync>>
        + Send
        + Sync,
>;

/// Route entry for a service: **per-method** handlers + optional OPTIONS config.
///
/// Internal structure stored by the server/router.
struct RouteEntry {
    /// Map of method → handler. This enables duplicate-method detection and
    /// allows different handlers per method if desired.
    handlers: HashMap<Method, RequestHandler>,
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
}

impl Server {
    /// Create a new [`ServerBuilder`].
    pub fn builder() -> ServerBuilder {
        ServerBuilder::new()
    }

    /// Accept loop:
    /// - Accepts TCP connections and enforces an optional global limit (semaphore).
    ///   If the limit is reached, send an early `ICAP/1.0 503 Service Unavailable`
    ///   with `Connection: close`; `to_raw()` auto-adds `Encapsulated: null-body=0`
    ///   (no ISTag on errors). Set `SO_LINGER(1s)`, non-blocking `try_read` drain,
    ///   then drop the socket (graceful FIN, fewer RSTs).
    /// - Otherwise, move the permit into a spawned task and call `handle_connection(...)`
    ///   which reads full ICAP messages (incl. chunked bodies) and dispatches to
    ///   registered handlers (`OPTIONS`, `REQMOD`, `RESPMOD`).
    /// - Shared routing/alias/default/max-conn state is passed via `Arc`.
    pub async fn run(self) -> IcapResult<()> {
        let local_addr = self.listener.local_addr()?;
        trace!(addr=%local_addr, "ICAP server started");

        loop {
            let (mut socket, addr) = self.listener.accept().await?;
            trace!(client=%addr, "new connection");

            let maybe_permit = if let Some(sem) = &self.conn_limit {
                match sem.clone().try_acquire_owned() {
                    Ok(p) => Some(p),
                    Err(_) => {
                        warn!(client=%addr, "refusing connection: too many concurrent connections");
                        let resp =
                            Response::new(StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable")
                                .add_header("Connection", "close");

                        match resp.to_raw() {
                            Ok(bytes) => {
                                if let Err(e) = socket.write_all(&bytes).await {
                                    warn!(client=%addr, error=%e, "failed to send 503");
                                } else {
                                    let _ =
                                        socket.set_linger(Some(std::time::Duration::from_secs(1)));

                                    let mut tmp = [0u8; 1024];
                                    loop {
                                        match socket.try_read(&mut tmp) {
                                            Ok(0) => break,
                                            Ok(_n) => continue,
                                            Err(ref e)
                                                if e.kind() == std::io::ErrorKind::WouldBlock =>
                                            {
                                                break;
                                            }
                                            Err(_e) => break,
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(client=%addr, error=%e, "failed to serialize 503");
                            }
                        }
                        continue;
                    }
                }
            } else {
                None
            };

            // Clone shared state into the task
            let routes = Arc::clone(&self.routes);
            let aliases = Arc::clone(&self.aliases);
            let default_service = self.default_service.clone();
            let advertised_max = self.advertised_max_conn;

            tokio::spawn(async move {
                let _permit = maybe_permit;
                if let Err(e) = Self::handle_connection(
                    socket,
                    routes,
                    aliases,
                    default_service,
                    advertised_max,
                )
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
            if let Some(def) = default_service {
                Cow::Borrowed(def)
            } else {
                Cow::Borrowed(raw)
            }
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
    async fn handle_connection(
        mut socket: TcpStream,
        routes: Arc<HashMap<String, RouteEntry>>,
        aliases: Arc<HashMap<String, String>>,
        default_service: Option<String>,
        advertised_max_conn: Option<usize>,
    ) -> IcapResult<()> {
        let mut buf: Vec<u8> = Vec::with_capacity(16 * 1024);
        let mut tmp = [0u8; 8192];

        loop {
            // === Read one full ICAP message (headers + maybe chunked body) ===
            let h_end = loop {
                if let Some(end) = find_double_crlf(&buf) {
                    break end;
                }
                let n = socket.read(&mut tmp).await?;
                if n == 0 {
                    return if buf.is_empty() {
                        Ok(())
                    } else {
                        Err("EOF before complete ICAP headers".into())
                    };
                }
                buf.extend_from_slice(&tmp[..n]);
            };

            let hdr_text =
                std::str::from_utf8(&buf[..h_end]).map_err(|_| "Invalid ICAP headers utf8")?;
            let enc = crate::parser::parse_encapsulated_header(hdr_text);
            let mut msg_end = h_end;

            // If body is present, ensure we read the whole chunked body into buf
            if let Some(body_rel) = enc.req_body.or(enc.res_body) {
                let body_abs = h_end + body_rel;
                while buf.len() < body_abs {
                    let n = socket.read(&mut tmp).await?;
                    if n == 0 {
                        return Err("Unexpected EOF before start of ICAP body".into());
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                msg_end = read_chunked_to_end(&mut socket, &mut buf, body_abs).await?;
            }

            // === Parse request and route ===
            let req = parse_icap_request(&buf[..msg_end])?;
            let method = req.method;
            let raw_service: &str = req.service.rsplit('/').next().unwrap_or(&req.service);

            let service_resolved =
                Self::resolve_service(raw_service, &aliases, default_service.as_deref());

            trace!(method=?method, service=%service_resolved, "received request");

            let resp = if let Some(entry) = routes.get(service_resolved.as_ref()) {
                match method {
                    Method::Options => {
                        // Build per-request OPTIONS with dynamic ISTag
                        let mut allowed: SmallVec<Method, 2> =
                            entry.handlers.keys().copied().collect();
                        allowed.sort_unstable();

                        let mut cfg = if let Some(cfg) = &entry.options {
                            cfg.clone()
                        } else {
                            ServiceOptions::new()
                                .with_static_istag(&format!("{}-default-1.0", service_resolved))
                                .with_options_ttl(3600)
                                .add_allow("204")
                        };

                        cfg.set_methods(allowed);

                        if cfg.service.is_none() {
                            cfg = cfg.with_service(&format!(
                                "ICAP Service {}",
                                service_resolved.as_ref()
                            ));
                        }

                        if let (Some(n), None) = (advertised_max_conn, cfg.max_connections) {
                            cfg.with_max_connections(n);
                        }

                        cfg.build_response_for(&req)
                    }
                    _ => {
                        // --- RFC guard for 204 ---
                        // If no Allow: 204 and no Preview -> MUST NOT return 204; echo original HTTP back with 200.
                        let allow_204 = req
                            .icap_headers
                            .get("Allow")
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.split(',').any(|t| t.trim() == "204"))
                            .unwrap_or(false);

                        let has_preview = req.icap_headers.get("Preview").is_some();

                        if !allow_204 && !has_preview {
                            let istag_now = entry
                                .options
                                .as_ref()
                                .map(|opts| opts.istag_for(&req))
                                .unwrap_or_else(|| format!("{}-default-1.0", service_resolved));

                            let mut out =
                                Response::new(StatusCode::OK, "OK").try_set_istag(&istag_now)?;

                            match (&req.embedded, method) {
                                (Some(EmbeddedHttp::Resp(http_resp)), Method::RespMod) => {
                                    out = out.with_http_response(http_resp)?;
                                }
                                (Some(EmbeddedHttp::Req(http_req)), Method::ReqMod) => {
                                    out = out.with_http_request(http_req)?;
                                }
                                _ => {}
                            }

                            out
                        } else {
                            // allowed to return 204 (either Allow: 204 present or Preview in use)
                            if let Some(h) = entry.handlers.get(&method) {
                                h(req).await?
                            } else {
                                Response::new(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed")
                            }
                        }
                    }
                }
            } else if method == Method::Options {
                Self::build_default_options_response(
                    service_resolved.as_ref(),
                    advertised_max_conn,
                    &req,
                )
            } else {
                trace!(service=%service_resolved, "service not found");
                Response::new(StatusCode::NOT_FOUND, "Service Not Found")
            };

            let should_close = !matches!(resp.status_code, StatusCode::OK | StatusCode::NO_CONTENT);

            let resp = if should_close {
                resp.add_header("Connection", "close")
            } else {
                resp
            };

            // === Write response ===
            let bytes = resp.to_raw()?;
            socket.write_all(&bytes).await?;
            trace!("Response sent with status {}", resp.status_code);

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
        cfg = cfg.with_service(&format!("ICAP Service {}", service_name));

        if let Some(n) = advertised_max {
            cfg.with_max_connections(n);
        }

        cfg.build_response_for(req)
    }
}

/// Builder for [`Server`].
///
/// Construct with [`Server::builder`], register routes, then call [`ServerBuilder::build`].
///
/// Duplicate registration of the **same (service, method)** panics with a clear error,
/// like axum.
pub struct ServerBuilder {
    bind_addr: Option<String>,
    routes: HashMap<String, RouteEntry>,
    max_connections_global: Option<usize>,
    aliases: HashMap<String, String>,
    default_service: Option<String>,
}

impl ServerBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            bind_addr: None,
            routes: HashMap::new(),
            max_connections_global: None,
            aliases: HashMap::new(),
            default_service: None,
        }
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
        Fut: Future<Output = IcapResult<Response>> + Send + Sync + 'static,
    {
        use std::collections::hash_map::Entry;

        let key = service.to_string();

        // Ensure service slot exists
        let entry = match self.routes.entry(key.clone()) {
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

            if m == Method::Options {
                panic!(
                    "OPTIONS cannot have a handler; it's answered automatically for '{service}'"
                );
            }
            if entry.handlers.contains_key(&m) {
                panic!(
                    "Overlapping method route. Handler for '{} {service}' already exists",
                    m
                );
            }

            let h_clone = h_arc.clone();
            let h: RequestHandler = Box::new(move |req| Box::pin(h_clone(req)));
            entry.handlers.insert(m, h);
        }

        // Attach options if provided for this route
        if let Some(cfg) = options {
            if entry.options.is_some() {
                panic!("Options already set for service '{service}'");
            }
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
        Fut: Future<Output = IcapResult<Response>> + Send + Sync + 'static,
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
        Fut: Future<Output = IcapResult<Response>> + Send + Sync + 'static,
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
        let bind_addr = self
            .bind_addr
            .unwrap_or_else(|| "127.0.0.1:1344".to_string());
        let listener = TcpListener::bind(&bind_addr).await?;

        let conn_limit = self
            .max_connections_global
            .map(|n| Arc::new(Semaphore::new(n)));
        let advertised_max_conn = self.max_connections_global;

        Ok(Server {
            listener,
            routes: Arc::new(self.routes),
            conn_limit,
            advertised_max_conn,
            aliases: Arc::new(self.aliases),
            default_service: self.default_service,
        })
    }
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self::new()
    }
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
            Err(e) => {
                if let Some(s) = e.downcast_ref::<&str>() {
                    (*s).to_string()
                } else if let Some(s) = e.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "<non-string panic>".to_string()
                }
            }
        }
    }

    fn assert_panics_with<F>(f: F, needles: &[&str])
    where
        F: FnOnce() + std::panic::UnwindSafe,
    {
        let res = catch_unwind(AssertUnwindSafe(f));
        assert!(res.is_err(), "expected panic, but code did not panic");
        let msg = panic_str(res.map(|_| ()));
        for n in needles {
            assert!(
                msg.contains(n),
                "expected panic message to contain {:?}, got: {}",
                n,
                msg
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
}
