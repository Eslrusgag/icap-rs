//! # Minimal ICAP server
//!
//! A small ICAP server with per-service routing and **one handler that can serve multiple
//! ICAP methods** (`REQMOD`, `RESPMOD`). The server:
//!
//! - Supports `OPTIONS`, `REQMOD`, `RESPMOD`;
//! - Lets you register services with **one handler** and a **list of allowed methods** via
//!   [`ServerBuilder::route`];
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
//!use icap_rs::{Server, Method, Request, Response, StatusCode};
//!use icap_rs::error::IcapResult;
//!
//!const ISTAG: &str = "scan-1.0";
//!
//!#[tokio::main]
//!async fn main() -> IcapResult<()> {
//!    let server = Server::builder()
//!        .bind("127.0.0.1:1344")
//!        // One handler for REQMOD and RESPMOD of the "scan" service.
//!        .route("scan", [Method::ReqMod, Method::RespMod], |req: Request| async move {
//!            match req.method {
//!                Method::ReqMod => {
//!                    // handle request modification (no changes) → 204
//!                    Ok(Response::no_content().try_set_istag(ISTAG)?)
//!                }
//!                Method::RespMod => {
//!                    // handle response modification (no changes) → 204
//!                    Ok(Response::no_content().try_set_istag(ISTAG)?)
//!                }
//!                Method::Options => unreachable!("OPTIONS is handled automatically by the server"),
//!            }
//!        })
//!        .with_max_connections(128)
//!     .build()
//!     .await?;
//!
//! server.run().await
//!}
//! ```
//!
//! When a client sends `OPTIONS icap://host/scan`, the server responds with
//! `Methods: REQMOD, RESPMOD` based on the registration above. If a method not in
//! the list is used, `405 Method Not Allowed` is returned; unknown services yield `404`.

use std::collections::HashMap;
use std::future::Future;
use std::str;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, Semaphore};
use tracing::{error, trace, warn};

use crate::error::IcapResult;
use crate::parser::{find_double_crlf, read_chunked_to_end, serialize_icap_response};
use crate::request::parse_icap_request;
use crate::{Method, OptionsConfig, Request, Response, StatusCode};
use smallvec::SmallVec;

/// A per-service ICAP handler.
///
/// One handler can serve multiple ICAP methods declared for a service via
/// [`ServerBuilder::route`].
pub type RequestHandler = Box<
    dyn Fn(
            Request,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = IcapResult<Response>> + Send + Sync>,
        > + Send
        + Sync,
>;

/// Route entry for a service: **per-method** handlers + optional OPTIONS config.
///
/// Internal structure stored by the server/router.
struct RouteEntry {
    /// Map of method → handler. This enables duplicate-method detection and
    /// allows different handlers per method if desired.
    handlers: HashMap<Method, RequestHandler>,
    options: Option<OptionsConfig>,
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
/// #[tokio::main]
/// async fn main() -> IcapResult<()> {
///     let server = Server::builder()
///     .bind("127.0.0.1:1344")
///     .route("scan", [Method::ReqMod], |_req: Request| async move {
///     Ok(Response::no_content().try_set_istag("scan-1.0")?)
///     })
///     .build()
///     .await?;
///
///     server.run().await
///  }
/// ```
pub struct Server {
    listener: TcpListener,
    routes: Arc<RwLock<HashMap<String, RouteEntry>>>,
    conn_limit: Option<Arc<Semaphore>>,
    advertised_max_conn: Option<u32>,
}

impl Server {
    /// Create a new [`ServerBuilder`].
    pub fn builder() -> ServerBuilder {
        ServerBuilder::new()
    }

    /// Main accept loop.
    ///
    /// Accepts TCP connections, enforces the optional connection limit, and
    /// dispatches ICAP messages (`OPTIONS`, `REQMOD`, `RESPMOD`) to registered handlers.
    pub async fn run(self) -> IcapResult<()> {
        let local_addr = self.listener.local_addr()?;
        trace!("ICAP server started on {}", local_addr);

        loop {
            let (mut socket, addr) = self.listener.accept().await?;
            trace!("New connection from {}", addr);

            let maybe_permit = if let Some(sem) = &self.conn_limit {
                match sem.clone().try_acquire_owned() {
                    Ok(p) => Some(p),
                    Err(_) => {
                        warn!(
                            "Refusing connection from {}: too many concurrent connections",
                            addr
                        );

                        let resp =
                            Response::new(StatusCode::ServiceUnavailable503, "Service Unavailable")
                                .add_header("Encapsulated", "null-body=0")
                                .add_header("Content-Length", "0");

                        if let Ok(bytes) = serialize_icap_response(&resp) {
                            if let Err(e) = socket.write_all(&bytes).await {
                                warn!("Failed to send 503 to {}: {}", addr, e);
                            }
                            let _ = socket.shutdown().await;
                        }
                        continue;
                    }
                }
            } else {
                None
            };

            let routes = Arc::clone(&self.routes);
            let advertised_max = self.advertised_max_conn;

            tokio::spawn(async move {
                let _permit = maybe_permit;
                if let Err(e) = Self::handle_connection(socket, routes, advertised_max).await {
                    error!("Error handling connection {}: {}", addr, e);
                }
            });
        }
    }

    /// Handle a single client connection (persistent / keep-alive).
    ///
    /// Reads one full ICAP message (headers + chunked body if any), parses and dispatches it,
    /// writes the response, then repeats until the peer closes the connection.
    async fn handle_connection(
        mut socket: TcpStream,
        routes: Arc<RwLock<HashMap<String, RouteEntry>>>,
        advertised_max_conn: Option<u32>,
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
            trace!("Received {} to service '{}'", req.method, req.service);

            let service_name = req
                .service
                .rsplit('/')
                .next()
                .unwrap_or(&req.service)
                .to_string();

            let method = req.method;

            let resp = {
                let routes_guard = routes.read().await;

                if let Some(entry) = routes_guard.get(&service_name) {
                    match method {
                        Method::Options => {
                            let allowed: SmallVec<Method, 2> =
                                entry.handlers.keys().copied().collect();

                            let mut cfg = if let Some(cfg) = &entry.options {
                                cfg.clone()
                            } else {
                                OptionsConfig::new(&format!("{}-default-1.0", service_name))
                                    .with_options_ttl(3600)
                                    .add_allow("204")
                            };

                            cfg.set_methods(allowed);

                            if cfg.service.is_none() {
                                cfg = cfg.with_service(&format!("ICAP Service {}", service_name));
                            }

                            if let (Some(n), None) = (advertised_max_conn, cfg.max_connections) {
                                cfg.with_max_connections(n);
                            }

                            cfg.build_response()
                        }
                        _ => {
                            // If exact method handler exists — call it; else 405.
                            if let Some(h) = entry.handlers.get(&method) {
                                h(req).await?
                            } else {
                                Response::new(StatusCode::MethodNotAllowed405, "Method Not Allowed")
                                    .add_header("Encapsulated", "null-body=0")
                                    .add_header("Content-Length", "0")
                            }
                        }
                    }
                } else if method == Method::Options {
                    Self::build_default_options_response(&service_name, advertised_max_conn)
                } else {
                    warn!("Service '{}' not found", service_name);
                    Response::new(StatusCode::NotFound404, "Service Not Found")
                        .add_header("Encapsulated", "null-body=0")
                        .add_header("Content-Length", "0")
                }
            };

            // === Write response and continue (keep-alive) ===
            let bytes = resp.to_raw()?;
            socket.write_all(&bytes).await?;
            socket.flush().await?;
            trace!("Response sent for service: {}", service_name);

            buf.drain(..msg_end);
        }
    }

    fn build_default_options_response(service_name: &str, advertised_max: Option<u32>) -> Response {
        let mut cfg = OptionsConfig::new(&format!("{}-default-1.0", service_name))
            .with_options_ttl(3600)
            .add_allow("204");

        cfg.set_methods([Method::RespMod]);

        cfg = cfg.with_service(&format!("ICAP Service {}", service_name));

        if let Some(n) = advertised_max {
            cfg.with_max_connections(n);
        }
        cfg.build_response()
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
    pending_options: HashMap<String, OptionsConfig>,
    max_connections_global: Option<usize>,
}

impl ServerBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            bind_addr: None,
            routes: HashMap::new(),
            pending_options: HashMap::new(),
            max_connections_global: None,
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
    /// not explicitly configured on the per-service `OptionsConfig`.
    pub fn with_max_connections(mut self, n: usize) -> Self {
        self.max_connections_global = Some(n.max(1));
        self
    }

    /// Register a **service route** for one or more ICAP methods.
    ///
    /// - Multiple calls to `.route(..)` for the **same service** are allowed
    ///   as long as methods do not overlap.
    /// - Registering the **same method** for the same service twice will `panic!`
    ///   with a clear message.
    /// - The same handler can be reused for multiple methods in a single call.
    pub fn route<MIt, MItem, F, Fut>(mut self, service: &str, methods: MIt, handler: F) -> Self
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

        if let Some(cfg) = self.pending_options.remove(&key) {
            entry.options = Some(cfg);
        }

        self
    }

    ///Register a route for `REQMOD` only.
    pub fn route_reqmod<F, Fut>(self, service: &str, handler: F) -> Self
    where
        F: Fn(Request) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = IcapResult<Response>> + Send + Sync + 'static,
    {
        self.route(service, [Method::ReqMod], handler)
    }

    /// Register a route for `RESPMOD` only.
    pub fn route_respmod<F, Fut>(self, service: &str, handler: F) -> Self
    where
        F: Fn(Request) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = IcapResult<Response>> + Send + Sync + 'static,
    {
        self.route(service, [Method::RespMod], handler)
    }

    /// Optional: set a per-service [`OptionsConfig`].
    ///
    /// Can be called **before or after** `.route(..)`; the config will be attached either way.
    pub fn set_options(mut self, service: &str, cfg: OptionsConfig) -> Self {
        let key = service.to_string();
        if let Some(entry) = self.routes.get_mut(&key) {
            entry.options = Some(cfg);
        } else {
            // store for later; attached in build() when the service is created
            self.pending_options.insert(key, cfg);
        }
        self
    }

    /// Finalize the builder and create a [`Server`].
    pub async fn build(mut self) -> IcapResult<Server> {
        for (svc, cfg) in self.pending_options.drain() {
            let entry = self.routes.entry(svc).or_insert_with(|| RouteEntry {
                handlers: HashMap::new(),
                options: None,
            });
            entry.options = Some(cfg);
        }

        let bind_addr = self
            .bind_addr
            .unwrap_or_else(|| "127.0.0.1:1344".to_string());
        let listener = TcpListener::bind(&bind_addr).await?;

        let conn_limit = self
            .max_connections_global
            .map(|n| Arc::new(Semaphore::new(n)));
        let advertised_max_conn = self.max_connections_global.map(|n| n as u32);

        Ok(Server {
            listener,
            routes: Arc::new(RwLock::new(self.routes)),
            conn_limit,
            advertised_max_conn,
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
    use std::panic::{AssertUnwindSafe, catch_unwind};

    async fn handler_ok(_: Request) -> IcapResult<Response> {
        Ok(Response::new(StatusCode::Ok200, "OK")
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

    #[test]
    fn route_allows_different_methods_same_service() {
        let h1 = handler_ok;
        let h2 = handler_ok;

        let _builder = Server::builder()
            .route("/spool", [Method::ReqMod], h1)
            .route("/spool", [Method::RespMod], h2);
    }

    #[test]
    fn route_panics_on_duplicate_method_same_service() {
        let h1 = handler_ok;
        let h2 = handler_ok;

        let builder = Server::builder().route("/spool", [Method::ReqMod], h1);

        let res = catch_unwind(AssertUnwindSafe(|| {
            let _ = builder.route("/spool", [Method::ReqMod], h2);
        }));

        assert!(res.is_err(), "expected panic on duplicate method route");
        let msg = panic_str(res.map(|_| ()));
        assert!(
            msg.contains("Overlapping method route")
                && msg.contains("REQMOD")
                && msg.contains("/spool"),
            "unexpected panic message: {msg}"
        );
    }

    #[test]
    fn panics_when_overlapping_multiple_methods() {
        let h = handler_ok;
        let h2 = handler_ok;

        let builder = Server::builder().route("/svc", [Method::ReqMod, Method::RespMod], h);

        let res = catch_unwind(AssertUnwindSafe(|| {
            let _ = builder.route("/svc", [Method::RespMod], h2);
        }));

        assert!(res.is_err(), "expected panic on overlapping RESPMOD");
        let msg = panic_str(res.map(|_| ()));
        assert!(
            msg.contains("Overlapping method route")
                && msg.contains("RESPMOD")
                && msg.contains("/svc"),
            "unexpected panic message: {msg}"
        );
    }

    #[test]
    fn route_accepts_string_methods_case_insensitive() {
        let h = handler_ok;
        let _b = Server::builder().route("/svc", ["reqmod", "RESPMOD"], h);
    }

    #[test]
    fn route_accepts_mixed_enum_and_string() {
        let h = handler_ok;
        let _b = Server::builder().route("/svc", vec![Method::ReqMod, "respmod".into()], h);
    }

    #[test]
    fn route_panics_on_unknown_method() {
        let h = handler_ok;

        let res = catch_unwind(AssertUnwindSafe(|| {
            let _ = Server::builder().route("/svc", ["FOO"], h);
        }));

        assert!(res.is_err(), "expected panic on unknown method string");
        let msg = panic_str(res.map(|_| ()));
        assert!(
            msg.contains("Unknown ICAP method string"),
            "unexpected panic message: {msg}"
        );
    }

    #[test]
    fn route_panics_on_options() {
        let h = handler_ok;

        let res = catch_unwind(AssertUnwindSafe(|| {
            let _ = Server::builder().route("/svc", ["OPTIONS"], h);
        }));

        assert!(
            res.is_err(),
            "expected panic when routing OPTIONS explicitly"
        );
        let msg = panic_str(res.map(|_| ()));
        assert!(
            msg.contains("OPTIONS is answered automatically")
                || msg.contains("OPTIONS cannot have a handler"),
            "unexpected panic message: {msg}"
        );
    }
}
