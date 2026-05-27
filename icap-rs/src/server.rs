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
//! use icap_rs::{IcapResult, IncomingRequest, Method, Response, Server, ServiceOptions, StatusCode};
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
//!             |req: IncomingRequest| async move {
//!                 match req.method() {
//!                     Method::ReqMod => Ok(Response::no_content_with_istag(ISTAG)?),
//!                     Method::RespMod => Ok(Response::no_content_with_istag(ISTAG)?),
//!                     Method::Options => unreachable!("OPTIONS is handled automatically by the server"),
//!                 }
//!             },
//!             Some(ServiceOptions::new().with_static_istag(ISTAG)
//!                 .with_service("Scan Service")
//!                 .allow_204()
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

mod builder;
mod connection;
mod errors;
pub mod handler;
mod no_modification;
pub mod options;
mod preview;
mod router;
pub mod timeouts;
pub use builder::ServerBuilder;
pub use handler::{BoxError, HandlerError, HandlerResult};
pub use preview::PreviewDecision;
pub use router::RouteOutput;
pub use timeouts::ServerTimeouts;

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
#[cfg(feature = "tls-rustls")]
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{error, trace, warn};

use crate::error::IcapResult;
use crate::request::RequestParserMode;
pub use crate::server::options::{IsTagHandle, ServiceOptions, TransferBehavior};
use crate::{Response, StatusCode};
use router::RouteEntry;
#[cfg(feature = "tls-rustls")]
use tokio_rustls::TlsAcceptor;

/// ICAP server.
///
/// Use [`Server::builder`] to construct and run an instance.
///
/// # Example
///
/// ```rust,no_run
/// use icap_rs::{IcapResult, IncomingRequest, Method, Response, Server, ServiceOptions};
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
///             |_req: IncomingRequest| async move {
///                 Ok(Response::no_content_with_istag(ISTAG)?)
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
    request_parser_mode: RequestParserMode,
    timeouts: ServerTimeouts,
    #[cfg(feature = "tls-rustls")]
    tls: Option<(TlsAcceptor, Duration)>,
}
impl Server {
    /// Create a new [`ServerBuilder`].
    pub fn builder() -> ServerBuilder {
        ServerBuilder::default()
    }

    /// Local socket address the server is bound to.
    ///
    /// Useful after binding to an ephemeral port (`127.0.0.1:0`).
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Run the accept loop until the process is killed.
    ///
    /// This is a convenience wrapper around [`run_until`](Self::run_until) with a
    /// `pending()` shutdown future, meaning the server runs indefinitely.
    /// Use [`run_until`](Self::run_until) when you need graceful shutdown.
    pub async fn run(self) -> IcapResult<()> {
        self.run_until(std::future::pending::<()>()).await
    }

    /// Run the accept loop until `shutdown` resolves, then drain active connections.
    ///
    /// When `shutdown` completes the server stops accepting new connections and
    /// signals all active keep-alive connections to close after their current
    /// in-flight request completes. Idle connections (waiting for the next
    /// request) are closed immediately. The method returns only after every
    /// active connection handler has finished.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use icap_rs::{IcapResult, Server};
    ///
    /// #[tokio::main]
    /// async fn main() -> IcapResult<()> {
    ///     let server = Server::builder()
    ///         .bind("127.0.0.1:1344")
    ///         .build()
    ///         .await?;
    ///
    ///     // Shut down cleanly on Ctrl-C.
    ///     server.run_until(async { tokio::signal::ctrl_c().await.ok(); }).await
    /// }
    /// ```
    pub async fn run_until<F>(self, shutdown: F) -> IcapResult<()>
    where
        F: Future<Output = ()>,
    {
        let local_addr = self.listener.local_addr()?;
        trace!(addr=%local_addr, "ICAP server started");

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut tasks: JoinSet<()> = JoinSet::new();

        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                biased;

                () = &mut shutdown => {
                    // Signal all active connections to close after their current request.
                    let _ = shutdown_tx.send(true);
                    let active = tasks.len();
                    if active > 0 {
                        if let Some(d) = self.timeouts.shutdown_drain {
                            warn!(
                                addr=%local_addr,
                                connections=%active,
                                "shutting down; draining {active} active connection(s); \
                                 new connections will be refused; \
                                 force-close in {d:.1?}",
                            );
                        } else {
                            warn!(
                                addr=%local_addr,
                                connections=%active,
                                "shutting down; draining {active} active connection(s); \
                                 new connections will be refused",
                            );
                        }
                    } else {
                        trace!(addr=%local_addr, "shutting down; no active connections");
                    }
                    break;
                }

                accept_result = self.listener.accept() => {
                    let (socket, addr) = accept_result?;
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
                    let request_parser_mode = self.request_parser_mode;
                    let timeouts = self.timeouts.clone();
                    let conn_shutdown = shutdown_rx.clone();

                    #[cfg(feature = "tls-rustls")]
                    let tls = self.tls.clone();

                    tasks.spawn(async move {
                        let _permit = permit_opt;

                        if over_limit {
                            // Reject before TLS handshake: avoids spending CPU on handshakes
                            // just to reject. For TLS, close the raw TCP socket instead.
                            #[cfg(feature = "tls-rustls")]
                            if tls.is_some() {
                                let mut sock = socket;
                                let _ = sock.shutdown().await;
                                return;
                            }

                            let resp =
                                Response::new(StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable")
                                    .add_header("Connection", "close");
                            match resp.to_raw() {
                                Ok(bytes) => {
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
                        if let Some((acceptor, hs_timeout)) = tls {
                            match timeout(hs_timeout, acceptor.accept(socket)).await {
                                Ok(Ok(stream)) => {
                                    if let Err(e) = Box::pin(Self::handle_connection(
                                        stream,
                                        routes,
                                        aliases,
                                        default_service,
                                        advertised_max,
                                        request_parser_mode,
                                        timeouts,
                                        conn_shutdown,
                                        addr,
                                    ))
                                    .await
                                    {
                                        error!(client=%addr, error=%e, "error handling TLS connection");
                                    }
                                }
                                Ok(Err(e)) => {
                                    warn!(client=%addr, error=%e, "TLS handshake failed");
                                }
                                Err(_) => {
                                    warn!(
                                        client=%addr,
                                        timeout=?hs_timeout,
                                        "TLS handshake timed out",
                                    );
                                }
                            }
                            return;
                        }

                        // Plain TCP
                        if let Err(e) = Box::pin(Self::handle_connection(
                            socket,
                            routes,
                            aliases,
                            default_service,
                            advertised_max,
                            request_parser_mode,
                            timeouts,
                            conn_shutdown,
                            addr,
                        ))
                        .await
                        {
                            error!(client=%addr, error=%e, "error handling connection");
                        }
                    });
                }
            }
        }

        // Wait for all in-flight connections to complete.
        if let Some(drain_timeout) = self.timeouts.shutdown_drain {
            if timeout(drain_timeout, async {
                while tasks.join_next().await.is_some() {}
            })
            .await
            .is_err()
            {
                let remaining = tasks.len();
                warn!(
                    addr=%local_addr,
                    connections=%remaining,
                    "shutdown drain timeout ({drain_timeout:.1?}) expired; \
                     cancelling {remaining} remaining connection(s)",
                );
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
            }
        } else {
            while tasks.join_next().await.is_some() {}
        }
        trace!(addr=%local_addr, "ICAP server stopped");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IncomingRequest, Method};
    use rstest::rstest;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    async fn handler_ok(_: IncomingRequest) -> crate::HandlerResult<Response> {
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
        assert!(msg.contains("default service"), "unexpected error: {msg}");
        assert!(msg.contains("missing"), "unexpected error: {msg}");
    }

    #[tokio::test]
    async fn build_errors_when_alias_target_is_unknown() {
        let options = ServiceOptions::new().with_static_istag("svc-1.0");
        let result = Server::builder()
            .route_reqmod("svc", handler_ok, Some(options))
            .alias("alt", "missing")
            .build()
            .await;
        let err = result
            .err()
            .expect("unknown alias target should fail at build time");

        let msg = err.to_string();
        assert!(msg.contains("alias"), "unexpected error: {msg}");
        assert!(msg.contains("missing"), "unexpected error: {msg}");
    }

    #[tokio::test]
    async fn build_errors_when_service_options_are_invalid() {
        let options = ServiceOptions::new()
            .with_static_istag("svc-1.0")
            .add_transfer_rule("exe", TransferBehavior::Preview);
        let result = Server::builder()
            .route_reqmod("svc", handler_ok, Some(options))
            .build()
            .await;
        let err = result
            .err()
            .expect("invalid service options should fail at build time");

        let msg = err.to_string();
        assert!(msg.contains("invalid options"), "unexpected error: {msg}");
        assert!(
            msg.contains("Default transfer behavior"),
            "unexpected error: {msg}"
        );
    }

    #[tokio::test]
    async fn build_errors_when_service_options_are_missing() {
        let result = Server::builder()
            .route_reqmod("svc", handler_ok, None)
            .build()
            .await;
        let err = result
            .err()
            .expect("missing service options should fail at build time");

        let msg = err.to_string();
        assert!(msg.contains("ServiceOptions"), "unexpected error: {msg}");
        assert!(msg.contains("ISTag"), "unexpected error: {msg}");
    }
}
