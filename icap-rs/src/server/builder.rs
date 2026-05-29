use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::future::Future;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use tokio_util::task::TaskTracker;

use crate::error::IcapResult;
use crate::request::{IncomingRequest, RequestParserMode};
use crate::server::timeouts::ServerTimeouts;
use crate::server::{ShutdownEvent, default_shutdown_handler};
#[cfg(feature = "tls-rustls")]
use crate::tls::ServerTlsConfig;
use crate::{Method, ServiceOptions};

use super::Server;
use super::router::{HandlerEntry, RequestHandler, RouteEntry, RouteOutput, resolve_service};

/// Builder for [`Server`].
///
/// Construct with [`Server::builder`], register routes, then call [`ServerBuilder::build`].
///
/// Duplicate registration of the **same (service, method)** panics with a clear error,
/// like axum.
#[must_use]
pub struct ServerBuilder {
    bind_addr: Option<String>,
    routes: HashMap<String, RouteEntry>,
    max_connections_global: Option<usize>,
    aliases: HashMap<String, String>,
    default_service: Option<String>,
    request_parser_mode: RequestParserMode,
    timeouts: ServerTimeouts,
    shutdown_handler: Arc<dyn Fn(ShutdownEvent) + Send + Sync>,
    task_tracker: Option<TaskTracker>,
    #[cfg(feature = "tls-rustls")]
    tls: Option<ServerTlsConfig>,
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self {
            bind_addr: None,
            routes: HashMap::new(),
            max_connections_global: None,
            aliases: HashMap::new(),
            default_service: None,
            request_parser_mode: RequestParserMode::default(),
            timeouts: ServerTimeouts::default(),
            shutdown_handler: Arc::new(default_shutdown_handler),
            task_tracker: None,
            #[cfg(feature = "tls-rustls")]
            tls: None,
        }
    }
}

impl ServerBuilder {
    /// Enable ICAPS (ICAP over TLS) using the supplied [`ServerTlsConfig`].
    ///
    /// Configuration objects encapsulate the certificate chain, private key,
    /// optional client-certificate verification and the handshake timeout.
    /// See the [`crate::tls`] module for builders to construct one.
    ///
    /// Only available when the `tls-rustls` feature is enabled.
    ///
    /// # Example
    /// ```no_run
    /// use icap_rs::{
    ///     IcapResult, IncomingRequest, Method, Response, Server, ServerTlsConfig, ServiceOptions,
    /// };
    ///
    /// const ISTAG: &str = "scan-1.0";
    ///
    /// #[tokio::main]
    /// async fn main() -> IcapResult<()> {
    ///     let tls = ServerTlsConfig::from_pem_files("certs/server.crt", "certs/server.key")?;
    ///
    ///     let server = Server::builder()
    ///         .bind("0.0.0.0:11344")
    ///         .with_tls(tls)
    ///         .route(
    ///             "scan",
    ///             [Method::ReqMod, Method::RespMod],
    ///             |_req: IncomingRequest| async move {
    ///                 Ok(Response::no_content_with_istag(ISTAG)?)
    ///             },
    ///             Some(ServiceOptions::new()
    ///                 .with_static_istag(ISTAG)
    ///                 .with_preview(2048)
    ///                 .allow_204()),
    ///         )
    ///         .build().await?;
    ///
    ///     server.run().await
    /// }
    /// ```
    #[cfg(feature = "tls-rustls")]
    pub fn with_tls(mut self, config: ServerTlsConfig) -> Self {
        self.tls = Some(config);
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

    /// Install a full [`ServerTimeouts`] configuration in one shot.
    ///
    /// See [`ServerTimeouts`] for the meaning of each field. Defaults are
    /// `None` (no timeout); fields not set on the supplied value disable the
    /// corresponding deadline.
    pub const fn with_timeouts(mut self, timeouts: ServerTimeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    /// Register a callback that is called with [`ShutdownEvent`] during graceful shutdown.
    ///
    /// The handler runs synchronously inside the accept loop task — keep it fast.
    /// Use it for custom logging, metrics, or alerting. When not set, the server
    /// logs via [`tracing::warn`] by default.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use icap_rs::{IcapResult, Server, ShutdownEvent};
    ///
    /// #[tokio::main]
    /// async fn main() -> IcapResult<()> {
    ///     let server = Server::builder()
    ///         .bind("127.0.0.1:1344")
    ///         .on_shutdown_event(|event| match event {
    ///             ShutdownEvent::Draining { active_connections, drain_timeout } => {
    ///                 eprintln!("[shutdown] {active_connections} connection(s) still active");
    ///                 if let Some(d) = drain_timeout {
    ///                     eprintln!("[shutdown] force-close in {d:.1?}");
    ///                 }
    ///             }
    ///             ShutdownEvent::DrainTimedOut { remaining_connections } => {
    ///                 eprintln!("[shutdown] timed out, cancelling {remaining_connections}");
    ///             }
    ///             _ => {}
    ///         })
    ///         .build()
    ///         .await?;
    ///
    ///     server.run_until(async { tokio::signal::ctrl_c().await.ok(); }).await
    /// }
    /// ```
    pub fn on_shutdown_event<F>(mut self, handler: F) -> Self
    where
        F: Fn(ShutdownEvent) + Send + Sync + 'static,
    {
        self.shutdown_handler = Arc::new(handler);
        self
    }

    /// Enable legacy compatibility request parsing.
    ///
    /// Strict RFC parsing is the default and requires every ICAP request,
    /// including `OPTIONS`, to carry an `Encapsulated` header. This opt-in mode
    /// accepts legacy `OPTIONS` requests without `Encapsulated`.
    pub const fn with_compatibility_request_parser(mut self) -> Self {
        self.request_parser_mode = RequestParserMode::Compatibility;
        self
    }

    /// Register a **service route** for one or more ICAP methods.
    ///
    /// - Each service must have a [`ServiceOptions`] value with an explicit
    ///   `ISTag`; routes without options are rejected by [`build`](Self::build).
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
        F: Fn(IncomingRequest) -> Fut + Send + Sync + 'static,
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

    /// Register a route for `REQMOD` only.
    ///
    /// Convenience wrapper around [`route`](Self::route) with `methods = [Method::ReqMod]`.
    /// See [`route`](Self::route) for full semantics, including panic conditions on
    /// duplicate (service, method) registration and `ServiceOptions` requirements.
    ///
    /// # Panics
    ///
    /// Panics if a `REQMOD` handler for the same `service` was already registered,
    /// or if `options` is provided more than once for the same service.
    pub fn route_reqmod<F, Fut>(
        self,
        service: &str,
        handler: F,
        options: Option<ServiceOptions>,
    ) -> Self
    where
        F: Fn(IncomingRequest) -> Fut + Send + Sync + 'static,
        Fut: Future + Send + 'static,
        Fut::Output: RouteOutput,
    {
        self.route(service, [Method::ReqMod], handler, options)
    }

    /// Register a route for `RESPMOD` only.
    ///
    /// Convenience wrapper around [`route`](Self::route) with `methods = [Method::RespMod]`.
    /// See [`route`](Self::route) for full semantics, including panic conditions on
    /// duplicate (service, method) registration and `ServiceOptions` requirements.
    ///
    /// # Panics
    ///
    /// Panics if a `RESPMOD` handler for the same `service` was already registered,
    /// or if `options` is provided more than once for the same service.
    pub fn route_respmod<F, Fut>(
        self,
        service: &str,
        handler: F,
        options: Option<ServiceOptions>,
    ) -> Self
    where
        F: Fn(IncomingRequest) -> Fut + Send + Sync + 'static,
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

    /// Register a [`TaskTracker`] for user-owned background tasks.
    ///
    /// After all active connections drain following a shutdown signal, the server
    /// calls [`TaskTracker::close`] on the tracker and waits for all tracked tasks
    /// to finish before returning from [`Server::run_until`].
    ///
    /// If a drain timeout is configured via [`ServerTimeouts::with_shutdown_drain`],
    /// the remaining budget is shared: once the drain deadline fires the tracker
    /// wait is skipped and the server returns immediately.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use icap_rs::{IcapResult, Server};
    /// use tokio_util::task::TaskTracker;
    ///
    /// #[tokio::main]
    /// async fn main() -> IcapResult<()> {
    ///     let tracker = TaskTracker::new();
    ///
    ///     // Spawn a background task and track it so the server waits for it on shutdown.
    ///     tracker.spawn(async {
    ///         // background work ...
    ///     });
    ///
    ///     let server = Server::builder()
    ///         .bind("127.0.0.1:1344")
    ///         .with_task_tracker(tracker)
    ///         .build()
    ///         .await?;
    ///
    ///     server.run_until(async { tokio::signal::ctrl_c().await.ok(); }).await
    /// }
    /// ```
    pub fn with_task_tracker(mut self, tracker: TaskTracker) -> Self {
        self.task_tracker = Some(tracker);
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
        let tls = self.tls.map(ServerTlsConfig::into_acceptor).transpose()?;

        Ok(Server {
            listener,
            routes: Arc::new(self.routes),
            conn_limit,
            advertised_max_conn,
            aliases: Arc::new(self.aliases),
            default_service: self.default_service,
            request_parser_mode: self.request_parser_mode,
            timeouts: self.timeouts,
            shutdown_handler: self.shutdown_handler,
            task_tracker: self.task_tracker,

            #[cfg(feature = "tls-rustls")]
            tls,
        })
    }
}

fn validate_builder_config(
    routes: &HashMap<String, RouteEntry>,
    aliases: &HashMap<String, String>,
    default_service: Option<&str>,
) -> IcapResult<()> {
    use crate::error::ConfigError;

    if let Some(default) = default_service {
        let resolved = resolve_service(default, aliases, None);
        if !routes.contains_key(resolved.as_ref()) {
            return Err(ConfigError::UnknownDefaultService {
                name: default.to_owned(),
                resolved: resolved.into_owned(),
            }
            .into());
        }
    }

    for (from, to) in aliases {
        let resolved = resolve_service(to, aliases, None);
        if !routes.contains_key(resolved.as_ref()) {
            return Err(ConfigError::UnknownAlias {
                from: from.clone(),
                resolved: resolved.into_owned(),
            }
            .into());
        }
    }

    for (service, entry) in routes {
        if entry.handlers.is_empty() {
            return Err(ConfigError::ServiceWithoutHandlers {
                service: service.clone(),
            }
            .into());
        }
        let Some(options) = &entry.options else {
            return Err(ConfigError::MissingServiceOptions {
                service: service.clone(),
            }
            .into());
        };
        if let Err(err) = options.validate() {
            return Err(ConfigError::InvalidServiceOptions {
                service: service.clone(),
                reason: err,
            }
            .into());
        }
    }

    Ok(())
}
