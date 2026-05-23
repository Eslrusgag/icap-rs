use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::future::Future;
#[cfg(feature = "tls-rustls")]
use std::path::PathBuf;
use std::sync::Arc;

#[cfg(feature = "tls-rustls")]
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
#[cfg(feature = "tls-rustls")]
use rustls::{RootCertStore, ServerConfig};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
#[cfg(feature = "tls-rustls")]
use tokio_rustls::TlsAcceptor;

use crate::error::IcapResult;
use crate::request::{IncomingRequest, RequestParserMode};
use crate::{Method, ServiceOptions};

use super::Server;
use super::router::{HandlerEntry, RequestHandler, RouteEntry, RouteOutput, resolve_service};

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
    request_parser_mode: RequestParserMode,
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
    /// use icap_rs::{IcapResult, IncomingRequest, Method, Response, Server, ServiceOptions};
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
    /// use icap_rs::{IcapResult, IncomingRequest, Method, Response, Server, ServiceOptions};
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

    /// Enable legacy compatibility request parsing.
    ///
    /// Strict RFC parsing is the default and requires every ICAP request,
    /// including `OPTIONS`, to carry an `Encapsulated` header. This opt-in mode
    /// accepts legacy `OPTIONS` requests without `Encapsulated`.
    pub const fn with_compatibility_request_parser(mut self) -> Self {
        self.request_parser_mode = RequestParserMode::Compatibility;
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

    /// Register a route for `REQMOD` only
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
            request_parser_mode: self.request_parser_mode,

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
        let resolved = resolve_service(default, aliases, None);
        if !routes.contains_key(resolved.as_ref()) {
            return Err(crate::error::Error::service(format!(
                "Default service '{default}' resolves to unknown service '{}'",
                resolved.as_ref()
            )));
        }
    }

    for (from, to) in aliases {
        let resolved = resolve_service(to, aliases, None);
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
