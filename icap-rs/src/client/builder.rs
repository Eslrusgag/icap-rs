use crate::client::{parse_authority_with_scheme, Client, ClientRef};
#[cfg(feature = "tls-rustls")]
use crate::tls::ClientTlsConfig;
use crate::{Error, IcapResult};
use http::{HeaderMap, HeaderName, HeaderValue};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// Policy for connection lifetime management.
///
/// - [`ConnectionPolicy::Close`] — close the TCP connection after every request.
/// - [`ConnectionPolicy::KeepAlive`] — keep a single idle connection and reuse it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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
#[derive(Debug, Default)]
#[must_use]
pub struct ClientBuilder {
    host: Option<String>,
    port: Option<u16>,
    host_override: Option<String>,
    default_headers: HeaderMap,
    connection_policy: ConnectionPolicy,
    read_timeout: Option<Duration>,

    // TLS state. `tls` is the user-supplied config (explicit `with_tls`),
    // `auto_tls` records whether `with_uri("icaps://...")` requested TLS.
    // At build time, an explicit config always wins; otherwise auto-TLS
    // defaults to native roots.
    #[cfg(feature = "tls-rustls")]
    tls: Option<ClientTlsConfig>,
    #[cfg(feature = "tls-rustls")]
    auto_tls: bool,
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
    pub const fn port(mut self, port: u16) -> Self {
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

    /// Tries to set the ICAP `User-Agent` header for all requests created by this client.
    ///
    /// A per-request override via `Request::icap_header("User-Agent", "...")`
    /// takes precedence over the value set here.
    /// Prefer this fallible variant when the value comes from user input.
    pub fn try_user_agent(mut self, user_agent: &str) -> IcapResult<Self> {
        self.default_headers.insert(
            HeaderName::from_static("user-agent"),
            HeaderValue::from_str(user_agent)?,
        );
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
    ///
    /// # Panics
    ///
    /// Panics if `user_agent` is not a valid HTTP header value. Use
    /// [`ClientBuilder::try_user_agent`] for untrusted input.
    pub fn user_agent(self, user_agent: &str) -> Self {
        self.try_user_agent(user_agent)
            .expect("invalid User-Agent header value")
    }

    /// Enable or disable connection reuse (keep-alive).
    pub const fn keep_alive(mut self, yes: bool) -> Self {
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
    pub const fn read_timeout(mut self, dur: Option<Duration>) -> Self {
        self.read_timeout = dur;
        self
    }

    /// Configure the builder from an ICAP URI (`icap://...` or `icaps://...`).
    ///
    /// This extracts `host` and `port` for use in the TCP connection. The service
    /// path, if present in the URI, is ignored here and should be set on the
    /// request itself. `icaps://` implicitly enables TLS using
    /// [`ClientTlsConfig::with_native_roots`]; call [`with_tls`](Self::with_tls)
    /// before or after `with_uri` to override the default TLS configuration.
    ///
    /// The default port is `1344` for `icap://` and `11344` for `icaps://`.
    pub fn with_uri(mut self, uri: &str) -> IcapResult<Self> {
        let (host, port, tls) = parse_authority_with_scheme(uri)?;
        self.host = Some(host);
        self.port = Some(port);
        if tls {
            #[cfg(feature = "tls-rustls")]
            {
                self.auto_tls = true;
            }
            #[cfg(not(feature = "tls-rustls"))]
            {
                return Err(Error::Service(
                    "`icaps://` requested but crate built without TLS features".into(),
                ));
            }
        }
        Ok(self)
    }

    /// Enable TLS using the supplied [`ClientTlsConfig`].
    ///
    /// Always wins over the implicit configuration enabled by
    /// [`with_uri("icaps://…")`](Self::with_uri).
    #[cfg(feature = "tls-rustls")]
    pub fn with_tls(mut self, config: ClientTlsConfig) -> Self {
        self.tls = Some(config);
        self
    }

    /// Build a [`Client`], returning an error when required configuration is missing.
    pub fn try_build(self) -> IcapResult<Client> {
        let host = self
            .host
            .ok_or_else(|| Error::service("ClientBuilder: host is required"))?;
        let port = self.port.unwrap_or(1344);

        #[cfg(feature = "tls-rustls")]
        let tls = {
            let cfg = match (self.tls, self.auto_tls) {
                (Some(cfg), _) => Some(cfg),
                (None, true) => Some(ClientTlsConfig::with_native_roots()),
                (None, false) => None,
            };
            cfg.map(ClientTlsConfig::into_connector).transpose()?
        };

        Ok(Client {
            inner: Arc::new(ClientRef {
                host,
                port,
                host_override: self.host_override,
                default_headers: self.default_headers,
                connection_policy: self.connection_policy,
                read_timeout: self.read_timeout,
                #[cfg(feature = "tls-rustls")]
                tls,
                idle_conn: Mutex::new(None),
            }),
        })
    }

    /// Build a [`Client`].
    ///
    /// # Panics
    ///
    /// Panics if required configuration is missing. Use
    /// [`ClientBuilder::try_build`] for fallible construction.
    pub fn build(self) -> Client {
        self.try_build().expect("ClientBuilder build failed")
    }
}
