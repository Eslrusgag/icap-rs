use crate::client::options_cache::{OptionsCache, OptionsCacheConfig};
use crate::client::timeouts::ClientTimeouts;
use crate::client::{Client, ClientRef, parse_authority_with_scheme};

#[cfg(feature = "tls-rustls")]
use crate::tls::ClientTlsConfig;
use crate::{Error, IcapResult};
use http::{HeaderMap, HeaderName, HeaderValue};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// Credentials for `Proxy-Authorization: Basic` authentication (RFC 3507 §7.1).
///
/// Supply via [`ClientBuilder::proxy_auth`]. When the ICAP server responds
/// with `407 Proxy Authentication Required`, the client retries the request
/// once with a `Proxy-Authorization: Basic <base64(username:password)>` header.
///
/// # Examples
///
/// ```
/// use icap_rs::{Client, ProxyAuth};
///
/// let client = Client::builder()
///     .host("127.0.0.1")
///     .proxy_auth("user", "secret")
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct ProxyAuth {
    pub(crate) username: String,
    pub(crate) password: String,
}

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
/// timeouts, and other options before creating a client instance.
///
/// By default:
/// - `ConnectionPolicy` is `Close`;
/// - no host/port are set until you call [`ClientBuilder::host`] / [`ClientBuilder::port`]
///   or [`ClientBuilder::with_uri`].
/// - no operation timeouts are applied unless configured explicitly.
#[derive(Debug, Default)]
#[must_use]
pub struct ClientBuilder {
    host: Option<String>,
    port: Option<u16>,
    host_override: Option<String>,
    default_headers: HeaderMap,
    connection_policy: ConnectionPolicy,
    timeouts: ClientTimeouts,
    max_response_header_bytes: Option<usize>,

    // OPTIONS cache. `None` keeps the legacy behavior (no automatic OPTIONS).
    options_cache: Option<OptionsCacheConfig>,

    // Proxy authentication credentials. `None` → no automatic 407 retry.
    proxy_auth: Option<ProxyAuth>,

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
    /// Invalid header values are silently dropped; use
    /// [`ClientBuilder::try_user_agent`] when validation is required.
    pub fn user_agent(mut self, user_agent: &str) -> Self {
        if let Ok(v) = HeaderValue::from_str(user_agent) {
            self.default_headers
                .insert(HeaderName::from_static("user-agent"), v);
        }
        self
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

    /// Install a full [`ClientTimeouts`] configuration in one shot.
    ///
    /// Replaces any per-field timeouts set via [`Self::timeout`],
    /// [`Self::connect_timeout`], [`Self::write_timeout`], or
    /// [`Self::continue_timeout`]. Per-field setters called *after*
    /// `with_timeouts` continue to mutate the same struct, so
    ///
    /// ```
    /// use std::time::Duration;
    /// use icap_rs::{Client, ClientTimeouts};
    ///
    /// let tos = ClientTimeouts::default();
    /// let d = Duration::from_secs(3);
    /// let _client = Client::builder()
    ///     .host("icap.example")
    ///     .with_timeouts(tos)
    ///     .connect_timeout(Some(d))
    ///     .build();
    /// ```
    ///
    /// is equivalent to mutating `tos.connect` before passing it in.
    pub const fn with_timeouts(mut self, timeouts: ClientTimeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    /// Set a timeout for the whole client send operation.
    ///
    /// This is an outer deadline around connect, optional TLS handshake, writes,
    /// Preview negotiation, and final response reads. More specific timeouts may
    /// still fire first.
    pub const fn timeout(mut self, dur: Option<Duration>) -> Self {
        self.timeouts.operation = dur;
        self
    }

    /// Set a timeout for establishing the TCP connection.
    ///
    /// For `icaps://`, this covers TCP connect only. TLS handshakes are governed
    /// by `ClientTlsConfig::with_handshake_timeout`.
    pub const fn connect_timeout(mut self, dur: Option<Duration>) -> Self {
        self.timeouts.connect = dur;
        self
    }

    /// Set a timeout for writing ICAP request bytes to the network.
    ///
    /// This covers request headers, preview markers, body chunks, and flushes.
    /// It does not limit reading from the caller-provided body source.
    pub const fn write_timeout(mut self, dur: Option<Duration>) -> Self {
        self.timeouts.write = dur;
        self
    }

    /// Set a timeout for Preview decision responses.
    ///
    /// When a request uses ICAP Preview, the client waits for either
    /// `100 Continue` or an early final response before sending the remainder.
    /// If this timeout is not set, only the outer [`timeout`](Self::timeout)
    /// applies when configured.
    pub const fn continue_timeout(mut self, dur: Option<Duration>) -> Self {
        self.timeouts.continue_after_preview = dur;
        self
    }

    /// Set the maximum ICAP response header block size, in bytes.
    ///
    /// The limit includes the status line, all ICAP header lines, and the
    /// terminating `CRLFCRLF`. The default is 64 KiB. Oversized response
    /// headers are reported as protocol header errors instead of generic I/O
    /// failures.
    pub const fn with_response_header_limit(mut self, bytes: usize) -> Self {
        self.max_response_header_bytes = Some(bytes);
        self
    }

    /// Enable client-side caching of `OPTIONS` responses (RFC 3507 §4.10 / §5).
    ///
    /// When enabled, the client fetches `OPTIONS` for a service once and reuses
    /// it for subsequent `REQMOD`/`RESPMOD` requests until it expires. The
    /// lifetime comes from the server's `Options-TTL` header, falling back to
    /// [`OptionsCacheConfig::default_ttl`] when the header is absent; with
    /// neither, the response is not cached. A changed `ISTag` on a later
    /// modification response invalidates the cached entry.
    ///
    /// Caching is opt-in: without this call the client never sends `OPTIONS`
    /// automatically.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use icap_rs::{Client, OptionsCacheConfig};
    ///
    /// let client = Client::builder()
    ///     .host("127.0.0.1")
    ///     .with_options_cache(OptionsCacheConfig::new().with_default_ttl(Duration::from_secs(60)))
    ///     .build();
    /// ```
    pub const fn with_options_cache(mut self, config: OptionsCacheConfig) -> Self {
        self.options_cache = Some(config);
        self
    }

    /// Configure proxy authentication credentials (RFC 3507 §7.1).
    ///
    /// When the ICAP server responds with `407 Proxy Authentication Required`,
    /// the client retries the request exactly once with a
    /// `Proxy-Authorization: Basic <base64(username:password)>` header.
    ///
    /// If the retry also yields a `407` (wrong credentials), the error response
    /// is returned to the caller as-is.
    ///
    /// # Examples
    ///
    /// ```
    /// use icap_rs::Client;
    ///
    /// let client = Client::builder()
    ///     .host("proxy.example.com")
    ///     .proxy_auth("alice", "hunter2")
    ///     .build();
    /// ```
    pub fn proxy_auth(mut self, username: &str, password: &str) -> Self {
        self.proxy_auth = Some(ProxyAuth {
            username: username.to_string(),
            password: password.to_string(),
        });
        self
    }

    /// Configure the builder from an ICAP URI (`icap://...` or `icaps://...`).
    ///
    /// This extracts `host` and `port` for use in the TCP connection. The service
    /// path, if present in the URI, is ignored here and should be set on the
    /// request itself. `icaps://` implicitly enables TLS using
    /// `ClientTlsConfig::with_native_roots`; call `with_tls` before or after
    /// `with_uri` to override the default TLS configuration.
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
                return Err(Error::service(
                    "`icaps://` requested but crate built without TLS features",
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
    ///
    /// # Errors
    ///
    /// Returns an error if `host` was not set via [`ClientBuilder::host`] or
    /// [`ClientBuilder::with_uri`].
    pub fn try_build(self) -> IcapResult<Client> {
        let host = self
            .host
            .clone()
            .ok_or_else(|| Error::service("ClientBuilder: host is required"))?;
        Ok(self.finish_with_host(host))
    }

    /// Build a [`Client`], defaulting `host` to `"127.0.0.1"` when unset.
    ///
    /// Use [`ClientBuilder::try_build`] when missing configuration should be
    /// reported as an error instead of being silently defaulted.
    pub fn build(self) -> Client {
        let host = self.host.clone().unwrap_or_else(|| "127.0.0.1".to_string());
        self.finish_with_host(host)
    }

    fn finish_with_host(self, host: String) -> Client {
        let port = self.port.unwrap_or(1344);

        #[cfg(feature = "tls-rustls")]
        let tls = {
            let cfg = match (self.tls, self.auto_tls) {
                (Some(cfg), _) => Some(cfg),
                (None, true) => Some(ClientTlsConfig::with_native_roots()),
                (None, false) => None,
            };
            cfg.map(ClientTlsConfig::into_connector)
        };

        let options_cache = self.options_cache.map(OptionsCache::new);

        Client {
            inner: Arc::new(ClientRef {
                host,
                port,
                host_override: self.host_override,
                default_headers: self.default_headers,
                connection_policy: self.connection_policy,
                timeouts: self.timeouts,
                max_response_header_bytes: self
                    .max_response_header_bytes
                    .unwrap_or(crate::DEFAULT_ICAP_HEADER_BYTES),
                #[cfg(feature = "tls-rustls")]
                tls,
                idle_conn: Mutex::new(None),
                options_cache,
                proxy_auth: self.proxy_auth,
            }),
        }
    }
}
