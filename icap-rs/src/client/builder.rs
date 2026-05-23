use crate::client::tls::{AnyTlsConnector, TlsBackend};
use crate::client::{Client, ClientRef, parse_authority_with_scheme};
use crate::{Error, IcapResult};
use http::{HeaderMap, HeaderName, HeaderValue};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

#[cfg(feature = "tls-rustls")]
use rustls::pki_types::CertificateDer;

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
#[derive(Debug)]
#[must_use]
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
    /// This extracts `host` and `port` for use in the TCP connection. The service path,
    /// if present in the URI, is ignored here and should be set on the request itself.
    /// `icaps://` enables TLS automatically.
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
                return Err(Error::Service(
                    "`icaps://` requested but crate built without TLS features".into(),
                ));
            }
        }
        Ok(self)
    }

    #[cfg(feature = "tls-rustls")]
    pub const fn use_rustls(mut self) -> Self {
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

    /// Compatibility toggle for disabling certificate verification.
    ///
    /// With rustls 0.23 this is currently a no-op, kept for API compatibility.
    pub const fn danger_disable_cert_verify(mut self, yes: bool) -> Self {
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

    /// Build a [`Client`], returning an error when required configuration is missing.
    pub fn try_build(self) -> IcapResult<Client> {
        let host = self
            .host
            .ok_or_else(|| Error::service("ClientBuilder: host is required"))?;
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
            Some(_) => return Err(Error::service("enable `tls-rustls` feature")),
        };

        Ok(Client {
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

impl Default for ClientBuilder {
    fn default() -> Self {
        Self {
            host: None,
            port: None,
            host_override: None,
            default_headers: HeaderMap::new(),
            connection_policy: ConnectionPolicy::default(),
            read_timeout: None,
            tls_backend: None,
            danger_disable_verify: false,
            sni_hostname: None,
            #[cfg(feature = "tls-rustls")]
            extra_roots: Vec::new(),
        }
    }
}
