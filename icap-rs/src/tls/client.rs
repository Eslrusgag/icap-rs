//! Client-side TLS configuration ([`ClientTlsConfig`]) and connector.
//!
//! See [`crate::tls`] for crypto-provider notes.

use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustls::client::ClientConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::RootCertStore;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{client::TlsStream, TlsConnector as TokioTlsConnector};
use tracing::warn;

use super::error::TlsError;
use super::pem::{load_cert_chain, load_private_key, load_roots_into};
use super::{ensure_crypto_provider, DEFAULT_HANDSHAKE_TIMEOUT};

/// Client-side TLS configuration for ICAPS connections.
///
/// Construct with [`ClientTlsConfig::with_native_roots`] (the typical
/// production setup), [`ClientTlsConfig::empty`] (for fully custom trust),
/// or [`ClientTlsConfig::from_rustls_config`] to plug in a pre-built
/// [`rustls::ClientConfig`].
///
/// Pass the finished value to [`crate::ClientBuilder::with_tls`].
#[must_use]
pub struct ClientTlsConfig {
    inner: ClientTlsInner,
    sni: Option<String>,
    handshake_timeout: Duration,
}

impl std::fmt::Debug for ClientTlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Intentionally redacted: private keys must not leak via Debug output.
        f.debug_struct("ClientTlsConfig")
            .field("sni", &self.sni)
            .field("handshake_timeout", &self.handshake_timeout)
            .field("source", &self.inner.kind())
            .finish()
    }
}

enum ClientTlsInner {
    /// Roots + optional client auth, assembled into a `ClientConfig`
    /// the first time it is needed.
    Builder {
        roots: RootCertStore,
        load_native: bool,
        client_auth: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
        disable_verify: bool,
    },
    /// Already assembled, possibly externally.
    Prebuilt(Arc<ClientConfig>),
}

impl ClientTlsConfig {
    /// Trust the platform's native root CAs.
    ///
    /// The roots are loaded lazily on first use so configuration is cheap.
    pub fn with_native_roots() -> Self {
        Self::new_builder(true)
    }

    /// Start with an empty trust store. Only roots added via
    /// [`ClientTlsConfig::add_root_ca_pem`] will be trusted.
    pub fn empty() -> Self {
        Self::new_builder(false)
    }

    fn new_builder(load_native: bool) -> Self {
        Self {
            inner: ClientTlsInner::Builder {
                roots: RootCertStore::empty(),
                load_native,
                client_auth: None,
                disable_verify: false,
            },
            sni: None,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        }
    }

    /// Wrap a pre-built [`rustls::ClientConfig`].
    ///
    /// Methods that modify the builder state ([`add_root_ca_pem`],
    /// [`with_client_auth_pem`], [`dangerous_disable_cert_verification`])
    /// return an error when called on a config constructed this way —
    /// configure the [`ClientConfig`] directly instead.
    ///
    /// [`add_root_ca_pem`]: Self::add_root_ca_pem
    /// [`with_client_auth_pem`]: Self::with_client_auth_pem
    /// [`dangerous_disable_cert_verification`]: Self::dangerous_disable_cert_verification
    pub const fn from_rustls_config(cfg: Arc<ClientConfig>) -> Self {
        Self {
            inner: ClientTlsInner::Prebuilt(cfg),
            sni: None,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        }
    }

    /// Append trust roots from a PEM file (one or more certificates).
    pub fn add_root_ca_pem(mut self, path: impl AsRef<Path>) -> Result<Self, TlsError> {
        self.inner = self.inner.add_root_ca_pem(path.as_ref())?;
        Ok(self)
    }

    /// Enable mutual TLS by presenting a client certificate chain and key.
    pub fn with_client_auth_pem(
        mut self,
        cert: impl AsRef<Path>,
        key: impl AsRef<Path>,
    ) -> Result<Self, TlsError> {
        self.inner = self
            .inner
            .with_client_auth_pem(cert.as_ref(), key.as_ref())?;
        Ok(self)
    }

    /// Override the SNI hostname used during the handshake.
    ///
    /// Useful when connecting to an IP literal whose certificate is issued
    /// for a DNS name, or when the ICAP `Host:` value should differ from
    /// the TLS server name.
    pub fn with_sni(mut self, name: impl Into<String>) -> Self {
        self.sni = Some(name.into());
        self
    }

    /// Override the TLS handshake timeout (default: 10s).
    pub const fn with_handshake_timeout(mut self, dur: Duration) -> Self {
        self.handshake_timeout = dur;
        self
    }

    /// **Disable server certificate verification entirely.**
    ///
    /// This is the equivalent of the `-tls-no-verify` flag in
    /// `c-icap-client`: any presented certificate is accepted and no
    /// hostname check is performed. Intended for local testing against
    /// self-signed deployments; never use in production.
    pub fn dangerous_disable_cert_verification(mut self) -> Result<Self, TlsError> {
        self.inner = self.inner.dangerous_disable_verify()?;
        Ok(self)
    }

    /// Build (and cache) the underlying [`rustls::ClientConfig`].
    pub(crate) fn into_connector(self) -> Result<ClientTlsConnector, TlsError> {
        ensure_crypto_provider()?;
        Ok(ClientTlsConnector {
            inner: Arc::new(ConnectorInner {
                source: self.inner,
                cached: OnceLock::new(),
            }),
            sni: self.sni,
            handshake_timeout: self.handshake_timeout,
        })
    }
}

impl ClientTlsInner {
    const fn kind(&self) -> &'static str {
        match self {
            Self::Builder { .. } => "builder",
            Self::Prebuilt(_) => "prebuilt-rustls-config",
        }
    }

    fn add_root_ca_pem(self, path: &Path) -> Result<Self, TlsError> {
        match self {
            Self::Builder {
                mut roots,
                load_native,
                client_auth,
                disable_verify,
            } => {
                load_roots_into(&mut roots, path)?;
                Ok(Self::Builder {
                    roots,
                    load_native,
                    client_auth,
                    disable_verify,
                })
            }
            Self::Prebuilt(_) => Err(TlsError::ConfigBuild(
                "extra roots cannot be added on top of a pre-built rustls ClientConfig".into(),
            )),
        }
    }

    fn with_client_auth_pem(self, cert: &Path, key: &Path) -> Result<Self, TlsError> {
        match self {
            Self::Builder {
                roots,
                load_native,
                client_auth: _,
                disable_verify,
            } => {
                let chain = load_cert_chain(cert)?;
                let key = load_private_key(key)?;
                Ok(Self::Builder {
                    roots,
                    load_native,
                    client_auth: Some((chain, key)),
                    disable_verify,
                })
            }
            Self::Prebuilt(_) => Err(TlsError::ConfigBuild(
                "client auth cannot be added on top of a pre-built rustls ClientConfig".into(),
            )),
        }
    }

    fn dangerous_disable_verify(self) -> Result<Self, TlsError> {
        match self {
            Self::Builder {
                roots,
                load_native,
                client_auth,
                disable_verify: _,
            } => {
                warn!(
                    "TLS server certificate verification disabled — insecure mode \
                     (equivalent to c-icap-client -tls-no-verify)"
                );
                Ok(Self::Builder {
                    roots,
                    load_native,
                    client_auth,
                    disable_verify: true,
                })
            }
            Self::Prebuilt(_) => Err(TlsError::ConfigBuild(
                "dangerous_disable_cert_verification cannot be combined with a pre-built \
                 rustls ClientConfig"
                    .into(),
            )),
        }
    }
}

/// Active TLS connector backed by a (lazily built) [`rustls::ClientConfig`].
///
/// Cheap to clone; the underlying config is shared via `Arc`.
#[derive(Clone)]
pub(crate) struct ClientTlsConnector {
    inner: Arc<ConnectorInner>,
    sni: Option<String>,
    handshake_timeout: Duration,
}

struct ConnectorInner {
    source: ClientTlsInner,
    cached: OnceLock<Result<Arc<ClientConfig>, String>>,
}

impl std::fmt::Debug for ClientTlsConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The `inner: Arc<ConnectorInner>` field intentionally holds keys and a
        // cached rustls config; we redact it via `finish_non_exhaustive`.
        f.debug_struct("ClientTlsConnector")
            .field("sni", &self.sni)
            .field("handshake_timeout", &self.handshake_timeout)
            .finish_non_exhaustive()
    }
}

impl ClientTlsConnector {
    /// Resolve the SNI hostname for this connection, preferring an explicit
    /// override over `fallback` (typically the connection host).
    pub(crate) fn resolve_sni<'a>(&'a self, fallback: &'a str) -> &'a str {
        self.sni.as_deref().unwrap_or(fallback)
    }

    /// Perform the TLS handshake on top of an already-connected TCP stream.
    pub(crate) async fn connect(
        &self,
        tcp: TcpStream,
        server_name: &str,
    ) -> Result<TlsStream<TcpStream>, TlsError> {
        let sni = ServerName::try_from(server_name.to_string())
            .map_err(|_| TlsError::InvalidServerName(server_name.to_string()))?;

        let cfg = self.inner.client_config()?;
        let connector = TokioTlsConnector::from(cfg);
        let handshake = connector.connect(sni, tcp);

        match timeout(self.handshake_timeout, handshake).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(e)) => Err(TlsError::Handshake(e)),
            Err(_) => Err(TlsError::HandshakeTimeout(self.handshake_timeout)),
        }
    }
}

impl ConnectorInner {
    fn client_config(&self) -> Result<Arc<ClientConfig>, TlsError> {
        let result = self
            .cached
            .get_or_init(|| build_client_config(&self.source).map(Arc::new));
        match result {
            Ok(cfg) => Ok(Arc::clone(cfg)),
            Err(msg) => Err(TlsError::ConfigBuild(msg.clone())),
        }
    }
}

fn build_client_config(source: &ClientTlsInner) -> Result<ClientConfig, String> {
    match source {
        ClientTlsInner::Prebuilt(cfg) => Ok((**cfg).clone()),
        ClientTlsInner::Builder {
            roots,
            load_native,
            client_auth,
            disable_verify,
        } => {
            let mut roots = roots.clone();
            if *load_native {
                let native = rustls_native_certs::load_native_certs();
                if !native.errors.is_empty() {
                    return Err(format!(
                        "failed to load platform trust roots: {} error(s)",
                        native.errors.len()
                    ));
                }
                for cert in native.certs {
                    roots
                        .add(cert)
                        .map_err(|e| format!("add platform root: {e}"))?;
                }
            }

            let base = ClientConfig::builder();
            let with_roots = if *disable_verify {
                base.dangerous()
                    .with_custom_certificate_verifier(Arc::new(danger::NoServerCertVerify::new()))
            } else {
                base.with_root_certificates(roots)
            };

            let cfg = match client_auth {
                None => with_roots.with_no_client_auth(),
                Some((chain, key)) => with_roots
                    .with_client_auth_cert(chain.clone(), key.clone_key())
                    .map_err(|e| format!("client auth: {e}"))?,
            };

            Ok(cfg)
        }
    }
}

mod danger {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::CryptoProvider;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::DigitallySignedStruct;

    /// Verifier that accepts any server certificate. Used **only** when
    /// the caller explicitly opted into
    /// [`super::ClientTlsConfig::dangerous_disable_cert_verification`].
    #[derive(Debug)]
    pub(super) struct NoServerCertVerify {
        provider: Option<&'static CryptoProvider>,
    }

    impl NoServerCertVerify {
        pub(super) fn new() -> Self {
            Self {
                provider: CryptoProvider::get_default().map(std::convert::AsRef::as_ref),
            }
        }

        fn supported_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.provider.map_or_else(Vec::new, |p| {
                p.signature_verification_algorithms.supported_schemes()
            })
        }
    }

    impl ServerCertVerifier for NoServerCertVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.supported_schemes()
        }
    }
}
