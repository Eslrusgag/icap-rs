//! Server-side TLS configuration ([`ServerTlsConfig`]).
//!
//! See [`crate::tls`] for crypto-provider notes.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ServerConfig, WebPkiClientVerifier};
use tokio_rustls::TlsAcceptor;

use super::error::TlsError;
use super::pem::{
    load_cert_chain, load_private_key, load_roots_into, parse_cert_chain, parse_private_key,
    parse_roots_into,
};
use super::{DEFAULT_HANDSHAKE_TIMEOUT, ensure_crypto_provider};

/// Server-side TLS configuration for ICAPS listeners.
///
/// Construct with [`ServerTlsConfig::from_pem`] to parse a certificate chain
/// and private key from PEM data, [`ServerTlsConfig::from_pem_files`] to load
/// them from disk, or [`ServerTlsConfig::from_rustls_config`] to plug in a
/// pre-built [`rustls::ServerConfig`].
///
/// After construction, configure client authentication (optional or
/// required) and the handshake timeout, then hand the value to
/// [`crate::ServerBuilder::with_tls`].
#[must_use]
pub struct ServerTlsConfig {
    inner: ServerTlsInner,
    handshake_timeout: Duration,
}

enum ServerTlsInner {
    Pem {
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        client_auth: ClientAuth,
    },
    Prebuilt(Arc<ServerConfig>),
}

#[derive(Default)]
enum ClientAuth {
    #[default]
    None,
    Required(RootCertStore),
    Optional(RootCertStore),
}

impl ServerTlsConfig {
    /// Parse a certificate chain and private key from PEM data.
    ///
    /// `cert_pem` must contain the server certificate followed by any
    /// intermediates. `key_pem` may contain a PKCS#8, PKCS#1 (RSA) or
    /// SEC1 (EC) encoded private key.
    pub fn from_pem(
        cert_pem: impl AsRef<[u8]>,
        key_pem: impl AsRef<[u8]>,
    ) -> Result<Self, TlsError> {
        let certs = parse_cert_chain("<server certificate PEM>", cert_pem)?;
        let key = parse_private_key("<server private key PEM>", key_pem)?;
        Ok(Self::from_certified_key(certs, key))
    }

    /// Load a certificate chain and private key from PEM files on disk.
    ///
    /// `cert_pem` must contain the server certificate followed by any
    /// intermediates. `key_pem` may contain a PKCS#8, PKCS#1 (RSA) or
    /// SEC1 (EC) encoded private key.
    pub fn from_pem_files(
        cert_pem: impl AsRef<Path>,
        key_pem: impl AsRef<Path>,
    ) -> Result<Self, TlsError> {
        let certs = load_cert_chain(cert_pem.as_ref())?;
        let key = load_private_key(key_pem.as_ref())?;
        Ok(Self::from_certified_key(certs, key))
    }

    const fn from_certified_key(
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Self {
        Self {
            inner: ServerTlsInner::Pem {
                certs,
                key,
                client_auth: ClientAuth::None,
            },
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        }
    }

    /// Wrap a pre-built [`rustls::ServerConfig`] so the same builder API
    /// can be used with a fully customised TLS configuration
    /// (custom verifiers, session storage, cipher suites, …).
    pub const fn from_rustls_config(cfg: Arc<ServerConfig>) -> Self {
        Self {
            inner: ServerTlsInner::Prebuilt(cfg),
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        }
    }

    /// Require client certificates that validate against the CA(s) in `ca_pem`.
    ///
    /// Clients that present no certificate, or one that does not chain to a
    /// configured CA, are rejected during the handshake.
    pub fn with_client_auth_pem(mut self, ca_pem: impl AsRef<[u8]>) -> Result<Self, TlsError> {
        let mut roots = RootCertStore::empty();
        parse_roots_into(&mut roots, "<client CA PEM>", ca_pem)?;
        self.inner = self.inner.with_client_auth(ClientAuth::Required(roots))?;
        Ok(self)
    }

    /// Require client certificates that validate against CA PEM file(s) on disk.
    pub fn with_client_auth_pem_file(mut self, ca_pem: impl AsRef<Path>) -> Result<Self, TlsError> {
        let mut roots = RootCertStore::empty();
        load_roots_into(&mut roots, ca_pem.as_ref())?;
        self.inner = self.inner.with_client_auth(ClientAuth::Required(roots))?;
        Ok(self)
    }

    /// Request — but do not require — client certificates.
    ///
    /// When present, certificates must still validate against `ca_pem`; clients
    /// presenting no certificate are accepted.
    pub fn with_optional_client_auth_pem(
        mut self,
        ca_pem: impl AsRef<[u8]>,
    ) -> Result<Self, TlsError> {
        let mut roots = RootCertStore::empty();
        parse_roots_into(&mut roots, "<client CA PEM>", ca_pem)?;
        self.inner = self.inner.with_client_auth(ClientAuth::Optional(roots))?;
        Ok(self)
    }

    /// Request optional client certificates using CA PEM file(s) on disk.
    pub fn with_optional_client_auth_pem_file(
        mut self,
        ca_pem: impl AsRef<Path>,
    ) -> Result<Self, TlsError> {
        let mut roots = RootCertStore::empty();
        load_roots_into(&mut roots, ca_pem.as_ref())?;
        self.inner = self.inner.with_client_auth(ClientAuth::Optional(roots))?;
        Ok(self)
    }

    /// Override the TLS handshake timeout (default: 10s).
    pub const fn with_handshake_timeout(mut self, dur: Duration) -> Self {
        self.handshake_timeout = dur;
        self
    }

    /// Build a [`TlsAcceptor`] ready to terminate inbound TLS sessions.
    ///
    /// Installs a rustls crypto provider on first call when none is set.
    pub(crate) fn into_acceptor(self) -> Result<(TlsAcceptor, Duration), TlsError> {
        ensure_crypto_provider();

        let timeout = self.handshake_timeout;
        let server_config: Arc<ServerConfig> = match self.inner {
            ServerTlsInner::Prebuilt(cfg) => cfg,
            ServerTlsInner::Pem {
                certs,
                key,
                client_auth,
            } => {
                let cfg = match client_auth {
                    ClientAuth::None => ServerConfig::builder()
                        .with_no_client_auth()
                        .with_single_cert(certs, key)
                        .map_err(|e| TlsError::ConfigBuild(e.to_string()))?,
                    ClientAuth::Required(roots) => {
                        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                            .build()
                            .map_err(|e| TlsError::ConfigBuild(e.to_string()))?;
                        ServerConfig::builder()
                            .with_client_cert_verifier(verifier)
                            .with_single_cert(certs, key)
                            .map_err(|e| TlsError::ConfigBuild(e.to_string()))?
                    }
                    ClientAuth::Optional(roots) => {
                        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                            .allow_unauthenticated()
                            .build()
                            .map_err(|e| TlsError::ConfigBuild(e.to_string()))?;
                        ServerConfig::builder()
                            .with_client_cert_verifier(verifier)
                            .with_single_cert(certs, key)
                            .map_err(|e| TlsError::ConfigBuild(e.to_string()))?
                    }
                };

                Arc::new(cfg)
            }
        };

        Ok((TlsAcceptor::from(server_config), timeout))
    }
}

impl ServerTlsInner {
    fn with_client_auth(self, ca: ClientAuth) -> Result<Self, TlsError> {
        match self {
            Self::Pem {
                certs,
                key,
                client_auth: _,
            } => Ok(Self::Pem {
                certs,
                key,
                client_auth: ca,
            }),
            Self::Prebuilt(_) => Err(TlsError::ConfigBuild(
                "client auth cannot be added on top of a pre-built rustls ServerConfig; \
                 configure it on the ServerConfig directly"
                    .into(),
            )),
        }
    }
}
