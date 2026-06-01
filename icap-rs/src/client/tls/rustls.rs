//! TLS connector built on top of **rustls** (0.23) + **tokio-rustls**.
//!
//! - Loads platform root CAs via `rustls-native-certs` and optionally
//!   appends user-provided extra roots.
//! - SNI is required (`server_name` must be a valid DNS name).
//! - Uses rustls default crypto provider selected by crate features.

use std::sync::Arc;
use std::sync::OnceLock;

use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector as TokioTlsConnector, client::TlsStream};

use rustls::RootCertStore;
use rustls::client::ClientConfig;
use rustls::pki_types::{CertificateDer, ServerName};

use crate::error::{Error, IcapResult};
use crate::net::Conn;

/// Configuration for the rustls-based TLS connector.
#[derive(Debug, Clone)]
pub struct RustlsConfig {
    /// Compatibility field; rustls 0.23 has no public "disable verify" switch.
    #[allow(dead_code)]
    pub danger_disable_verify: bool,
    /// Extra root certificates in **DER** form to be appended to the platform store.
    pub extra_roots: Vec<CertificateDer<'static>>,
}

/// A `TlsConnector` implementation backed by rustls.
#[derive(Debug, Clone)]
pub struct RustlsConnector {
    cfg: RustlsConfig,
    cached_client_cfg: Arc<OnceLock<Result<Arc<ClientConfig>, String>>>,
}

impl RustlsConnector {
    /// Create a new rustls connector with the given configuration.
    pub fn new(cfg: RustlsConfig) -> Self {
        Self {
            cfg,
            cached_client_cfg: Arc::new(OnceLock::new()),
        }
    }
}

#[async_trait]
impl crate::client::tls::TlsConnector for RustlsConnector {
    /// Perform a TLS client handshake over the provided TCP stream using SNI.
    async fn connect(&self, tcp: TcpStream, server_name: &str) -> IcapResult<Conn> {
        let server_name = ServerName::try_from(server_name.to_string())
            .map_err(|_| Error::InvalidUri("invalid SNI server name".into()))?;

        let cfg = self
            .cached_client_cfg
            .get_or_init(|| build_client_config(&self.cfg).map(Arc::new))
            .as_ref()
            .map_err(|e| e.clone())?;

        // Drive the handshake using tokio-rustls.
        let connector = TokioTlsConnector::from(Arc::clone(cfg));
        let tls: TlsStream<TcpStream> = connector.connect(server_name, tcp).await?;
        Ok(Conn::Rustls { inner: tls })
    }
}

fn build_client_config(cfg: &RustlsConfig) -> Result<ClientConfig, String> {
    // Build root store: platform roots + user-supplied extra roots.
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    if !native.errors.is_empty() {
        return Err(format!(
            "failed to load platform certs: {} error(s)",
            native.errors.len()
        ));
    }
    for cert in native.certs {
        roots
            .add(cert)
            .map_err(|e| format!("failed to add platform cert: {e}"))?;
    }
    for cert in &cfg.extra_roots {
        roots
            .add(cert.clone())
            .map_err(|e| format!("failed to add extra root cert: {e}"))?;
    }

    Ok(ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}
