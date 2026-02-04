//! TLS connector built on top of **rustls** (0.23) + **tokio-rustls**.
//!
//! - Loads platform root CAs via `rustls-native-certs` and optionally
//!   appends user-provided extra roots.
//! - SNI is required (`server_name` must be a valid DNS name).
//! - Exactly one crypto provider feature must be enabled:
//!   `tls-rustls-ring` **or** `tls-rustls-aws-lc`.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector as TokioTlsConnector, client::TlsStream};

use rustls::RootCertStore;
use rustls::client::ClientConfig;
use rustls::pki_types::{CertificateDer, ServerName};

use crate::error::IcapResult;
use crate::net::Conn;

/// Configuration for the rustls-based TLS connector.
#[derive(Debug, Clone)]
pub struct RustlsConfig {
    /// Kept for compatibility; rustls 0.23 has no public "disable verify" switch.
    #[allow(dead_code)]
    pub danger_disable_verify: bool,
    /// Extra root certificates in **DER** form to be appended to the platform store.
    pub extra_roots: Vec<CertificateDer<'static>>,
}

/// A `TlsConnector` implementation backed by rustls.
#[derive(Debug, Clone)]
pub struct RustlsConnector {
    cfg: RustlsConfig,
}

impl RustlsConnector {
    /// Create a new rustls connector with the given configuration.
    pub fn new(cfg: RustlsConfig) -> Self {
        Self { cfg }
    }
}

#[async_trait]
impl crate::client::tls::TlsConnector for RustlsConnector {
    /// Perform a TLS client handshake over the provided TCP stream using SNI.
    async fn connect(&self, tcp: TcpStream, server_name: &str) -> IcapResult<Conn> {
        let server_name =
            ServerName::try_from(server_name.to_string()).map_err(|_| "invalid SNI server name")?;

        // Build root store: platform roots + user-supplied extra roots.
        let mut roots = RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().expect("failed to load platform certs")
        {
            let _ = roots.add(cert);
        }
        for cert in &self.cfg.extra_roots {
            let _ = roots.add(cert.clone());
        }

        let provider: Arc<rustls::crypto::CryptoProvider> =
            rustls::crypto::ring::default_provider().into();

        // Build client config with safe defaults and our root store.
        let cfg: ClientConfig = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("protocol versions: {e}"))?
            .with_root_certificates(roots)
            .with_no_client_auth();

        // Drive the handshake using tokio-rustls.
        let connector = TokioTlsConnector::from(Arc::new(cfg));
        let tls: TlsStream<TcpStream> = connector.connect(server_name, tcp).await?;
        Ok(Conn::Rustls { inner: tls })
    }
}
