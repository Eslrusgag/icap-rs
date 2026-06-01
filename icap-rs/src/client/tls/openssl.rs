#![cfg(feature = "tls-openssl")]
//! TLS connector built on **OpenSSL** + `tokio-openssl`.
//!
//! - Supports optionally disabling certificate verification
//!   (for testing only) via `danger_disable_verify`.
//! - Uses SNI (`server_name`) during the handshake.

use super::TlsConnector;
use crate::error::IcapResult;
use crate::net::conn::Conn;
use tokio::net::TcpStream;

/// Configuration for the OpenSSL-based connector.
#[derive(Clone, Debug)]
pub struct OpensslConfig {
    /// Disable certificate verification.
    pub danger_disable_verify: bool,
}

/// A `TlsConnector` implementation backed by OpenSSL.
pub struct OpensslConnector {
    c: openssl::ssl::SslConnector,
}

impl OpensslConnector {
    /// Create a new OpenSSL connector using the provided configuration.
    pub fn new(cfg: OpensslConfig) -> Self {
        use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
        let mut b = SslConnector::builder(SslMethod::tls()).expect("openssl");
        if cfg.danger_disable_verify {
            b.set_verify(SslVerifyMode::NONE);
        }
        Self { c: b.build() }
    }
}

#[async_trait::async_trait]
impl TlsConnector for OpensslConnector {
    /// Perform a TLS client handshake over the provided TCP stream using SNI.
    async fn connect(&self, tcp: TcpStream, server_name: &str) -> IcapResult<Conn> {
        let ssl = self.c.configure()?.into_ssl(server_name)?;
        let mut s = tokio_openssl::SslStream::new(ssl, tcp)?;
        tokio_openssl::connect(&mut s).await?;
        Ok(Conn::Openssl { inner: s })
    }
}
