//! TLS abstraction layer for the ICAP client.
//!
//! This module provides a small facade over concrete TLS backends
//! (rustls or OpenSSL) and a common `TlsConnector` trait used by
//! the high-level client. It also exposes `AnyTlsConnector`, a
//! tiny enum-based dispatcher that can represent plain TCP or a
//! specific TLS backend.

#[cfg(feature = "tls-rustls")]
pub mod rustls;

#[cfg(feature = "tls-openssl")]
pub mod openssl;

use crate::error::IcapResult;
use crate::net::Conn;
use async_trait::async_trait;
use tokio::net::TcpStream;

/// Available TLS backends. Compile-time features determine which
/// variants are actually usable.
#[derive(Debug, Clone, Copy)]
pub enum TlsBackend {
    Rustls,
    Openssl,
}

/// Minimal async connector interface shared by all TLS backends.
#[async_trait]
pub trait TlsConnector: Send + Sync + std::fmt::Debug {
    /// Establish a (possibly TLS-wrapped) connection on top of the given TCP stream.
    /// `server_name` is used for SNI and certificate verification.
    async fn connect(&self, tcp: TcpStream, server_name: &str) -> IcapResult<Conn>;
}

/// Type-erased connector that can be plain TCP or one of the TLS backends.
#[derive(Debug, Clone)]
pub enum AnyTlsConnector {
    /// No TLS – pass the TCP stream through unchanged.
    Plain,
    /// rustls-backed connector (enabled via `tls-rustls` feature).
    #[cfg(feature = "tls-rustls")]
    Rustls(rustls::RustlsConnector),
    /// OpenSSL-backed connector (enabled via `tls-openssl` feature).
    #[cfg(feature = "tls-openssl")]
    Openssl(openssl::OpensslConnector),
}

impl AnyTlsConnector {
    /// Construct a non-TLS connector.
    pub fn plain() -> Self {
        AnyTlsConnector::Plain
    }

    /// Construct a rustls connector (available when `tls-rustls` is enabled).
    #[cfg(feature = "tls-rustls")]
    pub fn rustls(cfg: rustls::RustlsConfig) -> Self {
        AnyTlsConnector::Rustls(rustls::RustlsConnector::new(cfg))
    }

    /// Construct an OpenSSL connector (available when `tls-openssl` is enabled).
    #[cfg(feature = "tls-openssl")]
    pub fn openssl(cfg: openssl::OpensslConfig) -> Self {
        AnyTlsConnector::Openssl(openssl::OpensslConnector::new(cfg))
    }
}

#[async_trait]
impl TlsConnector for AnyTlsConnector {
    async fn connect(&self, tcp: TcpStream, server_name: &str) -> IcapResult<Conn> {
        match self {
            AnyTlsConnector::Plain => Ok(Conn::Plain { inner: tcp }),
            #[cfg(feature = "tls-rustls")]
            AnyTlsConnector::Rustls(c) => c.connect(tcp, server_name).await,
            #[cfg(feature = "tls-openssl")]
            AnyTlsConnector::Openssl(c) => c.connect(tcp, server_name).await,
        }
    }
}
