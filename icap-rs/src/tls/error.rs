//! Structured TLS errors.
//!
//! These errors surface protocol-level TLS problems through a dedicated
//! [`TlsError`] type instead of being collapsed into generic I/O errors.
//! That way callers can distinguish certificate verification failures,
//! handshake timeouts, PEM loading problems and SNI issues from ordinary
//! network errors that happen on an already-established connection.

use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;

/// Errors specific to the TLS layer used by ICAPS connections.
///
/// Variants are non-exhaustive in spirit: new ones may be added without
/// considering it a breaking change. Match with a `_` arm if you cannot
/// otherwise handle the variant.
#[derive(Debug, Error)]
pub enum TlsError {
    /// `server_name` could not be parsed as a valid DNS name for SNI.
    #[error("invalid TLS server name for SNI: {0}")]
    InvalidServerName(String),

    /// The TLS handshake failed.
    ///
    /// The wrapped `io::Error` typically has a [`rustls::Error`] as its
    /// `source()` when the failure originated inside rustls itself.
    ///
    /// [`rustls::Error`]: https://docs.rs/rustls/0.23/rustls/enum.Error.html
    #[error("TLS handshake failed: {0}")]
    Handshake(#[source] std::io::Error),

    /// The TLS handshake did not complete within the configured timeout.
    #[error("TLS handshake timed out after {0:?}")]
    HandshakeTimeout(Duration),

    /// Failure during certificate verification (chain, hostname, expiry…).
    #[error("certificate verification failed: {0}")]
    CertVerification(String),

    /// I/O error while reading a PEM file from disk.
    #[error("PEM I/O error for {path}: {source}")]
    PemIo {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The PEM file was readable but its contents could not be parsed.
    #[error("PEM parse error for {path}: {message}")]
    PemParse { path: PathBuf, message: String },

    /// The key file contained no recognizable private key
    /// (PKCS#8, PKCS#1/RSA, or SEC1/EC).
    #[error("no private key found in {0}")]
    NoPrivateKey(PathBuf),

    /// `rustls` rejected the assembled [`ServerConfig`]/[`ClientConfig`].
    ///
    /// [`ServerConfig`]: https://docs.rs/rustls/0.23/rustls/struct.ServerConfig.html
    /// [`ClientConfig`]: https://docs.rs/rustls/0.23/rustls/struct.ClientConfig.html
    #[error("rustls config build error: {0}")]
    ConfigBuild(String),

    /// No `rustls` [`CryptoProvider`] is installed and the crate was
    /// compiled without any provider feature
    /// (`tls-rustls` for `ring`, `tls-rustls-aws-lc-rs` for aws-lc-rs).
    ///
    /// [`CryptoProvider`]: https://docs.rs/rustls/0.23/rustls/crypto/struct.CryptoProvider.html
    #[error("no rustls crypto provider available")]
    CryptoProviderMissing,
}

impl TlsError {
    /// Helper for constructing a [`TlsError::PemIo`] from a path and an I/O error.
    pub fn pem_io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::PemIo {
            path: path.into(),
            source,
        }
    }

    /// Helper for constructing a [`TlsError::PemParse`] from a path and a message.
    pub fn pem_parse(path: impl Into<PathBuf>, message: impl Into<String>) -> Self {
        Self::PemParse {
            path: path.into(),
            message: message.into(),
        }
    }
}
