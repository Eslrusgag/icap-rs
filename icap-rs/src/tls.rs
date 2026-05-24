//! TLS support for ICAP (ICAPS).
//!
//! This module hosts the high-level configuration types used by both
//! the ICAP server and client when running over TLS:
//!
//! - [`ServerTlsConfig`] — server-side configuration (cert chain, private
//!   key, optional client-cert verification, handshake timeout).
//! - [`ClientTlsConfig`] — client-side configuration (trust roots, optional
//!   mutual auth, SNI, handshake timeout, dangerous "no-verify" toggle).
//! - [`TlsError`] — structured TLS errors, surfaced through
//!   [`crate::Error::Tls`] on failures.
//!
//! ## Crypto provider
//!
//! rustls 0.23 requires an installed [`CryptoProvider`]. The crate
//! installs one lazily the first time TLS is used:
//!
//! - With the default `tls-rustls` feature, `ring` is installed.
//! - With `tls-rustls-aws-lc-rs` enabled, aws-lc-rs is installed instead
//!   (both providers may be compiled in; aws-lc-rs is preferred when
//!   available).
//!
//! Callers that prefer to drive provider selection themselves can call
//! `rustls::crypto::*::default_provider().install_default()` before any
//! TLS object is constructed.
//!
//! [`CryptoProvider`]: https://docs.rs/rustls/0.23/rustls/crypto/struct.CryptoProvider.html

pub mod client;
pub mod error;
pub mod pem;
pub mod server;

pub use client::ClientTlsConfig;
pub use error::TlsError;
pub use server::ServerTlsConfig;

/// Default port for direct ICAPS connections (`icaps://` without a port).
///
/// RFC 3507 only registers port 1344 for plain ICAP and does not define
/// ICAPS; 11344 is the de-facto convention used by deployments and tools.
pub const ICAPS_DEFAULT_PORT: u16 = 11344;

/// Default TLS handshake timeout used when none is configured explicitly.
pub const DEFAULT_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Ensure a rustls [`CryptoProvider`] is installed as the process default.
///
/// Called lazily by [`ServerTlsConfig`]/[`ClientTlsConfig`] before building
/// rustls configs. If a provider has already been installed (by this crate
/// or by the host application) this returns `Ok(())` without touching it.
///
/// Provider selection follows compile-time features: aws-lc-rs is
/// preferred when compiled in, otherwise `ring` is installed.
///
/// [`CryptoProvider`]: https://docs.rs/rustls/0.23/rustls/crypto/struct.CryptoProvider.html
pub(crate) fn ensure_crypto_provider() -> Result<(), TlsError> {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return Ok(());
    }

    #[cfg(feature = "tls-rustls-aws-lc-rs")]
    {
        // Ignore the error: another thread may have raced us to install.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        return Ok(());
    }

    #[cfg(all(feature = "tls-rustls", not(feature = "tls-rustls-aws-lc-rs")))]
    {
        let _ = rustls::crypto::ring::default_provider().install_default();
        return Ok(());
    }

    #[allow(unreachable_code)]
    Err(TlsError::CryptoProviderMissing)
}
