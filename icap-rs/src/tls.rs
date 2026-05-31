#![doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/tls.md"))]

pub mod client;
pub mod error;
pub mod pem;
pub mod server;

pub use client::ClientTlsConfig;
pub use error::TlsError;
pub use server::ServerTlsConfig;

/// Default TLS handshake timeout used when none is configured explicitly.
pub const DEFAULT_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Ensure a rustls [`CryptoProvider`] is installed as the process default.
///
/// Called lazily by [`ServerTlsConfig`]/[`ClientTlsConfig`] before building
/// rustls configs. If a provider has already been installed (by this crate
/// or by the host application) this returns without touching it.
///
/// Provider selection follows compile-time features: aws-lc-rs is
/// preferred when compiled in, otherwise `ring` is installed.
///
/// [`CryptoProvider`]: https://docs.rs/rustls/0.23/rustls/crypto/struct.CryptoProvider.html
pub(crate) fn ensure_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return;
    }

    #[cfg(feature = "tls-rustls-aws-lc-rs")]
    {
        // Ignore the error: another thread may have raced us to install.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    #[cfg(all(feature = "tls-rustls", not(feature = "tls-rustls-aws-lc-rs")))]
    {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}
