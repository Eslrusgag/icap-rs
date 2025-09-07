//! Connection wrapper used by the ICAP client.
//!
//! This module exposes a single enum [`Conn`] that abstracts over the
//! underlying transport:
//!
//! - plain TCP (`TcpStream`)
//! - TLS over **rustls** (`tokio_rustls::client::TlsStream<TcpStream>`) — when the
//!   `tls-rustls` feature is enabled
//! - TLS over **OpenSSL** (`tokio_openssl::SslStream<TcpStream>`) — when the
//!   `tls-openssl` feature is enabled
//!
//! The exact shape of the enum depends on enabled Cargo features. To keep the
//! same public name regardless of features, we define the enum inside a
//! `conn_def` module selected by `#[cfg(...)]` and then `pub use` it below.
//!
//! The enum implements `AsyncRead`/`AsyncWrite` by delegating to the inner
//! stream. We use `pin_project_lite` to safely project pinned enum variants.

use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

#[cfg(all(feature = "tls-rustls", feature = "tls-openssl"))]
mod conn_def {
    use super::*;

    pin_project! {
        /// Transport connection when both TLS backends are compiled in.
        ///
        /// Variants:
        /// - [`Conn::Plain`] — raw `TcpStream`
        /// - [`Conn::Rustls`] — TLS via `tokio-rustls` + rustls
        /// - [`Conn::Openssl`] — TLS via `tokio-openssl` + OpenSSL
        #[project = ConnProj]
        #[derive(Debug)]
        pub enum Conn {
            /// Plain TCP connection (no TLS).
            Plain  { #[pin] inner: TcpStream },
            /// TLS connection using rustls.
            Rustls { #[pin] inner: tokio_rustls::client::TlsStream<TcpStream> },
            /// TLS connection using OpenSSL.
            Openssl{ #[pin] inner: tokio_openssl::SslStream<TcpStream> },
        }
    }

    // Delegate AsyncRead to the active variant.
    impl AsyncRead for Conn {
        fn poll_read(
            self: core::pin::Pin<&mut Self>,
            cx: &mut core::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> core::task::Poll<std::io::Result<()>> {
            match self.project() {
                ConnProj::Plain { inner } => inner.poll_read(cx, buf),
                ConnProj::Rustls { inner } => inner.poll_read(cx, buf),
                ConnProj::Openssl { inner } => inner.poll_read(cx, buf),
            }
        }
    }

    // Delegate AsyncWrite to the active variant.
    impl AsyncWrite for Conn {
        fn poll_write(
            self: core::pin::Pin<&mut Self>,
            cx: &mut core::task::Context<'_>,
            buf: &[u8],
        ) -> core::task::Poll<std::io::Result<usize>> {
            match self.project() {
                ConnProj::Plain { inner } => inner.poll_write(cx, buf),
                ConnProj::Rustls { inner } => inner.poll_write(cx, buf),
                ConnProj::Openssl { inner } => inner.poll_write(cx, buf),
            }
        }
        fn poll_flush(
            self: core::pin::Pin<&mut Self>,
            cx: &mut core::task::Context<'_>,
        ) -> core::task::Poll<std::io::Result<()>> {
            match self.project() {
                ConnProj::Plain { inner } => inner.poll_flush(cx),
                ConnProj::Rustls { inner } => inner.poll_flush(cx),
                ConnProj::Openssl { inner } => inner.poll_flush(cx),
            }
        }
        fn poll_shutdown(
            self: core::pin::Pin<&mut Self>,
            cx: &mut core::task::Context<'_>,
        ) -> core::task::Poll<std::io::Result<()>> {
            match self.project() {
                ConnProj::Plain { inner } => inner.poll_shutdown(cx),
                ConnProj::Rustls { inner } => inner.poll_shutdown(cx),
                ConnProj::Openssl { inner } => inner.poll_shutdown(cx),
            }
        }
    }
}

#[cfg(all(feature = "tls-rustls", not(feature = "tls-openssl")))]
mod conn_def {
    use super::*;

    pin_project! {
        /// Transport connection when only the rustls TLS backend is compiled in.
        #[project = ConnProj]
        #[derive(Debug)]
        pub enum Conn {
            /// Plain TCP connection (no TLS).
            Plain  { #[pin] inner: TcpStream },
            /// TLS connection using rustls.
            Rustls { #[pin] inner: tokio_rustls::client::TlsStream<TcpStream> },
        }
    }

    impl AsyncRead for Conn {
        fn poll_read(
            self: core::pin::Pin<&mut Self>,
            cx: &mut core::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> core::task::Poll<std::io::Result<()>> {
            match self.project() {
                ConnProj::Plain { inner } => inner.poll_read(cx, buf),
                ConnProj::Rustls { inner } => inner.poll_read(cx, buf),
            }
        }
    }

    impl AsyncWrite for Conn {
        fn poll_write(
            self: core::pin::Pin<&mut Self>,
            cx: &mut core::task::Context<'_>,
            buf: &[u8],
        ) -> core::task::Poll<std::io::Result<usize>> {
            match self.project() {
                ConnProj::Plain { inner } => inner.poll_write(cx, buf),
                ConnProj::Rustls { inner } => inner.poll_write(cx, buf),
            }
        }
        fn poll_flush(
            self: core::pin::Pin<&mut Self>,
            cx: &mut core::task::Context<'_>,
        ) -> core::task::Poll<std::io::Result<()>> {
            match self.project() {
                ConnProj::Plain { inner } => inner.poll_flush(cx),
                ConnProj::Rustls { inner } => inner.poll_flush(cx),
            }
        }
        fn poll_shutdown(
            self: core::pin::Pin<&mut Self>,
            cx: &mut core::task::Context<'_>,
        ) -> core::task::Poll<std::io::Result<()>> {
            match self.project() {
                ConnProj::Plain { inner } => inner.poll_shutdown(cx),
                ConnProj::Rustls { inner } => inner.poll_shutdown(cx),
            }
        }
    }
}

#[cfg(all(not(feature = "tls-rustls"), feature = "tls-openssl"))]
mod conn_def {
    use super::*;

    pin_project! {
        /// Transport connection when only the OpenSSL TLS backend is compiled in.
        #[project = ConnProj]
        #[derive(Debug)]
        pub enum Conn {
            /// Plain TCP connection (no TLS).
            Plain   { #[pin] inner: TcpStream },
            /// TLS connection using OpenSSL.
            Openssl { #[pin] inner: tokio_openssl::SslStream<TcpStream> },
        }
    }

    impl AsyncRead for Conn {
        fn poll_read(
            self: core::pin::Pin<&mut Self>,
            cx: &mut core::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> core::task::Poll<std::io::Result<()>> {
            match self.project() {
                ConnProj::Plain { inner } => inner.poll_read(cx, buf),
                ConnProj::Openssl { inner } => inner.poll_read(cx, buf),
            }
        }
    }

    impl AsyncWrite for Conn {
        fn poll_write(
            self: core::pin::Pin<&mut Self>,
            cx: &mut core::task::Context<'_>,
            buf: &[u8],
        ) -> core::task::Poll<std::io::Result<usize>> {
            match self.project() {
                ConnProj::Plain { inner } => inner.poll_write(cx, buf),
                ConnProj::Openssl { inner } => inner.poll_write(cx, buf),
            }
        }
        fn poll_flush(
            self: core::pin::Pin<&mut Self>,
            cx: &mut core::task::Context<'_>,
        ) -> core::task::Poll<std::io::Result<()>> {
            match self.project() {
                ConnProj::Plain { inner } => inner.poll_flush(cx),
                ConnProj::Openssl { inner } => inner.poll_flush(cx),
            }
        }
        fn poll_shutdown(
            self: core::pin::Pin<&mut Self>,
            cx: &mut core::task::Context<'_>,
        ) -> core::task::Poll<std::io::Result<()>> {
            match self.project() {
                ConnProj::Plain { inner } => inner.poll_shutdown(cx),
                ConnProj::Openssl { inner } => inner.poll_shutdown(cx),
            }
        }
    }
}

#[cfg(all(not(feature = "tls-rustls"), not(feature = "tls-openssl")))]
mod conn_def {
    use super::*;

    pin_project! {
        /// Transport connection when no TLS backends are compiled in.
        #[project = ConnProj]
        #[derive(Debug)]
        pub enum Conn {
            /// Plain TCP connection (no TLS).
            Plain { #[pin] inner: TcpStream },
        }
    }

    impl AsyncRead for Conn {
        fn poll_read(
            self: core::pin::Pin<&mut Self>,
            cx: &mut core::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> core::task::Poll<std::io::Result<()>> {
            match self.project() {
                ConnProj::Plain { inner } => inner.poll_read(cx, buf),
            }
        }
    }

    impl AsyncWrite for Conn {
        fn poll_write(
            self: core::pin::Pin<&mut Self>,
            cx: &mut core::task::Context<'_>,
            buf: &[u8],
        ) -> core::task::Poll<std::io::Result<usize>> {
            match self.project() {
                ConnProj::Plain { inner } => inner.poll_write(cx, buf),
            }
        }
        fn poll_flush(
            self: core::pin::Pin<&mut Self>,
            cx: &mut core::task::Context<'_>,
        ) -> core::task::Poll<std::io::Result<()>> {
            match self.project() {
                ConnProj::Plain { inner } => inner.poll_flush(cx),
            }
        }
        fn poll_shutdown(
            self: core::pin::Pin<&mut Self>,
            cx: &mut core::task::Context<'_>,
        ) -> core::task::Poll<std::io::Result<()>> {
            match self.project() {
                ConnProj::Plain { inner } => inner.poll_shutdown(cx),
            }
        }
    }
}

/// Re-export the feature-shaped `Conn` so callers can use a stable path.
pub use conn_def::Conn;
