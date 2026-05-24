//! Connection wrapper used by the ICAP client.
//!
//! Exposes [`Conn`], a tagged transport over either a plain TCP socket or a
//! rustls-backed TLS stream (when the `tls-rustls` feature is compiled in).
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

#[cfg(feature = "tls-rustls")]
mod conn_def {
    use super::{AsyncRead, AsyncWrite, TcpStream, pin_project};

    pin_project! {
        /// Transport connection when the rustls TLS backend is compiled in.
        ///
        /// Variants:
        /// - [`Conn::Plain`] — raw `TcpStream`
        /// - [`Conn::Rustls`] — TLS via `tokio-rustls` + rustls
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

#[cfg(not(feature = "tls-rustls"))]
mod conn_def {
    use super::{AsyncRead, AsyncWrite, TcpStream, pin_project};

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

impl Conn {
    /// Returns mutable access to the underlying plain TCP stream when transport is non-TLS.
    #[allow(clippy::unnecessary_wraps)]
    pub const fn plain_mut(&mut self) -> Option<&mut TcpStream> {
        match self {
            Self::Plain { inner } => Some(inner),
            #[cfg(feature = "tls-rustls")]
            Self::Rustls { .. } => None,
        }
    }
}
