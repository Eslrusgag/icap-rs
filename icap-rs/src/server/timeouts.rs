//! Server-side timeout configuration.
//!
//! Group all per-connection deadlines in one struct so they can be configured
//! at once via [`ServerBuilder::with_timeouts`](super::builder::ServerBuilder::with_timeouts)
//! and stored inside the [`Server`](super::Server) as a single field.
//!
//! All fields default to `None` (no timeout). TLS handshake timeouts are
//! configured on [`ServerTlsConfig`](crate::tls::ServerTlsConfig).

use std::time::Duration;

/// Aggregated server deadlines applied per connection and for graceful shutdown.
///
/// - [`header_read`](Self::header_read): max time to receive a full ICAP header
///   block (`CRLFCRLF`) once the request has started arriving. Mitigates
///   slowloris-style header attacks.
/// - [`body_read`](Self::body_read): max time budget for reading the encapsulated
///   body of a single request (chunked decoding included).
/// - [`write`](Self::write): max time to write any single response chunk to the
///   client.
/// - [`idle_keepalive`](Self::idle_keepalive): max time to wait for the **first**
///   byte of the next request on a kept-alive connection (after the previous
///   response was flushed). Used only for the leading read; once any bytes
///   arrive, [`header_read`](Self::header_read) governs the rest of the header
///   block.
/// - [`shutdown_drain`](Self::shutdown_drain): max time to wait for in-flight
///   requests to finish after a shutdown signal. If the deadline expires, the
///   remaining connections are cancelled. When `None` the server waits
///   indefinitely.
#[derive(Debug, Clone, Default)]
#[must_use]
pub struct ServerTimeouts {
    pub header_read: Option<Duration>,
    pub body_read: Option<Duration>,
    pub write: Option<Duration>,
    pub idle_keepalive: Option<Duration>,
    pub shutdown_drain: Option<Duration>,
}

impl ServerTimeouts {
    /// Construct a `ServerTimeouts` with every deadline disabled (`None`).
    pub const fn new() -> Self {
        Self {
            header_read: None,
            body_read: None,
            write: None,
            idle_keepalive: None,
            shutdown_drain: None,
        }
    }

    /// Set the [`header_read`](Self::header_read) deadline.
    ///
    /// Limits how long the server waits to receive a full ICAP header block
    /// (`CRLFCRLF`) once the request has started arriving.
    pub const fn with_header_read(mut self, dur: Duration) -> Self {
        self.header_read = Some(dur);
        self
    }

    /// Set the [`body_read`](Self::body_read) deadline.
    ///
    /// Bounds the time budget for reading the encapsulated body of a single
    /// request, including chunked decoding.
    pub const fn with_body_read(mut self, dur: Duration) -> Self {
        self.body_read = Some(dur);
        self
    }

    /// Set the [`write`](Self::write) deadline.
    ///
    /// Bounds the time to write any single response chunk to the client.
    pub const fn with_write(mut self, dur: Duration) -> Self {
        self.write = Some(dur);
        self
    }

    /// Set the [`idle_keepalive`](Self::idle_keepalive) deadline.
    ///
    /// Bounds how long the server waits for the **first** byte of the next
    /// request on a kept-alive connection after the previous response was
    /// flushed. Once any byte arrives, [`with_header_read`](Self::with_header_read)
    /// governs the rest of the header block.
    pub const fn with_idle_keepalive(mut self, dur: Duration) -> Self {
        self.idle_keepalive = Some(dur);
        self
    }

    /// Set the [`shutdown_drain`](Self::shutdown_drain) deadline.
    ///
    /// Bounds how long the server waits for active connections to finish after
    /// a shutdown signal. Connections still in flight when the deadline expires
    /// are cancelled. When not set the drain waits indefinitely.
    pub const fn with_shutdown_drain(mut self, dur: Duration) -> Self {
        self.shutdown_drain = Some(dur);
        self
    }
}
