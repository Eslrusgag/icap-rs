//! Server-side timeout configuration.
//!
//! Group all per-connection deadlines in one struct so they can be configured
//! at once via [`ServerBuilder::with_timeouts`](super::builder::ServerBuilder::with_timeouts)
//! and stored inside the [`Server`](super::Server) as a single field.
//!
//! All fields default to `None` (no timeout). TLS handshake timeouts are
//! configured on [`ServerTlsConfig`](crate::tls::ServerTlsConfig).

use std::time::Duration;

/// Aggregated server deadlines applied per connection.
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
#[derive(Debug, Clone, Default)]
#[must_use]
pub struct ServerTimeouts {
    pub header_read: Option<Duration>,
    pub body_read: Option<Duration>,
    pub write: Option<Duration>,
    pub idle_keepalive: Option<Duration>,
}

impl ServerTimeouts {
    pub const fn new() -> Self {
        Self {
            header_read: None,
            body_read: None,
            write: None,
            idle_keepalive: None,
        }
    }

    pub const fn with_header_read(mut self, dur: Duration) -> Self {
        self.header_read = Some(dur);
        self
    }

    pub const fn with_body_read(mut self, dur: Duration) -> Self {
        self.body_read = Some(dur);
        self
    }

    pub const fn with_write(mut self, dur: Duration) -> Self {
        self.write = Some(dur);
        self
    }

    pub const fn with_idle_keepalive(mut self, dur: Duration) -> Self {
        self.idle_keepalive = Some(dur);
        self
    }
}
