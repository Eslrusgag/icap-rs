//! Client-side timeout configuration.
//!
//! Group all client deadlines in one place so they can be carried through the
//! builder, stored inside the [`Client`](super::Client) as a single field, and
//! configured in bulk via [`ClientBuilder::with_timeouts`](super::builder::ClientBuilder::with_timeouts).
//!
//! All fields default to `None` (no timeout). The per-method setters on
//! [`ClientBuilder`](super::builder::ClientBuilder) write into the same struct.

use std::time::Duration;

/// Aggregated client deadlines.
///
/// - [`operation`](Self::operation) caps the whole `send()` call.
/// - [`connect`](Self::connect) caps TCP `connect()`.
/// - [`write`](Self::write) caps each individual write/flush/chunk write.
/// - [`continue_after_preview`](Self::continue_after_preview) caps the wait for
///   `100 Continue` (or an early final response) after a Preview body was sent.
///
/// TLS handshake timeouts are configured on
/// [`ClientTlsConfig`](crate::tls::ClientTlsConfig).
#[derive(Debug, Clone, Default)]
#[must_use]
pub struct ClientTimeouts {
    pub operation: Option<Duration>,
    pub connect: Option<Duration>,
    pub write: Option<Duration>,
    pub continue_after_preview: Option<Duration>,
}

impl ClientTimeouts {
    pub const fn new() -> Self {
        Self {
            operation: None,
            connect: None,
            write: None,
            continue_after_preview: None,
        }
    }

    pub const fn with_operation(mut self, dur: Duration) -> Self {
        self.operation = Some(dur);
        self
    }

    pub const fn with_connect(mut self, dur: Duration) -> Self {
        self.connect = Some(dur);
        self
    }

    pub const fn with_write(mut self, dur: Duration) -> Self {
        self.write = Some(dur);
        self
    }

    pub const fn with_continue_after_preview(mut self, dur: Duration) -> Self {
        self.continue_after_preview = Some(dur);
        self
    }
}
