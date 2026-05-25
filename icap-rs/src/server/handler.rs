//! Error type returned from user-defined route handlers.
//!
//! The server converts a [`HandlerError`] into an ICAP response — by default
//! `500 Internal Server Error` — and logs the underlying source at `WARN`
//! level. The connection stays open and is ready to serve the next request.
//!
//! `HandlerError` is intentionally not a `std::error::Error`: that lets it
//! accept *any* `std::error::Error + Send + Sync + 'static` through a blanket
//! `From` impl, so handlers can use `?` to propagate `crate::Error`,
//! `std::io::Error`, or any user-defined error without manual mapping.
//!
//! # Example
//!
//! ```
//! use icap_rs::{HandlerError, HandlerResult, IncomingRequest, Response, StatusCode};
//!
//! async fn handler(_req: IncomingRequest) -> HandlerResult<Response> {
//!     // Propagate a typed error from any layer — turns into 500 automatically.
//!     let resp = Response::no_content_with_istag("svc-1.0")?;
//!     Ok(resp)
//! }
//!
//! async fn handler_bad_request(_req: IncomingRequest) -> HandlerResult<Response> {
//!     Err(HandlerError::new(StatusCode::BAD_REQUEST).with_message("missing URL"))
//! }
//! ```

use std::fmt;

use crate::{Response, StatusCode};

/// Boxed `std::error::Error` carried as the source of a [`HandlerError`].
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Error returned from a route handler.
///
/// See the [module-level docs][self] for the full design rationale.
#[must_use]
pub struct HandlerError {
    status: StatusCode,
    message: Option<String>,
    source: Option<BoxError>,
}

impl HandlerError {
    /// Create a `HandlerError` with the given status and no source/message.
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            message: None,
            source: None,
        }
    }

    /// Create a 500 Internal Server Error with a human-readable message.
    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: Some(message.into()),
            source: None,
        }
    }

    /// Override the ICAP status emitted to the client.
    pub fn with_status(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }

    /// Attach a human-readable message used as the response reason phrase.
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    /// Attach an underlying error as the source (preserved in the error chain
    /// for logging).
    pub fn with_source(mut self, source: impl Into<BoxError>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// The status code the server will send.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The configured message, if any.
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// The underlying source error, if any.
    pub fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }

    /// Render the error as an ICAP `Response`.
    ///
    /// Uses [`Self::message`] as the reason phrase when set, otherwise the
    /// canonical reason for the status code, otherwise `"Handler error"`.
    pub(crate) fn into_response(self) -> Response {
        let reason = self
            .message
            .as_deref()
            .or_else(|| self.status.canonical_reason())
            .unwrap_or("Handler error");
        Response::new(self.status, reason)
    }
}

impl fmt::Debug for HandlerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandlerError")
            .field("status", &self.status.as_u16())
            .field("message", &self.message)
            .field("source", &self.source)
            .finish()
    }
}

impl fmt::Display for HandlerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "handler error ({})", self.status.as_u16())?;
        if let Some(msg) = &self.message {
            write!(f, ": {msg}")?;
        }
        if let Some(src) = &self.source {
            write!(f, ": {src}")?;
        }
        Ok(())
    }
}

// Anyhow-style blanket conversion. Works because `HandlerError` itself is
// intentionally NOT a `std::error::Error`, so no reflexive collision arises.
impl<E> From<E> for HandlerError
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn from(err: E) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: None,
            source: Some(Box::new(err)),
        }
    }
}

/// Convenient alias for results returned from route handlers.
pub type HandlerResult<T> = Result<T, HandlerError>;
