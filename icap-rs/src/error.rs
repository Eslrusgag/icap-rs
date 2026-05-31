//! Error types for the ICAP crate.
//!
//! The error surface is grouped by concern rather than dumped into a single
//! flat enum. This keeps matches concise and makes it possible to reason about
//! categories of failures (e.g. "is this a timeout?", "is this retryable?")
//! without enumerating every variant.
//!
//! # Layout
//!
//! - [`enum@Error`] is the top-level type returned from public APIs.
//! - [`TimeoutError`] + [`TimeoutKind`] describe deadline violations.
//! - [`ProtocolError`] + [`ProtocolField`] describe wire-protocol failures.
//! - [`ConfigError`] describes builder/setup mistakes.
//! - [`crate::tls::TlsError`] describes TLS-specific errors (when the
//!   `tls-rustls` feature is enabled).
//!
//! See [`Error::is_timeout`], [`Error::is_io`], [`Error::is_retryable`] for
//! convenient classifiers.
//!
//! [`HandlerError`](crate::HandlerError) is a *separate* type returned from
//! user handlers — it is not part of this enum.

use http::header::{InvalidHeaderName, InvalidHeaderValue};
use http::{Error as HttpError, header::ToStrError};
use std::error::Error as StdError;
use std::fmt;
use std::io;
use std::str::Utf8Error;
use std::string::FromUtf8Error;
use std::time::Duration;
use thiserror::Error;

/// Boxed `std::error::Error` used by [`Error::External`].
pub type BoxError = Box<dyn StdError + Send + Sync + 'static>;

/// Top-level error type.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Transport-level I/O error (TCP read/write/connect).
    #[error("I/O error: {0}")]
    Io(#[source] io::Error),

    /// Operation exceeded a configured deadline.
    #[error(transparent)]
    Timeout(#[from] TimeoutError),

    /// Wire-protocol failure (parsing, headers, encapsulation, etc.).
    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    /// Builder / configuration failure (invalid service options, unknown
    /// alias, missing handlers, …).
    #[error(transparent)]
    Config(#[from] ConfigError),

    /// TLS layer error (handshake, certificate verification, PEM loading…).
    #[cfg(feature = "tls-rustls")]
    #[error(transparent)]
    Tls(#[from] crate::tls::TlsError),

    /// Error returned by the `http` crate builders.
    #[error("HTTP builder error: {0}")]
    Http(#[from] HttpError),

    /// Error from outside this crate, preserved via [`ToIcapResult`] or
    /// [`Error::external`]. The original error is available through `source()`.
    #[error("external error: {0}")]
    External(#[source] BoxError),
}

impl Error {
    /// True if the error originates from an I/O failure on the transport.
    pub const fn is_io(&self) -> bool {
        matches!(self, Self::Io(_))
    }

    /// True if the error originates from a deadline (any [`TimeoutKind`]).
    pub const fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout(_))
    }

    /// True if the error came from the wire protocol layer.
    pub const fn is_protocol(&self) -> bool {
        matches!(self, Self::Protocol(_))
    }

    /// True if the peer sent an embedded body larger than a configured limit.
    pub const fn is_body_too_large(&self) -> bool {
        matches!(self, Self::Protocol(ProtocolError::BodyTooLarge { .. }))
    }

    /// True if the error came from builder / configuration validation.
    pub const fn is_config(&self) -> bool {
        matches!(self, Self::Config(_))
    }

    /// True for the "peer closed before headers" case — common on
    /// kept-alive connections that the server has idle-closed.
    pub const fn is_early_close(&self) -> bool {
        matches!(self, Self::Protocol(ProtocolError::EarlyClose))
    }

    /// True if a fresh attempt is likely to succeed.
    ///
    /// Conservative: connection-establishment timeouts, idle keep-alive
    /// closure, and `EarlyClose` are considered retryable. Application-level
    /// protocol errors are *not* retryable — the peer will reject the same
    /// bytes again.
    pub const fn is_retryable(&self) -> bool {
        if self.is_early_close() {
            return true;
        }
        if let Self::Timeout(t) = self {
            return matches!(t.kind, TimeoutKind::ClientConnect | TimeoutKind::ServerIdle);
        }
        false
    }

    /// Build a protocol parse error.
    pub fn parse(message: impl Into<String>) -> Self {
        Self::Protocol(ProtocolError::Parse(message.into()))
    }

    /// Build an embedded-HTTP parse error.
    pub fn http_parse(message: impl Into<String>) -> Self {
        Self::Protocol(ProtocolError::HttpParse(message.into()))
    }

    /// Build a generic header error.
    pub fn header(message: impl Into<String>) -> Self {
        Self::Protocol(ProtocolError::Header(message.into()))
    }

    /// Build a body error.
    pub fn body(message: impl Into<String>) -> Self {
        Self::Protocol(ProtocolError::Body(message.into()))
    }

    /// Build an oversized-body protocol error.
    pub const fn body_too_large(size: usize, max: usize) -> Self {
        Self::Protocol(ProtocolError::BodyTooLarge { size, max })
    }

    /// Build a serialization error.
    pub fn serialization(message: impl Into<String>) -> Self {
        Self::Protocol(ProtocolError::Serialization(message.into()))
    }

    /// Build a service / configuration error.
    pub fn service(message: impl Into<String>) -> Self {
        Self::Config(ConfigError::Other(message.into()))
    }

    /// Build a "missing required header" protocol error.
    pub const fn missing_header(name: &'static str) -> Self {
        Self::Protocol(ProtocolError::MissingHeader(name))
    }

    /// Build an "invalid `ISTag`" protocol error.
    pub fn invalid_istag(value: impl Into<String>) -> Self {
        Self::Protocol(ProtocolError::InvalidISTag(value.into()))
    }

    /// Build an "invalid status code" protocol error.
    pub fn invalid_status_code(value: impl Into<String>) -> Self {
        Self::Protocol(ProtocolError::invalid(ProtocolField::StatusCode, value))
    }

    /// Build an "invalid method" protocol error.
    pub fn invalid_method(value: impl Into<String>) -> Self {
        Self::Protocol(ProtocolError::invalid(ProtocolField::Method, value))
    }

    /// Build an "invalid URI" protocol error.
    pub fn invalid_uri(value: impl Into<String>) -> Self {
        Self::Protocol(ProtocolError::invalid(ProtocolField::Uri, value))
    }

    /// Build an "invalid protocol version" protocol error.
    pub fn invalid_version(value: impl Into<String>) -> Self {
        Self::Protocol(ProtocolError::invalid(ProtocolField::Version, value))
    }

    /// Build an `External` error from any `std::error::Error`.
    pub fn external<E>(err: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self::External(Box::new(err))
    }

    /// Build an `External` error from an ad-hoc message string.
    pub fn unexpected(message: impl Into<String>) -> Self {
        Self::External(Box::<MessageError>::new(MessageError(message.into())))
    }

    /// Build a `Timeout` from a kind + duration.
    pub const fn timeout(kind: TimeoutKind, duration: Duration) -> Self {
        Self::Timeout(TimeoutError { kind, duration })
    }

    pub const fn client_total_timeout(d: Duration) -> Self {
        Self::timeout(TimeoutKind::ClientTotal, d)
    }
    pub const fn client_connect_timeout(d: Duration) -> Self {
        Self::timeout(TimeoutKind::ClientConnect, d)
    }
    pub const fn client_write_timeout(d: Duration) -> Self {
        Self::timeout(TimeoutKind::ClientWrite, d)
    }
    pub const fn client_continue_timeout(d: Duration) -> Self {
        Self::timeout(TimeoutKind::ClientContinue, d)
    }
    pub const fn server_header_read_timeout(d: Duration) -> Self {
        Self::timeout(TimeoutKind::ServerHeaderRead, d)
    }
    pub const fn server_body_read_timeout(d: Duration) -> Self {
        Self::timeout(TimeoutKind::ServerBodyRead, d)
    }
    pub const fn server_write_timeout(d: Duration) -> Self {
        Self::timeout(TimeoutKind::ServerWrite, d)
    }
    pub const fn server_idle_timeout(d: Duration) -> Self {
        Self::timeout(TimeoutKind::ServerIdle, d)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<Utf8Error> for Error {
    fn from(e: Utf8Error) -> Self {
        Self::Protocol(ProtocolError::Utf8(e))
    }
}

impl From<FromUtf8Error> for Error {
    fn from(e: FromUtf8Error) -> Self {
        Self::Protocol(ProtocolError::FromUtf8(e))
    }
}

impl From<InvalidHeaderName> for Error {
    fn from(e: InvalidHeaderName) -> Self {
        Self::Protocol(ProtocolError::HeaderName(e))
    }
}

impl From<InvalidHeaderValue> for Error {
    fn from(e: InvalidHeaderValue) -> Self {
        Self::Protocol(ProtocolError::HeaderValue(e))
    }
}

impl From<ToStrError> for Error {
    fn from(e: ToStrError) -> Self {
        Self::Protocol(ProtocolError::HeaderToStr(e))
    }
}

/// A specific deadline violation. See [`TimeoutKind`] for the list of
/// recognised deadlines.
#[derive(Debug, Error)]
#[error("{kind} timed out after {duration:?}")]
pub struct TimeoutError {
    pub kind: TimeoutKind,
    pub duration: Duration,
}

/// Identifies which deadline was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimeoutKind {
    /// Whole client `send` operation.
    ClientTotal,
    /// Client TCP connect phase.
    ClientConnect,
    /// Client write phase.
    ClientWrite,
    /// Client waiting for `100 Continue` from the server.
    ClientContinue,
    /// Server reading the ICAP request headers.
    ServerHeaderRead,
    /// Server reading the request body.
    ServerBodyRead,
    /// Server writing the response.
    ServerWrite,
    /// Server idle keep-alive timeout.
    ServerIdle,
}

impl fmt::Display for TimeoutKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::ClientTotal => "client request",
            Self::ClientConnect => "client TCP connect",
            Self::ClientWrite => "client write",
            Self::ClientContinue => "client 100-continue wait",
            Self::ServerHeaderRead => "server header read",
            Self::ServerBodyRead => "server body read",
            Self::ServerWrite => "server write",
            Self::ServerIdle => "server idle keep-alive",
        };
        f.write_str(s)
    }
}

/// Wire-protocol failures: parsing, missing/invalid headers, encapsulation, …
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProtocolError {
    /// Peer closed the connection before a full ICAP header block arrived.
    #[error("peer closed before ICAP headers")]
    EarlyClose,

    /// Failed to parse an ICAP message.
    #[error("ICAP parse error: {0}")]
    Parse(String),

    /// Failed to parse an embedded HTTP message.
    #[error("HTTP parse error: {0}")]
    HttpParse(String),

    /// Required header was absent.
    #[error("missing required header: {0}")]
    MissingHeader(&'static str),

    /// Malformed header (catch-all). Prefer a more specific variant when
    /// possible.
    #[error("header error: {0}")]
    Header(String),

    /// Body-handling error (chunked decoder, dechunking, etc.).
    #[error("body error: {0}")]
    Body(String),

    /// Embedded body exceeded a configured byte limit.
    #[error("body too large: {size} bytes (max {max})")]
    BodyTooLarge { size: usize, max: usize },

    /// Invalid value for a specific ICAP/HTTP field.
    #[error("invalid {field}: {value}")]
    InvalidField { field: ProtocolField, value: String },

    /// `ISTag` validation failed.
    #[error("invalid ISTag: {0}")]
    InvalidISTag(String),

    /// Outgoing message could not be serialized.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Invalid UTF-8 in wire data.
    #[error("UTF-8 error: {0}")]
    Utf8(#[from] Utf8Error),

    /// Invalid UTF-8 while converting owned bytes into text.
    #[error("UTF-8 conversion error: {0}")]
    FromUtf8(#[from] FromUtf8Error),

    /// Invalid HTTP header name.
    #[error("invalid HTTP header name: {0}")]
    HeaderName(#[from] InvalidHeaderName),

    /// Invalid HTTP header value.
    #[error("invalid HTTP header value: {0}")]
    HeaderValue(#[from] InvalidHeaderValue),

    /// HTTP header value could not be represented as text.
    #[error("invalid HTTP header text: {0}")]
    HeaderToStr(#[from] ToStrError),
}

impl ProtocolError {
    /// Build [`Self::InvalidField`] tersely.
    pub fn invalid(field: ProtocolField, value: impl Into<String>) -> Self {
        Self::InvalidField {
            field,
            value: value.into(),
        }
    }
}

/// Identifies which ICAP/HTTP field carried an invalid value in
/// [`ProtocolError::InvalidField`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtocolField {
    StatusCode,
    Method,
    Uri,
    Version,
}

impl fmt::Display for ProtocolField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::StatusCode => "status code",
            Self::Method => "method",
            Self::Uri => "URI",
            Self::Version => "protocol version",
        };
        f.write_str(s)
    }
}

/// Builder / configuration errors. Surfaced from
/// [`crate::ServerBuilder::build`] and friends.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// A route was registered without any handlers.
    #[error("service '{service}' has no handlers")]
    ServiceWithoutHandlers { service: String },

    /// A service was registered without `ServiceOptions` carrying an `ISTag`.
    #[error("service '{service}' must configure ServiceOptions with an explicit ISTag")]
    MissingServiceOptions { service: String },

    /// `ServiceOptions::validate` rejected the configuration.
    #[error("invalid options for service '{service}': {reason}")]
    InvalidServiceOptions { service: String, reason: String },

    /// `default_service(...)` points at a name that resolves to no route.
    #[error("default service '{name}' resolves to unknown service '{resolved}'")]
    UnknownDefaultService { name: String, resolved: String },

    /// `alias(from, to)` points at a name that resolves to no route.
    #[error("alias '{from}' resolves to unknown service '{resolved}'")]
    UnknownAlias { from: String, resolved: String },

    /// Catch-all for anything that does not yet have a structured variant.
    #[error("{0}")]
    Other(String),
}

#[derive(Debug)]
struct MessageError(String);

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl StdError for MessageError {}

/// Convenient alias for results in the ICAP library.
pub type IcapResult<T> = Result<T, Error>;

/// Converts a generic `Result<T, E>` into an [`IcapResult<T>`] by wrapping
/// the error in [`Error::External`]. The original error is preserved via
/// `std::error::Error::source`.
pub trait ToIcapResult<T> {
    fn to_icap_result(self) -> IcapResult<T>;
}

impl<T, E> ToIcapResult<T> for Result<T, E>
where
    E: StdError + Send + Sync + 'static,
{
    fn to_icap_result(self) -> IcapResult<T> {
        self.map_err(Error::external)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_value_conversion_routes_through_protocol() {
        let err: Error = http::HeaderValue::from_str("bad\r\nvalue")
            .expect_err("header value must be rejected")
            .into();
        assert!(matches!(
            err,
            Error::Protocol(ProtocolError::HeaderValue(_))
        ));
        assert!(StdError::source(&err).is_some());
    }

    #[test]
    fn http_builder_conversion_preserves_source_error() {
        let err: Error = http::Request::builder()
            .method("bad method")
            .body(())
            .expect_err("invalid method must be rejected")
            .into();
        assert!(matches!(err, Error::Http(_)));
        assert!(StdError::source(&err).is_some());
    }

    #[test]
    fn to_icap_result_wraps_in_external() {
        let result: Result<(), io::Error> = Err(io::Error::other("external"));
        let err = result.to_icap_result().expect_err("external error");
        assert!(matches!(err, Error::External(_)));
        assert!(StdError::source(&err).is_some());
    }

    #[test]
    fn timeout_helpers_set_kind() {
        let err = Error::server_write_timeout(Duration::from_millis(5));
        match err {
            Error::Timeout(t) => assert_eq!(t.kind, TimeoutKind::ServerWrite),
            _ => panic!("expected Timeout variant"),
        }
    }

    #[test]
    fn classifiers_agree_with_variant() {
        let t = Error::client_connect_timeout(Duration::from_millis(1));
        assert!(t.is_timeout());
        assert!(t.is_retryable());

        let p = Error::parse("bad");
        assert!(p.is_protocol());
        assert!(!p.is_retryable());

        let e = Error::Protocol(ProtocolError::EarlyClose);
        assert!(e.is_early_close());
        assert!(e.is_retryable());
    }
}
