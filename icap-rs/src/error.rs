//! Error handling.
//!
//! This module defines:
//! - [`enum@Error`]: the main error type for ICAP operations.
//! - [`IcapResult<T>`]: a convenient alias for `Result<T, Error>`.
//! - [`ToIcapResult`]: a helper trait for converting generic `Result` into `IcapResult`.
//!
//! It covers network errors, parsing/serialization, configuration issues, typed
//! HTTP helper errors, and unexpected failures.
use http::header::{InvalidHeaderName, InvalidHeaderValue};
use http::{Error as HttpError, header::ToStrError};
use std::error::Error as StdError;
use std::str::Utf8Error;
use std::string::FromUtf8Error;
use std::time::Duration;
use thiserror::Error;

/// It covers network issues, parsing/serialization errors, invalid protocol fields,
/// configuration/service/handler failures, and unexpected runtime errors.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Network-level error (TCP connection, timeout, etc.).
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),

    /// The whole client operation exceeded the configured timeout.
    #[error("Client timeout after {0:?}")]
    ClientTimeout(Duration),

    /// The client could not establish a TCP connection within the configured timeout.
    #[error("Client TCP connect timeout after {0:?}")]
    ClientConnectTimeout(Duration),

    /// The client could not write request bytes within the configured timeout.
    #[error("Client write timeout after {0:?}")]
    ClientWriteTimeout(Duration),

    /// The server did not send `100 Continue` or an early final response in time.
    #[error("Client continue timeout after {0:?}")]
    ClientContinueTimeout(Duration),

    /// The server did not finish reading request headers in time.
    #[error("Server header read timeout after {0:?}")]
    ServerHeaderReadTimeout(Duration),

    /// The server did not finish reading the request body in time.
    #[error("Server body read timeout after {0:?}")]
    ServerBodyReadTimeout(Duration),

    /// The server could not write response bytes within the configured timeout.
    #[error("Server write timeout after {0:?}")]
    ServerWriteTimeout(Duration),

    /// A kept-alive client did not send the next request before idle expiry.
    #[error("Server idle keep-alive timeout after {0:?}")]
    ServerIdleTimeout(Duration),

    /// The peer closed the connection before a complete ICAP header block
    /// was received (no terminating `CRLFCRLF`).
    ///
    /// Typically indicates the server aborted the connection or sent an
    /// incomplete response.
    #[error("Peer closed before ICAP headers")]
    EarlyCloseWithoutHeaders,

    /// Invalid UTF-8 in wire data.
    #[error("UTF-8 error: {0}")]
    Utf8(#[from] Utf8Error),

    /// Invalid UTF-8 while converting owned bytes into text.
    #[error("UTF-8 conversion error: {0}")]
    FromUtf8(#[from] FromUtf8Error),

    /// Failed to parse an ICAP message.
    #[error("ICAP parsing error: {0}")]
    Parse(String),

    /// Failed to parse an embedded HTTP message.
    #[error("HTTP parsing error: {0}")]
    HttpParse(String),

    /// Invalid ICAP status code.
    #[error("Invalid status code: {0}")]
    InvalidStatusCode(String),

    /// Invalid ICAP method.
    #[error("Invalid method: {0}")]
    InvalidMethod(String),

    /// Invalid ICAP URI.
    #[error("Invalid URI: {0}")]
    InvalidUri(String),

    /// Invalid ICAP protocol version.
    #[error("Invalid protocol version: {0}")]
    InvalidVersion(String),

    /// Invalid `ISTag` header
    #[error("Invalid ISTag: {0}")]
    InvalidISTag(String),

    /// Invalid HTTP header name.
    #[error("Invalid HTTP header name: {0}")]
    HeaderName(#[from] InvalidHeaderName),

    /// Invalid HTTP header value.
    #[error("Invalid HTTP header value: {0}")]
    HeaderValue(#[from] InvalidHeaderValue),

    /// HTTP header value could not be represented as text.
    #[error("Invalid HTTP header text: {0}")]
    HeaderToStr(#[from] ToStrError),

    /// Missing required ICAP header
    #[error("Missing required header: {0}")]
    MissingHeader(&'static str),

    /// Invalid or malformed header.
    #[error("Header error: {0}")]
    Header(String),

    /// Error while handling the message body.
    #[error("Body error: {0}")]
    Body(String),

    /// Service-related error.
    #[error("Service error: {0}")]
    Service(String),

    /// Application handler error.
    #[error("Handler error: {0}")]
    Handler(String),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Deserialization error.
    #[error("Deserialization error: {0}")]
    Deserialization(String),

    /// Unexpected/unclassified error.
    #[error("Unexpected error: {0}")]
    Unexpected(String),

    /// Error from an external helper converted through [`ToIcapResult`].
    #[error("External error: {message}")]
    External {
        /// Human-readable error message.
        message: String,
        /// Original source error.
        #[source]
        source: Box<dyn StdError + Send + Sync + 'static>,
    },

    /// Error returned by the `http` crate builders.
    #[error("HTTP builder error: {0}")]
    Http(#[from] HttpError),

    /// TLS-layer error (handshake, certificate verification, PEM loading…).
    ///
    /// See [`crate::tls::TlsError`] for the structured variants. Only present
    /// when the crate is built with the `tls-rustls` feature.
    #[cfg(feature = "tls-rustls")]
    #[error(transparent)]
    Tls(#[from] crate::tls::TlsError),
}

impl Error {
    /// Create a parsing error.
    pub fn parse(message: impl Into<String>) -> Self {
        Self::Parse(message.into())
    }

    /// Create an HTTP parsing error.
    pub fn http_parse(message: impl Into<String>) -> Self {
        Self::HttpParse(message.into())
    }

    /// Create a header error.
    pub fn header(message: impl Into<String>) -> Self {
        Self::Header(message.into())
    }

    /// Create a body error.
    pub fn body(message: impl Into<String>) -> Self {
        Self::Body(message.into())
    }

    /// Create a service error.
    pub fn service(message: impl Into<String>) -> Self {
        Self::Service(message.into())
    }

    /// Create a handler error.
    pub fn handler(message: impl Into<String>) -> Self {
        Self::Handler(message.into())
    }

    /// Create a serialization error.
    pub fn serialization(message: impl Into<String>) -> Self {
        Self::Serialization(message.into())
    }

    /// Create a deserialization error.
    pub fn deserialization(message: impl Into<String>) -> Self {
        Self::Deserialization(message.into())
    }

    /// Create an unknown/unexpected error.
    pub fn unknown(message: impl Into<String>) -> Self {
        Self::Unexpected(message.into())
    }

    /// Create an unexpected/unclassified error.
    pub fn unexpected(message: impl Into<String>) -> Self {
        Self::Unexpected(message.into())
    }
}

impl From<String> for Error {
    fn from(err: String) -> Self {
        Self::Unexpected(err)
    }
}

impl From<&str> for Error {
    fn from(err: &str) -> Self {
        Self::Unexpected(err.to_string())
    }
}

/// Convenient alias for results in the ICAP library.
pub type IcapResult<T> = Result<T, Error>;

/// Converts a generic `Result<T, E>` into an `IcapResult<T>`.
///
/// Any error is wrapped into [`Error::External`] with the original source
/// preserved for callers that inspect the error chain.
pub trait ToIcapResult<T> {
    /// Convert the result into this crate's error type.
    fn to_icap_result(self) -> IcapResult<T>;
}

impl<T, E> ToIcapResult<T> for Result<T, E>
where
    E: StdError + Send + Sync + 'static,
{
    fn to_icap_result(self) -> IcapResult<T> {
        self.map_err(|e| Error::External {
            message: e.to_string(),
            source: Box::new(e),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, IcapResult, ToIcapResult};
    use std::error::Error as StdError;

    #[test]
    fn header_value_conversion_preserves_source_error() {
        let err: Error = http::HeaderValue::from_str("bad\r\nvalue")
            .expect_err("header value must be rejected")
            .into();

        assert!(matches!(err, Error::HeaderValue(_)));
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
    fn to_icap_result_preserves_external_source_error() {
        let result: Result<(), std::io::Error> = Err(std::io::Error::other("external"));
        let err = result.to_icap_result().expect_err("external error");

        assert!(matches!(err, Error::External { .. }));
        assert!(StdError::source(&err).is_some());
    }

    #[test]
    fn icap_result_alias_uses_crate_error() {
        fn returns_alias() -> IcapResult<()> {
            Err(Error::parse("bad message"))
        }

        assert!(matches!(returns_alias(), Err(Error::Parse(_))));
    }
}
