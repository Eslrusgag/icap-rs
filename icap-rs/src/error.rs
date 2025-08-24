//! Error handling
//!
//! This module defines:
//! - [`IcapError`]: the main error type for ICAP operations.
//! - [`IcapResult<T>`]: a convenient alias for `Result<T, IcapError>`.
//! - [`ToIcapResult`]: a helper trait for converting generic `Result` into `IcapResult`.
//!
//! It covers network errors, parsing/serialization, configuration issues, and unexpected failures.
use http::header::{InvalidHeaderName, InvalidHeaderValue};
use std::error::Error as StdError;
use std::str::Utf8Error;
use std::time::Duration;
use thiserror::Error;

/// It covers network issues, parsing/serialization errors, invalid protocol fields,
/// configuration/service/handler failures, and unexpected runtime errors.
#[derive(Error, Debug)]
pub enum Error {
    /// Network-level error (TCP connection, timeout, etc.).
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),

    #[error("Network timeout after {0:?}")]
    ClientTimeout(Duration),

    #[error("Peer closed before ICAP headers")]
    EarlyCloseWithoutHeaders,

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

    /// Invalid ISTag header (length/charset).
    #[error("Invalid ISTag: {0}")]
    InvalidISTag(String),

    /// Invalid or malformed header.
    #[error("Header error: {0}")]
    Header(String),

    /// Error while handling the message body.
    #[error("Body error: {0}")]
    Body(String),

    /// Service-related error.
    #[error("Service error: {0}")]
    Service(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Configuration(String),

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

    /// Create a configuration error.
    pub fn configuration(message: impl Into<String>) -> Self {
        Self::Configuration(message.into())
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

impl From<Box<dyn StdError + Send + Sync>> for Error {
    fn from(err: Box<dyn StdError + Send + Sync>) -> Self {
        Self::Unexpected(err.to_string())
    }
}

/// Convenient alias for results in the ICAP library.
pub type IcapResult<T> = Result<T, Error>;

/// Converts a generic `Result<T, E>` into an `IcapResult<T>`.
///
/// Any error is wrapped into [`IcapError::Unexpected`].
pub trait ToIcapResult<T> {
    fn to_icap_result(self) -> IcapResult<T>;
}

impl<T, E> ToIcapResult<T> for Result<T, E>
where
    E: StdError + Send + Sync + 'static,
{
    fn to_icap_result(self) -> IcapResult<T> {
        self.map_err(|e| Error::Unexpected(e.to_string()))
    }
}

impl From<Utf8Error> for Error {
    fn from(e: Utf8Error) -> Self {
        Error::HttpParse(e.to_string())
    }
}
impl From<InvalidHeaderName> for Error {
    fn from(e: InvalidHeaderName) -> Self {
        Error::HttpParse(e.to_string())
    }
}
impl From<InvalidHeaderValue> for Error {
    fn from(e: InvalidHeaderValue) -> Self {
        Error::HttpParse(e.to_string())
    }
}
