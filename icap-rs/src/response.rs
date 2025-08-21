//! ICAP response types and utilities.
//!
//! This module defines:
//! - [`StatusCode`]: enumeration of ICAP status codes (RFC 3507).
//! - [`Response`]: representation of an ICAP response, including headers and optional body.
//! - [`ResponseBuilder`]: a convenient builder for constructing responses programmatically.
//!
//! Features:
//! - Parsing and serializing ICAP responses (`from_raw`, `to_raw`).
//! - Easy header manipulation (`add_header`, `get_header`, `remove_header`).
//! - Helpers for common cases like `204 No Content`.
//! - Predicates for success/error classification.
//!
//! # Examples
//!
//! ```rust
//!
//! use icap_rs::{Response, StatusCode};
//!
//! // Construct a simple 204 No Content response
//! let resp = Response::no_content()
//!     .add_header("ISTag", "policy-123")
//!     .with_body_string("optional body");
//!
//! assert!(resp.is_success());
//! assert_eq!(resp.status_code, StatusCode::NoContent204);
//! ```

use crate::error::IcapResult;
use crate::headers_end;
use http::{HeaderMap, HeaderName, HeaderValue};
use std::fmt;
use std::str::FromStr;
use tracing::{debug, trace};

/// ICAP status codes as defined in RFC 3507.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusCode {
    Continue100,
    Ok200,
    NoContent204,
    PartialContent206,
    BadRequest400,
    NotFound404,
    MethodNotAllowed405,
    RequestEntityTooLarge413,
    InternalServerError500,
    ServiceUnavailable503,
    GatewayTimeout504,
}

impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            StatusCode::Continue100 => "100",
            StatusCode::Ok200 => "200",
            StatusCode::NoContent204 => "204",
            StatusCode::PartialContent206 => "206",
            StatusCode::BadRequest400 => "400",
            StatusCode::NotFound404 => "404",
            StatusCode::MethodNotAllowed405 => "405",
            StatusCode::RequestEntityTooLarge413 => "413",
            StatusCode::InternalServerError500 => "500",
            StatusCode::ServiceUnavailable503 => "503",
            StatusCode::GatewayTimeout504 => "504",
        };
        write!(f, "{s}")
    }
}

impl TryFrom<u16> for StatusCode {
    type Error = &'static str;

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        Ok(match v {
            100 => StatusCode::Continue100,
            200 => StatusCode::Ok200,
            204 => StatusCode::NoContent204,
            206 => StatusCode::PartialContent206,
            400 => StatusCode::BadRequest400,
            404 => StatusCode::NotFound404,
            405 => StatusCode::MethodNotAllowed405,
            413 => StatusCode::RequestEntityTooLarge413,
            500 => StatusCode::InternalServerError500,
            503 => StatusCode::ServiceUnavailable503,
            504 => StatusCode::GatewayTimeout504,
            _ => return Err("Invalid ICAP status code"),
        })
    }
}

impl FromStr for StatusCode {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "100" => StatusCode::Continue100,
            "200" => StatusCode::Ok200,
            "204" => StatusCode::NoContent204,
            "206" => StatusCode::PartialContent206,
            "400" => StatusCode::BadRequest400,
            "404" => StatusCode::NotFound404,
            "405" => StatusCode::MethodNotAllowed405,
            "413" => StatusCode::RequestEntityTooLarge413,
            "500" => StatusCode::InternalServerError500,
            "503" => StatusCode::ServiceUnavailable503,
            "504" => StatusCode::GatewayTimeout504,
            _ => return Err("Invalid ICAP status code"),
        })
    }
}

/// Representation of an ICAP response.
///
/// Contains version string, status code and text, ICAP headers,
/// and an optional body (such as encapsulated HTTP or chunked data).
#[derive(Debug, Clone)]
pub struct Response {
    /// ICAP protocol version (usually `"ICAP/1.0"`).
    pub version: String,
    /// Response status code.
    pub status_code: StatusCode,
    /// Human-readable status text (e.g. `"OK"`, `"No Content"`).
    pub status_text: String,
    /// ICAP headers.
    pub headers: HeaderMap,
    /// Optional body (arbitrary payload, chunked HTTP, etc.).
    pub body: Vec<u8>,
}

impl Response {
    /// Create a new ICAP response with the given status code and status text.
    pub fn new(status_code: StatusCode, status_text: &str) -> Self {
        Self {
            version: "ICAP/1.0".to_string(),
            status_code,
            status_text: status_text.to_string(),
            headers: HeaderMap::new(),
            body: Vec::new(),
        }
    }

    /// Shortcut for a `204 No Content` response.
    pub fn no_content() -> Self {
        Self::new(StatusCode::NoContent204, "No Content")
    }

    /// Shortcut for a `204 No Content` response with headers.
    pub fn no_content_with_headers(headers: HeaderMap) -> Self {
        Self {
            version: "ICAP/1.0".to_string(),
            status_code: StatusCode::NoContent204,
            status_text: "No Content".to_string(),
            headers,
            body: Vec::new(),
        }
    }

    /// Add or overwrite a header.
    pub fn add_header(mut self, name: &str, value: &str) -> Self {
        let n: HeaderName = name.parse().expect("invalid header name");
        let v: HeaderValue = HeaderValue::from_str(value).expect("invalid header value");
        self.headers.insert(n, v);
        self
    }

    /// Set the response body from bytes.
    pub fn with_body(mut self, body: &[u8]) -> Self {
        self.body = body.to_vec();
        self
    }

    /// Set the response body from a string.
    pub fn with_body_string(mut self, body: &str) -> Self {
        self.body = body.as_bytes().to_vec();
        self
    }

    /// Serialize into raw ICAP bytes.
    pub fn to_raw(&self) -> Vec<u8> {
        crate::parser::serialize_icap_response(self).unwrap_or_default()
    }

    /// Parse an ICAP response from raw bytes.
    pub fn from_raw(raw: &[u8]) -> IcapResult<Self> {
        parse_icap_response(raw)
    }

    /// Get a header value by name.
    pub fn get_header(&self, name: &str) -> Option<&HeaderValue> {
        self.headers.get(name)
    }

    /// Check whether a header exists.
    pub fn has_header(&self, name: &str) -> bool {
        self.headers.contains_key(name)
    }

    /// Remove a header by name.
    pub fn remove_header(&mut self, name: &str) -> Option<HeaderValue> {
        self.headers.remove(name)
    }

    /// Whether the response indicates success (200 or 204).
    pub fn is_success(&self) -> bool {
        matches!(
            self.status_code,
            StatusCode::Ok200 | StatusCode::NoContent204
        )
    }

    /// Whether the response indicates an error (4xx/5xx).
    pub fn is_error(&self) -> bool {
        matches!(
            self.status_code,
            StatusCode::BadRequest400
                | StatusCode::NotFound404
                | StatusCode::MethodNotAllowed405
                | StatusCode::RequestEntityTooLarge413
                | StatusCode::InternalServerError500
                | StatusCode::ServiceUnavailable503
                | StatusCode::GatewayTimeout504
        )
    }
}

impl Default for Response {
    fn default() -> Self {
        Self::new(StatusCode::Ok200, "OK")
    }
}

impl fmt::Display for Response {
    /// Formats the ICAP response for debugging: status line, headers, and body (if present).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{} {} {}",
            self.version, self.status_code, self.status_text
        )?;
        for (name, value) in self.headers.iter() {
            writeln!(
                f,
                "{}: {}",
                name.as_str(),
                value.to_str().unwrap_or_default()
            )?;
        }
        if !self.body.is_empty() {
            writeln!(f, "\n{}", String::from_utf8_lossy(&self.body))?;
        }
        Ok(())
    }
}

/// Builder for [`Response`].
///
/// Provides a fluent API for constructing ICAP responses programmatically.
#[derive(Debug)]
pub struct ResponseBuilder {
    response: Response,
}

impl ResponseBuilder {
    /// Create a new builder with given status code and text.
    pub fn new(status_code: StatusCode, status_text: &str) -> Self {
        Self {
            response: Response::new(status_code, status_text),
        }
    }

    /// Add a header.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.response = self.response.add_header(name, value);
        self
    }

    /// Set the body from bytes.
    pub fn body(mut self, body: &[u8]) -> Self {
        self.response = self.response.with_body(body);
        self
    }

    /// Set the body from a string.
    pub fn body_string(mut self, body: &str) -> Self {
        self.response = self.response.with_body_string(body);
        self
    }

    /// Finish and return the constructed [`Response`].
    pub fn build(self) -> Response {
        self.response
    }
}

pub fn parse_icap_response(raw: &[u8]) -> IcapResult<Response> {
    trace!("parse_icap_response: len={}", raw.len());
    if raw.is_empty() {
        return Err("Empty response".into());
    }

    let hdr_end = headers_end(raw).ok_or("ICAP response headers not complete")?;
    let head = &raw[..hdr_end];
    let head_str = std::str::from_utf8(head)?;
    let mut lines = head_str.split("\r\n");

    let status_line = lines.next().ok_or("Empty response")?;
    let parts: Vec<&str> = status_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err("Invalid status line format".into());
    }

    let version = parts[0].to_string();

    let status_code = match StatusCode::from_str(parts[1]) {
        Ok(code) => code,
        Err(_) => {
            let code_num = parts[1].parse::<u16>().map_err(|_| "Invalid status code")?;
            StatusCode::try_from(code_num)
                .map_err(|_| format!("Unknown ICAP status code: {}", code_num))?
        }
    };

    let status_text = if parts.len() > 2 {
        parts[2..].join(" ")
    } else {
        String::new()
    };

    debug!(
        "parse_icap_response: {} {} {}",
        version, status_code, status_text
    );

    let mut headers = HeaderMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(colon) = line.find(':') {
            let name = &line[..colon];
            let value = line[colon + 1..].trim();
            headers.insert(
                HeaderName::from_bytes(name.as_bytes())?,
                HeaderValue::from_str(value)?,
            );
        }
    }

    let body = raw[hdr_end..].to_vec();
    trace!("parse_icap_response: body_len={}", body.len());

    Ok(Response {
        version,
        status_code,
        status_text,
        headers,
        body,
    })
}
