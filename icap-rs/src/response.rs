//! ICAP response types and utilities.
//!
//! This module defines:
//! - [`StatusCode`]: enumeration of ICAP status codes (RFC 3507).
//! - [`Response`]: representation of an ICAP response, including headers and optional body.
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

use crate::ICAP_VERSION;
use crate::error::{Error, IcapResult};
use crate::parser::{find_double_crlf, serialize_http_response};
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
    pub(crate) headers: HeaderMap,
    /// Optional body (arbitrary payload, chunked HTTP, etc.).
    pub body: Vec<u8>,
}

impl Response {
    /// Create a new ICAP response with the given status code and status text.
    pub fn new(status_code: StatusCode, status_text: &str) -> Self {
        Self {
            version: ICAP_VERSION.to_string(),
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
    pub fn no_content_with_headers(headers: HeaderMap) -> IcapResult<Self> {
        let istag = headers
            .get("ISTag")
            .ok_or(Error::MissingHeader("ISTag"))?
            .to_str()
            .map_err(|e| Error::Unexpected(e.to_string()))?;
        validate_istag(istag)?;

        Ok(Self {
            version: ICAP_VERSION.to_string(),
            status_code: StatusCode::NoContent204,
            status_text: "No Content".to_string(),
            headers,
            body: Vec::new(),
        })
    }

    /// Add or overwrite a header.
    /// NOTE: Setting `ISTag` here is discouraged; prefer `try_set_istag()`.
    pub fn add_header(mut self, name: &str, value: &str) -> Self {
        if name.eq_ignore_ascii_case("ISTag") {
            if let Err(e) = validate_istag(value) {
                tracing::warn!("ignoring invalid ISTag passed to add_header: {}", e);
                return self;
            }
            let val = HeaderValue::from_str(value).expect("invalid ISTag header value");
            self.headers.insert(HeaderName::from_static("istag"), val);
            return self;
        }

        let n: HeaderName = name.parse().expect("invalid header name");
        let v: HeaderValue = HeaderValue::from_str(value).expect("invalid header value");
        self.headers.insert(n, v);
        self
    }

    /// Set ISTag header with validation (length ≤32, charset [A-Za-z0-9.-]).
    /// Returns `Self` on success; otherwise `Error::InvalidISTag`.
    pub fn try_set_istag(mut self, istag: &str) -> IcapResult<Self> {
        validate_istag(istag)?;
        let name = HeaderName::from_static("istag");
        let val = HeaderValue::from_str(istag).map_err(|e| Error::Header(e.to_string()))?;
        self.headers.insert(name, val);
        Ok(self)
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
    pub fn to_raw(&self) -> IcapResult<Vec<u8>> {
        let mut resp = self.clone();

        let require_istag = matches!(
            resp.status_code,
            StatusCode::Ok200 | StatusCode::NoContent204 | StatusCode::PartialContent206
        );

        if require_istag {
            let istag = resp
                .headers
                .get("ISTag")
                .ok_or(Error::MissingHeader("ISTag"))?
                .to_str()
                .map_err(|e| Error::Unexpected(e.to_string()))?;
            validate_istag(istag)?;
        } else if let Some(v) = resp.headers.get("ISTag") {
            let s = v.to_str().map_err(|e| Error::Unexpected(e.to_string()))?;
            validate_istag(s)?;
        }

        match resp.status_code {
            StatusCode::NoContent204 => {
                if !resp.body.is_empty() {
                    return Err(Error::Body("204 must not carry a body".into()));
                }
                if !resp.headers.contains_key("Encapsulated") {
                    resp.headers.insert(
                        HeaderName::from_static("encapsulated"),
                        HeaderValue::from_static("null-body=0"),
                    );
                } else if resp.headers.get("Encapsulated").map(|v| v.as_bytes())
                    != Some(b"null-body=0".as_slice())
                {
                    return Err(Error::Header(
                        "204 requires Encapsulated: null-body=0".into(),
                    ));
                }
            }
            StatusCode::Ok200 | StatusCode::PartialContent206 => {
                if !resp.headers.contains_key("Encapsulated") {
                    if resp.body.is_empty() {
                        return Err(Error::MissingHeader(
                            "Encapsulated missing and cannot infer for 2xx with empty body; \
                         set it explicitly or use Response::with_http_response(...)",
                        ));
                    }
                    if looks_like_http_resp(&resp.body) {
                        let enc = compute_enc_for_res_body(&resp.body)?;
                        let hv = HeaderValue::from_str(&enc)
                            .map_err(|e| Error::Header(e.to_string()))?;
                        resp.headers
                            .insert(HeaderName::from_static("encapsulated"), hv);
                    } else {
                        return Err(Error::Header(
                            "Encapsulated missing and body is not an embedded HTTP/1.x".to_string(),
                        ));
                    }
                }
            }
            _ => {
                if !resp.headers.contains_key("Encapsulated") {
                    if resp.body.is_empty() {
                        resp.headers.insert(
                            HeaderName::from_static("encapsulated"),
                            HeaderValue::from_static("null-body=0"),
                        );
                    } else if looks_like_http_resp(&resp.body) {
                        let enc = compute_enc_for_res_body(&resp.body)?;
                        let hv = HeaderValue::from_str(&enc)
                            .map_err(|e| Error::Header(e.to_string()))?;
                        resp.headers
                            .insert(HeaderName::from_static("encapsulated"), hv);
                    } else {
                        resp.headers.insert(
                            HeaderName::from_static("encapsulated"),
                            HeaderValue::from_static("opt-body=0"),
                        );
                    }
                }
            }
        }

        crate::parser::serialize_icap_response(&resp)
            .map_err(|e| Error::Serialization(e.to_string()))
    }

    /// Parse an ICAP response from raw bytes.
    pub fn from_raw(raw: &[u8]) -> IcapResult<Self> {
        parse_icap_response(raw)
    }

    /// Get a header value by name.
    pub fn get_header(&self, name: &str) -> Option<&HeaderValue> {
        self.headers.get(name)
    }

    /// Return a read-only view of all ICAP headers.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
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

    pub fn with_http_response(mut self, http: &http::Response<Vec<u8>>) -> IcapResult<Self> {
        let bytes = serialize_http_response(http);

        let enc = compute_enc_for_res_body(&bytes)?;
        let hv = HeaderValue::from_str(&enc).map_err(|e| Error::Header(e.to_string()))?;

        self.body = bytes;
        self.headers
            .insert(HeaderName::from_static("encapsulated"), hv);
        Ok(self)
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

#[inline]
fn looks_like_http_resp(body: &[u8]) -> bool {
    body.starts_with(b"HTTP/1.0") || body.starts_with(b"HTTP/1.1")
}

fn compute_enc_for_res_body(body: &[u8]) -> IcapResult<String> {
    let hdr_end = find_double_crlf(body)
        .ok_or_else(|| Error::Header("embedded HTTP missing CRLFCRLF".into()))?;
    if body.len() > hdr_end {
        Ok(format!("res-hdr=0, res-body={}", hdr_end))
    } else {
        Ok("res-hdr=0".to_string())
    }
}

pub(crate) fn parse_icap_response(raw: &[u8]) -> IcapResult<Response> {
    trace!("parse_icap_response: len={}", raw.len());
    if raw.is_empty() {
        return Err("Empty response".into());
    }

    let hdr_end = find_double_crlf(raw).ok_or("ICAP response headers not complete")?;
    let head = &raw[..hdr_end];
    let head_str = std::str::from_utf8(head)?;
    let mut lines = head_str.split("\r\n");

    let status_line = lines.next().ok_or("Empty response")?;
    let parts: Vec<&str> = status_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err("Invalid status line format".into());
    }

    if parts[0] != ICAP_VERSION {
        return Err(Error::InvalidVersion(parts[0].to_string()));
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
    let mut seen_encapsulated = false;
    let mut encapsulated_value: Option<String> = None;

    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(colon) = line.find(':') {
            let name = &line[..colon];
            let value = line[colon + 1..].trim();

            if name.eq_ignore_ascii_case("Encapsulated") {
                if seen_encapsulated {
                    return Err(Error::Header("duplicate Encapsulated header".into()));
                }
                seen_encapsulated = true;
                encapsulated_value = Some(value.to_string());
            }

            if name.eq_ignore_ascii_case("ISTag") {
                validate_istag(value)?;
            }

            headers.insert(
                HeaderName::from_bytes(name.as_bytes())?,
                HeaderValue::from_str(value)?,
            );
        }
    }

    let require_istag = matches!(
        status_code,
        StatusCode::Ok200 | StatusCode::NoContent204 | StatusCode::PartialContent206
    );
    if !headers.contains_key("ISTag") {
        if require_istag {
            return Err(Error::MissingHeader("ISTag"));
        } else {
            tracing::warn!(
                code = %status_code,
                "ICAP response without ISTag (non-2xx) — accepting for compatibility"
            );
        }
    }

    let body = raw[hdr_end..].to_vec();
    trace!("parse_icap_response: body_len={}", body.len());

    if require_istag {
        let enc_val = encapsulated_value
            .or_else(|| {
                headers
                    .get("Encapsulated")
                    .and_then(|v| v.to_str().ok().map(|s| s.to_string()))
            })
            .ok_or(Error::MissingHeader("Encapsulated"))?;

        match status_code {
            StatusCode::NoContent204 => {
                if !enc_val.trim().eq_ignore_ascii_case("null-body=0") {
                    return Err(Error::Header(
                        "204 requires Encapsulated: null-body=0".into(),
                    ));
                }
                if !body.is_empty() {
                    return Err(Error::Body("204 must not carry a body".into()));
                }
            }
            StatusCode::Ok200 | StatusCode::PartialContent206 => {
                let pairs = parse_encapsulated_pairs_strict(&enc_val)?;
                validate_encapsulated_offsets(&pairs, body.len())?;
            }
            _ => {}
        }
    }

    Ok(Response {
        version,
        status_code,
        status_text,
        headers,
        body,
    })
}

fn parse_encapsulated_pairs_strict(s: &str) -> IcapResult<Vec<(String, usize)>> {
    let mut out = Vec::new();
    if s.trim().is_empty() {
        return Err(Error::MissingHeader("Encapsulated"));
    }

    for part in s.split(',') {
        let p = part.trim();
        let (name, off_str) = p
            .split_once('=')
            .ok_or_else(|| Error::Header(format!("invalid Encapsulated token: {p}")))?;
        let name_norm = name.trim();
        let name_lc = name_norm.to_ascii_lowercase();

        let ok_name = matches!(
            name_lc.as_str(),
            "req-hdr" | "res-hdr" | "req-body" | "res-body" | "opt-body" | "null-body"
        );
        if !ok_name {
            return Err(Error::Header(format!(
                "invalid Encapsulated part name: {name_norm}"
            )));
        }

        // оффсет
        let off: usize = off_str
            .trim()
            .parse::<usize>()
            .map_err(|_| Error::Header(format!("invalid Encapsulated offset: {off_str}")))?;

        out.push((name_lc, off));
    }

    Ok(out)
}

fn validate_encapsulated_offsets(pairs: &[(String, usize)], enc_len: usize) -> IcapResult<()> {
    for (_, off) in pairs {
        if *off > enc_len {
            return Err(Error::Header(format!(
                "Encapsulated offset {} out of range (len={})",
                off, enc_len
            )));
        }
    }
    for w in pairs.windows(2) {
        let prev = w[0].1;
        let curr = w[1].1;
        if curr < prev {
            return Err(Error::Header(format!(
                "Encapsulated offsets not monotonic: {} -> {}",
                prev, curr
            )));
        }
    }
    Ok(())
}

#[inline]
fn validate_istag(raw: &str) -> IcapResult<()> {
    let s = raw.trim();

    let mut val = String::new();
    if s.starts_with('"') {
        if !s.ends_with('"') || s.len() < 2 {
            return Err(Error::InvalidISTag("unterminated quoted ISTag".into()));
        }
        let inner = &s[1..s.len() - 1];
        let mut it = inner.chars();
        while let Some(c) = it.next() {
            if c == '\\' {
                if let Some(esc) = it.next() {
                    val.push(esc);
                } else {
                    return Err(Error::InvalidISTag(
                        "dangling escape in quoted ISTag".into(),
                    ));
                }
            } else {
                if c.is_control() {
                    return Err(Error::InvalidISTag("control char in quoted ISTag".into()));
                }
                val.push(c);
            }
        }
    } else {
        val.push_str(s);
    }

    if val.len() > 32 {
        return Err(Error::InvalidISTag(format!(
            "too long: {} bytes (max 32)",
            val.len()
        )));
    }
    if !val
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(Error::InvalidISTag(format!(
            "invalid characters in: {raw} (allowed: [A-Za-z0-9.-])"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn icap_bytes(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    #[test]
    fn statuscode_display_and_from() {
        assert_eq!(StatusCode::Ok200.to_string(), "200");
        assert_eq!(StatusCode::NoContent204.to_string(), "204");

        assert_eq!(StatusCode::from_str("200").unwrap(), StatusCode::Ok200);
        assert_eq!(
            StatusCode::from_str("204").unwrap(),
            StatusCode::NoContent204
        );
        assert!(StatusCode::from_str("777").is_err());

        assert_eq!(
            StatusCode::try_from(206).unwrap(),
            StatusCode::PartialContent206
        );
        assert!(StatusCode::try_from(777u16).is_err());
    }

    #[test]
    fn response_add_get_remove_header() {
        let mut resp = Response::new(StatusCode::Ok200, "OK").add_header("Service", "Test");
        assert!(resp.has_header("Service"));
        assert_eq!(
            resp.get_header("Service").unwrap(),
            &HeaderValue::from_static("Test")
        );

        let removed = resp.remove_header("Service");
        assert!(removed.is_some());
        assert!(!resp.has_header("Service"));
    }

    #[test]
    fn last_duplicate_header_wins() {
        let raw = icap_bytes(
            "ICAP/1.0 204 No Content\r\n\
         ISTag: a\r\n\
         ISTag: b\r\n\
         Encapsulated: null-body=0\r\n\
         \r\n",
        );
        let r = parse_icap_response(&raw).expect("parse");
        assert_eq!(
            r.get_header("ISTag").unwrap(),
            &HeaderValue::from_static("b")
        );
    }

    #[test]
    fn parse_errors_on_empty() {
        let err = parse_icap_response(b"").unwrap_err();
        assert!(err.to_string().contains("Empty response"));
    }

    #[test]
    fn parse_errors_on_invalid_status_code_token() {
        let raw = icap_bytes(
            "ICAP/1.0 ABC OK\r\n\
             \r\n",
        );
        let err = parse_icap_response(&raw).unwrap_err();
        assert!(err.to_string().contains("Invalid status code"));
    }

    #[test]
    fn parse_errors_on_unknown_numeric_status_code() {
        let raw = icap_bytes(
            "ICAP/1.0 777 Weird\r\n\
             \r\n",
        );
        let err = parse_icap_response(&raw).unwrap_err();
        assert!(err.to_string().contains("Unknown ICAP status code: 777"));
    }

    #[test]
    fn add_header_istag_rejects_invalid_but_does_not_panic() {
        let resp = Response::new(StatusCode::Ok200, "OK").add_header("ISTag", "BAD TAG WITH SPACE");
        assert!(resp.get_header("ISTag").is_none());
    }

    #[test]
    fn add_header_istag_accepts_valid_value() {
        let resp = Response::new(StatusCode::Ok200, "OK").add_header("ISTag", "ok-Tag.123");
        assert_eq!(
            resp.get_header("ISTag").unwrap(),
            &HeaderValue::from_static("ok-Tag.123")
        );
    }

    #[test]
    fn to_raw_errors_if_istag_missing() {
        let resp = Response::new(StatusCode::Ok200, "OK").add_header("Service", "X");
        let err = resp.to_raw().unwrap_err();
        assert!(matches!(err, Error::MissingHeader(h) if h == "ISTag"));
    }

    #[test]
    fn to_raw_ok_when_istag_is_valid() {
        let resp = Response::new(StatusCode::Ok200, "OK")
            .try_set_istag("ok-Tag.123")
            .unwrap()
            .add_header("Encapsulated", "res-hdr=0")
            .with_body_string("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let _bytes = resp
            .to_raw()
            .expect("to_raw should succeed with valid ISTag");
    }

    #[test]
    fn istag_accepts_quoted() {
        assert!(validate_istag(r#""5BDEEEA9-12E4-2""#).is_ok());
    }

    #[test]
    fn istag_rejects_unterminated_quote() {
        assert!(validate_istag(r#""ABC"#).is_err());
    }

    #[test]
    fn istag_quoted_too_long_rejected() {
        let v = format!(r#""{}""#, "A".repeat(33));
        assert!(validate_istag(&v).is_err());
    }

    #[test]
    fn istag_quoted_with_bad_char_rejected() {
        assert!(validate_istag(r#""ABC_DEF""#).is_err());
    }

    #[test]
    fn to_raw_autogenerates_encapsulated_for_404_without_body() {
        let resp = Response::new(StatusCode::NotFound404, "Not Found");
        let raw = resp.to_raw().expect("serialize 404");
        let s = String::from_utf8(raw).unwrap();
        assert!(s.contains("Encapsulated: null-body=0"));
        assert!(!s.to_lowercase().contains("istag:"), "no ISTag on non-2xx");
    }

    #[test]
    fn to_raw_autogenerates_opt_body_for_non_http_body_on_error() {
        let resp =
            Response::new(StatusCode::InternalServerError500, "Internal").with_body_string("oops");
        let raw = resp.to_raw().expect("serialize 500 with body");
        let s = String::from_utf8(raw).unwrap();
        assert!(s.contains("Encapsulated: opt-body=0"));
    }
}

#[cfg(test)]
mod rfc_tests {
    //! RFC 3507 conformance tests for ICAP **responses**.
    //!
    //! These tests assert behavior that follows the spec explicitly:
    //! - Status line & version (`ICAP/1.0` only), multi-word reason phrase
    //! - ISTag (RFC 3507 §4.7): required for 2xx; ≤32 bytes; charset [A-Za-z0-9.-]
    //! - `Encapsulated` header constraints
    //! - 204 semantics (`null-body=0`, no body)
    //! - Basic status codes recognition
    //! - Case-insensitive headers
    //! - Framing (CRLFCRLF)
    //! - Sanity case for 200 with `res-hdr` skeleton

    use super::*;
    use http::HeaderValue;

    fn icap_bytes(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    #[test]
    fn version_must_be_icap_1_0() {
        let raw = icap_bytes(
            "ICAP/2.0 200 OK\r\n\
             ISTag: x\r\n\
             Encapsulated: null-body=0\r\n\
             \r\n",
        );
        let err = parse_icap_response(&raw).unwrap_err();
        assert!(
            matches!(err, Error::InvalidVersion(ref v) if v == "ICAP/2.0"),
            "expected InvalidVersion(\"ICAP/2.0\"), got: {err:?}"
        );
    }

    #[test]
    fn supports_multiword_reason_phrase() {
        let raw = icap_bytes(
            "ICAP/1.0 405 Method Not Allowed\r\n\
             ISTag: x\r\n\
             Encapsulated: null-body=0\r\n\
             \r\n",
        );
        let r = parse_icap_response(&raw).expect("parse ok");
        assert_eq!(r.status_code, StatusCode::MethodNotAllowed405);
        assert_eq!(r.status_text, "Method Not Allowed");
    }

    // --- ISTag (RFC 3507 §4.7) ---

    #[test]
    fn istag_required_for_2xx() {
        let raw = b"ICAP/1.0 200 OK\r\nEncapsulated: null-body=0\r\n\r\n";
        let err = parse_icap_response(raw).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("istag"));
    }

    #[test]
    fn istag_may_be_absent_in_404() {
        let raw = b"ICAP/1.0 404 Not Found\r\n\r\n";
        let r = parse_icap_response(raw).expect("lenient for non-2xx");
        assert_eq!(r.status_code, StatusCode::NotFound404);
        assert!(r.get_header("ISTag").is_none());
    }

    #[test]
    fn istag_must_not_exceed_32_bytes() {
        let too_long = "A".repeat(33);
        let raw = format!(
            "ICAP/1.0 200 OK\r\n\
             ISTag: {}\r\n\
             Encapsulated: null-body=0\r\n\
             \r\n",
            too_long
        );
        let err = parse_icap_response(raw.as_bytes()).unwrap_err();
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("istag") || msg.contains("32"),
            "expected ISTag length error; got: {msg}"
        );
    }

    #[test]
    fn istag_at_most_32_bytes_is_ok() {
        let valid = "A".repeat(32);
        let raw = format!(
            "ICAP/1.0 200 OK\r\n\
             ISTag: {}\r\n\
             Encapsulated: null-body=0\r\n\
             \r\n",
            valid
        );
        let resp = parse_icap_response(raw.as_bytes()).expect("parse ok");
        let hdr = resp.get_header("ISTag").unwrap();
        assert_eq!(hdr, &HeaderValue::from_str(&valid).unwrap());
    }

    #[test]
    fn istag_allows_dashes_and_dots() {
        let valid = "helloo.1755855904-1755855904181"; // 31 chars
        let raw = format!(
            "ICAP/1.0 200 OK\r\n\
             ISTag: {}\r\n\
             Encapsulated: null-body=0\r\n\
             \r\n",
            valid
        );
        let resp = parse_icap_response(raw.as_bytes()).expect("parse ok");
        let hdr = resp.get_header("ISTag").unwrap();
        assert_eq!(hdr, &HeaderValue::from_str(valid).unwrap());
    }

    #[test]
    fn istag_invalid_characters_are_rejected() {
        for bad in ["TAG 1", "TAG_1", "TAG#1", "TAG@1"] {
            let raw = format!(
                "ICAP/1.0 200 OK\r\n\
                 ISTag: {}\r\n\
                 Encapsulated: null-body=0\r\n\
                 \r\n",
                bad
            );
            let err = parse_icap_response(raw.as_bytes()).unwrap_err();
            let msg = err.to_string().to_lowercase();
            assert!(
                msg.contains("istag") && (msg.contains("invalid") || msg.contains("character")),
                "expected ISTag invalid-char error; got: {msg}"
            );
        }
    }

    // --- Encapsulated ---

    #[test]
    fn encapsulated_required_for_200() {
        let raw = icap_bytes(
            "ICAP/1.0 200 OK\r\n\
             ISTag: x\r\n\
             \r\n",
        );
        let err = parse_icap_response(&raw).unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("encapsulated"),
            "expected missing Encapsulated; got {err}"
        );
    }

    #[test]
    fn no_duplicate_encapsulated_headers() {
        let raw = icap_bytes(
            "ICAP/1.0 200 OK\r\n\
             ISTag: x\r\n\
             Encapsulated: res-hdr=0, res-body=100\r\n\
             Encapsulated: req-hdr=0\r\n\
             \r\n",
        );
        let err = parse_icap_response(&raw).unwrap_err();
        let m = err.to_string().to_lowercase();
        assert!(
            m.contains("duplicate") || m.contains("encapsulated"),
            "expected duplicate Encapsulated error; got: {m}"
        );
    }

    #[test]
    fn invalid_encapsulated_tokens_are_rejected() {
        let raw = icap_bytes(
            "ICAP/1.0 200 OK\r\n\
             ISTag: x\r\n\
             Encapsulated: totally-wrong=abc, res-body=-5\r\n\
             \r\n",
        );
        let err = parse_icap_response(&raw).unwrap_err();
        let m = err.to_string().to_lowercase();
        assert!(
            m.contains("encapsulated") || m.contains("invalid") || m.contains("parse"),
            "expected invalid Encapsulated; got: {m}"
        );
    }

    #[test]
    fn encapsulated_offsets_must_be_monotonic_and_in_range() {
        let raw = icap_bytes(
            "ICAP/1.0 200 OK\r\n\
             ISTag: x\r\n\
             Encapsulated: res-hdr=50, res-body=10\r\n\
             \r\n\
             HTTP/1.1 200 OK\r\n\
             Content-Length: 0\r\n\
             \r\n",
        );
        let err = parse_icap_response(&raw).unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("offset"),
            "expected offsets validation error; got: {err}"
        );
    }

    // --- 204 semantics ---

    #[test]
    fn valid_minimal_204() {
        let raw = icap_bytes(
            "ICAP/1.0 204 No Content\r\n\
             ISTag: x\r\n\
             Encapsulated: null-body=0\r\n\
             \r\n",
        );
        let r = parse_icap_response(&raw).expect("parse ok");
        assert_eq!(r.status_code, StatusCode::NoContent204);
        assert_eq!(
            r.get_header("Encapsulated").unwrap(),
            &HeaderValue::from_static("null-body=0")
        );
        assert!(r.body.is_empty(), "204 must not carry a body");
    }

    #[test]
    fn rfc_204_must_have_null_body_header() {
        let raw = icap_bytes(
            "ICAP/1.0 204 No Content\r\n\
             ISTag: x\r\n\
             \r\n",
        );
        let err = parse_icap_response(&raw).unwrap_err();
        let m = err.to_string().to_lowercase();
        assert!(
            m.contains("encapsulated") || m.contains("null-body"),
            "expected missing null-body=0; got: {m}"
        );
    }

    #[test]
    fn rfc_204_must_not_have_body_bytes() {
        let raw = icap_bytes(
            "ICAP/1.0 204 No Content\r\n\
             ISTag: x\r\n\
             Encapsulated: null-body=0\r\n\
             \r\n\
             ILLEGAL_BODY",
        );
        let err = parse_icap_response(&raw).unwrap_err();
        let m = err.to_string().to_lowercase();
        assert!(
            m.contains("204")
                && (m.contains("no body")
                    || m.contains("null-body")
                    || m.contains("must not carry a body")),
            "expected 204-with-body error; got: {m}"
        );
    }

    // --- Basic statuses ---

    #[test]
    fn supports_100_continue() {
        let raw = icap_bytes(
            "ICAP/1.0 100 Continue\r\n\
             ISTag: x\r\n\
             Encapsulated: null-body=0\r\n\
             \r\n",
        );
        let r = parse_icap_response(&raw).expect("parse ok");
        assert_eq!(r.status_code, StatusCode::Continue100);
    }

    #[test]
    fn supports_404_not_found() {
        let raw = icap_bytes(
            "ICAP/1.0 404 ICAP Service not found\r\n\
             \r\n",
        );
        let r = parse_icap_response(&raw).expect("parse ok");
        assert_eq!(r.status_code, StatusCode::NotFound404);
        assert!(r.status_text.to_lowercase().contains("not"));
    }

    // --- Header case-insensitivity ---

    #[test]
    fn header_lookup_is_case_insensitive() {
        let raw = icap_bytes(
            "ICAP/1.0 200 OK\r\n\
             isTag: X\r\n\
             eNcaPsulated: null-body=0\r\n\
             \r\n",
        );
        let r = parse_icap_response(&raw).expect("parse ok");
        assert_eq!(
            r.get_header("ISTag").unwrap(),
            &HeaderValue::from_static("X")
        );
        assert_eq!(
            r.get_header("Encapsulated").unwrap(),
            &HeaderValue::from_static("null-body=0")
        );
    }

    // --- Framing & sanity ---

    #[test]
    fn error_on_incomplete_headers() {
        let raw = icap_bytes("ICAP/1.0 200 OK\r\nISTag: x\r\n");
        let err = parse_icap_response(&raw).unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("headers"),
            "expected incomplete headers error; got {err}"
        );
    }

    #[test]
    fn allows_empty_reason_phrase() {
        let raw = icap_bytes(
            "ICAP/1.0 200 \r\n\
             ISTag: x\r\n\
             Encapsulated: null-body=0\r\n\
             \r\n",
        );
        let r = parse_icap_response(&raw).expect("parse ok");
        assert_eq!(r.status_code, StatusCode::Ok200);
        assert_eq!(r.status_text, "");
    }

    #[test]
    fn ok_minimal_200_with_res_hdr_skeleton() {
        let raw = icap_bytes(
            "ICAP/1.0 200 OK\r\n\
             ISTag: x\r\n\
             Encapsulated: res-hdr=0\r\n\
             \r\n\
             HTTP/1.1 200 OK\r\n\
             Content-Length: 0\r\n\
             \r\n",
        );
        let r = parse_icap_response(&raw).expect("parse ok");
        assert_eq!(r.status_code, StatusCode::Ok200);
    }
}
