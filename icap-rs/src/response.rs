//! ICAP response types and helpers.
//!
//! This module defines:
//! - [`StatusCode`]: a re-export of [`http::StatusCode`]. ICAP uses the same
//!   numeric status codes as HTTP. When emitting an ICAP status line, use
//!   [`StatusCode::as_str`] to print the **numeric** code (e.g., `"200"`),
//!   not the `Display` impl (which prints `"200 OK"`).
//! - [`Response`]: representation of an ICAP response, including headers and an optional body.
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
//! use icap_rs::{Response, StatusCode};
//!
//! // Construct a minimal 204 No Content response.
//! // Note: 204 MUST NOT have a body and MUST carry `Encapsulated: null-body=0`.
//! let resp = Response::no_content_with_istag("policy-123").unwrap();
//!
//! assert!(resp.is_success());
//! assert_eq!(resp.status_code, StatusCode::NO_CONTENT);
//! ```

use crate::ICAP_VERSION;
use crate::error::{Error, IcapResult};
use crate::parser::icap::{Encapsulated, find_double_crlf, parse_encapsulated_value};
use crate::parser::wire::parse_one_chunk;
use crate::parser::{serialize_http_request, serialize_http_response};
use http::{HeaderMap, HeaderName, HeaderValue};
use memchr::memchr;
use std::fmt;
use std::str::FromStr;
use tracing::{trace, warn};

/// ICAP status codes.
///
/// ICAP reuses HTTP numeric status codes (RFC 3507), so this crate exposes
/// `http::StatusCode` under `icap_rs::StatusCode`.
///
/// ICAP-specific note: do **not** use `Display` of `StatusCode` when writing
/// the ICAP status line. Format it as:
/// `ICAP/1.0 <code> <reason>`
/// and obtain the numeric part via `as_str()` or `as_u16()`.
///
/// ICAP-specific behavior (e.g., `ISTag` requirements for 2xx, `Encapsulated`
/// rules for 204/2xx) is implemented elsewhere in this crate.
///
/// # Examples
/// ```
/// use icap_rs::StatusCode;
/// assert!(StatusCode::OK.is_success());
/// assert_eq!(StatusCode::NO_CONTENT.as_str(), "204");
/// ```
pub type StatusCode = http::StatusCode;

/// Representation of an ICAP response.
///
/// Contains version string, status code and text, ICAP headers,
/// and an optional body (such as encapsulated HTTP or chunked data).
#[derive(Debug, Clone)]
#[must_use]
pub struct Response {
    /// ICAP protocol version (usually `"ICAP/1.0"`).
    pub version: String,
    /// Response status code.
    pub status_code: StatusCode,
    /// Human-readable status text (e.g. `"OK"`, `"No Content"`).
    pub status_text: String,
    /// ICAP headers.
    pub(crate) headers: HeaderMap,
    /// Offset from the original HTTP body to resume after a 206 partial body.
    pub(crate) use_original_body: Option<usize>,
    /// Optional body (arbitrary payload, chunked HTTP, etc.).
    pub body: Vec<u8>,
}

#[inline]
fn ensure_owned_response<'a>(
    owned: &'a mut Option<Response>,
    original: &Response,
) -> &'a mut Response {
    if owned.is_none() {
        *owned = Some(original.clone());
    }
    owned.as_mut().expect("owned response")
}

impl Response {
    /// Create a new ICAP response with the given status code and status text.
    pub fn new(status_code: StatusCode, status_text: &str) -> Self {
        Self {
            version: ICAP_VERSION.to_string(),
            status_code,
            status_text: status_text.to_string(),
            headers: HeaderMap::new(),
            use_original_body: None,
            body: Vec::new(),
        }
    }

    /// Shortcut for a `200 OK` response.
    ///
    /// Successful ICAP responses require a valid `ISTag` before serialization.
    /// Use [`Response::ok_with_istag`] when the tag is known at construction time.
    pub fn ok() -> Self {
        Self::new(StatusCode::OK, "OK")
    }

    /// Shortcut for a `200 OK` response with a validated `ISTag`.
    pub fn ok_with_istag(istag: &str) -> IcapResult<Self> {
        Self::ok().try_set_istag(istag)
    }

    /// Shortcut for a `204 No Content` response.
    pub fn no_content() -> Self {
        Self::new(StatusCode::NO_CONTENT, "No Content")
    }

    /// Shortcut for a `204 No Content` response with a validated `ISTag`.
    ///
    /// This is the common "no modification needed" response for clients that
    /// advertised `Allow: 204` or used Preview.
    pub fn no_content_with_istag(istag: &str) -> IcapResult<Self> {
        Self::no_content().try_set_istag(istag)
    }

    /// Shortcut for a `206 Partial Content` response.
    ///
    /// Pair this with
    /// [`Response::with_http_request_head_and_original_body`] or
    /// [`Response::with_http_response_head_and_original_body`] to emit the
    /// RFC 3507 `use-original-body` marker.
    pub fn partial_content() -> Self {
        Self::new(StatusCode::PARTIAL_CONTENT, "Partial Content")
    }

    /// Shortcut for a `206 Partial Content` response with a validated `ISTag`.
    pub fn partial_content_with_istag(istag: &str) -> IcapResult<Self> {
        Self::partial_content().try_set_istag(istag)
    }

    /// Shortcut for a `204 No Content` response with headers.
    pub fn no_content_with_headers(headers: HeaderMap) -> IcapResult<Self> {
        let istag = headers
            .get("ISTag")
            .ok_or(Error::MissingHeader("ISTag"))?
            .to_str()?;
        validate_istag(istag)?;

        Ok(Self {
            version: ICAP_VERSION.to_string(),
            status_code: StatusCode::NO_CONTENT,
            status_text: "No Content".to_string(),
            headers,
            use_original_body: None,
            body: Vec::new(),
        })
    }

    /// Try to add or overwrite a header.
    ///
    /// Setting `ISTag` here is discouraged; prefer [`Response::try_set_istag`].
    pub fn try_add_header(mut self, name: &str, value: &str) -> IcapResult<Self> {
        if name.eq_ignore_ascii_case("ISTag") {
            validate_istag(value)?;
            let val = HeaderValue::from_str(value)?;
            self.headers.insert(HeaderName::from_static("istag"), val);
            return Ok(self);
        }

        let n: HeaderName = name.parse()?;
        let v: HeaderValue = HeaderValue::from_str(value)?;
        self.headers.insert(n, v);
        Ok(self)
    }

    /// Add or overwrite a header.
    /// NOTE: Setting `ISTag` here is discouraged; prefer `try_set_istag()`.
    ///
    /// # Panics
    ///
    /// Panics if `name` or `value` is not a valid HTTP header field. Invalid
    /// `ISTag` values are ignored for compatibility with previous releases; use
    /// [`Response::try_add_header`] or [`Response::try_set_istag`] for fallible
    /// handling.
    pub fn add_header(self, name: &str, value: &str) -> Self {
        if name.eq_ignore_ascii_case("ISTag")
            && let Err(e) = validate_istag(value)
        {
            trace!("ignoring invalid ISTag passed to add_header: {}", e);
            return self;
        }

        self.try_add_header(name, value)
            .expect("invalid response header name or value")
    }

    /// Set `ISTag` header with validation (length ≤32; unquoted must be HTTP token,
    /// quoted-string is accepted per RFC 3507/2616).
    /// Returns `Self` on success; otherwise `Error::InvalidISTag`.
    pub fn try_set_istag(mut self, istag: &str) -> IcapResult<Self> {
        validate_istag(istag)?;
        let name = HeaderName::from_static("istag");
        let val = HeaderValue::from_str(istag)?;
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
    ///
    /// This validates ICAP-specific response invariants before writing:
    /// successful responses require a valid `ISTag`, `204` must use
    /// `Encapsulated: null-body=0`, and embedded HTTP bodies are framed per RFC
    /// 3507 with unchunked HTTP heads and chunked encapsulated entity bodies.
    pub fn to_raw(&self) -> IcapResult<Vec<u8>> {
        let require_istag = self.status_code.is_success();

        if require_istag {
            let istag = self
                .headers
                .get("ISTag")
                .ok_or(Error::MissingHeader("ISTag"))?
                .to_str()?;
            validate_istag(istag)?;
        } else if let Some(v) = self.headers.get("ISTag") {
            let s = v.to_str()?;
            validate_istag(s)?;
        }

        let mut owned: Option<Self> = None;

        match self.status_code {
            StatusCode::NO_CONTENT => {
                if !self.body.is_empty() {
                    return Err(Error::Body("204 must not carry a body".into()));
                }
                match self.headers.get("Encapsulated") {
                    None => {
                        ensure_owned_response(&mut owned, self).headers.insert(
                            HeaderName::from_static("encapsulated"),
                            HeaderValue::from_static("null-body=0"),
                        );
                    }
                    Some(v) if v.as_bytes() != b"null-body=0".as_slice() => {
                        return Err(Error::Header(
                            "204 requires Encapsulated: null-body=0".into(),
                        ));
                    }
                    Some(_) => {}
                }
            }
            StatusCode::OK | StatusCode::PARTIAL_CONTENT => {
                if !self.headers.contains_key("Encapsulated") {
                    if self.body.is_empty() {
                        return Err(Error::MissingHeader(
                            "Encapsulated missing and cannot infer for 2xx with empty body; \
                         set it explicitly or use Response::with_http_response(...)",
                        ));
                    }
                    if looks_like_http_resp(&self.body) {
                        let enc = compute_enc_for_res_body(&self.body)?;
                        let hv = HeaderValue::from_str(&enc)?;
                        ensure_owned_response(&mut owned, self)
                            .headers
                            .insert(HeaderName::from_static("encapsulated"), hv);
                    } else {
                        return Err(Error::Header(
                            "Encapsulated missing and body is not an embedded HTTP/1.x".to_string(),
                        ));
                    }
                }
            }
            _ => {
                if !self.headers.contains_key("Encapsulated") {
                    if self.body.is_empty() {
                        ensure_owned_response(&mut owned, self).headers.insert(
                            HeaderName::from_static("encapsulated"),
                            HeaderValue::from_static("null-body=0"),
                        );
                    } else if looks_like_http_resp(&self.body) {
                        let enc = compute_enc_for_res_body(&self.body)?;
                        let hv = HeaderValue::from_str(&enc)?;
                        ensure_owned_response(&mut owned, self)
                            .headers
                            .insert(HeaderName::from_static("encapsulated"), hv);
                    } else {
                        ensure_owned_response(&mut owned, self).headers.insert(
                            HeaderName::from_static("encapsulated"),
                            HeaderValue::from_static("opt-body=0"),
                        );
                    }
                }
            }
        }

        let resp_ref = owned.as_ref().unwrap_or(self);
        if !resp_ref.body.is_empty()
            && let Some(enc_val) = resp_ref
                .headers
                .get("Encapsulated")
                .and_then(|v| v.to_str().ok())
            && parse_encapsulated_value(enc_val).is_ok_and(|enc| enc.null_body.is_some())
        {
            return Err(Error::Body(
                "Encapsulated: null-body must not carry a body".into(),
            ));
        }
        if let Some(offset) = resp_ref.use_original_body {
            if resp_ref.status_code != StatusCode::PARTIAL_CONTENT {
                return Err(Error::Header(
                    "use-original-body is only valid on 206 Partial Content".into(),
                ));
            }
            let enc_val = resp_ref
                .headers
                .get("Encapsulated")
                .and_then(|v| v.to_str().ok())
                .ok_or(Error::MissingHeader("Encapsulated"))?;
            let enc = parse_encapsulated_value(enc_val)?;
            if enc.req_body.or(enc.res_body).or(enc.opt_body).is_none() {
                return Err(Error::Header(
                    "use-original-body requires an encapsulated body offset".into(),
                ));
            }
            trace!(offset, "serializing 206 use-original-body marker");
        }
        Ok(crate::parser::serialize_icap_response(resp_ref))
    }

    /// Parse an ICAP response from raw bytes.
    ///
    /// When the response contains an embedded HTTP message, `Response::body`
    /// contains the embedded HTTP head followed by the dechunked HTTP entity
    /// body. ICAP chunk-size metadata is not preserved.
    pub fn from_raw(raw: &[u8]) -> IcapResult<Self> {
        parse_icap_response(raw)
    }

    /// Get a header value by name.
    pub fn get_header(&self, name: &str) -> Option<&HeaderValue> {
        self.headers.get(name)
    }

    /// Return a read-only view of all ICAP headers.
    pub const fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Return the `use-original-body` offset from a parsed or constructed 206 response.
    ///
    /// When present, the response carries an ICAP zero-chunk extension telling
    /// the client to append the original HTTP entity body starting at this byte
    /// offset after any partial body bytes included in the 206 response.
    pub const fn use_original_body_offset(&self) -> Option<usize> {
        self.use_original_body
    }

    /// Check whether a header exists.
    pub fn has_header(&self, name: &str) -> bool {
        self.headers.contains_key(name)
    }

    /// Remove a header by name.
    pub fn remove_header(&mut self, name: &str) -> Option<HeaderValue> {
        self.headers.remove(name)
    }

    /// Whether the response indicates success (2XX).
    pub fn is_success(&self) -> bool {
        self.status_code.is_success()
    }

    /// Whether the response indicates a client error (4xx).
    pub fn is_client_error(&self) -> bool {
        self.status_code.is_client_error()
    }

    /// Whether the response indicates a server error (5xx).
    pub fn is_server_error(&self) -> bool {
        self.status_code.is_server_error()
    }

    /// Attach an **embedded HTTP request** (for `REQMOD` flows).
    /// Sets `Encapsulated: req-hdr=0[, req-body=..]`.
    pub fn with_http_request(mut self, http: &http::Request<Vec<u8>>) -> IcapResult<Self> {
        let bytes = serialize_http_request(http);

        let enc = compute_enc_for_req_body(&bytes)?;
        let hv = HeaderValue::from_str(&enc)?;

        self.body = bytes;
        self.use_original_body = None;
        self.headers
            .insert(HeaderName::from_static("encapsulated"), hv);
        Ok(self)
    }

    /// Attach an **embedded HTTP response** (for `RESPMOD` flows).
    /// Sets `Encapsulated: res-hdr=0[, res-body=..]`.
    pub fn with_http_response(mut self, http: &http::Response<Vec<u8>>) -> IcapResult<Self> {
        let bytes = serialize_http_response(http);

        let enc = compute_enc_for_res_body(&bytes)?;
        let hv = HeaderValue::from_str(&enc)?;

        self.body = bytes;
        self.use_original_body = None;
        self.headers
            .insert(HeaderName::from_static("encapsulated"), hv);
        Ok(self)
    }

    /// Attach an embedded HTTP request head and emit a 206 `use-original-body` marker.
    ///
    /// The serialized response will contain the HTTP request head, no adapted
    /// body bytes, and a final ICAP chunk `0; use-original-body=<offset>`.
    pub fn with_http_request_head_and_original_body(
        mut self,
        head: &http::Request<()>,
        offset: usize,
    ) -> IcapResult<Self> {
        let mut builder = http::Request::builder()
            .method(head.method().clone())
            .uri(head.uri().clone())
            .version(head.version());
        if let Some(headers) = builder.headers_mut() {
            headers.extend(head.headers().clone());
        }
        let http = builder
            .body(Vec::new())
            .map_err(|e| Error::Body(format!("build embedded HTTP request head: {e}")))?;
        let bytes = serialize_http_request(&http);
        let hdr_end = find_double_crlf(&bytes)
            .ok_or_else(|| Error::Header("embedded HTTP request missing CRLFCRLF".into()))?;
        self.body = bytes;
        self.use_original_body = Some(offset);
        self.headers.insert(
            HeaderName::from_static("encapsulated"),
            HeaderValue::from_str(&format!("req-hdr=0, req-body={hdr_end}"))?,
        );
        Ok(self)
    }

    /// Attach an embedded HTTP response head and emit a 206 `use-original-body` marker.
    ///
    /// The serialized response will contain the HTTP response head, no adapted
    /// body bytes, and a final ICAP chunk `0; use-original-body=<offset>`.
    pub fn with_http_response_head_and_original_body(
        mut self,
        head: &http::Response<()>,
        offset: usize,
    ) -> IcapResult<Self> {
        let mut builder = http::Response::builder()
            .status(head.status())
            .version(head.version());
        if let Some(headers) = builder.headers_mut() {
            headers.extend(head.headers().clone());
        }
        let http = builder
            .body(Vec::new())
            .map_err(|e| Error::Body(format!("build embedded HTTP response head: {e}")))?;
        let bytes = serialize_http_response(&http);
        let hdr_end = find_double_crlf(&bytes)
            .ok_or_else(|| Error::Header("embedded HTTP response missing CRLFCRLF".into()))?;
        self.body = bytes;
        self.use_original_body = Some(offset);
        self.headers.insert(
            HeaderName::from_static("encapsulated"),
            HeaderValue::from_str(&format!("res-hdr=0, res-body={hdr_end}"))?,
        );
        Ok(self)
    }
}

impl fmt::Display for Response {
    /// Formats the ICAP response for debugging: status line, headers, and body (if present).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{} {} {}",
            self.version,
            self.status_code.as_str(),
            self.status_text
        )?;
        for (name, value) in &self.headers {
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
#[inline]
fn compute_enc_for_res_body(body: &[u8]) -> IcapResult<String> {
    let hdr_end = find_double_crlf(body)
        .ok_or_else(|| Error::Header("embedded HTTP missing CRLFCRLF".into()))?;
    if body.len() > hdr_end {
        Ok(format!("res-hdr=0, res-body={hdr_end}"))
    } else {
        Ok("res-hdr=0".to_string())
    }
}
#[inline]
fn compute_enc_for_req_body(body: &[u8]) -> IcapResult<String> {
    let hdr_end = find_double_crlf(body)
        .ok_or_else(|| Error::Header("embedded HTTP missing CRLFCRLF".into()))?;
    if body.len() > hdr_end {
        Ok(format!("req-hdr=0, req-body={hdr_end}"))
    } else {
        Ok("req-hdr=0".to_string())
    }
}

struct ParsedResponseHead {
    response: Response,
    header_end: usize,
    encapsulated_value: Option<String>,
}

fn parse_response_head_parts(raw: &[u8]) -> IcapResult<ParsedResponseHead> {
    if raw.is_empty() {
        return Err(Error::parse("Empty response"));
    }

    let hdr_end =
        find_double_crlf(raw).ok_or_else(|| Error::parse("ICAP response headers not complete"))?;
    let head = &raw[..hdr_end];
    let head_str = std::str::from_utf8(head)?;
    let mut lines = head_str.split("\r\n");

    let status_line = lines.next().ok_or_else(|| Error::parse("Empty response"))?;
    let parts: Vec<&str> = status_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(Error::parse("Invalid status line format"));
    }

    if parts[0] != ICAP_VERSION {
        return Err(Error::InvalidVersion(parts[0].to_string()));
    }

    let version = parts[0].to_string();
    let status_code = if let Ok(code) = StatusCode::from_str(parts[1]) {
        code
    } else {
        let code_num = parts[1]
            .parse::<u16>()
            .map_err(|_| Error::InvalidStatusCode("Invalid status code".into()))?;
        StatusCode::try_from(code_num).map_err(|_| {
            Error::InvalidStatusCode(format!("Unknown ICAP status code: {code_num}"))
        })?
    };

    let status_text = if parts.len() > 2 {
        parts[2..].join(" ")
    } else {
        String::new()
    };

    trace!(version = %version, code = %status_code.as_str(), text = %status_text, "parsed status line");

    let mut headers = HeaderMap::new();
    let mut seen_encapsulated = false;
    let mut encapsulated_value = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(colon) = memchr(b':', line.as_bytes()) {
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

    let require_istag = status_code.is_success();

    if !headers.contains_key("ISTag") {
        if require_istag {
            return Err(Error::MissingHeader("ISTag"));
        }
        warn!(code = %status_code, "response without ISTag on non-2xx (accepted for compatibility)");
    }

    Ok(ParsedResponseHead {
        response: Response {
            version,
            status_code,
            status_text,
            headers,
            use_original_body: None,
            body: Vec::new(),
        },
        header_end: hdr_end,
        encapsulated_value,
    })
}

pub(crate) fn parse_icap_response(raw: &[u8]) -> IcapResult<Response> {
    trace!(len = raw.len(), "parse_icap_response");
    let ParsedResponseHead {
        mut response,
        header_end,
        encapsulated_value,
    } = parse_response_head_parts(raw)?;

    let mut body = raw[header_end..].to_vec();
    trace!(body_len = body.len(), "parsed body");
    if response.status_code.is_success() {
        let enc_val = encapsulated_value
            .as_deref()
            .or_else(|| {
                response
                    .headers
                    .get("Encapsulated")
                    .and_then(|v| v.to_str().ok())
            })
            .ok_or(Error::MissingHeader("Encapsulated"))?;

        match response.status_code {
            StatusCode::NO_CONTENT => {
                if !enc_val.trim().eq_ignore_ascii_case("null-body=0") {
                    return Err(Error::Header(
                        "204 requires Encapsulated: null-body=0".into(),
                    ));
                }
                if !body.is_empty() {
                    return Err(Error::Body("204 must not carry a body".into()));
                }
            }
            StatusCode::OK | StatusCode::PARTIAL_CONTENT => {
                let enc = parse_encapsulated_value(enc_val)?;
                response.use_original_body = dechunk_response_body_if_needed(&enc, &mut body)?;
                if response.use_original_body.is_some()
                    && response.status_code != StatusCode::PARTIAL_CONTENT
                {
                    return Err(Error::Header(
                        "use-original-body is only valid on 206 Partial Content".into(),
                    ));
                }
                validate_encapsulated_offsets(&enc, body.len())?;
            }
            _ => {}
        }
    }

    response.body = body;
    Ok(response)
}

pub(crate) fn parse_icap_response_head(raw: &[u8]) -> IcapResult<Response> {
    trace!(len = raw.len(), "parse_icap_response_head");
    Ok(parse_response_head_parts(raw)?.response)
}

fn validate_encapsulated_offsets(enc: &Encapsulated, enc_len: usize) -> IcapResult<()> {
    for off in encapsulated_offsets(enc) {
        if off > enc_len {
            return Err(Error::Header(format!(
                "Encapsulated offset {off} out of range (len={enc_len})"
            )));
        }
    }
    Ok(())
}

fn dechunk_response_body_if_needed(
    enc: &Encapsulated,
    body: &mut Vec<u8>,
) -> IcapResult<Option<usize>> {
    let Some(body_start) = enc.req_body.or(enc.res_body).or(enc.opt_body) else {
        return Ok(None);
    };

    if body_start > body.len() {
        return Err(Error::Header(format!(
            "Encapsulated body offset {body_start} out of range (len={})",
            body.len()
        )));
    }
    if parse_one_chunk(body, body_start).is_none() {
        return Err(Error::Body(
            "missing ICAP chunked entity body at Encapsulated body offset".into(),
        ));
    }

    let mut chunked = &body[body_start..];
    let (decoded, use_original_body) = dechunk_icap_entity_with_use_original_body(&mut chunked)
        .map_err(|e| Error::Body(format!("dechunk ICAP entity: {e}")))?;
    body.splice(body_start.., decoded);
    Ok(use_original_body)
}

fn dechunk_icap_entity_with_use_original_body(
    data: &mut &[u8],
) -> Result<(Vec<u8>, Option<usize>), String> {
    let mut out = Vec::with_capacity((*data).len());
    let mut d = *data;

    loop {
        let crlf_pos = memchr::memmem::find(d, b"\r\n").ok_or("chunk size line without CRLF")?;
        let (size_line, rest) = d.split_at(crlf_pos);
        d = &rest[2..];

        let size_hex = memchr(b';', size_line).map_or(size_line, |i| &size_line[..i]);
        let size_str = core::str::from_utf8(size_hex).map_err(|_| "chunk size not utf8")?;
        let size = usize::from_str_radix(size_str.trim(), 16).map_err(|_| "chunk size not hex")?;

        if size == 0 {
            let use_original_body = parse_use_original_body_extension(size_line)?;
            if d.starts_with(b"\r\n") {
                d = &d[2..];
            } else {
                return Err("missing final CRLF after zero chunk".into());
            }
            *data = d;
            return Ok((out, use_original_body));
        }

        if d.len() < size + 2 {
            return Err("incomplete chunk data".into());
        }
        out.extend_from_slice(&d[..size]);
        d = &d[size..];
        if !d.starts_with(b"\r\n") {
            return Err("missing CRLF after chunk".into());
        }
        d = &d[2..];
    }
}

fn parse_use_original_body_extension(size_line: &[u8]) -> Result<Option<usize>, String> {
    let Some(ext_start) = memchr(b';', size_line) else {
        return Ok(None);
    };
    let ext_text = core::str::from_utf8(&size_line[ext_start + 1..])
        .map_err(|_| "chunk extension not utf8")?;
    for ext in ext_text.split(';') {
        let Some((name, value)) = ext.trim().split_once('=') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("use-original-body") {
            return value
                .trim()
                .parse::<usize>()
                .map(Some)
                .map_err(|_| "use-original-body offset not decimal".to_string());
        }
    }
    Ok(None)
}

fn encapsulated_offsets(enc: &Encapsulated) -> impl Iterator<Item = usize> {
    [
        enc.req_hdr,
        enc.res_hdr,
        enc.req_body,
        enc.res_body,
        enc.opt_body,
        enc.null_body,
    ]
    .into_iter()
    .flatten()
}

#[inline]
fn validate_istag(raw: &str) -> IcapResult<()> {
    let s = raw.trim();

    let mut val = String::new();
    let quoted = s.starts_with('"');
    if quoted {
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
    if quoted {
        return Ok(());
    }

    if !val.chars().all(is_http_token_char) {
        return Err(Error::InvalidISTag(format!(
            "invalid unquoted ISTag: {raw} (use quoted-string to allow extra symbols)"
        )));
    }
    Ok(())
}

#[inline]
fn is_http_token_char(c: char) -> bool {
    // Accept '/' and '=' for compatibility with c-icap, which can send
    // unquoted base64-like ISTag values.
    c.is_ascii()
        && !c.is_control()
        && !matches!(
            c,
            '(' | ')'
                | '<'
                | '>'
                | '@'
                | ','
                | ';'
                | ':'
                | '\\'
                | '"'
                | '['
                | ']'
                | '?'
                | '{'
                | '}'
                | ' '
                | '\t'
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[inline]
    fn icap_bytes(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    #[test]
    fn response_add_get_remove_header() {
        let mut resp = Response::new(StatusCode::OK, "OK").add_header("Service", "Test");
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
    fn success_shortcuts_set_status_and_istag() {
        let ok = Response::ok_with_istag("ok-1").expect("valid ISTag");
        assert_eq!(ok.status_code, StatusCode::OK);
        assert_eq!(ok.status_text, "OK");
        assert_eq!(
            ok.get_header("ISTag").unwrap(),
            &HeaderValue::from_static("ok-1")
        );

        let no_content = Response::no_content_with_istag("no-change-1").expect("valid ISTag");
        assert_eq!(no_content.status_code, StatusCode::NO_CONTENT);
        assert_eq!(no_content.status_text, "No Content");

        let partial = Response::partial_content_with_istag("partial-1").expect("valid ISTag");
        assert_eq!(partial.status_code, StatusCode::PARTIAL_CONTENT);
        assert_eq!(partial.status_text, "Partial Content");
    }

    #[test]
    fn success_shortcuts_validate_istag() {
        let err = Response::ok_with_istag("BAD TAG").expect_err("shortcut must validate ISTag");
        assert!(matches!(err, Error::InvalidISTag(_)));
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
    fn add_header_istag_rejects_invalid_but_does_not_panic() {
        let resp = Response::new(StatusCode::OK, "OK").add_header("ISTag", "BAD TAG WITH SPACE");
        assert!(resp.get_header("ISTag").is_none());
    }

    #[test]
    fn try_add_header_rejects_invalid_header_input() {
        let err = Response::new(StatusCode::OK, "OK")
            .try_add_header("Bad Header", "value")
            .expect_err("invalid header name should be rejected");

        assert!(matches!(err, Error::Header(_)));
    }

    #[test]
    fn try_add_header_rejects_invalid_istag() {
        let err = Response::new(StatusCode::OK, "OK")
            .try_add_header("ISTag", "BAD TAG WITH SPACE")
            .expect_err("invalid ISTag should be rejected");

        assert!(matches!(err, Error::InvalidISTag(_)));
    }

    #[test]
    fn add_header_istag_accepts_valid_value() {
        let resp = Response::new(StatusCode::OK, "OK").add_header("ISTag", "ok-Tag.123");
        assert_eq!(
            resp.get_header("ISTag").unwrap(),
            &HeaderValue::from_static("ok-Tag.123")
        );
    }

    #[test]
    fn to_raw_errors_if_istag_missing() {
        let resp = Response::new(StatusCode::OK, "OK").add_header("Service", "X");
        let err = resp.to_raw().unwrap_err();
        assert!(matches!(err, Error::MissingHeader(h) if h == "ISTag"));
    }

    #[test]
    fn to_raw_ok_when_istag_is_valid() {
        let resp = Response::new(StatusCode::OK, "OK")
            .try_set_istag("ok-Tag.123")
            .unwrap()
            .add_header("Encapsulated", "res-hdr=0")
            .with_body_string("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let _bytes = resp
            .to_raw()
            .expect("to_raw should succeed with valid ISTag");
    }

    // -------- serialization rules for auto Encapsulated --------

    #[test]
    fn to_raw_autogenerates_encapsulated_for_404_without_body() {
        let resp = Response::new(StatusCode::NOT_FOUND, "Not Found");
        let raw = resp.to_raw().expect("serialize 404");
        let s = String::from_utf8(raw).unwrap();
        assert!(s.contains("Encapsulated: null-body=0"));
        assert!(
            !s.to_lowercase().contains("istag:"),
            "no ISTag required on non-2xx"
        );
    }

    #[test]
    fn to_raw_autogenerates_opt_body_for_non_http_body_on_error() {
        let resp =
            Response::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal").with_body_string("oops");
        let raw = resp.to_raw().expect("serialize 500 with body");
        let s = String::from_utf8(raw).unwrap();
        assert!(s.contains("Encapsulated: opt-body=0"));
    }

    #[test]
    fn status_line_has_single_reason() {
        let bytes = Response::new(http::StatusCode::OK, "OK")
            .try_set_istag("x")
            .unwrap()
            .add_header("Encapsulated", "null-body=0")
            .to_raw()
            .unwrap();

        let line = std::str::from_utf8(&bytes).unwrap().lines().next().unwrap();
        assert_eq!(line, "ICAP/1.0 200 OK");
    }

    #[test]
    fn to_raw_chunks_only_embedded_http_entity_body() {
        let http = http::Response::builder()
            .status(http::StatusCode::OK)
            .version(http::Version::HTTP_11)
            .header("Content-Length", "5")
            .body(b"hello".to_vec())
            .unwrap();

        let raw = Response::new(StatusCode::OK, "OK")
            .try_set_istag("x")
            .unwrap()
            .with_http_response(&http)
            .unwrap()
            .to_raw()
            .unwrap();

        let icap_header_end = find_double_crlf(&raw).expect("ICAP header end");
        assert_eq!(&raw[icap_header_end..icap_header_end + 5], b"HTTP/");

        let text = String::from_utf8_lossy(&raw);
        assert!(text.contains("Encapsulated: res-hdr=0, res-body="));
        assert!(text.contains("\r\n5\r\nhello\r\n0\r\n\r\n"));
    }

    #[test]
    fn parse_rfc_wire_dechunks_embedded_http_entity_body() {
        let raw = b"ICAP/1.0 200 OK\r\n\
                    ISTag: x\r\n\
                    Encapsulated: res-hdr=0, res-body=38\r\n\
                    \r\n\
                    HTTP/1.1 200 OK\r\n\
                    Content-Length: 5\r\n\
                    \r\n\
                    5\r\n\
                    hello\r\n\
                    0\r\n\
                    \r\n";

        let parsed = parse_icap_response(raw).expect("parse RFC wire response");
        assert_eq!(
            parsed.body,
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        );
    }

    #[test]
    fn to_raw_206_serializes_use_original_body_zero_chunk_extension() {
        let http = http::Response::builder()
            .status(http::StatusCode::OK)
            .version(http::Version::HTTP_11)
            .header("Content-Length", "5")
            .body(())
            .unwrap();

        let raw = Response::new(StatusCode::PARTIAL_CONTENT, "Partial Content")
            .try_set_istag("x")
            .unwrap()
            .with_http_response_head_and_original_body(&http, 0)
            .unwrap()
            .to_raw()
            .unwrap();
        let text = String::from_utf8(raw).unwrap();

        assert!(text.starts_with("ICAP/1.0 206 Partial Content\r\n"));
        assert!(text.contains("Encapsulated: res-hdr=0, res-body="));
        assert!(text.ends_with("\r\n0; use-original-body=0\r\n\r\n"));
    }

    #[test]
    fn parse_206_extracts_use_original_body_offset() {
        let raw = b"ICAP/1.0 206 Partial Content\r\n\
                    ISTag: x\r\n\
                    Encapsulated: res-hdr=0, res-body=38\r\n\
                    \r\n\
                    HTTP/1.1 200 OK\r\n\
                    Content-Length: 5\r\n\
                    \r\n\
                    0; use-original-body=0\r\n\
                    \r\n";

        let parsed = parse_icap_response(raw).expect("parse 206 partial content");

        assert_eq!(parsed.status_code, StatusCode::PARTIAL_CONTENT);
        assert_eq!(parsed.use_original_body_offset(), Some(0));
        assert_eq!(parsed.body, b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n");
    }

    #[test]
    fn parse_rejects_use_original_body_on_200() {
        let raw = b"ICAP/1.0 200 OK\r\n\
                    ISTag: x\r\n\
                    Encapsulated: res-hdr=0, res-body=38\r\n\
                    \r\n\
                    HTTP/1.1 200 OK\r\n\
                    Content-Length: 5\r\n\
                    \r\n\
                    0; use-original-body=0\r\n\
                    \r\n";

        let err = parse_icap_response(raw).expect_err("use-original-body requires 206");

        assert!(err.to_string().contains("206 Partial Content"));
    }

    #[test]
    fn parse_rejects_legacy_unchunked_entity_body_after_body_offset() {
        let raw = b"ICAP/1.0 200 OK\r\n\
                    ISTag: x\r\n\
                    Encapsulated: res-hdr=0, res-body=38\r\n\
                    \r\n\
                    HTTP/1.1 200 OK\r\n\
                    Content-Length: 5\r\n\
                    \r\n\
                    hello";

        let err = parse_icap_response(raw).expect_err("legacy unchunked body must be rejected");
        assert!(
            err.to_string().to_lowercase().contains("chunked"),
            "expected chunked framing error, got: {err}"
        );
    }
}

#[cfg(test)]
mod response_wire_parser_tests {
    //! Low-level response parser regressions for private helpers.
    //! Release-facing RFC coverage lives in `tests/rfc3507.rs`.

    use super::*;
    use http::HeaderValue;
    use rstest::rstest;

    #[inline]
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
        assert_eq!(r.status_code, StatusCode::METHOD_NOT_ALLOWED);
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
        assert_eq!(r.status_code, StatusCode::NOT_FOUND);
        assert!(r.get_header("ISTag").is_none());
    }

    #[rstest]
    #[case("ok-Tag.123".to_string(), true)] // valid plain token
    #[case("helloo.1755855904-1755855904181".to_string(), true)] // 31 chars; '.' and '-' allowed
    #[case("x".to_string(), true)] // minimal valid
    #[case("A".repeat(32), true)] // exactly 32 chars
    #[case(r#""5BDEEEA9-12E4-2""#.to_string(), true)] // valid quoted form
    #[case(r#""ABC"#.to_string(), false)] // unterminated quote
    #[case(format!(r#""{}""#, "A".repeat(33)), false)] // >32 chars in quotes
    #[case(r#""ABC_DEF""#.to_string(), true)] // quoted-string allows visible ASCII
    #[case(r#""QUJDREUrLw==""#.to_string(), true)] // quoted base64 (+,/)
    #[case("QUJDREUrLw==".to_string(), true)] // c-icap base64 ISTag compatibility
    #[case("TAG 1".to_string(), false)] // space not allowed
    #[case("TAG_1".to_string(), true)] // '_' allowed in HTTP token
    #[case("TAG+1".to_string(), true)] // '+' allowed in HTTP token
    #[case("TAG/1".to_string(), true)] // c-icap may send base64-like unquoted ISTags
    #[case("TAG#1".to_string(), true)] // '#' allowed in HTTP token
    #[case("TAG@1".to_string(), false)] // '@' not allowed
    fn istag_validate_cases(#[case] value: String, #[case] ok: bool) {
        // 1) direct validator check
        assert_eq!(
            validate_istag(&value).is_ok(),
            ok,
            "validate_istag failed for value={value:?}"
        );

        // 2) integration with ICAP response parser
        let raw = format!(
            "ICAP/1.0 200 OK\r\n\
         ISTag: {value}\r\n\
         Encapsulated: null-body=0\r\n\
         \r\n",
        );

        match (ok, parse_icap_response(raw.as_bytes())) {
            (true, Ok(resp)) => {
                assert_eq!(
                    resp.get_header("ISTag").unwrap(),
                    &HeaderValue::from_str(&value).unwrap(),
                    "parsed ISTag differs for value={value:?}"
                );
            }
            (false, Err(e)) => {
                let msg = e.to_string().to_lowercase();
                assert!(
                    msg.contains("istag"),
                    "expected ISTag-related error, got: {msg}"
                );
            }
            (true, Err(e)) => panic!("expected parse OK for valid ISTag={value:?}, got error: {e}"),
            (false, Ok(_)) => panic!("expected parse error for invalid ISTag={value:?}"),
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
    fn duplicate_encapsulated_parts_are_rejected() {
        let raw = icap_bytes(
            "ICAP/1.0 200 OK\r\n\
             ISTag: x\r\n\
             Encapsulated: res-hdr=0, res-hdr=10\r\n\
             \r\n\
             HTTP/1.1 200 OK\r\n\
             Content-Length: 0\r\n\
             \r\n",
        );
        let err = parse_icap_response(&raw).unwrap_err();
        let m = err.to_string().to_lowercase();
        assert!(
            m.contains("duplicate") && m.contains("encapsulated"),
            "expected duplicate Encapsulated part error; got: {m}"
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
        assert_eq!(r.status_code, StatusCode::NO_CONTENT);
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

    // --- Basic statuses & headers case-insensitive ---

    #[test]
    fn supports_100_continue() {
        let raw = icap_bytes(
            "ICAP/1.0 100 Continue\r\n\
             ISTag: x\r\n\
             Encapsulated: null-body=0\r\n\
             \r\n",
        );
        let r = parse_icap_response(&raw).expect("parse ok");
        assert_eq!(r.status_code, StatusCode::CONTINUE);
    }

    #[test]
    fn supports_404_not_found() {
        let raw = icap_bytes(
            "ICAP/1.0 404 ICAP Service not found\r\n\
             \r\n",
        );
        let r = parse_icap_response(&raw).expect("parse ok");
        assert_eq!(r.status_code, StatusCode::NOT_FOUND);
        assert!(r.status_text.to_lowercase().contains("not"));
    }

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
        assert_eq!(r.status_code, StatusCode::OK);
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
        assert_eq!(r.status_code, StatusCode::OK);
    }
}
