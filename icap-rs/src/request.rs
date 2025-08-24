//! ICAP request types and helpers.
//!
//! This module defines:
//! - [`EmbeddedHttp`]: an enum for embedded HTTP messages (request/response).
//! - [`Request`]: the single, public ICAP request type used by the client.
//!
//! The [`Request`] type is used by `icap_rs::Client` to build and send ICAP
//! messages (`OPTIONS`, `REQMOD`, `RESPMOD`), including Preview negotiation
//! and optional fast-204 (`ieof`) hints. Attach embedded HTTP via
//! [`Request::with_http_request`] / [`Request::with_http_response`].
//!
//! # Example (REQMOD with embedded HTTP request)
//! ```rust
//! use http::Request as HttpRequest;
//! use icap_rs::{Method, Request};
//!
//! let http_req = HttpRequest::builder()
//!     .method("GET")
//!     .uri("http://example.com/")
//!     .header("Host", "example.com")
//!     .body(Vec::new())
//!     .unwrap();
//!
//! let icap_req = Request::reqmod("icap/test")
//!     .allow_204(true)
//!     .preview(4)
//!     .with_http_request(http_req);
//!
//!assert_eq!(icap_req.method, Method::ReqMod);
//! assert!(icap_req.allow_204);
//! assert_eq!(icap_req.preview_size, Some(4));
//! ```

use crate::error::IcapResult;
use crate::parser::{
    find_double_crlf, serialize_http_request, serialize_http_response, split_http_bytes,
};
use http::{
    HeaderMap, HeaderName, HeaderValue, Request as HttpRequest, Response as HttpResponse,
    StatusCode as HttpStatus, Version,
};
use std::fmt;
use tracing::{debug, trace};

/// ICAP protocol methods recognized by the server/router.
///
/// Defined by RFC 3507. In this crate:
/// - `OPTIONS` is answered **automatically** by the server (capabilities discovery);
/// - you register routes only for `REQMOD` and/or `RESPMOD` (see [`ServerBuilder::route`]).
///
/// ### Methods
/// - **REQMOD** — *Request modification*: the ICAP client (usually a proxy)
///   sends an embedded HTTP **request** to be adapted. Typical uses:
///   URL/category filtering, DLP on outbound requests, antivirus before fetching
///   the origin response, header normalization/enrichment.
/// - **RESPMOD** — *Response modification*: the ICAP client sends an embedded
///   HTTP **response** to be adapted. Typical uses: antivirus scanning of
///   downloaded content, content rewriting, compliance filtering, response
///   header/body adjustments.
/// - **OPTIONS** — *Capability discovery*: clients learn which methods and
///   features a service supports. **Handled automatically** by the server; do
///   not register a handler for `OPTIONS`.
///
/// ### Conversions
/// `Method` implements `From<&str>` / `From<String>` so you can pass
/// `"REQMOD"` / `"RESPMOD"` (case-insensitive) to [`ServerBuilder::route`].
/// Passing `"OPTIONS"` or an unknown string will **panic**.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum Method {
    /// Request modification (`REQMOD`).
    ReqMod,
    /// Response modification (`RESPMOD`).
    RespMod,
    /// Capability discovery (`OPTIONS`).
    Options,
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Method::ReqMod => write!(f, "REQMOD"),
            Method::RespMod => write!(f, "RESPMOD"),
            Method::Options => write!(f, "OPTIONS"),
        }
    }
}

impl Method {
    pub fn as_str(&self) -> &'static str {
        match self {
            Method::ReqMod => "REQMOD",
            Method::RespMod => "RESPMOD",
            Method::Options => "OPTIONS",
        }
    }
}

impl From<&str> for Method {
    fn from(s: &str) -> Self {
        match s.trim().to_ascii_uppercase().as_str() {
            "REQMOD" => Method::ReqMod,
            "RESPMOD" => Method::RespMod,
            "OPTIONS" => Method::Options,
            other => panic!("Unknown ICAP method string: {other}"),
        }
    }
}

impl From<String> for Method {
    fn from(s: String) -> Self {
        Method::from(s.as_str())
    }
}

/// Embedded HTTP message inside an ICAP request.
#[derive(Debug, Clone)]
pub enum EmbeddedHttp {
    /// Embedded HTTP request (typical for `REQMOD`).
    Req(HttpRequest<Vec<u8>>),
    /// Embedded HTTP response (typical for `RESPMOD`).
    Resp(HttpResponse<Vec<u8>>),
}

pub(crate) fn serialize_embedded_http(e: &EmbeddedHttp) -> (Vec<u8>, Option<Vec<u8>>) {
    match e {
        EmbeddedHttp::Req(r) => split_http_bytes(&serialize_http_request(r)),
        EmbeddedHttp::Resp(r) => split_http_bytes(&serialize_http_response(r)),
    }
}

/// Single public ICAP request type used by the client.
///
/// This structure carries ICAP method/service and flags that influence how
/// the request is serialized on the wire (Preview, Allow: 204/206, ieof).
#[derive(Debug, Clone)]
pub struct Request {
    /// ICAP method: `"OPTIONS" | "REQMOD" | "RESPMOD"`.
    pub method: Method,
    /// Service path like `"icap/test"` or `"respmod"`. Leading slash is allowed.
    pub service: String,
    /// ICAP headers (case-insensitive).
    pub icap_headers: HeaderMap,
    /// Optional embedded HTTP message (request/response).
    pub embedded: Option<EmbeddedHttp>,
    /// `Preview: n` (if set).
    pub preview_size: Option<usize>,
    /// Whether `Allow: 204` should be advertised.
    pub allow_204: bool,
    /// Whether `Allow: 206` should be advertised.
    pub allow_206: bool,
    /// If `true` and `preview_size == Some(0)`, send `0; ieof` (fast 204 hint).
    pub preview_ieof: bool,
}

impl Request {
    /// Create a new ICAP request.
    pub fn new<M: Into<Method>>(method: M, service: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            service: service.into(),
            icap_headers: HeaderMap::new(),
            embedded: None,
            preview_size: None,
            allow_204: false,
            allow_206: false,
            preview_ieof: false,
        }
    }

    ///Construct Options Request.
    pub fn options(service: impl Into<String>) -> Self {
        Self::new(Method::Options, service)
    }
    ///Construct ReqMod Request.
    pub fn reqmod(service: impl Into<String>) -> Self {
        Self::new(Method::ReqMod, service)
    }
    ///Construct RespMod Request.
    pub fn respmod(service: impl Into<String>) -> Self {
        Self::new(Method::RespMod, service)
    }

    /// Set/override an ICAP header.
    pub fn icap_header(mut self, name: &str, value: &str) -> Self {
        let n: HeaderName = name.parse().expect("invalid ICAP header name");
        let v: HeaderValue = HeaderValue::from_str(value).expect("invalid ICAP header value");
        self.icap_headers.insert(n, v);
        self
    }

    /// Preview controls.
    pub fn preview(mut self, n: usize) -> Self {
        self.preview_size = Some(n);
        self
    }
    pub fn preview_ieof(mut self, yes: bool) -> Self {
        self.preview_ieof = yes;
        self
    }

    /// Advertise Allow: 204/206.
    pub fn allow_204(mut self, yes: bool) -> Self {
        self.allow_204 = yes;
        self
    }
    pub fn allow_206(mut self, yes: bool) -> Self {
        self.allow_206 = yes;
        self
    }

    /// True for REQMOD/RESPMOD.
    #[inline]
    pub fn is_mod(&self) -> bool {
        matches!(self.method, Method::ReqMod | Method::RespMod)
    }

    /// Attach embedded HTTP.
    pub fn with_http_request(mut self, req: HttpRequest<Vec<u8>>) -> Self {
        self.embedded = Some(EmbeddedHttp::Req(req));
        self
    }
    pub fn with_http_response(mut self, resp: HttpResponse<Vec<u8>>) -> Self {
        self.embedded = Some(EmbeddedHttp::Resp(resp));
        self
    }
}

pub(crate) fn parse_icap_request(data: &[u8]) -> IcapResult<Request> {
    trace!("parse_icap_request: len={}", data.len());
    let hdr_end = find_double_crlf(data).ok_or("ICAP request headers not complete")?;
    let head = &data[..hdr_end];
    let head_str = std::str::from_utf8(head)?;

    // Request line: METHOD <icap-uri> ICAP/1.0
    let mut lines = head_str.split("\r\n");
    let request_line = lines.next().ok_or("Empty request")?;
    let mut parts = request_line.split_whitespace();
    let method_str = parts.next().ok_or("Invalid request line")?;
    let method = Method::from(method_str);
    let icap_uri = parts.next().ok_or("Invalid request line")?.to_string();
    let _version = parts.next().ok_or("Invalid request line")?.to_string();
    debug!("parse_icap_request: {} {}", method, icap_uri);

    // ICAP headers
    let mut icap_headers = HeaderMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(colon) = line.find(':') {
            let name = &line[..colon];
            let value = line[colon + 1..].trim();
            icap_headers.insert(
                HeaderName::from_bytes(name.as_bytes())?,
                HeaderValue::from_str(value)?,
            );
        }
    }

    let service = icap_uri.rsplit('/').next().unwrap_or("").to_string();

    let allow_204 = icap_headers
        .get("Allow")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').any(|p| p.trim() == "204"))
        .unwrap_or(false);

    let allow_206 = icap_headers
        .get("Allow")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').any(|p| p.trim() == "206"))
        .unwrap_or(false);

    let preview_size = icap_headers
        .get("Preview")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<usize>().ok());

    let rest = &data[hdr_end..];
    let embedded = if rest.is_empty() {
        None
    } else if let Some(http_hdr_end) = find_double_crlf(rest) {
        let http_head = &rest[..http_hdr_end];
        let http_head_str = std::str::from_utf8(http_head)?;
        let mut hlines = http_head_str.split("\r\n");
        let start = hlines.next().unwrap_or_default();

        if start.starts_with("HTTP/") {
            // HTTP Response
            let mut p = start.split_whitespace();
            let _ver = p.next().unwrap_or("HTTP/1.1");
            let code = p.next().unwrap_or("200").parse::<u16>().unwrap_or(200);
            debug!("parse_icap_request: embedded HTTP response code={}", code);

            let mut http_headers = HeaderMap::new();
            for line in hlines {
                if line.is_empty() {
                    break;
                }
                if let Some(colon) = line.find(':') {
                    let name = &line[..colon];
                    let value = line[colon + 1..].trim();
                    http_headers.insert(
                        HeaderName::from_bytes(name.as_bytes())?,
                        HeaderValue::from_str(value)?,
                    );
                }
            }
            let body = rest[http_hdr_end..].to_vec();
            let mut builder = HttpResponse::builder()
                .status(HttpStatus::from_u16(code).unwrap_or(HttpStatus::OK))
                .version(Version::HTTP_11);
            {
                let headers_mut = builder
                    .headers_mut()
                    .ok_or("response builder: headers_mut is None")?;
                headers_mut.extend(http_headers);
            }
            let resp = builder
                .body(body)
                .map_err(|e| format!("build http::Response: {e}"))?;
            Some(EmbeddedHttp::Resp(resp))
        } else {
            // HTTP Request
            let mut p = start.split_whitespace();
            let m = p.next().unwrap_or("GET");
            let u = p.next().unwrap_or("/");
            debug!("parse_icap_request: embedded HTTP request {} {}", m, u);

            let mut http_headers = HeaderMap::new();
            for line in hlines {
                if line.is_empty() {
                    break;
                }
                if let Some(colon) = line.find(':') {
                    let name = &line[..colon];
                    let value = line[colon + 1..].trim();
                    http_headers.insert(
                        HeaderName::from_bytes(name.as_bytes())?,
                        HeaderValue::from_str(value)?,
                    );
                }
            }
            let body = rest[http_hdr_end..].to_vec();
            let mut builder = HttpRequest::builder()
                .method(m)
                .uri(u)
                .version(Version::HTTP_11);
            {
                let headers_mut = builder
                    .headers_mut()
                    .ok_or("request builder: headers_mut is None")?;
                headers_mut.extend(http_headers);
            }
            let req = builder
                .body(body)
                .map_err(|e| format!("build http::Request: {e}"))?;
            Some(EmbeddedHttp::Req(req))
        }
    } else {
        None
    };

    Ok(Request {
        method,
        service,
        icap_headers,
        embedded,
        preview_size,
        allow_204,
        allow_206,
        preview_ieof: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{Request as HttpRequest, Response as HttpResponse, StatusCode, Version};

    fn icap_bytes(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    #[test]
    fn builder_creates_basic_requests() {
        let o = Request::options("icap/test");
        assert_eq!(o.method, Method::Options);
        assert_eq!(o.service, "icap/test");
        assert!(!o.is_mod());

        let r = Request::reqmod("svc");
        assert_eq!(r.method, Method::ReqMod);
        assert!(r.is_mod());

        let s = Request::respmod("svc");
        assert_eq!(s.method, Method::RespMod);
        assert!(s.is_mod());
    }

    #[test]
    fn builder_flags_preview_allow() {
        let req = Request::reqmod("icap/test")
            .allow_204(true)
            .allow_206(true)
            .preview(16)
            .preview_ieof(true);

        assert!(req.allow_204);
        assert!(req.allow_206);
        assert_eq!(req.preview_size, Some(16));
        assert!(req.preview_ieof);
    }

    #[test]
    fn builder_sets_and_overrides_headers() {
        let req = Request::options("icap/test")
            .icap_header("Host", "icap.example.org")
            .icap_header("Host", "icap2.example.org");

        assert_eq!(
            req.icap_headers.get("Host").unwrap(),
            &HeaderValue::from_static("icap2.example.org")
        );
    }

    #[test]
    fn builder_embeds_http_req_and_resp() {
        let http_req = HttpRequest::builder()
            .method("POST")
            .uri("/x")
            .version(Version::HTTP_11)
            .body(Vec::<u8>::new())
            .unwrap();

        let req = Request::reqmod("svc").with_http_request(http_req);
        matches!(req.embedded, Some(EmbeddedHttp::Req(_)));

        let http_resp = HttpResponse::builder()
            .status(StatusCode::OK)
            .version(Version::HTTP_11)
            .body(Vec::<u8>::new())
            .unwrap();

        let req2 = Request::respmod("svc").with_http_response(http_resp);
        matches!(req2.embedded, Some(EmbeddedHttp::Resp(_)));
    }

    #[test]
    fn parse_minimal_options_without_http() {
        let raw = icap_bytes(
            "OPTIONS icap://icap.example.org/icap/test ICAP/1.0\r\n\
         Host: icap.example.org\r\n\
         \r\n",
        );
        let r = parse_icap_request(&raw).expect("parse");
        assert_eq!(r.method, Method::Options);
        assert_eq!(r.service, "test");
        assert_eq!(
            r.icap_headers.get("Host").unwrap(),
            &HeaderValue::from_static("icap.example.org")
        );
        assert!(r.embedded.is_none());
        assert!(!r.allow_204);
        assert!(!r.allow_206);
        assert_eq!(r.preview_size, None);
    }

    #[test]
    fn parse_reqmod_with_allow_and_preview() {
        let raw = icap_bytes(
            "REQMOD icap://icap.example.org/icap/test ICAP/1.0\r\n\
         Host: icap.example.org\r\n\
         Allow: 204, 206\r\n\
         Preview: 128\r\n\
         \r\n",
        );
        let r = parse_icap_request(&raw).expect("parse");
        assert_eq!(r.method, Method::ReqMod);
        assert!(r.allow_204);
        assert!(r.allow_206);
        assert_eq!(r.preview_size, Some(128));
    }

    #[test]
    fn parse_reqmod_with_embedded_http_request_and_body() {
        let raw = icap_bytes(
            "REQMOD icap://icap.example.org/icap/test ICAP/1.0\r\n\
             Host: icap.example.org\r\n\
             Encapsulated: req-hdr=0\r\n\
             \r\n\
             GET / HTTP/1.1\r\n\
             Host: example.com\r\n\
             \r\n\
             body...",
        );
        let r = parse_icap_request(&raw).expect("parse");
        match r.embedded {
            Some(EmbeddedHttp::Req(ref req)) => {
                assert_eq!(req.method(), "GET");
                assert_eq!(req.uri(), "/");
                assert_eq!(
                    req.headers().get("Host").unwrap(),
                    &HeaderValue::from_static("example.com")
                );
                assert_eq!(req.body(), b"body...");
            }
            _ => panic!("expected embedded HTTP request"),
        }
    }

    #[test]
    fn parse_respmod_with_embedded_http_response_and_body() {
        let raw = icap_bytes(
            "RESPMOD icap://icap.example.org/icap/test ICAP/1.0\r\n\
             Host: icap.example.org\r\n\
             Encapsulated: res-hdr=0\r\n\
             \r\n\
             HTTP/1.1 200 OK\r\n\
             Content-Type: text/plain\r\n\
             \r\n\
             hello",
        );
        let r = parse_icap_request(&raw).expect("parse");
        match r.embedded {
            Some(EmbeddedHttp::Resp(ref resp)) => {
                assert_eq!(resp.status(), StatusCode::OK);
                assert_eq!(
                    resp.headers().get("Content-Type").unwrap(),
                    &HeaderValue::from_static("text/plain")
                );
                assert_eq!(resp.body(), b"hello");
            }
            _ => panic!("expected embedded HTTP response"),
        }
    }

    #[test]
    fn parse_errors_on_incomplete_headers() {
        let raw = icap_bytes("REQMOD icap://h/s ICAP/1.0\r\nHost: h\r\n"); // no \r\n\r\n
        let err = parse_icap_request(&raw).unwrap_err();
        assert!(
            err.to_string().contains("not complete"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_errors_on_bad_request_line() {
        // Missing icap-uri and version
        let raw = icap_bytes("REQMOD\r\n\r\n");
        let err = parse_icap_request(&raw).unwrap_err();
        assert!(
            err.to_string().contains("Invalid request line")
                || err.to_string().contains("Empty request"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_ignores_malformed_header_line_without_colon() {
        let raw = icap_bytes(
            "OPTIONS icap://icap.example.org/icap/test ICAP/1.0\r\n\
             Host: icap.example.org\r\n\
             ThisIsBadHeader\r\n\
             \r\n",
        );
        let r = parse_icap_request(&raw).expect("parse");
        assert_eq!(
            r.icap_headers.get("Host").unwrap(),
            &HeaderValue::from_static("icap.example.org")
        );
        // Just ensure we didn't panic and header map remains valid.
    }

    #[test]
    fn parse_preview_not_a_number_is_ignored() {
        let raw = icap_bytes(
            "REQMOD icap://icap.example.org/icap/test ICAP/1.0\r\n\
             Host: icap.example.org\r\n\
             Preview: notanumber\r\n\
             \r\n",
        );
        let r = parse_icap_request(&raw).expect("parse");
        assert_eq!(r.preview_size, None);
    }

    #[test]
    fn parse_allow_whitespace_variants() {
        let raw = icap_bytes(
            "REQMOD icap://icap.example.org/icap/test ICAP/1.0\r\n\
             Host: icap.example.org\r\n\
             Allow:   204 ,    206 \r\n\
             \r\n",
        );
        let r = parse_icap_request(&raw).expect("parse");
        assert!(r.allow_204);
        assert!(r.allow_206);
    }
}
