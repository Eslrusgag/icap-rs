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
//! use icap_rs::Request; // re-exported from icap_rs::request
//!
//! let http_req = HttpRequest::builder()
//!     .method("GET")
//!     .uri("http://example.com/")
//!     .header("Host", "example.com")
//!     .body(Vec::new())
//!     .unwrap();
//!
//! let icap_req = Request::reqmod("icap/full")
//!     .allow_204(true)
//!     .preview(4)
//!     .with_http_request(http_req);
//!
//! assert!(icap_req.method.eq_ignore_ascii_case("REQMOD"));
//! assert!(icap_req.allow_204);
//! assert_eq!(icap_req.preview_size, Some(4));
//! ```

use http::{HeaderMap, HeaderName, HeaderValue, Request as HttpRequest, Response as HttpResponse};

/// Embedded HTTP message inside an ICAP request.
#[derive(Debug, Clone)]
pub enum EmbeddedHttp {
    /// Embedded HTTP request (typical for `REQMOD`).
    Req(HttpRequest<Vec<u8>>),
    /// Embedded HTTP response (typical for `RESPMOD`).
    Resp(HttpResponse<Vec<u8>>),
}

/// Single public ICAP request type used by the client.
///
/// This structure carries ICAP method/service and flags that influence how
/// the request is serialized on the wire (Preview, Allow: 204/206, ieof).
#[derive(Debug, Clone)]
pub struct Request {
    /// ICAP method: `"OPTIONS" | "REQMOD" | "RESPMOD"`.
    pub method: String,
    /// Service path like `"icap/full"` or `"respmod"`. Leading slash is allowed.
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
    pub fn new(method: &str, service: &str) -> Self {
        Self {
            method: method.to_string(),
            service: service.to_string(),
            icap_headers: HeaderMap::new(),
            embedded: None,
            preview_size: None,
            allow_204: false,
            allow_206: false,
            preview_ieof: false,
        }
    }

    /// Convenience constructors.
    pub fn options(service: &str) -> Self {
        Self::new("OPTIONS", service)
    }
    pub fn reqmod(service: &str) -> Self {
        Self::new("REQMOD", service)
    }
    pub fn respmod(service: &str) -> Self {
        Self::new("RESPMOD", service)
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
        self.method.eq_ignore_ascii_case("REQMOD") || self.method.eq_ignore_ascii_case("RESPMOD")
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
