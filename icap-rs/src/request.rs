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
//! let icap_req = Request::reqmod("icap/test")
//!     .allow_204(true)
//!     .preview(4)
//!     .with_http_request(http_req);
//!
//! assert!(icap_req.method.eq_ignore_ascii_case("REQMOD"));
//! assert!(icap_req.allow_204);
//! assert_eq!(icap_req.preview_size, Some(4));
//! ```

use crate::error::IcapResult;
use crate::icap::find_double_crlf;
use http::{
    HeaderMap, HeaderName, HeaderValue, Request as HttpRequest, Response as HttpResponse,
    StatusCode as HttpStatus, Version,
};
use tracing::{debug, trace};

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
    pub fn new(method: impl Into<String>, service: impl Into<String>) -> Self {
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
        Self::new("OPTIONS", service)
    }
    ///Construct ReqMod Request.
    pub fn reqmod(service: impl Into<String>) -> Self {
        Self::new("REQMOD", service)
    }
    ///Construct RespMod Request.
    pub fn respmod(service: impl Into<String>) -> Self {
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

pub(crate) fn parse_icap_request(data: &[u8]) -> IcapResult<Request> {
    trace!("parse_icap_request: len={}", data.len());
    let hdr_end = find_double_crlf(data).ok_or("ICAP request headers not complete")?;
    let head = &data[..hdr_end];
    let head_str = std::str::from_utf8(head)?;

    // Request line: METHOD <icap-uri> ICAP/1.0
    let mut lines = head_str.split("\r\n");
    let request_line = lines.next().ok_or("Empty request")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or("Invalid request line")?.to_string();
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
    } else if let Some(http_hdr_end) = crate::parser::icap::find_double_crlf(rest) {
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
