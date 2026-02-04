//! ICAP request types and helpers.
//!
//! This module defines:
//! - [`Body`]: a generic HTTP body container used for embedded HTTP messages.
//! - [`EmbeddedHttp`]: an enum for embedded HTTP messages (request/response) that
//!   always carries `head` and `body` together.
//! - [`Request<R>`]: a single, public ICAP request type used by both **client** and
//!   **server**, parameterized by the body carrier `R`.
//! ## Preview (server-side)
//! When the server receives a Preview (`Preview: N`), it should construct
//! `EmbeddedHttp<BodyRead>` with `Body::Preview { bytes, ieof, remainder }`.
//! Calling `Body<BodyRead>::ensure_full()` will (lazily) send `ICAP/1.0 100 Continue`
//! if needed and convert the body to `Body::Full`, returning a unified reader that
//! yields `preview-bytes` followed by the remainder stream.
//!
//! ## Example (client: REQMOD with an embedded HTTP request)
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
//! let icap_req: Request = Request::reqmod("icap/test")
//!     .allow_204()
//!     .preview(4)
//!     .with_http_request(http_req);
//!
//! assert_eq!(icap_req.method, Method::ReqMod);
//! assert!(icap_req.allow_204);
//! assert_eq!(icap_req.preview_size, Some(4));

use crate::ICAP_VERSION;
use crate::error::{Error, IcapResult};
use crate::parser::icap::find_double_crlf;
use crate::parser::{serialize_http_request, serialize_http_response, split_http_bytes};
use bytes::Bytes;
use http::{
    HeaderMap, HeaderName, HeaderValue, Request as HttpRequest, Response as HttpResponse,
    StatusCode as HttpStatus, Version,
};
use memchr::memchr;
use memchr::memmem;
use std::fmt;
use std::future::Future;
use std::str::FromStr;
use tracing::trace;

use std::io::Read as _;
use std::pin::Pin;
use tokio::io::AsyncRead;

/// ICAP protocol methods recognized by the server/router.
///
/// Defined by RFC 3507. In this crate:
/// - `OPTIONS` is answered **automatically** by the server (capabilities discovery);
///
/// ### Methods
/// - **REQMOD** — *Request modification*: the ICAP client (usually a proxy)
///   sends an embedded HTTP **request** to be adapted.
/// - **RESPMOD** — *Response modification*: the ICAP client sends an embedded
///   HTTP **response** to be adapted.
/// - **OPTIONS** — *Capability discovery*: clients learn which methods and
///   features a service supports. **Handled automatically** by the server; do
///   not register a handler for `OPTIONS`.
///
/// ### Conversions
/// `Method` implements `From<&str>` / `From<String>` so you can pass
/// strings in a builder-style API. Passing an unknown string will **panic**.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub enum Method {
    /// Request modification (`REQMOD`).
    ReqMod,
    /// Response modification (`RESPMOD`).
    RespMod,
    /// Capability discovery (`OPTIONS`).
    Options,
}

impl Method {
    /// Returns the canonical ICAP token for this method.
    ///
    /// Always uppercase: `"REQMOD"`, `"RESPMOD"`, or `"OPTIONS"`.
    #[inline]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Method::ReqMod => "REQMOD",
            Method::RespMod => "RESPMOD",
            Method::Options => "OPTIONS",
        }
    }
}

impl fmt::Display for Method {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Method {
    type Err = &'static str;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let t = s.trim();
        if t.eq_ignore_ascii_case("REQMOD") {
            Ok(Method::ReqMod)
        } else if t.eq_ignore_ascii_case("RESPMOD") {
            Ok(Method::RespMod)
        } else if t.eq_ignore_ascii_case("OPTIONS") {
            Ok(Method::Options)
        } else {
            Err("Unknown ICAP method string")
        }
    }
}

impl From<&str> for Method {
    #[inline]
    fn from(s: &str) -> Self {
        s.parse()
            .unwrap_or_else(|_| panic!("Unknown ICAP method string: {s}"))
    }
}

impl From<String> for Method {
    #[inline]
    fn from(s: String) -> Self {
        s.as_str().into()
    }
}

type BoxedUnitFut = Pin<Box<dyn Future<Output = IcapResult<()>> + Send>>;

/// A one-shot handle to send `ICAP/1.0 100 Continue` when the handler decides
/// to read past the preview boundary (server-side only).
pub struct ContinueHandle {
    send: Option<Box<dyn FnOnce() -> BoxedUnitFut + Send + Sync>>,
}

impl ContinueHandle {
    pub fn new<F, Fut>(f: F) -> Self
    where
        F: FnOnce() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = IcapResult<()>> + Send + 'static,
    {
        Self {
            send: Some(Box::new(move || Box::pin(f()))),
        }
    }

    pub async fn send_100_continue(&mut self) -> IcapResult<()> {
        if let Some(f) = self.send.take() {
            f().await
        } else {
            Ok(())
        }
    }
}

/// The remainder of an HTTP body after the preview boundary.
///
/// `cont` is present only when `ieof=false` (i.e., more data exists and
/// requires a `100 Continue` before the client sends it).
pub struct Remainder<R> {
    reader: R,
    cont: Option<ContinueHandle>,
}

impl<R> Remainder<R> {
    pub fn new(reader: R, cont: Option<ContinueHandle>) -> Self {
        Self { reader, cont }
    }
    pub async fn continue_if_needed(&mut self) -> IcapResult<()> {
        if let Some(mut c) = self.cont.take() {
            c.send_100_continue().await
        } else {
            Ok(())
        }
    }
    pub fn take_reader(self) -> R {
        self.reader
    }
}

impl<R> fmt::Debug for Remainder<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Remainder")
            .field("cont_present", &self.cont.is_some())
            .finish()
    }
}

/// Generic HTTP body used inside `EmbeddedHttp<R>`.
///
/// - `Empty` — no body (e.g., GET without payload, or OPTIONS).
/// - `Preview` — the first `N` bytes are available in `bytes`, followed by the
///   `remainder` stream. `ieof=true` indicates the whole body already fits into
///   the preview and no `100 Continue` is needed.
/// - `Full` — the complete body is available via `reader`.
pub enum Body<R> {
    Empty,
    Preview {
        bytes: Bytes,
        ieof: bool,
        remainder: Remainder<R>,
    },
    Full {
        reader: R,
    },
}

impl<R> fmt::Debug for Body<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Body::Empty => f.write_str("Body::Empty"),
            Body::Full { .. } => f.write_str("Body::Full"),
            Body::Preview {
                bytes,
                ieof,
                remainder,
            } => f
                .debug_struct("Body::Preview")
                .field("bytes_len", &bytes.len())
                .field("ieof", ieof)
                .field("remainder", remainder)
                .finish(),
        }
    }
}

/// Trait-object body reader used by the server side for streaming.
pub type BodyRead = Box<dyn AsyncRead + Unpin + Send>;

/// An in-memory, non-blocking reader over bytes (used to feed preview bytes into AsyncRead).
struct CursorReader<T>(std::io::Cursor<T>);

impl<T: AsRef<[u8]> + Unpin> AsyncRead for CursorReader<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let mut tmp = [0u8; 8192];
        let want = buf.remaining().min(tmp.len());
        match self.0.read(&mut tmp[..want]) {
            Ok(n) => {
                if n > 0 {
                    buf.put_slice(&tmp[..n]);
                }
                std::task::Poll::Ready(Ok(()))
            }
            Err(e) => std::task::Poll::Ready(Err(e)),
        }
    }
}
impl Body<BodyRead> {
    /// Ensure a full stream is available.
    ///
    /// If the body is currently `Preview { .. }` and `ieof=false`, this will
    /// send `ICAP/1.0 100 Continue` **exactly once**, then convert the body into
    /// `Full { reader }` where `reader` yields `preview-bytes` followed by the
    /// remainder stream.
    /// Ensure a full stream is available (SAFE version, no `unsafe`).
    pub async fn ensure_full(&mut self) -> IcapResult<&mut (dyn AsyncRead + Unpin + Send)> {
        struct Concat<A, B>(Option<A>, B);

        impl<A: AsyncRead + Unpin, B: AsyncRead + Unpin> AsyncRead for Concat<A, B> {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                if let Some(a) = self.0.as_mut() {
                    let mut tmp = [0u8; 8192];
                    let want = buf.remaining().min(tmp.len());
                    let mut sub = tokio::io::ReadBuf::new(&mut tmp[..want]);

                    match std::pin::Pin::new(a).poll_read(cx, &mut sub) {
                        std::task::Poll::Pending => return std::task::Poll::Pending,
                        std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                        std::task::Poll::Ready(Ok(())) => {
                            let n = sub.filled().len();
                            if n > 0 {
                                buf.put_slice(sub.filled());
                                return std::task::Poll::Ready(Ok(()));
                            }
                            self.0 = None;
                        }
                    }
                }

                std::pin::Pin::new(&mut self.1).poll_read(cx, buf)
            }
        }

        match self {
            Body::Empty => Err("no body".into()),
            Body::Full { reader } => Ok(reader.as_mut()),
            Body::Preview {
                bytes,
                ieof,
                remainder,
            } => {
                if !*ieof {
                    remainder.continue_if_needed().await?;
                }

                let preview_reader: BodyRead =
                    Box::new(CursorReader(std::io::Cursor::new(std::mem::take(bytes))));

                let rem = std::mem::replace(
                    remainder,
                    Remainder::new(Box::new(tokio::io::empty()), None),
                );
                let tail = rem.take_reader();

                let concat: BodyRead = Box::new(Concat(Some(preview_reader), tail));
                *self = Body::Full { reader: concat };

                match self {
                    Body::Full { reader } => Ok(reader.as_mut()),
                    _ => unreachable!(),
                }
            }
        }
    }
}

/// Embedded HTTP message inside an ICAP request.
///
/// Stores HTTP **head** and **body** together to avoid duplication.
#[derive(Debug)]
pub enum EmbeddedHttp<R> {
    /// Embedded HTTP request (typical for `REQMOD`).
    Req {
        head: HttpRequest<()>,
        body: Body<R>,
    },
    /// Embedded HTTP response (typical for `RESPMOD`).
    Resp {
        head: HttpResponse<()>,
        body: Body<R>,
    },
}

/// Serialize embedded HTTP (client-side).
///
/// Returns `(bytes_of_http_head, optional_http_body_bytes)`.
pub(crate) fn serialize_embedded_http(e: &EmbeddedHttp<Vec<u8>>) -> (Vec<u8>, Option<Vec<u8>>) {
    match e {
        EmbeddedHttp::Req { head, body } => {
            // Rebuild http::Request<Vec<u8>> for serializer
            let mut builder = HttpRequest::builder()
                .method(head.method().clone())
                .uri(head.uri().clone())
                .version(head.version());
            {
                let headers_mut = builder.headers_mut().expect("headers_mut");
                headers_mut.extend(head.headers().clone());
            }
            let body_bytes = match body {
                Body::Empty => Vec::new(),
                Body::Full { reader } => reader.clone(),
                Body::Preview { .. } => Vec::new(), // client shouldn't serialize Preview
            };
            let req = builder.body(body_bytes).expect("build request");
            split_http_bytes(&serialize_http_request(&req))
        }
        EmbeddedHttp::Resp { head, body } => {
            let mut builder = HttpResponse::builder()
                .status(head.status())
                .version(head.version());
            {
                let headers_mut = builder.headers_mut().expect("headers_mut");
                headers_mut.extend(head.headers().clone());
            }
            let body_bytes = match body {
                Body::Empty => Vec::new(),
                Body::Full { reader } => reader.clone(),
                Body::Preview { .. } => Vec::new(),
            };
            let resp = builder.body(body_bytes).expect("build response");
            split_http_bytes(&serialize_http_response(&resp))
        }
    }
}

/// Single public ICAP request type used by both client and server.
///
/// This structure carries ICAP method/service and flags that influence how
/// the request is serialized on the wire (Preview, Allow: 204/206, ieof).
#[derive(Debug)]
pub struct Request<R = Vec<u8>> {
    /// ICAP method: `"OPTIONS" | "REQMOD" | "RESPMOD"`.
    pub method: Method,
    /// Service path like `"icap/test"` or `"respmod"`. Leading slash is allowed.
    pub service: String,
    /// ICAP headers (case-insensitive).
    pub icap_headers: HeaderMap,
    /// Optional embedded HTTP message (request/response).
    pub embedded: Option<EmbeddedHttp<R>>,
    /// `Preview: n` (if set).
    pub preview_size: Option<usize>,
    /// Whether `Allow: 204` should be advertised.
    pub allow_204: bool,
    /// Whether `Allow: 206` should be advertised.
    pub allow_206: bool,
    /// If `true` and `preview_size == Some(0)`, send `0; ieof` (fast 204 hint).
    pub preview_ieof: bool,
}

impl<R> Request<R> {
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

    /// Construct `OPTIONS` request.
    pub fn options(service: impl Into<String>) -> Self {
        Self::new(Method::Options, service)
    }
    /// Construct `REQMOD` request.
    pub fn reqmod(service: impl Into<String>) -> Self {
        Self::new(Method::ReqMod, service)
    }
    /// Construct `RESPMOD` request.
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
    pub fn preview_ieof(mut self) -> Self {
        self.preview_ieof = true;
        self
    }

    /// Advertise `Allow: 204` / `Allow: 206`.
    pub fn allow_204(mut self) -> Self {
        self.allow_204 = true;
        self
    }
    pub fn allow_206(mut self) -> Self {
        self.allow_206 = true;
        self
    }

    /// True for `REQMOD`/`RESPMOD`.
    #[inline]
    pub fn is_mod(&self) -> bool {
        matches!(self.method, Method::ReqMod | Method::RespMod)
    }
}

/// Client-side convenience: attach embedded HTTP with **owned bytes**.
impl Request<Vec<u8>> {
    pub fn with_http_request(mut self, req: HttpRequest<Vec<u8>>) -> Self {
        let (parts, body) = req.into_parts();
        let head = HttpRequest::from_parts(parts, ());
        self.embedded = Some(EmbeddedHttp::Req {
            head,
            body: Body::Full { reader: body },
        });
        self
    }
    pub fn with_http_response(mut self, resp: HttpResponse<Vec<u8>>) -> Self {
        let (parts, body) = resp.into_parts();
        let head = HttpResponse::from_parts(parts, ());
        self.embedded = Some(EmbeddedHttp::Resp {
            head,
            body: Body::Full { reader: body },
        });
        self
    }
}

/// Parse ICAP request from bytes
///
/// Note: this parser constructs `Request<Vec<u8>>`, i.e. a fully buffered
/// embedded HTTP body when present.
pub(crate) fn parse_icap_request(data: &[u8]) -> IcapResult<Request<Vec<u8>>> {
    trace!("parse_icap_request: len={}", data.len());

    let hdr_end = find_double_crlf(data).ok_or("ICAP request headers not complete")?;
    let head = &data[..hdr_end];
    let head_str = std::str::from_utf8(head)?;

    let mut lines = head_str.split("\r\n");
    let request_line = lines.next().ok_or("Empty request")?;
    let mut parts = request_line.split_whitespace();

    let method_str = parts.next().ok_or("Invalid request line")?;
    let method = match method_str.trim().to_ascii_uppercase().as_str() {
        "REQMOD" => Method::ReqMod,
        "RESPMOD" => Method::RespMod,
        "OPTIONS" => Method::Options,
        other => return Err(format!("Unknown ICAP method: {other}").into()),
    };

    let icap_uri = parts.next().ok_or("Invalid request line")?;
    let version = parts.next().ok_or("Invalid request line")?;

    if !version.eq_ignore_ascii_case(ICAP_VERSION) {
        return Err(Error::InvalidVersion(version.to_string()));
    }

    let mut icap_headers = HeaderMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(colon) = memchr(b':', line.as_bytes()) {
            let name = &line[..colon];
            let value = line[colon + 1..].trim();
            icap_headers.insert(
                HeaderName::from_bytes(name.as_bytes())?,
                HeaderValue::from_str(value)?,
            );
        }
    }

    if !icap_headers.contains_key("Host") {
        return Err(Error::MissingHeader("Host"));
    }

    if matches!(method, Method::ReqMod | Method::RespMod)
        && !icap_headers.contains_key("Encapsulated")
    {
        return Err(Error::MissingHeader("Encapsulated"));
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

    // Encapsulated area: сразу после ICAP headers CRLFCRLF
    let enc_area = &data[hdr_end..];

    let enc = icap_headers
        .get("Encapsulated")
        .and_then(|v| v.to_str().ok())
        .map(crate::parser::icap::parse_encapsulated_value)
        .unwrap_or_default();

    let http_hdr_off = match method {
        Method::ReqMod => enc.req_hdr,
        Method::RespMod => enc.res_hdr,
        Method::Options => None,
    };

    let embedded = if let Some(hdr_off) = http_hdr_off {
        let hdr_end_off = next_offset_after(&enc, hdr_off);
        let http_region = slice_encapsulated(enc_area, hdr_off, hdr_end_off)?;

        let Some(http_hdr_len) = find_double_crlf(http_region) else {
            return Ok(Request {
                method,
                service,
                icap_headers,
                embedded: None,
                preview_size,
                allow_204,
                allow_206,
                preview_ieof: false,
            });
        };
        let http_head_bytes = &http_region[..http_hdr_len];
        let inline_body = &http_region[http_hdr_len..];

        let first_line_end =
            memmem::find(http_head_bytes, b"\r\n").unwrap_or(http_head_bytes.len());
        let start_bytes = &http_head_bytes[..first_line_end];
        let is_response = start_bytes.starts_with(b"HTTP/");

        let http_head_str = std::str::from_utf8(http_head_bytes)?;
        let mut hlines = http_head_str.split("\r\n");
        let start = hlines.next().unwrap_or_default();

        let mut http_headers = HeaderMap::new();
        for line in hlines {
            if line.is_empty() {
                break;
            }
            if let Some(colon) = memchr(b':', line.as_bytes()) {
                let name = &line[..colon];
                let value = line[colon + 1..].trim();
                http_headers.insert(
                    HeaderName::from_bytes(name.as_bytes())?,
                    HeaderValue::from_str(value)?,
                );
            }
        }

        let body_off = match method {
            Method::ReqMod => enc.req_body,
            Method::RespMod => enc.res_body,
            Method::Options => None,
        };

        let no_body = body_off.is_none() && enc.null_body.is_some();

        let body_bytes: Vec<u8> = if no_body {
            Vec::new()
        } else if let Some(boff) = body_off {
            // Граница тела — следующий offset после boff, либо конец enc_area.
            let bend = next_offset_after(&enc, boff);
            let body_slice = slice_encapsulated(enc_area, boff, bend)?;

            if boff < hdr_off {
                return Err("Encapsulated offsets invalid (body before headers)".into());
            }

            body_slice.to_vec()
        } else {
            inline_body.to_vec()
        };

        if is_response {
            // HTTP Response
            let mut p = start.split_whitespace();
            let _ver = p.next().unwrap_or("HTTP/1.1");
            let code = p.next().unwrap_or("200").parse::<u16>().unwrap_or(200);

            let mut builder = HttpResponse::builder()
                .status(HttpStatus::from_u16(code).unwrap_or(HttpStatus::OK))
                .version(Version::HTTP_11);

            {
                let headers_mut = builder
                    .headers_mut()
                    .ok_or("response builder: headers_mut is None")?;
                headers_mut.extend(http_headers);
            }

            let head = builder
                .body(())
                .map_err(|e| format!("build http::Response head: {e}"))?;

            Some(EmbeddedHttp::Resp {
                head,
                body: Body::Full { reader: body_bytes },
            })
        } else {
            // HTTP Request
            let mut p = start.split_whitespace();
            let m = p.next().unwrap_or("GET");
            let u = p.next().unwrap_or("/");

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

            let head = builder
                .body(())
                .map_err(|e| format!("build http::Request head: {e}"))?;

            Some(EmbeddedHttp::Req {
                head,
                body: Body::Full { reader: body_bytes },
            })
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

fn next_offset_after(enc: &crate::parser::icap::Encapsulated, start: usize) -> Option<usize> {
    let mut min: Option<usize> = None;

    let mut consider = |v: Option<usize>| {
        if let Some(o) = v {
            if o > start {
                min = Some(match min {
                    Some(m) => m.min(o),
                    None => o,
                });
            }
        }
    };

    consider(enc.req_hdr);
    consider(enc.res_hdr);
    consider(enc.req_body);
    consider(enc.res_body);
    consider(enc.null_body);

    min
}

fn slice_encapsulated(enc_area: &[u8], start: usize, end: Option<usize>) -> IcapResult<&[u8]> {
    if start > enc_area.len() {
        return Err("Encapsulated offset out of bounds".into());
    }
    let end = end.unwrap_or(enc_area.len());
    if end > enc_area.len() {
        return Err("Encapsulated end offset out of bounds".into());
    }
    if end < start {
        return Err("Encapsulated offsets invalid (end < start)".into());
    }
    Ok(&enc_area[start..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{
        HeaderValue, Method as HttpMethod, Request as HttpRequest, Response as HttpResponse,
        StatusCode as HttpStatus, Version,
    };
    use rstest::rstest;

    #[inline]
    fn icap_bytes(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    #[rstest]
    #[case("reqmod", Method::ReqMod)]
    #[case("RESPMOD", Method::RespMod)]
    #[case("  Options  ", Method::Options)]
    fn method_from_str_is_case_insensitive(#[case] s: &str, #[case] expected: Method) {
        assert_eq!(Method::from(s), expected);
    }

    #[test]
    #[should_panic(expected = "Unknown ICAP method string")]
    fn method_from_str_unknown_panics() {
        let _ = Method::from("PATCH");
    }

    #[test]
    fn builder_creates_basic_requests() {
        let o: Request = Request::options("icap/test");
        assert_eq!(o.method, Method::Options);
        assert_eq!(o.service, "icap/test");
        assert!(!o.is_mod());

        let r: Request = Request::reqmod("svc");
        assert_eq!(r.method, Method::ReqMod);
        assert!(r.is_mod());

        let s: Request = Request::respmod("svc");
        assert_eq!(s.method, Method::RespMod);
        assert!(s.is_mod());
    }

    #[test]
    fn builder_flags_preview_allow() {
        let req: Request = Request::reqmod("icap/test")
            .allow_204()
            .allow_206()
            .preview(16)
            .preview_ieof();

        assert!(req.allow_204);
        assert!(req.allow_206);
        assert_eq!(req.preview_size, Some(16));
        assert!(req.preview_ieof);
    }

    #[test]
    fn builder_sets_and_overrides_headers() {
        let req: Request = Request::options("icap/test")
            .icap_header("Host", "icap.example.org")
            .icap_header("Host", "icap2.example.org");

        assert_eq!(
            req.icap_headers.get("Host").unwrap(),
            &HeaderValue::from_static("icap2.example.org")
        );
    }

    #[test]
    fn parse_reqmod_body_is_sliced_by_next_offset() {
        let http = b"GET / HTTP/1.1\r\nHost: ex\r\n\r\n";
        let body = b"12345678";
        let tail = b"ZZZZ"; // это будет идти после null-body boundary

        let req_body_off = http.len(); // тело сразу после http headers
        let null_body_off = req_body_off + body.len(); // конец тела

        let raw = format!(
            "REQMOD icap://icap.example.org/icap/test ICAP/1.0\r\n\
Host: icap.example.org\r\n\
Encapsulated: req-hdr=0, req-body={}, null-body={}\r\n\
\r\n",
            req_body_off, null_body_off
        )
        .into_bytes();

        let mut bytes = raw;
        bytes.extend_from_slice(http);
        bytes.extend_from_slice(body);
        bytes.extend_from_slice(tail);

        let r = parse_icap_request(&bytes).expect("parse");
        match r.embedded {
            Some(EmbeddedHttp::Req {
                body: Body::Full { reader },
                ..
            }) => {
                assert_eq!(reader, body);
            }
            _ => panic!("expected embedded req with full body"),
        }
    }

    #[test]
    fn builder_embeds_http_req_and_resp() {
        let http_req = HttpRequest::builder()
            .method("POST")
            .uri("/x")
            .version(Version::HTTP_11)
            .body(Vec::<u8>::new())
            .unwrap();

        let req: Request = Request::reqmod("svc").with_http_request(http_req);
        assert!(matches!(req.embedded, Some(EmbeddedHttp::Req { .. })));

        let http_resp = HttpResponse::builder()
            .status(HttpStatus::OK)
            .version(Version::HTTP_11)
            .body(Vec::<u8>::new())
            .unwrap();

        let req2: Request = Request::respmod("svc").with_http_response(http_resp);
        assert!(matches!(req2.embedded, Some(EmbeddedHttp::Resp { .. })));
    }

    // ---------- Version & framing ----------

    #[test]
    fn version_must_be_icap_1_0_in_request() {
        let raw = b"REQMOD icap://h/s ICAP/2.0\r\n\
                    Host: h\r\n\
                    Encapsulated: req-hdr=0\r\n\
                    \r\n";
        let err = parse_icap_request(raw).unwrap_err();
        assert!(matches!(err, Error::InvalidVersion(v) if v == "ICAP/2.0"));
    }

    #[rstest]
    #[case(
        "REQMOD icap://icap.example.org/icap/test ICAP/1.0\r\nHost: icap.example.org\r\nEncapsulated: req-hdr=0\r\n\r\n",
        "test"
    )]
    #[case(
        "RESPMOD icap://icap.example.org/respmod ICAP/1.0\r\nHost: icap.example.org\r\nEncapsulated: res-hdr=0\r\n\r\n",
        "respmod"
    )]
    fn service_is_last_path_segment_of_icap_uri(
        #[case] wire: &str,
        #[case] expected_service: &str,
    ) {
        let r = parse_icap_request(&icap_bytes(wire)).expect("parse");
        assert_eq!(r.service, expected_service);
    }

    #[test]
    fn headers_are_case_insensitive_allow_parsed_with_whitespace() {
        let raw = icap_bytes(
            "REQMOD icap://h/s ICAP/1.0\r\n\
             host: icap.example.org\r\n\
             aLlOw: 206, 204 \r\n\
             Encapsulated: req-hdr=0\r\n\
             \r\n",
        );
        let r = parse_icap_request(&raw).expect("parse");
        assert!(r.allow_204);
        assert!(r.allow_206);
        assert_eq!(
            r.icap_headers.get("Host").unwrap(),
            &HeaderValue::from_static("icap.example.org")
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
    }

    #[test]
    fn host_header_is_required() {
        let raw = b"REQMOD icap://icap.example.org/icap/test ICAP/1.0\r\n\
                    Encapsulated: req-hdr=0\r\n\
                    \r\n";
        let err = parse_icap_request(raw).unwrap_err();
        let m = err.to_string().to_lowercase();
        assert!(m.contains("host"), "expected missing Host error; got: {m}");
    }

    #[test]
    fn encapsulated_is_required_for_request() {
        let raw_req = b"REQMOD icap://icap.example.org/icap/test ICAP/1.0\r\n\
                        Host: icap.example.org\r\n\
                        \r\n";
        let err1 = parse_icap_request(raw_req).unwrap_err();
        assert!(
            matches!(err1, Error::MissingHeader(h) if h == "Encapsulated"),
            "expected MissingHeader(Encapsulated); got: {err1}"
        );

        let raw_resp = b"RESPMOD icap://icap.example.org/icap/test ICAP/1.0\r\n\
                         Host: icap.example.org\r\n\
                         \r\n";
        let err2 = parse_icap_request(raw_resp).unwrap_err();
        assert!(
            matches!(err2, Error::MissingHeader(h) if h == "Encapsulated"),
            "expected MissingHeader(Encapsulated); got: {err2}"
        );
    }

    #[test]
    fn parse_reqmod_with_allow_and_preview() {
        let raw = icap_bytes(
            "REQMOD icap://icap.example.org/icap/test ICAP/1.0\r\n\
             Host: icap.example.org\r\n\
             Encapsulated: req-hdr=0\r\n\
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
    fn parse_preview_not_a_number_is_ignored() {
        let raw = icap_bytes(
            "REQMOD icap://icap.example.org/icap/test ICAP/1.0\r\n\
             Host: icap.example.org\r\n\
             Preview: notanumber\r\n\
             Encapsulated: req-hdr=0\r\n\
             \r\n",
        );
        let r = parse_icap_request(&raw).expect("parse");
        assert_eq!(r.preview_size, None);
    }

    // ---------- Embedded HTTP ----------

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
            Some(EmbeddedHttp::Req { ref head, ref body }) => {
                assert_eq!(head.method(), &HttpMethod::GET);
                assert_eq!(head.uri(), "/");
                assert_eq!(
                    head.headers().get("Host").unwrap(),
                    &HeaderValue::from_static("example.com")
                );
                match body {
                    Body::Full { reader } => assert_eq!(reader, b"body..."),
                    _ => panic!("expected Full body"),
                }
            }
            _ => panic!("expected embedded HTTP request"),
        }
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
}

#[cfg(test)]
mod rfc_tests {
    //! RFC 3507 conformance tests for ICAP **requests**.
    //!
    //! These tests check:
    //! - Method parsing (case-insensitive, unknown → panic by design)
    //! - Service extraction from ICAP URI (last path segment)
    //! - `Allow: 204/206` & `Preview: n` parsing (with whitespace variants)
    //! - Embedded HTTP request/response extraction
    //! - Case-insensitive headers
    //! - Request-line/headers framing errors
    use super::*;
    use http::{HeaderValue, StatusCode as HttpStatus};

    fn icap_bytes(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    #[test]
    fn method_from_str_is_case_insensitive() {
        assert_eq!(Method::from("reqmod"), Method::ReqMod);
        assert_eq!(Method::from("RESPMOD"), Method::RespMod);
        assert_eq!(Method::from("  Options  "), Method::Options);
    }

    #[test]
    #[should_panic(expected = "Unknown ICAP method string")]
    fn method_from_str_unknown_panics() {
        let _ = Method::from("PATCH");
    }

    #[test]
    fn service_is_last_path_segment_of_icap_uri() {
        let raw = icap_bytes(
            "REQMOD icap://icap.example.org/icap/test ICAP/1.0\r\n\
         Host: icap.example.org\r\n\
         Encapsulated: req-hdr=0\r\n\
         \r\n",
        );
        let r = parse_icap_request(&raw).expect("parse");
        assert_eq!(r.service, "test");

        let raw2 = icap_bytes(
            "RESPMOD icap://icap.example.org/respmod ICAP/1.0\r\n\
         Host: icap.example.org\r\n\
         Encapsulated: res-hdr=0\r\n\
         \r\n",
        );
        let r2 = parse_icap_request(&raw2).expect("parse");
        assert_eq!(r2.service, "respmod");
    }

    #[test]
    fn headers_are_case_insensitive_allow_parsed_with_whitespace() {
        let raw = icap_bytes(
            "REQMOD icap://h/s ICAP/1.0\r\n\
         host: icap.example.org\r\n\
         aLlOw: 206, 204 \r\n\
         Encapsulated: req-hdr=0\r\n\
         \r\n",
        );
        let r = parse_icap_request(&raw).expect("parse");
        assert!(r.allow_204);
        assert!(r.allow_206);
        assert_eq!(
            r.icap_headers.get("Host").unwrap(),
            &HeaderValue::from_static("icap.example.org")
        );
    }

    #[test]
    fn preview_zero_does_not_imply_ieof() {
        let r: Request = Request::reqmod("svc").preview(0);
        assert_eq!(r.preview_size, Some(0));
        assert!(!r.preview_ieof);

        let r2: Request = Request::reqmod("svc").preview(0).preview_ieof();
        assert_eq!(r2.preview_size, Some(0));
        assert!(r2.preview_ieof);
    }

    #[test]
    fn rejects_embedded_http_without_encapsulated() {
        let raw = b"REQMOD icap://icap.example.org/icap/test ICAP/1.0\r\n\
                Host: icap.example.org\r\n\
                \r\n\
                GET / HTTP/1.1\r\n\
                Host: example.com\r\n\
                \r\n";
        let err = parse_icap_request(raw).unwrap_err();
        assert!(matches!(err, Error::MissingHeader(h) if h == "Encapsulated"));
    }

    #[test]
    fn parses_embedded_http_response_with_res_hdr_token() {
        let raw = icap_bytes(
            "RESPMOD icap://icap.example.org/icap/test ICAP/1.0\r\n\
             Host: icap.example.org\r\n\
             Encapsulated: res-hdr=0\r\n\
             \r\n\
             HTTP/1.1 200 OK\r\n\
             Content-Length: 5\r\n\
             \r\n\
             hello",
        );
        let r = parse_icap_request(&raw).expect("parse");
        match r.embedded {
            Some(EmbeddedHttp::Resp { ref head, ref body }) => {
                assert_eq!(head.status(), HttpStatus::OK);
                assert_eq!(head.headers().get("Content-Length").unwrap(), "5");
                match body {
                    Body::Full { reader } => assert_eq!(reader, b"hello"),
                    _ => panic!("expected Full body"),
                }
            }
            _ => panic!("expected embedded HTTP response"),
        }
    }

    #[test]
    fn request_line_must_have_method_uri_and_version() {
        let raw = icap_bytes("REQMOD icap://h/s\r\n\r\n");
        let err = parse_icap_request(&raw).unwrap_err();
        assert!(
            err.to_string().contains("Invalid request line"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn error_on_incomplete_headers_request_side() {
        let raw = icap_bytes("REQMOD icap://h/s ICAP/1.0\r\nHost: h\r\n");
        let err = parse_icap_request(&raw).unwrap_err();
        assert!(err.to_string().contains("not complete"), "err: {err}");
    }

    #[test]
    fn host_header_is_required() {
        let raw = b"REQMOD icap://icap.example.org/icap/test ICAP/1.0\r\n\
                Encapsulated: req-hdr=0\r\n\
                \r\n";
        let err = parse_icap_request(raw).unwrap_err();
        let m = err.to_string().to_lowercase();
        assert!(m.contains("host"), "expected missing Host error; got: {m}");
    }

    #[test]
    fn encapsulated_is_required_for_request() {
        let raw_req = b"REQMOD icap://icap.example.org/icap/test ICAP/1.0\r\n\
                    Host: icap.example.org\r\n\
                    \r\n";
        let err1 = parse_icap_request(raw_req).unwrap_err();
        assert!(
            matches!(err1, Error::MissingHeader(h) if h == "Encapsulated"),
            "expected MissingHeader(Encapsulated); got: {err1}"
        );

        let raw_resp = b"RESPMOD icap://icap.example.org/icap/test ICAP/1.0\r\n\
                     Host: icap.example.org\r\n\
                     \r\n";
        let err2 = parse_icap_request(raw_resp).unwrap_err();
        assert!(
            matches!(err2, Error::MissingHeader(h) if h == "Encapsulated"),
            "expected MissingHeader(Encapsulated); got: {err2}"
        );
    }
}
