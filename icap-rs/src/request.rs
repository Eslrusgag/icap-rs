//! ICAP request types and helpers.
//!
//! This module defines:
//! - [`Body`]: a generic HTTP body container used for embedded HTTP messages.
//! - [`EmbeddedHttp`]: an enum for embedded HTTP messages (request/response) that
//!   always carries `head` and `body` together.
//! - [`Request<R, D>`]: a single ICAP request type parameterized by the body
//!   carrier `R` and direction marker `D`.
//! - [`OutboundRequest`]: the client-side request builder shape.
//! - [`IncomingRequest`]: the server-side handler shape with read-only ICAP
//!   metadata and mutable/consumable embedded HTTP access.
//! ## Preview (server-side)
//! By default, the server handles Preview (`Preview: N`) on the wire:
//! - reads preview chunks first,
//! - sends `ICAP/1.0 100 Continue` when preview is non-`ieof`,
//! - then reads and de-chunks the remainder before invoking handlers.
//!
//! As a result, regular server handlers receive embedded bodies as `Body::Full`.
//! Return `PreviewDecision` from a route handler when a service needs to make
//! an early decision from preview bytes and return a final response before
//! `100 Continue`.
//! `Body::Preview` and `Body<BodyRead>::ensure_full()` remain available for custom
//! integrations that build preview-aware pipelines explicitly.
//!
//! Request parsing requires `Encapsulated` on every ICAP request, including
//! `OPTIONS`. Servers can opt into legacy compatibility parsing for old peers
//! that omit `Encapsulated` on `OPTIONS`.
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
//!     .with_http_request(http_req)?;
//!
//! assert_eq!(icap_req.method(), Method::ReqMod);
//! assert!(icap_req.allows_204());
//! assert_eq!(icap_req.preview_size(), Some(4));
//! # Ok::<(), icap_rs::Error>(())
//! ```

use crate::ICAP_VERSION;
use crate::error::{Error, IcapResult};
#[cfg(test)]
use crate::error::{ProtocolError, ProtocolField};
use crate::protocol::{
    find_double_crlf, parse_header_lines, parse_http_request_start_line,
    parse_http_response_start_line,
};
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Request as HttpRequest, Response as HttpResponse};
use memchr::memmem;
use std::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::str::FromStr;
use tracing::trace;

use std::io::Write as _;
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
            Self::ReqMod => "REQMOD",
            Self::RespMod => "RESPMOD",
            Self::Options => "OPTIONS",
        }
    }

    /// Parse an ICAP method token into a structured [`Method`].
    ///
    /// This is the non-panicking counterpart to `Method::from(&str)`.
    pub fn parse_token(token: &str) -> IcapResult<Self> {
        token.parse().map_err(|_| {
            Error::invalid_method(format!("Unknown ICAP method string: {}", token.trim()))
        })
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
            Ok(Self::ReqMod)
        } else if t.eq_ignore_ascii_case("RESPMOD") {
            Ok(Self::RespMod)
        } else if t.eq_ignore_ascii_case("OPTIONS") {
            Ok(Self::Options)
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
    pub const fn new(reader: R, cont: Option<ContinueHandle>) -> Self {
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
            .finish_non_exhaustive()
    }
}

/// Generic HTTP body used inside [`EmbeddedHttp`].
///
/// - `Empty` — no body (e.g., GET without payload, or OPTIONS).
/// - `Preview` — the first `N` bytes are available in `bytes`, followed by the
///   `remainder` stream. `ieof=true` indicates the whole body already fits into
///   the preview and no `100 Continue` is needed.
/// - `Full` — the complete body is available via `reader`.
///
/// Regular server routes normally receive `Full` bodies because the server owns
/// the RFC Preview handshake. Preview-aware routes may see `Preview` before
/// `100 Continue` is sent.
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
            Self::Empty => f.write_str("Body::Empty"),
            Self::Full { .. } => f.write_str("Body::Full"),
            Self::Preview {
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

/// An in-memory, non-blocking reader over bytes (used to feed preview bytes into `AsyncRead`).
struct CursorReader<T>(std::io::Cursor<T>);

impl<T: AsRef<[u8]> + Unpin> AsyncRead for CursorReader<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Read directly into the ReadBuf's unfilled portion; invalid cursor positions
        // are treated as EOF because this reader only advances within the backing slice.
        let src = self.0.get_ref().as_ref();
        let pos = usize::try_from(self.0.position()).map_or(src.len(), |pos| pos.min(src.len()));
        let remaining = src.len().saturating_sub(pos);
        if remaining > 0 {
            let to_copy = remaining.min(buf.remaining());
            buf.put_slice(&src[pos..pos + to_copy]);
            self.0.set_position((pos + to_copy) as u64);
        }
        std::task::Poll::Ready(Ok(()))
    }
}
impl Body<BodyRead> {
    /// Ensure a full stream is available.
    ///
    /// If the body is currently `Preview { .. }` and `ieof=false`, this will
    /// send `ICAP/1.0 100 Continue` **exactly once**, then convert the body into
    /// `Full { reader }` where `reader` yields `preview-bytes` followed by the
    /// remainder stream.
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
            Body::Empty => Err(Error::body("no body")),
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

/// The type of embedded HTTP message carried by an ICAP request.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[must_use]
pub enum EmbeddedHttpKind {
    /// Embedded HTTP request (`req-hdr` / `req-body`).
    Request,
    /// Embedded HTTP response (`res-hdr` / `res-body`).
    Response,
}

impl<R> EmbeddedHttp<R> {
    /// Return whether this embedded message is an HTTP request or response.
    pub const fn kind(&self) -> EmbeddedHttpKind {
        match self {
            Self::Req { .. } => EmbeddedHttpKind::Request,
            Self::Resp { .. } => EmbeddedHttpKind::Response,
        }
    }
}

/// Serialize embedded HTTP (client-side).
///
/// Returns `(http_head_bytes, body_bytes_up_to_limit, original_body_len)`.
///
/// `body_limit` caps how many body bytes are copied into the returned `Vec`.
/// Pass `None` to copy the full body (required for [`Client::send`] so the
/// remainder is available after `100 Continue`).
/// Pass `Some(preview_size)` for dry-run helpers like [`Client::get_request`]
/// where only the preview bytes need to appear in the wire buffer; the caller
/// must use `original_body_len` to decide the correct chunk terminator
/// (`ieof` vs `0\r\n\r\n`) regardless of how many bytes were actually copied.
pub(crate) fn serialize_embedded_http(
    e: &EmbeddedHttp<Vec<u8>>,
    body_limit: Option<usize>,
) -> (Vec<u8>, Option<Vec<u8>>, usize) {
    #[inline]
    fn copy_body(reader: &[u8], limit: Option<usize>) -> (Option<Vec<u8>>, usize) {
        if reader.is_empty() {
            return (None, 0);
        }
        let original_len = reader.len();
        let end = limit.map_or(original_len, |lim| original_len.min(lim));
        (Some(reader[..end].to_vec()), original_len)
    }

    match e {
        EmbeddedHttp::Req { head, body } => {
            let head_bytes = serialize_http_request_head(head);
            let (body_bytes, original_len) = match body {
                Body::Full { reader } => copy_body(reader, body_limit),
                Body::Empty | Body::Preview { .. } => (None, 0),
            };
            (head_bytes, body_bytes, original_len)
        }
        EmbeddedHttp::Resp { head, body } => {
            let head_bytes = serialize_http_response_head(head);
            let (body_bytes, original_len) = match body {
                Body::Full { reader } => copy_body(reader, body_limit),
                Body::Empty | Body::Preview { .. } => (None, 0),
            };
            (head_bytes, body_bytes, original_len)
        }
    }
}

fn serialize_http_request_head(head: &HttpRequest<()>) -> Vec<u8> {
    let mut out = Vec::with_capacity(256 + head.headers().len() * 32);
    write!(
        &mut out,
        "{} {} {}\r\n",
        head.method(),
        head.uri(),
        crate::protocol::http_version_str(head.version())
    )
    .expect("write request line");
    for (name, value) in head.headers() {
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

fn serialize_http_response_head(head: &HttpResponse<()>) -> Vec<u8> {
    let mut out = Vec::with_capacity(256 + head.headers().len() * 32);
    write!(
        &mut out,
        "{} {} {}\r\n",
        crate::protocol::http_version_str(head.version()),
        head.status().as_u16(),
        head.status().canonical_reason().unwrap_or("")
    )
    .expect("write status line");
    for (name, value) in head.headers() {
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Single public ICAP request type used by both client and server.
///
/// The second type parameter is a direction marker:
/// - [`Outbound`] is the default client-side builder shape.
/// - [`Incoming`] is the server-side handler shape.
///
/// Server handlers receive [`IncomingRequest`], whose ICAP metadata is read-only
/// through accessors. Services may inspect or modify the embedded HTTP message
/// via [`Request::embedded_mut`] or consume it via [`Request::into_embedded`],
/// but they cannot mutate the ICAP request line, ICAP headers, preview flags,
/// or advertised `Allow` values through public API.
#[derive(Debug)]
#[must_use]
pub struct Request<R = Vec<u8>, D = Outbound> {
    /// ICAP method: `"OPTIONS" | "REQMOD" | "RESPMOD"`.
    pub(crate) method: Method,
    /// Service path like `"icap/test"` or `"respmod"`. Leading slash is allowed.
    pub(crate) service: String,
    /// ICAP headers (case-insensitive).
    pub(crate) icap_headers: HeaderMap,
    /// Optional embedded HTTP message (request/response).
    pub(crate) embedded: Option<EmbeddedHttp<R>>,
    /// `Preview: n` (if set).
    pub(crate) preview_size: Option<usize>,
    /// Whether `Allow: 204` should be advertised.
    pub(crate) allow_204: bool,
    /// Whether `Allow: 206` should be advertised.
    pub(crate) allow_206: bool,
    /// If `true` and `preview_size == Some(0)`, send `0; ieof` (fast 204 hint).
    pub(crate) preview_ieof: bool,
    pub(crate) direction: PhantomData<D>,
}

/// Client-side request marker.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Outbound {}

/// Server-side request marker.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Incoming {}

/// Request shape accepted by client send/build APIs.
pub type OutboundRequest<R = Vec<u8>> = Request<R, Outbound>;

/// Request shape received by server route handlers.
pub type IncomingRequest<R = Vec<u8>> = Request<R, Incoming>;

pub(crate) struct IncomingRequestParts<R> {
    method: Method,
    service: String,
    icap_headers: HeaderMap,
    embedded: Option<EmbeddedHttp<R>>,
    preview_size: Option<usize>,
    allow_204: bool,
    allow_206: bool,
    preview_ieof: bool,
}

impl<R> Request<R, Outbound> {
    /// Create a new outbound ICAP request.
    pub fn new(method: Method, service: impl Into<String>) -> Self {
        Self {
            method,
            service: service.into(),
            icap_headers: HeaderMap::new(),
            embedded: None,
            preview_size: None,
            allow_204: false,
            allow_206: false,
            preview_ieof: false,
            direction: PhantomData,
        }
    }

    /// Create a new outbound ICAP request from a method token without panicking.
    pub fn try_new(method: &str, service: impl Into<String>) -> IcapResult<Self> {
        Ok(Self::new(Method::parse_token(method)?, service))
    }
}

impl<R, D> Request<R, D> {
    /// Return the ICAP method.
    #[inline]
    pub const fn method(&self) -> Method {
        self.method
    }

    /// Return the service path carried in the ICAP URI.
    #[inline]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Return ICAP headers supplied on the request.
    #[inline]
    pub const fn icap_headers(&self) -> &HeaderMap {
        &self.icap_headers
    }

    /// Return embedded HTTP, if this request carries one.
    #[inline]
    pub const fn embedded(&self) -> Option<&EmbeddedHttp<R>> {
        self.embedded.as_ref()
    }

    /// Return mutable embedded HTTP, if this request carries one.
    #[inline]
    pub const fn embedded_mut(&mut self) -> Option<&mut EmbeddedHttp<R>> {
        self.embedded.as_mut()
    }

    /// Consume the request and return the embedded HTTP message.
    #[inline]
    pub fn into_embedded(self) -> Option<EmbeddedHttp<R>> {
        self.embedded
    }

    /// Return the requested preview size.
    #[inline]
    pub const fn preview_size(&self) -> Option<usize> {
        self.preview_size
    }

    /// Return whether `Preview: 0` should be sent as `0; ieof`.
    #[inline]
    pub const fn is_preview_ieof(&self) -> bool {
        self.preview_ieof
    }

    /// Return whether `Allow: 204` is advertised.
    #[inline]
    pub const fn allows_204(&self) -> bool {
        self.allow_204
    }

    /// Return whether `Allow: 206` is advertised.
    #[inline]
    pub const fn allows_206(&self) -> bool {
        self.allow_206
    }
}

impl<R> Request<R, Outbound> {
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

    /// Try to set or override an ICAP header.
    pub fn try_icap_header(mut self, name: &str, value: &str) -> IcapResult<Self> {
        let n: HeaderName = name.parse()?;
        let v: HeaderValue = HeaderValue::from_str(value)?;
        self.icap_headers.insert(n, v);
        Ok(self)
    }

    /// Set or override an ICAP header.
    ///
    /// # Panics
    ///
    /// Panics if `name` or `value` is not a valid HTTP header field. Use
    /// [`Request::try_icap_header`] for untrusted input.
    pub fn icap_header(self, name: &str, value: &str) -> Self {
        self.try_icap_header(name, value)
            .expect("invalid ICAP header name or value")
    }

    /// Advertise `Preview: n`.
    ///
    /// `Preview: 0` means the client sends an immediate zero-size preview chunk
    /// and waits for either a final response or `100 Continue`.
    pub const fn preview(mut self, n: usize) -> Self {
        self.preview_size = Some(n);
        self
    }
    /// Mark a `Preview: 0` request as complete using the `ieof` chunk extension.
    pub const fn preview_ieof(mut self) -> Self {
        self.preview_ieof = true;
        self
    }

    /// Advertise `Allow: 204`.
    pub const fn allow_204(mut self) -> Self {
        self.allow_204 = true;
        self
    }
    /// Advertise `Allow: 206`.
    ///
    /// The companion server can answer eligible no-modification flows with
    /// `206 Partial Content` and `use-original-body`.
    pub const fn allow_206(mut self) -> Self {
        self.allow_206 = true;
        self
    }

    /// True for `REQMOD`/`RESPMOD`.
    #[inline]
    pub const fn is_mod(&self) -> bool {
        matches!(self.method, Method::ReqMod | Method::RespMod)
    }

    /// True for `OPTIONS`.
    #[inline]
    pub const fn is_options(&self) -> bool {
        matches!(self.method, Method::Options)
    }

    /// Return the embedded HTTP message kind, if present.
    #[inline]
    pub const fn embedded_kind(&self) -> Option<EmbeddedHttpKind> {
        match &self.embedded {
            Some(embedded) => Some(embedded.kind()),
            None => None,
        }
    }

    /// Validate that this request can be serialized as a coherent ICAP request.
    ///
    /// This checks method-to-embedded-message compatibility but does not require
    /// a buffered body, because streaming sends attach body bytes separately.
    pub fn validate_for_send(&self) -> IcapResult<()> {
        match (self.method, self.embedded_kind()) {
            (Method::Options, Some(_)) => {
                return Err(Error::serialization(
                    "OPTIONS requests must not carry embedded HTTP",
                ));
            }
            (Method::ReqMod, Some(EmbeddedHttpKind::Response)) => {
                return Err(Error::serialization(
                    "REQMOD requests must carry an embedded HTTP request",
                ));
            }
            (Method::RespMod, Some(EmbeddedHttpKind::Request)) => {
                return Err(Error::serialization(
                    "RESPMOD requests must carry an embedded HTTP response",
                ));
            }
            _ => {}
        }

        if self.preview_ieof && self.preview_size != Some(0) {
            return Err(Error::serialization(
                "preview_ieof is only valid together with Preview: 0",
            ));
        }

        Ok(())
    }
}

impl<R> Request<R, Incoming> {
    #[allow(clippy::missing_const_for_fn)]
    pub(crate) fn incoming(parts: IncomingRequestParts<R>) -> Self {
        Self {
            method: parts.method,
            service: parts.service,
            icap_headers: parts.icap_headers,
            embedded: parts.embedded,
            preview_size: parts.preview_size,
            allow_204: parts.allow_204,
            allow_206: parts.allow_206,
            preview_ieof: parts.preview_ieof,
            direction: PhantomData,
        }
    }
}

/// Client-side convenience: attach embedded HTTP with **owned bytes**.
impl Request<Vec<u8>, Outbound> {
    /// Attach only HTTP request head (no buffered body bytes).
    ///
    /// Useful with streaming client APIs such as `Client::send_streaming_reader`.
    pub fn with_http_request_head(mut self, head: HttpRequest<()>) -> IcapResult<Self> {
        if self.method != Method::ReqMod {
            return Err(Error::serialization(
                "HTTP request heads can only be attached to REQMOD requests",
            ));
        }
        self.embedded = Some(EmbeddedHttp::Req {
            head,
            body: Body::Empty,
        });
        Ok(self)
    }

    /// Attach only HTTP response head (no buffered body bytes).
    ///
    /// Useful with streaming client APIs such as `Client::send_streaming_reader`.
    pub fn with_http_response_head(mut self, head: HttpResponse<()>) -> IcapResult<Self> {
        if self.method != Method::RespMod {
            return Err(Error::serialization(
                "HTTP response heads can only be attached to RESPMOD requests",
            ));
        }
        self.embedded = Some(EmbeddedHttp::Resp {
            head,
            body: Body::Empty,
        });
        Ok(self)
    }

    /// Attach a complete embedded HTTP request.
    ///
    /// This is the usual client-side builder for `REQMOD` requests when the
    /// HTTP entity body is already available in memory. For large bodies, use
    /// [`Request::with_http_request_head`] together with a streaming client
    pub fn with_http_request(mut self, req: HttpRequest<Vec<u8>>) -> IcapResult<Self> {
        if self.method != Method::ReqMod {
            return Err(Error::serialization(
                "HTTP requests can only be attached to REQMOD requests",
            ));
        }
        let (parts, body) = req.into_parts();
        let head = HttpRequest::from_parts(parts, ());
        self.embedded = Some(EmbeddedHttp::Req {
            head,
            body: Body::Full { reader: body },
        });
        Ok(self)
    }

    /// Attach a complete embedded HTTP response.
    ///
    /// This is the usual client-side builder for `RESPMOD` requests when the
    /// HTTP entity body is already available in memory. For large bodies, use
    /// [`Request::with_http_response_head`] together with a streaming client
    pub fn with_http_response(mut self, resp: HttpResponse<Vec<u8>>) -> IcapResult<Self> {
        if self.method != Method::RespMod {
            return Err(Error::serialization(
                "HTTP responses can only be attached to RESPMOD requests",
            ));
        }
        let (parts, body) = resp.into_parts();
        let head = HttpResponse::from_parts(parts, ());
        self.embedded = Some(EmbeddedHttp::Resp {
            head,
            body: Body::Full { reader: body },
        });
        Ok(self)
    }
}

/// Parse ICAP request from bytes
///
/// Note: this parser constructs `IncomingRequest<Vec<u8>>`, i.e. a fully buffered
/// embedded HTTP body when present.
pub(crate) fn parse_icap_request(data: &[u8]) -> IcapResult<IncomingRequest<Vec<u8>>> {
    parse_icap_request_with_mode(data, RequestParserMode::Strict)
}

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
pub(crate) enum RequestParserMode {
    Compatibility,
    #[default]
    Strict,
}

pub(crate) fn parse_icap_request_with_mode(
    data: &[u8],
    mode: RequestParserMode,
) -> IcapResult<IncomingRequest<Vec<u8>>> {
    trace!("parse_icap_request: len={}", data.len());

    let hdr_end =
        find_double_crlf(data).ok_or_else(|| Error::parse("ICAP request headers not complete"))?;
    let head = &data[..hdr_end];
    let head_str = std::str::from_utf8(head)?;

    let mut lines = head_str.split("\r\n");
    let request_line = lines.next().ok_or_else(|| Error::parse("Empty request"))?;
    let mut parts = request_line.split_whitespace();

    let method_str = parts
        .next()
        .ok_or_else(|| Error::parse("Invalid request line"))?;
    let method = match method_str.trim().to_ascii_uppercase().as_str() {
        "REQMOD" => Method::ReqMod,
        "RESPMOD" => Method::RespMod,
        "OPTIONS" => Method::Options,
        other => {
            return Err(Error::invalid_method(format!(
                "Unknown ICAP method: {other}"
            )));
        }
    };

    let icap_uri = parts
        .next()
        .ok_or_else(|| Error::parse("Invalid request line"))?;
    let version = parts
        .next()
        .ok_or_else(|| Error::parse("Invalid request line"))?;

    if !version.eq_ignore_ascii_case(ICAP_VERSION) {
        return Err(Error::invalid_version(version.to_string()));
    }

    let icap_headers = parse_header_lines(lines)?;

    if !icap_headers.contains_key("Host") {
        return Err(Error::missing_header("Host"));
    }

    if (matches!(method, Method::ReqMod | Method::RespMod)
        || (mode == RequestParserMode::Strict && method == Method::Options))
        && !icap_headers.contains_key("Encapsulated")
    {
        return Err(Error::missing_header("Encapsulated"));
    }

    let service = icap_uri.rsplit('/').next().unwrap_or("").to_string();

    let allow_204 = allow_contains_token(&icap_headers, "204");
    let allow_206 = allow_contains_token(&icap_headers, "206");

    // RFC 3507 §4.5: `Preview` carries a non-negative integer count of body bytes
    // included in the preview. Malformed values are a protocol error.
    let preview_size = match icap_headers.get("Preview") {
        None => None,
        Some(v) => {
            let s = v
                .to_str()
                .map_err(|_| Error::parse("Preview header has non-ASCII value"))?;
            let trimmed = s.trim();
            let n = trimmed.parse::<usize>().map_err(|_| {
                Error::parse(format!("Preview header has invalid integer '{trimmed}'"))
            })?;
            Some(n)
        }
    };

    // Encapsulated bytes start immediately after the ICAP header terminator.
    let enc_area = &data[hdr_end..];

    let enc = match icap_headers.get("Encapsulated") {
        Some(v) => {
            let raw = v.to_str()?;
            crate::protocol::parse_encapsulated_value(raw)?
        }
        None => crate::protocol::Encapsulated::default(),
    };
    validate_encapsulated_for_method(method, &enc)?;

    let http_hdr_off = match method {
        Method::ReqMod => enc.req_hdr,
        Method::RespMod => enc.res_hdr,
        Method::Options => None,
    };

    let embedded = if let Some(hdr_off) = http_hdr_off {
        let hdr_end_off = next_offset_after(&enc, hdr_off);
        let http_region = slice_encapsulated(enc_area, hdr_off, hdr_end_off)?;
        if http_region.is_empty() {
            return Ok(IncomingRequest::incoming(IncomingRequestParts {
                method,
                service,
                icap_headers,
                embedded: None,
                preview_size,
                allow_204,
                allow_206,
                preview_ieof: false,
            }));
        }

        let http_hdr_len = find_double_crlf(http_region)
            .ok_or_else(|| Error::http_parse("embedded HTTP headers not complete".to_string()))?;
        let http_head_bytes = &http_region[..http_hdr_len];
        let inline_body = &http_region[http_hdr_len..];

        let first_line_end =
            memmem::find(http_head_bytes, b"\r\n").unwrap_or(http_head_bytes.len());
        let start_bytes = &http_head_bytes[..first_line_end];
        let start = std::str::from_utf8(start_bytes)?;

        let http_head_str = std::str::from_utf8(http_head_bytes)?;
        let mut hlines = http_head_str.split("\r\n");
        let _ = hlines.next();

        let http_headers = parse_header_lines(hlines)?;

        let body_off = match method {
            Method::ReqMod => enc.req_body,
            Method::RespMod => enc.res_body,
            Method::Options => None,
        };

        let no_body = body_off.is_none() && enc.null_body.is_some();

        let body_bytes: Vec<u8> = if no_body {
            Vec::new()
        } else if let Some(boff) = body_off {
            // The body boundary is the next Encapsulated offset or the end of the area.
            let bend = next_offset_after(&enc, boff);
            let body_slice = slice_encapsulated(enc_area, boff, bend)?;

            if boff < hdr_off {
                return Err(Error::header(
                    "Encapsulated offsets invalid (body before headers)",
                ));
            }

            body_slice.to_vec()
        } else {
            inline_body.to_vec()
        };

        if method == Method::RespMod {
            let (version, status) = parse_http_response_start_line(start)?;

            let mut builder = HttpResponse::builder().status(status).version(version);

            {
                let headers_mut = builder
                    .headers_mut()
                    .ok_or_else(|| Error::unexpected("response builder: headers_mut is None"))?;
                headers_mut.extend(http_headers);
            }

            let head = builder
                .body(())
                .map_err(|e| Error::http_parse(format!("build http::Response head: {e}")))?;

            Some(EmbeddedHttp::Resp {
                head,
                body: Body::Full { reader: body_bytes },
            })
        } else {
            let (http_method, uri, version) = parse_http_request_start_line(start)?;

            let mut builder = HttpRequest::builder()
                .method(http_method)
                .uri(uri)
                .version(version);

            {
                let headers_mut = builder
                    .headers_mut()
                    .ok_or_else(|| Error::unexpected("request builder: headers_mut is None"))?;
                headers_mut.extend(http_headers);
            }

            let head = builder
                .body(())
                .map_err(|e| Error::http_parse(format!("build http::Request head: {e}")))?;

            Some(EmbeddedHttp::Req {
                head,
                body: Body::Full { reader: body_bytes },
            })
        }
    } else {
        None
    };

    Ok(IncomingRequest::incoming(IncomingRequestParts {
        method,
        service,
        icap_headers,
        embedded,
        preview_size,
        allow_204,
        allow_206,
        preview_ieof: false,
    }))
}

fn validate_encapsulated_for_method(
    method: Method,
    enc: &crate::protocol::Encapsulated,
) -> IcapResult<()> {
    if enc.null_body.is_some()
        && (enc.req_body.is_some() || enc.res_body.is_some() || enc.opt_body.is_some())
    {
        return Err(Error::header(
            "Encapsulated null-body must not be combined with body tokens",
        ));
    }

    match method {
        Method::ReqMod => {
            if enc.res_hdr.is_some() || enc.res_body.is_some() || enc.opt_body.is_some() {
                return Err(Error::header(
                    "REQMOD Encapsulated must not contain response or opt-body parts",
                ));
            }
            if enc.req_body.is_some() && enc.req_hdr.is_none() {
                return Err(Error::header(
                    "REQMOD Encapsulated req-body requires req-hdr",
                ));
            }
        }
        Method::RespMod => {
            if enc.req_body.is_some() || enc.opt_body.is_some() {
                return Err(Error::header(
                    "RESPMOD Encapsulated must not contain req-body or opt-body parts",
                ));
            }
            if enc.res_body.is_some() && enc.res_hdr.is_none() {
                return Err(Error::header(
                    "RESPMOD Encapsulated res-body requires res-hdr",
                ));
            }
        }
        Method::Options => {
            if enc.req_hdr.is_some()
                || enc.res_hdr.is_some()
                || enc.req_body.is_some()
                || enc.res_body.is_some()
                || enc.opt_body.is_some()
            {
                return Err(Error::header(
                    "OPTIONS request Encapsulated must be absent or null-body",
                ));
            }
        }
    }

    Ok(())
}

fn next_offset_after(enc: &crate::protocol::Encapsulated, start: usize) -> Option<usize> {
    let mut min: Option<usize> = None;

    let mut consider = |v: Option<usize>| {
        if let Some(o) = v
            && o > start
        {
            min = Some(min.map_or(o, |m| m.min(o)));
        }
    };

    consider(enc.req_hdr);
    consider(enc.res_hdr);
    consider(enc.req_body);
    consider(enc.res_body);
    consider(enc.opt_body);
    consider(enc.null_body);

    min
}

fn slice_encapsulated(enc_area: &[u8], start: usize, end: Option<usize>) -> IcapResult<&[u8]> {
    if start > enc_area.len() {
        return Err(Error::header("Encapsulated offset out of bounds"));
    }
    let end = end.unwrap_or(enc_area.len());
    if end > enc_area.len() {
        return Err(Error::header("Encapsulated end offset out of bounds"));
    }
    if end < start {
        return Err(Error::header("Encapsulated offsets invalid (end < start)"));
    }
    Ok(&enc_area[start..end])
}

#[inline]
fn allow_contains_token(headers: &HeaderMap, token: &str) -> bool {
    headers
        .get("Allow")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.split(',').any(|p| p.trim().eq_ignore_ascii_case(token)))
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
    fn preview_zero_does_not_imply_ieof() {
        let req: Request = Request::reqmod("svc").preview(0);
        assert_eq!(req.preview_size, Some(0));
        assert!(!req.preview_ieof);

        let req: Request = Request::reqmod("svc").preview(0).preview_ieof();
        assert_eq!(req.preview_size, Some(0));
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
    fn try_icap_header_rejects_invalid_header_input() {
        let err = Request::<Vec<u8>>::options("icap/test")
            .try_icap_header("Bad Header", "value")
            .expect_err("invalid header name should be rejected");

        assert!(matches!(err, Error::Protocol(ProtocolError::HeaderName(_))));
    }

    #[test]
    fn try_new_rejects_unknown_method_without_panic() {
        let err = Request::<Vec<u8>>::try_new("PATCH", "svc")
            .expect_err("unknown method should be rejected");

        assert!(matches!(
            err,
            Error::Protocol(ProtocolError::InvalidField {
                field: ProtocolField::Method,
                ..
            })
        ));
    }

    #[test]
    fn parse_reqmod_body_uses_req_body_offset() {
        let http = b"GET / HTTP/1.1\r\nHost: ex\r\n\r\n";
        let body = b"12345678";

        let req_body_off = http.len(); // body starts immediately after HTTP headers

        let raw = format!(
            "REQMOD icap://icap.example.org/icap/test ICAP/1.0\r\n\
Host: icap.example.org\r\n\
Encapsulated: req-hdr=0, req-body={req_body_off}\r\n\
\r\n",
        )
        .into_bytes();

        let mut bytes = raw;
        bytes.extend_from_slice(http);
        bytes.extend_from_slice(body);

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

        let req: Request = Request::reqmod("svc").with_http_request(http_req).unwrap();
        assert!(matches!(req.embedded, Some(EmbeddedHttp::Req { .. })));

        let http_resp = HttpResponse::builder()
            .status(HttpStatus::OK)
            .version(Version::HTTP_11)
            .body(Vec::<u8>::new())
            .unwrap();

        let req2: Request = Request::respmod("svc")
            .with_http_response(http_resp)
            .unwrap();
        assert!(matches!(req2.embedded, Some(EmbeddedHttp::Resp { .. })));
    }

    #[test]
    fn builder_embeds_http_heads_without_buffered_body() {
        let req_head = HttpRequest::builder()
            .method("POST")
            .uri("/x")
            .version(Version::HTTP_11)
            .body(())
            .unwrap();
        let req: Request = Request::reqmod("svc")
            .with_http_request_head(req_head)
            .unwrap();
        assert!(matches!(
            req.embedded,
            Some(EmbeddedHttp::Req {
                body: Body::Empty,
                ..
            })
        ));

        let resp_head = HttpResponse::builder()
            .status(HttpStatus::OK)
            .version(Version::HTTP_11)
            .body(())
            .unwrap();
        let req2: Request = Request::respmod("svc")
            .with_http_response_head(resp_head)
            .unwrap();
        assert!(matches!(
            req2.embedded,
            Some(EmbeddedHttp::Resp {
                body: Body::Empty,
                ..
            })
        ));
    }

    #[test]
    fn validated_embedded_builders_reject_method_mismatch() {
        let http_req = HttpRequest::builder()
            .method("GET")
            .uri("/x")
            .version(Version::HTTP_11)
            .body(Vec::<u8>::new())
            .unwrap();

        let err = Request::respmod("svc")
            .with_http_request(http_req)
            .expect_err("RESPMOD must reject embedded HTTP requests");

        assert!(matches!(
            err,
            Error::Protocol(ProtocolError::Serialization(_))
        ));

        let http_resp = HttpResponse::builder()
            .status(HttpStatus::OK)
            .version(Version::HTTP_11)
            .body(Vec::<u8>::new())
            .unwrap();

        let err = Request::reqmod("svc")
            .with_http_response(http_resp)
            .expect_err("REQMOD must reject embedded HTTP responses");

        assert!(matches!(
            err,
            Error::Protocol(ProtocolError::Serialization(_))
        ));
    }

    #[test]
    fn validate_for_send_rejects_incoherent_request_shapes() {
        let req: Request = Request::reqmod("svc").preview(16).preview_ieof();
        let err = req
            .validate_for_send()
            .expect_err("ieof is only valid with Preview: 0");
        assert!(matches!(
            err,
            Error::Protocol(ProtocolError::Serialization(_))
        ));
    }

    // ---------- Version & framing ----------

    #[test]
    fn version_must_be_icap_1_0_in_request() {
        let raw = b"REQMOD icap://h/s ICAP/2.0\r\n\
                    Host: h\r\n\
                    Encapsulated: req-hdr=0\r\n\
                    \r\n";
        let err = parse_icap_request(raw).unwrap_err();
        assert!(
            matches!(err, Error::Protocol(ProtocolError::InvalidField { field: ProtocolField::Version, value: v, .. }) if v == "ICAP/2.0")
        );
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
             Encapsulated: null-body=0\r\n\
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
            matches!(err1, Error::Protocol(ProtocolError::MissingHeader(h)) if h == "Encapsulated"),
            "expected MissingHeader(Encapsulated); got: {err1}"
        );

        let raw_resp = b"RESPMOD icap://icap.example.org/icap/test ICAP/1.0\r\n\
                         Host: icap.example.org\r\n\
                         \r\n";
        let err2 = parse_icap_request(raw_resp).unwrap_err();
        assert!(
            matches!(err2, Error::Protocol(ProtocolError::MissingHeader(h)) if h == "Encapsulated"),
            "expected MissingHeader(Encapsulated); got: {err2}"
        );
    }

    #[test]
    fn invalid_encapsulated_token_is_rejected() {
        let raw = icap_bytes(
            "REQMOD icap://icap.example.org/icap/test ICAP/1.0\r\n\
             Host: icap.example.org\r\n\
             Encapsulated: req-hdr=0, bad-token=10\r\n\
             \r\n",
        );
        let err = parse_icap_request(&raw).unwrap_err();
        let m = err.to_string().to_lowercase();
        assert!(
            m.contains("encapsulated") || m.contains("invalid"),
            "expected Encapsulated parse error, got: {m}"
        );
    }

    #[test]
    fn duplicate_encapsulated_part_is_rejected() {
        let raw = icap_bytes(
            "RESPMOD icap://icap.example.org/icap/test ICAP/1.0\r\n\
             Host: icap.example.org\r\n\
             Encapsulated: res-hdr=0, res-hdr=10\r\n\
             \r\n",
        );
        let err = parse_icap_request(&raw).unwrap_err();
        let m = err.to_string().to_lowercase();
        assert!(
            m.contains("duplicate") && m.contains("encapsulated"),
            "expected duplicate Encapsulated part error, got: {m}"
        );
    }

    #[test]
    fn reqmod_rejects_response_oriented_encapsulated_parts() {
        let raw = icap_bytes(
            "REQMOD icap://icap.example.org/icap/test ICAP/1.0\r\n\
             Host: icap.example.org\r\n\
             Encapsulated: res-hdr=0\r\n\
             \r\n\
             HTTP/1.1 200 OK\r\n\
             Content-Length: 0\r\n\
             \r\n",
        );
        let err = parse_icap_request(&raw).unwrap_err();
        let m = err.to_string().to_lowercase();
        assert!(
            m.contains("reqmod") && m.contains("encapsulated"),
            "expected REQMOD Encapsulated validation error, got: {m}"
        );
    }

    #[test]
    fn respmod_rejects_request_body_encapsulated_part() {
        let raw = icap_bytes(
            "RESPMOD icap://icap.example.org/icap/test ICAP/1.0\r\n\
             Host: icap.example.org\r\n\
             Encapsulated: req-hdr=0, req-body=30\r\n\
             \r\n\
             GET / HTTP/1.1\r\n\
             Host: example.com\r\n\
             \r\n",
        );
        let err = parse_icap_request(&raw).unwrap_err();
        let m = err.to_string().to_lowercase();
        assert!(
            m.contains("respmod") && m.contains("encapsulated"),
            "expected RESPMOD Encapsulated validation error, got: {m}"
        );
    }

    #[test]
    fn null_body_must_not_be_combined_with_body_tokens() {
        let raw = icap_bytes(
            "REQMOD icap://icap.example.org/icap/test ICAP/1.0\r\n\
             Host: icap.example.org\r\n\
             Encapsulated: req-hdr=0, req-body=30, null-body=34\r\n\
             \r\n\
             GET / HTTP/1.1\r\n\
             Host: example.com\r\n\
             \r\n\
             body",
        );
        let err = parse_icap_request(&raw).unwrap_err();
        let m = err.to_string().to_lowercase();
        assert!(
            m.contains("null-body") && m.contains("body"),
            "expected null-body/body validation error, got: {m}"
        );
    }

    #[test]
    fn options_request_rejects_embedded_http_parts() {
        let raw = icap_bytes(
            "OPTIONS icap://icap.example.org/icap/test ICAP/1.0\r\n\
             Host: icap.example.org\r\n\
             Encapsulated: req-hdr=0\r\n\
             \r\n",
        );
        let err = parse_icap_request(&raw).unwrap_err();
        let m = err.to_string().to_lowercase();
        assert!(
            m.contains("options") && m.contains("encapsulated"),
            "expected OPTIONS Encapsulated validation error, got: {m}"
        );
    }

    #[test]
    fn compatibility_mode_accepts_options_without_encapsulated() {
        let raw = icap_bytes(
            "OPTIONS icap://icap.example.org/icap/test ICAP/1.0\r\n\
             Host: icap.example.org\r\n\
             \r\n",
        );
        let r = parse_icap_request_with_mode(&raw, RequestParserMode::Compatibility)
            .expect("compatibility mode keeps OPTIONS lenient");
        assert_eq!(r.method, Method::Options);
    }

    #[test]
    fn default_parser_requires_encapsulated_for_options() {
        let raw = icap_bytes(
            "OPTIONS icap://icap.example.org/icap/test ICAP/1.0\r\n\
             Host: icap.example.org\r\n\
             \r\n",
        );
        let err = parse_icap_request(&raw).unwrap_err();
        assert!(
            matches!(err, Error::Protocol(ProtocolError::MissingHeader(h)) if h == "Encapsulated"),
            "expected strict MissingHeader(Encapsulated), got: {err}"
        );
    }

    #[test]
    fn default_parser_accepts_options_with_null_body() {
        let raw = icap_bytes(
            "OPTIONS icap://icap.example.org/icap/test ICAP/1.0\r\n\
             Host: icap.example.org\r\n\
             Encapsulated: null-body=0\r\n\
             \r\n",
        );
        let r = parse_icap_request(&raw).expect("strict parse");
        assert_eq!(r.method, Method::Options);
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
    fn parse_preview_not_a_number_is_rejected() {
        // RFC 3507 §4.5: `Preview` value must be a non-negative integer; a
        // malformed value is a protocol error rather than "no preview".
        let raw = icap_bytes(
            "REQMOD icap://icap.example.org/icap/test ICAP/1.0\r\n\
             Host: icap.example.org\r\n\
             Preview: notanumber\r\n\
             Encapsulated: req-hdr=0\r\n\
             \r\n",
        );
        let err = parse_icap_request(&raw).expect_err("malformed Preview must error");
        let msg = err.to_string();
        assert!(
            msg.contains("Preview"),
            "error should mention Preview, got: {msg}"
        );
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
    fn rejects_incomplete_embedded_http_headers() {
        let raw = icap_bytes(
            "REQMOD icap://icap.example.org/icap/test ICAP/1.0\r\n\
             Host: icap.example.org\r\n\
             Encapsulated: req-hdr=0\r\n\
             \r\n\
             GET / HTTP/1.1\r\n\
             Host: example.com\r\n",
        );

        let err = parse_icap_request(&raw).unwrap_err();
        assert!(
            matches!(err, Error::Protocol(ProtocolError::HttpParse(_))),
            "expected embedded HTTP parse error, got: {err}"
        );
    }

    #[test]
    fn rejects_respmod_with_http_request_start_line() {
        let raw = icap_bytes(
            "RESPMOD icap://icap.example.org/icap/test ICAP/1.0\r\n\
             Host: icap.example.org\r\n\
             Encapsulated: res-hdr=0\r\n\
             \r\n\
             GET / HTTP/1.1\r\n\
             Host: example.com\r\n\
             \r\n",
        );

        let err = parse_icap_request(&raw).unwrap_err();
        assert!(
            matches!(err, Error::Protocol(ProtocolError::HttpParse(_))),
            "expected embedded HTTP status-line parse error, got: {err}"
        );
    }

    #[test]
    fn rejects_respmod_with_invalid_status_code() {
        let raw = icap_bytes(
            "RESPMOD icap://icap.example.org/icap/test ICAP/1.0\r\n\
             Host: icap.example.org\r\n\
             Encapsulated: res-hdr=0\r\n\
             \r\n\
             HTTP/1.1 nope OK\r\n\
             Content-Length: 0\r\n\
             \r\n",
        );

        let err = parse_icap_request(&raw).unwrap_err();
        assert!(
            matches!(err, Error::Protocol(ProtocolError::HttpParse(_))),
            "expected embedded HTTP status code parse error, got: {err}"
        );
    }

    #[test]
    fn parse_minimal_options_with_null_body() {
        let raw = icap_bytes(
            "OPTIONS icap://icap.example.org/icap/test ICAP/1.0\r\n\
             Host: icap.example.org\r\n\
             Encapsulated: null-body=0\r\n\
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
