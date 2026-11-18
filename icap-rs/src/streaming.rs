//! Bounded ICAP transactions over caller-owned transports and workspaces.
//!
//! This module allocates no buffers, opens no connections and starts no tasks.
//! The caller supplies the transport, request headers, head/framing workspaces,
//! body slices, deadlines and cancellation. A dropped I/O future poisons the
//! transaction; discard the transport after cancellation or any error.
//!
//! Call [`Transaction::start`], feed admitted slices with
//! [`Transaction::write_body`], and finish the preview or body. After the final
//! response head, read or discard the complete response body before accepting
//! the result. Response metadata remains borrowed from the head workspace.

use std::fmt::{self, Write as _};
use std::future::Future;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// An async byte transport.
///
/// Implementations must obey `Read`/`Write` byte-count
/// conventions. No allocation, buffering, timeout or ownership policy is implied.
/// All returned futures are `Send`; no operation outlives its caller.
pub trait Transport: Send {
    fn read(&mut self, out: &mut [u8]) -> impl Future<Output = io::Result<usize>> + Send;
    fn write(&mut self, bytes: &[u8]) -> impl Future<Output = io::Result<usize>> + Send;
    fn flush(&mut self) -> impl Future<Output = io::Result<()>> + Send;
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + ?Sized> Transport for T {
    async fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        AsyncReadExt::read(self, out).await
    }

    async fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        AsyncWriteExt::write(self, bytes).await
    }

    async fn flush(&mut self) -> io::Result<()> {
        AsyncWriteExt::flush(self).await
    }
}

/// Method used by the bounded API, independent of owned convenience types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method {
    Options,
    ReqMod,
    RespMod,
}

impl Method {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Options => "OPTIONS",
            Self::ReqMod => "REQMOD",
            Self::RespMod => "RESPMOD",
        }
    }
}

#[cfg(feature = "full")]
impl From<crate::Method> for Method {
    fn from(value: crate::Method) -> Self {
        match value {
            crate::Method::Options => Self::Options,
            crate::Method::ReqMod => Self::ReqMod,
            crate::Method::RespMod => Self::RespMod,
        }
    }
}

/// Borrowed request description. Embedded heads include their final CRLFCRLF.
///
/// `headers` may include pre-encoded authorization; this module never logs it.
/// Host, Preview and Encapsulated are generated and cannot be overridden.
#[derive(Clone, Copy, Debug)]
pub struct RequestHead<'a> {
    pub method: Method,
    pub uri: &'a str,
    pub host: &'a str,
    pub headers: &'a [(&'a str, &'a str)],
    pub http_request: &'a [u8],
    pub http_response: &'a [u8],
    pub preview: Option<u64>,
}

/// Bounded diagnostics deliberately do not retain wire input or credentials.
#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    InvalidInput(&'static str),
    Protocol(&'static str),
    Limit(&'static str),
    InvalidState,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "transport: {e}"),
            Self::InvalidInput(s) => write!(f, "invalid request: {s}"),
            Self::Protocol(s) => write!(f, "invalid ICAP response: {s}"),
            Self::Limit(s) => write!(f, "workspace limit: {s}"),
            Self::InvalidState => f.write_str("transaction unavailable in this state"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Result of preview negotiation. Final metadata is available via `response`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreviewOutcome {
    Continue,
    Final,
}

/// Validated borrowed ICAP response head; body completion is a separate step.
#[derive(Clone, Copy, Debug)]
pub struct ResponseHead<'a> {
    text: &'a str,
    code: u16,
}

impl<'a> ResponseHead<'a> {
    pub const fn status_code(&self) -> u16 {
        self.code
    }

    pub fn header(&self, name: &str) -> Option<&'a str> {
        self.headers()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value)
    }

    /// Returns all occurrences, preserving repeated application headers.
    /// With obsolete folding enabled, values include raw CRLF and continuation
    /// indentation. No unfolding allocation occurs; callers interpret values.
    pub fn headers(&self) -> impl Iterator<Item = (&'a str, &'a str)> + 'a {
        HeaderIter {
            remaining: self.text.split_once("\r\n").map_or("", |(_, rest)| rest),
        }
    }
}

struct HeaderIter<'a> {
    remaining: &'a str,
}

impl<'a> Iterator for HeaderIter<'a> {
    type Item = (&'a str, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        let first_end = self.remaining.find("\r\n")?;
        if first_end == 0 {
            return None;
        }
        let colon = self.remaining[..first_end].find(':')?;
        let mut end = first_end;
        while self.remaining[end + 2..].starts_with([' ', '\t']) {
            let rest = &self.remaining[end + 2..];
            end += 2 + rest.find("\r\n")?;
        }
        let result = (
            &self.remaining[..colon],
            self.remaining[colon + 1..end].trim_matches([' ', '\t']),
        );
        self.remaining = &self.remaining[end + 2..];
        Some(result)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Fresh,
    Preview,
    Upload,
    AwaitFinal,
    Response,
    Complete,
    Poisoned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Part {
    Request,
    Response,
    Body,
    Null,
}

#[derive(Clone, Copy)]
struct Encapsulation {
    ends: [usize; 2],
    kinds: [Part; 2],
    headers: usize,
    body: bool,
}

/// A single transaction using caller-owned storage.
///
/// The head workspace bounds both serialized request
/// heads and received ICAP heads, and the total encapsulated HTTP head bytes.
/// The line workspace bounds a chunk-size line and the complete trailer block.
/// Body length and preview length do not affect storage requirements.
///
/// On cancellation/error, discard this transaction and its transport. A new
/// transaction may reuse a successfully drained transport; connection policy
/// and server `Connection: close` handling belong to the caller.
pub struct Transaction<'a, T: Transport + ?Sized> {
    transport: &'a mut T,
    head: &'a mut [u8],
    line: &'a mut [u8],
    state: State,
    preview: u64,
    sent: u64,
    head_len: usize,
    buffered: usize,
    cursor: usize,
    code: u16,
    encapsulation: Encapsulation,
    embedded_done: bool,
    remaining: u64,
    chunk_crlf: bool,
    allow_obs_fold: bool,
}

impl<'a, T: Transport + ?Sized> Transaction<'a, T> {
    /// Workspaces must have at least four and 32 bytes respectively. Typical
    /// choices are 16 KiB for heads and 1 KiB for chunk framing/trailers.
    pub const fn new(
        transport: &'a mut T,
        head: &'a mut [u8],
        line: &'a mut [u8],
    ) -> Result<Self, Error> {
        if head.len() < 4 || line.len() < 32 {
            return Err(Error::InvalidInput("workspaces too small"));
        }
        Ok(Self {
            transport,
            head,
            line,
            state: State::Fresh,
            preview: 0,
            sent: 0,
            head_len: 0,
            buffered: 0,
            cursor: 0,
            code: 0,
            encapsulation: Encapsulation {
                ends: [0; 2],
                kinds: [Part::Request; 2],
                headers: 0,
                body: false,
            },
            embedded_done: false,
            remaining: 0,
            chunk_crlf: false,
            allow_obs_fold: false,
        })
    }

    /// Opt into obsolete folding in incoming ICAP extension headers.
    ///
    /// Call before `start`. Strict parsing is the default. Continuations must
    /// follow a valid field and share the head workspace limit. Protocol and
    /// framing fields cannot be folded. Values retain raw CRLF/indentation.
    pub fn allow_obs_fold(&mut self, allow: bool) -> Result<(), Error> {
        self.require(State::Fresh)?;
        self.allow_obs_fold = allow;
        Ok(())
    }

    /// Serialize the ICAP and embedded heads into caller storage before I/O.
    /// OPTIONS has no body and immediately becomes ready for a response.
    pub async fn start(&mut self, request: RequestHead<'_>) -> Result<(), Error> {
        self.require(State::Fresh)?;
        self.state = State::Poisoned;
        let len = serialize_request(self.head, request)?;
        write_all(self.transport, &self.head[..len]).await?;
        self.transport.flush().await?;
        self.preview = request.preview.unwrap_or(0);
        self.state = if request.method == Method::Options {
            State::AwaitFinal
        } else if request.preview.is_some() {
            State::Preview
        } else {
            State::Upload
        };
        Ok(())
    }

    /// Send one chunk directly from a caller slice. Empty slices are no-ops.
    /// Preview feeds may not exceed the advertised byte count.
    pub async fn write_body(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if !matches!(self.state, State::Preview | State::Upload) {
            return Err(Error::InvalidState);
        }
        let previous = self.state;
        self.state = State::Poisoned;
        let count = u64::try_from(bytes.len()).map_err(|_| Error::Limit("body length"))?;
        let sent = self
            .sent
            .checked_add(count)
            .ok_or(Error::Limit("body length"))?;
        if previous == State::Preview && sent > self.preview {
            return Err(Error::InvalidInput("preview exceeded"));
        }
        if !bytes.is_empty() {
            let mut line = Buffer::new(self.line);
            write!(line, "{:x}\r\n", bytes.len()).map_err(|_| Error::Limit("chunk line"))?;
            write_all(self.transport, line.written()).await?;
            write_all(self.transport, bytes).await?;
            write_all(self.transport, b"\r\n").await?;
        }
        self.sent = sent;
        self.state = previous;
        Ok(())
    }

    /// End preview and read the peer decision. Non-EOF previews must exactly
    /// fill the advertised count. EOF forbids a subsequent 100 Continue.
    pub async fn finish_preview(&mut self, eof: bool) -> Result<PreviewOutcome, Error> {
        self.require(State::Preview)?;
        self.state = State::Poisoned;
        if !eof && self.sent != self.preview {
            return Err(Error::InvalidInput("incomplete preview"));
        }
        let end: &[u8] = if eof {
            b"0; ieof\r\n\r\n"
        } else {
            b"0\r\n\r\n"
        };
        write_all(self.transport, end).await?;
        self.transport.flush().await?;
        self.receive_head().await?;
        if self.code == 100 {
            if eof || self.encapsulation.body || self.encapsulation.headers != 0 {
                return Err(Error::Protocol("unexpected continue"));
            }
            self.state = State::Upload;
            Ok(PreviewOutcome::Continue)
        } else {
            self.state = State::Response;
            Ok(PreviewOutcome::Final)
        }
    }

    /// Terminate a non-preview body (or the remainder after 100 Continue).
    pub async fn finish_body(&mut self) -> Result<(), Error> {
        self.require(State::Upload)?;
        self.state = State::Poisoned;
        write_all(self.transport, b"0\r\n\r\n").await?;
        self.transport.flush().await?;
        self.state = State::AwaitFinal;
        Ok(())
    }

    /// Read and validate a final response head. This does not establish that
    /// the encapsulated response has arrived completely; drain its body too.
    pub async fn read_response(&mut self) -> Result<(), Error> {
        self.require(State::AwaitFinal)?;
        self.state = State::Poisoned;
        self.receive_head().await?;
        if self.code < 200 {
            return Err(Error::Protocol("unexpected informational response"));
        }
        self.state = State::Response;
        Ok(())
    }

    /// Available after a final head and after successful body completion.
    pub fn response(&self) -> Option<ResponseHead<'_>> {
        if !matches!(self.state, State::Response | State::Complete) {
            return None;
        }
        Some(ResponseHead {
            // receive_head validates UTF-8 before publishing a response.
            text: std::str::from_utf8(&self.head[..self.head_len]).ok()?,
            code: self.code,
        })
    }

    /// Read decoded entity bytes; embedded HTTP heads are validated/discarded.
    /// Zero indicates complete validated framing, including all trailers.
    /// An empty output is rejected so it cannot be mistaken for completion.
    pub async fn read_body(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        if out.is_empty() {
            return Err(Error::InvalidInput("empty body output"));
        }
        if self.state == State::Complete {
            return Ok(0);
        }
        self.require(State::Response)?;
        self.state = State::Poisoned;
        if !self.embedded_done {
            self.skip_embedded().await?;
            self.embedded_done = true;
        }
        if !self.encapsulation.body {
            self.complete()?;
            return Ok(0);
        }
        if self.remaining == 0 {
            if self.chunk_crlf && (self.byte().await? != b'\r' || self.byte().await? != b'\n') {
                return Err(Error::Protocol("missing chunk CRLF"));
            }
            let n = self.read_line().await?;
            self.remaining = parse_chunk_line(&self.line[..n])?;
            if self.remaining == 0 {
                self.read_trailers().await?;
                self.complete()?;
                return Ok(0);
            }
            self.chunk_crlf = true;
        }
        let take = usize::try_from(self.remaining)
            .unwrap_or(usize::MAX)
            .min(out.len());
        let n = self.read_bytes(&mut out[..take]).await?;
        self.remaining -= u64::try_from(n).map_err(|_| Error::Limit("body length"))?;
        self.state = State::Response;
        Ok(n)
    }

    /// Drain a response using only caller-owned scratch; retains the ICAP head.
    pub async fn discard_body(&mut self, scratch: &mut [u8]) -> Result<(), Error> {
        while self.read_body(scratch).await? != 0 {}
        Ok(())
    }

    fn require(&self, state: State) -> Result<(), Error> {
        if self.state == state {
            Ok(())
        } else {
            Err(Error::InvalidState)
        }
    }

    const fn complete(&mut self) -> Result<(), Error> {
        if self.cursor != self.buffered {
            return Err(Error::Protocol("bytes after response boundary"));
        }
        self.state = State::Complete;
        Ok(())
    }

    async fn receive_head(&mut self) -> Result<(), Error> {
        // Preserve read-ahead after an interim head without allocating.
        self.head.copy_within(self.cursor..self.buffered, 0);
        self.buffered -= self.cursor;
        self.cursor = 0;
        let end = loop {
            if let Some(n) = double_crlf(&self.head[..self.buffered]) {
                break n;
            }
            if self.buffered == self.head.len() {
                return Err(Error::Limit("ICAP head"));
            }
            let n = self.transport.read(&mut self.head[self.buffered..]).await?;
            if n == 0 {
                return Err(Error::Protocol("EOF in ICAP head"));
            }
            self.buffered += n;
        };
        let response = validate_response(&self.head[..end], self.allow_obs_fold)?;
        self.code = response.code;
        self.encapsulation = parse_encapsulation(response, self.head.len())?;
        self.head_len = end;
        self.cursor = end;
        self.embedded_done = false;
        self.remaining = 0;
        self.chunk_crlf = false;
        Ok(())
    }

    async fn byte(&mut self) -> Result<u8, Error> {
        let mut byte = [0];
        self.read_bytes(&mut byte).await?;
        Ok(byte[0])
    }

    async fn read_bytes(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        if self.cursor < self.buffered {
            let n = out.len().min(self.buffered - self.cursor);
            out[..n].copy_from_slice(&self.head[self.cursor..self.cursor + n]);
            self.cursor += n;
            return Ok(n);
        }
        let n = self.transport.read(out).await?;
        if n == 0 {
            Err(Error::Protocol("truncated response"))
        } else {
            Ok(n)
        }
    }

    async fn read_line(&mut self) -> Result<usize, Error> {
        let mut used = 0;
        loop {
            if used == self.line.len() {
                return Err(Error::Limit("framing line"));
            }
            let byte = self.byte().await?;
            self.line[used] = byte;
            used += 1;
            if used >= 2 && &self.line[used - 2..used] == b"\r\n" {
                return Ok(used - 2);
            }
        }
    }

    async fn skip_embedded(&mut self) -> Result<(), Error> {
        let mut previous = 0;
        for index in 0..self.encapsulation.headers {
            let end = self.encapsulation.ends[index];
            let mut remaining = end - previous;
            let mut start_line = true;
            while remaining > 0 {
                let n = self.read_line().await?;
                remaining = remaining
                    .checked_sub(n + 2)
                    .ok_or(Error::Protocol("encapsulated offset splits a line"))?;
                if start_line {
                    validate_http_start(&self.line[..n], self.encapsulation.kinds[index])?;
                    start_line = false;
                } else if n == 0 {
                    if remaining != 0 {
                        return Err(Error::Protocol("encapsulated header offset mismatch"));
                    }
                } else {
                    validate_field(&self.line[..n])?;
                }
                if remaining == 0 && n != 0 {
                    return Err(Error::Protocol("unterminated encapsulated head"));
                }
            }
            previous = end;
        }
        Ok(())
    }

    async fn read_trailers(&mut self) -> Result<(), Error> {
        let mut total = 0usize;
        loop {
            let n = self.read_line().await?;
            total = total.checked_add(n + 2).ok_or(Error::Limit("trailers"))?;
            if total > self.line.len() {
                return Err(Error::Limit("trailers"));
            }
            if n == 0 {
                return Ok(());
            }
            let (name, _) = validate_field(&self.line[..n])?;
            if [
                "Encapsulated",
                "ISTag",
                "Preview",
                "Content-Length",
                "Transfer-Encoding",
            ]
            .iter()
            .any(|reserved| name.eq_ignore_ascii_case(reserved))
            {
                return Err(Error::Protocol("framing or identity trailer"));
            }
        }
    }
}

async fn write_all<T: Transport + ?Sized>(
    transport: &mut T,
    mut bytes: &[u8],
) -> Result<(), Error> {
    while !bytes.is_empty() {
        let n = transport.write(bytes).await?;
        if n == 0 {
            return Err(Error::Io(io::ErrorKind::WriteZero.into()));
        }
        bytes = &bytes[n..];
    }
    Ok(())
}

struct Buffer<'a> {
    bytes: &'a mut [u8],
    used: usize,
}

impl<'a> Buffer<'a> {
    const fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, used: 0 }
    }
    fn written(&self) -> &[u8] {
        &self.bytes[..self.used]
    }
    fn add(&mut self, bytes: &[u8]) -> fmt::Result {
        let end = self.used.checked_add(bytes.len()).ok_or(fmt::Error)?;
        let out = self.bytes.get_mut(self.used..end).ok_or(fmt::Error)?;
        out.copy_from_slice(bytes);
        self.used = end;
        Ok(())
    }
}

impl fmt::Write for Buffer<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.add(s.as_bytes())
    }
}

fn serialize_request(out: &mut [u8], request: RequestHead<'_>) -> Result<usize, Error> {
    if !request.uri.starts_with("icap://") && !request.uri.starts_with("icaps://") {
        return Err(Error::InvalidInput("absolute ICAP URI required"));
    }
    if !clean_word(request.uri.as_bytes()) || !clean_word(request.host.as_bytes()) {
        return Err(Error::InvalidInput("URI or host"));
    }
    match request.method {
        Method::Options => {
            if !request.http_request.is_empty()
                || !request.http_response.is_empty()
                || request.preview.is_some()
            {
                return Err(Error::InvalidInput("OPTIONS has no embedded request body"));
            }
        }
        Method::ReqMod => {
            validate_http_head(request.http_request, Part::Request)?;
            if !request.http_response.is_empty() {
                return Err(Error::InvalidInput("REQMOD response head"));
            }
        }
        Method::RespMod => {
            if !request.http_request.is_empty() {
                validate_http_head(request.http_request, Part::Request)?;
            }
            validate_http_head(request.http_response, Part::Response)?;
        }
    }
    for &(name, value) in request.headers {
        if name.is_empty() || !name.bytes().all(token) || !field_value(value.as_bytes()) {
            return Err(Error::InvalidInput("header syntax"));
        }
        if [
            "Host",
            "Preview",
            "Encapsulated",
            "Content-Length",
            "Transfer-Encoding",
        ]
        .iter()
        .any(|reserved| name.eq_ignore_ascii_case(reserved))
        {
            return Err(Error::InvalidInput("reserved header"));
        }
    }
    let mut buffer = Buffer::new(out);
    let result = (|| -> fmt::Result {
        write!(
            buffer,
            "{} {} ICAP/1.0\r\nHost: {}\r\n",
            request.method.as_str(),
            request.uri,
            request.host
        )?;
        for &(name, value) in request.headers {
            write!(buffer, "{name}: {value}\r\n")?;
        }
        if let Some(preview) = request.preview {
            write!(buffer, "Preview: {preview}\r\n")?;
        }
        match request.method {
            Method::Options => buffer.add(b"Encapsulated: null-body=0\r\n\r\n")?,
            Method::ReqMod => write!(
                buffer,
                "Encapsulated: req-hdr=0, req-body={}\r\n\r\n",
                request.http_request.len()
            )?,
            Method::RespMod => {
                buffer.add(b"Encapsulated: ")?;
                if !request.http_request.is_empty() {
                    buffer.add(b"req-hdr=0, ")?;
                }
                let body = request
                    .http_request
                    .len()
                    .checked_add(request.http_response.len())
                    .ok_or(fmt::Error)?;
                write!(
                    buffer,
                    "res-hdr={}, res-body={body}\r\n\r\n",
                    request.http_request.len()
                )?;
            }
        }
        buffer.add(request.http_request)?;
        buffer.add(request.http_response)
    })();
    result.map_err(|_| Error::Limit("request head"))?;
    Ok(buffer.used)
}

fn double_crlf(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|b| b == b"\r\n\r\n")
        .map(|p| p + 4)
}

fn token(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn clean_word(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(u8::is_ascii_graphic)
}

fn field_value(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == b'\t' || b >= 32 && b != 127)
}

fn validate_field(bytes: &[u8]) -> Result<(&str, &str), Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::Protocol("header encoding"))?;
    let (name, value) = text
        .split_once(':')
        .ok_or(Error::Protocol("missing header colon"))?;
    if name.is_empty() || !name.bytes().all(token) || !field_value(value.as_bytes()) {
        return Err(Error::Protocol("header syntax"));
    }
    Ok((name, value.trim_matches([' ', '\t'])))
}

fn validate_http_start(bytes: &[u8], kind: Part) -> Result<(), Error> {
    if !field_value(bytes) {
        return Err(Error::Protocol("embedded HTTP start line"));
    }
    let mut parts = bytes.split(|&b| b == b' ');
    let a = parts.next().unwrap_or_default();
    let b = parts.next().unwrap_or_default();
    let c = parts.next().unwrap_or_default();
    let version = |s: &[u8]| s == b"HTTP/1.0" || s == b"HTTP/1.1";
    let valid = if kind == Part::Response {
        version(a) && b.len() == 3 && b.iter().all(u8::is_ascii_digit) && field_value(c)
    } else {
        !a.is_empty()
            && a.iter().copied().all(token)
            && clean_word(b)
            && version(c)
            && parts.next().is_none()
    };
    if valid {
        Ok(())
    } else {
        Err(Error::Protocol("embedded HTTP start line"))
    }
}

fn validate_http_head(bytes: &[u8], kind: Part) -> Result<(), Error> {
    if double_crlf(bytes) != Some(bytes.len()) {
        return Err(Error::InvalidInput("embedded HTTP terminator"));
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| Error::InvalidInput("embedded HTTP encoding"))?;
    let mut lines = text.split("\r\n");
    validate_http_start(lines.next().unwrap_or_default().as_bytes(), kind)?;
    for line in lines.take_while(|s| !s.is_empty()) {
        validate_field(line.as_bytes())?;
    }
    Ok(())
}

fn validate_response(bytes: &[u8], allow_obs_fold: bool) -> Result<ResponseHead<'_>, Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::Protocol("ICAP head encoding"))?;
    let mut lines = text.split("\r\n");
    let status = lines.next().ok_or(Error::Protocol("missing status line"))?;
    let mut parts = status.splitn(3, ' ');
    if parts.next() != Some("ICAP/1.0") {
        return Err(Error::Protocol("ICAP version"));
    }
    let digits = parts.next().unwrap_or_default();
    if digits.len() != 3 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Protocol("status code"));
    }
    let code: u16 = digits.parse().map_err(|_| Error::Protocol("status code"))?;
    if !(100..=599).contains(&code) || code < 200 && code != 100 {
        return Err(Error::Protocol("unsupported status"));
    }
    if code == 206 {
        return Err(Error::Protocol("partial responses unsupported"));
    }
    if !field_value(parts.next().unwrap_or_default().as_bytes()) {
        return Err(Error::Protocol("status reason"));
    }
    let mut tag = false;
    let mut may_fold = false;
    let mut singletons = 0u32;
    for line in lines.take_while(|s| !s.is_empty()) {
        if line.starts_with([' ', '\t']) {
            if !allow_obs_fold || !may_fold || !field_value(line.as_bytes()) {
                return Err(Error::Protocol("invalid header continuation"));
            }
            continue;
        }
        let (name, value) = validate_field(line.as_bytes())?;
        let singleton = singleton_bit(name);
        may_fold = singleton == 0;
        if singletons & singleton != 0 {
            return Err(Error::Protocol("duplicate protocol header"));
        }
        singletons |= singleton;
        if name.eq_ignore_ascii_case("ISTag") {
            validate_tag(value)?;
            tag = true;
        }
    }
    if (200..300).contains(&code) && !tag {
        return Err(Error::Protocol("missing ISTag"));
    }
    Ok(ResponseHead { text, code })
}

fn singleton_bit(name: &str) -> u32 {
    [
        "Encapsulated",
        "ISTag",
        "Preview",
        "Content-Length",
        "Transfer-Encoding",
        "Connection",
        "Options-TTL",
        "Max-Connections",
        "Methods",
        "Transfer-Preview",
        "Transfer-Ignore",
        "Transfer-Complete",
    ]
    .iter()
    .position(|reserved| name.eq_ignore_ascii_case(reserved))
    .map_or(0, |index| 1u32 << index)
}

fn validate_tag(value: &str) -> Result<(), Error> {
    let bytes = value.as_bytes();
    let mut count = 0;
    if bytes.first() == Some(&b'"') {
        if bytes.len() < 2 || bytes.last() != Some(&b'"') {
            return Err(Error::Protocol("ISTag quotes"));
        }
        let mut inner = bytes[1..bytes.len() - 1].iter().copied();
        while let Some(b) = inner.next() {
            let escaped = if b == b'\\' {
                inner.next().ok_or(Error::Protocol("ISTag escape"))?
            } else {
                b
            };
            if escaped < 32 || escaped == 127 || b == b'"' {
                return Err(Error::Protocol("ISTag syntax"));
            }
            count += 1;
        }
    } else {
        if bytes.is_empty() || !bytes.iter().all(|&b| token(b) || b == b'/' || b == b'=') {
            return Err(Error::Protocol("ISTag syntax"));
        }
        count = bytes.len();
    }
    if count > 32 {
        return Err(Error::Protocol("ISTag length"));
    }
    Ok(())
}

fn parse_encapsulation(response: ResponseHead<'_>, max: usize) -> Result<Encapsulation, Error> {
    let mut enc = Encapsulation {
        ends: [0; 2],
        kinds: [Part::Request; 2],
        headers: 0,
        body: false,
    };
    let Some(value) = response.header("Encapsulated") else {
        if (200..300).contains(&response.code) {
            return Err(Error::Protocol("missing Encapsulated"));
        }
        return Ok(enc);
    };
    let mut previous = None;
    let mut terminal = false;
    for part in value.split(',') {
        if terminal {
            return Err(Error::Protocol("part after encapsulated body"));
        }
        let (name, value) = part
            .trim()
            .split_once('=')
            .ok_or(Error::Protocol("Encapsulated syntax"))?;
        let offset = decimal(value.trim())?;
        if previous.is_none() && offset != 0 {
            return Err(Error::Protocol("first encapsulated offset"));
        }
        if let Some(last) = previous {
            if offset <= last {
                return Err(Error::Protocol("encapsulated offsets not increasing"));
            }
            enc.ends[enc.headers - 1] = offset;
        }
        let kind = if name.eq_ignore_ascii_case("req-hdr") {
            Part::Request
        } else if name.eq_ignore_ascii_case("res-hdr") {
            Part::Response
        } else if ["req-body", "res-body", "opt-body"]
            .iter()
            .any(|v| name.eq_ignore_ascii_case(v))
        {
            Part::Body
        } else if name.eq_ignore_ascii_case("null-body") {
            Part::Null
        } else {
            return Err(Error::Protocol("unknown encapsulated part"));
        };
        if kind == Part::Request || kind == Part::Response {
            if enc.headers == 2
                || enc.headers > 0 && (kind != Part::Response || enc.kinds[0] != Part::Request)
            {
                return Err(Error::Protocol("encapsulated header order"));
            }
            enc.kinds[enc.headers] = kind;
            enc.headers += 1;
        } else {
            terminal = true;
            enc.body = kind == Part::Body;
        }
        if offset > max {
            return Err(Error::Limit("encapsulated heads"));
        }
        previous = Some(offset);
    }
    if !terminal {
        return Err(Error::Protocol("missing encapsulated body marker"));
    }
    if (response.code == 100 || response.code == 204) && (enc.body || enc.headers != 0) {
        return Err(Error::Protocol("body on continue or no-content"));
    }
    Ok(enc)
}

fn decimal(value: &str) -> Result<usize, Error> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Protocol("offset syntax"));
    }
    value
        .parse()
        .map_err(|_| Error::Protocol("offset overflow"))
}

fn parse_chunk_line(line: &[u8]) -> Result<u64, Error> {
    let mut parts = line.splitn(2, |&b| b == b';');
    let size = parts.next().unwrap_or_default();
    if size.is_empty() || !size.iter().all(u8::is_ascii_hexdigit) {
        return Err(Error::Protocol("chunk size"));
    }
    let mut value = 0u64;
    for &b in size {
        let digit = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            _ => b - b'A' + 10,
        };
        value = value
            .checked_mul(16)
            .and_then(|v| v.checked_add(u64::from(digit)))
            .ok_or(Error::Protocol("chunk size overflow"))?;
    }
    if let Some(extension) = parts.next() {
        // use-original-body and ieof require application semantics not offered
        // by this decoded-body API. Never silently treat a partial body as full.
        if value == 0 {
            return Err(Error::Protocol("unsupported terminal chunk extension"));
        }
        if !field_value(extension) {
            return Err(Error::Protocol("chunk extension"));
        }
    }
    Ok(value)
}
