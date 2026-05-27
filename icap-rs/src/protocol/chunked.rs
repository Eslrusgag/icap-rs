use crate::error::{Error, IcapResult};
use http::{HeaderMap, HeaderName, HeaderValue};
use memchr::{memchr, memmem};
use std::io::Write;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkMeta {
    pub next_pos: usize,
    pub is_zero: bool,
    pub has_ieof: bool,
    pub size: usize,
}

/// Parse a single chunk: returns (`next_pos`, `is_final_zero`, size).
pub fn parse_one_chunk(buf: &[u8], from: usize) -> Option<(usize, bool, usize)> {
    let mut i = from;
    while i + 1 < buf.len() {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' {
            let size_line = &buf[from..i];
            let size_hex = size_line.split(|&b| b == b';').next().unwrap_or(size_line);
            let size_str = std::str::from_utf8(size_hex).ok()?.trim();
            let size = usize::from_str_radix(size_str, 16).ok()?;
            let after_size = i + 2;
            let need = after_size + size + 2;
            if buf.len() < need {
                return None;
            }
            if size == 0 {
                if buf.len() < after_size + 2 {
                    return None;
                }
                return Some((after_size, true, 0));
            }
            return Some((need, false, size));
        }
        i += 1;
    }
    None
}

pub fn parse_one_chunk_meta(buf: &[u8], from: usize) -> IcapResult<Option<ChunkMeta>> {
    if from >= buf.len() {
        return Ok(None);
    }

    let rel = memmem::find(&buf[from..], b"\r\n");
    let Some(line_end_rel) = rel else {
        return Ok(None);
    };
    let line_end = from + line_end_rel;
    let size_line = &buf[from..line_end];
    let after_size = line_end + 2;

    let (size_hex, ext_part) = memchr(b';', size_line).map_or((size_line, None), |i| {
        (&size_line[..i], Some(&size_line[i + 1..]))
    });

    let size_str = std::str::from_utf8(size_hex)
        .map_err(|_| Error::body("chunk size not utf8"))?
        .trim();
    let size =
        usize::from_str_radix(size_str, 16).map_err(|_| Error::body("chunk size not hex"))?;

    let has_ieof = ext_part
        .and_then(|b| std::str::from_utf8(b).ok())
        .is_some_and(|s| s.split(';').any(|t| t.trim().eq_ignore_ascii_case("ieof")));

    if size == 0 {
        if buf.len() < after_size + 2 {
            return Ok(None);
        }
        if &buf[after_size..after_size + 2] != b"\r\n" {
            return Err(Error::body("invalid chunked terminator"));
        }
        return Ok(Some(ChunkMeta {
            next_pos: after_size + 2,
            is_zero: true,
            has_ieof,
            size: 0,
        }));
    }

    let need = after_size + size + 2;
    if buf.len() < need {
        return Ok(None);
    }
    if &buf[after_size + size..need] != b"\r\n" {
        return Err(Error::body("missing CRLF after chunk"));
    }
    Ok(Some(ChunkMeta {
        next_pos: need,
        is_zero: false,
        has_ieof: false,
        size,
    }))
}

/// Parse HTTP-style chunk trailers that follow the zero chunk.
///
/// RFC 7230 §4.1.2 (and RFC 3507 §6.3 by reference) allows zero or more
/// `Name: Value` trailer headers after the `0\r\n` terminator, each ending
/// with `\r\n`, followed by a final empty `\r\n`.
///
/// `data` must start immediately after the `0\r\n` zero-chunk line.
///
/// Returns `(trailers, bytes_consumed)` where `bytes_consumed` includes the
/// final empty `\r\n`.  When there are no trailers (`data` starts with `\r\n`)
/// the returned `HeaderMap` is empty and `bytes_consumed` is 2.
#[must_use]
pub fn parse_chunk_trailers(data: &[u8]) -> IcapResult<(HeaderMap, usize)> {
    let mut trailers = HeaderMap::new();
    let mut pos = 0;
    loop {
        if data.len() < pos + 2 {
            return Err(Error::body("incomplete chunk trailers: truncated data"));
        }
        // Empty line terminates the trailer block.
        if &data[pos..pos + 2] == b"\r\n" {
            return Ok((trailers, pos + 2));
        }
        // Find the CRLF that ends this trailer line.
        let Some(crlf_rel) = memmem::find(&data[pos..], b"\r\n") else {
            return Err(Error::body("incomplete chunk trailer: missing CRLF"));
        };
        let line = &data[pos..pos + crlf_rel];
        pos += crlf_rel + 2;
        // Split on the first ':'.
        let colon =
            memchr(b':', line).ok_or_else(|| Error::body("malformed chunk trailer: missing ':'"))?;
        let name_str = std::str::from_utf8(&line[..colon])
            .map_err(|_| Error::body("chunk trailer name is not UTF-8"))?
            .trim();
        let value_str = std::str::from_utf8(&line[colon + 1..])
            .map_err(|_| Error::body("chunk trailer value is not UTF-8"))?
            .trim();
        let name = HeaderName::from_bytes(name_str.as_bytes())
            .map_err(|_| Error::body("invalid chunk trailer name"))?;
        let value = HeaderValue::from_str(value_str)
            .map_err(|_| Error::body("invalid chunk trailer value"))?;
        trailers.insert(name, value);
    }
}

/// Drain ICAP chunked body until zero chunk. Returns position after final CRLF.
pub async fn read_chunked_to_end<S>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    mut pos: usize,
) -> IcapResult<usize>
where
    S: AsyncRead + Unpin,
{
    loop {
        if let Some((next_pos, is_final, _)) = parse_one_chunk(buf, pos) {
            if is_final {
                // `next_pos` is right after `0\r\n`.  Scan line-by-line until
                // an empty `\r\n` signals the end of the (possibly empty)
                // trailer block.  RFC 7230 §4.1.2, RFC 3507 §6.3.
                pos = next_pos;
                loop {
                    // Ensure at least 2 bytes are buffered at `pos`.
                    while buf.len() < pos + 2 {
                        let mut tmp = [0u8; 4096];
                        let n = AsyncReadExt::read(stream, &mut tmp).await?;
                        if n == 0 {
                            return Err(Error::body("unexpected EOF in chunk trailer block"));
                        }
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    // Find the CRLF that ends the current line at `pos`.
                    let crlf_rel = loop {
                        if let Some(rel) = memmem::find(&buf[pos..], b"\r\n") {
                            break rel;
                        }
                        let mut tmp = [0u8; 4096];
                        let n = AsyncReadExt::read(stream, &mut tmp).await?;
                        if n == 0 {
                            return Err(Error::body("unexpected EOF in chunk trailer block"));
                        }
                        buf.extend_from_slice(&tmp[..n]);
                    };
                    pos += crlf_rel + 2;
                    if crlf_rel == 0 {
                        // Empty line — end of trailer block.
                        return Ok(pos);
                    }
                    // Non-empty line — a trailer header; continue to next line.
                }
            }
            pos = next_pos;
        } else {
            let mut tmp = [0u8; 4096];
            let n = AsyncReadExt::read(stream, &mut tmp).await?;
            if n == 0 {
                return Err(Error::body(
                    "unexpected EOF while reading ICAP chunked body",
                ));
            }
            buf.extend_from_slice(&tmp[..n]);
        }
    }
}

pub async fn read_chunked_until_zero<S>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    mut pos: usize,
) -> IcapResult<(usize, bool)>
where
    S: AsyncRead + Unpin,
{
    loop {
        if let Some(meta) = parse_one_chunk_meta(buf, pos)? {
            if meta.is_zero {
                return Ok((meta.next_pos, meta.has_ieof));
            }
            pos = meta.next_pos;
        } else {
            let mut tmp = [0u8; 4096];
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(Error::body(
                    "unexpected EOF while reading ICAP preview body",
                ));
            }
            buf.extend_from_slice(&tmp[..n]);
        }
    }
}

/// Decode a complete ICAP chunked body.
///
/// Returns `(body, trailers)` where `trailers` contains any RFC 7230 §4.1.2
/// chunk trailer headers found after the zero chunk.  When no trailers are
/// present the map is empty.
pub fn dechunk_icap_entity(data: &mut &[u8]) -> IcapResult<(Vec<u8>, HeaderMap)> {
    let mut out = Vec::with_capacity((*data).len());
    let mut d = *data;

    loop {
        let crlf_pos =
            memmem::find(d, b"\r\n").ok_or_else(|| Error::body("chunk size line without CRLF"))?;
        let (size_line, rest) = d.split_at(crlf_pos);
        d = &rest[2..];

        let size_hex = memchr(b';', size_line).map_or(size_line, |i| &size_line[..i]);

        let size_str =
            core::str::from_utf8(size_hex).map_err(|_| Error::body("chunk size not utf8"))?;
        let size = usize::from_str_radix(size_str.trim(), 16)
            .map_err(|_| Error::body("chunk size not hex"))?;

        if size == 0 {
            let (trailers, consumed) = parse_chunk_trailers(d)?;
            d = &d[consumed..];
            *data = d;
            return Ok((out, trailers));
        }

        if d.len() < size + 2 {
            return Err(Error::body("incomplete chunk data"));
        }

        out.extend_from_slice(&d[..size]);

        if &d[size..size + 2] != b"\r\n" {
            return Err(Error::body("missing CRLF after chunk"));
        }

        d = &d[size + 2..];
    }
}

/// Decode a complete ICAP chunked body, also detecting the `ieof` extension.
///
/// Returns `(body, ieof, trailers)`.  `ieof` is `true` when the zero chunk
/// carries the `; ieof` extension (RFC 3507 §4.5).  `trailers` contains any
/// RFC 7230 §4.1.2 trailer headers; empty when none are present.
pub fn dechunk_icap_entity_with_ieof(data: &mut &[u8]) -> IcapResult<(Vec<u8>, bool, HeaderMap)> {
    let mut out = Vec::with_capacity((*data).len());
    let mut d = *data;
    let ieof;
    loop {
        let rel =
            memmem::find(d, b"\r\n").ok_or_else(|| Error::body("chunk size line without CRLF"))?;
        let line = &d[..rel];
        d = &d[rel + 2..];

        let (size_hex, ext_part) =
            memchr(b';', line).map_or((line, None), |i| (&line[..i], Some(&line[i + 1..])));

        let size_str =
            std::str::from_utf8(size_hex).map_err(|_| Error::body("chunk size not utf8"))?;
        let size = usize::from_str_radix(size_str.trim(), 16)
            .map_err(|_| Error::body("chunk size not hex"))?;

        let has_ieof = ext_part
            .and_then(|b| std::str::from_utf8(b).ok())
            .is_some_and(|s| s.split(';').any(|t| t.trim().eq_ignore_ascii_case("ieof")));

        if size == 0 {
            ieof = has_ieof;
            break;
        }

        if d.len() < size + 2 {
            return Err(Error::body("incomplete chunk data"));
        }
        out.extend_from_slice(&d[..size]);
        if &d[size..size + 2] != b"\r\n" {
            return Err(Error::body("missing CRLF after chunk"));
        }
        d = &d[size + 2..];
    }

    let (trailers, consumed) = parse_chunk_trailers(d)?;
    d = &d[consumed..];
    *data = d;
    Ok((out, ieof, trailers))
}

/// Decode a complete ICAP chunked body, also extracting a `use-original-body` extension.
///
/// Returns `(body, use_original_body_offset, trailers)`.  `use_original_body_offset`
/// is `Some(n)` when the zero chunk carries `; use-original-body=n` (RFC 3507 §4.7).
/// `trailers` contains any RFC 7230 §4.1.2 trailer headers; empty when none are present.
pub fn dechunk_icap_entity_with_use_original_body(
    data: &mut &[u8],
) -> IcapResult<(Vec<u8>, Option<usize>, HeaderMap)> {
    let mut out = Vec::with_capacity((*data).len());
    let mut d = *data;

    loop {
        let crlf_pos =
            memmem::find(d, b"\r\n").ok_or_else(|| Error::body("chunk size line without CRLF"))?;
        let (size_line, rest) = d.split_at(crlf_pos);
        d = &rest[2..];

        let size_hex = memchr(b';', size_line).map_or(size_line, |i| &size_line[..i]);
        let size_str =
            core::str::from_utf8(size_hex).map_err(|_| Error::body("chunk size not utf8"))?;
        let size = usize::from_str_radix(size_str.trim(), 16)
            .map_err(|_| Error::body("chunk size not hex"))?;

        if size == 0 {
            let use_original_body = parse_use_original_body_extension(size_line)?;
            let (trailers, consumed) = parse_chunk_trailers(d)?;
            d = &d[consumed..];
            *data = d;
            return Ok((out, use_original_body, trailers));
        }

        if d.len() < size + 2 {
            return Err(Error::body("incomplete chunk data"));
        }
        out.extend_from_slice(&d[..size]);
        d = &d[size..];
        if !d.starts_with(b"\r\n") {
            return Err(Error::body("missing CRLF after chunk"));
        }
        d = &d[2..];
    }
}

fn parse_use_original_body_extension(size_line: &[u8]) -> IcapResult<Option<usize>> {
    let Some(ext_start) = memchr(b';', size_line) else {
        return Ok(None);
    };
    let ext_text = core::str::from_utf8(&size_line[ext_start + 1..])
        .map_err(|_| Error::body("chunk extension not utf8"))?;
    for ext in ext_text.split(';') {
        let Some((name, value)) = ext.trim().split_once('=') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("use-original-body") {
            return value
                .trim()
                .parse::<usize>()
                .map(Some)
                .map_err(|_| Error::body("use-original-body offset not decimal"));
        }
    }
    Ok(None)
}

/// Write one chunk to socket.
pub async fn write_chunk<S>(stream: &mut S, data: &[u8]) -> IcapResult<()>
where
    S: AsyncWrite + Unpin,
{
    let mut buf = Vec::with_capacity(16 + data.len() + 2);
    write!(&mut buf, "{:X}\r\n", data.len())?;
    if !data.is_empty() {
        buf.extend_from_slice(data);
    }
    buf.extend_from_slice(b"\r\n");
    stream.write_all(&buf).await?;
    Ok(())
}

/// Write one chunk into already-assembled buffer.
pub fn write_chunk_into(out: &mut Vec<u8>, data: &[u8]) {
    // `io::Write` for `Vec<u8>` is infallible.
    let _ = write!(out, "{:X}\r\n", data.len());
    if !data.is_empty() {
        out.extend_from_slice(data);
    }
    out.extend_from_slice(b"\r\n");
}
