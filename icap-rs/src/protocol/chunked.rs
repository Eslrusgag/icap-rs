use crate::error::IcapResult;
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

pub fn parse_one_chunk_meta(buf: &[u8], from: usize) -> Result<Option<ChunkMeta>, String> {
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
        .map_err(|_| "chunk size not utf8".to_string())?
        .trim();
    let size = usize::from_str_radix(size_str, 16).map_err(|_| "chunk size not hex".to_string())?;

    let has_ieof = ext_part
        .and_then(|b| std::str::from_utf8(b).ok())
        .is_some_and(|s| s.split(';').any(|t| t.trim().eq_ignore_ascii_case("ieof")));

    if size == 0 {
        if buf.len() < after_size + 2 {
            return Ok(None);
        }
        if &buf[after_size..after_size + 2] != b"\r\n" {
            return Err("Invalid chunked terminator".into());
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
        return Err("missing CRLF after chunk".into());
    }
    Ok(Some(ChunkMeta {
        next_pos: need,
        is_zero: false,
        has_ieof: false,
        size,
    }))
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
                pos = next_pos;
                while buf.len() < pos + 2 {
                    let mut tmp = [0u8; 4096];
                    let n = AsyncReadExt::read(stream, &mut tmp).await?;
                    if n == 0 {
                        return Err("Unexpected EOF after zero chunk".into());
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                if &buf[pos..pos + 2] != b"\r\n" {
                    return Err("Invalid chunked terminator".into());
                }
                return Ok(pos + 2);
            }
            pos = next_pos;
        } else {
            let mut tmp = [0u8; 4096];
            let n = AsyncReadExt::read(stream, &mut tmp).await?;
            if n == 0 {
                return Err("Unexpected EOF while reading ICAP chunked body".into());
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
                return Err("Unexpected EOF while reading ICAP preview body".into());
            }
            buf.extend_from_slice(&tmp[..n]);
        }
    }
}

pub fn dechunk_icap_entity(data: &mut &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity((*data).len());
    let mut d = *data;

    loop {
        let crlf_pos = memmem::find(d, b"\r\n").ok_or("chunk size line without CRLF")?;
        let (size_line, rest) = d.split_at(crlf_pos);
        d = &rest[2..];

        let size_hex = memchr(b';', size_line).map_or(size_line, |i| &size_line[..i]);

        let size_str = core::str::from_utf8(size_hex).map_err(|_| "chunk size not utf8")?;
        let size = usize::from_str_radix(size_str.trim(), 16).map_err(|_| "chunk size not hex")?;

        if size == 0 {
            if d.starts_with(b"\r\n") {
                d = &d[2..];
            }
            *data = d;
            break;
        }

        if d.len() < size + 2 {
            return Err("incomplete chunk data".into());
        }

        out.extend_from_slice(&d[..size]);

        if &d[size..size + 2] != b"\r\n" {
            return Err("missing CRLF after chunk".into());
        }

        d = &d[size + 2..];
    }

    Ok(out)
}

pub fn dechunk_icap_entity_with_ieof(data: &mut &[u8]) -> Result<(Vec<u8>, bool), String> {
    let mut out = Vec::with_capacity((*data).len());
    let mut d = *data;
    let ieof = loop {
        let rel = memmem::find(d, b"\r\n").ok_or("chunk size line without CRLF")?;
        let line = &d[..rel];
        d = &d[rel + 2..];

        let (size_hex, ext_part) =
            memchr(b';', line).map_or((line, None), |i| (&line[..i], Some(&line[i + 1..])));

        let size_str = std::str::from_utf8(size_hex).map_err(|_| "chunk size not utf8")?;
        let size = usize::from_str_radix(size_str.trim(), 16).map_err(|_| "chunk size not hex")?;

        let has_ieof = ext_part
            .and_then(|b| std::str::from_utf8(b).ok())
            .is_some_and(|s| s.split(';').any(|t| t.trim().eq_ignore_ascii_case("ieof")));

        if size == 0 {
            if d.starts_with(b"\r\n") {
                d = &d[2..];
            } else {
                return Err("missing final CRLF after zero chunk".into());
            }
            *data = d;
            break has_ieof;
        }

        if d.len() < size + 2 {
            return Err("incomplete chunk data".into());
        }
        out.extend_from_slice(&d[..size]);
        if &d[size..size + 2] != b"\r\n" {
            return Err("missing CRLF after chunk".into());
        }
        d = &d[size + 2..];
    };

    Ok((out, ieof))
}

pub fn dechunk_icap_entity_with_use_original_body(
    data: &mut &[u8],
) -> Result<(Vec<u8>, Option<usize>), String> {
    let mut out = Vec::with_capacity((*data).len());
    let mut d = *data;

    loop {
        let crlf_pos = memmem::find(d, b"\r\n").ok_or("chunk size line without CRLF")?;
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
    write!(out, "{:X}\r\n", data.len()).unwrap();
    if !data.is_empty() {
        out.extend_from_slice(data);
    }
    out.extend_from_slice(b"\r\n");
}
