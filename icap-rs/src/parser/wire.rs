use crate::error::IcapResult;
use std::io::Write;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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

/// Decode a complete ICAP chunked entity body.
///
/// ICAP uses HTTP chunked coding for encapsulated entity bodies only; embedded
/// HTTP headers before the body offset are not part of this input.
pub fn dechunk_icap_entity(data: &mut &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity((*data).len());
    let mut d = *data;

    loop {
        let crlf_pos = memchr::memmem::find(d, b"\r\n").ok_or("chunk size line without CRLF")?;
        let (size_line, rest) = d.split_at(crlf_pos);
        d = &rest[2..];

        let size_hex = size_line.split(|&b| b == b';').next().unwrap_or(size_line);
        let size_str = std::str::from_utf8(size_hex).map_err(|_| "chunk size not utf8")?;
        let size = usize::from_str_radix(size_str.trim(), 16).map_err(|_| "chunk size not hex")?;

        if size == 0 {
            if d.starts_with(b"\r\n") {
                d = &d[2..];
            } else {
                return Err("missing final CRLF after zero chunk".into());
            }
            *data = d;
            break;
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

    Ok(out)
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
