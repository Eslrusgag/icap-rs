use crate::ICAP_VERSION;
use crate::error::{Error, IcapResult};
use crate::protocol::chunked::write_chunk_into;
use crate::protocol::encapsulated::parse_encapsulated_value;
use crate::protocol::validate_istag;
use crate::response::Response;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Version};
use std::borrow::Cow;
use std::io::Write as IoWrite;
use std::str::FromStr;
use tracing::{trace, warn};

#[derive(Debug)]
pub struct RawIcapResponseHead {
    pub version: String,
    pub status_code: StatusCode,
    pub status_text: String,
    pub headers: HeaderMap,
    pub header_end: usize,
    pub encapsulated_value: Option<String>,
}

/// Find end of ICAP header block (position after CRLFCRLF).
#[inline]
pub fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    memchr::memmem::find(buf, b"\r\n\r\n").map(|i| i + 4)
}

pub const fn http_version_str(v: Version) -> &'static str {
    match v {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    }
}

pub fn parse_icap_response_head(raw: &[u8]) -> IcapResult<RawIcapResponseHead> {
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
        return Err(Error::invalid_version(parts[0].to_string()));
    }

    let version = parts[0].to_string();
    let status_code = if let Ok(code) = StatusCode::from_str(parts[1]) {
        code
    } else {
        let code_num = parts[1]
            .parse::<u16>()
            .map_err(|_| Error::invalid_status_code("Invalid status code"))?;
        StatusCode::try_from(code_num).map_err(|_| {
            Error::invalid_status_code(format!("Unknown ICAP status code: {code_num}"))
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
        if let Some(colon) = memchr::memchr(b':', line.as_bytes()) {
            let name = &line[..colon];
            let value = line[colon + 1..].trim();

            if name.eq_ignore_ascii_case("Encapsulated") {
                if seen_encapsulated {
                    return Err(Error::header("duplicate Encapsulated header"));
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

    if !headers.contains_key("ISTag") {
        if status_code.is_success() {
            return Err(Error::missing_header("ISTag"));
        }
        warn!(code = %status_code, "response without ISTag on non-2xx (accepted for compatibility)");
    }

    Ok(RawIcapResponseHead {
        version,
        status_code,
        status_text,
        headers,
        header_end: hdr_end,
        encapsulated_value,
    })
}

pub fn parse_header_lines<'a, I>(lines: I) -> IcapResult<HeaderMap>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut headers = HeaderMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(colon) = memchr::memchr(b':', line.as_bytes()) {
            let name = &line[..colon];
            let value = line[colon + 1..].trim();
            headers.insert(
                HeaderName::from_bytes(name.as_bytes())?,
                HeaderValue::from_str(value)?,
            );
        }
    }
    Ok(headers)
}

pub fn parse_preview_header_value(hdr_text: &str) -> Option<usize> {
    for line in hdr_text.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("Preview") {
            return value.trim().parse::<usize>().ok();
        }
    }
    None
}

pub fn serialize_icap_response(resp: &Response) -> Vec<u8> {
    // Pre-allocate: status line (~32 B) + headers (~48 B each) + separator
    // + body (exact) + chunked overhead (~32 B).
    let header_cap = 32 + resp.headers.len() * 48 + 2;
    let body_cap = if resp.body.is_empty() {
        32
    } else {
        resp.body.len() + 32
    };
    let mut out = Vec::with_capacity(header_cap + body_cap);

    // Write status line and headers directly into the Vec<u8> via io::Write.
    write!(
        out,
        "{} {} {}\r\n",
        resp.version,
        resp.status_code.as_str(),
        resp.status_text
    )
    .expect("write status line");
    for (name, value) in &resp.headers {
        let canon = canon_icap_header(name.as_str());
        write!(out, "{}: {}\r\n", canon, value.to_str().unwrap_or_default()).expect("write header");
    }
    out.extend_from_slice(b"\r\n");

    if resp.body.is_empty() {
        if let Some(offset) = resp.use_original_body {
            write!(out, "0; use-original-body={offset}\r\n\r\n").expect("write use-original-body");
        }
        return out;
    }

    let enc = resp
        .headers
        .get("Encapsulated")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| parse_encapsulated_value(value).ok());

    if enc.is_some_and(|enc| enc.null_body.is_some()) {
        return out;
    }

    let body_start = enc.and_then(|enc| enc.req_body.or(enc.res_body).or(enc.opt_body));

    if let Some(offset) = body_start {
        let split = offset.min(resp.body.len());
        out.extend_from_slice(&resp.body[..split]);
        if split < resp.body.len() {
            write_chunk_into(&mut out, &resp.body[split..]);
        }
        if let Some(offset) = resp.use_original_body {
            write!(out, "0; use-original-body={offset}\r\n\r\n").expect("write use-original-body");
        } else {
            out.extend_from_slice(b"0\r\n\r\n");
        }
    } else {
        out.extend_from_slice(&resp.body);
    }
    out
}

/// Return canonical ICAP header name (title-cased, with special-cases).
/// Input should be lowercased (`http::HeaderName::as_str()` already is).
pub fn canon_icap_header(name: &str) -> Cow<'_, str> {
    match name {
        "methods" => Cow::Borrowed("Methods"),
        "istag" => Cow::Borrowed("ISTag"),
        "encapsulated" => Cow::Borrowed("Encapsulated"),
        "service" => Cow::Borrowed("Service"),
        "max-connections" => Cow::Borrowed("Max-Connections"),
        "options-ttl" => Cow::Borrowed("Options-TTL"),
        "preview" => Cow::Borrowed("Preview"),
        "allow" => Cow::Borrowed("Allow"),
        "service-id" => Cow::Borrowed("Service-ID"),
        "opt-body-type" => Cow::Borrowed("Opt-body-type"),
        "transfer-preview" => Cow::Borrowed("Transfer-Preview"),
        "transfer-ignore" => Cow::Borrowed("Transfer-Ignore"),
        "transfer-complete" => Cow::Borrowed("Transfer-Complete"),
        "date" => Cow::Borrowed("Date"),
        "server" => Cow::Borrowed("Server"),
        "connection" => Cow::Borrowed("Connection"),
        "content-length" => Cow::Borrowed("Content-Length"),
        "content-type" => Cow::Borrowed("Content-Type"),
        "cache-control" => Cow::Borrowed("Cache-Control"),
        "pragma" => Cow::Borrowed("Pragma"),
        "expires" => Cow::Borrowed("Expires"),
        _ => {
            let mut out = String::with_capacity(name.len());
            for (i, seg) in name.split('-').enumerate() {
                if i > 0 {
                    out.push('-');
                }
                let mut chars = seg.chars();
                if let Some(c0) = chars.next() {
                    out.extend(c0.to_uppercase());
                    for c in chars {
                        out.extend(c.to_lowercase());
                    }
                }
            }
            Cow::Owned(out)
        }
    }
}
