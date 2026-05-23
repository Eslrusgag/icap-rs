use crate::protocol::chunked::write_chunk_into;
use crate::protocol::encapsulated::parse_encapsulated_value;
use crate::response::Response;
use http::Version;
use std::borrow::Cow;
use std::fmt::Write;

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

pub fn serialize_icap_response(resp: &Response) -> Vec<u8> {
    let mut head = String::new();
    write!(
        &mut head,
        "{} {} {}\r\n",
        resp.version,
        resp.status_code.as_str(),
        resp.status_text
    )
    .expect("write to String");
    for (name, value) in &resp.headers {
        let canon = canon_icap_header(name.as_str());
        write!(
            &mut head,
            "{}: {}\r\n",
            canon,
            value.to_str().unwrap_or_default()
        )
        .expect("write to String");
    }
    head.push_str("\r\n");

    let mut out = head.into_bytes();
    if resp.body.is_empty() {
        if let Some(offset) = resp.use_original_body {
            out.extend_from_slice(format!("0; use-original-body={offset}\r\n\r\n").as_bytes());
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
            out.extend_from_slice(format!("0; use-original-body={offset}\r\n\r\n").as_bytes());
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
