use crate::error::{Error, IcapResult};
//use crate::request::{EmbeddedHttp, Request};
use crate::response::Response;
use std::borrow::Cow;

//use http::{Request as HttpRequest, Response as HttpResponse, StatusCode as HttpStatus};
use http::Version;
use std::fmt::Write;

/// Find end of ICAP header block (position after CRLFCRLF).
#[inline]
pub(crate) fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    memchr::memmem::find(buf, b"\r\n\r\n").map(|i| i + 4)
}

/// Offsets parsed from the `Encapsulated` header.
///
/// Offsets are **relative to the start of the encapsulated area**
/// (i.e., immediately after the ICAP headers CRLFCRLF).
#[derive(Debug, Clone, Copy, Default)]
pub struct Encapsulated {
    pub(crate) req_hdr: Option<usize>,
    pub(crate) res_hdr: Option<usize>,
    pub(crate) req_body: Option<usize>,
    pub(crate) res_body: Option<usize>,
    pub(crate) opt_body: Option<usize>,
    pub(crate) null_body: Option<usize>,
}

/// Parse the `Encapsulated:` header into offsets.
/// Parse only the value of the `Encapsulated:` header (right side).
///
pub fn parse_encapsulated_value(val: &str) -> IcapResult<Encapsulated> {
    if val.trim().is_empty() {
        return Err(Error::MissingHeader("Encapsulated"));
    }

    let mut enc = Encapsulated::default();
    let mut offsets: Vec<usize> = Vec::new();

    for part in val.split(',') {
        let p = part.trim();
        let (name_raw, off_raw) = p
            .split_once('=')
            .ok_or_else(|| Error::Header(format!("invalid Encapsulated token: {p}")))?;

        let name = name_raw.trim().to_ascii_lowercase();
        let off: usize = off_raw
            .trim()
            .parse()
            .map_err(|_| Error::Header(format!("invalid Encapsulated offset: {off_raw}")))?;

        let slot = match name.as_str() {
            "req-hdr" => &mut enc.req_hdr,
            "res-hdr" => &mut enc.res_hdr,
            "req-body" => &mut enc.req_body,
            "res-body" => &mut enc.res_body,
            "opt-body" => &mut enc.opt_body,
            "null-body" => &mut enc.null_body,
            _ => {
                return Err(Error::Header(format!(
                    "invalid Encapsulated part name: {}",
                    name_raw.trim()
                )));
            }
        };

        if slot.replace(off).is_some() {
            return Err(Error::Header(format!(
                "duplicate Encapsulated part name: {}",
                name_raw.trim()
            )));
        }
        offsets.push(off);
    }

    for w in offsets.windows(2) {
        if w[1] < w[0] {
            return Err(Error::Header(format!(
                "Encapsulated offsets not monotonic: {} -> {}",
                w[0], w[1]
            )));
        }
    }

    Ok(enc)
}

/// Parse the `Encapsulated:` header from raw headers text.
pub fn parse_encapsulated_header(headers_text: &str) -> IcapResult<Encapsulated> {
    for line in headers_text.lines() {
        let Some((name, val)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("Encapsulated") {
            continue;
        }
        return parse_encapsulated_value(val);
    }
    Ok(Encapsulated::default())
}

pub fn http_version_str(v: Version) -> &'static str {
    match v {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    }
}

// pub fn serialize_icap_request(req: &Request) -> IcapResult<Vec<u8>> {
//     let full_uri = format!("icap://localhost/{}", req.service.trim_start_matches('/'));
//
//     let mut out = String::new();
//     write!(&mut out, "{} {} ICAP/1.0\r\n", req.method, full_uri).unwrap();
//
//     for (name, value) in req.icap_headers.iter() {
//         let canon = canon_icap_header(name.as_str());
//         write!(
//             &mut out,
//             "{}: {}\r\n",
//             canon,
//             value.to_str().unwrap_or_default()
//         )
//         .unwrap();
//     }
//     out.push_str("\r\n");
//
//     let mut bytes = out.into_bytes();
//     if let Some(ref emb) = req.embedded {
//         match emb {
//             EmbeddedHttp::Req(r) => bytes.extend_from_slice(&serialize_http_request(r)),
//             EmbeddedHttp::Resp(r) => bytes.extend_from_slice(&serialize_http_response(r)),
//         }
//     }
//     Ok(bytes)
// }

pub fn serialize_icap_response(resp: &Response) -> IcapResult<Vec<u8>> {
    let mut head = String::new();
    write!(
        &mut head,
        "{} {} {}\r\n",
        resp.version,
        resp.status_code.as_str(),
        resp.status_text
    )
    .unwrap();
    for (name, value) in resp.headers.iter() {
        let canon = canon_icap_header(name.as_str());
        write!(
            &mut head,
            "{}: {}\r\n",
            canon,
            value.to_str().unwrap_or_default()
        )
        .unwrap();
    }
    head.push_str("\r\n");

    let mut out = head.into_bytes();
    if resp.body.is_empty() {
        return Ok(out);
    }

    let size_line = format!("{:X}\r\n", resp.body.len());
    out.extend_from_slice(size_line.as_bytes());
    out.extend_from_slice(&resp.body);
    out.extend_from_slice(b"\r\n0\r\n\r\n");
    Ok(out)
}

/// Return canonical ICAP header name (title-cased, with special-cases).
/// Input should be lowercased (http::HeaderName::as_str() already is).
pub fn canon_icap_header(name: &str) -> Cow<'_, str> {
    match name {
        // ICAP core / common headers
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
        // Transfer-* group used by some servers
        "transfer-preview" => Cow::Borrowed("Transfer-Preview"),
        "transfer-ignore" => Cow::Borrowed("Transfer-Ignore"),
        "transfer-complete" => Cow::Borrowed("Transfer-Complete"),
        // Generic/HTTP-ish ones that we might include too
        "date" => Cow::Borrowed("Date"),
        "server" => Cow::Borrowed("Server"),
        "connection" => Cow::Borrowed("Connection"),
        "content-length" => Cow::Borrowed("Content-Length"),
        "content-type" => Cow::Borrowed("Content-Type"),
        "cache-control" => Cow::Borrowed("Cache-Control"),
        "pragma" => Cow::Borrowed("Pragma"),
        "expires" => Cow::Borrowed("Expires"),
        // Fallback: Title-Case each hyphen-separated token.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_encapsulated_value_variants() {
        let e = parse_encapsulated_value("req-hdr=0, req-body=123").expect("parse");
        assert_eq!(e.req_hdr, Some(0));
        assert_eq!(e.req_body, Some(123));

        let e2 = parse_encapsulated_value("res-hdr=0,res-body=42").expect("parse");
        assert_eq!(e2.res_hdr, Some(0));
        assert_eq!(e2.res_body, Some(42));
    }

    #[test]
    fn parse_encapsulated_value_rejects_invalid_tokens() {
        let err = parse_encapsulated_value("req-hdr=0, bad=10").unwrap_err();
        assert!(err.to_string().to_lowercase().contains("encapsulated"));
    }

    #[test]
    fn parse_encapsulated_value_rejects_non_monotonic_offsets() {
        let err = parse_encapsulated_value("req-hdr=10, req-body=5").unwrap_err();
        assert!(err.to_string().to_lowercase().contains("offset"));
    }
}
