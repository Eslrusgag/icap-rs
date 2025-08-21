use crate::error::IcapResult;
use crate::request::{EmbeddedHttp, Request};
use crate::response::{Response, StatusCode};
use std::borrow::Cow;

use http::{
    HeaderMap, HeaderName, HeaderValue, Request as HttpRequest, Response as HttpResponse,
    StatusCode as HttpStatus, Version,
};
use std::fmt::Write;
use std::str::FromStr;
use tracing::{debug, trace};

/// Offsets parsed from the `Encapsulated` header.
///
/// Offsets are **relative to the start of the encapsulated area**
/// (i.e., immediately after the ICAP headers CRLFCRLF).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Encapsulated {
    pub(crate) req_hdr: Option<usize>,
    pub(crate) res_hdr: Option<usize>,
    pub(crate) req_body: Option<usize>,
    pub(crate) res_body: Option<usize>,
    pub(crate) null_body: Option<usize>,
}

/// Parse the `Encapsulated:` header into offsets.
pub(crate) fn parse_encapsulated_header(headers_text: &str) -> Encapsulated {
    let mut enc = Encapsulated::default();
    for line in headers_text.lines() {
        let Some((name, val)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("Encapsulated") {
            continue;
        }
        for part in val.split(',') {
            let part = part.trim();
            let mut it = part.split('=');
            let key = it.next().unwrap_or("").trim().to_ascii_lowercase();
            let off = it.next().and_then(|s| s.trim().parse::<usize>().ok());
            match (key.as_str(), off) {
                ("req-hdr", Some(o)) => enc.req_hdr = Some(o),
                ("res-hdr", Some(o)) => enc.res_hdr = Some(o),
                ("req-body", Some(o)) => enc.req_body = Some(o),
                ("res-body", Some(o)) => enc.res_body = Some(o),
                ("null-body", Some(o)) => enc.null_body = Some(o),
                _ => {}
            }
        }
        break;
    }
    enc
}

#[inline]
fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

#[inline]
pub fn is_complete_icap_request(buffer: &[u8]) -> bool {
    find_double_crlf(buffer).is_some()
}

#[inline]
pub fn is_complete_icap_response(buffer: &[u8]) -> bool {
    find_double_crlf(buffer).is_some()
}

pub fn extract_service_name(uri: &str) -> IcapResult<String> {
    let s = uri
        .rsplit('/')
        .next()
        .ok_or("Invalid ICAP URI (no /service)")?;
    if s.is_empty() {
        Err("Empty service name".into())
    } else {
        Ok(s.to_string())
    }
}

pub(crate) fn http_version_str(v: Version) -> &'static str {
    match v {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    }
}

pub fn parse_icap_request(data: &[u8]) -> IcapResult<Request> {
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
    } else if let Some(http_hdr_end) = find_double_crlf(rest) {
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

pub fn parse_icap_response(raw: &[u8]) -> IcapResult<Response> {
    trace!("parse_icap_response: len={}", raw.len());
    if raw.is_empty() {
        return Err("Empty response".into());
    }

    let hdr_end = find_double_crlf(raw).ok_or("ICAP response headers not complete")?;
    let head = &raw[..hdr_end];
    let head_str = std::str::from_utf8(head)?;
    let mut lines = head_str.split("\r\n");

    // Статусная строка
    let status_line = lines.next().ok_or("Empty response")?;
    let parts: Vec<&str> = status_line.split_whitespace().collect();
    if parts.len() < 3 {
        return Err("Invalid status line format".into());
    }

    let version = parts[0].to_string();
    let status_code = match StatusCode::from_str(parts[1]) {
        Ok(code) => code,
        Err(_) => {
            let code_num = parts[1].parse::<u16>().map_err(|_| "Invalid status code")?;
            match code_num {
                100 => StatusCode::Continue100,
                200 => StatusCode::Ok200,
                204 => StatusCode::NoContent204,
                400 => StatusCode::BadRequest400,
                404 => StatusCode::NotFound404,
                405 => StatusCode::MethodNotAllowed405,
                413 => StatusCode::RequestEntityTooLarge413,
                500 => StatusCode::InternalServerError500,
                503 => StatusCode::ServiceUnavailable503,
                504 => StatusCode::GatewayTimeout504,
                _ => return Err(format!("Unknown ICAP status code: {}", code_num).into()),
            }
        }
    };
    let status_text = parts[2..].join(" ");
    debug!(
        "parse_icap_response: {} {} {}",
        version, status_code, status_text
    );

    let mut headers = HeaderMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(colon) = line.find(':') {
            let name = &line[..colon];
            let value = line[colon + 1..].trim();
            headers.insert(
                HeaderName::from_bytes(name.as_bytes())?,
                HeaderValue::from_str(value)?,
            );
        }
    }

    // Тело (всё после CRLFCRLF)
    let body = raw[hdr_end..].to_vec();
    trace!("parse_icap_response: body_len={}", body.len());

    Ok(Response {
        version,
        status_code,
        status_text,
        headers,
        body,
    })
}

pub fn serialize_icap_request(req: &Request) -> IcapResult<Vec<u8>> {
    let full_uri = format!("icap://localhost/{}", req.service.trim_start_matches('/'));

    let mut out = String::new();
    write!(&mut out, "{} {} ICAP/1.0\r\n", req.method, full_uri).unwrap();

    for (name, value) in req.icap_headers.iter() {
        let canon = canonical_icap_header(name.as_str());
        write!(
            &mut out,
            "{}: {}\r\n",
            canon,
            value.to_str().unwrap_or_default()
        )
        .unwrap();
    }
    out.push_str("\r\n");

    let mut bytes = out.into_bytes();
    if let Some(ref emb) = req.embedded {
        match emb {
            EmbeddedHttp::Req(r) => bytes.extend_from_slice(&serialize_http_request(r)),
            EmbeddedHttp::Resp(r) => bytes.extend_from_slice(&serialize_http_response(r)),
        }
    }
    Ok(bytes)
}

pub fn serialize_icap_response(resp: &Response) -> IcapResult<Vec<u8>> {
    use std::fmt::Write as _;

    // Status line
    let mut head = String::new();
    write!(
        &mut head,
        "{} {} {}\r\n",
        resp.version, resp.status_code, resp.status_text
    )
    .unwrap();

    // Canonicalize header names on output
    for (name, value) in resp.headers.iter() {
        let canon = canonical_icap_header(name.as_str());
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

    let encapsulated = resp
        .headers
        .get("Encapsulated")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    let is_http_embedded = encapsulated.contains("req-hdr=") || encapsulated.contains("res-hdr=");

    if is_http_embedded {
        if let Some(pos) = resp.body.windows(4).position(|w| w == b"\r\n\r\n") {
            let http_hdr_end = pos + 4;

            // 1) raw HTTP headers
            out.extend_from_slice(&resp.body[..http_hdr_end]);

            // 2) HTTP body → ICAP chunked
            let http_body = &resp.body[http_hdr_end..];
            if !http_body.is_empty() {
                let size_line = format!("{:X}\r\n", http_body.len());
                out.extend_from_slice(size_line.as_bytes());
                out.extend_from_slice(http_body);
                out.extend_from_slice(b"\r\n0\r\n\r\n");
            } else {
                out.extend_from_slice(b"0\r\n\r\n");
            }
            return Ok(out);
        }
    }

    out.extend_from_slice(&resp.body);
    Ok(out)
}

fn serialize_http_request(req: &HttpRequest<Vec<u8>>) -> Vec<u8> {
    let mut out = String::new();
    write!(
        &mut out,
        "{} {} {}\r\n",
        req.method(),
        req.uri(),
        http_version_str(req.version())
    )
    .unwrap();

    for (n, v) in req.headers().iter() {
        write!(
            &mut out,
            "{}: {}\r\n",
            n.as_str(),
            v.to_str().unwrap_or_default()
        )
        .unwrap();
    }
    out.push_str("\r\n");

    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(req.body());
    bytes
}

fn serialize_http_response(resp: &HttpResponse<Vec<u8>>) -> Vec<u8> {
    let mut out = String::new();
    let code: HttpStatus = resp.status();
    write!(
        &mut out,
        "{} {} {}\r\n",
        http_version_str(resp.version()),
        code.as_u16(),
        code.canonical_reason().unwrap_or("")
    )
    .unwrap();

    for (n, v) in resp.headers().iter() {
        write!(
            &mut out,
            "{}: {}\r\n",
            n.as_str(),
            v.to_str().unwrap_or_default()
        )
        .unwrap();
    }
    out.push_str("\r\n");

    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(resp.body());
    bytes
}

/// Return canonical ICAP header name (title-cased, with special-cases).
/// Input should be lowercased (http::HeaderName::as_str() already is).
fn canonical_icap_header(name: &str) -> Cow<str> {
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
    fn parse_encapsulated_header_variants() {
        let t = "Encapsulated: req-hdr=0, req-body=123\r\n";
        let e = parse_encapsulated_header(t);
        assert_eq!(e.req_hdr, Some(0));
        assert_eq!(e.req_body, Some(123));
        assert_eq!(e.res_hdr, None);

        let t2 = "Some: x\r\nEncapsulated: res-hdr=0, res-body=42\r\nFoo: y\r\n";
        let e2 = parse_encapsulated_header(t2);
        assert_eq!(e2.res_hdr, Some(0));
        assert_eq!(e2.res_body, Some(42));
        assert!(e2.req_hdr.is_none());
    }
}
