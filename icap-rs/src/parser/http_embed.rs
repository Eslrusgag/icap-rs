use crate::parser::http_version_str;
use http::{Request as HttpRequest, Response as HttpResponse, StatusCode};
use std::fmt::Write as _;

/// Serialize HTTP request for embedding into ICAP.
pub fn serialize_http_request(req: &HttpRequest<Vec<u8>>) -> Vec<u8> {
    let mut out = String::new();
    write!(
        &mut out,
        "{} {} {}\r\n",
        req.method(),
        req.uri(),
        http_version_str(req.version())
    )
    .unwrap();
    for (name, value) in req.headers().iter() {
        write!(
            &mut out,
            "{}: {}\r\n",
            name.as_str(),
            value.to_str().unwrap_or_default()
        )
        .unwrap();
    }
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(req.body());
    bytes
}

/// Serialize HTTP response for embedding into ICAP.
pub fn serialize_http_response(resp: &HttpResponse<Vec<u8>>) -> Vec<u8> {
    let mut out = String::new();
    let code: StatusCode = resp.status();
    write!(
        &mut out,
        "{} {} {}\r\n",
        http_version_str(resp.version()),
        code.as_u16(),
        code.canonical_reason().unwrap_or("")
    )
    .unwrap();
    for (name, value) in resp.headers().iter() {
        write!(
            &mut out,
            "{}: {}\r\n",
            name.as_str(),
            value.to_str().unwrap_or_default()
        )
        .unwrap();
    }
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(resp.body());
    bytes
}

