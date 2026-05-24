use crate::error::{Error, IcapResult};
use crate::protocol::http_version_str;
use http::{Method as HttpMethod, StatusCode as HttpStatus, Version};
use http::{Request as HttpRequest, Response as HttpResponse, StatusCode};
use std::fmt::Write as _;
use std::str::FromStr;

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
    for (name, value) in req.headers() {
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
    for (name, value) in resp.headers() {
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

pub fn parse_http_request_start_line(start: &str) -> IcapResult<(HttpMethod, &str, Version)> {
    let mut parts = start.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| Error::http_parse("embedded HTTP request line missing method"))?;
    let uri = parts
        .next()
        .ok_or_else(|| Error::http_parse("embedded HTTP request line missing URI"))?;
    let version = parts
        .next()
        .ok_or_else(|| Error::http_parse("embedded HTTP request line missing version"))?;

    if parts.next().is_some() {
        return Err(Error::http_parse(
            "embedded HTTP request line has extra fields",
        ));
    }

    Ok((
        HttpMethod::from_str(method)
            .map_err(|err| Error::http_parse(format!("invalid embedded HTTP method: {err}")))?,
        uri,
        parse_http_version(version)?,
    ))
}

pub fn parse_http_response_start_line(start: &str) -> IcapResult<(Version, HttpStatus)> {
    let mut parts = start.split_whitespace();
    let version = parts
        .next()
        .ok_or_else(|| Error::http_parse("embedded HTTP status line missing version"))?;
    if !version.starts_with("HTTP/") {
        return Err(Error::http_parse(format!(
            "embedded HTTP status line must start with HTTP/, got {version}"
        )));
    }

    let status = parts
        .next()
        .ok_or_else(|| Error::http_parse("embedded HTTP status line missing status code"))?;
    let status = status
        .parse::<u16>()
        .map_err(|_| Error::http_parse(format!("invalid embedded HTTP status code: {status}")))?;

    let status = HttpStatus::from_u16(status)
        .map_err(|err| Error::http_parse(format!("invalid embedded HTTP status code: {err}")))?;

    Ok((parse_http_version(version)?, status))
}

pub fn parse_http_version(version: &str) -> IcapResult<Version> {
    match version {
        "HTTP/0.9" => Ok(Version::HTTP_09),
        "HTTP/1.0" => Ok(Version::HTTP_10),
        "HTTP/1.1" => Ok(Version::HTTP_11),
        "HTTP/2.0" | "HTTP/2" => Ok(Version::HTTP_2),
        "HTTP/3.0" | "HTTP/3" => Ok(Version::HTTP_3),
        _ => Err(Error::InvalidVersion(version.to_string())),
    }
}
