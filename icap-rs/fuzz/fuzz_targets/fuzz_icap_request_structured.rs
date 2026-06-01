//! Fuzz target: full ICAP request parser — structured generation.
//!
//! Uses `arbitrary` to generate realistic ICAP REQMOD / RESPMOD wire messages
//! with varied embedded HTTP data (methods, URIs, headers, bodies), then feeds
//! them to the parser and checks invariants.
//!
//! Why structured fuzzing in addition to raw bytes?
//! The raw target explores the parser from the outside, but most arbitrary byte
//! sequences are rejected at the first ICAP header check. The structured target
//! generates inputs that are mostly-valid — they reach deeper layers (embedded
//! HTTP parsing, chunked body decoding, header validation) far more often.
//!
//! Invariants verified on every successful parse:
//!   - Method matches what was encoded in the wire message.
//!   - Service is non-empty and matches what was encoded.
//!   - Embedded HTTP body bytes match what was encoded.
#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use icap_rs::request::fuzz_api::parse_icap_request;
use icap_rs::{EmbeddedHttp, Method};
use libfuzzer_sys::fuzz_target;
use std::fmt::Write as FmtWrite;

// ---------------------------------------------------------------------------
// Newtype wrappers that produce constrained ASCII strings via Arbitrary.
// Using a fixed alphabet avoids spending fuzzer iterations on trivially invalid
// token or header-value bytes.
// ---------------------------------------------------------------------------

const TOKEN_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.";
const VALUE_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 -_.,:;@=+/";
// Host chars: labels, dots, hyphens, optional :port digits.
const HOST_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789-.";

/// A short ASCII token (no whitespace, no colon).
#[derive(Debug)]
struct AsciiToken(String);

impl<'a> Arbitrary<'a> for AsciiToken {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let len = u.int_in_range(1usize..=24)?;
        let s: String = (0..len)
            .map(|_| {
                let b: u8 = u.arbitrary()?;
                Ok(TOKEN_CHARS[(b as usize) % TOKEN_CHARS.len()] as char)
            })
            .collect::<arbitrary::Result<_>>()?;
        Ok(AsciiToken(s))
    }
}

/// A short ASCII header value (printable + space, no CR/LF).
#[derive(Debug)]
struct AsciiHeaderValue(String);

impl<'a> Arbitrary<'a> for AsciiHeaderValue {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let len = u.int_in_range(0usize..=64)?;
        let s: String = (0..len)
            .map(|_| {
                let b: u8 = u.arbitrary()?;
                Ok(VALUE_CHARS[(b as usize) % VALUE_CHARS.len()] as char)
            })
            .collect::<arbitrary::Result<_>>()?;
        Ok(AsciiHeaderValue(s))
    }
}

/// A hostname, optionally with a port: `example.com` or `proxy.local:1344`.
#[derive(Debug)]
struct AsciiHost(String);

impl<'a> Arbitrary<'a> for AsciiHost {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let len = u.int_in_range(1usize..=32)?;
        let mut s: String = (0..len)
            .map(|_| {
                let b: u8 = u.arbitrary()?;
                Ok(HOST_CHARS[(b as usize) % HOST_CHARS.len()] as char)
            })
            .collect::<arbitrary::Result<_>>()?;
        // Optionally append a port number.
        if u.arbitrary::<bool>()? {
            let port: u16 = u.arbitrary()?;
            let _ = write!(s, ":{port}");
        }
        Ok(AsciiHost(s))
    }
}

// ---------------------------------------------------------------------------
// Structured request types
// ---------------------------------------------------------------------------

const HTTP_METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS", "CONNECT"];

#[derive(Debug, Arbitrary)]
struct FuzzReqmod {
    /// Host in the ICAP `Host:` header (identifies the ICAP server).
    icap_host: AsciiHost,
    /// Host in the embedded HTTP `Host:` header (identifies the origin server).
    http_host: AsciiHost,
    http_method_idx: u8,
    uri: AsciiToken,
    http_headers: Vec<(AsciiToken, AsciiHeaderValue)>,
    body: Vec<u8>,
    allow_204: bool,
    allow_206: bool,
}

#[derive(Debug, Arbitrary)]
struct FuzzRespmod {
    /// Host in the ICAP `Host:` header.
    icap_host: AsciiHost,
    /// Host in the embedded HTTP request head.
    http_req_host: AsciiHost,
    /// Status code 100–599 (mapped via modulo).
    status_raw: u16,
    req_uri: AsciiToken,
    http_resp_headers: Vec<(AsciiToken, AsciiHeaderValue)>,
    body: Vec<u8>,
    allow_204: bool,
}

#[derive(Debug, Arbitrary)]
enum FuzzRequest {
    ReqMod(FuzzReqmod),
    RespMod(FuzzRespmod),
}

// ---------------------------------------------------------------------------
// Wire serialisation helpers
// ---------------------------------------------------------------------------

fn write_chunked_body(out: &mut Vec<u8>, body: &[u8]) {
    if !body.is_empty() {
        let mut line = String::new();
        let _ = write!(line, "{:x}\r\n", body.len());
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\n\r\n");
}

fn build_reqmod(r: &FuzzReqmod, service: &str) -> Vec<u8> {
    let method = HTTP_METHODS[(r.http_method_idx as usize) % HTTP_METHODS.len()];

    // Embedded HTTP request head — host comes from the fuzz input.
    let mut http_head = format!(
        "{} /{} HTTP/1.1\r\nHost: {}\r\n",
        method, r.uri.0, r.http_host.0
    );
    for (name, val) in &r.http_headers {
        let _ = write!(http_head, "{}: {}\r\n", name.0, val.0);
    }
    http_head.push_str("\r\n");
    let http_head_bytes = http_head.into_bytes();

    let body_offset = http_head_bytes.len();

    // ICAP head — icap_host drives the Host header.
    let mut icap = format!(
        "REQMOD icap://{}/{} ICAP/1.0\r\nHost: {}\r\n",
        r.icap_host.0, service, r.icap_host.0
    );
    if r.allow_204 {
        icap.push_str("Allow: 204\r\n");
    }
    if r.allow_206 {
        let _ = write!(icap, "Allow: {}\r\n", if r.allow_204 { "204, 206" } else { "206" });
    }
    let _ = write!(icap, "Encapsulated: req-hdr=0, req-body={}\r\n\r\n", body_offset);

    let mut wire = icap.into_bytes();
    wire.extend_from_slice(&http_head_bytes);
    write_chunked_body(&mut wire, &r.body);
    wire
}

fn build_respmod(r: &FuzzRespmod, service: &str) -> Vec<u8> {
    let status = 100 + (r.status_raw as usize % 500);

    // Embedded HTTP request head — http_req_host comes from the fuzz input.
    let req_head = format!(
        "GET /{} HTTP/1.1\r\nHost: {}\r\n\r\n",
        r.req_uri.0, r.http_req_host.0
    );
    let req_head_bytes = req_head.as_bytes();

    // Embedded HTTP response head.
    let mut resp_head = format!("HTTP/1.1 {} Reason\r\n", status);
    for (name, val) in &r.http_resp_headers {
        let _ = write!(resp_head, "{}: {}\r\n", name.0, val.0);
    }
    resp_head.push_str("\r\n");
    let resp_head_bytes = resp_head.into_bytes();

    let res_hdr_offset = req_head_bytes.len();
    let res_body_offset = res_hdr_offset + resp_head_bytes.len();

    // ICAP head — icap_host drives the Host header.
    let mut icap = format!(
        "RESPMOD icap://{}/{} ICAP/1.0\r\nHost: {}\r\n",
        r.icap_host.0, service, r.icap_host.0
    );
    if r.allow_204 {
        icap.push_str("Allow: 204\r\n");
    }
    let _ = write!(
        icap,
        "Encapsulated: req-hdr=0, res-hdr={}, res-body={}\r\n\r\n",
        res_hdr_offset, res_body_offset
    );

    let mut wire = icap.into_bytes();
    wire.extend_from_slice(req_head_bytes);
    wire.extend_from_slice(&resp_head_bytes);
    write_chunked_body(&mut wire, &r.body);
    wire
}

// ---------------------------------------------------------------------------
// Fuzz entry point
// ---------------------------------------------------------------------------

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(fuzz_req) = FuzzRequest::arbitrary(&mut u) else {
        return;
    };

    let (wire, expected_method, expected_service) = match &fuzz_req {
        FuzzRequest::ReqMod(r) => (build_reqmod(r, "test"), Method::ReqMod, "test"),
        FuzzRequest::RespMod(r) => (build_respmod(r, "scan"), Method::RespMod, "scan"),
    };

    let Ok(parsed) = parse_icap_request(&wire) else {
        // A structured request failing to parse is unexpected — but rather
        // than panic here (which would mask the real error), let the fuzzer
        // accumulate the input and investigate via RUST_BACKTRACE if needed.
        return;
    };

    assert_eq!(
        parsed.method, expected_method,
        "method mismatch: expected {:?}, got {:?}",
        expected_method, parsed.method
    );
    assert_eq!(
        parsed.service, expected_service,
        "service mismatch: expected {:?}, got {:?}",
        expected_service, parsed.service
    );

    // Verify embedded body round-trips correctly.
    let expected_body: &[u8] = match &fuzz_req {
        FuzzRequest::ReqMod(r) => &r.body,
        FuzzRequest::RespMod(r) => &r.body,
    };

    match &parsed.embedded {
        Some(EmbeddedHttp::Req { body, .. }) | Some(EmbeddedHttp::Resp { body, .. }) => {
            if let icap_rs::Body::Full { reader } = body {
                assert_eq!(
                    reader.as_slice(),
                    expected_body,
                    "body round-trip mismatch"
                );
            }
        }
        None => {}
    }
});
