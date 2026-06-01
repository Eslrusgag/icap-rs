//! Fuzz target: ICAP response parser — structured generation.
//!
//! Generates complete ICAP server responses (200 OK with embedded adapted HTTP,
//! 204 No Content, and error responses) and feeds them to `parse_icap_response`.
//!
//! This exercises the client-side parsing path:
//!   raw bytes
//!     → ICAP response status line + headers
//!     → Encapsulated offset parsing
//!     → embedded HTTP response head
//!     → dechunked adapted body
//!
//! Invariants verified on every successful parse:
//!   - Status code matches what was encoded.
//!   - A 200 OK response with a body must decode the body correctly.
//!   - A 204 No Content response must carry no body.
#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use icap_rs::response::fuzz_api::parse_icap_response_fuzz;
use icap_rs::StatusCode;
use libfuzzer_sys::fuzz_target;
use std::fmt::Write as FmtWrite;

// ---------------------------------------------------------------------------
// Constrained string newtypes
// ---------------------------------------------------------------------------

const TOKEN_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.";
const VALUE_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 -_.,:;@=+/";

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

// ---------------------------------------------------------------------------
// Structured response types
// ---------------------------------------------------------------------------

/// A 200 OK ICAP response with an embedded adapted HTTP response.
#[derive(Debug, Arbitrary)]
struct FuzzOkResponse {
    /// HTTP status code 100–599 for the embedded adapted response.
    http_status_raw: u16,
    resp_headers: Vec<(AsciiToken, AsciiHeaderValue)>,
    body: Vec<u8>,
    icap_headers: Vec<(AsciiToken, AsciiHeaderValue)>,
}

/// A 204 No Content ICAP response.
#[derive(Debug, Arbitrary)]
struct FuzzNoContentResponse {
    icap_headers: Vec<(AsciiToken, AsciiHeaderValue)>,
}

/// An ICAP error response (4xx / 5xx).
#[derive(Debug, Arbitrary)]
struct FuzzErrorResponse {
    /// Selects from a fixed set of common error codes.
    code_idx: u8,
}

const ERROR_CODES: &[u16] = &[400, 403, 404, 405, 500, 501, 503];

#[derive(Debug, Arbitrary)]
enum FuzzResponse {
    Ok(FuzzOkResponse),
    NoContent(FuzzNoContentResponse),
    Error(FuzzErrorResponse),
}

// ---------------------------------------------------------------------------
// Wire serialisation
// ---------------------------------------------------------------------------

fn write_chunk(out: &mut Vec<u8>, data: &[u8]) {
    if !data.is_empty() {
        let mut line = String::new();
        let _ = write!(line, "{:x}\r\n", data.len());
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(data);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\n\r\n");
}

fn build_ok_response(r: &FuzzOkResponse) -> (Vec<u8>, u16) {
    let http_status = 100 + (r.http_status_raw as usize % 500);

    // Embedded adapted HTTP response head.
    let mut http_head = format!("HTTP/1.1 {} Reason\r\n", http_status);
    for (name, val) in &r.resp_headers {
        let _ = write!(http_head, "{}: {}\r\n", name.0, val.0);
    }
    http_head.push_str("\r\n");
    let http_head_bytes = http_head.into_bytes();

    let res_body_offset = http_head_bytes.len();

    // ICAP 200 OK response head.
    let mut icap = String::from("ICAP/1.0 200 OK\r\n");
    for (name, val) in &r.icap_headers {
        let _ = write!(icap, "{}: {}\r\n", name.0, val.0);
    }
    let _ = write!(
        icap,
        "Encapsulated: res-hdr=0, res-body={res_body_offset}\r\n\r\n"
    );

    let mut wire = icap.into_bytes();
    wire.extend_from_slice(&http_head_bytes);
    write_chunk(&mut wire, &r.body);

    (wire, 200)
}

fn build_no_content_response(r: &FuzzNoContentResponse) -> (Vec<u8>, u16) {
    let mut icap = String::from("ICAP/1.0 204 No Content\r\n");
    for (name, val) in &r.icap_headers {
        let _ = write!(icap, "{}: {}\r\n", name.0, val.0);
    }
    icap.push_str("Encapsulated: null-body=0\r\n\r\n");
    (icap.into_bytes(), 204)
}

fn build_error_response(r: &FuzzErrorResponse) -> (Vec<u8>, u16) {
    let code = ERROR_CODES[(r.code_idx as usize) % ERROR_CODES.len()];
    let wire = format!("ICAP/1.0 {code} Error\r\nEncapsulated: null-body=0\r\n\r\n");
    (wire.into_bytes(), code)
}

// ---------------------------------------------------------------------------
// Fuzz entry point
// ---------------------------------------------------------------------------

fuzz_target!(|data: &[u8]| {
    // --- raw bytes path: must never panic ---
    let _ = parse_icap_response_fuzz(data);

    // --- structured path ---
    let mut u = Unstructured::new(data);
    let Ok(fuzz_resp) = FuzzResponse::arbitrary(&mut u) else {
        return;
    };

    let (wire, expected_code) = match &fuzz_resp {
        FuzzResponse::Ok(r) => build_ok_response(r),
        FuzzResponse::NoContent(r) => build_no_content_response(r),
        FuzzResponse::Error(r) => build_error_response(r),
    };

    let Ok(parsed) = parse_icap_response_fuzz(&wire) else {
        return;
    };

    assert_eq!(
        parsed.status_code().as_u16(),
        expected_code,
        "status code mismatch: expected {expected_code}, got {}",
        parsed.status_code().as_u16()
    );

    // 204 must carry no body.
    if parsed.status_code() == StatusCode::NO_CONTENT {
        assert!(
            parsed.body().is_empty(),
            "204 response must have empty body, got {} bytes",
            parsed.body().len()
        );
    }

    // 200 body must round-trip.
    if let FuzzResponse::Ok(r) = &fuzz_resp {
        assert_eq!(
            parsed.body(),
            r.body.as_slice(),
            "200 body round-trip mismatch"
        );
    }
});
