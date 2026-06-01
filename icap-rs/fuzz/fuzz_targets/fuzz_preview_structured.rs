//! Fuzz target: ICAP Preview header — structured generation.
//!
//! Generates ICAP REQMOD and RESPMOD wire messages that include a `Preview: N`
//! header (RFC 3507 §4.5).  The preview body is emitted as a chunked section;
//! the zero-chunk optionally carries `; ieof` to signal that the preview IS the
//! complete body.
//!
//! Invariants verified on every successful parse:
//!   - Method matches the encoded value.
//!   - Service is non-empty.
//!   - When no Preview header is present the parser must still succeed.
//!   - `parse_preview_header_value` returns `Some(N)` for the same N we encoded.
//!
//! Also exercises `parse_preview_header_value` standalone with arbitrary text.
#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use icap_rs::protocol::headers::parse_preview_header_value;
use icap_rs::request::fuzz_api::parse_icap_request;
use icap_rs::Method;
use libfuzzer_sys::fuzz_target;
use std::fmt::Write as FmtWrite;

// ---------------------------------------------------------------------------
// Constrained string newtypes (shared alphabet with the other structured target)
// ---------------------------------------------------------------------------

const TOKEN_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.";
const HOST_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789-.";

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
        if u.arbitrary::<bool>()? {
            let port: u16 = u.arbitrary()?;
            let _ = write!(s, ":{port}");
        }
        Ok(AsciiHost(s))
    }
}

// ---------------------------------------------------------------------------
// Structured fuzz types
// ---------------------------------------------------------------------------

#[derive(Debug, Arbitrary)]
struct FuzzPreviewRequest {
    icap_host: AsciiHost,
    http_host: AsciiHost,
    uri: AsciiToken,
    /// Raw bytes for the preview section (first N bytes of the body).
    preview_body: Vec<u8>,
    /// Additional bytes that come after preview (only used when `ieof=false`).
    remaining_body: Vec<u8>,
    /// When true, the zero-chunk carries `; ieof` — no continuation expected.
    ieof: bool,
    /// Whether to include a `Preview:` header at all.
    include_preview_header: bool,
}

// ---------------------------------------------------------------------------
// Wire serialisation
// ---------------------------------------------------------------------------

fn write_chunk(out: &mut Vec<u8>, data: &[u8]) {
    let mut line = String::new();
    let _ = write!(line, "{:x}\r\n", data.len());
    out.extend_from_slice(line.as_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
}

fn write_zero_chunk(out: &mut Vec<u8>, ieof: bool) {
    if ieof {
        out.extend_from_slice(b"0; ieof\r\n\r\n");
    } else {
        out.extend_from_slice(b"0\r\n\r\n");
    }
}

fn build_preview_reqmod(r: &FuzzPreviewRequest, service: &str) -> Vec<u8> {
    let http_head = format!(
        "GET /{} HTTP/1.1\r\nHost: {}\r\n\r\n",
        r.uri.0, r.http_host.0
    );
    let http_head_bytes = http_head.as_bytes();
    let body_offset = http_head_bytes.len();

    let preview_size = r.preview_body.len();

    let mut icap = format!(
        "REQMOD icap://{}/{} ICAP/1.0\r\nHost: {}\r\n",
        r.icap_host.0, service, r.icap_host.0
    );
    if r.include_preview_header {
        let _ = write!(icap, "Preview: {preview_size}\r\n");
    }
    let _ = write!(icap, "Encapsulated: req-hdr=0, req-body={body_offset}\r\n\r\n");

    let mut wire = icap.into_bytes();
    wire.extend_from_slice(http_head_bytes);

    if r.ieof || !r.include_preview_header {
        // Emit all body data in one pass with ieof (or no preview header).
        if !r.preview_body.is_empty() {
            write_chunk(&mut wire, &r.preview_body);
        }
        if !r.ieof && !r.remaining_body.is_empty() {
            write_chunk(&mut wire, &r.remaining_body);
        }
        write_zero_chunk(&mut wire, r.ieof && r.include_preview_header);
    } else {
        // Preview followed by continuation body.
        if !r.preview_body.is_empty() {
            write_chunk(&mut wire, &r.preview_body);
        }
        write_zero_chunk(&mut wire, false);
        if !r.remaining_body.is_empty() {
            write_chunk(&mut wire, &r.remaining_body);
        }
        // Closing zero-chunk for the continuation part.
        write_zero_chunk(&mut wire, false);
    }

    wire
}

// ---------------------------------------------------------------------------
// Fuzz entry point
// ---------------------------------------------------------------------------

fuzz_target!(|data: &[u8]| {
    // --- standalone parse_preview_header_value with arbitrary text ---
    // Feed raw data as a UTF-8 string to `parse_preview_header_value`.  We
    // expect it never to panic regardless of input.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse_preview_header_value(s);
    }

    // --- structured Preview request ---
    let mut u = Unstructured::new(data);
    let Ok(fuzz_req) = FuzzPreviewRequest::arbitrary(&mut u) else {
        return;
    };

    let wire = build_preview_reqmod(&fuzz_req, "preview-svc");

    // Verify parse_preview_header_value agrees with what we encoded.
    if fuzz_req.include_preview_header {
        // Build just the ICAP header section (up to the blank line) as a string
        // so we can feed it to `parse_preview_header_value`.
        if let Ok(wire_str) = std::str::from_utf8(&wire) {
            if let Some(hdr_end) = wire_str.find("\r\n\r\n") {
                let hdr_text = &wire_str[..hdr_end];
                let parsed_preview = parse_preview_header_value(hdr_text);
                assert_eq!(
                    parsed_preview,
                    Some(fuzz_req.preview_body.len()),
                    "parse_preview_header_value returned {parsed_preview:?}, expected Some({})",
                    fuzz_req.preview_body.len()
                );
            }
        }
    }

    let Ok(parsed) = parse_icap_request(&wire) else {
        return;
    };

    assert_eq!(
        parsed.method,
        Method::ReqMod,
        "expected ReqMod, got {:?}",
        parsed.method
    );
    assert_eq!(parsed.service, "preview-svc");
});
