use http::HeaderValue;
use icap_rs::error::Error;
use icap_rs::response::{StatusCode, parse_icap_response};

fn icap_bytes(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

#[test]
fn version_must_be_icap_1_0() {
    let raw = icap_bytes(
        "ICAP/2.0 200 OK\r\n\
         ISTag: x\r\n\
         Encapsulated: null-body=0\r\n\
         \r\n",
    );
    let err = parse_icap_response(&raw).unwrap_err();
    assert!(
        matches!(err, Error::InvalidVersion(ref v) if v == "ICAP/2.0"),
        "expected InvalidVersion(\"ICAP/2.0\"), got: {err:?}"
    );
}

#[test]
fn status_line_must_have_code() {
    let raw = icap_bytes(
        "ICAP/1.0 OK\r\n\
         ISTag: x\r\n\
         Encapsulated: null-body=0\r\n\
         \r\n",
    );
    let err = parse_icap_response(&raw).unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("status"),
        "expected invalid status line error; got {err}"
    );
}

#[test]
fn supports_multiword_reason_phrase() {
    let raw = icap_bytes(
        "ICAP/1.0 405 Method Not Allowed\r\n\
         ISTag: x\r\n\
         Encapsulated: null-body=0\r\n\
         \r\n",
    );
    let r = parse_icap_response(&raw).expect("parse ok");
    assert_eq!(r.status_code, StatusCode::MethodNotAllowed405);
    assert_eq!(r.status_text, "Method Not Allowed");
}

// 2) ISTag is mandatory

#[test]
fn istag_required_in_every_response() {
    let raw = icap_bytes(
        "ICAP/1.0 200 OK\r\n\
         Encapsulated: null-body=0\r\n\
         \r\n",
    );
    let err = parse_icap_response(&raw).unwrap_err();
    let m = err.to_string().to_lowercase();
    assert!(
        m.contains("istag"),
        "expected missing ISTag error; got: {m}"
    );
}

#[test]
fn istag_must_not_exceed_32_bytes() {
    // 33 bytes => should fail
    let too_long = "A".repeat(33);
    let raw = format!(
        "ICAP/1.0 200 OK\r\n\
         ISTag: {}\r\n\
         Encapsulated: null-body=0\r\n\
         \r\n",
        too_long
    );
    let err = parse_icap_response(raw.as_bytes()).unwrap_err();
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("istag") || msg.contains("32"),
        "expected ISTag length error; got: {msg}"
    );
}

#[test]
fn istag_at_most_32_bytes_is_ok() {
    // exactly 32 characters => should succeed
    let valid = "A".repeat(32);
    let raw = format!(
        "ICAP/1.0 200 OK\r\n\
         ISTag: {}\r\n\
         Encapsulated: null-body=0\r\n\
         \r\n",
        valid
    );
    let resp = parse_icap_response(raw.as_bytes()).expect("parse ok");
    let hdr = resp.get_header("ISTag").unwrap();
    assert_eq!(hdr, &HeaderValue::from_str(&valid).unwrap());
}

// 3) Encapsulated header: shape and restrictions

#[test]
fn encapsulated_required_for_200() {
    let raw = icap_bytes(
        "ICAP/1.0 200 OK\r\n\
         ISTag: x\r\n\
         \r\n",
    );
    let err = parse_icap_response(&raw).unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("encapsulated"),
        "expected missing Encapsulated; got {err}"
    );
}

#[test]
fn no_duplicate_encapsulated_headers() {
    let raw = icap_bytes(
        "ICAP/1.0 200 OK\r\n\
         ISTag: x\r\n\
         Encapsulated: res-hdr=0, res-body=100\r\n\
         Encapsulated: req-hdr=0\r\n\
         \r\n",
    );
    let err = parse_icap_response(&raw).unwrap_err();
    let m = err.to_string().to_lowercase();
    assert!(
        m.contains("duplicate") || m.contains("encapsulated"),
        "expected duplicate Encapsulated error; got: {m}"
    );
}

#[test]
fn invalid_encapsulated_tokens_are_rejected() {
    let raw = icap_bytes(
        "ICAP/1.0 200 OK\r\n\
         ISTag: x\r\n\
         Encapsulated: totally-wrong=abc, res-body=-5\r\n\
         \r\n",
    );
    let err = parse_icap_response(&raw).unwrap_err();
    let m = err.to_string().to_lowercase();
    assert!(
        m.contains("encapsulated") || m.contains("invalid") || m.contains("parse"),
        "expected invalid Encapsulated; got: {m}"
    );
}

#[test]
fn encapsulated_offsets_must_be_monotonic_and_in_range() {
    let raw = icap_bytes(
        "ICAP/1.0 200 OK\r\n\
         ISTag: x\r\n\
         Encapsulated: res-hdr=50, res-body=10\r\n\
         \r\n\
         HTTP/1.1 200 OK\r\n\
         Content-Length: 0\r\n\
         \r\n",
    );
    let err = parse_icap_response(&raw).unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("offset"),
        "expected offsets validation error; got: {err}"
    );
}

// 4) 204 No Content semantics

#[test]
fn valid_minimal_204() {
    let raw = icap_bytes(
        "ICAP/1.0 204 No Content\r\n\
         ISTag: x\r\n\
         Encapsulated: null-body=0\r\n\
         \r\n",
    );
    let r = parse_icap_response(&raw).expect("parse ok");
    assert_eq!(r.status_code, StatusCode::NoContent204);
    assert_eq!(
        r.get_header("Encapsulated").unwrap(),
        &HeaderValue::from_static("null-body=0")
    );
    assert!(r.body.is_empty(), "204 must not carry a body");
}

#[test]
fn rfc_204_must_have_null_body_header() {
    let raw = icap_bytes(
        "ICAP/1.0 204 No Content\r\n\
         ISTag: x\r\n\
         \r\n",
    );
    let err = parse_icap_response(&raw).unwrap_err();
    let m = err.to_string().to_lowercase();
    assert!(
        m.contains("encapsulated") || m.contains("null-body"),
        "expected missing null-body=0; got: {m}"
    );
}

#[test]
fn rfc_204_must_not_have_body_bytes() {
    let raw = icap_bytes(
        "ICAP/1.0 204 No Content\r\n\
         ISTag: x\r\n\
         Encapsulated: null-body=0\r\n\
         \r\n\
         ILLEGAL_BODY",
    );
    let err = parse_icap_response(&raw).unwrap_err();
    let m = err.to_string().to_lowercase();
    assert!(
        m.contains("204") && (m.contains("no body") || m.contains("null-body")),
        "expected 204-with-body error; got: {m}"
    );
}

// 5) 100 Continue and basic statuses

#[test]
fn supports_100_continue() {
    let raw = icap_bytes(
        "ICAP/1.0 100 Continue\r\n\
         ISTag: x\r\n\
         Encapsulated: null-body=0\r\n\
         \r\n",
    );
    let r = parse_icap_response(&raw).expect("parse ok");
    assert_eq!(r.status_code, StatusCode::Continue100);
}

#[test]
fn supports_404_not_found() {
    let raw = icap_bytes(
        "ICAP/1.0 404 ICAP Service not found\r\n\
         ISTag: x\r\n\
         Encapsulated: null-body=0\r\n\
         \r\n",
    );
    let r = parse_icap_response(&raw).expect("parse ok");
    assert_eq!(r.status_code, StatusCode::NotFound404);
    assert!(r.status_text.to_lowercase().contains("not"));
}

// 6) Case-insensitive headers

#[test]
fn header_lookup_is_case_insensitive() {
    let raw = icap_bytes(
        "ICAP/1.0 200 OK\r\n\
         isTag: X\r\n\
         eNcaPsulated: null-body=0\r\n\
         \r\n",
    );
    let r = parse_icap_response(&raw).expect("parse ok");
    assert_eq!(
        r.get_header("ISTag").unwrap(),
        &HeaderValue::from_static("X")
    );
    assert_eq!(
        r.get_header("Encapsulated").unwrap(),
        &HeaderValue::from_static("null-body=0")
    );
}

// 7) Misc: incomplete headers / CRLFCRLF

#[test]
fn error_on_incomplete_headers() {
    let raw = icap_bytes("ICAP/1.0 200 OK\r\nISTag: x\r\n");
    let err = parse_icap_response(&raw).unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("headers"),
        "expected incomplete headers error; got {err}"
    );
}

#[test]
fn allows_empty_reason_phrase() {
    let raw = icap_bytes(
        "ICAP/1.0 200 \r\n\
         ISTag: x\r\n\
         Encapsulated: null-body=0\r\n\
         \r\n",
    );
    let r = parse_icap_response(&raw).expect("parse ok");
    assert_eq!(r.status_code, StatusCode::Ok200);
    assert_eq!(r.status_text, "");
}

// 8) Positive sanity check for 200 + res-hdr skeleton

#[test]
fn ok_minimal_200_with_res_hdr_skeleton() {
    let raw = icap_bytes(
        "ICAP/1.0 200 OK\r\n\
         ISTag: x\r\n\
         Encapsulated: res-hdr=0\r\n\
         \r\n\
         HTTP/1.1 200 OK\r\n\
         Content-Length: 0\r\n\
         \r\n",
    );
    let r = parse_icap_response(&raw).expect("parse ok");
    assert_eq!(r.status_code, StatusCode::Ok200);
    assert!(r.body.len() >= 0);
}
