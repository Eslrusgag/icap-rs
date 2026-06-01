//! Fuzz target: embedded HTTP start-line parsers
//!
//! Exercises `parse_http_request_start_line` and
//! `parse_http_response_start_line` over arbitrary UTF-8 strings.
//!
//! Invariants verified on every input:
//!   - Must not panic.
//!   - On success, the HTTP version returned must be one of the known variants
//!     (the parser is strict and only accepts `HTTP/0.9`, `HTTP/1.0`,
//!     `HTTP/1.1`, `HTTP/2.0`, `HTTP/3.0`).
#![no_main]

use http::Version;
use icap_rs::protocol::http_embed::{
    parse_http_request_start_line, parse_http_response_start_line,
};
use libfuzzer_sys::fuzz_target;

const KNOWN_VERSIONS: &[Version] = &[
    Version::HTTP_09,
    Version::HTTP_10,
    Version::HTTP_11,
    Version::HTTP_2,
    Version::HTTP_3,
];

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok((_method, _uri, version)) = parse_http_request_start_line(s) {
        assert!(
            KNOWN_VERSIONS.contains(&version),
            "unexpected HTTP version from request parser: {:?}",
            version
        );
    }

    if let Ok((version, _status)) = parse_http_response_start_line(s) {
        assert!(
            KNOWN_VERSIONS.contains(&version),
            "unexpected HTTP version from response parser: {:?}",
            version
        );
    }
});
