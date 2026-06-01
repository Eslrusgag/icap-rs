//! Fuzz target: full ICAP request parser — raw bytes.
//!
//! Feeds arbitrary byte sequences directly into `parse_icap_request` and its
//! compatibility-mode variant. This exercises every layer of the server-side
//! parse path in a single call:
//!
//!   raw bytes
//!     → ICAP request-line + headers
//!     → Encapsulated offset calculation
//!     → embedded HTTP request/response start-line + headers
//!     → dechunked body assembly
//!
//! Invariants verified on every successful parse:
//!   - Method must be one of the three known ICAP methods.
//!   - `service` must be non-empty.
//!   - `allow_204` / `allow_206` are plain booleans — no constraint.
//!   - Both parser modes must agree: if strict accepts a payload, compat must
//!     also accept it (compat is a superset of strict).
#![no_main]

use icap_rs::Method;
use icap_rs::request::fuzz_api::{parse_icap_request, parse_icap_request_compat};
use libfuzzer_sys::fuzz_target;

const KNOWN_METHODS: &[Method] = &[Method::ReqMod, Method::RespMod, Method::Options];

fuzz_target!(|data: &[u8]| {
    let strict = parse_icap_request(data);
    let compat = parse_icap_request_compat(data);

    if let Ok(ref req) = strict {
        assert!(
            KNOWN_METHODS.contains(&req.method),
            "unexpected method {:?}",
            req.method
        );
        assert!(!req.service.is_empty(), "service must be non-empty");

        // Strict Ok ⟹ compat Ok (compat is a strict superset).
        assert!(
            compat.is_ok(),
            "strict accepted but compat rejected: {:?}",
            compat.unwrap_err()
        );
    }
});
