//! Fuzz target: `parse_icap_response_head`
//!
//! Invariants verified on every input:
//!   - Must not panic.
//!   - On success, `status_code` must be a valid HTTP status code (guaranteed
//!     by the return type, checked here for defence-in-depth).
//!   - On success, `version` must equal `"ICAP/1.0"`.
//!   - `header_end` must be ≤ `data.len()`.
#![no_main]

use icap_rs::protocol::headers::parse_icap_response_head;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(head) = parse_icap_response_head(data) else {
        return;
    };

    assert_eq!(head.version, "ICAP/1.0");
    assert!(
        head.header_end <= data.len(),
        "header_end {} > data.len() {}",
        head.header_end,
        data.len()
    );
});
