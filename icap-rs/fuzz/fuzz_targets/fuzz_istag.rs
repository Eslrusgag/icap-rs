//! Fuzz target: `validate_istag` and `istag_header_value`
//!
//! Invariants verified on every input:
//!   - Neither function must panic.
//!   - If `validate_istag` returns `Ok`, then `istag_header_value` must also
//!     return `Ok` (they share the same acceptance criteria).
//!   - The wire value produced by `istag_header_value` must always be a
//!     quoted-string: starts and ends with `"`.
#![no_main]

use icap_rs::protocol::istag::{istag_header_value, validate_istag};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    let valid = validate_istag(s);
    let wire = istag_header_value(s);

    // Both functions must agree on validity.
    assert_eq!(
        valid.is_ok(),
        wire.is_ok(),
        "validate_istag and istag_header_value disagree for {:?}",
        s
    );

    if let Ok(hv) = wire {
        // Use as_bytes() — to_str() would panic on obs-text bytes if they
        // ever slipped through, which itself would be a bug we'd miss.
        let bytes = hv.as_bytes();
        assert!(
            bytes.first() == Some(&b'"') && bytes.last() == Some(&b'"'),
            "wire ISTag is not a quoted-string: {:?}",
            hv
        );
        // After the validate_istag fix, ISTag wire values must be pure ASCII.
        assert!(
            hv.to_str().is_ok(),
            "wire ISTag contains non-ASCII bytes: {:?}",
            hv
        );
    }
});
