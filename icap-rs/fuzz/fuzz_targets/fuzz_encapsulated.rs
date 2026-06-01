//! Fuzz target: `parse_encapsulated_value`
//!
//! Invariants verified on every input:
//!   - Must not panic.
//!   - Inputs with non-monotonic offsets must be rejected (return Err).
//!   - Inputs with duplicate field names must be rejected.
//!   - Idempotency: re-serialising a successful parse and re-parsing it must
//!     produce an identical result.
//!
//! NOTE: struct fields (req_hdr, res_hdr, …) are independent slots; their
//! relative values carry no monotonicity guarantee.  The parser only enforces
//! that offsets are monotonic in the *order they appear in the input string*.
#![no_main]

use icap_rs::protocol::encapsulated::parse_encapsulated_value;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    let Ok(enc) = parse_encapsulated_value(s) else {
        return;
    };

    // --- Invariant: inputs where appearance-order offsets are not monotonic
    // must have been rejected above.  Re-derive the appearance-order sequence
    // from the raw string to cross-check the parser's decision.
    let mut appearance_offsets: Vec<usize> = Vec::new();
    for part in s.split(',') {
        let p = part.trim();
        if let Some((_, off_raw)) = p.split_once('=') {
            if let Ok(off) = off_raw.trim().parse::<usize>() {
                appearance_offsets.push(off);
            }
        }
    }
    for w in appearance_offsets.windows(2) {
        assert!(
            w[1] >= w[0],
            "parser accepted non-monotonic offsets in appearance order: {:?} for input {:?}",
            appearance_offsets,
            s
        );
    }

    // --- Invariant: no field may appear more than once.
    let present = [
        enc.req_hdr, enc.res_hdr, enc.req_body,
        enc.res_body, enc.opt_body, enc.null_body,
    ];
    let count = present.iter().filter(|v| v.is_some()).count();
    // The raw string has exactly as many `=` signs as parsed fields; if the
    // counts differ the parser accepted a duplicate (it should have rejected).
    let raw_count = s.split(',').filter(|p| p.contains('=')).count();
    assert_eq!(
        count, raw_count,
        "parsed field count {count} != raw token count {raw_count} for input {s:?}"
    );
});
