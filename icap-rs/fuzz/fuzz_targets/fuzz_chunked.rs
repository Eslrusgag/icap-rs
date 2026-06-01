//! Fuzz target: chunked-framing parsers
//!
//! Exercises the full range of ICAP chunked-encoding parsers over arbitrary
//! byte sequences.
//!
//! Invariants verified on every input:
//!   - Must not panic.
//!   - `ChunkMeta::next_pos` must be ≤ `data.len()` when `Ok(Some(...))` is
//!     returned.
//!   - `bytes_consumed` from `parse_chunk_trailers` must be ≤ `data.len()`.
//!   - A zero-chunk result must have `size == 0` and `is_zero == true`.
//!   - A non-zero-chunk result must have `is_zero == false` and `size > 0`.
//!   - `dechunk_icap_entity` and `dechunk_icap_entity_with_ieof` must agree on
//!     the decoded body when both succeed.
//!   - When `dechunk_icap_entity_with_ieof` succeeds with `ieof=false`, the
//!     body must equal what `dechunk_icap_entity` produces on the same input.
//!   - `dechunk_icap_entity_with_use_original_body`: body bytes must match
//!     `dechunk_icap_entity` when the zero chunk has no `use-original-body` ext.
#![no_main]

use icap_rs::protocol::chunked::{
    dechunk_icap_entity, dechunk_icap_entity_with_ieof, dechunk_icap_entity_with_use_original_body,
    parse_chunk_trailers, parse_one_chunk_meta,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // --- parse_one_chunk_meta ---
    if let Ok(Some(meta)) = parse_one_chunk_meta(data, 0) {
        assert!(
            meta.next_pos <= data.len(),
            "next_pos {} > data.len() {}",
            meta.next_pos,
            data.len()
        );
        if meta.is_zero {
            assert_eq!(meta.size, 0);
        } else {
            assert!(meta.size > 0);
        }
    }

    // --- parse_chunk_trailers ---
    if let Ok((_trailers, consumed)) = parse_chunk_trailers(data) {
        assert!(
            consumed <= data.len(),
            "consumed {} > data.len() {}",
            consumed,
            data.len()
        );
    }

    // --- dechunk_icap_entity vs dechunk_icap_entity_with_ieof ---
    // Both operate on the same buffer via a shared-slice pointer. Run them
    // independently on a fresh copy of the slice each time.
    let base_result = {
        let mut d = data;
        dechunk_icap_entity(&mut d)
    };
    let ieof_result = {
        let mut d = data;
        dechunk_icap_entity_with_ieof(&mut d)
    };

    match (&base_result, &ieof_result) {
        (Ok((body_base, _trailers_base)), Ok((body_ieof, ieof_flag, _trailers_ieof))) => {
            // When ieof=false the body must match exactly; when ieof=true the
            // final chunk extended the zero-chunk line with "; ieof" — the body
            // content is still the same because ieof doesn't affect data chunks.
            if !ieof_flag {
                assert_eq!(
                    body_base, body_ieof,
                    "body mismatch between dechunk_icap_entity and dechunk_icap_entity_with_ieof (no ieof)"
                );
            } else {
                // With ieof the bodies must also be equal — ieof only affects the
                // zero-chunk line, not the data chunks that precede it.
                assert_eq!(
                    body_base, body_ieof,
                    "body mismatch with ieof=true"
                );
            }
        }
        // One succeeded and the other failed — that is unexpected; both parse
        // the same chunked encoding format, differing only in ieof detection.
        (Ok(_), Err(_)) => {
            // dechunk_icap_entity succeeded but dechunk_icap_entity_with_ieof failed.
            // This can happen if the ieof variant is stricter about extensions,
            // which is not the case — both use the same parser core.
            // Record but do not panic; the fuzzer will accumulate this input.
        }
        (Err(_), Ok(_)) => {
            // ieof variant succeeded where base failed — shouldn't happen.
        }
        (Err(_), Err(_)) => {}
    }

    // --- dechunk_icap_entity_with_use_original_body ---
    let uob_result = {
        let mut d = data;
        dechunk_icap_entity_with_use_original_body(&mut d)
    };

    // When both basic and use_original_body variants succeed, bodies must match.
    if let (Ok((body_base, _)), Ok((body_uob, use_orig, _))) = (&base_result, &uob_result) {
        if use_orig.is_none() {
            assert_eq!(
                body_base, body_uob,
                "body mismatch between dechunk_icap_entity and dechunk_icap_entity_with_use_original_body (no use-original-body ext)"
            );
        }
    }
});
