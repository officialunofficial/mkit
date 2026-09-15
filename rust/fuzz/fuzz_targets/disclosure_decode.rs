//! cargo-fuzz target — partial-disclosure bundle decoding (issue #1015
//! verifier kit PR 2, SPEC-DISCLOSURE). See sibling `merkle_proof.rs` for
//! guardrail rationale. Decoding a bundle must never panic on adversarial
//! input, regardless of the commit id it is checked against.

#![no_main]
#![cfg(feature = "libfuzzer")]

use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU32, Ordering};

use mkit_fuzz::{MAX_ITER, disclosure_decode_one_iteration, run_one};

static ITERS: AtomicU32 = AtomicU32::new(0);

fuzz_target!(|data: &[u8]| {
    let n = ITERS.fetch_add(1, Ordering::Relaxed);
    if n >= MAX_ITER {
        return;
    }
    let _ = run_one(data, disclosure_decode_one_iteration);
});
