//! cargo-fuzz target — SPEC-WRITE-GRANTS epoch and visibility statement
//! codecs and the stateless verifier (`epoch_visibility_parse`). See sibling
//! `delta.rs` for guardrail rationale. Invariant: no panic, every accepted
//! statement re-encodes to exactly itself, and nothing unsigned verifies.

#![no_main]
#![cfg(feature = "libfuzzer")]

use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU32, Ordering};

use mkit_fuzz::{MAX_ITER, epoch_visibility_parse_one_iteration, run_one};

static ITERS: AtomicU32 = AtomicU32::new(0);

fuzz_target!(|data: &[u8]| {
    let n = ITERS.fetch_add(1, Ordering::Relaxed);
    if n >= MAX_ITER {
        return;
    }
    let _ = run_one(data, epoch_visibility_parse_one_iteration);
});
