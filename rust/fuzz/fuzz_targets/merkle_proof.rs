//! cargo-fuzz target — merkle object identity + inclusion-proof
//! verification. See sibling `delta.rs` for guardrail rationale. Building
//! an id and verifying a proof must never panic on adversarial input.

#![no_main]
#![cfg(feature = "libfuzzer")]

use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU32, Ordering};

use mkit_fuzz::{MAX_ITER, merkle_proof_one_iteration, run_one};

static ITERS: AtomicU32 = AtomicU32::new(0);

fuzz_target!(|data: &[u8]| {
    let n = ITERS.fetch_add(1, Ordering::Relaxed);
    if n >= MAX_ITER {
        return;
    }
    let _ = run_one(data, merkle_proof_one_iteration);
});
