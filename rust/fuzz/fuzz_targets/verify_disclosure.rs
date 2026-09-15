//! cargo-fuzz target — partial-disclosure bundle verification (issue
//! #1015 verifier kit PR 2, SPEC-DISCLOSURE). A fresh, real fixture is
//! built per call (real libfuzzer runs, unlike the unit-test loop, want
//! per-call isolation — mirrors `pack.rs`). Verifying must never panic; a
//! freshly built bundle must verify; a mutated bundle must reject
//! cleanly.

#![no_main]
#![cfg(feature = "libfuzzer")]

use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU32, Ordering};

use mkit_fuzz::{MAX_ITER, run_one, verify_disclosure_one_iteration};

static ITERS: AtomicU32 = AtomicU32::new(0);

fuzz_target!(|data: &[u8]| {
    let n = ITERS.fetch_add(1, Ordering::Relaxed);
    if n >= MAX_ITER {
        return;
    }
    let _ = run_one(data, verify_disclosure_one_iteration);
});
