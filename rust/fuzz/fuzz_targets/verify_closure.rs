//! cargo-fuzz target — `verify_closure` / `verify_closure_manifest`
//! (issue #1015 verifier kit PR 3, SPEC-DISCLOSURE §7). Never panics;
//! a freshly exported closure verifies; a mutated manifest rejects.

#![no_main]
#![cfg(feature = "libfuzzer")]

use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU32, Ordering};

use mkit_fuzz::{MAX_ITER, run_one, verify_closure_one_iteration};

static ITERS: AtomicU32 = AtomicU32::new(0);

fuzz_target!(|data: &[u8]| {
    let n = ITERS.fetch_add(1, Ordering::Relaxed);
    if n >= MAX_ITER {
        return;
    }
    let _ = run_one(data, verify_closure_one_iteration);
});
