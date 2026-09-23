//! Bounded MKHG v1 malformed-envelope fuzz target.
#![no_main]
#![cfg(feature = "libfuzzer")]
use libfuzzer_sys::fuzz_target;
use mkit_fuzz::{MAX_ITER, hosted_grant_one_iteration, run_one};
use std::sync::atomic::{AtomicU32, Ordering};

static ITERS: AtomicU32 = AtomicU32::new(0);

fuzz_target!(|data: &[u8]| {
    if ITERS.fetch_add(1, Ordering::Relaxed) >= MAX_ITER {
        return;
    }
    let _ = run_one(data, hosted_grant_one_iteration);
});
