//! Borrowed staged-update envelope and inventory fuzz target.
#![no_main]
#![cfg(feature = "libfuzzer")]

use libfuzzer_sys::fuzz_target;
use mkit_fuzz::{MAX_ITER, run_one, staged_update_one_iteration};
use std::sync::atomic::{AtomicU32, Ordering};

static ITERS: AtomicU32 = AtomicU32::new(0);

fuzz_target!(|data: &[u8]| {
    if ITERS.fetch_add(1, Ordering::Relaxed) >= MAX_ITER {
        return;
    }
    let _ = run_one(data, staged_update_one_iteration);
});
