//! cargo-fuzz target for bounded authenticated selected-file overlays.

#![no_main]
#![cfg(feature = "libfuzzer")]

use std::sync::atomic::{AtomicU32, Ordering};

use libfuzzer_sys::fuzz_target;
use mkit_fuzz::{MAX_ITER, partial_overlay_one_iteration, run_one};

static ITERS: AtomicU32 = AtomicU32::new(0);

fuzz_target!(|data: &[u8]| {
    if ITERS.fetch_add(1, Ordering::Relaxed) >= MAX_ITER {
        return;
    }
    let _ = run_one(data, partial_overlay_one_iteration);
});
