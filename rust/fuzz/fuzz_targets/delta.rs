//! cargo-fuzz target — `delta::decode`. Guardrail bodies live in
//! `mkit-fuzz` (`src/lib.rs`); this file is the libfuzzer entry point
//! and enforces the 100-iteration / 100 ms / 64 KiB caps in-target so
//! libfuzzer's own `loop {}` cannot overrun them.

#![no_main]
#![cfg(feature = "libfuzzer")]

use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU32, Ordering};

use mkit_fuzz::{MAX_ITER, delta_one_iteration, run_one};

static ITERS: AtomicU32 = AtomicU32::new(0);

fuzz_target!(|data: &[u8]| {
    // Guardrail #1: stop after MAX_ITER even if libfuzzer keeps calling.
    let n = ITERS.fetch_add(1, Ordering::Relaxed);
    if n >= MAX_ITER {
        return;
    }
    let _ = run_one(data, delta_one_iteration);
});
