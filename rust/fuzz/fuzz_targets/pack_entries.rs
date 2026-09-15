//! cargo-fuzz target — `PackEntries` store-less iterator (issue #1015
//! verifier kit PR 3). Never panics on adversarial pack bytes; agrees
//! with `PackReader::read` on validity for packs the reader accepts.

#![no_main]
#![cfg(feature = "libfuzzer")]

use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU32, Ordering};

use mkit_fuzz::{MAX_ITER, pack_entries_one_iteration, run_one};

static ITERS: AtomicU32 = AtomicU32::new(0);

fuzz_target!(|data: &[u8]| {
    let n = ITERS.fetch_add(1, Ordering::Relaxed);
    if n >= MAX_ITER {
        return;
    }
    let _ = run_one(data, pack_entries_one_iteration);
});
