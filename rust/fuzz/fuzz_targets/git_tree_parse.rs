//! cargo-fuzz target — git-bridge import parser (`git_tree_parse`). See sibling
//! `delta.rs` for guardrail rationale; this is the SPEC-GIT-IMPORT §2
//! untrusted-input boundary.

#![no_main]
#![cfg(feature = "libfuzzer")]

use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU32, Ordering};

use mkit_fuzz::{MAX_ITER, git_tree_parse_one_iteration, run_one};

static ITERS: AtomicU32 = AtomicU32::new(0);

fuzz_target!(|data: &[u8]| {
    let n = ITERS.fetch_add(1, Ordering::Relaxed);
    if n >= MAX_ITER {
        return;
    }
    let _ = run_one(data, git_tree_parse_one_iteration);
});
