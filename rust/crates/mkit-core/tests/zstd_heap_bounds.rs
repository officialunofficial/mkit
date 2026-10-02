//! Meter the actual pure-Rust decoder, without native C feature unification.
#![cfg(all(feature = "pack-ruzstd", not(feature = "pack-zstd")))]
#![allow(clippy::unwrap_used)]

#[path = "../../../tests/support/zstd_heap_bounds.rs"]
mod support;

#[test]
fn corrupt_zstd_frames_bound_heap() {
    support::corrupt_zstd_frames_bound_heap();
}
