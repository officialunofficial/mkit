//! Run the same allocator regression under node with real wasm32 usize.
// Native workspace feature unification selects the C decoder. Its window
// policy differs, so the native ruzstd lane lives in mkit-core's test binary.
#![cfg(target_arch = "wasm32")]
#![allow(clippy::unwrap_used)]

#[path = "../../../tests/support/zstd_heap_bounds.rs"]
mod support;

#[wasm_bindgen_test::wasm_bindgen_test]
fn corrupt_zstd_frames_bound_heap() {
    support::corrupt_zstd_frames_bound_heap();
}
