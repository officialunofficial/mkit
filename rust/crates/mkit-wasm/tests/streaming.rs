//! Integration tests for the streaming primitives added to mkit-wasm
//! (`chunk_boundaries`, `chunked_blob_encode`, `delta_encode`,
//! `bao_encode` + `bao_slice` + `bao_verify_slice`).
//!
//! These run on native — the underlying implementations are the same
//! pure-Rust code paths the wasm build exports, so exercising them
//! here covers correctness. The `wasm-bindgen-test` harness needs a
//! browser/node driver we don't wire up in CI today, so gate those
//! with `#[cfg(target_arch = "wasm32")]` under a separate module.

#![allow(clippy::unwrap_used)]

use mkit_wasm::{
    bao_encode, bao_slice, bao_verify_slice, chunk_boundaries, chunked_blob_encode, delta_encode,
};

/// Deterministic pseudorandom bytes — xorshift*, not crypto. Keeps tests
/// reproducible across machines without pulling in a `rand` version.
fn pseudorandom(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.max(1);
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        for b in z.to_le_bytes() {
            if out.len() == len {
                break;
            }
            out.push(b);
        }
    }
    out
}

// ---- chunker ----

#[test]
fn chunker_emits_ordered_contiguous_chunks() {
    let data = pseudorandom(0xDEAD_BEEF, 300 * 1024);
    let res = chunk_boundaries(&data).unwrap();
    assert!(res.chunk_count() > 1, "expected multi-chunk output");
    assert_eq!(res.avg(), 64 * 1024);
    assert_eq!(res.min(), 16 * 1024);
    assert_eq!(res.max(), 256 * 1024);

    let mut expected_offset = 0u32;
    let mut total = 0u32;
    for i in 0..res.chunk_count() {
        let c = res.chunk(i).unwrap();
        assert_eq!(c.offset(), expected_offset, "chunks must be contiguous");
        assert!(c.len() > 0);
        expected_offset = expected_offset.checked_add(c.len()).unwrap();
        total = total.checked_add(c.len()).unwrap();
        assert_eq!(c.hash_hex().len(), 64);
    }
    assert_eq!(total as usize, data.len());
}

// ---- chunked_blob ----

#[test]
fn chunked_blob_encode_is_deterministic_and_references_chunks() {
    let data = pseudorandom(0xCAFE_BABE, 200 * 1024);
    let a = chunked_blob_encode(&data).unwrap();
    let b = chunked_blob_encode(&data).unwrap();
    assert_eq!(a.root_hash_hex(), b.root_hash_hex());
    assert_eq!(a.bytes_len() as usize, data.len());
    assert_eq!(a.chunk_count(), b.chunk_count());
    // First chunk starts at 0.
    let c0 = a.chunk(0).unwrap();
    assert_eq!(c0.offset(), 0);
}

// ---- delta ----

#[test]
fn delta_small_edit_is_much_smaller_than_full() {
    // A medium payload with a tiny tail edit — the writer should emit a
    // single big COPY plus a small INSERT.
    let base = pseudorandom(0xABCD, 64 * 1024);
    let mut target = base.clone();
    target.extend_from_slice(b"// one small change\n");

    let d = delta_encode(&base, &target).unwrap();
    assert_eq!(d.full_size() as usize, target.len());
    assert!(
        (d.bytes_on_wire() as usize) < target.len() / 4,
        "delta should be <25% of target, got {} vs {}",
        d.bytes_on_wire(),
        target.len(),
    );
    assert!(d.op_count() >= 1);

    // First op should be a COPY of the unchanged prefix.
    let op0 = d.op(0).unwrap();
    assert_eq!(op0.kind(), "copy");
    assert!(op0.offset().is_some());
}

#[test]
fn delta_empty_base_is_all_inserts() {
    let target = b"hello world, mkit streaming demo".to_vec();
    let d = delta_encode(b"", &target).unwrap();
    for i in 0..d.op_count() {
        let op = d.op(i).unwrap();
        assert_eq!(op.kind(), "insert");
        assert!(op.offset().is_none());
    }
    // Sum of INSERT lengths must equal target.
    let insert_total: u32 = (0..d.op_count()).map(|i| d.op(i).unwrap().len()).sum();
    assert_eq!(insert_total as usize, target.len());
}

// ---- bao ----

#[test]
fn bao_roundtrip_slice_verifies() {
    let data = pseudorandom(0xFEED_FACE, 128 * 1024);
    let enc = bao_encode(&data).unwrap();
    let outboard = enc.outboard();
    let hash_hex = enc.hash_hex();

    // Slice the middle 32 KiB.
    let offset = 16 * 1024u32;
    let len = 32 * 1024u32;
    let slice = bao_slice(&outboard, &data, offset, len).unwrap();

    let v = bao_verify_slice(&hash_hex, &slice, offset, len).unwrap();
    assert!(v.ok(), "verify failed: {:?}", v.error());
    let verified = v.bytes().unwrap();
    assert_eq!(
        &verified[..],
        &data[offset as usize..(offset + len) as usize],
    );
}

#[test]
fn bao_tampered_slice_fails_verify() {
    let data = pseudorandom(0x1234_5678, 64 * 1024);
    let enc = bao_encode(&data).unwrap();
    let outboard = enc.outboard();
    let offset = 0u32;
    let len = 8 * 1024u32;

    let slice = bao_slice(&outboard, &data, offset, len).unwrap();
    let mut bad = slice.to_vec();
    // Flip a byte near the end — inside the data region, past the
    // header/proof nodes.
    let idx = bad.len() - 1;
    bad[idx] ^= 0x01;

    let v = bao_verify_slice(&enc.hash_hex(), &bad, offset, len).unwrap();
    assert!(!v.ok(), "tamper should not verify");
    assert!(v.error().is_some());
    assert!(v.bytes().is_none());
}

// ---- full pipeline smoke: 1 MiB → chunk → chunked blob → delta → bao ----

#[test]
fn streaming_pipeline_end_to_end_1mib() {
    let hero = pseudorandom(0x5EED_1234, 1024 * 1024); // 1 MiB

    // 1. chunk
    let chunks = chunk_boundaries(&hero).unwrap();
    assert!(chunks.chunk_count() >= 4);

    // 2. chunked blob
    let cb = chunked_blob_encode(&hero).unwrap();
    assert_eq!(cb.bytes_len() as usize, hero.len());
    // Chunk count from both paths must match — same v1 boundaries.
    assert_eq!(cb.chunk_count(), chunks.chunk_count());

    // 3. delta against a slightly-edited copy
    let mut edited = hero.clone();
    let mid = edited.len() / 2;
    edited[mid..mid + 4].copy_from_slice(b"EDIT");
    let d = delta_encode(&hero, &edited).unwrap();
    assert_eq!(d.full_size() as usize, edited.len());
    // A 4-byte in-place edit with CDC-sized data should compress heavily.
    assert!(
        (d.bytes_on_wire() as usize) < hero.len() / 2,
        "delta should be <50% of hero"
    );

    // 4. bao encode + slice + verify
    let enc = bao_encode(&hero).unwrap();
    let offset = 256 * 1024u32;
    let len = 64 * 1024u32;
    let slice = bao_slice(&enc.outboard(), &hero, offset, len).unwrap();
    let v = bao_verify_slice(&enc.hash_hex(), &slice, offset, len).unwrap();
    assert!(v.ok(), "bao verify failed: {:?}", v.error());
    assert_eq!(
        &v.bytes().unwrap()[..],
        &hero[offset as usize..(offset + len) as usize],
    );
}
