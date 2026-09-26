//! A pack entry whose `payload_len` is `u32::MAX` must be a clean
//! `PackError`, never an overflow trap, on a 32-bit `usize`.
//!
//! `pos + payload_len` overflowed on `wasm32-unknown-unknown` (release
//! builds keep `overflow-checks`), trapping in `PackEntries::new`,
//! `delta_base_hashes`, `verify_closure_packs` (exported by mkit-wasm) and
//! `decode_entries_with`. Found by the WP-4.2 review's wasm32 probe.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

use mkit_core::ops::graph::ClosureMode;
use mkit_core::pack::{
    DecodeLimits, HEADER_LEN, NoExternalBases, PackEntries, PackError, PackWriter, TRAILER_LEN,
    decode_entries_with, delta_base_hashes, rewrite_excluding,
};

/// A one-entry raw pack with the entry's `payload_len` patched to `len`
/// and the trailer recomputed.
fn pack_with_payload_len(len: u32) -> Vec<u8> {
    let blob = mkit_core::serialize::serialize(&mkit_core::object::Object::Blob(
        mkit_core::object::Blob {
            data: vec![1, 2, 3],
        },
    ))
    .unwrap();
    let mut w = PackWriter::new_raw_only();
    w.push_raw(mkit_core::hash::hash(&blob), &blob).unwrap();
    let mut pack = w.finish().unwrap();
    pack[HEADER_LEN + 1..HEADER_LEN + 5].copy_from_slice(&len.to_le_bytes());
    let split = pack.len() - TRAILER_LEN;
    let trailer = mkit_core::hash::hash(&pack[..split]);
    pack[split..].copy_from_slice(&trailer);
    pack
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn payload_len_near_u32_max_is_a_clean_error() {
    for len in [u32::MAX, u32::MAX - 4, 0x8000_0000, 0x7FFF_FFFF] {
        let pack = pack_with_payload_len(len);
        assert!(matches!(
            PackEntries::new(&pack).unwrap_err(),
            PackError::UnexpectedEof
        ));
        assert!(matches!(
            delta_base_hashes(&pack).unwrap_err(),
            PackError::UnexpectedEof
        ));
        assert!(
            mkit_core::verify::verify_closure_packs(&[0; 32], ClosureMode::Snapshot, &[&pack])
                .is_err()
        );
        let err = decode_entries_with(&pack, &mut NoExternalBases, DecodeLimits::default(), |_| {
            Ok(())
        })
        .unwrap_err();
        assert!(matches!(err, PackError::UnexpectedEof), "{err:?}");
        let err = rewrite_excluding(
            &pack,
            &std::collections::HashSet::new(),
            &mut NoExternalBases,
            DecodeLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(err, PackError::UnexpectedEof), "{err:?}");
    }
}
