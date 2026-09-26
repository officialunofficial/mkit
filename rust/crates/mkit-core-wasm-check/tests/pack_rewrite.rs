//! Exercise raw/delta rewrites with a 32-bit usize and no zstd encoder.
#![allow(clippy::unwrap_used)]

use mkit_core::{
    delta, hash,
    object::{Blob, Object},
    pack::{
        DecodeLimits, NoExternalBases, PackEntries, PackEntry, PackWriter, decode_entries_with,
        rewrite_excluding,
    },
    serialize,
};
use std::collections::HashSet;

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn rewrite_through_taken_down_base_still_decodes() {
    let objects: Vec<_> = (0..3)
        .map(|i| {
            let mut data = vec![17; 2048];
            data[100] = i;
            let bytes = serialize::serialize(&Object::Blob(Blob { data })).unwrap();
            (hash::hash(&bytes), bytes)
        })
        .collect();
    let mut w = PackWriter::new();
    w.push_raw(objects[0].0, &objects[0].1).unwrap();
    for pair in objects.windows(2) {
        w.push_delta(&pair[0].0, &delta::encode(&pair[0].1, &pair[1].1).unwrap())
            .unwrap();
    }
    let pack = w.finish().unwrap();
    let excluded = HashSet::from([objects[0].0]);
    let result = rewrite_excluding(
        &pack,
        &excluded,
        &mut NoExternalBases,
        DecodeLimits::default(),
    )
    .unwrap();
    assert_eq!(result.removed, vec![objects[0].0]);
    assert_eq!(result.rawified, vec![objects[1].0]);
    // Native workspace feature unification may enable the zstd writer.
    // This harness's wasm build is decode-only and must emit v1.
    #[cfg(target_arch = "wasm32")]
    assert_eq!(&result.bytes[4..8], &1u32.to_le_bytes());
    let mut decoded = Vec::new();
    decode_entries_with(
        &result.bytes,
        &mut NoExternalBases,
        DecodeLimits::default(),
        |entry| {
            decoded.push((entry.id, entry.bytes.to_vec()));
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(decoded, objects[1..]);
    let mut entries = PackEntries::new(&result.bytes).unwrap();
    assert!(matches!(
        entries.next().unwrap().unwrap(),
        PackEntry::Raw { .. }
    ));
    assert!(
        matches!(entries.next().unwrap().unwrap(), PackEntry::Delta { base, .. } if base == objects[1].0)
    );
    let again = rewrite_excluding(
        &pack,
        &excluded,
        &mut NoExternalBases,
        DecodeLimits::default(),
    )
    .unwrap();
    assert_eq!(result, again);
}
