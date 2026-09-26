//! Decode every committed C-encoded SPEC-PACKFILE v2 fixture through
//! mkit-core built with `pack-ruzstd` only, and check the recovered
//! objects against the fixture sidecars (SPEC-PACKFILE §10 #20).
//!
//! On `wasm32-unknown-unknown` this is the only lane that exercises the
//! pure-Rust decoder with a 32-bit `usize`, where hand-written frame
//! parsing can overflow (the 5-byte literals header in
//! `large_literals.bin` did). Fixtures are embedded with `include_bytes!`
//! because the wasm32 test runner has no filesystem.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

use std::collections::HashMap;

use mkit_core::hash::{self, Hash, from_hex, to_hex};
use mkit_core::pack::{PackEntries, PackEntry};
use serde_json::Value;

macro_rules! fixture {
    ($name:literal) => {
        (
            $name,
            include_bytes!(concat!("../../../tests/golden/pack-v2/", $name, ".bin")).as_slice(),
            include_str!(concat!("../../../tests/golden/pack-v2/", $name, ".json")),
        )
    };
}

const MANIFEST: &str = include_str!("../../../tests/golden/pack-v2/MANIFEST.txt");

const FIXTURES: [(&str, &[u8], &str); 5] = [
    fixture!("raw_4k_repeat"),
    fixture!("delta_repeat"),
    fixture!("mixed"),
    fixture!("tree_and_commit"),
    fixture!("large_literals"),
];

fn manifest_digest(file: &str) -> &'static str {
    MANIFEST
        .lines()
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| {
            let (f, d) = l.split_once(' ')?;
            (f == file).then_some(d.trim())
        })
        .unwrap_or_else(|| panic!("{file} is not listed in MANIFEST.txt"))
}

fn hex_field(v: &Value, key: &str) -> Hash {
    from_hex(v[key].as_str().unwrap()).unwrap()
}

/// The harness is only meaningful if the wasm32 lane really is 32-bit.
#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn wasm32_lane_has_a_32_bit_usize() {
    let expected = if cfg!(target_arch = "wasm32") {
        32
    } else {
        usize::BITS
    };
    assert_eq!(usize::BITS, expected);
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn pack_v2_fixtures_decode_through_ruzstd() {
    let listed = MANIFEST.lines().filter(|l| l.contains(".bin ")).count();
    assert_eq!(
        listed,
        FIXTURES.len(),
        "MANIFEST.txt and this harness disagree"
    );
    for (name, pack, sidecar) in FIXTURES {
        assert_eq!(
            to_hex(&hash::hash(pack)),
            manifest_digest(&format!("{name}.bin"))
        );
        assert_eq!(
            to_hex(&hash::hash(sidecar.as_bytes())),
            manifest_digest(&format!("{name}.json"))
        );
        let side: Value = serde_json::from_str(sidecar).unwrap();
        let want = side["entries"].as_array().unwrap();

        let mut resolved: HashMap<Hash, Vec<u8>> = HashMap::new();
        let mut count = 0;
        for (entry, w) in PackEntries::new(pack).unwrap().zip(want) {
            let (object, decoded) = match entry.unwrap_or_else(|e| panic!("{name}: {e}")) {
                PackEntry::Raw { bytes } => (bytes.to_vec(), bytes.into_owned()),
                PackEntry::Delta { base, stream } => (
                    mkit_core::delta::decode(&resolved[&base], &stream).unwrap(),
                    stream.into_owned(),
                ),
            };
            if let Some(d) = w["decoded_blake3"].as_str() {
                assert_eq!(to_hex(&hash::hash(&decoded)), d, "{name}: decoded payload");
            }
            assert_eq!(object.len() as u64, w["len"].as_u64().unwrap(), "{name}");
            assert_eq!(
                hash::hash(&object),
                hex_field(w, "blake3_of_bytes"),
                "{name}"
            );
            let obj = mkit_core::serialize::deserialize(&object).unwrap();
            let id = mkit_core::object::id_from_object(&obj, &object);
            assert_eq!(id, hex_field(w, "id"), "{name}: object id");
            resolved.insert(id, object);
            count += 1;
        }
        assert_eq!(count, want.len(), "{name}: every entry decoded");
    }
}
