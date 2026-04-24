//! Integration test: write a harvested-from-Zig golden blob through the
//! Rust [`ObjectStore`] and confirm the resulting on-disk path and hash
//! match what the Zig reference implementation would produce.
//!
//! Cross-binds the store layout (`docs/SPEC-OBJECTS.md` §10) to the
//! canonical byte format already pinned by `tests/golden.rs`.

use std::fs;
use std::path::PathBuf;

use mkit_core::hash::{from_hex, hash, to_hex};
use mkit_core::{ObjectStore, deserialize};

fn golden_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("tests");
    d.push("golden");
    d.push("phase1");
    d
}

/// Pull the `blake3` field out of a sidecar JSON without bringing in
/// `serde`. The file is hand-written by the harvester and uses a fixed
/// shape; we only need one field, so a tiny string scan is enough.
fn blake3_from_sidecar(name: &str) -> String {
    let path = golden_dir().join(format!("{name}.json"));
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read sidecar {}: {e}", path.display()));
    let needle = "\"blake3\":";
    let after = raw
        .split(needle)
        .nth(1)
        .expect("sidecar lacks blake3 field");
    let q1 = after
        .find('"')
        .expect("sidecar blake3 missing opening quote");
    let after_q1 = &after[q1 + 1..];
    let q2 = after_q1
        .find('"')
        .expect("sidecar blake3 missing closing quote");
    after_q1[..q2].to_string()
}

#[test]
fn write_blob_golden_into_store() {
    let bytes = fs::read(golden_dir().join("blob.bin")).expect("blob.bin must exist");
    let expected_hex = blake3_from_sidecar("blob");
    let expected_hash = from_hex(&expected_hex).expect("sidecar hex parses");

    let dir = tempfile::TempDir::new().unwrap();
    let store = ObjectStore::init(dir.path()).unwrap();

    let written = store.write(&bytes).unwrap();
    assert_eq!(
        to_hex(&written),
        expected_hex,
        "written hash must match the harvested sidecar"
    );
    assert_eq!(written, expected_hash);
    assert!(store.contains(&written));

    // Confirm the .mkit/objects/<dd>/<62-hex> layout.
    let objects_root = dir.path().join(".mkit").join("objects");
    let shard = objects_root.join(&expected_hex[..2]);
    let final_path = shard.join(&expected_hex[2..]);
    assert!(
        final_path.is_file(),
        "expected file at {} (shard layout broken?)",
        final_path.display()
    );

    let on_disk = fs::read(&final_path).unwrap();
    assert_eq!(on_disk, bytes, "on-disk bytes must match the input");
    assert_eq!(hash(&on_disk), expected_hash);

    // Read-through verification path also sees the same bytes.
    let read_back = store.read(&written).unwrap();
    assert_eq!(read_back, bytes);

    // And the typed read decodes into the exact Object the harvester encoded.
    let parsed = store.read_object(&written).unwrap();
    let baseline = deserialize(&bytes).unwrap();
    assert_eq!(parsed, baseline);
}
