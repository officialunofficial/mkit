//! Integration test: write a pinned golden blob through the
//! [`ObjectStore`] and confirm the resulting on-disk path and hash are
//! stable.
//!
//! Cross-binds the store layout (`docs/SPEC-OBJECTS.md` §10) to the
//! canonical byte format pinned by `tests/golden.rs`.

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

// ---- WriteBatch black-box durability contract ------------------------
//
// The flush-ordering and flush-count proofs live as unit tests in
// `src/batch.rs` (they need the pub(crate) Syncer seam). These tests
// pin the externally observable contract: visibility is deferred to
// commit, aborted batches leave nothing behind, and concurrent batches
// over overlapping objects do not corrupt the store.

#[test]
fn commit_makes_objects_readable_across_handles() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = ObjectStore::init(dir.path()).unwrap();

    let batch = store.batch();
    let hashes: Vec<_> = (0u32..20)
        .map(|i| batch.write(format!("object {i}").as_bytes()).unwrap())
        .collect();
    batch.commit().unwrap();

    let other = ObjectStore::open(dir.path()).unwrap();
    for (i, h) in hashes.iter().enumerate() {
        assert_eq!(other.read(h).unwrap(), format!("object {i}").as_bytes());
    }
}

#[test]
fn uncommitted_batch_objects_unreadable() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = ObjectStore::init(dir.path()).unwrap();

    let batch = store.batch();
    let h = batch.write(b"never committed").unwrap();

    let other = ObjectStore::open(dir.path()).unwrap();
    assert!(!other.contains(&h));
    assert!(other.read(&h).is_err());
    drop(batch);
    assert!(
        !other.contains(&h),
        "dropped batch must leave the object absent"
    );
    assert!(
        other.iter_object_hashes().unwrap().is_empty(),
        "store must be empty after an aborted batch"
    );
}

#[test]
fn interleaved_batches_do_not_corrupt() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = ObjectStore::init(dir.path()).unwrap();

    // Two batches stage an overlapping set of objects, then both
    // commit. Content-addressing must make this race benign: every
    // object readable, bytes intact.
    let a = store.batch();
    let b = store.batch();
    let shared: Vec<&[u8]> = vec![b"both stage me", b"me too"];
    let mut hashes = Vec::new();
    for bytes in &shared {
        hashes.push(a.write(bytes).unwrap());
        assert_eq!(*hashes.last().unwrap(), b.write(bytes).unwrap());
    }
    let only_a = a.write(b"only in a").unwrap();
    let only_b = b.write(b"only in b").unwrap();
    a.commit().unwrap();
    b.commit().unwrap();

    assert_eq!(store.read(&hashes[0]).unwrap(), shared[0]);
    assert_eq!(store.read(&hashes[1]).unwrap(), shared[1]);
    assert_eq!(store.read(&only_a).unwrap(), b"only in a");
    assert_eq!(store.read(&only_b).unwrap(), b"only in b");
}
