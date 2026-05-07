//! Golden-vector tests for the canonical object byte format.
//!
//! Loads the byte fixtures in `rust/tests/golden/phase1/` and asserts
//! that this crate:
//!
//! 1. Re-serializes byte-for-byte the same fixture (proves the encoder
//!    matches the spec, not just the decoder).
//! 2. Round-trips the fixture through `deserialize` -> `serialize`.
//! 3. Computes the BLAKE3 digest pinned in `MANIFEST.txt`.
//!
//! If you change byte layout in the spec, regenerate the fixtures
//! intentionally and then re-run this suite.

use std::fs;
use std::path::PathBuf;

use mkit_core::hash::{hash, to_hex};
use mkit_core::object::{
    Blob, ChunkedBlob, Commit, EntryMode, IDENTITY_MAX_LEN, Identity, IdentityKind, Object, Remix,
    RemixSource, Tree, TreeEntry,
};
use mkit_core::{deserialize, serialize};

fn golden_dir() -> PathBuf {
    // The fixtures live at <repo>/rust/tests/golden/phase1/. CARGO_MANIFEST_DIR
    // points at the crate (rust/crates/mkit-core); walk up two levels.
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop(); // crates/
    d.pop(); // rust/
    d.push("tests");
    d.push("golden");
    d.push("phase1");
    d
}

fn load(name: &str) -> Vec<u8> {
    let p = golden_dir().join(name);
    fs::read(&p).unwrap_or_else(|e| panic!("cannot read golden fixture {}: {e}", p.display()))
}

fn manifest_digest(name: &str) -> Option<String> {
    let raw = fs::read_to_string(golden_dir().join("MANIFEST.txt")).ok()?;
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let n = parts.next()?;
        let d = parts.next()?;
        if n == name {
            return Some(d.to_string());
        }
    }
    None
}

fn assert_object_matches(name: &str, obj: &Object) {
    let want = load(&format!("{name}.bin"));
    let got = serialize(obj).expect("test vector is valid");
    assert_eq!(
        got, want,
        "{name}.bin: re-serialized bytes differ from harvested vector"
    );
    let parsed = deserialize(&want).expect("golden fixture deserializes");
    assert_eq!(&parsed, obj, "{name}.bin: deserialized form differs");
    if let Some(want_hex) = manifest_digest(name) {
        let got_hex = to_hex(&hash(&want));
        assert_eq!(
            got_hex, want_hex,
            "{name}.bin: BLAKE3 digest does not match MANIFEST.txt"
        );
    }
}

// ---- Identity fixtures (raw wire form, no prologue) ----

fn assert_identity_matches(name: &str, id: &Identity) {
    let want = load(&format!("{name}.bin"));
    // Hand-encode per SPEC-OBJECTS §9: [u8 kind][u16 LE len][payload].
    assert!(id.is_valid());
    let mut buf = Vec::with_capacity(3 + id.bytes.len());
    buf.push(id.kind as u8);
    buf.extend_from_slice(&u16::try_from(id.bytes.len()).unwrap().to_le_bytes());
    buf.extend_from_slice(&id.bytes);
    assert_eq!(buf, want, "{name}.bin: identity bytes mismatch");
    if let Some(want_hex) = manifest_digest(name) {
        let got_hex = to_hex(&hash(&want));
        assert_eq!(got_hex, want_hex, "{name}.bin: BLAKE3 mismatch");
    }
}

// Pinned test constants — changing these will break golden vectors.
const PUBKEY_A: [u8; 32] = [0xAA; 32];
const PUBKEY_B: [u8; 32] = [0xBB; 32];
const SIGNER: [u8; 32] = [0x11; 32];
const SIGNATURE: [u8; 64] = [0x22; 64];
const TS: u64 = 1_700_000_000;

#[test]
fn identity_ed25519_matches_golden() {
    assert_identity_matches("identity_ed25519", &Identity::ed25519(PUBKEY_A));
}

#[test]
fn identity_opaque_matches_golden() {
    let payload = vec![0x2A, 0, 0, 0, 0, 0, 0, 0];
    let id = Identity {
        kind: IdentityKind::Opaque,
        bytes: payload,
    };
    assert_identity_matches("identity_opaque", &id);
    let _ = IDENTITY_MAX_LEN;
}

#[test]
fn blob_matches_golden() {
    let obj = Object::Blob(Blob {
        data: b"hello mkit\n".to_vec(),
    });
    assert_object_matches("blob", &obj);
}

#[test]
fn tree_matches_golden() {
    let blob_child = [0x55u8; 32];
    let tree_child = [0x33u8; 32];
    let exec_child = [0x66u8; 32];
    let obj = Object::Tree(Tree {
        entries: vec![
            TreeEntry {
                name: b"README.md".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob_child,
            },
            TreeEntry {
                name: b"scripts".to_vec(),
                mode: EntryMode::Executable,
                object_hash: exec_child,
            },
            TreeEntry {
                name: b"src".to_vec(),
                mode: EntryMode::Tree,
                object_hash: tree_child,
            },
        ],
    });
    assert_object_matches("tree", &obj);
}

fn make_commit(parents: Vec<[u8; 32]>, msg: &[u8], ts_offset: u64) -> Object {
    let tree_hash = [0x77u8; 32];
    Object::Commit(Commit::new_unannotated(
        tree_hash,
        parents,
        Identity::ed25519(PUBKEY_A),
        SIGNER,
        msg.to_vec(),
        TS + ts_offset,
        SIGNATURE,
    ))
}

#[test]
fn commit_root_matches_golden() {
    assert_object_matches("commit_0parent", &make_commit(vec![], b"genesis", 0));
}

#[test]
fn commit_one_parent_matches_golden() {
    let p0 = [0xA0u8; 32];
    assert_object_matches("commit_1parent", &make_commit(vec![p0], b"second", 1));
}

#[test]
fn commit_two_parents_matches_golden() {
    let p0 = [0xA0u8; 32];
    let p1 = [0xB0u8; 32];
    assert_object_matches("commit_2parent", &make_commit(vec![p0, p1], b"merge", 2));
}

#[test]
fn remix_two_sources_matches_golden() {
    let obj = Object::Remix(Remix {
        tree_hash: [0x77; 32],
        parents: vec![],
        sources: vec![
            RemixSource {
                upstream_id: [0x10; 32],
                commit_hash: [0x30; 32],
            },
            RemixSource {
                upstream_id: [0x20; 32],
                commit_hash: [0x40; 32],
            },
        ],
        author: Identity::ed25519(PUBKEY_B),
        signer: SIGNER,
        message: b"remix two".to_vec(),
        timestamp: TS + 10,
        signature: SIGNATURE,
    });
    assert_object_matches("remix_2sources", &obj);
}

#[test]
fn chunked_blob_matches_golden() {
    let obj = Object::ChunkedBlob(ChunkedBlob {
        total_size: 4 * 65536,
        chunk_size: 65536,
        chunks: vec![[0x01; 32], [0x02; 32], [0x03; 32], [0x04; 32]],
    });
    assert_object_matches("chunked_blob", &obj);
}

// ---- SPEC-OBJECTS §13 mandatory vectors ----

#[test]
fn empty_blob_matches_golden() {
    let obj = Object::Blob(Blob { data: Vec::new() });
    assert_object_matches("empty_blob", &obj);
    // SPEC §13.1: 10-byte file (6-byte prologue + u32 length=0).
    let bytes = serialize(&obj).unwrap();
    assert_eq!(bytes.len(), 10, "empty_blob.bin must be exactly 10 bytes");
}

#[test]
fn empty_tree_matches_golden() {
    let obj = Object::Tree(Tree { entries: vec![] });
    assert_object_matches("empty_tree", &obj);
    // SPEC §13.2: 10-byte file (6-byte prologue + u32 entry_count=0).
    let bytes = serialize(&obj).unwrap();
    assert_eq!(bytes.len(), 10, "empty_tree.bin must be exactly 10 bytes");
}

#[test]
fn tree_single_file_matches_golden() {
    // SPEC §13.3: single-entry tree pointing at the empty blob hash.
    let empty_blob_bytes = serialize(&Object::Blob(Blob { data: Vec::new() })).unwrap();
    let blob_hash = hash(&empty_blob_bytes);
    let obj = Object::Tree(Tree {
        entries: vec![TreeEntry {
            name: b"README.md".to_vec(),
            mode: EntryMode::Blob,
            object_hash: blob_hash,
        }],
    });
    assert_object_matches("tree_single_file", &obj);
}

#[test]
fn chunked_blob_cs0_3chunks_matches_golden() {
    // SPEC §13.7: chunk_size=0 (CDC marker) + 3 chunks => exactly 118 bytes.
    let obj = Object::ChunkedBlob(ChunkedBlob {
        total_size: 1_000_000,
        chunk_size: 0,
        chunks: vec![[0xA1; 32], [0xA2; 32], [0xA3; 32]],
    });
    assert_object_matches("chunked_blob_cs0_3chunks", &obj);
    let bytes = serialize(&obj).unwrap();
    // 6 (prologue) + 8 (total_size u64) + 4 (chunk_size u32) + 4 (count u32) + 32*3 = 118
    assert_eq!(
        bytes.len(),
        118,
        "chunked_blob_cs0_3chunks must be exactly 118 bytes per SPEC §13.7"
    );
}

#[test]
fn remix_identical_upstream_distinct_commit_matches_golden() {
    // SPEC §13.6: two sources with identical upstream_id, distinct
    // commit_hash. Exercises the secondary sort key on commit_hash.
    let obj = Object::Remix(Remix {
        tree_hash: [0x77; 32],
        parents: vec![],
        sources: vec![
            RemixSource {
                upstream_id: [0x10; 32],
                commit_hash: [0x30; 32],
            },
            RemixSource {
                upstream_id: [0x10; 32],
                commit_hash: [0x31; 32],
            },
        ],
        author: Identity::ed25519([0xBB; 32]),
        signer: [0x11; 32],
        message: b"remix same upstream".to_vec(),
        timestamp: TS + 11,
        signature: [0x22; 64],
    });
    assert!(
        matches!(&obj, Object::Remix(r) if r.sources_sorted()),
        "secondary-key sort must hold"
    );
    assert_object_matches("remix_identical_upstream_distinct_commit", &obj);
}
