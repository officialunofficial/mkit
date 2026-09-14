//! Golden vectors for BMT inclusion proofs (`docs/specs/SPEC-MERKLE-OBJECTS.md`
//! §5, issue #1015 "verifier kit" PR 1).
//!
//! Each vector is an encoded [`mkit_core::merkle::Proof`] (`<name>.bin`) plus
//! a `.json` sidecar carrying everything an independent verifier — with no
//! access to this crate's Rust source, per issue #1015's acceptance
//! criteria — needs to check it: the object id to verify against, the
//! proven leaf data, the position/range/positions, the `max_items` decode
//! bound, and the expected accept/reject outcome (with a reason for every
//! reject). `MANIFEST.txt` pins the BLAKE3 digest of every `.bin`.
//!
//! This file is deliberately two independent halves:
//!
//! * [`write_all`] (run via `MKIT_WRITE_GOLDEN=1`) generates the vectors
//!   from deterministic pinned fixtures and (re)writes the `.bin`/`.json`/
//!   `MANIFEST.txt` files. This is the only way the fixtures change; do
//!   not hand-edit them.
//! * `golden_proof_vectors_verify` reads ONLY the committed files back —
//!   it never calls the generator — and replays the same accept/reject
//!   check a language-agnostic verifier built from the spec plus these
//!   vectors would perform. This is what actually runs in CI.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use mkit_core::hash::{Hash, from_hex, hash, to_hex};
use mkit_core::merkle::{self, Proof};
use mkit_core::object::{EntryMode, Object, Tree, TreeEntry};
use serde_json::{Value, json};

fn golden_root() -> PathBuf {
    // CARGO_MANIFEST_DIR points at rust/crates/mkit-core; walk up to rust/.
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop(); // crates/
    d.pop(); // rust/
    d.push("tests");
    d.push("golden");
    d
}

fn proofs_dir() -> PathBuf {
    golden_root().join("proofs")
}

fn objects_dir() -> PathBuf {
    golden_root().join("objects")
}

fn writing() -> bool {
    std::env::var("MKIT_WRITE_GOLDEN").is_ok()
}

fn load_object(name: &str) -> Object {
    let bytes = fs::read(objects_dir().join(format!("{name}.bin")))
        .unwrap_or_else(|e| panic!("cannot read {name}.bin from objects/: {e}"));
    mkit_core::deserialize(&bytes).unwrap_or_else(|e| panic!("cannot deserialize {name}.bin: {e}"))
}

fn entry_mode_from_u8(b: u8) -> EntryMode {
    match b {
        0x01 => EntryMode::Blob,
        0x02 => EntryMode::Tree,
        0x03 => EntryMode::Symlink,
        0x04 => EntryMode::Executable,
        other => panic!("unknown EntryMode byte {other:#x} in golden vector JSON"),
    }
}

fn hex_entry(e: &TreeEntry) -> Value {
    json!({
        "name_hex": hex::encode(&e.name),
        "mode": e.mode as u8,
        "object_hash_hex": to_hex(&e.object_hash),
    })
}

fn entry_from_json(v: &Value) -> TreeEntry {
    TreeEntry {
        name: hex::decode(v["name_hex"].as_str().unwrap()).unwrap(),
        mode: entry_mode_from_u8(u8::try_from(v["mode"].as_u64().unwrap()).unwrap()),
        object_hash: from_hex(v["object_hash_hex"].as_str().unwrap()).unwrap(),
    }
}

// ---------------------------------------------------------------------------
// Deterministic synthetic fixtures (pinned; changing these breaks goldens)
// ---------------------------------------------------------------------------

fn synth_entry(idx: u8) -> TreeEntry {
    TreeEntry {
        name: vec![b'a' + idx],
        mode: EntryMode::Blob,
        object_hash: [idx.wrapping_add(1); 32],
    }
}

fn synth_tree(n: u8) -> Tree {
    Tree {
        entries: (0..n).map(synth_entry).collect(),
    }
}

// ---------------------------------------------------------------------------
// Vector assembly (writer-only)
// ---------------------------------------------------------------------------

struct Vector {
    name: &'static str,
    description: &'static str,
    bin: Vec<u8>,
    json: Value,
}

/// `base` is the common envelope every sidecar carries: `object_id_hex`
/// (the id to verify against — deliberately the bare inner root for the
/// id-confusion negative vector), `max_items`, `expect`, and (for a
/// reject) `reject_reason`. `extra` is merged in on top with the
/// kind/proof_kind/position(s)/leaf-data fields specific to this vector.
#[allow(clippy::too_many_arguments)]
fn vector(
    name: &'static str,
    description: &'static str,
    bin: Vec<u8>,
    object_id: &Hash,
    max_items: usize,
    expect_accept: bool,
    reject_reason: Option<&'static str>,
    mut extra: Value,
) -> Vector {
    let obj = extra.as_object_mut().expect("extra must be a JSON object");
    obj.insert("object_id_hex".into(), json!(to_hex(object_id)));
    obj.insert("max_items".into(), json!(max_items));
    obj.insert(
        "expect".into(),
        json!(if expect_accept { "accept" } else { "reject" }),
    );
    if let Some(r) = reject_reason {
        obj.insert("reject_reason".into(), json!(r));
    }
    Vector {
        name,
        description,
        bin,
        json: extra,
    }
}

#[allow(clippy::too_many_lines)] // one block per golden vector, kept together for auditability
fn build_vectors() -> Vec<Vector> {
    let mut v = Vec::new();

    // ---- tree: single-leaf proofs ----

    let t1 = synth_tree(1);
    let id1 = merkle::compute_tree_id(&t1);
    v.push(vector(
        "tree_1entry_pos0",
        "1-entry tree, single-leaf proof at position 0 (zero siblings).",
        merkle::build_tree_entry_proof(&t1, 0).unwrap().encode(),
        &id1,
        1,
        true,
        None,
        json!({
            "kind": "tree_entry",
            "proof_kind": "single",
            "position": 0,
            "entries": [hex_entry(&t1.entries[0])],
        }),
    ));

    let t3 = synth_tree(3);
    let id3 = merkle::compute_tree_id(&t3);
    for pos in 0u32..3 {
        let name: &'static str = match pos {
            0 => "tree_3entry_pos0",
            1 => "tree_3entry_pos1",
            _ => "tree_3entry_pos2",
        };
        v.push(vector(
            name,
            "3-entry tree, single-leaf proof — exercises the odd trailing node.",
            merkle::build_tree_entry_proof(&t3, pos).unwrap().encode(),
            &id3,
            1,
            true,
            None,
            json!({
                "kind": "tree_entry",
                "proof_kind": "single",
                "position": pos,
                "entries": [hex_entry(&t3.entries[pos as usize])],
            }),
        ));
    }

    let t7 = synth_tree(7);
    let id7 = merkle::compute_tree_id(&t7);
    let tree_7entry_pos6_proof = merkle::build_tree_entry_proof(&t7, 6).unwrap();
    v.push(vector(
        "tree_7entry_pos6",
        "7-entry tree, single-leaf proof at the last (odd trailing) position.",
        tree_7entry_pos6_proof.encode(),
        &id7,
        1,
        true,
        None,
        json!({
            "kind": "tree_entry",
            "proof_kind": "single",
            "position": 6,
            "entries": [hex_entry(&t7.entries[6])],
        }),
    ));

    // ---- tree: range + multi ----

    let t8 = synth_tree(8);
    let id8 = merkle::compute_tree_id(&t8);
    v.push(vector(
        "tree_8entry_range2to4",
        "8-entry tree, range proof over positions 2..=4.",
        merkle::build_tree_entries_range_proof(&t8, 2, 4)
            .unwrap()
            .encode(),
        &id8,
        3,
        true,
        None,
        json!({
            "kind": "tree_entry",
            "proof_kind": "range",
            "start": 2,
            "entries": t8.entries[2..=4].iter().map(hex_entry).collect::<Vec<_>>(),
        }),
    ));

    let t9 = synth_tree(9);
    let id9 = merkle::compute_tree_id(&t9);
    let multi_entries: Vec<Value> = [0usize, 4, 8]
        .iter()
        .map(|&p| hex_entry(&t9.entries[p]))
        .collect();
    v.push(vector(
        "tree_9entry_multi_0_4_8",
        "9-entry tree, multi-leaf proof over positions {0, 4, 8}.",
        merkle::build_tree_entries_multi_proof(&t9, [0, 4, 8])
            .unwrap()
            .encode(),
        &id9,
        3,
        true,
        None,
        json!({
            "kind": "tree_entry",
            "proof_kind": "multi",
            "positions": [0, 4, 8],
            "entries": multi_entries,
        }),
    ));

    // ---- tree: the real `tree_single_file` object from objects/ ----

    let Object::Tree(tree_single_file) = load_object("tree_single_file") else {
        panic!("objects/tree_single_file.bin is not a Tree")
    };
    let id_tsf = merkle::compute_tree_id(&tree_single_file);
    v.push(vector(
        "tree_single_file_pos0",
        "The `tree_single_file` object from ../objects/, single-leaf proof at position 0.",
        merkle::build_tree_entry_proof(&tree_single_file, 0)
            .unwrap()
            .encode(),
        &id_tsf,
        1,
        true,
        None,
        json!({
            "kind": "tree_entry",
            "proof_kind": "single",
            "position": 0,
            "entries": [hex_entry(&tree_single_file.entries[0])],
        }),
    ));

    // ---- chunked blob: the real `chunked_blob_cs0_3chunks` object ----

    let Object::ChunkedBlob(cb) = load_object("chunked_blob_cs0_3chunks") else {
        panic!("objects/chunked_blob_cs0_3chunks.bin is not a ChunkedBlob")
    };
    let id_cb = merkle::compute_chunked_id(&cb);

    for pos in 1u32..=3 {
        let name: &'static str = match pos {
            1 => "chunked_blob_cs0_3chunks_pos1",
            2 => "chunked_blob_cs0_3chunks_pos2",
            _ => "chunked_blob_cs0_3chunks_pos3",
        };
        v.push(vector(
            name,
            "`chunked_blob_cs0_3chunks` from ../objects/, single chunk proof.",
            merkle::build_chunk_proof(&cb, pos).unwrap().encode(),
            &id_cb,
            1,
            true,
            None,
            json!({
                "kind": "chunk",
                "proof_kind": "single",
                "position": pos,
                "total_size": cb.total_size,
                "chunk_size": cb.chunk_size,
                "chunk_hashes_hex": [to_hex(&cb.chunks[(pos - 1) as usize])],
            }),
        ));
    }

    v.push(vector(
        "chunked_blob_cs0_3chunks_range1to3",
        "`chunked_blob_cs0_3chunks` from ../objects/, range proof over all 3 chunks.",
        merkle::build_chunks_range_proof(&cb, 1, 3)
            .unwrap()
            .encode(),
        &id_cb,
        3,
        true,
        None,
        json!({
            "kind": "chunk",
            "proof_kind": "range",
            "start": 1,
            "total_size": cb.total_size,
            "chunk_size": cb.chunk_size,
            "chunk_hashes_hex": cb.chunks.iter().map(to_hex).collect::<Vec<_>>(),
        }),
    ));

    // NEGATIVE: position 0 is a *valid* raw BMT proof of the metadata leaf,
    // but `verify_chunk` MUST reject it — position 0 is never a chunk.
    v.push(vector(
        "chunked_blob_cs0_3chunks_metapos0_reject",
        "Position 0 (the metadata leaf) is a structurally valid BMT proof, but \
         MUST be rejected by chunk verification: position 0 is never a chunk.",
        merkle::build_chunk_proof(&cb, 0).unwrap().encode(),
        &id_cb,
        1,
        false,
        Some("position 0 is the ChunkedBlob metadata leaf, not a chunk"),
        json!({
            "kind": "chunk",
            "proof_kind": "single",
            "position": 0,
            "total_size": cb.total_size,
            "chunk_size": cb.chunk_size,
            // No chunk hash is recorded: the metadata leaf's pre-image isn't
            // reachable from outside merkle.rs, and isn't needed — a verifier
            // rejects on position alone, before ever hashing a leaf.
            "chunk_hashes_hex": [],
        }),
    ));

    // ---- negatives, derived from the tree_7entry_pos6 vector above ----
    // (it has 3 siblings, enough to demonstrate a swap).

    let base_proof = tree_7entry_pos6_proof.clone();
    let inner_root7 = merkle::tree_inner_root(&t7);

    v.push(vector(
        "neg_wrong_position",
        "A valid tree_7entry proof for position 6, verified against position 5.",
        base_proof.encode(),
        &id7,
        1,
        false,
        Some("proof was built for position 6, not the position it is checked against"),
        json!({
            "kind": "tree_entry",
            "proof_kind": "single",
            "position": 5,
            "entries": [hex_entry(&t7.entries[6])],
        }),
    ));

    let mut swapped = base_proof.clone();
    assert!(
        swapped.siblings.len() >= 2,
        "need >=2 siblings to demonstrate a swap"
    );
    swapped.siblings.swap(0, 1);
    v.push(vector(
        "neg_swapped_siblings",
        "A valid tree_7entry proof with its first two sibling digests swapped.",
        swapped.encode(),
        &id7,
        1,
        false,
        Some("sibling order was tampered with (siblings 0 and 1 swapped)"),
        json!({
            "kind": "tree_entry",
            "proof_kind": "single",
            "position": 6,
            "entries": [hex_entry(&t7.entries[6])],
        }),
    ));

    let full = base_proof.encode();
    let truncated = full[..full.len() - mkit_core::hash::HASH_LEN].to_vec();
    v.push(vector(
        "neg_truncated",
        "A valid tree_7entry proof with its last sibling digest chopped off. \
         Must fail to decode, not merely fail to verify.",
        truncated,
        &id7,
        1,
        false,
        Some("proof bytes are truncated (decode must fail)"),
        json!({
            "kind": "tree_entry",
            "proof_kind": "single",
            "position": 6,
            "entries": [hex_entry(&t7.entries[6])],
        }),
    ));

    let mut wrong_leaf_count = base_proof.clone();
    wrong_leaf_count.leaf_count = wrong_leaf_count.leaf_count.wrapping_add(1);
    v.push(vector(
        "neg_leaf_count_off_by_one",
        "A valid tree_7entry proof with leaf_count incremented by one.",
        wrong_leaf_count.encode(),
        &id7,
        1,
        false,
        Some("leaf_count was tampered with (off by one)"),
        json!({
            "kind": "tree_entry",
            "proof_kind": "single",
            "position": 6,
            "entries": [hex_entry(&t7.entries[6])],
        }),
    ));

    // The classic footgun the id-based API closes: the SAME valid proof,
    // checked against the bare inner root instead of the wrapped object id.
    v.push(vector(
        "neg_id_vs_inner_root",
        "A valid tree_7entry proof, but `object_id_hex` here is deliberately \
         the bare (pre-wrap) inner root rather than the real object id — the \
         mistake SPEC-MERKLE-OBJECTS §5 and issue #1015 §Security call out. \
         A verifier MUST apply the type-domain wrap before comparing.",
        base_proof.encode(),
        &inner_root7, // deliberately wrong: not wrap_id(Tree, inner_root7)
        1,
        false,
        Some("verified against the bare inner root instead of the wrapped object id"),
        json!({
            "kind": "tree_entry",
            "proof_kind": "single",
            "position": 6,
            "entries": [hex_entry(&t7.entries[6])],
        }),
    ));

    let mut trailing = base_proof.encode();
    trailing.push(0x00);
    v.push(vector(
        "neg_trailing_byte",
        "A valid tree_7entry proof with one extra trailing byte appended. \
         Must fail to decode (trailing bytes are rejected).",
        trailing,
        &id7,
        1,
        false,
        Some("trailing byte after the encoded proof (decode must fail)"),
        json!({
            "kind": "tree_entry",
            "proof_kind": "single",
            "position": 6,
            "entries": [hex_entry(&t7.entries[6])],
        }),
    ));

    v
}

/// Regenerate `rust/tests/golden/proofs/` from `build_vectors()`. Only
/// runs under `MKIT_WRITE_GOLDEN=1`; otherwise a no-op.
fn write_all() {
    let dir = proofs_dir();
    fs::create_dir_all(&dir).expect("create proofs/ dir");
    let mut manifest = String::from(
        "# BMT inclusion-proof golden vectors (deterministic)\n\
         # Produced by `MKIT_WRITE_GOLDEN=1 cargo test -p mkit-core --test golden_proofs`\n\
         # Format: <name> <blake3-hex-of-bin-bytes>\n\
         # See docs/specs/SPEC-MERKLE-OBJECTS.md §5.\n",
    );
    for v in build_vectors() {
        let digest = to_hex(&hash(&v.bin));
        fs::write(dir.join(format!("{}.bin", v.name)), &v.bin).expect("write .bin");
        let mut sidecar = json!({
            "name": v.name,
            "description": v.description,
            "bin": format!("{}.bin", v.name),
            "size": v.bin.len(),
            "blake3": digest,
        });
        // Merge in the vector-specific fields (kind/proof_kind/position(s)/
        // entries/expect/...) alongside the standard envelope above.
        let merged = sidecar.as_object_mut().unwrap();
        for (k, val) in v.json.as_object().unwrap() {
            merged.insert(k.clone(), val.clone());
        }
        fs::write(
            dir.join(format!("{}.json", v.name)),
            serde_json::to_string_pretty(&sidecar).unwrap() + "\n",
        )
        .expect("write .json");
        let _ = writeln!(manifest, "{} {}", v.name, digest);
    }
    fs::write(dir.join("MANIFEST.txt"), manifest).expect("write MANIFEST.txt");
}

#[test]
fn write_golden_proof_vectors_if_requested() {
    if writing() {
        write_all();
    }
}

// ---------------------------------------------------------------------------
// Consumer: reads ONLY the committed files, never the generator above.
// ---------------------------------------------------------------------------

fn manifest_names_and_digests() -> Vec<(String, String)> {
    let raw = fs::read_to_string(proofs_dir().join("MANIFEST.txt"))
        .expect("read rust/tests/golden/proofs/MANIFEST.txt");
    raw.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let mut parts = l.split_whitespace();
            let name = parts.next().expect("name").to_string();
            let digest = parts.next().expect("digest").to_string();
            (name, digest)
        })
        .collect()
}

#[allow(clippy::too_many_lines)] // one match arm per (kind, proof_kind) pair
fn verify_vector(name: &str, want_digest: &str) {
    let dir = proofs_dir();
    let bin = fs::read(dir.join(format!("{name}.bin")))
        .unwrap_or_else(|e| panic!("cannot read {name}.bin: {e}"));
    let got_digest = to_hex(&hash(&bin));
    assert_eq!(
        got_digest, want_digest,
        "{name}.bin: BLAKE3 digest does not match MANIFEST.txt"
    );

    let sidecar: Value = serde_json::from_str(
        &fs::read_to_string(dir.join(format!("{name}.json")))
            .unwrap_or_else(|e| panic!("cannot read {name}.json: {e}")),
    )
    .unwrap_or_else(|e| panic!("{name}.json is not valid JSON: {e}"));
    assert_eq!(sidecar["blake3"].as_str().unwrap(), want_digest);
    assert_eq!(
        usize::try_from(sidecar["size"].as_u64().unwrap()).unwrap(),
        bin.len()
    );

    let max_items = usize::try_from(sidecar["max_items"].as_u64().unwrap()).unwrap();
    let expect_accept = match sidecar["expect"].as_str().unwrap() {
        "accept" => true,
        "reject" => false,
        other => panic!("{name}.json: unknown expect value {other:?}"),
    };

    let proof = match Proof::decode(&bin, max_items) {
        Ok(p) => p,
        Err(e) => {
            assert!(
                !expect_accept,
                "{name}: decode failed ({e:?}) but the vector expects accept"
            );
            // A reject-on-decode vector is fully checked: it never reaches
            // a verify_* call.
            return;
        }
    };

    let object_id: Hash = from_hex(sidecar["object_id_hex"].as_str().unwrap()).unwrap();
    let kind = sidecar["kind"].as_str().unwrap();
    let proof_kind = sidecar["proof_kind"].as_str().unwrap();

    let result: Result<(), merkle::MerkleError> = match (kind, proof_kind) {
        ("tree_entry", "single") => {
            let position = u32::try_from(sidecar["position"].as_u64().unwrap()).unwrap();
            let entry = entry_from_json(&sidecar["entries"][0]);
            merkle::verify_tree_entry(&object_id, &entry, position, &proof)
        }
        ("tree_entry", "range") => {
            let start = u32::try_from(sidecar["start"].as_u64().unwrap()).unwrap();
            let entries: Vec<TreeEntry> = sidecar["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(entry_from_json)
                .collect();
            merkle::verify_tree_entries_range(&object_id, start, &entries, &proof)
        }
        ("tree_entry", "multi") => {
            let positions: Vec<u32> = sidecar["positions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| u32::try_from(p.as_u64().unwrap()).unwrap())
                .collect();
            let entries: Vec<TreeEntry> = sidecar["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(entry_from_json)
                .collect();
            let pairs: Vec<(TreeEntry, u32)> =
                entries.into_iter().zip(positions.iter().copied()).collect();
            merkle::verify_tree_entries_multi(&object_id, &pairs, &proof)
        }
        ("chunk", "single") => {
            let position = u32::try_from(sidecar["position"].as_u64().unwrap()).unwrap();
            let hashes = sidecar["chunk_hashes_hex"].as_array().unwrap();
            if hashes.is_empty() {
                // The meta-leaf negative vector carries no chunk hash — any
                // hash is fine, `verify_chunk` must reject on position alone.
                merkle::verify_chunk(&object_id, &[0u8; 32], position, &proof)
            } else {
                let chunk_hash: Hash = from_hex(hashes[0].as_str().unwrap()).unwrap();
                merkle::verify_chunk(&object_id, &chunk_hash, position, &proof)
            }
        }
        ("chunk", "range") => {
            let start = u32::try_from(sidecar["start"].as_u64().unwrap()).unwrap();
            let chunk_hashes: Vec<Hash> = sidecar["chunk_hashes_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| from_hex(h.as_str().unwrap()).unwrap())
                .collect();
            merkle::verify_chunks_range(&object_id, start, &chunk_hashes, &proof)
        }
        (k, p) => panic!("{name}: unknown (kind, proof_kind) = ({k}, {p})"),
    };

    if expect_accept {
        result.unwrap_or_else(|e| panic!("{name}: expected accept, got {e:?}"));
    } else {
        assert!(
            result.is_err(),
            "{name}: expected reject ({}), but verification accepted it",
            sidecar
                .get("reject_reason")
                .and_then(Value::as_str)
                .unwrap_or("<no reason recorded>")
        );
    }
}

#[test]
fn golden_proof_vectors_verify() {
    if writing() {
        // `write_golden_proof_vectors_if_requested` owns this run; racing
        // the two in the same process (tests run in parallel by default)
        // would read a partially-written MANIFEST.txt.
        return;
    }
    let vectors = manifest_names_and_digests();
    assert!(
        !vectors.is_empty(),
        "MANIFEST.txt listed no vectors — did you forget to run \
         `MKIT_WRITE_GOLDEN=1 cargo test -p mkit-core --test golden_proofs`?"
    );
    for (name, digest) in vectors {
        verify_vector(&name, &digest);
    }
}
