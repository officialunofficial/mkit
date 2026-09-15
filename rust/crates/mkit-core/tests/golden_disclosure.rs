//! Golden vectors for the SPEC-DISCLOSURE.md partial-disclosure bundle
//! (issue #1015 "verifier kit" PR 2).
//!
//! Like `golden_proofs.rs`, this file is deliberately two independent
//! halves:
//!
//! * [`write_all`] (run via `MKIT_WRITE_GOLDEN=1`) builds a deterministic
//!   fixture repo, assembles every vector, and (re)writes the `.bin`/
//!   `.json`/`MANIFEST.txt` files under `rust/tests/golden/disclosure/`.
//! * `golden_disclosure_vectors_verify` reads ONLY the committed files —
//!   never the generator — and replays the accept/reject check an
//!   independent verifier built from SPEC-DISCLOSURE.md plus these
//!   vectors would perform. This is what runs in CI.
//!
//! Every reject vector's bytes are assembled by [`wire`], a from-scratch
//! encoder over `commonware-codec` public primitives — not by tampering
//! with `mkit_core::verify`'s private wire types (there are none reachable
//! from an external test crate; see that module's docs on why `Step` is
//! public but the payload's wire shape is not). This mirrors exactly what
//! an independent, non-Rust verifier's own vector generator would need to
//! do, per issue #1015's acceptance criteria.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use commonware_codec::Write as CodecWrite;
use mkit_core::hash::{Hash, hash, to_hex};
use mkit_core::merkle;
use mkit_core::object::{EntryMode, Identity, Object};
use mkit_core::store::ObjectStore;
use mkit_core::verify::{self, Disclosed, DisclosedPayload, Selector, Step, VerifyError};
use serde_json::{Value, json};

mod common;

fn golden_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop(); // crates/
    d.pop(); // rust/
    d.push("tests");
    d.push("golden");
    d
}

fn disclosure_dir() -> PathBuf {
    golden_root().join("disclosure")
}

fn writing() -> bool {
    std::env::var("MKIT_WRITE_GOLDEN").is_ok()
}

// ---------------------------------------------------------------------------
// From-scratch wire encoder (commonware-codec public primitives only).
// ---------------------------------------------------------------------------

mod wire {
    use super::CodecWrite;
    use mkit_core::hash::Hash;
    use mkit_core::merkle::Proof;
    use mkit_core::verify::Step;

    pub(crate) fn bundle(
        commit_id: &Hash,
        commit_bytes: &[u8],
        steps: &[Step],
        payload: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"MKDP");
        out.push(1u8);
        commit_id.write(&mut out);
        commit_bytes.write(&mut out);
        steps.write(&mut out);
        out.extend_from_slice(payload);
        out
    }

    pub(crate) fn object_payload(bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8];
        bytes.write(&mut out);
        out
    }

    pub(crate) fn chunk_payload(
        total_size: u64,
        chunk_size: u32,
        index: u32,
        proof: &Proof,
        bytes: &[u8],
    ) -> Vec<u8> {
        let mut out = vec![1u8];
        total_size.write(&mut out);
        chunk_size.write(&mut out);
        index.write(&mut out);
        proof.write(&mut out);
        bytes.write(&mut out);
        out
    }

    /// Range payload's `ChunkHdr` sub-message fields (SPEC-DISCLOSURE §3).
    pub(crate) struct ChunkHdr {
        pub(crate) total_size: u64,
        pub(crate) chunk_size: u32,
        pub(crate) index: u32,
        pub(crate) chunk_id: Hash,
        pub(crate) proof: Proof,
    }

    /// Range payload's `LenProof` sub-message fields (SPEC-DISCLOSURE §3).
    pub(crate) struct LenProof {
        pub(crate) index: u32,
        pub(crate) chunk_id: Hash,
        pub(crate) proof: Proof,
        pub(crate) slice: Vec<u8>,
    }

    pub(crate) fn range_payload(
        chunk: Option<&ChunkHdr>,
        offset_in_blob: u64,
        len: u64,
        slice: &[u8],
        chunk_len_proofs: &[LenProof],
    ) -> Vec<u8> {
        let mut out = vec![2u8];
        match chunk {
            None => false.write(&mut out),
            Some(c) => {
                true.write(&mut out);
                c.total_size.write(&mut out);
                c.chunk_size.write(&mut out);
                c.index.write(&mut out);
                c.chunk_id.write(&mut out);
                c.proof.write(&mut out);
            }
        }
        offset_in_blob.write(&mut out);
        len.write(&mut out);
        slice.write(&mut out);
        chunk_len_proofs.len().write(&mut out);
        for lp in chunk_len_proofs {
            lp.index.write(&mut out);
            lp.chunk_id.write(&mut out);
            lp.proof.write(&mut out);
            lp.slice.write(&mut out);
        }
        out
    }
}

use common::build_fixture;

/// Walk `path` from the fixture's root tree, independently of
/// `verify::build_disclosure`, returning the authenticated `Step`s and
/// the leaf id. Used by every vector builder below so reject vectors can
/// mutate one ingredient (a step, a payload field) while every other
/// piece is genuinely valid.
fn walk_path(store: &ObjectStore, tree_hash: Hash, path: &[&[u8]]) -> (Vec<Step>, Hash) {
    let mut steps = Vec::with_capacity(path.len());
    let mut current = tree_hash;
    let mut leaf = tree_hash;
    for &name in path {
        let Object::Tree(tree) = store.read_object(&current).unwrap() else {
            panic!("path component is not under a Tree");
        };
        let position = merkle::tree_entry_position(&tree, name).expect("entry present");
        let entry = tree.entries[position as usize].clone();
        let proof = merkle::build_tree_entry_proof(&tree, position).unwrap();
        steps.push(Step {
            name: name.to_vec(),
            mode: entry.mode,
            child_id: entry.object_hash,
            position,
            proof,
        });
        leaf = entry.object_hash;
        if entry.mode == EntryMode::Tree {
            current = entry.object_hash;
        }
    }
    (steps, leaf)
}

fn bao_slice(canonical: &[u8], bao_offset: u64, len: u64) -> Vec<u8> {
    let (outboard, _root) = bao::encode::outboard(canonical);
    let mut extractor = bao::encode::SliceExtractor::new_outboard(
        std::io::Cursor::new(canonical),
        std::io::Cursor::new(outboard),
        bao_offset,
        len,
    );
    let mut out = Vec::new();
    std::io::Read::read_to_end(&mut extractor, &mut out).unwrap();
    out
}

fn canonical_bytes(store: &ObjectStore, id: &Hash) -> Vec<u8> {
    store.read(id).unwrap()
}

// ---------------------------------------------------------------------------
// Vector assembly
// ---------------------------------------------------------------------------

struct Vector {
    name: &'static str,
    description: &'static str,
    bin: Vec<u8>,
    json: Value,
}

fn hex_path(path: &[&[u8]]) -> Vec<String> {
    path.iter().map(hex::encode).collect()
}

fn base_json(
    commit_id: &Hash,
    path: &[&[u8]],
    selector_desc: &str,
    expect_accept: bool,
    reject_reason: Option<&'static str>,
) -> Value {
    let mut v = json!({
        "commit_id_hex": to_hex(commit_id),
        "path_hex": hex_path(path),
        "selector": selector_desc,
        "expect": if expect_accept { "accept" } else { "reject" },
    });
    if let Some(r) = reject_reason {
        v.as_object_mut()
            .unwrap()
            .insert("reject_reason".into(), json!(r));
    }
    v
}

fn disclosed_summary(d: &Disclosed) -> Value {
    let path: Vec<Value> = d
        .path
        .iter()
        .map(|(name, mode)| json!({"name_hex": hex::encode(name), "mode": *mode as u8}))
        .collect();
    let payload = match &d.payload {
        DisclosedPayload::Object { bytes } => json!({
            "kind": "object",
            "bytes_blake3": to_hex(&hash(bytes)),
            "len": bytes.len(),
        }),
        DisclosedPayload::Chunk {
            total_size,
            chunk_size,
            index,
            bytes,
        } => json!({
            "kind": "chunk",
            "total_size": total_size,
            "chunk_size": chunk_size,
            "index": index,
            "bytes_blake3": to_hex(&hash(bytes)),
            "len": bytes.len(),
        }),
        DisclosedPayload::Range {
            blob_id,
            chunk,
            offset_in_blob,
            absolute_offset,
            bytes,
        } => json!({
            "kind": "range",
            "blob_id_hex": to_hex(blob_id),
            "chunk": chunk.map(|(idx, ts, cs)| json!({"index": idx, "total_size": ts, "chunk_size": cs})),
            "offset_in_blob": offset_in_blob,
            "absolute_offset": absolute_offset,
            "bytes_blake3": to_hex(&hash(bytes)),
            "len": bytes.len(),
        }),
    };
    json!({
        "tree_hash_hex": to_hex(&d.tree_hash),
        "leaf_id_hex": to_hex(&d.leaf_id),
        "path": path,
        "payload": payload,
        "signer_hex": to_hex(&d.signer),
        "signature_valid": d.signature_valid,
    })
}

#[allow(clippy::too_many_lines)] // one block per golden vector, kept together for auditability
fn build_vectors() -> Vec<Vector> {
    let f = build_fixture();
    let mut v = Vec::new();

    // ---- accept: Object over increasingly deep paths ----

    for (name, description, path) in [
        (
            "root_tree",
            "The commit's root tree, disclosed directly (empty path).",
            Vec::<&[u8]>::new(),
        ),
        (
            "shallow_file",
            "A file directly under the root.",
            vec![b"shallow.txt".as_slice()],
        ),
        (
            "nested_file_3levels",
            "A file 3 directory levels deep.",
            vec![
                b"sub".as_slice(),
                b"deep".as_slice(),
                b"deep.txt".as_slice(),
            ],
        ),
        (
            "executable_file",
            "A file with the Executable entry mode.",
            vec![b"exec.sh".as_slice()],
        ),
    ] {
        let bundle =
            verify::build_disclosure(&f.store, &f.commit_id, &path, Selector::Object).unwrap();
        let d = verify::verify_disclosure(&f.commit_id, &bundle).unwrap();
        let mut j = base_json(&f.commit_id, &path, "object", true, None);
        j.as_object_mut()
            .unwrap()
            .insert("disclosed".into(), disclosed_summary(&d));
        v.push(Vector {
            name,
            description,
            bin: bundle,
            json: j,
        });
    }

    // ---- accept: one chunk of the chunked file ----

    let chunked_path = [b"chunked.bin".as_slice()];
    let bundle =
        verify::build_disclosure(&f.store, &f.commit_id, &chunked_path, Selector::Chunk(1))
            .unwrap();
    let d = verify::verify_disclosure(&f.commit_id, &bundle).unwrap();
    let mut j = base_json(&f.commit_id, &chunked_path, "chunk(1)", true, None);
    j.as_object_mut()
        .unwrap()
        .insert("disclosed".into(), disclosed_summary(&d));
    v.push(Vector {
        name: "chunked_file_chunk1",
        description: "Chunk index 1 of the 3 MiB chunked file.",
        bin: bundle,
        json: j,
    });

    // ---- accept: a range inside a chunk, without/with offsets ----

    // Locate an offset guaranteed to fall inside a chunk other than
    // chunk 0 (so the with-offsets vector has a non-trivial length-proof
    // set to verify).
    let range_offset: u64 = {
        let Object::ChunkedBlob(cb) = f
            .store
            .read_object(&{
                let Object::Tree(root) = f.store.read_object(&f.tree_hash).unwrap() else {
                    panic!("root is a Tree");
                };
                root.entries
                    .iter()
                    .find(|e| e.name == b"chunked.bin")
                    .unwrap()
                    .object_hash
            })
            .unwrap()
        else {
            panic!("chunked.bin is a ChunkedBlob");
        };
        let first_chunk_len = f.store.read(&cb.chunks[0]).unwrap().len() as u64 - 10;
        first_chunk_len + 32 // safely inside chunk 1 (index > 0)
    };

    for (name, description, with_offsets) in [
        (
            "chunked_range_no_offsets",
            "A 64-byte range inside a non-first chunk, no absolute-offset proof.",
            false,
        ),
        (
            "chunked_range_with_offsets",
            "The same range, with a complete chunk_len_proofs set proving the absolute file offset.",
            true,
        ),
    ] {
        let bundle = verify::build_disclosure(
            &f.store,
            &f.commit_id,
            &chunked_path,
            Selector::Range {
                offset: range_offset,
                len: 64,
                with_offsets,
            },
        )
        .unwrap();
        let d = verify::verify_disclosure(&f.commit_id, &bundle).unwrap();
        let mut j = base_json(
            &f.commit_id,
            &chunked_path,
            &format!("range(offset={range_offset},len=64,with_offsets={with_offsets})"),
            true,
            None,
        );
        j.as_object_mut()
            .unwrap()
            .insert("disclosed".into(), disclosed_summary(&d));
        v.push(Vector {
            name,
            description,
            bin: bundle,
            json: j,
        });
    }

    // ---- accept: ranges over a small (multi-Bao-block) blob ----

    let range_path = [b"range.bin".as_slice()];
    for (name, description, offset, len) in [
        (
            "small_blob_range_first_block",
            "The first 1 KiB Bao block of a 1536-byte blob.",
            0u64,
            1024u64,
        ),
        (
            "small_blob_range_last_partial_block",
            "The final, partial (< 1 KiB) Bao block of the same blob.",
            1024u64,
            (f.range_blob.len() as u64) - 1024,
        ),
        (
            "small_blob_range_whole",
            "The entire small blob, as one range.",
            0u64,
            f.range_blob.len() as u64,
        ),
    ] {
        let bundle = verify::build_disclosure(
            &f.store,
            &f.commit_id,
            &range_path,
            Selector::Range {
                offset,
                len,
                with_offsets: false,
            },
        )
        .unwrap();
        let d = verify::verify_disclosure(&f.commit_id, &bundle).unwrap();
        let mut j = base_json(
            &f.commit_id,
            &range_path,
            &format!("range(offset={offset},len={len})"),
            true,
            None,
        );
        j.as_object_mut()
            .unwrap()
            .insert("disclosed".into(), disclosed_summary(&d));
        v.push(Vector {
            name,
            description,
            bin: bundle,
            json: j,
        });
    }

    // ---- reject vectors ----

    // 1. Non-tree intermediate mode: the middle step of the 3-level path,
    //    with its mode overwritten to Blob (a structurally valid step,
    //    but not the final one).
    {
        let (mut steps, leaf) = walk_path(&f.store, f.tree_hash, &[b"sub", b"deep", b"deep.txt"]);
        steps[1].mode = EntryMode::Blob;
        let bytes = canonical_bytes(&f.store, &leaf);
        let commit_bytes = canonical_bytes(&f.store, &f.commit_id);
        let bin = wire::bundle(
            &f.commit_id,
            &commit_bytes,
            &steps,
            &wire::object_payload(&bytes),
        );
        v.push(Vector {
            name: "neg_non_tree_intermediate_mode",
            description: "The 2nd of 3 steps has mode Blob though it is not the final step.",
            bin,
            json: base_json(
                &f.commit_id,
                &[b"sub", b"deep", b"deep.txt"],
                "object",
                false,
                Some("non-final step's mode is not Tree"),
            ),
        });
    }

    // 2. Step proof checked against the wrong parent: swap the first two
    //    of the 3-level path's steps.
    {
        let (mut steps, leaf) = walk_path(&f.store, f.tree_hash, &[b"sub", b"deep", b"deep.txt"]);
        steps.swap(0, 1);
        let bytes = canonical_bytes(&f.store, &leaf);
        let commit_bytes = canonical_bytes(&f.store, &f.commit_id);
        let bin = wire::bundle(
            &f.commit_id,
            &commit_bytes,
            &steps,
            &wire::object_payload(&bytes),
        );
        v.push(Vector {
            name: "neg_swapped_steps",
            description: "The first two of three path steps are swapped.",
            bin,
            json: base_json(
                &f.commit_id,
                &[b"sub", b"deep", b"deep.txt"],
                "object",
                false,
                Some("a step's proof does not verify against the (now wrong) parent id"),
            ),
        });
    }

    // 3. Invalid entry name (trailing space).
    {
        let (mut steps, leaf) = walk_path(&f.store, f.tree_hash, &[b"shallow.txt"]);
        steps[0].name = b"shallow.txt ".to_vec();
        let bytes = canonical_bytes(&f.store, &leaf);
        let commit_bytes = canonical_bytes(&f.store, &f.commit_id);
        let bin = wire::bundle(
            &f.commit_id,
            &commit_bytes,
            &steps,
            &wire::object_payload(&bytes),
        );
        v.push(Vector {
            name: "neg_invalid_entry_name",
            description: "The step's entry name has a trailing space (SPEC-OBJECTS §4.1).",
            bin,
            json: base_json(
                &f.commit_id,
                &[b"shallow.txt"],
                "object",
                false,
                Some("entry name fails SPEC-OBJECTS §4.1 validation"),
            ),
        });
    }

    // 4. Payload id != leaf id: flip the last byte of the disclosed
    //    Object payload.
    {
        let (steps, leaf) = walk_path(&f.store, f.tree_hash, &[b"shallow.txt"]);
        let mut bytes = canonical_bytes(&f.store, &leaf);
        *bytes.last_mut().unwrap() ^= 0xFF;
        let commit_bytes = canonical_bytes(&f.store, &f.commit_id);
        let bin = wire::bundle(
            &f.commit_id,
            &commit_bytes,
            &steps,
            &wire::object_payload(&bytes),
        );
        v.push(Vector {
            name: "neg_payload_id_mismatch",
            description: "The Object payload's last byte is flipped; its id no longer matches the leaf id.",
            bin,
            json: base_json(
                &f.commit_id,
                &[b"shallow.txt"],
                "object",
                false,
                Some("payload id does not equal the authenticated leaf id"),
            ),
        });
    }

    // 5. Chunk meta with forged total_size.
    {
        let (steps, leaf) = walk_path(&f.store, f.tree_hash, &["chunked.bin".as_bytes()]);
        let Object::ChunkedBlob(cb) = f.store.read_object(&leaf).unwrap() else {
            panic!("expected ChunkedBlob");
        };
        let position = merkle::chunk_position(&cb, &cb.chunks[1]).unwrap();
        let proof = merkle::build_chunks_multi_proof(&cb, [0, position]).unwrap();
        let chunk_bytes = canonical_bytes(&f.store, &cb.chunks[1]);
        let commit_bytes = canonical_bytes(&f.store, &f.commit_id);
        let bin = wire::bundle(
            &f.commit_id,
            &commit_bytes,
            &steps,
            &wire::chunk_payload(cb.total_size + 1, cb.chunk_size, 1, &proof, &chunk_bytes),
        );
        v.push(Vector {
            name: "neg_chunk_meta_forged_total_size",
            description: "The Chunk payload's total_size is off by one from the real ChunkedBlob's.",
            bin,
            json: base_json(
                &f.commit_id,
                &chunked_path,
                "chunk(1) [forged total_size]",
                false,
                Some("forged total_size no longer folds to the ChunkedBlob id"),
            ),
        });
    }

    // 6. Slice at the wrong offset: request the range payload's Bao
    //    slice for one offset but claim a different `offset_in_blob` in a
    //    *different* 1 KiB Bao chunk (a claimed offset inside the same
    //    already-authenticated chunk would trivially still verify — Bao's
    //    cryptographic granularity is the whole 1 KiB chunk, not the
    //    sub-range requested within it — so the claim MUST cross a chunk
    //    boundary to actually be a forgery: the slice built for chunk 0
    //    contains none of chunk 1's bytes to satisfy a chunk-1 claim).
    {
        let (steps, leaf) = walk_path(&f.store, f.tree_hash, &["range.bin".as_bytes()]);
        let canonical = canonical_bytes(&f.store, &leaf);
        let slice = bao_slice(&canonical, 10, 32); // real slice: chunk 0, offset 0, len 32
        let commit_bytes = canonical_bytes(&f.store, &f.commit_id);
        let bin = wire::bundle(
            &f.commit_id,
            &commit_bytes,
            &steps,
            &wire::range_payload(None, 1024, 32, &slice, &[]), // claims chunk 1, not chunk 0
        );
        v.push(Vector {
            name: "neg_slice_wrong_offset",
            description: "A genuine Bao slice for chunk 0 (offset 0) is claimed to be at offset 1024 (chunk 1).",
            bin,
            json: base_json(
                &f.commit_id,
                &range_path,
                "range(offset=1024,len=32) [slice built for offset=0]",
                false,
                Some("Bao slice does not verify at the claimed offset"),
            ),
        });
    }

    // 7. Zero-length range.
    {
        let (steps, leaf) = walk_path(&f.store, f.tree_hash, &["shallow.txt".as_bytes()]);
        let canonical = canonical_bytes(&f.store, &leaf);
        let slice = bao_slice(&canonical, 10, 1);
        let commit_bytes = canonical_bytes(&f.store, &f.commit_id);
        let bin = wire::bundle(
            &f.commit_id,
            &commit_bytes,
            &steps,
            &wire::range_payload(None, 0, 0, &slice, &[]),
        );
        v.push(Vector {
            name: "neg_zero_length_range",
            description: "A Range payload with len = 0.",
            bin,
            json: base_json(
                &f.commit_id,
                &[b"shallow.txt"],
                "range(offset=0,len=0)",
                false,
                Some("byte range length is zero"),
            ),
        });
    }

    // 8. Incomplete chunk_len_proofs (drops the proof for index 0 out of
    //    a set that should cover 0..index).
    {
        let (steps, leaf) = walk_path(&f.store, f.tree_hash, &chunked_path);
        let Object::ChunkedBlob(cb) = f.store.read_object(&leaf).unwrap() else {
            panic!("expected ChunkedBlob");
        };
        // The target offset MUST land at least 2 chunks in: dropping
        // index 0's proof from a set covering only `{0}` (target index 1)
        // would leave an *empty* vec, indistinguishable from "offsets not
        // requested" — the gap must leave at least one other entry behind
        // to actually exercise incomplete-set detection.
        let first_two_chunks_len: u64 = cb.chunks[..2]
            .iter()
            .map(|id| f.store.read(id).unwrap().len() as u64 - 10)
            .sum();
        let target_offset = first_two_chunks_len + 32;
        let mut cumulative = 0u64;
        let mut target_index = 0usize;
        for (idx, id) in cb.chunks.iter().enumerate() {
            let content_len = f.store.read(id).unwrap().len() as u64 - 10;
            if target_offset < cumulative + content_len {
                target_index = idx;
                break;
            }
            cumulative += content_len;
        }
        assert!(
            target_index >= 2,
            "fixture assumption: target chunk index >= 2 (got {target_index})"
        );
        let position = merkle::chunk_position(&cb, &cb.chunks[target_index]).unwrap();
        let hdr_proof = merkle::build_chunks_multi_proof(&cb, [0, position]).unwrap();
        let chunk_canonical = f.store.read(&cb.chunks[target_index]).unwrap();
        let offset_in_chunk = target_offset - cumulative;
        let slice = bao_slice(&chunk_canonical, offset_in_chunk + 10, 16);

        // A complete set would cover 0..target_index; drop index 0.
        let mut len_proofs = Vec::new();
        for j in 0..target_index {
            if j == 0 {
                continue; // the gap
            }
            let jpos = merkle::chunk_position(&cb, &cb.chunks[j]).unwrap();
            let jproof = merkle::build_chunk_proof(&cb, jpos).unwrap();
            let jcanonical = f.store.read(&cb.chunks[j]).unwrap();
            let jslice = bao_slice(&jcanonical, 0, 10);
            len_proofs.push(wire::LenProof {
                index: u32::try_from(j).unwrap(),
                chunk_id: cb.chunks[j],
                proof: jproof,
                slice: jslice,
            });
        }
        let commit_bytes = canonical_bytes(&f.store, &f.commit_id);
        let bin = wire::bundle(
            &f.commit_id,
            &commit_bytes,
            &steps,
            &wire::range_payload(
                Some(&wire::ChunkHdr {
                    total_size: cb.total_size,
                    chunk_size: cb.chunk_size,
                    index: u32::try_from(target_index).unwrap(),
                    chunk_id: cb.chunks[target_index],
                    proof: hdr_proof,
                }),
                offset_in_chunk,
                16,
                &slice,
                &len_proofs,
            ),
        );
        v.push(Vector {
            name: "neg_incomplete_length_proof_set",
            description: "chunk_len_proofs is missing the proof for index 0, an incomplete 0..index set.",
            bin,
            json: base_json(
                &f.commit_id,
                &chunked_path,
                "range [chunk_len_proofs missing index 0]",
                false,
                Some("chunk_len_proofs does not cover exactly 0..index"),
            ),
        });
    }

    // 9. steps.len() = 129 (one over MAX_TREE_DEPTH).
    {
        let (steps, leaf) = walk_path(&f.store, f.tree_hash, &["shallow.txt".as_bytes()]);
        let too_many: Vec<Step> = std::iter::repeat_n(steps[0].clone(), 129).collect();
        let bytes = canonical_bytes(&f.store, &leaf);
        let commit_bytes = canonical_bytes(&f.store, &f.commit_id);
        let bin = wire::bundle(
            &f.commit_id,
            &commit_bytes,
            &too_many,
            &wire::object_payload(&bytes),
        );
        v.push(Vector {
            name: "neg_too_many_steps",
            description: "129 steps, one over MAX_TREE_DEPTH (128).",
            bin,
            json: base_json(
                &f.commit_id,
                &[],
                "object",
                false,
                Some("steps.len() > MAX_TREE_DEPTH"),
            ),
        });
    }

    // 10. version = 2.
    {
        let (steps, leaf) = walk_path(&f.store, f.tree_hash, &["shallow.txt".as_bytes()]);
        let bytes = canonical_bytes(&f.store, &leaf);
        let commit_bytes = canonical_bytes(&f.store, &f.commit_id);
        let mut bin = wire::bundle(
            &f.commit_id,
            &commit_bytes,
            &steps,
            &wire::object_payload(&bytes),
        );
        bin[4] = 2;
        v.push(Vector {
            name: "neg_unsupported_version",
            description: "The version byte is 2 instead of the only supported value, 1.",
            bin,
            json: base_json(
                &f.commit_id,
                &[b"shallow.txt"],
                "object",
                false,
                Some("unsupported version"),
            ),
        });
    }

    // 11. Trailing byte.
    {
        let (steps, leaf) = walk_path(&f.store, f.tree_hash, &["shallow.txt".as_bytes()]);
        let bytes = canonical_bytes(&f.store, &leaf);
        let commit_bytes = canonical_bytes(&f.store, &f.commit_id);
        let mut bin = wire::bundle(
            &f.commit_id,
            &commit_bytes,
            &steps,
            &wire::object_payload(&bytes),
        );
        bin.push(0);
        v.push(Vector {
            name: "neg_trailing_byte",
            description: "One extra trailing byte after the declared body.",
            bin,
            json: base_json(
                &f.commit_id,
                &[b"shallow.txt"],
                "object",
                false,
                Some("trailing bytes"),
            ),
        });
    }

    // 12. commit_bytes that decode to a Tag, not a Commit/Remix.
    {
        let tag = mkit_core::object::Tag {
            target: f.commit_id,
            target_type: mkit_core::object::ObjectType::Commit,
            name: b"v1".to_vec(),
            tagger: Identity::ed25519([9u8; 32]),
            signer: [9u8; 32],
            message: Vec::new(),
            timestamp: 0,
            signature: [0u8; 64],
        };
        let tag_bytes = mkit_core::serialize::serialize(&Object::Tag(tag)).unwrap();
        let tag_id = hash(&tag_bytes);
        let bin = wire::bundle(&tag_id, &tag_bytes, &[], &wire::object_payload(&tag_bytes));
        v.push(Vector {
            name: "neg_commit_bytes_are_a_tag",
            description: "commit_bytes decode to a valid, signed Tag rather than a Commit/Remix.",
            bin,
            json: base_json(
                &tag_id,
                &[],
                "object",
                false,
                Some("commit_bytes decode to a Tag"),
            ),
        });
    }

    // 13. chunk_len_proofs present when the disclosed chunk is index 0.
    //     Nothing precedes chunk 0, so any entry here — however
    //     plausible-looking — MUST be rejected outright, the same as the
    //     plain-Blob path already rejects a non-empty set.
    {
        let (steps, leaf) = walk_path(&f.store, f.tree_hash, &chunked_path);
        let Object::ChunkedBlob(cb) = f.store.read_object(&leaf).unwrap() else {
            panic!("expected ChunkedBlob");
        };
        let position0 = merkle::chunk_position(&cb, &cb.chunks[0]).unwrap();
        let hdr_proof = merkle::build_chunks_multi_proof(&cb, [0, position0]).unwrap();
        let chunk0_canonical = f.store.read(&cb.chunks[0]).unwrap();
        let slice = bao_slice(&chunk0_canonical, 10, 16); // offset 0, len 16 inside chunk 0

        // A plausible-looking but structurally invalid entry: it claims
        // to describe "the chunk before index 0" using chunk 0's own
        // (otherwise genuine) proof and length slice.
        let len_proof_entry_proof = merkle::build_chunk_proof(&cb, position0).unwrap();
        let len_slice = bao_slice(&chunk0_canonical, 0, 10);

        let commit_bytes = canonical_bytes(&f.store, &f.commit_id);
        let bin = wire::bundle(
            &f.commit_id,
            &commit_bytes,
            &steps,
            &wire::range_payload(
                Some(&wire::ChunkHdr {
                    total_size: cb.total_size,
                    chunk_size: cb.chunk_size,
                    index: 0,
                    chunk_id: cb.chunks[0],
                    proof: hdr_proof,
                }),
                0,
                16,
                &slice,
                &[wire::LenProof {
                    index: 0,
                    chunk_id: cb.chunks[0],
                    proof: len_proof_entry_proof,
                    slice: len_slice,
                }],
            ),
        );
        v.push(Vector {
            name: "neg_len_proofs_on_chunk0",
            description: "A Range payload discloses chunk index 0 but still carries a chunk_len_proofs entry; index 0 has nothing preceding it to describe, so any entry there is rejected outright.",
            bin,
            json: base_json(
                &f.commit_id,
                &chunked_path,
                "range(offset=0,len=16) [chunk_len_proofs on chunk 0]",
                false,
                Some("chunk_len_proofs is only meaningful at chunk index > 0"),
            ),
        });
    }

    v
}

/// Regenerate `rust/tests/golden/disclosure/` from `build_vectors()`.
fn write_all() {
    let dir = disclosure_dir();
    fs::create_dir_all(&dir).expect("create disclosure/ dir");
    let mut manifest = String::from(
        "# SPEC-DISCLOSURE golden vectors (deterministic)\n\
         # Produced by `MKIT_WRITE_GOLDEN=1 cargo test -p mkit-core --test golden_disclosure`\n\
         # Format: <name> <blake3-hex-of-bin-bytes>\n\
         # See docs/specs/SPEC-DISCLOSURE.md.\n",
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
fn write_golden_disclosure_vectors_if_requested() {
    if writing() {
        write_all();
    }
}

// ---------------------------------------------------------------------------
// Consumer: reads ONLY the committed files, never the generator above.
// ---------------------------------------------------------------------------

fn manifest_names_and_digests() -> Vec<(String, String)> {
    let raw = fs::read_to_string(disclosure_dir().join("MANIFEST.txt"))
        .expect("read rust/tests/golden/disclosure/MANIFEST.txt");
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

fn verify_vector(name: &str, want_digest: &str) {
    let dir = disclosure_dir();
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

    let commit_id: Hash =
        mkit_core::hash::from_hex(sidecar["commit_id_hex"].as_str().unwrap()).unwrap();
    let expect_accept = match sidecar["expect"].as_str().unwrap() {
        "accept" => true,
        "reject" => false,
        other => panic!("{name}.json: unknown expect value {other:?}"),
    };

    let result: Result<Disclosed, VerifyError> = verify::verify_disclosure(&commit_id, &bin);
    match (expect_accept, result) {
        (true, Ok(d)) => {
            let want = &sidecar["disclosed"];
            assert_eq!(
                to_hex(&d.leaf_id),
                want["leaf_id_hex"].as_str().unwrap(),
                "{name}: leaf_id mismatch"
            );
            assert_eq!(
                to_hex(&d.tree_hash),
                want["tree_hash_hex"].as_str().unwrap(),
                "{name}: tree_hash mismatch"
            );
            let payload_bytes = match &d.payload {
                DisclosedPayload::Object { bytes }
                | DisclosedPayload::Chunk { bytes, .. }
                | DisclosedPayload::Range { bytes, .. } => bytes,
            };
            assert_eq!(
                to_hex(&hash(payload_bytes)),
                want["payload"]["bytes_blake3"].as_str().unwrap(),
                "{name}: disclosed payload bytes hash mismatch"
            );
            if let DisclosedPayload::Range {
                absolute_offset, ..
            } = &d.payload
            {
                let want_abs = want["payload"]["absolute_offset"].as_u64();
                assert_eq!(
                    absolute_offset.map(i128::from),
                    want_abs.map(i128::from),
                    "{name}: absolute_offset mismatch"
                );
            }
        }
        (true, Err(e)) => panic!("{name}: expected accept, got {e:?}"),
        (false, Ok(_)) => panic!(
            "{name}: expected reject ({}), but verification accepted it",
            sidecar
                .get("reject_reason")
                .and_then(Value::as_str)
                .unwrap_or("<none recorded>")
        ),
        (false, Err(_)) => {} // any typed rejection satisfies a reject vector
    }
}

#[test]
fn golden_disclosure_vectors_verify() {
    if writing() {
        return;
    }
    let vectors = manifest_names_and_digests();
    assert!(
        !vectors.is_empty(),
        "MANIFEST.txt listed no vectors — did you forget to run \
         `MKIT_WRITE_GOLDEN=1 cargo test -p mkit-core --test golden_disclosure`?"
    );
    for (name, digest) in vectors {
        verify_vector(&name, &digest);
    }
}
