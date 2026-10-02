//! Native tests for the verifier-kit wasm exports (issue #1015 PR 4).
//!
//! Golden vectors are the same files `mkit-core` consumes. This crate
//! only reads `MANIFEST.txt` and the committed sidecars — it does not
//! re-derive expectations. Tests run on native (`cdylib` + `rlib`); the
//! wasm-bindgen wrappers call the same Rust functions the bundler build
//! exports.

#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;

use mkit_wasm::{
    blake3_hex, blob_bao_encode, blob_bao_slice, blob_bao_verify_slice, blob_encode,
    chunked_blob_decode, disclosure_payload_bytes, object_id, verify_chunk,
    verify_closure_manifest, verify_closure_packs, verify_disclosure, verify_disclosure_span,
    verify_tree_entry, wrap_object_id,
};
use serde_json::Value;

fn golden_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("tests");
    d.push("golden");
    d
}

fn manifest_names_and_digests(dir: &std::path::Path) -> Vec<(String, String)> {
    let raw = fs::read_to_string(dir.join("MANIFEST.txt"))
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.join("MANIFEST.txt").display()));
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

fn read_json(path: &std::path::Path) -> Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn concat_packs(packs: &[Vec<u8>]) -> (Vec<u8>, String) {
    let mut out = Vec::new();
    let mut lens = Vec::new();
    for p in packs {
        lens.push(u64::try_from(p.len()).unwrap());
        out.extend_from_slice(p);
    }
    (out, serde_json::to_string(&lens).unwrap())
}

fn entry_mode_js(mode: u64) -> &'static str {
    match mode {
        1 => "blob",
        2 => "tree",
        3 => "symlink",
        4 => "exec",
        other => panic!("unknown EntryMode {other}"),
    }
}

fn assert_rejected<T: std::fmt::Debug>(result: &Result<T, String>, name: &str) {
    assert!(result.is_err(), "{name}: expected reject, got {result:?}");
}

// ---------------------------------------------------------------------------
// Disclosure goldens
// ---------------------------------------------------------------------------

#[test]
fn golden_disclosure_vectors_via_wasm() {
    let dir = golden_root().join("disclosure");
    let vectors = manifest_names_and_digests(&dir);
    assert!(!vectors.is_empty(), "disclosure MANIFEST.txt is empty");
    for (name, digest) in vectors {
        let bin = fs::read(dir.join(format!("{name}.bin"))).unwrap();
        assert_eq!(blake3_hex(&bin), digest, "{name}.bin digest");
        let sidecar = read_json(&dir.join(format!("{name}.json")));
        assert_eq!(sidecar["blake3"].as_str().unwrap(), digest);
        let commit = sidecar["commit_id_hex"].as_str().unwrap();
        let expect = sidecar["expect"].as_str().unwrap();
        match expect {
            "accept" => {
                let json: Value =
                    serde_json::from_str(&verify_disclosure(commit, &bin).unwrap()).unwrap();
                let want = &sidecar["disclosed"];
                assert_eq!(json["commit_id"], commit);
                assert_eq!(json["leaf_id"], want["leaf_id_hex"]);
                assert_eq!(json["tree_hash"], want["tree_hash_hex"]);
                assert_eq!(json["signer"], want["signer_hex"]);
                assert_eq!(json["signature_valid"], want["signature_valid"]);
                assert_eq!(json["payload"]["kind"], want["payload"]["kind"]);
                assert_eq!(
                    json["payload"]["bytes_blake3"],
                    want["payload"]["bytes_blake3"]
                );
                let payload = disclosure_payload_bytes(commit, &bin).unwrap();
                assert_eq!(blake3_hex(&payload), want["payload"]["bytes_blake3"]);
                if want["payload"]["kind"] == "range" {
                    assert_eq!(
                        json["payload"]["absolute_offset"],
                        want["payload"]["absolute_offset"]
                    );
                    assert_eq!(
                        json["payload"]["offset_in_blob"],
                        want["payload"]["offset_in_blob"]
                    );
                }
            }
            "reject" => {
                assert_rejected(&verify_disclosure(commit, &bin), &name);
                assert_rejected(&disclosure_payload_bytes(commit, &bin), &name);
            }
            other => panic!("{name}: unknown expect {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP-objects MKDS goldens
// ---------------------------------------------------------------------------

fn http_object_body(dir: &std::path::Path, name: &str, sidecar: &Value) -> Vec<u8> {
    let Some(segments) = sidecar
        .pointer("/recipe/segments")
        .and_then(Value::as_array)
    else {
        return fs::read(dir.join(format!("{name}.bin"))).unwrap();
    };
    let mut bytes = Vec::new();
    for segment in segments {
        if let Some(source) = segment["source"].as_str() {
            let base = fs::read(dir.join(source)).unwrap();
            let offset = usize::try_from(segment["offset"].as_u64().unwrap()).unwrap();
            let length = usize::try_from(segment["length"].as_u64().unwrap()).unwrap();
            bytes.extend_from_slice(&base[offset..offset + length]);
        } else {
            bytes.extend_from_slice(&hex::decode(segment["hex"].as_str().unwrap()).unwrap());
        }
    }
    bytes
}

#[test]
fn golden_http_object_spans_via_wasm() {
    let dir = golden_root().join("http-objects");
    let mut seen_accept = 0;
    let mut seen_reject = 0;
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let name = path.file_stem().unwrap().to_str().unwrap();
        if [
            "url-parse",
            "response-cases",
            "content-headers",
            "object_shallow",
            "object_root",
            "chunk",
            "in_chunk_range",
            "blob_range",
        ]
        .contains(&name)
        {
            continue;
        }
        let sidecar = read_json(&path);
        let mut bytes = http_object_body(&dir, name, &sidecar);
        assert_eq!(
            sidecar["size"],
            serde_json::json!(bytes.len()),
            "{name}: reconstructed size"
        );
        assert_eq!(sidecar["blake3"], blake3_hex(&bytes), "{name}: body digest");
        let want = &sidecar["expect"];
        if let Some(expand_to) = want["expand_to"].as_u64() {
            bytes.resize(usize::try_from(expand_to).unwrap(), 0);
        }
        let commit = sidecar["commit"].as_str().unwrap();
        if want["accept"] == true {
            seen_accept += 1;
            let span = verify_disclosure_span(commit, &bytes).unwrap();
            let json: Value = serde_json::from_str(&span.json()).unwrap();
            assert_eq!(json["commit_id"], commit, "{name}");
            assert_eq!(json["leaf_id"], want["leaf"], "{name}");
            assert_eq!(json["offset"], want["offset"], "{name}");
            assert_eq!(json["bytes_len"], want["bytes_len"], "{name}");
            assert_eq!(json["bytes_blake3"], want["bytes_blake3"], "{name}");
            assert_eq!(json["signature_valid"], want["signature_valid"], "{name}");
            let path_hex: Vec<_> = json["path"]
                .as_array()
                .unwrap()
                .iter()
                .map(|part| part["name_hex"].clone())
                .collect();
            assert_eq!(serde_json::json!(path_hex), want["path_hex"], "{name}");
            assert_eq!(blake3_hex(&span.bytes()), want["bytes_blake3"], "{name}");
        } else {
            seen_reject += 1;
            let reason = want["reject_reason"].as_str().unwrap();
            let err = verify_disclosure_span(commit, &bytes).unwrap_err();
            assert!(err.starts_with(reason), "{name}: {err}");
        }
    }
    assert!(seen_accept >= 3);
    assert!(seen_reject >= 15);
}

#[test]
fn disclosure_exports_reject_the_other_format() {
    let dir = golden_root().join("http-objects");
    let single_bundle = fs::read(dir.join("in_chunk_range.bin")).unwrap();
    let span_container = fs::read(dir.join("span_two_chunks.bin")).unwrap();
    let commit = read_json(&dir.join("span_two_chunks.json"))["commit"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        verify_disclosure_span(&commit, &single_bundle)
            .unwrap_err()
            .starts_with("span_magic")
    );
    assert!(verify_disclosure(&commit, &span_container).is_err());
}

#[test]
fn oversize_span_input_returns_reason() {
    let bytes = vec![0u8; 64 * 1024 * 1024 + 1];
    let err = verify_disclosure_span(&"00".repeat(32), &bytes).unwrap_err();
    assert!(err.starts_with("span_too_large"), "{err}");
}

// ---------------------------------------------------------------------------
// Closure goldens
// ---------------------------------------------------------------------------

#[test]
fn golden_closure_vectors_via_wasm() {
    let dir = golden_root().join("closure");
    let vectors = manifest_names_and_digests(&dir);
    assert!(!vectors.is_empty(), "closure MANIFEST.txt is empty");
    for (name, digest) in vectors {
        let manifest = fs::read(dir.join(format!("{name}.manifest.bin"))).unwrap();
        assert_eq!(blake3_hex(&manifest), digest, "{name}.manifest.bin digest");
        let sidecar = read_json(&dir.join(format!("{name}.json")));
        let n_packs = usize::try_from(sidecar["n_packs"].as_u64().unwrap()).unwrap();
        let mut packs = Vec::with_capacity(n_packs);
        for i in 0..n_packs {
            packs.push(fs::read(dir.join(format!("{name}.pack{i}.bin"))).unwrap());
        }
        let (concat, lengths) = concat_packs(&packs);
        let root = sidecar["root_hex"].as_str().unwrap();
        match sidecar["expect"].as_str().unwrap() {
            "reject" => {
                assert_rejected(
                    &verify_closure_manifest(root, &manifest, &concat, &lengths),
                    &name,
                );
            }
            "accept" | "incomplete" => {
                let json: Value = serde_json::from_str(
                    &verify_closure_manifest(root, &manifest, &concat, &lengths).unwrap(),
                )
                .unwrap();
                assert_eq!(json["unreferenced_checked"], true, "{name}");
                let complete = json["complete"].as_bool().unwrap();
                if sidecar["expect"] == "accept" {
                    assert!(complete, "{name}: expected complete");
                    assert_eq!(json["verified"], sidecar["verified"]);
                    assert_eq!(json["unreferenced"], sidecar["unreferenced"]);
                    assert_eq!(json["root"], root);
                    assert_eq!(json["mode"], sidecar["mode"]);
                    let via_packs: Value = serde_json::from_str(
                        &verify_closure_packs(
                            root,
                            sidecar["mode"].as_str().unwrap(),
                            &concat,
                            &lengths,
                        )
                        .unwrap(),
                    )
                    .unwrap();
                    assert!(via_packs["complete"].as_bool().unwrap());
                    assert_eq!(via_packs["verified"], json["verified"]);
                    assert_eq!(via_packs["unreferenced_checked"], true, "{name}");
                } else {
                    assert!(!complete, "{name}: expected incomplete");
                }
            }
            other => panic!("{name}: unknown expect {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Proof goldens (single-leaf exports only)
// ---------------------------------------------------------------------------

#[test]
fn golden_proof_vectors_via_wasm() {
    let dir = golden_root().join("proofs");
    let vectors = manifest_names_and_digests(&dir);
    assert!(!vectors.is_empty(), "proofs MANIFEST.txt is empty");
    let mut seen_single = 0usize;
    for (name, digest) in vectors {
        let bin = fs::read(dir.join(format!("{name}.bin"))).unwrap();
        assert_eq!(blake3_hex(&bin), digest, "{name}.bin digest");
        let sidecar = read_json(&dir.join(format!("{name}.json")));
        let kind = sidecar["kind"].as_str().unwrap();
        let proof_kind = sidecar["proof_kind"].as_str().unwrap();
        let expect_accept = sidecar["expect"].as_str().unwrap() == "accept";
        match (kind, proof_kind) {
            ("tree_entry", "single") => {
                seen_single += 1;
                let entry = &sidecar["entries"][0];
                let entry_json = serde_json::json!({
                    "name_hex": entry["name_hex"],
                    "mode": entry_mode_js(entry["mode"].as_u64().unwrap()),
                    "object_hash": entry["object_hash_hex"],
                })
                .to_string();
                let position = u32::try_from(sidecar["position"].as_u64().unwrap()).unwrap();
                let result = verify_tree_entry(
                    sidecar["object_id_hex"].as_str().unwrap(),
                    &entry_json,
                    position,
                    &bin,
                );
                if expect_accept {
                    assert!(result.unwrap(), "{name}: expected accept");
                } else {
                    match result {
                        Ok(false) | Err(_) => {}
                        Ok(true) => panic!("{name}: expected reject, proof accepted"),
                    }
                }
            }
            ("chunk", "single") => {
                seen_single += 1;
                let hashes = sidecar["chunk_hashes_hex"].as_array().unwrap();
                let chunk_hex = if hashes.is_empty() {
                    "00".repeat(32)
                } else {
                    hashes[0].as_str().unwrap().to_string()
                };
                let position = u32::try_from(sidecar["position"].as_u64().unwrap()).unwrap();
                let result = verify_chunk(
                    sidecar["object_id_hex"].as_str().unwrap(),
                    &chunk_hex,
                    position,
                    &bin,
                );
                if expect_accept {
                    assert!(result.unwrap(), "{name}: expected accept");
                } else {
                    match result {
                        Ok(false) | Err(_) => {}
                        Ok(true) => panic!("{name}: expected reject, proof accepted"),
                    }
                }
            }
            ("tree_entry", "range" | "multi") | ("chunk", "range") => {
                // PR 4 exports only the single-leaf verifiers. Range/multi
                // stay on mkit-core; the MANIFEST digest check above still
                // pins the bytes.
            }
            (k, p) => panic!("{name}: unknown (kind, proof_kind) = ({k}, {p})"),
        }
    }
    assert!(seen_single > 0, "no single-leaf proof vectors found");
}

// ---------------------------------------------------------------------------
// Canonical-blob Bao
// ---------------------------------------------------------------------------

#[test]
fn blob_bao_hash_equals_blob_id_and_round_trips() {
    let content = b"canonical-blob-bao";
    let encoded = blob_encode(content).unwrap();
    let bao = blob_bao_encode(content).unwrap();
    assert_eq!(bao.hash_hex(), encoded.hash_hex());
    assert_eq!(bao.hash_hex(), object_id(&encoded.bytes()).unwrap());

    let offset = 2u32;
    let len = 8u32;
    let slice = blob_bao_slice(&bao.outboard(), content, offset, len).unwrap();
    let v = blob_bao_verify_slice(&bao.hash_hex(), &slice, offset, len).unwrap();
    assert!(v.ok(), "verify failed: {:?}", v.error());
    assert_eq!(
        &v.bytes().unwrap()[..],
        &content[offset as usize..][..len as usize]
    );

    let mut bad = slice.to_vec();
    let idx = bad.len() - 1;
    bad[idx] ^= 0x01;
    let flipped = blob_bao_verify_slice(&bao.hash_hex(), &bad, offset, len).unwrap();
    assert!(!flipped.ok(), "byte flip must fail");
}

// ---------------------------------------------------------------------------
// Oversize / malformed input
// ---------------------------------------------------------------------------

#[test]
fn oversize_inputs_return_err() {
    let oversized = vec![0u8; 16 * 1024 * 1024 + 1];
    assert!(chunked_blob_decode(&oversized).is_err());
    assert!(blob_bao_encode(&oversized).is_err());

    // Length-declaring header: MKDP v1 + 32-byte id + a commit_bytes
    // varint of 5_000_000 and no payload. Decode must fail without
    // allocating that many bytes.
    let mut tiny = Vec::from(*b"MKDP");
    tiny.push(1);
    tiny.extend_from_slice(&[0u8; 32]);
    tiny.extend_from_slice(&[0xC0, 0x96, 0x31]);
    let commit_hex = "00".repeat(32);
    assert!(verify_disclosure(&commit_hex, &tiny).is_err());

    assert!(
        verify_closure_packs(&commit_hex, "snapshot", &[], "[4294967295]").is_err(),
        "claimed pack length larger than the concatenated buffer"
    );
    assert!(wrap_object_id("blob", &commit_hex).is_err());
    assert!(verify_tree_entry(&commit_hex, "[]", 0, &[]).is_err());
}

#[test]
fn wrap_object_id_rejects_unknown_kind() {
    let hex = "11".repeat(32);
    assert!(wrap_object_id("commit", &hex).is_err());
    assert_eq!(wrap_object_id("tree", &hex).unwrap().len(), 64);
    assert_eq!(wrap_object_id("chunked_blob", &hex).unwrap().len(), 64);
}
