//! Disclosure, closure, and Merkle-proof verification exports.
//!
//! Thin wrappers over `mkit_core::verify` and `mkit_core::merkle`. Structured
//! results cross the JS boundary as JSON strings; payload bytes of a
//! disclosure are returned out-of-band by [`disclosure_payload_bytes`].
//! Hashes are 64-char lowercase hex. Every input length is checked before
//! decode work. See issue #1015 (verifier kit) PR 4.

use std::io::Read as _;

use wasm_bindgen::prelude::*;

use mkit_core::ClosureMode;
use mkit_core::hash::{hash, to_hex};
use mkit_core::merkle::{self, MerkleError, ObjectKind, Proof};
use mkit_core::object::{Blob, ChunkedBlob, EntryMode, Object, TreeEntry};
use mkit_core::serialize::serialize;
use mkit_core::verify::{
    self, ClosureReport, Disclosed, DisclosedPayload, MAX_BUNDLE_BYTES, MAX_CLOSURE_PACKS,
};

use crate::chunking::{BaoEncoded, BaoVerify};
use crate::common::MAX_JSON_BYTES;
use crate::objects::MAX_WORKSPACE_OBJECT_BYTES;

/// Hard cap on the concatenated closure packs a wasm verifier will accept,
/// checked independently of [`MAX_BUNDLE_BYTES`] (a disclosure bundle and a
/// closure pack set are different shapes with different realistic sizes: a
/// bundle is a handful of proofs, a closure is every object reachable from a
/// commit). Matches `mkit_core::store::MAX_RAW_OBJECT_SIZE` (1 GiB) — the
/// same ceiling the native store already applies to a single object, so a
/// wasm closure verifier admits nothing a native `ObjectStore` would refuse
/// to write in the first place.
pub(crate) const MAX_CLOSURE_INPUT_BYTES: usize = 1024 * 1024 * 1024;

fn hash_hex(s: &str) -> Result<[u8; 32], String> {
    mkit_core::hash::from_hex(s).map_err(|_| "expected 64 lowercase hex characters".into())
}

fn cap_object(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > MAX_WORKSPACE_OBJECT_BYTES {
        return Err("workspace object exceeds 16 MiB".into());
    }
    Ok(())
}

fn cap_bundle(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(format!(
            "disclosure bundle exceeds the {MAX_BUNDLE_BYTES} byte cap"
        ));
    }
    Ok(())
}

fn mode_str(mode: EntryMode) -> &'static str {
    match mode {
        EntryMode::Blob => "blob",
        EntryMode::Tree => "tree",
        EntryMode::Symlink => "symlink",
        EntryMode::Executable => "exec",
    }
}

fn parse_mode(s: &str) -> Result<EntryMode, String> {
    match s {
        "blob" => Ok(EntryMode::Blob),
        "tree" => Ok(EntryMode::Tree),
        "symlink" => Ok(EntryMode::Symlink),
        "exec" => Ok(EntryMode::Executable),
        other => Err(format!("unknown entry mode `{other}`")),
    }
}

fn parse_closure_mode(s: &str) -> Result<ClosureMode, String> {
    match s {
        "snapshot" => Ok(ClosureMode::Snapshot),
        "history" => Ok(ClosureMode::History),
        other => Err(format!("unknown closure mode `{other}`")),
    }
}

fn closure_mode_str(mode: ClosureMode) -> &'static str {
    match mode {
        ClosureMode::Snapshot => "snapshot",
        ClosureMode::History => "history",
    }
}

fn payload_bytes(payload: &DisclosedPayload) -> &[u8] {
    match payload {
        DisclosedPayload::Object { bytes }
        | DisclosedPayload::Chunk { bytes, .. }
        | DisclosedPayload::Range { bytes, .. } => bytes,
    }
}

fn path_json(path: &[(Vec<u8>, EntryMode)]) -> serde_json::Value {
    serde_json::Value::Array(
        path.iter()
            .map(|(name, mode)| {
                let utf8 = std::str::from_utf8(name).ok();
                serde_json::json!({
                    "name": utf8,
                    "name_hex": hex::encode(name),
                    "mode": mode_str(*mode),
                })
            })
            .collect(),
    )
}

fn payload_json(payload: &DisclosedPayload) -> serde_json::Value {
    let bytes = payload_bytes(payload);
    let bytes_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let bytes_blake3 = to_hex(&hash(bytes));
    match payload {
        DisclosedPayload::Object { .. } => serde_json::json!({
            "kind": "object",
            "bytes_len": bytes_len,
            "bytes_blake3": bytes_blake3,
        }),
        DisclosedPayload::Chunk {
            total_size,
            chunk_size,
            index,
            ..
        } => serde_json::json!({
            "kind": "chunk",
            "bytes_len": bytes_len,
            "bytes_blake3": bytes_blake3,
            "index": index,
            "total_size": total_size,
            "chunk_size": chunk_size,
        }),
        DisclosedPayload::Range {
            blob_id,
            chunk,
            offset_in_blob,
            absolute_offset,
            ..
        } => serde_json::json!({
            "kind": "range",
            "bytes_len": bytes_len,
            "bytes_blake3": bytes_blake3,
            "blob_id": to_hex(blob_id),
            "chunk": match chunk {
                None => serde_json::Value::Null,
                Some((index, total_size, chunk_size)) => serde_json::json!({
                    "index": index,
                    "total_size": total_size,
                    "chunk_size": chunk_size,
                }),
            },
            "offset_in_blob": offset_in_blob,
            "absolute_offset": match absolute_offset {
                Some(off) => serde_json::json!(off),
                None => serde_json::Value::Null,
            },
        }),
    }
}

fn disclosed_to_json(d: &Disclosed) -> Result<String, String> {
    serde_json::to_string(&serde_json::json!({
        "commit_id": to_hex(&d.commit_id),
        "tree_hash": to_hex(&d.tree_hash),
        "path": path_json(&d.path),
        "leaf_id": to_hex(&d.leaf_id),
        "signer": to_hex(&d.signer),
        "signature_valid": d.signature_valid,
        "payload": payload_json(&d.payload),
        "step_inner_roots": d.step_inner_roots.iter().map(to_hex).collect::<Vec<_>>(),
        "chunk_inner_root": d.chunk_inner_root.as_ref().map(to_hex),
    }))
    .map_err(|e| format!("disclosed JSON: {e}"))
}

fn report_to_json(r: &ClosureReport) -> Result<String, String> {
    serde_json::to_string(&serde_json::json!({
        "root": to_hex(&r.root),
        "mode": closure_mode_str(r.mode),
        "verified": u64::try_from(r.verified).unwrap_or(u64::MAX),
        "complete": r.is_complete(),
        "missing": r.missing.iter().map(to_hex).collect::<Vec<_>>(),
        "corrupt": r.corrupt.iter().map(|(id, reason)| {
            serde_json::json!({ "id": to_hex(id), "reason": reason })
        }).collect::<Vec<_>>(),
        "unreferenced": r.unreferenced.iter().map(to_hex).collect::<Vec<_>>(),
    }))
    .map_err(|e| format!("closure JSON: {e}"))
}

fn split_packs<'a>(packs: &'a [u8], lengths_json: &str) -> Result<Vec<&'a [u8]>, String> {
    if packs.len() > MAX_CLOSURE_INPUT_BYTES {
        return Err(format!(
            "closure packs exceed the {MAX_CLOSURE_INPUT_BYTES} byte cap"
        ));
    }
    if lengths_json.len() > MAX_JSON_BYTES {
        return Err("pack lengths JSON exceeds 16 MiB cap".into());
    }
    let v: serde_json::Value =
        serde_json::from_str(lengths_json).map_err(|e| format!("pack lengths JSON: {e}"))?;
    let arr = v
        .as_array()
        .ok_or_else(|| "pack lengths JSON must be an array".to_string())?;
    if arr.len() > MAX_CLOSURE_PACKS {
        return Err("closure pack count exceeds MAX_CLOSURE_PACKS".into());
    }
    let mut out = Vec::with_capacity(arr.len());
    let mut offset = 0usize;
    for (i, n) in arr.iter().enumerate() {
        let len = n
            .as_u64()
            .ok_or_else(|| format!("pack_lengths[{i}] must be a number"))?;
        if len > MAX_CLOSURE_INPUT_BYTES as u64 {
            return Err(format!(
                "pack {i} exceeds the {MAX_CLOSURE_INPUT_BYTES} byte cap"
            ));
        }
        let len =
            usize::try_from(len).map_err(|_| format!("pack {i} length does not fit usize"))?;
        let end = offset
            .checked_add(len)
            .ok_or_else(|| format!("pack {i} length overflow"))?;
        if end > packs.len() {
            return Err(format!(
                "pack lengths exceed concatenated packs (at pack {i})"
            ));
        }
        out.push(&packs[offset..end]);
        offset = end;
    }
    if offset != packs.len() {
        return Err("pack lengths do not cover the concatenated packs".into());
    }
    Ok(out)
}

fn parse_tree_entry(entry_json: &str) -> Result<TreeEntry, String> {
    if entry_json.len() > MAX_JSON_BYTES {
        return Err("entry JSON exceeds 16 MiB cap".into());
    }
    let v: serde_json::Value =
        serde_json::from_str(entry_json).map_err(|e| format!("entry JSON: {e}"))?;
    let obj = v
        .as_object()
        .ok_or_else(|| "entry JSON must be an object".to_string())?;
    let mode = obj
        .get("mode")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "entry.mode must be a string".to_string())?;
    let mode = parse_mode(mode)?;
    let hash_hex = obj
        .get("object_hash")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "entry.object_hash must be a string".to_string())?;
    let object_hash = mkit_core::hash::from_hex(hash_hex)
        .map_err(|_| "expected 64 lowercase hex characters".to_string())?;
    let name = match (obj.get("name"), obj.get("name_hex")) {
        (Some(serde_json::Value::String(n)), None) => n.as_bytes().to_vec(),
        (None, Some(serde_json::Value::String(h))) => {
            hex::decode(h).map_err(|_| "entry.name_hex is not valid hex".to_string())?
        }
        (Some(serde_json::Value::String(n)), Some(serde_json::Value::String(h))) => {
            let decoded =
                hex::decode(h).map_err(|_| "entry.name_hex is not valid hex".to_string())?;
            if n.as_bytes() != decoded.as_slice() {
                return Err("entry.name and entry.name_hex do not match".into());
            }
            decoded
        }
        (Some(serde_json::Value::Null), Some(serde_json::Value::String(h))) => {
            hex::decode(h).map_err(|_| "entry.name_hex is not valid hex".to_string())?
        }
        _ => {
            return Err("entry needs `name` or `name_hex`".into());
        }
    };
    Ok(TreeEntry {
        name,
        mode,
        object_hash,
    })
}

fn merkle_bool(r: Result<(), MerkleError>) -> Result<bool, String> {
    match r {
        Ok(()) => Ok(true),
        Err(MerkleError::VerificationFailed) => Ok(false),
        Err(e) => Err(e.to_string()),
    }
}

fn canonical_blob(content: &[u8]) -> Result<Vec<u8>, String> {
    if content.len() > MAX_WORKSPACE_OBJECT_BYTES {
        return Err("workspace object exceeds 16 MiB".into());
    }
    serialize(&Object::Blob(Blob {
        data: content.to_vec(),
    }))
    .map_err(|e| format!("serialize: {e}"))
}

fn verify_disclosure_inner(commit_id_hex: &str, bundle: &[u8]) -> Result<Disclosed, String> {
    cap_bundle(bundle)?;
    let commit_id = mkit_core::hash::from_hex(commit_id_hex)
        .map_err(|_| "expected 64 lowercase hex characters".to_string())?;
    verify::verify_disclosure(&commit_id, bundle).map_err(|e| e.to_string())
}

/// Verify a disclosure bundle against a trusted commit id.
///
/// Returns JSON `{ commit_id, tree_hash, path, leaf_id, signer,
/// signature_valid, payload, step_inner_roots, chunk_inner_root }`
/// **without** payload bytes. Call
/// [`disclosure_payload_bytes`] for the verified bytes. Both functions
/// re-verify; a caller that wants both should call this first and treat a
/// failure of either as a failure.
///
/// `path` entries are `{ name }` (UTF-8 or `null`), `{ name_hex }`, and
/// `{ mode }` (`blob` / `tree` / `symlink` / `exec`). Payload `kind` is
/// `object`, `chunk`, or `range`. Bundles larger than 64 MiB
/// ([`MAX_BUNDLE_BYTES`]) are rejected before decode.
///
/// # Errors
///
/// Malformed hex, an oversize bundle, or any [`verify::VerifyError`].
#[wasm_bindgen]
pub fn verify_disclosure(commit_id_hex: &str, bundle: &[u8]) -> Result<String, String> {
    let d = verify_disclosure_inner(commit_id_hex, bundle)?;
    disclosed_to_json(&d)
}

/// Return the verified payload bytes of a disclosure bundle.
///
/// Re-verifies the bundle. Object payload: canonical object bytes. Chunk
/// payload: the chunk's canonical blob bytes. Range payload: the
/// disclosed range bytes.
///
/// # Errors
///
/// The same failures as [`verify_disclosure`].
#[wasm_bindgen]
pub fn disclosure_payload_bytes(commit_id_hex: &str, bundle: &[u8]) -> Result<Vec<u8>, String> {
    let d = verify_disclosure_inner(commit_id_hex, bundle)?;
    Ok(payload_bytes(&d.payload).to_vec())
}

/// Verify concatenated raw-only closure packs against a trusted root.
///
/// `mode` is `"snapshot"` or `"history"`. `packs` is the concatenation of
/// each pack's bytes; `pack_lengths_json` is a JSON array of those
/// lengths in the same order, e.g. `"[1024,2048]"`. Each pack and the
/// concatenated buffer are capped at 64 MiB.
///
/// Returns JSON `{ root, mode, verified, complete, missing, corrupt,
/// unreferenced }`.
///
/// # Errors
///
/// Malformed hex or mode, oversize or mis-sliced packs, or any
/// [`verify::VerifyError`].
#[wasm_bindgen]
pub fn verify_closure_packs(
    root_hex: &str,
    mode: &str,
    packs: &[u8],
    pack_lengths_json: &str,
) -> Result<String, String> {
    let root = hash_hex(root_hex)?;
    let mode = parse_closure_mode(mode)?;
    let slices = split_packs(packs, pack_lengths_json)?;
    let report = verify::verify_closure_packs(&root, mode, &slices).map_err(|e| e.to_string())?;
    report_to_json(&report)
}

/// Verify a closure manifest plus concatenated packs against a trusted root.
///
/// The manifest is a locator, never a trust anchor: `expected_root_hex`
/// must match the manifest root. Pack framing matches
/// [`verify_closure_packs`].
///
/// # Errors
///
/// Malformed hex, oversize input, or any [`verify::VerifyError`].
#[wasm_bindgen]
pub fn verify_closure_manifest(
    expected_root_hex: &str,
    manifest: &[u8],
    packs: &[u8],
    pack_lengths_json: &str,
) -> Result<String, String> {
    cap_bundle(manifest)?;
    let expected = hash_hex(expected_root_hex)?;
    let slices = split_packs(packs, pack_lengths_json)?;
    let report =
        verify::verify_closure_manifest(&expected, manifest, &slices).map_err(|e| e.to_string())?;
    report_to_json(&report)
}

/// Verify a single tree-entry inclusion proof against a tree object id.
///
/// `entry_json` is `{ "name" | "name_hex", "mode", "object_hash" }`.
/// `mode` matches [`crate::tree_encode`]: `blob` / `tree` / `symlink` /
/// `exec`. `object_hash` is 64-char lowercase hex. Returns `Ok(false)`
/// when the proof does not fold to `tree_id_hex`
/// ([`MerkleError::VerificationFailed`]); `Err` on malformed input.
///
/// # Errors
///
/// Malformed hex, JSON, or proof bytes, or any merkle error other than
/// [`MerkleError::VerificationFailed`].
#[wasm_bindgen]
pub fn verify_tree_entry(
    tree_id_hex: &str,
    entry_json: &str,
    position: u32,
    proof: &[u8],
) -> Result<bool, String> {
    let tree_id = hash_hex(tree_id_hex)?;
    let entry = parse_tree_entry(entry_json)?;
    let proof = Proof::decode(proof, 1).map_err(|e| e.to_string())?;
    merkle_bool(merkle::verify_tree_entry(
        &tree_id, &entry, position, &proof,
    ))
}

/// Verify a single chunk inclusion proof against a `ChunkedBlob` id.
///
/// `position` is the BMT position (chunk index + 1). Position 0 is the
/// metadata leaf and is never a valid chunk proof. Returns `Ok(false)`
/// on [`MerkleError::VerificationFailed`]; `Err` on malformed input.
///
/// # Errors
///
/// Malformed hex or proof bytes, or any merkle error other than
/// [`MerkleError::VerificationFailed`].
#[wasm_bindgen]
pub fn verify_chunk(
    chunked_id_hex: &str,
    chunk_id_hex: &str,
    position: u32,
    proof: &[u8],
) -> Result<bool, String> {
    let chunked_id = hash_hex(chunked_id_hex)?;
    let chunk_id = hash_hex(chunk_id_hex)?;
    let proof = Proof::decode(proof, 1).map_err(|e| e.to_string())?;
    merkle_bool(merkle::verify_chunk(
        &chunked_id,
        &chunk_id,
        position,
        &proof,
    ))
}

/// Decode a canonical `ChunkedBlob` object into JSON
/// `{ total_size, chunk_size, chunks: [hex] }`.
///
/// Input is capped at 16 MiB, matching [`crate::chunked_blob_encode`]'s
/// workspace admission limit.
///
/// # Errors
///
/// Oversize input, invalid encoding, or a non-`ChunkedBlob` object.
#[wasm_bindgen]
pub fn chunked_blob_decode(bytes: &[u8]) -> Result<String, String> {
    cap_object(bytes)?;
    let Object::ChunkedBlob(ChunkedBlob {
        total_size,
        chunk_size,
        chunks,
    }) = mkit_core::deserialize(bytes).map_err(|e| format!("deserialize: {e}"))?
    else {
        return Err("object is not a chunked blob".into());
    };
    serde_json::to_string(&serde_json::json!({
        "total_size": total_size,
        "chunk_size": chunk_size,
        "chunks": chunks.iter().map(to_hex).collect::<Vec<_>>(),
    }))
    .map_err(|e| format!("chunked blob JSON: {e}"))
}

/// Bao outboard over the **canonical blob bytes** of `content`.
///
/// `hash_hex` equals the blob object id (`object_id(blob_encode(content).bytes)`).
/// Distinct from [`crate::bao_encode`], which hashes raw file bytes.
///
/// # Errors
///
/// Content larger than 16 MiB, or a serialize failure.
#[wasm_bindgen]
pub fn blob_bao_encode(content: &[u8]) -> Result<BaoEncoded, String> {
    let canonical = canonical_blob(content)?;
    let (outboard, h) = bao::encode::outboard(&canonical);
    Ok(BaoEncoded::new(hex::encode(h.as_bytes()), outboard))
}

/// Extract a Bao slice over canonical blob bytes at a **content** offset.
///
/// The +10 shift onto the canonical blob (6-byte prologue + 4-byte
/// length) happens inside. Distinct from [`crate::bao_slice`].
///
/// # Errors
///
/// Oversize content, serialize failure, or a slice-extract error.
#[wasm_bindgen]
pub fn blob_bao_slice(
    outboard: &[u8],
    content: &[u8],
    content_offset: u32,
    len: u32,
) -> Result<Box<[u8]>, String> {
    let canonical = canonical_blob(content)?;
    let bao_offset = u64::from(content_offset).saturating_add(10);
    let mut extractor = bao::encode::SliceExtractor::new_outboard(
        std::io::Cursor::new(canonical),
        std::io::Cursor::new(outboard),
        bao_offset,
        u64::from(len),
    );
    let mut out = Vec::new();
    extractor
        .read_to_end(&mut out)
        .map_err(|e| format!("slice extract: {e}"))?;
    Ok(out.into_boxed_slice())
}

/// Verify a Bao slice against a blob id at a **content** offset.
///
/// Delegates to [`mkit_core::verify::verify_blob_slice`]. Tamper returns
/// `{ ok: false, error }` rather than throwing, matching [`crate::bao_verify_slice`].
///
/// # Errors
///
/// Malformed `blob_id_hex`.
#[wasm_bindgen]
pub fn blob_bao_verify_slice(
    blob_id_hex: &str,
    slice: &[u8],
    content_offset: u32,
    len: u32,
) -> Result<BaoVerify, String> {
    let blob_id = hash_hex(blob_id_hex)?;
    match verify::verify_blob_slice(&blob_id, u64::from(content_offset), u64::from(len), slice) {
        Ok(bytes) => Ok(BaoVerify::ok_bytes(bytes)),
        Err(e) => Ok(BaoVerify::fail(e.to_string())),
    }
}

/// Wrap a BMT inner root with the mkit type domain, producing the object id.
///
/// `kind` is `"tree"` or `"chunked_blob"`. For a commonware BMT verifier
/// that checked the inner root, this is the remaining step before
/// comparing to an mkit id.
///
/// # Errors
///
/// Unknown `kind` or malformed hex.
#[wasm_bindgen]
pub fn wrap_object_id(kind: &str, inner_root_hex: &str) -> Result<String, String> {
    let kind = match kind {
        "tree" => ObjectKind::Tree,
        "chunked_blob" => ObjectKind::ChunkedBlob,
        other => return Err(format!("unknown object kind `{other}`")),
    };
    let inner = hash_hex(inner_root_hex)?;
    Ok(to_hex(&merkle::wrap_id(kind, &inner)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use mkit_core::object::{Tree, TreeEntry};

    #[test]
    fn chunked_blob_decode_round_trip() {
        let cb = ChunkedBlob {
            total_size: 3,
            chunk_size: 0,
            chunks: vec![[1u8; 32]],
        };
        let bytes = serialize(&Object::ChunkedBlob(cb)).unwrap();
        let json: serde_json::Value =
            serde_json::from_str(&chunked_blob_decode(&bytes).unwrap()).unwrap();
        assert_eq!(json["total_size"], 3);
        assert_eq!(json["chunk_size"], 0);
        assert_eq!(json["chunks"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn closure_input_cap_is_independent_of_bundle_cap() {
        // A single "pack" bigger than the old (bundle) cap but under the
        // closure cap must not be rejected by the size check — `split_packs`
        // only slices by the declared lengths, so this succeeds (whether the
        // resulting bytes form a real pack is checked later, by
        // `verify_closure_packs`).
        let over_bundle_cap = MAX_BUNDLE_BYTES + 1;
        let packs = vec![0u8; over_bundle_cap];
        let lengths = format!("[{over_bundle_cap}]");
        let slices = split_packs(&packs, &lengths).unwrap();
        assert_eq!(slices, vec![packs.as_slice()]);
    }

    #[test]
    fn closure_input_cap_still_rejects_oversize_packs() {
        let lengths = format!("[{}]", MAX_CLOSURE_INPUT_BYTES + 1);
        let err = split_packs(&[], &lengths).unwrap_err();
        assert!(err.contains("byte cap"), "got: {err}");
    }

    #[test]
    fn wrap_object_id_matches_compute_tree_id() {
        let tree = Tree {
            entries: vec![TreeEntry {
                name: b"a.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: [0x11; 32],
            }],
        };
        let inner = merkle::tree_inner_root(&tree);
        let id = merkle::compute_tree_id(&tree);
        assert_eq!(
            wrap_object_id("tree", &to_hex(&inner)).unwrap(),
            to_hex(&id)
        );
    }
}
