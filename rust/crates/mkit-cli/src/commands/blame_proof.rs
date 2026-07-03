//! JCS-canonical JSON codec for the blame-proof predicate (SPEC-BLAME-PROOF
//! v1, §6). This is the CLI-layer half of issue #495's PR C: `mkit-core`
//! (`ops::blame::proof`) defines the typed [`BlameProofPredicate`] but has no
//! `serde` dependency (see that module's docs), so the JCS emission/parsing
//! lives here — the same layering every other mkit predicate uses (compare
//! `commands::git_import`'s hand-built `gitCommit`/`refName`/`remoteUrl`
//! predicate, or `commands::self_update`'s `jcs::Value` builder for
//! `release/v1`). This module is that same pattern, just for a predicate
//! with enough nested structure to warrant a dedicated file.
//!
//! Field names, casing, encodings, and JCS member order all follow
//! `docs/SPEC-BLAME-PROOF.md` §6 exactly: camelCase keys, lowercase hex64 for
//! every commit-identity/tree/blob hash, base64 (standard alphabet) for the
//! commit message bytes, hex for the two arbitrary-length byte fields
//! (`commitHeader.author.bytes`, `treePath[].proof`), dense 1-based
//! `attributions` pairs, and `ignoreRevs` sorted ascending (already sorted by
//! [`BlameOptionsRecord::from_opts`] on the build side; `decode_predicate`
//! does not re-sort — an unsorted `ignoreRevs` from an untrusted encoder is
//! preserved as-is since it doesn't affect [`verify_blame_proof`]'s checks).
//!
//! [`encode_predicate`] / [`decode_predicate`] round-trip losslessly for
//! every field — see the unit tests at the bottom of this file.
//!
//! [`verify_blame_proof`]: mkit_core::ops::blame::proof::verify_blame_proof

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::Value as Json;

use mkit_attest::jcs::{self, Member, Value};
use mkit_core::hash::{self, Hash};
use mkit_core::object::{EntryMode, Identity, IdentityKind};
use mkit_core::ops::blame::proof::{
    BlameOptionsRecord, BlameProofPredicate, ChunkLayout, CommitHeader, CopyRecord, MoveRecord,
    OriginHeader, TreePathEntry,
};

/// Predicate type URI (SPEC-BLAME-PROOF §3, D2). Deliberately the
/// `github.com/officialunofficial/mkit` convention every other in-tree
/// predicate uses (`git-bridge/v1`, `git-import/v1`, `release/v1`) — NOT
/// issue #495's initial `https://mkit.dev/...` sketch, which the spec
/// doc's §3 explicitly overrides.
pub const BLAME_PROOF_PREDICATE_TYPE: &str =
    "https://github.com/officialunofficial/mkit/spec/predicate/blame-proof/v1";

/// Errors from [`encode_predicate`] / [`decode_predicate`].
#[derive(Debug, thiserror::Error)]
pub enum PredicateCodecError {
    #[error("encode: {0}")]
    Jcs(#[from] mkit_attest::Error),
    #[error("encode: treePath entryName is not valid UTF-8")]
    NonUtf8EntryName,
    #[error("decode: predicate is not a JSON object")]
    NotAnObject,
    #[error("decode: malformed JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("decode: missing field `{0}`")]
    MissingField(&'static str),
    #[error("decode: field `{0}` has the wrong type")]
    WrongType(&'static str),
    #[error("decode: field `{0}` is not valid hex64")]
    BadHash(&'static str),
    #[error("decode: field `{0}` is not valid hex")]
    BadHex(&'static str),
    #[error("decode: field `{0}` is not valid base64")]
    BadBase64(&'static str),
    #[error("decode: unknown entryMode {0}")]
    BadEntryMode(u64),
    #[error("decode: unknown identity kind {0}")]
    BadIdentityKind(u64),
    #[error("decode: numeric field `{0}` out of range")]
    OutOfRange(&'static str),
}

type CodecResult<T> = Result<T, PredicateCodecError>;

// ===========================================================================
// Encode: typed -> JCS-canonical JSON bytes
// ===========================================================================

/// Encode a [`BlameProofPredicate`] to JCS-canonical JSON per
/// `docs/SPEC-BLAME-PROOF.md` §6. The result is a JSON *object* — the shape
/// `mkit_attest::statement::Statement::predicate_jcs` expects verbatim.
///
/// # Errors
/// [`PredicateCodecError::NonUtf8EntryName`] if a `treePath` entry's name
/// isn't valid UTF-8 (SPEC-BLAME-PROOF §6.1 requires `path`/`entryName` to be
/// UTF-8 strings); [`PredicateCodecError::Jcs`] if the assembled value
/// somehow fails JCS's sorted-keys invariant (defence in depth — every
/// object below is built pre-sorted by construction).
pub fn encode_predicate(p: &BlameProofPredicate) -> CodecResult<String> {
    let attributions = Value::Array(
        p.attributions
            .iter()
            .map(|(n, h)| Value::Array(vec![Value::Uint(u64::from(*n)), Value::String(hex(h))]))
            .collect(),
    );

    let tree_path = p
        .tree_path
        .iter()
        .map(encode_tree_path_entry)
        .collect::<CodecResult<Vec<_>>>()?;

    let origins: Vec<Value> = p.origins.iter().map(encode_origin).collect();

    let value = Value::Object(vec![
        Member::new("attributions", attributions),
        Member::new("blameOptions", encode_blame_options(&p.blame_options)),
        Member::new("blob", Value::String(hex(&p.blob))),
        Member::new("chunkLayout", encode_chunk_layout(p.chunk_layout.as_ref())),
        Member::new("commit", Value::String(hex(&p.commit))),
        Member::new("commitHeader", encode_commit_header(&p.commit_header)),
        Member::new("origins", Value::Array(origins)),
        Member::new("path", Value::String(p.path.clone())),
        Member::new("treePath", Value::Array(tree_path)),
        Member::new("v", Value::Uint(u64::from(p.v))),
    ]);

    Ok(jcs::encode(&value)?)
}

fn encode_chunk_layout(cl: Option<&ChunkLayout>) -> Value {
    match cl {
        None => Value::Null,
        Some(cl) => Value::Object(vec![
            Member::new("chunkSize", Value::Uint(u64::from(cl.chunk_size))),
            Member::new("totalSize", Value::Uint(cl.total_size)),
        ]),
    }
}

fn encode_blame_options(o: &BlameOptionsRecord) -> Value {
    let copies = match &o.copies {
        None => Value::Null,
        Some(CopyRecord { level, threshold }) => Value::Object(vec![
            Member::new("level", Value::Uint(u64::from(*level))),
            Member::new("threshold", Value::Uint(u64::from(*threshold))),
        ]),
    };
    let moves = match &o.moves {
        None => Value::Null,
        Some(MoveRecord { threshold }) => Value::Object(vec![Member::new(
            "threshold",
            Value::Uint(u64::from(*threshold)),
        )]),
    };
    let ignore_revs = Value::Array(
        o.ignore_revs
            .iter()
            .map(|h| Value::String(hex(h)))
            .collect(),
    );
    Value::Object(vec![
        Member::new("copies", copies),
        Member::new("firstParent", Value::Bool(o.first_parent)),
        Member::new("ignoreRevPrecise", Value::Bool(o.ignore_rev_precise)),
        Member::new("ignoreRevs", ignore_revs),
        Member::new("ignoreWhitespace", Value::Bool(o.ignore_whitespace)),
        Member::new("moves", moves),
    ])
}

fn encode_identity(id: &Identity) -> Value {
    Value::Object(vec![
        Member::new("bytes", Value::String(hash::to_hex_bytes(&id.bytes))),
        Member::new("kind", Value::Uint(u64::from(id.kind as u8))),
    ])
}

fn encode_commit_header(h: &CommitHeader) -> Value {
    let parents = Value::Array(h.parents.iter().map(|p| Value::String(hex(p))).collect());
    Value::Object(vec![
        Member::new("author", encode_identity(&h.author)),
        Member::new("message", Value::String(B64.encode(&h.message))),
        Member::new("parents", parents),
        Member::new("signer", Value::String(hex(&h.signer))),
        Member::new("timestamp", Value::Uint(h.timestamp)),
        Member::new("tree", Value::String(hex(&h.tree))),
    ])
}

fn encode_origin(o: &OriginHeader) -> Value {
    Value::Object(vec![
        Member::new("commit", Value::String(hex(&o.commit))),
        Member::new("header", encode_commit_header(&o.header)),
    ])
}

fn encode_tree_path_entry(e: &TreePathEntry) -> CodecResult<Value> {
    let entry_name = String::from_utf8(e.entry_name.clone())
        .map_err(|_| PredicateCodecError::NonUtf8EntryName)?;
    Ok(Value::Object(vec![
        Member::new("childId", Value::String(hex(&e.child_id))),
        Member::new("entryMode", Value::Uint(u64::from(e.entry_mode as u8))),
        Member::new("entryName", Value::String(entry_name)),
        Member::new("innerRoot", Value::String(hex(&e.inner_root))),
        Member::new("position", Value::Uint(u64::from(e.position))),
        Member::new("proof", Value::String(hash::to_hex_bytes(&e.proof))),
    ]))
}

fn hex(h: &Hash) -> String {
    hash::to_hex(h)
}

// ===========================================================================
// Decode: JSON bytes -> typed
// ===========================================================================

/// Parse a blame-proof predicate body (JCS-canonical JSON, as emitted by
/// [`encode_predicate`]) back into a [`BlameProofPredicate`].
///
/// A relaxed `serde_json` parser is used here (we don't need to
/// re-canonicalise on the read side — same convention as
/// `mkit_attest::verify::extract_primary_commit_hash`), but every field is
/// validated against its §6.1 type/encoding before being accepted: hashes
/// must be exactly 64 hex chars, `message`/`author.bytes`/`proof` must
/// decode cleanly, `entryMode`/identity `kind` must be one of the spec's
/// pinned discriminants, and every numeric field must fit its declared
/// width.
///
/// # Errors
/// See [`PredicateCodecError`]'s variants — each failure names the specific
/// field and reason.
pub fn decode_predicate(bytes: &[u8]) -> CodecResult<BlameProofPredicate> {
    let root: Json = serde_json::from_slice(bytes)?;
    let Json::Object(_) = &root else {
        return Err(PredicateCodecError::NotAnObject);
    };

    let v = u32_field(&root, "v")?;
    let commit = hash_field(&root, "commit")?;
    let path = str_field(&root, "path")?.to_owned();
    let blob = hash_field(&root, "blob")?;
    let chunk_layout = decode_chunk_layout(field(&root, "chunkLayout")?)?;
    let attributions = decode_attributions(field(&root, "attributions")?)?;
    let blame_options = decode_blame_options(field(&root, "blameOptions")?)?;
    let tree_path = decode_tree_path(field(&root, "treePath")?)?;
    let commit_header = decode_commit_header(field(&root, "commitHeader")?)?;
    let origins = decode_origins(field(&root, "origins")?)?;

    Ok(BlameProofPredicate {
        v,
        commit,
        path,
        blob,
        chunk_layout,
        attributions,
        blame_options,
        tree_path,
        commit_header,
        origins,
    })
}

fn field<'a>(v: &'a Json, key: &'static str) -> CodecResult<&'a Json> {
    v.get(key).ok_or(PredicateCodecError::MissingField(key))
}

fn str_field<'a>(v: &'a Json, key: &'static str) -> CodecResult<&'a str> {
    field(v, key)?
        .as_str()
        .ok_or(PredicateCodecError::WrongType(key))
}

fn bool_field(v: &Json, key: &'static str) -> CodecResult<bool> {
    field(v, key)?
        .as_bool()
        .ok_or(PredicateCodecError::WrongType(key))
}

fn u64_field(v: &Json, key: &'static str) -> CodecResult<u64> {
    field(v, key)?
        .as_u64()
        .ok_or(PredicateCodecError::WrongType(key))
}

fn u32_field(v: &Json, key: &'static str) -> CodecResult<u32> {
    u32::try_from(u64_field(v, key)?).map_err(|_| PredicateCodecError::OutOfRange(key))
}

fn u8_field(v: &Json, key: &'static str) -> CodecResult<u8> {
    u8::try_from(u64_field(v, key)?).map_err(|_| PredicateCodecError::OutOfRange(key))
}

fn hash_field(v: &Json, key: &'static str) -> CodecResult<Hash> {
    hash::from_hex(str_field(v, key)?).map_err(|_| PredicateCodecError::BadHash(key))
}

fn array_field<'a>(v: &'a Json, key: &'static str) -> CodecResult<&'a Vec<Json>> {
    field(v, key)?
        .as_array()
        .ok_or(PredicateCodecError::WrongType(key))
}

/// Decode arbitrary-length hex (not a fixed-width [`Hash`]) — used for
/// `commitHeader.author.bytes` and `treePath[].proof`.
fn hex_bytes(s: &str, field_name: &'static str) -> CodecResult<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(PredicateCodecError::BadHex(field_name));
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        let hi = nibble(b[i]).ok_or(PredicateCodecError::BadHex(field_name))?;
        let lo = nibble(b[i + 1]).ok_or(PredicateCodecError::BadHex(field_name))?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn nibble(c: u8) -> Option<u8> {
    Some(match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => 10 + c - b'a',
        b'A'..=b'F' => 10 + c - b'A',
        _ => return None,
    })
}

fn entry_mode_from_u8(b: u8) -> Option<EntryMode> {
    Some(match b {
        0x01 => EntryMode::Blob,
        0x02 => EntryMode::Tree,
        0x03 => EntryMode::Symlink,
        0x04 => EntryMode::Executable,
        _ => return None,
    })
}

fn identity_kind_from_u8(b: u8) -> Option<IdentityKind> {
    Some(match b {
        0x01 => IdentityKind::Ed25519,
        0x02 => IdentityKind::DidKey,
        0x03 => IdentityKind::Opaque,
        _ => return None,
    })
}

fn decode_chunk_layout(v: &Json) -> CodecResult<Option<ChunkLayout>> {
    if v.is_null() {
        return Ok(None);
    }
    let chunk_size = u32_field(v, "chunkSize")?;
    let total_size = u64_field(v, "totalSize")?;
    Ok(Some(ChunkLayout {
        total_size,
        chunk_size,
    }))
}

fn decode_attributions(v: &Json) -> CodecResult<Vec<(u32, Hash)>> {
    let arr = v
        .as_array()
        .ok_or(PredicateCodecError::WrongType("attributions"))?;
    let mut out = Vec::with_capacity(arr.len());
    for entry in arr {
        let pair = entry
            .as_array()
            .ok_or(PredicateCodecError::WrongType("attributions[]"))?;
        if pair.len() != 2 {
            return Err(PredicateCodecError::WrongType("attributions[]"));
        }
        let line_num = u32::try_from(
            pair[0]
                .as_u64()
                .ok_or(PredicateCodecError::WrongType("attributions[][0]"))?,
        )
        .map_err(|_| PredicateCodecError::OutOfRange("attributions[][0]"))?;
        let origin_hex = pair[1]
            .as_str()
            .ok_or(PredicateCodecError::WrongType("attributions[][1]"))?;
        let origin = hash::from_hex(origin_hex)
            .map_err(|_| PredicateCodecError::BadHash("attributions[][1]"))?;
        out.push((line_num, origin));
    }
    Ok(out)
}

fn decode_blame_options(v: &Json) -> CodecResult<BlameOptionsRecord> {
    let copies = match field(v, "copies")? {
        Json::Null => None,
        obj => Some(CopyRecord {
            level: u8_field(obj, "level")?,
            threshold: u32_field(obj, "threshold")?,
        }),
    };
    let moves = match field(v, "moves")? {
        Json::Null => None,
        obj => Some(MoveRecord {
            threshold: u32_field(obj, "threshold")?,
        }),
    };
    let ignore_revs = array_field(v, "ignoreRevs")?
        .iter()
        .map(|j| {
            j.as_str()
                .ok_or(PredicateCodecError::WrongType("ignoreRevs[]"))
                .and_then(|s| {
                    hash::from_hex(s).map_err(|_| PredicateCodecError::BadHash("ignoreRevs[]"))
                })
        })
        .collect::<CodecResult<Vec<_>>>()?;
    Ok(BlameOptionsRecord {
        ignore_whitespace: bool_field(v, "ignoreWhitespace")?,
        moves,
        copies,
        ignore_revs,
        ignore_rev_precise: bool_field(v, "ignoreRevPrecise")?,
        first_parent: bool_field(v, "firstParent")?,
    })
}

fn decode_identity(v: &Json) -> CodecResult<Identity> {
    let kind_raw = u8_field(v, "kind")?;
    let kind = identity_kind_from_u8(kind_raw)
        .ok_or(PredicateCodecError::BadIdentityKind(u64::from(kind_raw)))?;
    let bytes = hex_bytes(str_field(v, "bytes")?, "commitHeader.author.bytes")?;
    Ok(Identity { kind, bytes })
}

fn decode_commit_header(v: &Json) -> CodecResult<CommitHeader> {
    let tree = hash_field(v, "tree")?;
    let parents = array_field(v, "parents")?
        .iter()
        .map(|j| {
            j.as_str()
                .ok_or(PredicateCodecError::WrongType("parents[]"))
                .and_then(|s| {
                    hash::from_hex(s).map_err(|_| PredicateCodecError::BadHash("parents[]"))
                })
        })
        .collect::<CodecResult<Vec<_>>>()?;
    let author = decode_identity(field(v, "author")?)?;
    let message_b64 = str_field(v, "message")?;
    let message = B64
        .decode(message_b64)
        .map_err(|_| PredicateCodecError::BadBase64("message"))?;
    let signer = hash_field(v, "signer")?;
    let timestamp = u64_field(v, "timestamp")?;
    Ok(CommitHeader {
        tree,
        parents,
        author,
        message,
        timestamp,
        signer,
    })
}

fn decode_origins(v: &Json) -> CodecResult<Vec<OriginHeader>> {
    let arr = v
        .as_array()
        .ok_or(PredicateCodecError::WrongType("origins"))?;
    arr.iter()
        .map(|o| {
            let commit = hash_field(o, "commit")?;
            let header = decode_commit_header(field(o, "header")?)?;
            Ok(OriginHeader { commit, header })
        })
        .collect()
}

fn decode_tree_path(v: &Json) -> CodecResult<Vec<TreePathEntry>> {
    let arr = v
        .as_array()
        .ok_or(PredicateCodecError::WrongType("treePath"))?;
    arr.iter()
        .map(|e| {
            let child_id = hash_field(e, "childId")?;
            let mode_raw = u8_field(e, "entryMode")?;
            let entry_mode = entry_mode_from_u8(mode_raw)
                .ok_or(PredicateCodecError::BadEntryMode(u64::from(mode_raw)))?;
            let entry_name = str_field(e, "entryName")?.as_bytes().to_vec();
            let inner_root = hash_field(e, "innerRoot")?;
            let position = u32_field(e, "position")?;
            let proof = hex_bytes(str_field(e, "proof")?, "treePath[].proof")?;
            Ok(TreePathEntry {
                entry_name,
                entry_mode,
                child_id,
                inner_root,
                position,
                proof,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_core::ops::blame::proof::BLAME_PROOF_VERSION;

    fn sample_predicate() -> BlameProofPredicate {
        let h = |b: u8| -> Hash { [b; 32] };
        BlameProofPredicate {
            v: BLAME_PROOF_VERSION,
            commit: h(0xC1),
            path: "src/lib.rs".to_owned(),
            blob: h(0xB1),
            chunk_layout: Some(ChunkLayout {
                total_size: 4096,
                chunk_size: 0,
            }),
            attributions: vec![(1, h(0xA1)), (2, h(0xA2)), (3, h(0xA1))],
            blame_options: BlameOptionsRecord {
                ignore_whitespace: true,
                moves: Some(MoveRecord { threshold: 20 }),
                copies: Some(CopyRecord {
                    level: 2,
                    threshold: 40,
                }),
                ignore_revs: vec![h(0x01), h(0x02)],
                ignore_rev_precise: true,
                first_parent: false,
            },
            tree_path: vec![
                TreePathEntry {
                    entry_name: b"lib.rs".to_vec(),
                    entry_mode: EntryMode::Blob,
                    child_id: h(0xB1),
                    inner_root: h(0xD1),
                    position: 3,
                    proof: vec![1, 2, 3, 4, 5],
                },
                TreePathEntry {
                    entry_name: b"src".to_vec(),
                    entry_mode: EntryMode::Tree,
                    child_id: h(0xD2),
                    inner_root: h(0xD3),
                    position: 0,
                    proof: vec![9, 8, 7],
                },
            ],
            commit_header: CommitHeader {
                tree: h(0xE1),
                parents: vec![h(0xF1), h(0xF2)],
                author: Identity {
                    kind: IdentityKind::Ed25519,
                    bytes: vec![0xAA; 32],
                },
                message: b"a commit message\nwith a newline".to_vec(),
                timestamp: 1_751_500_000,
                signer: h(0xF3),
            },
            origins: vec![OriginHeader {
                commit: h(0xA1),
                header: CommitHeader {
                    tree: h(0xE2),
                    parents: vec![],
                    author: Identity {
                        kind: IdentityKind::Opaque,
                        bytes: vec![1, 2, 3],
                    },
                    message: Vec::new(),
                    timestamp: 100,
                    signer: h(0xF4),
                },
            }],
        }
    }

    #[test]
    fn round_trip_identity() {
        let p = sample_predicate();
        let encoded = encode_predicate(&p).expect("encode");
        let decoded = decode_predicate(encoded.as_bytes()).expect("decode");
        assert_eq!(p, decoded);
    }

    #[test]
    fn round_trip_with_no_chunk_layout_and_empty_origins() {
        let mut p = sample_predicate();
        p.chunk_layout = None;
        p.origins.clear();
        p.blame_options.moves = None;
        p.blame_options.copies = None;
        p.blame_options.ignore_revs.clear();
        let encoded = encode_predicate(&p).expect("encode");
        let decoded = decode_predicate(encoded.as_bytes()).expect("decode");
        assert_eq!(p, decoded);
    }

    #[test]
    fn encode_is_jcs_canonical_and_member_ordering_is_alphabetical() {
        let p = sample_predicate();
        let encoded = encode_predicate(&p).expect("encode");
        // Top-level member order per SPEC-BLAME-PROOF.md §6 (alphabetical).
        let attributions_pos = encoded.find("\"attributions\"").unwrap();
        let blame_options_pos = encoded.find("\"blameOptions\"").unwrap();
        let blob_pos = encoded.find("\"blob\"").unwrap();
        let chunk_layout_pos = encoded.find("\"chunkLayout\"").unwrap();
        let commit_pos = encoded.find("\"commit\"").unwrap();
        let commit_header_pos = encoded.find("\"commitHeader\"").unwrap();
        let origins_pos = encoded.find("\"origins\"").unwrap();
        let path_pos = encoded.find("\"path\"").unwrap();
        let tree_path_pos = encoded.find("\"treePath\"").unwrap();
        let v_pos = encoded.rfind("\"v\"").unwrap();
        assert!(attributions_pos < blame_options_pos);
        assert!(blame_options_pos < blob_pos);
        assert!(blob_pos < chunk_layout_pos);
        assert!(chunk_layout_pos < commit_pos);
        assert!(commit_pos < commit_header_pos);
        assert!(commit_header_pos < origins_pos);
        assert!(origins_pos < path_pos);
        assert!(path_pos < tree_path_pos);
        assert!(tree_path_pos < v_pos);
        // No insignificant whitespace (JCS).
        assert!(!encoded.contains(" \"") && !encoded.contains(": "));
    }

    #[test]
    fn decode_rejects_non_object() {
        let err = decode_predicate(b"[1,2,3]").unwrap_err();
        assert!(matches!(err, PredicateCodecError::NotAnObject));
    }

    #[test]
    fn decode_rejects_malformed_json() {
        let err = decode_predicate(b"{not json").unwrap_err();
        assert!(matches!(err, PredicateCodecError::Json(_)));
    }

    #[test]
    fn decode_rejects_missing_field() {
        let p = sample_predicate();
        let encoded = encode_predicate(&p).unwrap();
        let mut json: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        json.as_object_mut().unwrap().remove("commit");
        let err = decode_predicate(json.to_string().as_bytes()).unwrap_err();
        assert!(matches!(err, PredicateCodecError::MissingField("commit")));
    }

    #[test]
    fn decode_rejects_bad_hash_length() {
        let p = sample_predicate();
        let encoded = encode_predicate(&p).unwrap();
        let mut json: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        json["commit"] = serde_json::Value::String("deadbeef".to_owned());
        let err = decode_predicate(json.to_string().as_bytes()).unwrap_err();
        assert!(matches!(err, PredicateCodecError::BadHash("commit")));
    }

    #[test]
    fn decode_rejects_unknown_entry_mode() {
        let p = sample_predicate();
        let encoded = encode_predicate(&p).unwrap();
        let mut json: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        json["treePath"][0]["entryMode"] = serde_json::Value::from(9);
        let err = decode_predicate(json.to_string().as_bytes()).unwrap_err();
        assert!(matches!(err, PredicateCodecError::BadEntryMode(9)));
    }

    #[test]
    fn predicate_type_matches_spec_uri() {
        assert_eq!(
            BLAME_PROOF_PREDICATE_TYPE,
            "https://github.com/officialunofficial/mkit/spec/predicate/blame-proof/v1"
        );
    }
}
