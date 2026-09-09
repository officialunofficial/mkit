//! Object byte-format primitives: blob / tree / commit / remix encode +
//! decode and the object-kind probe, plus the view/result structs the
//! decoders return. Thin wrappers over `mkit-core`'s serialize path.

use wasm_bindgen::prelude::*;

use mkit_core::hash::to_hex;
use mkit_core::object::{Blob, Commit, EntryMode, Identity, Object, Remix, Tree, TreeEntry};
use mkit_core::sign::{
    COMMIT_DOMAIN, KeyPair, REMIX_DOMAIN, Signature, commit_signing_bytes, remix_signing_bytes,
};

use zeroize::Zeroizing;

use crate::common::{
    CommitCore, encode_object, js_err, js_vec_count, js_vec_get, parse_hash_hex,
    parse_json_triples, parse_parent_list, parse_remix_sources,
};

// Edge/browser workspace admission limit, not an on-disk format limit.
const MAX_WORKSPACE_OBJECT_BYTES: usize = 16 * 1024 * 1024;

fn decode_workspace_object(bytes: &[u8]) -> Result<Object, String> {
    if bytes.len() > MAX_WORKSPACE_OBJECT_BYTES {
        return Err("workspace object exceeds 16 MiB".into());
    }
    mkit_core::deserialize(bytes).map_err(|e| format!("deserialize: {e}"))
}

/// Return a canonical object's 64-hex content id, including Merkle ids.
///
/// This checks the encoding, not signatures or referenced child objects.
/// Callers must compare the result with the independently requested id.
///
/// # Errors
/// Invalid object encoding or input larger than 16 MiB.
#[wasm_bindgen]
pub fn object_id(bytes: &[u8]) -> Result<String, JsValue> {
    let object = decode_workspace_object(bytes).map_err(js_err)?;
    Ok(to_hex(&mkit_core::object::id_from_object(&object, bytes)))
}

/// Decode a canonical blob into its uninterpreted file bytes.
///
/// # Errors
/// Invalid encoding, a non-blob object, or input larger than 16 MiB.
#[wasm_bindgen]
pub fn blob_decode(bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    decode_blob(bytes).map_err(js_err)
}

fn decode_blob(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let Object::Blob(blob) = decode_workspace_object(bytes)? else {
        return Err("object is not a blob".into());
    };
    Ok(blob.data)
}

/// Decode a canonical tree into JSON `[name, mode, hash_hex]` triples.
/// Modes match [`tree_encode`]: `blob`, `tree`, `symlink`, and `exec`.
///
/// # Errors
/// Invalid encoding, a non-tree object, input larger than 16 MiB, or a
/// non-UTF-8 entry name (which cannot round-trip through the JSON API).
#[wasm_bindgen]
pub fn tree_decode(bytes: &[u8]) -> Result<String, JsValue> {
    decode_tree(bytes).map_err(js_err)
}

fn decode_tree(bytes: &[u8]) -> Result<String, String> {
    let Object::Tree(tree) = decode_workspace_object(bytes)? else {
        return Err("object is not a tree".into());
    };
    let mut entries = Vec::with_capacity(tree.entries.len());
    for entry in tree.entries {
        let name = String::from_utf8(entry.name)
            .map_err(|_| "tree entry name is not UTF-8".to_string())?;
        let mode = match entry.mode {
            EntryMode::Blob => "blob",
            EntryMode::Tree => "tree",
            EntryMode::Symlink => "symlink",
            EntryMode::Executable => "exec",
        };
        entries.push((name, mode, to_hex(&entry.object_hash)));
    }
    serde_json::to_string(&entries).map_err(|e| format!("entries JSON: {e}"))
}

/// Verify a canonical remix's signature. Returns false for invalid encoding,
/// wrong object kind, signature failure, or input larger than 16 MiB.
#[wasm_bindgen]
#[must_use]
pub fn remix_verify(bytes: &[u8]) -> bool {
    let Ok(Object::Remix(remix)) = decode_workspace_object(bytes) else {
        return false;
    };
    mkit_core::sign::verify_remix(&remix).is_ok()
}

/// Serialize a blob object and return `{ bytes, hash_hex }`.
///
/// The returned `bytes` are the canonical on-disk v1 object bytes
/// (see `docs/specs/SPEC-OBJECTS.md`); `hash_hex` is the object's content id
/// (via `id_from_object`) — for a non-merkelized `Blob`, BLAKE3 of those bytes.
#[wasm_bindgen]
pub fn blob_encode(data: &[u8]) -> Result<EncodedObject, JsValue> {
    let obj = Object::Blob(Blob {
        data: data.to_vec(),
    });
    encode_object(&obj)
}

/// Build a tree object from a JSON array of `[name, mode, hash_hex]`
/// triples and return its serialized bytes + hash. `mode` is one of
/// `"blob" | "tree" | "symlink" | "exec"`.
#[wasm_bindgen]
pub fn tree_encode(entries_json: &str) -> Result<EncodedObject, JsValue> {
    let parsed: Vec<(String, String, String)> =
        parse_json_triples(entries_json).map_err(|e| js_err(format!("entries JSON: {e}")))?;

    let mut entries = Vec::with_capacity(parsed.len());
    for (name, mode, hash_hex) in parsed {
        let mode = match mode.as_str() {
            "blob" => EntryMode::Blob,
            "tree" => EntryMode::Tree,
            "symlink" => EntryMode::Symlink,
            "exec" => EntryMode::Executable,
            other => return Err(js_err(format!("unknown entry mode `{other}`"))),
        };
        let name_bytes = name.into_bytes();
        if !TreeEntry::validate_name(&name_bytes) {
            return Err(js_err("invalid tree entry name"));
        }
        let object_hash = parse_hash_hex(&hash_hex)?;
        entries.push(TreeEntry {
            name: name_bytes,
            mode,
            object_hash,
        });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    let tree = Tree { entries };
    if !tree.is_sorted() {
        return Err(js_err("tree entries must have unique names"));
    }
    encode_object(&Object::Tree(tree))
}

/// Build and sign a commit, returning `{ bytes, hash_hex, signature_hex }`.
///
/// `parent_hex` is a comma-separated list of parent commit hashes (empty
/// string = root commit). `seed_hex` is the 32-byte Ed25519 seed.
#[wasm_bindgen]
pub fn commit_encode_and_sign(
    tree_hash_hex: &str,
    parent_hex: &str,
    message: &str,
    timestamp: u64,
    seed_hex: &str,
) -> Result<EncodedCommit, JsValue> {
    let tree_hash = parse_hash_hex(tree_hash_hex)?;
    let parents = parse_parent_list(parent_hex)?;
    // # Zeroization
    //
    // We cannot scrub the JS-side ArrayBuffer that backed `seed_hex`,
    // but every Rust-side temporary holding the raw seed must zero on
    // drop. `Zeroizing` carries that scrub into the destructor; the
    // `from_seed_zeroizing` constructor avoids the `[u8; 32]: Copy`
    // synthesis that a `*seed` deref would create.
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(parse_hash_hex(seed_hex)?);

    let kp = KeyPair::from_seed_zeroizing(&seed);
    let signer_pub = kp.public.0;
    let author = Identity::ed25519(signer_pub);

    // Start from an empty signature so `commit_signing_bytes` excludes it,
    // then populate after we compute the signature.
    let mut commit = Commit::new_unannotated(
        tree_hash,
        parents,
        author,
        signer_pub,
        message.as_bytes().to_vec(),
        timestamp,
        [0u8; 64],
    );

    let signing_bytes =
        commit_signing_bytes(&commit).map_err(|e| js_err(format!("signing bytes: {e}")))?;
    let sig: Signature = kp.sign(COMMIT_DOMAIN, &signing_bytes);
    commit.signature = sig.0;

    let encoded = encode_object(&Object::Commit(commit))?;
    Ok(EncodedCommit {
        bytes: encoded.bytes,
        hash_hex: encoded.hash_hex,
        signature_hex: hex::encode(sig.0),
    })
}

/// Verify a commit signature, given the raw on-disk commit bytes.
/// Returns `true` on pass, `false` on structural or crypto failure.
#[wasm_bindgen]
#[must_use]
pub fn commit_verify(commit_bytes: &[u8]) -> bool {
    let Ok(obj) = mkit_core::deserialize(commit_bytes) else {
        return false;
    };
    let Object::Commit(c) = obj else { return false };
    mkit_core::sign::verify_commit(&c).is_ok()
}

/// Decode a commit object's display fields from its raw on-disk bytes.
///
/// Deserializes via the same path [`commit_verify`] uses
/// (`mkit_core::deserialize` → [`Object::Commit`]) and exposes the
/// fields the multiplayer log needs to walk + render the room's `main`
/// chain: the [`CommitInfoJs::message`], the parents via
/// [`CommitInfoJs::parent_count`] / [`CommitInfoJs::parent`]
/// (64-hex object ids, parent 0 first), the
/// [`CommitInfoJs::signer_hex`] (the 64-hex Ed25519 signer/author
/// pubkey), the [`CommitInfoJs::timestamp`] (unix seconds), the
/// [`CommitInfoJs::tree_hex`] (64-hex tree object id), and the
/// [`CommitInfoJs::signature_hex`] (128-hex Ed25519 signature) — the
/// last two power the navigable commit-detail view.
///
/// # Errors
/// `commit_bytes` is not a valid serialized object, or it deserializes
/// to a non-`Commit` object.
#[wasm_bindgen]
pub fn commit_decode(bytes: &[u8]) -> Result<CommitInfoJs, JsValue> {
    let obj = mkit_core::deserialize(bytes).map_err(|e| js_err(format!("deserialize: {e}")))?;
    let Object::Commit(c) = obj else {
        return Err(js_err("object is not a commit"));
    };
    let message = String::from_utf8_lossy(&c.message).into_owned();
    let parents = c.parents.iter().map(to_hex).collect();
    Ok(CommitInfoJs {
        core: CommitCore {
            message,
            parents,
            signer_hex: to_hex(&c.signer),
            timestamp: c.timestamp,
            tree_hex: to_hex(&c.tree_hash),
            signature_hex: hex::encode(c.signature),
        },
    })
}

/// Build and sign a remix (fork/derivation), returning
/// `{ bytes, hash_hex, signature_hex }` like [`commit_encode_and_sign`].
///
/// A `Remix` is the first-class fork object: it snapshots a `tree_hash`,
/// names zero or more `parents` (prior remixes/commits in the fork's own
/// history), and — crucially — records one or more `sources`, each a
/// `RemixSource { upstream_id, commit_hash }` pointing at the upstream
/// commit(s) this fork derives from.
///
/// Inputs mirror the commit variant, plus `sources_json`:
/// * `tree_hash_hex` — 64-hex tree object id this remix snapshots.
/// * `parent_hex` — comma-separated parent ids (empty = root remix).
/// * `sources_json` — JSON array of `{ "upstream_id_hex", "commit_hash_hex" }`
///   objects, each 64-hex. The upstream commits being forked/remixed.
/// * `message` / `timestamp` — same as a commit.
/// * `seed_hex` — the 32-byte Ed25519 seed.
///
/// `sources` are sorted here by `(upstream_id, commit_hash)` and checked
/// for duplicates, satisfying the strict-ascending order mkit-core's
/// `read_remix` enforces at decode time (see `Remix::sources_sorted`).
/// At least one source is required — a remix with no source is not a fork.
///
/// # Errors
/// Any hex field is malformed, `sources_json` does not parse, `sources`
/// is empty or contains a duplicate `(upstream_id, commit_hash)` pair, or
/// signing-bytes construction fails.
#[wasm_bindgen]
pub fn remix_encode_and_sign(
    tree_hash_hex: &str,
    parent_hex: &str,
    sources_json: &str,
    message: &str,
    timestamp: u64,
    seed_hex: &str,
) -> Result<EncodedCommit, JsValue> {
    let tree_hash = parse_hash_hex(tree_hash_hex)?;
    let parents = parse_parent_list(parent_hex)?;
    let mut sources = parse_remix_sources(sources_json)?;
    if sources.is_empty() {
        return Err(js_err("a remix must reference at least one source"));
    }
    // Strict-ascending order by (upstream_id, commit_hash) is what
    // `read_remix` enforces at decode time. Sort, then reject duplicates
    // (sort alone would silently accept a repeated pair).
    sources.sort_by(|a, b| {
        a.upstream_id
            .cmp(&b.upstream_id)
            .then(a.commit_hash.cmp(&b.commit_hash))
    });
    if sources
        .windows(2)
        .any(|w| w[0].upstream_id == w[1].upstream_id && w[0].commit_hash == w[1].commit_hash)
    {
        return Err(js_err("duplicate remix source (upstream_id, commit_hash)"));
    }

    // # Zeroization — see `commit_encode_and_sign`.
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(parse_hash_hex(seed_hex)?);
    let kp = KeyPair::from_seed_zeroizing(&seed);
    let signer_pub = kp.public.0;
    let author = Identity::ed25519(signer_pub);

    // Start from an empty signature so `remix_signing_bytes` excludes it,
    // then populate after we compute the signature.
    let mut remix = Remix {
        tree_hash,
        parents,
        sources,
        author,
        signer: signer_pub,
        message: message.as_bytes().to_vec(),
        timestamp,
        signature: [0u8; 64],
    };

    let signing_bytes =
        remix_signing_bytes(&remix).map_err(|e| js_err(format!("signing bytes: {e}")))?;
    let sig: Signature = kp.sign(REMIX_DOMAIN, &signing_bytes);
    remix.signature = sig.0;

    let encoded = encode_object(&Object::Remix(remix))?;
    Ok(EncodedCommit {
        bytes: encoded.bytes,
        hash_hex: encoded.hash_hex,
        signature_hex: hex::encode(sig.0),
    })
}

/// Decode a remix object's display fields from its raw on-disk bytes.
///
/// The remix counterpart of [`commit_decode`]: deserializes via
/// `mkit_core::deserialize` → [`Object::Remix`] and exposes the same
/// commit-shaped fields (`message`, `signer_hex`, `timestamp`,
/// `tree_hex`, `signature_hex`, `parents`) plus the remix-only
/// `sources` — each a `{ upstream_id_hex, commit_hash_hex }`
/// read by `source_count` + the `source(i)` indexed getter. The web
/// browser uses the sources to render the "fork of …" badge whose
/// `commit_hash` links to the upstream commit's detail.
///
/// # Errors
/// `bytes` is not a valid serialized object, or it deserializes to a
/// non-`Remix` object.
#[wasm_bindgen]
pub fn remix_decode(bytes: &[u8]) -> Result<RemixInfoJs, JsValue> {
    let obj = mkit_core::deserialize(bytes).map_err(|e| js_err(format!("deserialize: {e}")))?;
    let Object::Remix(r) = obj else {
        return Err(js_err("object is not a remix"));
    };
    let message = String::from_utf8_lossy(&r.message).into_owned();
    let parents = r.parents.iter().map(to_hex).collect();
    let sources = r
        .sources
        .iter()
        .map(|s| RemixSourceJs {
            upstream_id_hex: to_hex(&s.upstream_id),
            commit_hash_hex: to_hex(&s.commit_hash),
        })
        .collect();
    Ok(RemixInfoJs {
        core: CommitCore {
            message,
            parents,
            signer_hex: to_hex(&r.signer),
            timestamp: r.timestamp,
            tree_hex: to_hex(&r.tree_hash),
            signature_hex: hex::encode(r.signature),
        },
        sources,
    })
}

/// Read the object-type tag from a serialized object's prologue and
/// return its spec short name: `"commit" | "remix" | "tree" | "blob" |
/// "chunked_blob" | "delta" | "tag"`.
///
/// Lets the browser route a fetched object to the right decoder
/// (`commit_decode` vs `remix_decode`) without guessing or trial-decoding.
/// Goes through `mkit_core::deserialize` so the answer reflects a fully
/// well-formed object, then reports `ObjectType::name`.
///
/// # Errors
/// `bytes` is not a valid serialized object (bad prologue / truncated /
/// unknown type tag).
#[wasm_bindgen]
pub fn object_kind(bytes: &[u8]) -> Result<String, JsValue> {
    let obj = mkit_core::deserialize(bytes).map_err(|e| js_err(format!("deserialize: {e}")))?;
    Ok(obj.object_type().name().to_string())
}

// ---------------------------------------------------------------------
// Returned structs (plain JS objects via wasm-bindgen getters)
// ---------------------------------------------------------------------

#[wasm_bindgen]
#[derive(Debug)]
pub struct EncodedObject {
    bytes: Vec<u8>,
    hash_hex: String,
}

impl EncodedObject {
    /// Construct from the serialized bytes + content id. Used by
    /// [`crate::common::encode_object`], which lives in a sibling module and so
    /// cannot reach the private fields directly.
    pub(crate) fn new(bytes: Vec<u8>, hash_hex: String) -> Self {
        Self { bytes, hash_hex }
    }
}

#[wasm_bindgen]
impl EncodedObject {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn bytes(&self) -> Box<[u8]> {
        self.bytes.clone().into_boxed_slice()
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn hash_hex(&self) -> String {
        self.hash_hex.clone()
    }
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct EncodedCommit {
    bytes: Vec<u8>,
    hash_hex: String,
    signature_hex: String,
}

#[wasm_bindgen]
impl EncodedCommit {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn bytes(&self) -> Box<[u8]> {
        self.bytes.clone().into_boxed_slice()
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn hash_hex(&self) -> String {
        self.hash_hex.clone()
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn signature_hex(&self) -> String {
        self.signature_hex.clone()
    }
}

/// Decoded display fields of a commit object — what [`commit_decode`]
/// returns for the multiplayer log to walk + render the room's `main`
/// chain. `parents` are 64-hex object ids (parent 0 first); `signer_hex`
/// is the 64-hex Ed25519 signer/author pubkey; `timestamp` is unix
/// seconds; `tree_hex` is the 64-hex tree object id; `signature_hex` is
/// the 128-hex Ed25519 signature.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct CommitInfoJs {
    core: CommitCore,
}

#[wasm_bindgen]
impl CommitInfoJs {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn message(&self) -> String {
        self.core.message()
    }
    /// Number of parents; pair with [`CommitInfoJs::parent`] to read each
    /// 64-hex id by index, matching the `*_count` + indexed-getter shape
    /// used by the streaming result structs.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn parent_count(&self) -> u32 {
        self.core.parent_count()
    }
    #[wasm_bindgen]
    #[must_use]
    pub fn parent(&self, i: u32) -> Option<String> {
        self.core.parent(i)
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn signer_hex(&self) -> String {
        self.core.signer_hex()
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn timestamp(&self) -> u64 {
        self.core.timestamp()
    }
    /// 64-hex id of the tree this commit snapshots.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn tree_hex(&self) -> String {
        self.core.tree_hex()
    }
    /// 128-hex Ed25519 signature over the commit's signing bytes.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn signature_hex(&self) -> String {
        self.core.signature_hex()
    }
}

/// One remix source: a `{ upstream_id_hex, commit_hash_hex }` pair naming
/// an upstream commit this fork derives from. `upstream_id` is the opaque
/// caller-chosen 32-byte provenance tag (e.g. the room id); `commit_hash`
/// is the 64-hex id of the upstream commit being remixed.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct RemixSourceJs {
    upstream_id_hex: String,
    commit_hash_hex: String,
}

#[wasm_bindgen]
impl RemixSourceJs {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn upstream_id_hex(&self) -> String {
        self.upstream_id_hex.clone()
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn commit_hash_hex(&self) -> String {
        self.commit_hash_hex.clone()
    }
}

/// Decoded display fields of a remix object — the remix counterpart of
/// [`CommitInfoJs`]. Carries the same commit-shaped fields plus the
/// remix-only `sources` (read via `source_count` + the `source(i)`
/// indexed getter), each a [`RemixSourceJs`] naming an upstream commit
/// the fork derives from. `parents` are 64-hex object ids (parent 0
/// first); `signer_hex` is the 64-hex Ed25519 signer pubkey; `timestamp`
/// is unix seconds; `tree_hex` is the 64-hex tree id; `signature_hex` is
/// the 128-hex Ed25519 signature.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct RemixInfoJs {
    core: CommitCore,
    sources: Vec<RemixSourceJs>,
}

#[wasm_bindgen]
impl RemixInfoJs {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn message(&self) -> String {
        self.core.message()
    }
    /// Number of parents; pair with [`RemixInfoJs::parent`] to read each
    /// 64-hex id by index.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn parent_count(&self) -> u32 {
        self.core.parent_count()
    }
    #[wasm_bindgen]
    #[must_use]
    pub fn parent(&self, i: u32) -> Option<String> {
        self.core.parent(i)
    }
    /// Number of sources (upstream commits this fork derives from); pair
    /// with [`RemixInfoJs::source`] to read each `{ upstream_id_hex,
    /// commit_hash_hex }` by index.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn source_count(&self) -> u32 {
        js_vec_count(&self.sources)
    }
    #[wasm_bindgen]
    #[must_use]
    pub fn source(&self, i: u32) -> Option<RemixSourceJs> {
        js_vec_get(&self.sources, i)
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn signer_hex(&self) -> String {
        self.core.signer_hex()
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn timestamp(&self) -> u64 {
        self.core.timestamp()
    }
    /// 64-hex id of the tree this remix snapshots.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn tree_hex(&self) -> String {
        self.core.tree_hex()
    }
    /// 128-hex Ed25519 signature over the remix's signing bytes.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn signature_hex(&self) -> String {
        self.core.signature_hex()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_core::hash::hash;
    use mkit_core::serialize::serialize;

    #[test]
    fn workspace_blob_roundtrip_preserves_binary_bytes_and_id() {
        for data in [b"".as_slice(), &[0, 255, 128, 10, 13]] {
            let encoded = blob_encode(data).unwrap();
            assert_eq!(blob_decode(&encoded.bytes).unwrap(), data);
            assert_eq!(object_id(&encoded.bytes).unwrap(), encoded.hash_hex);
            assert_eq!(encoded.hash_hex, to_hex(&hash(&encoded.bytes)));
        }
    }

    #[test]
    fn workspace_tree_roundtrip_preserves_modes_names_order_and_merkle_id() {
        let entries = serde_json::json!([
            ["a\"quoted", "blob", to_hex(&[1; 32])],
            ["dir", "tree", to_hex(&[2; 32])],
            ["link", "symlink", to_hex(&[3; 32])],
            ["éxec", "exec", to_hex(&[4; 32])]
        ]);
        let encoded = tree_encode(&entries.to_string()).unwrap();
        let decoded = tree_decode(&encoded.bytes).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&decoded).unwrap(),
            entries
        );
        assert_eq!(tree_encode(&decoded).unwrap().bytes, encoded.bytes);
        assert_eq!(object_id(&encoded.bytes).unwrap(), encoded.hash_hex);
        assert_ne!(encoded.hash_hex, to_hex(&hash(&encoded.bytes)));
    }

    // Exercise the fallible Rust paths directly: JsError construction requires
    // a JS runtime, but these are the same paths used by the exported wrappers.
    #[test]
    fn workspace_decoders_reject_wrong_kind_corruption_and_oversize() {
        let blob = blob_encode(b"data").unwrap();
        let tree = tree_encode("[]").unwrap();
        assert!(decode_tree(&blob.bytes).is_err());
        assert!(decode_blob(&tree.bytes).is_err());
        for mut bytes in [blob.bytes, tree.bytes] {
            bytes.pop();
            assert!(decode_workspace_object(&bytes).is_err());
            assert!(decode_blob(&bytes).is_err());
            assert!(decode_tree(&bytes).is_err());
        }
        let oversized = vec![0; MAX_WORKSPACE_OBJECT_BYTES + 1];
        assert_eq!(
            decode_workspace_object(&oversized).unwrap_err(),
            "workspace object exceeds 16 MiB"
        );
    }

    #[test]
    fn workspace_tree_rejects_non_utf8_names_without_substitution() {
        let tree = Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: vec![255],
                mode: EntryMode::Blob,
                object_hash: [1; 32],
            }],
        });
        assert_eq!(
            decode_tree(&serialize(&tree).unwrap()).unwrap_err(),
            "tree entry name is not UTF-8"
        );
    }

    #[test]
    fn remix_verification_rejects_changed_signature_and_wrong_kind() {
        let encoded = remix_encode_and_sign(
            &to_hex(&[1; 32]),
            "",
            &serde_json::json!([{
                "upstream_id_hex": to_hex(&[2; 32]),
                "commit_hash_hex": to_hex(&[3; 32])
            }])
            .to_string(),
            "remix",
            42,
            &to_hex(&[4; 32]),
        )
        .unwrap();
        assert!(remix_verify(&encoded.bytes));
        assert_eq!(object_id(&encoded.bytes).unwrap(), encoded.hash_hex);
        let mut corrupt = encoded.bytes;
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(!remix_verify(&corrupt));
        assert!(!remix_verify(&blob_encode(b"data").unwrap().bytes));
        assert!(!remix_verify(b"invalid"));
    }

    /// `tree_encode` must key a tree by its **BMT root**
    /// (`merkle::compute_tree_id`), matching the id the native store uses — and
    /// must NOT be the pre-merkle flat BLAKE3 of the serialized bytes.
    #[test]
    fn tree_encode_id_matches_native_bmt_root() {
        let h1 = [0x11u8; 32];
        let h2 = [0x22u8; 32];
        let entries_json = format!(
            r#"[["a.txt","blob","{}"],["b.txt","blob","{}"]]"#,
            to_hex(&h1),
            to_hex(&h2)
        );
        let wasm_id = tree_encode(&entries_json).expect("tree encodes").hash_hex();

        let tree = Tree {
            entries: vec![
                TreeEntry {
                    name: b"a.txt".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: h1,
                },
                TreeEntry {
                    name: b"b.txt".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: h2,
                },
            ],
        };
        let native_root = to_hex(&mkit_core::merkle::compute_tree_id(&tree));
        assert_eq!(wasm_id, native_root, "tree_encode must emit the BMT root");

        let flat = to_hex(&hash(&serialize(&Object::Tree(tree)).unwrap()));
        assert_ne!(wasm_id, flat, "tree id regressed to pre-merkle flat BLAKE3");
    }
}
