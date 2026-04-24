//! WASM bindings for the mkit demo site.
//!
//! Thin wrappers over the pure byte-format and crypto paths in
//! `mkit-core` and `mkit-attest`. No filesystem access — the demo runs
//! entirely in the browser.

#![forbid(unsafe_code)]
#![allow(clippy::multiple_crate_versions)]

use wasm_bindgen::prelude::*;

use mkit_attest::envelope::{Envelope, Sig};
use mkit_attest::statement::{Statement, Subject, encode as encode_statement};
use mkit_attest::verify::{Registry, TrustRoot, verify_envelope};
use mkit_attest::{PAYLOAD_TYPE_IN_TOTO, Signer, signer_repo_key::RepoKeySigner};
use mkit_core::hash::{from_hex, hash, to_hex};
use mkit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use mkit_core::serialize::serialize;
use mkit_core::sign::{COMMIT_DOMAIN, KeyPair, PublicKey, Signature, commit_signing_bytes, verify};

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

fn js_err(msg: impl Into<String>) -> JsValue {
    JsError::new(&msg.into()).into()
}

fn parse_hash_hex(hex: &str) -> Result<[u8; 32], JsValue> {
    from_hex(hex).map_err(|_| js_err("expected 64 lowercase hex characters"))
}

fn parse_fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], JsValue> {
    <[u8; N]>::try_from(bytes).map_err(|_| js_err(format!("expected {N} bytes")))
}

// ---------------------------------------------------------------------
// 1. Content-addressing primitives
// ---------------------------------------------------------------------

/// BLAKE3 of arbitrary bytes, as 64-char lowercase hex. This is the
/// object id mkit uses for every stored object.
#[wasm_bindgen]
#[must_use]
pub fn blake3_hex(data: &[u8]) -> String {
    to_hex(&hash(data))
}

/// Serialize a blob object and return `{ bytes, hash_hex }`.
///
/// The returned `bytes` are the canonical on-disk v1 object bytes
/// (see `docs/SPEC-OBJECTS.md`); `hash_hex` is BLAKE3 of those bytes.
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
    let seed = parse_hash_hex(seed_hex)?;

    let kp = KeyPair::from_seed(seed);
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

// ---------------------------------------------------------------------
// 2. Ed25519 keygen + raw sign/verify
// ---------------------------------------------------------------------

/// Derive `{ seed_hex, pubkey_hex }` from a 32-byte seed. Deterministic:
/// the same seed always yields the same public key.
#[wasm_bindgen]
pub fn keypair_from_seed(seed_hex: &str) -> Result<KeyPairJs, JsValue> {
    let seed = parse_hash_hex(seed_hex)?;
    let kp = KeyPair::from_seed(seed);
    Ok(KeyPairJs {
        seed_hex: seed_hex.to_string(),
        pubkey_hex: hex::encode(kp.public.0),
    })
}

/// Generate a fresh Ed25519 keypair from the browser CSPRNG.
#[wasm_bindgen]
pub fn keypair_generate() -> Result<KeyPairJs, JsValue> {
    let kp = KeyPair::generate().map_err(|e| js_err(format!("rng: {e}")))?;
    Ok(KeyPairJs {
        seed_hex: hex::encode(kp.secret.0),
        pubkey_hex: hex::encode(kp.public.0),
    })
}

/// Sign arbitrary bytes under mkit's commit signing domain. Exposed for
/// the signing demo — real mkit commits go through `commit_encode_and_sign`.
#[wasm_bindgen]
pub fn sign_bytes_commit_domain(seed_hex: &str, bytes: &[u8]) -> Result<String, JsValue> {
    let seed = parse_hash_hex(seed_hex)?;
    let kp = KeyPair::from_seed(seed);
    let sig = kp.sign(COMMIT_DOMAIN, bytes);
    Ok(hex::encode(sig.0))
}

/// Verify a signature made by [`sign_bytes_commit_domain`].
#[wasm_bindgen]
#[must_use]
pub fn verify_bytes_commit_domain(pubkey_hex: &str, bytes: &[u8], sig_hex: &str) -> bool {
    let Ok(pk) = parse_hash_hex(pubkey_hex) else {
        return false;
    };
    let Ok(sig_bytes) = hex::decode(sig_hex) else {
        return false;
    };
    let Ok(sig_arr) = parse_fixed::<64>(&sig_bytes) else {
        return false;
    };
    verify(&PublicKey(pk), COMMIT_DOMAIN, bytes, &Signature(sig_arr)).is_ok()
}

// ---------------------------------------------------------------------
// 3. Attestations — in-toto v1 Statement wrapped in a DSSE envelope
// ---------------------------------------------------------------------

/// Build a DSSE-wrapped in-toto v1 attestation over a commit hash.
///
/// * `predicate_type` is a URI like `https://example.com/Review/v1`.
/// * `predicate_jcs` is the predicate body as already-canonical JCS
///   bytes (must start with `{` and end with `}`).
/// * `seed_hex` is a 32-byte Ed25519 seed. The signer is mkit's
///   `RepoKeySigner`: `keyid = "blake3:" || hex(BLAKE3(pubkey))`.
///
/// Returns `{ envelope_json, keyid, attestation_id_hex }`.
#[wasm_bindgen]
pub fn attest_build(
    commit_hash_hex: &str,
    predicate_type: &str,
    predicate_jcs: &[u8],
    seed_hex: &str,
) -> Result<AttestationJs, JsValue> {
    // Validate the commit hash; we don't decode the commit, just the hex.
    let _ = parse_hash_hex(commit_hash_hex)?;
    let seed = parse_hash_hex(seed_hex)?;

    let stmt = Statement {
        subjects: vec![Subject {
            name: Some("commit".to_string()),
            digest_blake3_hex: commit_hash_hex.to_string(),
        }],
        predicate_type: predicate_type.to_string(),
        predicate_jcs,
    };
    let statement_json = encode_statement(&stmt).map_err(|e| js_err(format!("statement: {e}")))?;
    let payload = statement_json.into_bytes();

    let kp = KeyPair::from_seed(seed);
    let mut signer = RepoKeySigner::new(kp);
    let keyid = signer.keyid().map_err(|e| js_err(format!("keyid: {e}")))?;

    // Build PAE, sign it, assemble the envelope.
    let mut env = Envelope {
        payload_type: PAYLOAD_TYPE_IN_TOTO.to_string(),
        payload,
        signatures: Vec::new(),
    };
    let pae = env.pae();
    let sig_bytes = signer
        .sign(&pae)
        .map_err(|e| js_err(format!("sign: {e}")))?;
    env.signatures.push(Sig {
        keyid: keyid.clone(),
        sig: sig_bytes,
    });

    let envelope_json = env.encode().map_err(|e| js_err(format!("envelope: {e}")))?;
    let att_id = env
        .attestation_id()
        .map_err(|e| js_err(format!("attestation_id: {e}")))?;

    Ok(AttestationJs {
        envelope_json,
        keyid,
        attestation_id_hex: to_hex(&att_id),
    })
}

/// Verify a DSSE envelope against a single Ed25519 trust root.
///
/// * `envelope_json` is the canonical DSSE envelope JSON emitted by
///   [`attest_build`] (or mkit's native attestation store).
/// * `pubkey_hex` is the raw 32-byte Ed25519 public key, hex-encoded.
///
/// Returns `true` iff at least one signature in the envelope verifies
/// under the supplied pubkey's `blake3:<hex-of-pubkey>` keyid.
#[wasm_bindgen]
#[must_use]
pub fn attest_verify(envelope_json: &str, pubkey_hex: &str) -> bool {
    let Ok(pk) = parse_hash_hex(pubkey_hex) else {
        return false;
    };

    let mut registry = Registry::new();
    let keyid = format!("blake3:{}", to_hex(&hash(&pk)));
    registry.add(keyid, TrustRoot::Ed25519PubKey(pk));

    match verify_envelope(envelope_json.as_bytes(), &registry) {
        Ok(r) => r.any_verified,
        Err(_) => false,
    }
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

#[wasm_bindgen]
#[derive(Debug)]
pub struct KeyPairJs {
    seed_hex: String,
    pubkey_hex: String,
}

#[wasm_bindgen]
impl KeyPairJs {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn seed_hex(&self) -> String {
        self.seed_hex.clone()
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn pubkey_hex(&self) -> String {
        self.pubkey_hex.clone()
    }
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct AttestationJs {
    envelope_json: String,
    keyid: String,
    attestation_id_hex: String,
}

#[wasm_bindgen]
impl AttestationJs {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn envelope_json(&self) -> String {
        self.envelope_json.clone()
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn keyid(&self) -> String {
        self.keyid.clone()
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn attestation_id_hex(&self) -> String {
        self.attestation_id_hex.clone()
    }
}

// ---------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------

fn encode_object(obj: &Object) -> Result<EncodedObject, JsValue> {
    let bytes = serialize(obj).map_err(|e| js_err(format!("serialize: {e}")))?;
    let hash_hex = to_hex(&hash(&bytes));
    Ok(EncodedObject { bytes, hash_hex })
}

fn parse_parent_list(s: &str) -> Result<Vec<[u8; 32]>, JsValue> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(Vec::new());
    }
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(parse_hash_hex)
        .collect()
}

/// Tiny JSON parser for `[["name","mode","hex"], ...]`. We avoid pulling
/// serde into this crate: the input shape is fixed and we control both
/// sides, so a hand-rolled parser keeps the wasm blob small.
fn parse_json_triples(s: &str) -> Result<Vec<(String, String, String)>, &'static str> {
    let s = s.trim();
    let inner = s
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or("expected top-level JSON array")?;
    let mut out = Vec::new();
    let mut chars = inner.chars().peekable();
    loop {
        skip_ws(&mut chars);
        if chars.peek().is_none() {
            break;
        }
        if *chars.peek().unwrap() != '[' {
            return Err("expected `[` opening a triple");
        }
        chars.next();
        let a = read_string(&mut chars)?;
        expect_comma(&mut chars)?;
        let b = read_string(&mut chars)?;
        expect_comma(&mut chars)?;
        let c = read_string(&mut chars)?;
        skip_ws(&mut chars);
        match chars.next() {
            Some(']') => {}
            _ => return Err("expected `]` closing a triple"),
        }
        out.push((a, b, c));
        skip_ws(&mut chars);
        match chars.peek() {
            Some(',') => {
                chars.next();
            }
            None => break,
            _ => return Err("expected `,` or end of array"),
        }
    }
    Ok(out)
}

fn skip_ws(it: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while let Some(&c) = it.peek() {
        if c.is_whitespace() {
            it.next();
        } else {
            break;
        }
    }
}

fn expect_comma(it: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Result<(), &'static str> {
    skip_ws(it);
    match it.next() {
        Some(',') => Ok(()),
        _ => Err("expected `,`"),
    }
}

fn read_string(it: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Result<String, &'static str> {
    skip_ws(it);
    match it.next() {
        Some('"') => {}
        _ => return Err("expected `\"`"),
    }
    let mut out = String::new();
    loop {
        match it.next() {
            Some('"') => return Ok(out),
            Some('\\') => match it.next() {
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                _ => return Err("unsupported escape"),
            },
            Some(c) => out.push(c),
            None => return Err("unterminated string"),
        }
    }
}
