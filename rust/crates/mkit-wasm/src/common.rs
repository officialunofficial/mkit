//! Shared private helpers used across the wasm submodules.
//!
//! Nothing here is `#[wasm_bindgen]`-exposed — these are the parsing,
//! hex, count/index, and object-encoding utilities the public exports in
//! `objects` / `crypto` / `attest` / `chunking` build on, plus the
//! internal [`CommitCore`] that backs both `CommitInfoJs` and
//! `RemixInfoJs` so their six shared display fields live in one place.

use wasm_bindgen::prelude::*;

use mkit_attest::algorithm::Algorithm;
use mkit_core::hash::from_hex;
use mkit_core::object::{Object, RemixSource, id_from_object};
use mkit_core::serialize::serialize;

use crate::objects::EncodedObject;

/// Upper bound on the JSON input accepted by [`parse_json_triples`].
///
/// The hand-rolled parser is O(n) in input length but performs a string
/// allocation per escaped token, so a hostile caller pasting a giant
/// blob would cause the WASM blob to allocate well beyond what the
/// demo site can recover from. 16 MiB is comfortably larger than any
/// realistic triple list and small enough to keep the tab responsive
/// when an attacker tries to wedge it.
pub(crate) const MAX_JSON_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn js_err(msg: impl Into<String>) -> JsValue {
    JsError::new(&msg.into()).into()
}

pub(crate) fn parse_hash_hex(hex: &str) -> Result<[u8; 32], JsValue> {
    from_hex(hex).map_err(|_| js_err("expected 64 lowercase hex characters"))
}

pub(crate) fn parse_fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], JsValue> {
    <[u8; N]>::try_from(bytes).map_err(|_| js_err(format!("expected {N} bytes")))
}

/// Parse `"ed25519" | "secp256k1" | "p256"` into the attestation-side `Algorithm` tag. These are the only three
/// algorithms the attestation verifier dispatches on today.
pub(crate) fn parse_algo(s: &str) -> Result<Algorithm, JsValue> {
    s.parse::<Algorithm>()
        .map_err(|e| js_err(format!("unknown algorithm: {}", e.0)))
}

/// `len()` of a slice exposed to JS as a `u32`, saturating at `u32::MAX`.
///
/// Single home for the count/index boundary policy shared by every
/// `*_count` getter on the result structs, so the saturation choice
/// lives in one place rather than being re-justified per struct.
pub(crate) fn js_vec_count<T>(xs: &[T]) -> u32 {
    u32::try_from(xs.len()).unwrap_or(u32::MAX)
}

/// Indexed accessor matching [`js_vec_count`]: clones the element at the
/// JS-supplied `u32` index, or `None` when out of range.
pub(crate) fn js_vec_get<T: Clone>(xs: &[T], i: u32) -> Option<T> {
    xs.get(i as usize).cloned()
}

/// The six commit-shaped display fields shared by `CommitInfoJs` and
/// `RemixInfoJs`. Plain struct, NOT wasm-exposed: both view structs embed
/// one and delegate their identically-named getters to it, so the field
/// set + getter bodies live in a single place. The wasm-visible getter
/// names/signatures are unchanged — this only removes the duplication
/// behind them.
#[derive(Debug, Clone)]
pub(crate) struct CommitCore {
    pub message: String,
    pub parents: Vec<String>,
    pub signer_hex: String,
    pub timestamp: u64,
    pub tree_hex: String,
    pub signature_hex: String,
}

impl CommitCore {
    pub(crate) fn message(&self) -> String {
        self.message.clone()
    }
    pub(crate) fn parent_count(&self) -> u32 {
        js_vec_count(&self.parents)
    }
    pub(crate) fn parent(&self, i: u32) -> Option<String> {
        js_vec_get(&self.parents, i)
    }
    pub(crate) fn signer_hex(&self) -> String {
        self.signer_hex.clone()
    }
    pub(crate) fn timestamp(&self) -> u64 {
        self.timestamp
    }
    pub(crate) fn tree_hex(&self) -> String {
        self.tree_hex.clone()
    }
    pub(crate) fn signature_hex(&self) -> String {
        self.signature_hex.clone()
    }
}

pub(crate) fn encode_object(obj: &Object) -> Result<EncodedObject, JsValue> {
    let bytes = serialize(obj).map_err(|e| js_err(format!("serialize: {e}")))?;
    // Canonical content id: the BMT root for merkelized types (Tree /
    // ChunkedBlob), BLAKE3 of the bytes otherwise. Routing through the same
    // `id_from_object` dispatch the native store uses keeps wasm-computed ids
    // equal to the key mkit stores the object under (no flat-hash drift).
    let hash_hex = mkit_core::hash::to_hex(&id_from_object(obj, &bytes));
    Ok(EncodedObject::new(bytes, hash_hex))
}

pub(crate) fn parse_parent_list(s: &str) -> Result<Vec<[u8; 32]>, JsValue> {
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

/// Parse the `sources_json` handed to [`crate::objects::remix_encode_and_sign`]:
/// a JSON array of `{ "upstream_id_hex": <64-hex>, "commit_hash_hex": <64-hex> }`
/// objects. Uses `serde_json` (already a dep) rather than the hand-rolled
/// triple parser, since the shape is an object-array, not a triple-array.
///
/// Each pair's two fields are decoded to 32-byte hashes here so the caller
/// gets ready-to-sort `RemixSource`s; ordering/dedup is the caller's job.
pub(crate) fn parse_remix_sources(s: &str) -> Result<Vec<RemixSource>, JsValue> {
    if s.len() > MAX_JSON_BYTES {
        return Err(js_err("sources JSON exceeds 16 MiB cap"));
    }
    let v: serde_json::Value =
        serde_json::from_str(s).map_err(|e| js_err(format!("sources JSON: {e}")))?;
    let arr = v
        .as_array()
        .ok_or_else(|| js_err("sources JSON must be an array"))?;
    let mut out = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        let obj = item
            .as_object()
            .ok_or_else(|| js_err(format!("source[{i}] must be an object")))?;
        let upstream_hex = obj
            .get("upstream_id_hex")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| js_err(format!("source[{i}].upstream_id_hex must be a string")))?;
        let commit_hex = obj
            .get("commit_hash_hex")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| js_err(format!("source[{i}].commit_hash_hex must be a string")))?;
        out.push(RemixSource {
            upstream_id: parse_hash_hex(upstream_hex)?,
            commit_hash: parse_hash_hex(commit_hex)?,
        });
    }
    Ok(out)
}

/// Tiny JSON parser for `[["name","mode","hex"], ...]`. We avoid pulling
/// serde into this crate: the input shape is fixed and we control both
/// sides, so a hand-rolled parser keeps the wasm blob small.
pub(crate) fn parse_json_triples(s: &str) -> Result<Vec<(String, String, String)>, &'static str> {
    // Cheap up-front guard against pathological inputs — see
    // `MAX_JSON_BYTES` for rationale.
    if s.len() > MAX_JSON_BYTES {
        return Err("input exceeds 16 MiB cap");
    }
    let s = s.trim();
    let inner = s
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or("expected top-level JSON array")?;
    let mut out = Vec::new();
    let mut chars = inner.chars().peekable();
    loop {
        skip_ws(&mut chars);
        match chars.peek() {
            None => break,
            Some('[') => {}
            Some(_) => return Err("expected `[` opening a triple"),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_json_triples_rejects_oversize_input() {
        // One byte over the cap is enough — the guard must fire before
        // the parser even looks for a leading `[`.
        let oversize = "x".repeat(MAX_JSON_BYTES + 1);
        let err = parse_json_triples(&oversize).expect_err("must reject oversize input");
        assert!(
            err.contains("16 MiB cap"),
            "unexpected error message: {err}"
        );
    }

    #[test]
    fn parse_json_triples_accepts_small_valid_input() {
        let out = parse_json_triples(r#"[["a","b","c"]]"#).expect("small input is valid");
        assert_eq!(out, vec![("a".into(), "b".into(), "c".into())]);
    }

    #[test]
    fn parse_json_triples_rejects_triple_not_opening_with_bracket() {
        // A top-level array element that is not itself a `[ … ]` triple must
        // be rejected, not panic. Guards the `Some(_) => Err` arm of the
        // opening-token match (previously a `peek().unwrap()`).
        let err = parse_json_triples(r#"["a","b","c"]"#).expect_err("scalars are not triples");
        assert!(
            err.contains("expected `[`"),
            "unexpected error message: {err}"
        );
    }
}
