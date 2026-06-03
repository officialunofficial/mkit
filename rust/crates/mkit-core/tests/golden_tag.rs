//! Phase 9 (annotated / signed tag) golden vectors.
//!
//! Pins the canonical byte layout of [`Tag`] objects (SPEC-OBJECTS §6a)
//! and the tag signing bytes + signing hash + Ed25519 signature under
//! the distinct `mkit.tag\0` domain (SPEC-SIGNING §4a).
//!
//! For each fixture we:
//!
//! 1. Build the deterministic [`Tag`] from pinned constants.
//! 2. Re-serialize and compare byte-for-byte against `<name>.bin`.
//! 3. Round-trip `deserialize` -> `serialize`.
//! 4. Cross-check the BLAKE3 digest of the bin against `MANIFEST.txt`.
//!
//! The signed fixture additionally pins the 64-byte Ed25519 signature
//! (deterministic per RFC 8032) and asserts `verify_tag` succeeds.
//!
//! Set `MKIT_HARVEST=1` to (re)generate the fixtures + MANIFEST instead
//! of verifying. This is the only way the `.bin` files change; do not
//! hand-edit them.

use std::fs;
use std::path::PathBuf;

use mkit_core::deserialize;
use mkit_core::hash::{hash, to_hex};
use mkit_core::object::{Identity, Object, ObjectType, Tag};
use mkit_core::serialize;
use mkit_core::sign::{
    KeyPair, TAG_DOMAIN, sign_tag, tag_signing_bytes, tag_signing_hash, verify_tag,
};

fn golden_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop(); // crates/
    d.pop(); // rust/
    d.push("tests");
    d.push("golden");
    d.push("phase9");
    d
}

fn load(name: &str) -> Vec<u8> {
    let p = golden_dir().join(name);
    fs::read(&p).unwrap_or_else(|e| panic!("cannot read golden fixture {}: {e}", p.display()))
}

fn harvesting() -> bool {
    std::env::var("MKIT_HARVEST").is_ok()
}

fn write_bin(name: &str, bytes: &[u8]) {
    fs::write(golden_dir().join(name), bytes).expect("write fixture");
}

// ---- Pinned constants (changing these breaks goldens) ----

/// Fixed signing seed for the signed-tag fixture.
const SEED: [u8; 32] = [0x07; 32];
const TARGET: [u8; 32] = [0xC0; 32];
const TS: u64 = 1_700_000_000;

fn signer_kp() -> KeyPair {
    KeyPair::from_seed(SEED)
}

/// Annotated (unsigned) tag fixture.
fn annotated_tag() -> Tag {
    Tag {
        target: TARGET,
        target_type: ObjectType::Commit,
        name: b"v1.0.0".to_vec(),
        tagger: Identity::ed25519([0xAA; 32]),
        signer: [0xAA; 32],
        message: b"mkit 1.0.0 release".to_vec(),
        timestamp: TS,
        signature: [0u8; 64],
    }
}

/// Signed tag fixture — same shape, tagger/signer derived from the
/// fixed seed, signature filled in.
fn signed_tag() -> Tag {
    let kp = signer_kp();
    let mut t = Tag {
        target: TARGET,
        target_type: ObjectType::Commit,
        name: b"v1.0.0".to_vec(),
        tagger: Identity::ed25519(kp.public.0),
        signer: kp.public.0,
        message: b"mkit 1.0.0 release".to_vec(),
        timestamp: TS,
        signature: [0u8; 64],
    };
    t.signature = sign_tag(&t, &kp).expect("sign").0;
    t
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
    let got = serialize(obj).expect("serialise");
    if harvesting() {
        write_bin(&format!("{name}.bin"), &got);
        return;
    }
    let want = load(&format!("{name}.bin"));
    assert_eq!(got, want, "{name}.bin: re-serialised bytes differ");
    let parsed = deserialize(&want).expect("deserialise");
    assert_eq!(&parsed, obj, "{name}.bin: deserialised form differs");
    if let Some(want_hex) = manifest_digest(name) {
        assert_eq!(
            to_hex(&hash(&want)),
            want_hex,
            "{name}.bin: BLAKE3 digest does not match MANIFEST.txt"
        );
    }
}

#[test]
fn tag_annotated_matches_golden() {
    assert_object_matches("tag_annotated", &Object::Tag(annotated_tag()));
}

#[test]
fn tag_signed_matches_golden() {
    let t = signed_tag();
    assert_object_matches("tag_signed", &Object::Tag(t.clone()));
    // The signed fixture must actually verify under the tag domain.
    verify_tag(&t).expect("signed golden tag verifies");
}

#[test]
fn tag_signing_bytes_match_golden() {
    let t = annotated_tag();
    let sb = tag_signing_bytes(&t).expect("derive");
    if harvesting() {
        write_bin("tag_annotated_signing_bytes.bin", &sb);
    } else {
        let want = load("tag_annotated_signing_bytes.bin");
        assert_eq!(sb, want, "tag signing bytes diverge from pinned golden");
        if let Some(want_hex) = manifest_digest("tag_annotated_signing_bytes") {
            assert_eq!(to_hex(&hash(&want)), want_hex);
        }
    }
}

#[test]
fn tag_signing_hash_is_stable() {
    // Pin the canonical signing hash (what Ed25519 actually signs).
    // Any drift in the tag domain separator or length prefix trips here.
    let t = annotated_tag();
    let got = to_hex(&tag_signing_hash(&t).expect("hash"));
    if harvesting() {
        eprintln!("tag_annotated signing_hash = {got}");
        return;
    }
    let want = manifest_digest("tag_annotated_signing_hash")
        .expect("MANIFEST has tag_annotated_signing_hash");
    assert_eq!(got, want, "tag signing hash drifted");
}

#[test]
fn tag_signature_is_deterministic_and_distinct_domain() {
    // Pin the 64-byte signature for the signed fixture.
    let t = signed_tag();
    let got = hex::encode(t.signature);
    if harvesting() {
        eprintln!("tag_signed signature = {got}");
    } else {
        let want =
            manifest_digest("tag_signed_signature").expect("MANIFEST has tag_signed_signature");
        assert_eq!(got, want, "signed tag signature drifted");
    }
    // Cross-domain guard: the SAME signing bytes signed under the tag
    // domain must not coincide with a commit/remix-domain signature.
    let kp = signer_kp();
    let sb = tag_signing_bytes(&t).expect("derive");
    let tag_sig = kp.sign(TAG_DOMAIN, &sb);
    assert_eq!(
        tag_sig.0, t.signature,
        "sign_tag matches kp.sign(TAG_DOMAIN)"
    );
}
