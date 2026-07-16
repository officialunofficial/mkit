//! Attestation verification — §5.3 of `docs/specs/SPEC-ATTESTATIONS.md`.
//!
//! This module only validates envelope well-formedness and per-signature
//! cryptographic integrity against a caller-supplied trust-root registry.
//! Binding an attestation to a particular commit (subject check) is the
//! caller's responsibility; [`extract_primary_commit_hash`] is exposed
//! as a convenience for that step.
//!
//! The registry dispatches on the DSSE `keyid` (§6.3). `repo-key`
//! signers are keyed as `blake3:<hex>`; sigstore-keyless uses
//! `sigstore:<san>`. Verification of sigstore signatures requires a
//! full Rekor/Fulcio walk and is deliberately scaffolded here — §6.2.

use std::collections::HashMap;

#[cfg(feature = "algo-ed25519")]
use ed25519_dalek::{Signature as DalekSig, VerifyingKey};
use serde::Deserialize;

use crate::Error;
use crate::algorithm::Algorithm;
use crate::envelope::{self, Envelope};
use mkit_core::Hash;
use mkit_core::hash::{HASH_LEN, HEX_LEN, from_hex};

// -- Trust roots --

/// What kind of credential a `keyid` resolves to.
#[derive(Debug, Clone)]
pub enum TrustRoot {
    /// Raw 32-byte Ed25519 public key.
    Ed25519PubKey([u8; 32]),
    /// SEC1-encoded P-256 public key. Compressed (33 bytes,
    /// `0x02`/`0x03` prefix) and uncompressed (65 bytes, `0x04`
    /// prefix) are both accepted — `WebAuthn` authenticators ship
    /// uncompressed, our in-process signer ships compressed.
    #[cfg(feature = "algo-p256")]
    P256PubKeySec1(Vec<u8>),
    /// SEC1-encoded secp256k1 public key. Compressed (33 bytes,
    /// `0x02`/`0x03` prefix) and uncompressed (65 bytes, `0x04`
    /// prefix) are both accepted — wallet / browser-crypto clients
    /// typically ship compressed.
    #[cfg(feature = "algo-secp256k1")]
    Secp256k1PubKeySec1(Vec<u8>),
    /// Wire-encoded BLS12-381 G2 compressed public key (96 bytes for
    /// the `MinSig` variant — see `signer_bls_threshold`). Aggregated
    /// threshold signatures verify against this key using the in-tree
    /// `signer_bls_threshold::verify` function and the mkit-attest
    /// BLS namespace.
    #[cfg(feature = "bls-threshold")]
    Bls12381ThresholdPubKey(Vec<u8>),
    /// Scaffold — sigstore verification needs a Rekor + Fulcio walk
    /// that this crate does not yet ship. See SPEC-ATTESTATIONS §6.2.
    /// Any signature dispatched to this trust root reports
    /// [`Reason::UnsupportedTrustRoot`].
    SigstoreCa,
}

/// keyid → trust root lookup table. Keys are owned `String`s; insertion
/// replaces an existing entry without dropping any in-flight references.
#[derive(Debug, Default)]
pub struct Registry {
    entries: HashMap<String, TrustRoot>,
}

impl Registry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add (or replace) a trust root for `keyid`.
    pub fn add(&mut self, keyid: impl Into<String>, root: TrustRoot) {
        self.entries.insert(keyid.into(), root);
    }

    #[must_use]
    pub fn lookup(&self, keyid: &str) -> Option<&TrustRoot> {
        self.entries.get(keyid)
    }
}

// -- Per-signature / envelope verdict --

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Ok,
    UnknownKeyid,
    SignatureMismatch,
    UnsupportedTrustRoot,
    /// The keyid resolved to an algorithm whose crypto backend was
    /// compiled out of this build (e.g. `secp256k1:...` with
    /// `--no-default-features --features algo-ed25519`).
    AlgorithmNotEnabled,
    /// The keyid's prefix did not match any known algorithm and is not
    /// the legacy `blake3:` compatibility form.
    UnknownKeyidPrefix,
}

#[derive(Debug, Clone)]
pub struct SignatureResult {
    pub keyid: String,
    pub verified: bool,
    pub reason: Reason,
}

#[derive(Debug, Clone)]
pub struct VerifyResult {
    pub any_verified: bool,
    pub signatures: Vec<SignatureResult>,
}

/// Verify a DSSE envelope against a trust root registry.
///
/// The caller is responsible for further checks (e.g. that the
/// Statement subject matches the commit being asked about). This
/// function only validates envelope well-formedness + per-signature
/// crypto.
///
/// # Errors
/// * [`Error::MalformedEnvelope`] — propagated from the decoder.
/// * [`Error::UnsupportedPayloadType`] — payload type not
///   `application/vnd.in-toto+json`.
/// * [`Error::EmptySignatures`] — envelope has zero signatures.
pub fn verify_envelope(envelope_bytes: &[u8], registry: &Registry) -> Result<VerifyResult, Error> {
    let env = envelope::decode(envelope_bytes)?;
    verify(&env, registry)
}

/// Verify an already-decoded envelope. Same semantics as
/// [`verify_envelope`].
///
/// # Errors
/// See [`verify_envelope`].
pub fn verify(env: &Envelope, registry: &Registry) -> Result<VerifyResult, Error> {
    if env.payload_type != envelope::PAYLOAD_TYPE_IN_TOTO {
        return Err(Error::UnsupportedPayloadType);
    }
    if env.signatures.is_empty() {
        return Err(Error::EmptySignatures);
    }

    let pae = env.pae();

    let mut sigs = Vec::with_capacity(env.signatures.len());
    let mut any_verified = false;

    for s in &env.signatures {
        // Dispatch strategy:
        //   1. Parse the keyid prefix into an `Algorithm`. This is
        //      informational for now; the trust-root variant is the
        //      source of truth for which crypto path runs.
        //   2. Look up the trust root. A miss is `UnknownKeyid`
        //      regardless of whether the prefix was recognised.
        //   3. Per trust-root variant, either run the verifier (if
        //      compiled in) or surface `AlgorithmNotEnabled`.
        let alg_hint = Algorithm::from_keyid(&s.keyid);

        let mut row = SignatureResult {
            keyid: s.keyid.clone(),
            verified: false,
            reason: Reason::UnknownKeyid,
        };

        match registry.lookup(&s.keyid) {
            None => {
                // Distinguish "we don't know this keyid" from "we
                // don't even recognise the prefix shape" so callers
                // can surface a better diagnostic. Both map to
                // not-verified.
                row.reason = if alg_hint.is_none() {
                    Reason::UnknownKeyidPrefix
                } else {
                    Reason::UnknownKeyid
                };
            }
            Some(TrustRoot::Ed25519PubKey(pk)) => {
                row.reason = dispatch_ed25519(*pk, &s.sig, &pae);
                if row.reason == Reason::Ok {
                    row.verified = true;
                    any_verified = true;
                }
            }
            #[cfg(feature = "algo-p256")]
            Some(TrustRoot::P256PubKeySec1(pk)) => {
                row.reason = match crate::signer_p256::verify_p256(pk, &pae, &s.sig) {
                    Ok(()) => Reason::Ok,
                    Err(_) => Reason::SignatureMismatch,
                };
                if row.reason == Reason::Ok {
                    row.verified = true;
                    any_verified = true;
                }
            }
            #[cfg(feature = "algo-secp256k1")]
            Some(TrustRoot::Secp256k1PubKeySec1(pk)) => {
                row.reason = match crate::signer_k256::verify_secp256k1(pk, &pae, &s.sig) {
                    Ok(()) => Reason::Ok,
                    Err(_) => Reason::SignatureMismatch,
                };
                if row.reason == Reason::Ok {
                    row.verified = true;
                    any_verified = true;
                }
            }
            #[cfg(feature = "bls-threshold")]
            Some(TrustRoot::Bls12381ThresholdPubKey(pk)) => {
                row.reason = match crate::signer_bls_threshold::verify(pk, &pae, &s.sig) {
                    Ok(()) => Reason::Ok,
                    Err(_) => Reason::SignatureMismatch,
                };
                if row.reason == Reason::Ok {
                    row.verified = true;
                    any_verified = true;
                }
            }
            Some(TrustRoot::SigstoreCa) => {
                row.reason = Reason::UnsupportedTrustRoot;
            }
        }
        sigs.push(row);
    }

    Ok(VerifyResult {
        any_verified,
        signatures: sigs,
    })
}

/// Verify a raw signature under the named algorithm.
///
/// It takes the raw pubkey, signature, and message bytes with the
/// [`Algorithm`] explicit, so callers that already know the algorithm
/// don't have to reparse a keyid string.
///
/// Contract:
/// * `Ok(())` — the signature verified under `pubkey` over `msg`.
/// * `Err(Error::AlgorithmNotEnabled(alg))` — returned when the
///   algorithm's backend is compiled out of this build (e.g.
///   `--no-default-features --features algo-ed25519` verifying a
///   `secp256k1` keyid). For the **Ed25519** and **BLS12-381 threshold**
///   arms this variant is *also* returned when the backend ran but the
///   signature failed to verify: those two arms deliberately collapse
///   crypto-mismatch into the same variant as a disabled backend.
/// * Typed per-algorithm errors — the **secp256k1** and **P-256** arms
///   do NOT collapse. On failure they surface their backend's own typed
///   variant ([`Error::Secp256k1KeyInvalid`],
///   [`Error::Secp256k1SignatureInvalid`],
///   [`Error::Secp256k1VerifyFailed`], or the `P256*` equivalents),
///   never `AlgorithmNotEnabled`. A caller that matches only
///   `AlgorithmNotEnabled` would therefore miss a genuine secp256k1/p256
///   verification failure — match the typed variants too, or use
///   [`verify_envelope`], which normalises every backend into a
///   per-signature [`Reason`].
///
/// # Errors
/// * [`Error::AlgorithmNotEnabled`] — backend compiled out, or (Ed25519
///   / BLS-threshold only) the signature failed to verify.
/// * [`Error::Secp256k1KeyInvalid`] / [`Error::Secp256k1SignatureInvalid`]
///   / [`Error::Secp256k1VerifyFailed`] — secp256k1 backend failures.
/// * [`Error::P256KeyInvalid`] / [`Error::P256SignatureInvalid`] /
///   [`Error::P256VerifyFailed`] — P-256 backend failures.
pub fn verify_signature(
    algorithm: Algorithm,
    pubkey: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<(), Error> {
    match algorithm {
        Algorithm::Ed25519 => {
            #[cfg(feature = "algo-ed25519")]
            {
                let pk: [u8; 32] = pubkey
                    .try_into()
                    .map_err(|_| Error::AlgorithmNotEnabled(Algorithm::Ed25519))?;
                match verify_ed25519(pk, sig, msg) {
                    Reason::Ok => Ok(()),
                    _ => Err(Error::AlgorithmNotEnabled(Algorithm::Ed25519)),
                }
            }
            #[cfg(not(feature = "algo-ed25519"))]
            {
                let _ = (pubkey, msg, sig);
                Err(Error::AlgorithmNotEnabled(Algorithm::Ed25519))
            }
        }
        Algorithm::Secp256k1 => {
            #[cfg(feature = "algo-secp256k1")]
            {
                crate::signer_k256::verify_secp256k1(pubkey, msg, sig)
            }
            #[cfg(not(feature = "algo-secp256k1"))]
            {
                let _ = (pubkey, msg, sig);
                Err(Error::AlgorithmNotEnabled(Algorithm::Secp256k1))
            }
        }
        Algorithm::P256 => {
            #[cfg(feature = "algo-p256")]
            {
                crate::signer_p256::verify_p256(pubkey, msg, sig)
            }
            #[cfg(not(feature = "algo-p256"))]
            {
                let _ = (pubkey, msg, sig);
                Err(Error::AlgorithmNotEnabled(Algorithm::P256))
            }
        }
        // BLS12-381 threshold dispatch routes through the
        // `signer_bls_threshold::verify` helper, which uses the
        // mkit-attest BLS namespace + the MinSig variant — i.e. only
        // signatures produced by this crate's `ThresholdSigner`
        // verify. A third-party BLS aggregator using a different
        // namespace will NOT verify here, by design.
        //
        // The `verify_signature` contract (see function-level
        // doc-comment) collapses crypto-mismatch into the same
        // `AlgorithmNotEnabled` error variant as a compiled-out
        // backend. Callers wanting reason-level detail use
        // `verify_envelope`.
        #[cfg(feature = "bls-threshold")]
        Algorithm::Bls12381Threshold => {
            match crate::signer_bls_threshold::verify(pubkey, msg, sig) {
                Ok(()) => Ok(()),
                Err(_) => Err(Error::AlgorithmNotEnabled(Algorithm::Bls12381Threshold)),
            }
        }
    }
}

/// Verify an Ed25519 signature over `pae` under `pk`.
///
/// Uses `verify_strict`, which enforces canonical R, s mod L, and
/// canonical A encoding. Rejects the Ed25519 malleability vectors
/// documented at <https://hdevalence.ca/blog/2020-10-04-its-25519am> —
/// attestation verification MUST be deterministic (all honest verifiers
/// reach the same verdict on the same signature), which the default
/// loose `verify()` does not guarantee.
///
/// Returns [`Reason::Ok`] on success and [`Reason::SignatureMismatch`]
/// on any failure (malformed `pk`, wrong `sig_bytes` length, or strict
/// verification reject). Public so downstream consumers — notably the
/// `mkit-wasm` `ed25519_verify` export — can share this exact strict
/// verifier instead of re-implementing it (and re-relitigating which
/// malleability cases to reject).
#[cfg(feature = "algo-ed25519")]
#[must_use]
pub fn verify_ed25519(pk: [u8; 32], sig_bytes: &[u8], pae: &[u8]) -> Reason {
    if sig_bytes.len() != ed25519_dalek::SIGNATURE_LENGTH {
        return Reason::SignatureMismatch;
    }
    let mut arr = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
    arr.copy_from_slice(sig_bytes);
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
        return Reason::SignatureMismatch;
    };
    let sig = DalekSig::from_bytes(&arr);
    if vk.verify_strict(pae, &sig).is_ok() {
        Reason::Ok
    } else {
        Reason::SignatureMismatch
    }
}

/// Dispatch an Ed25519 verify, mapping the compiled-out build to
/// [`Reason::AlgorithmNotEnabled`] so the registry path can keep a
/// uniform per-signature `Reason` shape without Cargo-feature clutter.
fn dispatch_ed25519(pk: [u8; 32], sig_bytes: &[u8], pae: &[u8]) -> Reason {
    #[cfg(feature = "algo-ed25519")]
    {
        verify_ed25519(pk, sig_bytes, pae)
    }
    #[cfg(not(feature = "algo-ed25519"))]
    {
        let _ = (pk, sig_bytes, pae);
        Reason::AlgorithmNotEnabled
    }
}

// -- Subject helper --

/// Parse the in-toto Statement payload and return the first
/// `subject[].digest.blake3` as a [`Hash`](tyalias@mkit_core::Hash). Errors if the JSON is
/// malformed, `subject[]` is missing/empty, or the first entry is
/// missing a blake3 digest with the expected 64-char hex shape.
///
/// We use a relaxed JSON parser here (serde) — we do not need to re-
/// canonicalise on the verify side; we only want to read the subject
/// hash out for binding to a commit.
///
/// # Errors
/// See above.
pub fn extract_primary_commit_hash(statement_json: &[u8]) -> Result<Hash, Error> {
    #[derive(Deserialize)]
    struct Stmt {
        #[serde(default)]
        subject: Vec<SubjEntry>,
    }
    #[derive(Deserialize)]
    struct SubjEntry {
        digest: HashMap<String, String>,
    }

    let stmt: Stmt =
        serde_json::from_slice(statement_json).map_err(|_| Error::MalformedStatement)?;
    let first = stmt.subject.first().ok_or(Error::SubjectMissing)?;
    let hex = first
        .digest
        .get("blake3")
        .ok_or(Error::SubjectDigestMissing)?;
    if hex.len() != HEX_LEN {
        return Err(Error::InvalidDigestLength);
    }
    let h = from_hex(hex).map_err(|_| Error::InvalidDigestHex)?;
    debug_assert_eq!(h.len(), HASH_LEN);
    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{self as env_mod, Envelope, Sig};
    use crate::statement::{self, Statement, Subject};
    use ed25519_dalek::{Signer, SigningKey};
    use mkit_core::hash::to_hex;

    /// Build a DSSE envelope with a single Ed25519 signature over an
    /// in-toto Statement claiming `commit_hex` as its subject.
    fn build_signed_envelope(
        seed: [u8; 32],
        keyid: &str,
        commit_hex: &str,
        predicate_jcs: &[u8],
    ) -> (Vec<u8>, [u8; 32]) {
        let signing = SigningKey::from_bytes(&seed);
        let pk_bytes = signing.verifying_key().to_bytes();

        let stmt = statement::encode(&Statement {
            subjects: vec![Subject {
                name: Some("commit".into()),
                digest_blake3_hex: commit_hex.into(),
                digest_sha256_hex: "00".repeat(32),
            }],
            predicate_type: "https://example.com/predicate/v1".into(),
            predicate_jcs,
        })
        .unwrap();

        let pae = env_mod::pae_of(env_mod::PAYLOAD_TYPE_IN_TOTO, stmt.as_bytes());
        let sig = signing.sign(&pae);

        let env = Envelope {
            payload_type: env_mod::PAYLOAD_TYPE_IN_TOTO.into(),
            payload: stmt.into_bytes(),
            signatures: vec![Sig {
                keyid: keyid.into(),
                sig: sig.to_bytes().to_vec(),
            }],
        };
        (env.encode().unwrap().into_bytes(), pk_bytes)
    }

    #[cfg(feature = "algo-ed25519")]
    #[test]
    fn deterministic_repo_key_roundtrip() {
        let seed = [0xAB; 32];
        let keyid = "blake3:deadbeef";
        let commit_hex = "0011223344556677889900112233445566778899001122334455667788990011";

        let (bytes, pk) = build_signed_envelope(seed, keyid, commit_hex, b"{}");

        let mut reg = Registry::new();
        reg.add(keyid, TrustRoot::Ed25519PubKey(pk));

        let r = verify_envelope(&bytes, &reg).unwrap();
        assert!(r.any_verified);
        assert_eq!(r.signatures.len(), 1);
        assert_eq!(r.signatures[0].reason, Reason::Ok);
        assert!(r.signatures[0].verified);
        assert_eq!(r.signatures[0].keyid, keyid);
    }

    #[test]
    fn rejects_empty_signatures() {
        // Hand-craft an envelope our strict decoder accepts but with [].
        let bytes = b"{\"payload\":\"e30=\",\
                       \"payloadType\":\"application/vnd.in-toto+json\",\
                       \"signatures\":[]}";
        let reg = Registry::new();
        assert!(matches!(
            verify_envelope(bytes, &reg),
            Err(Error::EmptySignatures)
        ));
    }

    #[test]
    fn rejects_bad_payload_type() {
        let bytes = b"{\"payload\":\"e30=\",\
                       \"payloadType\":\"application/x-foo\",\
                       \"signatures\":[{\"keyid\":\"k\",\"sig\":\"AQID\"}]}";
        let reg = Registry::new();
        assert!(matches!(
            verify_envelope(bytes, &reg),
            Err(Error::UnsupportedPayloadType)
        ));
    }

    #[test]
    fn unknown_keyid_does_not_verify() {
        let seed = [0x11; 32];
        let keyid = "blake3:unknown";
        let commit_hex = "a".repeat(64);

        let (bytes, _pk) = build_signed_envelope(seed, keyid, &commit_hex, b"{}");
        let reg = Registry::new();

        let r = verify_envelope(&bytes, &reg).unwrap();
        assert!(!r.any_verified);
        assert_eq!(r.signatures[0].reason, Reason::UnknownKeyid);
        assert!(!r.signatures[0].verified);
    }

    #[cfg(feature = "algo-ed25519")]
    #[test]
    fn tampered_payload_fails_signature() {
        let seed = [0x42; 32];
        let keyid = "blake3:tampered";
        let commit_hex = "b".repeat(64);

        let (bytes, pk) = build_signed_envelope(seed, keyid, &commit_hex, b"{}");

        // Decode, flip a payload byte, re-encode under the SAME signature.
        let mut env = env_mod::decode(&bytes).unwrap();
        let mid = env.payload.len() / 2;
        env.payload[mid] ^= 0x01;
        let tampered = env.encode().unwrap();

        let mut reg = Registry::new();
        reg.add(keyid, TrustRoot::Ed25519PubKey(pk));

        let r = verify_envelope(tampered.as_bytes(), &reg).unwrap();
        assert!(!r.any_verified);
        assert_eq!(r.signatures[0].reason, Reason::SignatureMismatch);
    }

    #[test]
    fn extract_primary_commit_hash_happy_path() {
        let commit: Hash = [0xCC; 32];
        let hex = to_hex(&commit);
        let stmt = statement::encode(&Statement {
            subjects: vec![Subject {
                name: Some("commit".into()),
                digest_blake3_hex: hex,
                digest_sha256_hex: "00".repeat(32),
            }],
            predicate_type: "https://example.com/p".into(),
            predicate_jcs: b"{}",
        })
        .unwrap();
        let parsed = extract_primary_commit_hash(stmt.as_bytes()).unwrap();
        assert_eq!(parsed, commit);
    }

    #[test]
    fn extract_primary_commit_hash_rejects_missing_subject() {
        let empty_subject = b"{\"_type\":\"https://in-toto.io/Statement/v1\",\
                                \"predicate\":{},\
                                \"predicateType\":\"https://example.com/p\",\
                                \"subject\":[]}";
        assert!(matches!(
            extract_primary_commit_hash(empty_subject),
            Err(Error::SubjectMissing)
        ));

        // No subject key at all (serde default = empty vec → SubjectMissing).
        let no_subject = b"{\"_type\":\"https://in-toto.io/Statement/v1\",\
                            \"predicate\":{},\
                            \"predicateType\":\"https://example.com/p\"}";
        assert!(matches!(
            extract_primary_commit_hash(no_subject),
            Err(Error::SubjectMissing)
        ));
    }

    #[test]
    fn sigstore_trust_root_is_scaffold() {
        let seed = [0x33; 32];
        let keyid = "sigstore:https://example.com/workflow";
        let commit_hex = "c".repeat(64);

        let (bytes, _pk) = build_signed_envelope(seed, keyid, &commit_hex, b"{}");

        let mut reg = Registry::new();
        reg.add(keyid, TrustRoot::SigstoreCa);

        let r = verify_envelope(&bytes, &reg).unwrap();
        assert!(!r.any_verified);
        assert_eq!(r.signatures[0].reason, Reason::UnsupportedTrustRoot);
    }

    #[test]
    fn registry_add_replaces_existing() {
        let mut reg = Registry::new();
        reg.add("k", TrustRoot::Ed25519PubKey([0; 32]));
        reg.add("k", TrustRoot::Ed25519PubKey([1; 32]));
        match reg.lookup("k") {
            Some(TrustRoot::Ed25519PubKey(pk)) => assert_eq!(pk[0], 1),
            _ => panic!(),
        }
    }

    // -- multi-algorithm foundation tests --

    /// A synthetic `secp256k1:<hex>` keyid (not in the registry) must
    /// surface as `UnknownKeyid` through the dispatch layer — not as a
    /// generic error. Once a secp256k1 trust root is wired and
    /// the caller adds it to the registry, the reason turns into
    /// `AlgorithmNotEnabled` (when the feature is off) or `Ok` (when
    /// the feature is on and the signature verifies).
    #[test]
    fn secp256k1_keyid_unknown_to_registry_reports_unknown_keyid() {
        // Build an envelope whose *ed25519* signature happens to be
        // attached to a `secp256k1:...` keyid. We're testing dispatch,
        // not crypto — the signature bytes don't matter because the
        // registry misses.
        let seed = [0x55; 32];
        let keyid = "secp256k1:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let commit_hex = "d".repeat(64);
        let (bytes, _pk) = build_signed_envelope(seed, keyid, &commit_hex, b"{}");

        let reg = Registry::new();
        let r = verify_envelope(&bytes, &reg).unwrap();
        assert!(!r.any_verified);
        assert_eq!(r.signatures.len(), 1);
        assert_eq!(r.signatures[0].reason, Reason::UnknownKeyid);
    }

    /// A keyid with an entirely unknown prefix (not one of `ed25519:`,
    /// `secp256k1:`, `p256:`, or the legacy `blake3:`) and not present
    /// in the registry must surface as `UnknownKeyidPrefix`, not
    /// `UnknownKeyid`. The distinction lets callers render a useful
    /// diagnostic ("what kind of key is this?") vs. the plain
    /// "registered something else" miss.
    #[test]
    fn unknown_prefix_keyid_reports_unknown_keyid_prefix() {
        let seed = [0x66; 32];
        let keyid = "quantum-foo:whatever";
        let commit_hex = "e".repeat(64);
        let (bytes, _pk) = build_signed_envelope(seed, keyid, &commit_hex, b"{}");

        let reg = Registry::new();
        let r = verify_envelope(&bytes, &reg).unwrap();
        assert!(!r.any_verified);
        assert_eq!(r.signatures[0].reason, Reason::UnknownKeyidPrefix);
    }

    /// Legacy-compat path: a `blake3:<hex>` keyid must continue to
    /// verify as Ed25519, because that's the shape existing
    /// attestations on disk carry. Gated on `algo-ed25519` because the
    /// crypto step needs the backend compiled in.
    #[cfg(feature = "algo-ed25519")]
    #[test]
    fn legacy_blake3_keyid_still_verifies_as_ed25519() {
        let seed = [0x77; 32];
        let keyid = "blake3:abc123";
        let commit_hex = "f".repeat(64);
        let (bytes, pk) = build_signed_envelope(seed, keyid, &commit_hex, b"{}");

        // `Algorithm::from_keyid` is the source of the dispatch hint.
        assert_eq!(Algorithm::from_keyid(keyid), Some(Algorithm::Ed25519));

        let mut reg = Registry::new();
        reg.add(keyid, TrustRoot::Ed25519PubKey(pk));

        let r = verify_envelope(&bytes, &reg).unwrap();
        assert!(r.any_verified);
        assert_eq!(r.signatures[0].reason, Reason::Ok);
    }

    /// When `algo-ed25519` is compiled out, a `blake3:<hex>` keyid
    /// whose trust root IS registered (Ed25519PubKey variant) falls
    /// through to `Reason::AlgorithmNotEnabled` instead of running the
    /// dalek path. Registry-miss path is tested separately above.
    #[cfg(not(feature = "algo-ed25519"))]
    #[test]
    fn ed25519_backend_disabled_reports_algorithm_not_enabled() {
        // We can't cleanly build a signed envelope without dalek at
        // runtime, but we can synthesise an envelope whose signature
        // bytes are garbage and whose keyid is registered — the
        // dispatch should surface AlgorithmNotEnabled before hitting
        // any crypto. We hand-craft the envelope JSON to avoid any
        // dalek dep.
        let bytes = b"{\"payload\":\"e30=\",\
                       \"payloadType\":\"application/vnd.in-toto+json\",\
                       \"signatures\":[{\"keyid\":\"blake3:abc\",\"sig\":\"AAAA\"}]}";
        let mut reg = Registry::new();
        reg.add("blake3:abc", TrustRoot::Ed25519PubKey([0u8; 32]));

        let r = verify_envelope(bytes, &reg).unwrap();
        assert!(!r.any_verified);
        assert_eq!(r.signatures[0].reason, Reason::AlgorithmNotEnabled);
    }

    /// `verify_signature` with an Ed25519 key + valid signature returns
    /// `Ok(())`.
    #[cfg(feature = "algo-ed25519")]
    #[test]
    fn verify_signature_ed25519_happy_path() {
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&[0x99; 32]);
        let pk = sk.verifying_key().to_bytes();
        let msg = b"DSSEv1 test message";
        let sig = sk.sign(msg).to_bytes();

        assert!(verify_signature(Algorithm::Ed25519, &pk, msg, &sig).is_ok());
    }

    /// `verify_signature` returns `Err(AlgorithmNotEnabled)` only when
    /// the algorithm's backend is truly compiled out. With all features
    /// enabled (the default), every arm has a real verifier that
    /// surfaces its own typed error on malformed input.
    #[cfg(not(any(feature = "algo-secp256k1", feature = "algo-p256")))]
    #[test]
    fn verify_signature_disabled_algorithms_return_not_enabled() {
        let pk = [0u8; 33];
        let msg = b"anything";
        let sig = [0u8; 64];

        #[cfg(not(feature = "algo-secp256k1"))]
        match verify_signature(Algorithm::Secp256k1, &pk, msg, &sig) {
            Err(Error::AlgorithmNotEnabled(Algorithm::Secp256k1)) => {}
            other => panic!("expected AlgorithmNotEnabled(Secp256k1), got {other:?}"),
        }
        #[cfg(not(feature = "algo-p256"))]
        match verify_signature(Algorithm::P256, &pk, msg, &sig) {
            Err(Error::AlgorithmNotEnabled(Algorithm::P256)) => {}
            other => panic!("expected AlgorithmNotEnabled(P256), got {other:?}"),
        }
        let _ = (pk, msg, sig);
    }

    /// With the backend compiled in, `verify_signature` surfaces the
    /// backend's own typed error on malformed inputs instead of
    /// `AlgorithmNotEnabled`. This is what every in-tree build hits by
    /// default since all three algorithms are on.
    #[cfg(feature = "algo-secp256k1")]
    #[test]
    fn verify_signature_secp256k1_enabled_surfaces_backend_error() {
        let pk = [0u8; 33];
        let msg = b"anything";
        let sig = [0u8; 64];
        assert!(matches!(
            verify_signature(Algorithm::Secp256k1, &pk, msg, &sig),
            Err(Error::Secp256k1KeyInvalid)
        ));
    }

    #[cfg(feature = "algo-p256")]
    #[test]
    fn verify_signature_p256_enabled_surfaces_backend_error() {
        let pk = [0u8; 33];
        let msg = b"anything";
        let sig = [0u8; 64];
        assert!(verify_signature(Algorithm::P256, &pk, msg, &sig).is_err());
    }

    /// `verify_signature` collapses crypto-mismatch into the same
    /// `AlgorithmNotEnabled` error variant today (per the function's
    /// contract). Callers wanting reason-level detail use
    /// `verify_envelope` which returns a `Reason`.
    #[cfg(feature = "algo-ed25519")]
    #[test]
    fn verify_signature_ed25519_mismatch_returns_err() {
        let pk = [0u8; 32];
        let msg = b"hello";
        let sig = [0u8; 64];
        assert!(verify_signature(Algorithm::Ed25519, &pk, msg, &sig).is_err());
    }

    /// End-to-end: a DSSE envelope signed by a 3-of-4 BLS threshold
    /// cohort verifies against a `Bls12381ThresholdPubKey` trust root
    /// in the registry. Pins the registry-dispatch wiring.
    #[cfg(feature = "bls-threshold")]
    #[test]
    fn registry_dispatches_bls_threshold_keyid_to_verify() {
        use crate::signer::Signer as _;
        use crate::signer_bls_threshold::{
            KEYID_PREFIX, ThresholdSigner, aggregate, trusted_dealer,
        };
        use commonware_codec::Encode as _;
        use commonware_utils::{NZU32, TestRng};

        // 3-of-4 cohort.
        let mut rng = TestRng::new(0xBEEF);
        let (sharing, shares) = trusted_dealer(&mut rng, NZU32!(4));
        let agg_pubkey = sharing.public().encode().to_vec();
        let keyid = format!("{KEYID_PREFIX}{}", mkit_core::to_hex_bytes(&agg_pubkey));

        // Build an envelope around an in-toto Statement, then sign its
        // PAE with 3 of the 4 holders and aggregate.
        let stmt = crate::statement::encode(&crate::statement::Statement {
            subjects: vec![crate::statement::Subject {
                name: Some("commit".into()),
                digest_blake3_hex: "a".repeat(64),
                digest_sha256_hex: "00".repeat(32),
            }],
            predicate_type: "https://example.com/p/v1".into(),
            predicate_jcs: b"{}",
        })
        .unwrap();
        let pae = envelope::pae_of(envelope::PAYLOAD_TYPE_IN_TOTO, stmt.as_bytes());

        let mut partials: Vec<Vec<u8>> = Vec::with_capacity(3);
        for s in shares.iter().take(3) {
            let mut signer = ThresholdSigner::new(s.clone(), sharing.clone());
            partials.push(signer.sign(&pae).expect("partial sign"));
        }
        let agg_sig = aggregate(&sharing, &partials).expect("aggregate");

        let env = Envelope {
            payload_type: envelope::PAYLOAD_TYPE_IN_TOTO.into(),
            payload: stmt.into_bytes(),
            signatures: vec![envelope::Sig {
                keyid: keyid.clone(),
                sig: agg_sig,
            }],
        };
        let bytes = env.encode().unwrap().into_bytes();

        let mut reg = Registry::new();
        reg.add(
            keyid.clone(),
            TrustRoot::Bls12381ThresholdPubKey(agg_pubkey),
        );

        let r = verify_envelope(&bytes, &reg).unwrap();
        assert!(r.any_verified);
        assert_eq!(r.signatures.len(), 1);
        assert_eq!(r.signatures[0].reason, Reason::Ok);
        assert!(r.signatures[0].verified);
        assert_eq!(r.signatures[0].keyid, keyid);
    }

    /// Tampered aggregate signature reports `SignatureMismatch` (not
    /// `UnknownKeyid` or `UnsupportedTrustRoot`).
    #[cfg(feature = "bls-threshold")]
    #[test]
    fn registry_rejects_tampered_bls_aggregate() {
        use crate::signer::Signer as _;
        use crate::signer_bls_threshold::{
            KEYID_PREFIX, ThresholdSigner, aggregate, trusted_dealer,
        };
        use commonware_codec::Encode as _;
        use commonware_utils::{NZU32, TestRng};

        let mut rng = TestRng::new(0xCAFE);
        let (sharing, shares) = trusted_dealer(&mut rng, NZU32!(4));
        let agg_pubkey = sharing.public().encode().to_vec();
        let keyid = format!("{KEYID_PREFIX}{}", mkit_core::to_hex_bytes(&agg_pubkey));

        let stmt = crate::statement::encode(&crate::statement::Statement {
            subjects: vec![crate::statement::Subject {
                name: Some("commit".into()),
                digest_blake3_hex: "b".repeat(64),
                digest_sha256_hex: "00".repeat(32),
            }],
            predicate_type: "https://example.com/p/v1".into(),
            predicate_jcs: b"{}",
        })
        .unwrap();
        let pae = envelope::pae_of(envelope::PAYLOAD_TYPE_IN_TOTO, stmt.as_bytes());

        let mut partials: Vec<Vec<u8>> = Vec::with_capacity(3);
        for s in shares.iter().take(3) {
            let mut signer = ThresholdSigner::new(s.clone(), sharing.clone());
            partials.push(signer.sign(&pae).expect("partial sign"));
        }
        let mut agg_sig = aggregate(&sharing, &partials).expect("aggregate");
        let last = agg_sig.len() - 1;
        agg_sig[last] ^= 0x01;

        let env = Envelope {
            payload_type: envelope::PAYLOAD_TYPE_IN_TOTO.into(),
            payload: stmt.into_bytes(),
            signatures: vec![envelope::Sig {
                keyid: keyid.clone(),
                sig: agg_sig,
            }],
        };
        let bytes = env.encode().unwrap().into_bytes();

        let mut reg = Registry::new();
        reg.add(keyid, TrustRoot::Bls12381ThresholdPubKey(agg_pubkey));

        let r = verify_envelope(&bytes, &reg).unwrap();
        assert!(!r.any_verified);
        assert_eq!(r.signatures[0].reason, Reason::SignatureMismatch);
    }
}
