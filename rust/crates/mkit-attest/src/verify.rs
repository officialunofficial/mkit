//! Attestation verification — §5.3 of `docs/SPEC-ATTESTATIONS.md`.
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

use ed25519_dalek::{Signature as DalekSig, Verifier, VerifyingKey};
use serde::Deserialize;

use crate::Error;
use crate::envelope::{self, Envelope};
use mkit_core::Hash;
use mkit_core::hash::{HASH_LEN, HEX_LEN, from_hex};

// -- Trust roots --

/// What kind of credential a `keyid` resolves to.
#[derive(Debug, Clone)]
pub enum TrustRoot {
    /// Raw 32-byte Ed25519 public key.
    Ed25519PubKey([u8; 32]),
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
        let mut row = SignatureResult {
            keyid: s.keyid.clone(),
            verified: false,
            reason: Reason::UnknownKeyid,
        };
        match registry.lookup(&s.keyid) {
            None => row.reason = Reason::UnknownKeyid,
            Some(TrustRoot::Ed25519PubKey(pk)) => {
                row.reason = verify_ed25519(*pk, &s.sig, &pae);
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

fn verify_ed25519(pk: [u8; 32], sig_bytes: &[u8], pae: &[u8]) -> Reason {
    if sig_bytes.len() != ed25519_dalek::SIGNATURE_LENGTH {
        return Reason::SignatureMismatch;
    }
    let mut arr = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
    arr.copy_from_slice(sig_bytes);
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
        return Reason::SignatureMismatch;
    };
    let sig = DalekSig::from_bytes(&arr);
    if vk.verify(pae, &sig).is_ok() {
        Reason::Ok
    } else {
        Reason::SignatureMismatch
    }
}

// -- Subject helper --

/// Parse the in-toto Statement payload and return the first
/// `subject[].digest.blake3` as a [`Hash`]. Errors if the JSON is
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
}
