//! BLS12-381 threshold signer — partial signing + aggregation.
//!
//! Part of the release-party flow (see `docs/specs/SPEC-RELEASE-THRESHOLD.md`).
//! This module exposes:
//!
//! * [`ThresholdSigner`] — a per-holder [`crate::Signer`] adapter that
//!   accepts a single trusted-dealer share + the group's aggregated
//!   public key and, on `sign`, returns a wire-encoded
//!   [`PartialSignature`].
//! * [`aggregate`] — a free function that recovers a threshold signature
//!   from M-of-N wire-encoded partials.
//! * [`verify`] — verify an already-aggregated threshold signature against
//!   the group's aggregated public key.
//!
//! The signer is currently **trusted-dealer-style**: a single party
//! runs `commonware-cryptography::bls12381::dkg::feldman_desmedt::deal_anonymous` and
//! hands each holder their share. A future revision may replace the
//! dealer with a proper DKG ceremony; the signer adapter is API-stable
//! because the dealer/DKG choice only affects how shares are produced,
//! not how they're consumed at sign time.
//!
//! ## Variant
//!
//! We pin the [`MinSig`] variant: signature in G1 (48 bytes), public
//! key in G2 (96 bytes). A "release party" produces one signature per
//! release that ships in the SLSA bundle, so we minimise the
//! signature side; the public key is registered once in the verifier
//! trust root and amortised across every release. This matches the
//! convention in the upstream threshold examples.
//!
//! ## Namespace
//!
//! BLS signing in commonware takes a namespace separate from the
//! message body; the on-curve hash is `union_unique(namespace, message)`
//! with the BLS DST. We use [`NAMESPACE`] = `b"mkit-attest/dsse/v1"`
//! so a release-party signature can't be replayed against an arbitrary
//! BLS verifier that happens to share the maintainer key.

use commonware_codec::{DecodeExt, Encode as _};
use commonware_cryptography::bls12381::dkg;
use commonware_cryptography::bls12381::primitives::group::Share;
use commonware_cryptography::bls12381::primitives::ops::{self, threshold};
use commonware_cryptography::bls12381::primitives::sharing::{Mode, Sharing};
use commonware_cryptography::bls12381::primitives::variant::{MinSig, PartialSignature, Variant};
use commonware_parallel::Sequential;
use commonware_utils::{Faults, N3f1};

use crate::Error;
use crate::algorithm::Algorithm;
use crate::signer::Signer;

/// DSSE namespace for mkit threshold signatures.
///
/// BLS signatures are domain-separated by hash-to-curve DST plus a
/// caller namespace. The DST is fixed by the curve (`MinSig` =
/// `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_`); the namespace below
/// stops a maintainer-set BLS key from being abused to sign arbitrary
/// messages outside the attestation flow. v1 is fixed for the duration
/// of Protocol v1; a future Protocol v2 bumps it.
pub const NAMESPACE: &[u8] = b"mkit-attest/dsse/v1";

/// Pinned variant. See module docs.
pub type V = MinSig;

/// Wire size of a `MinSig` aggregated signature (G1 compressed).
const SIGNATURE_SIZE: usize = 48;

/// Wire size of a `MinSig` group public key (G2 compressed).
pub const PUBLIC_KEY_SIZE: usize = 96;

/// Keyid prefix for BLS12-381 threshold-aggregated keys. The body is
/// the hex-encoded G2 compressed public key (192 hex chars), so the
/// full keyid is 13 + 192 = 205 chars.
pub const KEYID_PREFIX: &str = "bls12381-thr:";

/// A holder's threshold-signing adapter.
///
/// One [`ThresholdSigner`] per share. The aggregator never holds an
/// instance — it only sees serialised partial signatures coming back
/// from holders. The `sign` impl returns the partial signature
/// serialised via [`commonware_codec::Encode`] (so it can travel as
/// raw bytes through DSSE / a coordination channel) — call
/// [`aggregate`] to recover the threshold signature from M-of-N
/// partials.
#[derive(Debug)]
pub struct ThresholdSigner {
    /// This holder's private share (index + scalar).
    share: Share,
    /// The whole-cohort `Sharing` (public polynomial, mode, total).
    /// Held by every holder; it's the public-side material the dealer
    /// hands out alongside the share.
    sharing: Sharing<V>,
    /// Cached keyid (`bls12381-thr:<hex of compressed G2 pubkey>`).
    /// Computed once at construction so `keyid()` is allocation-free
    /// on the hot path.
    keyid: String,
}

impl ThresholdSigner {
    /// Construct a holder-side signer from a trusted-dealer share +
    /// the cohort's public sharing.
    ///
    /// The dealer is expected to have produced `(sharing, shares)` via
    /// [`commonware_cryptography::bls12381::dkg::feldman_desmedt::deal_anonymous`]
    /// (current trusted-dealer mode) or a future DKG protocol. The dealer
    /// hands the same `sharing` to every holder, plus one `Share` per
    /// holder.
    #[must_use]
    pub fn new(share: Share, sharing: Sharing<V>) -> Self {
        let pk_hex = mkit_core::to_hex_bytes(&sharing.public().encode());
        let keyid = format!("{KEYID_PREFIX}{pk_hex}");
        Self {
            share,
            sharing,
            keyid,
        }
    }

    /// Return the cohort's aggregated G2 public key (96 bytes,
    /// compressed — [`PUBLIC_KEY_SIZE`]). Verifier consumers register
    /// this under the keyid returned by [`Self::keyid`].
    #[must_use]
    pub fn aggregate_public_key(&self) -> Vec<u8> {
        self.sharing.public().encode().to_vec()
    }
}

impl Signer for ThresholdSigner {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Bls12381Threshold
    }

    fn keyid(&self) -> Result<String, Error> {
        Ok(self.keyid.clone())
    }

    fn sign(&mut self, pae: &[u8]) -> Result<Vec<u8>, Error> {
        let partial = threshold::sign_message::<V>(&self.share, NAMESPACE, pae);
        Ok(partial.encode().to_vec())
    }
}

/// Aggregate M-of-N wire-encoded partial signatures into a single
/// threshold signature.
///
/// `sharing` is the cohort's public polynomial — the same one held by
/// every signer. Uses the [`N3f1`] fault model (threshold =
/// quorum, i.e. ceil(2n/3) — matches the upstream tests).
///
/// # Errors
/// * [`Error::BlsThresholdPartialDecode`] — one or more `partials`
///   entries are not a valid wire-encoded [`PartialSignature`].
/// * [`Error::BlsThresholdInsufficientPartials`] — fewer than
///   `threshold` distinct partials were supplied, or the recovery
///   failed (e.g. duplicate indices).
pub fn aggregate(sharing: &Sharing<V>, partials: &[Vec<u8>]) -> Result<Vec<u8>, Error> {
    // Decode each partial. Any malformed entry kills the aggregate —
    // we deliberately don't best-effort, because the aggregator is
    // expected to have already verified each partial individually
    // (the future release-party CLI does this) and a bad partial
    // at aggregate time is a protocol violation, not a transient.
    let mut decoded: Vec<PartialSignature<V>> = Vec::with_capacity(partials.len());
    for p in partials {
        let ps = PartialSignature::<V>::decode(p.as_slice())
            .map_err(|_| Error::BlsThresholdPartialDecode)?;
        decoded.push(ps);
    }

    let sig = threshold::recover::<V, _, N3f1>(sharing, &decoded, &Sequential)
        .map_err(|_| Error::BlsThresholdInsufficientPartials)?;

    Ok(sig.encode().to_vec())
}

/// Verify an aggregated threshold signature against the cohort's
/// group public key.
///
/// `aggregate_pubkey` is the G2 compressed public key returned by
/// [`ThresholdSigner::aggregate_public_key`] (96 bytes). `signature`
/// is a G1 compressed encoding (48 bytes) in the pinned `MinSig`
/// variant. `message` is the same PAE the holders signed.
///
/// # Errors
/// * [`Error::BlsThresholdPublicKeyDecode`] — `aggregate_pubkey` is
///   not a valid G2 compressed encoding (wrong length, off-curve, etc.).
/// * [`Error::BlsThresholdSignatureDecode`] — `signature` is not a
///   valid G1 compressed encoding (wrong length, off-curve, etc.).
/// * [`Error::BlsThresholdVerifyFailed`] — the signature is well-
///   formed but does not verify against `aggregate_pubkey`.
pub fn verify(aggregate_pubkey: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
    if aggregate_pubkey.len() != PUBLIC_KEY_SIZE {
        return Err(Error::BlsThresholdPublicKeyDecode);
    }
    let pk = <V as Variant>::Public::decode(aggregate_pubkey)
        .map_err(|_| Error::BlsThresholdPublicKeyDecode)?;
    if signature.len() != SIGNATURE_SIZE {
        return Err(Error::BlsThresholdSignatureDecode);
    }
    let sig = <V as Variant>::Signature::decode(signature)
        .map_err(|_| Error::BlsThresholdSignatureDecode)?;
    ops::verify_message::<V>(&pk, NAMESPACE, message, &sig)
        .map_err(|_| Error::BlsThresholdVerifyFailed)
}

/// Trusted-dealer helper: build a cohort of `n` holders with
/// the [`N3f1`] threshold (quorum = ceil(2n/3) per the fault model).
///
/// This is the dealer side of the trusted-dealer ceremony. A future
/// revision may replace it with a DKG protocol; the holder-side API
/// ([`ThresholdSigner`], [`aggregate`], [`verify`]) is stable across
/// that swap. Exposed for tests and a future release-party dealer
/// binary.
#[must_use]
pub fn trusted_dealer<R: rand_core::CryptoRng>(
    rng: &mut R,
    n: core::num::NonZeroU32,
) -> (Sharing<V>, Vec<Share>) {
    dkg::feldman_desmedt::deal_anonymous::<V, N3f1>(rng, Mode::default(), n)
}

/// N3f1-quorum threshold for `n` holders under the N3f1 fault model.
/// Helper for tests and the future release-party CLI.
#[must_use]
pub fn threshold_for(n: u32) -> u32 {
    N3f1::quorum(n)
}

// Hex encoding goes through the workspace-canonical
// `mkit_core::hash::to_hex_bytes`; nothing BLS-specific here.

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::{NZU32, TestRng};

    /// Helper: deal a 3-of-? cohort. The N3f1 fault model with n=3
    /// gives quorum = 3 (no faults tolerated at n=3), so we use n=4
    /// to get a 3-of-4 cohort for the threshold tests. With n=4,
    /// `max_faults` = 1, quorum = 3.
    fn deal_3_of_4() -> (Sharing<V>, Vec<Share>) {
        let mut rng = TestRng::new(0x4242);
        trusted_dealer(&mut rng, NZU32!(4))
    }

    /// #505 PR 5/5: split from the former `roundtrip_3_of_4_aggregates_and_verifies`
    /// mega-test. Every holder's `keyid()` contract (algorithm, prefix,
    /// exact length, and — the whole point of threshold signing — every
    /// holder reporting the SAME keyid) is asserted here in isolation, so
    /// a keyid-contract regression can't mask (or be masked by) a failure
    /// in the sign/aggregate/verify crypto path exercised by
    /// `threshold_3_of_4_aggregate_recovers_verifying_signature` below.
    #[test]
    fn threshold_3_of_4_keyids_share_one_public_identity() {
        let (sharing, shares) = deal_3_of_4();
        assert_eq!(threshold_for(4), 3);

        let expected_kid = format!(
            "{KEYID_PREFIX}{}",
            mkit_core::to_hex_bytes(&sharing.public().encode())
        );
        for s in shares.iter().take(3) {
            let signer = ThresholdSigner::new(s.clone(), sharing.clone());
            assert_eq!(signer.algorithm(), Algorithm::Bls12381Threshold);
            let kid = signer.keyid().expect("keyid");
            assert!(kid.starts_with(KEYID_PREFIX));
            assert_eq!(kid.len(), KEYID_PREFIX.len() + PUBLIC_KEY_SIZE * 2);
            // Every holder reports the SAME keyid — that's the whole
            // point of threshold signing: one public identity.
            assert_eq!(kid, expected_kid);
        }
    }

    /// #505 PR 5/5: split from the former `roundtrip_3_of_4_aggregates_and_verifies`
    /// mega-test — the crypto path in isolation, with no interspersed
    /// keyid assertions to mask it: 3 of 4 holders sign a PAE; aggregate;
    /// the recovered threshold signature verifies against the cohort
    /// public key.
    #[test]
    fn threshold_3_of_4_aggregate_recovers_verifying_signature() {
        let (sharing, shares) = deal_3_of_4();

        // PAE the holders sign. The actual DSSE PAE shape doesn't
        // matter to BLS — it treats it as opaque bytes — but pinning
        // it to a representative DSSE PAE prefix is a regression
        // guard if the namespace ever moves.
        let pae = b"DSSEv1 28 application/vnd.in-toto+json 12 release v0.2.0";

        // Each of the first 3 holders produces a partial.
        let mut partials_bytes: Vec<Vec<u8>> = Vec::with_capacity(3);
        for s in shares.iter().take(3) {
            let mut signer = ThresholdSigner::new(s.clone(), sharing.clone());
            let bytes = signer.sign(pae).expect("sign partial");
            partials_bytes.push(bytes);
        }

        // Aggregator combines partials. Aggregated signature is the
        // 48-byte G1 compressed form.
        let agg_sig = aggregate(&sharing, &partials_bytes).expect("aggregate");
        assert_eq!(agg_sig.len(), SIGNATURE_SIZE);

        // Verify against the group public key.
        let pk = sharing.public().encode().to_vec();
        assert_eq!(pk.len(), PUBLIC_KEY_SIZE);
        verify(&pk, pae, &agg_sig).expect("aggregated signature verifies");
    }

    /// `verify`'s length gates run before any decode/pairing work is
    /// attempted (SPEC-RELEASE-THRESHOLD §4). Feed a wrong-length
    /// aggregate signature (not `SIGNATURE_SIZE` = 48 bytes) directly
    /// and confirm it is rejected as a decode failure, never reaching
    /// pairing — a well-formed public key alone is enough to observe
    /// this, since the signature-length check runs unconditionally.
    #[test]
    fn verify_rejects_wrong_length_signature_before_pairing() {
        let (sharing, _shares) = deal_3_of_4();
        let pk = sharing.public().encode().to_vec();
        let pae = b"DSSEv1 4 test 2 hi";

        for len in [0, 1, SIGNATURE_SIZE - 1, SIGNATURE_SIZE + 1, 128] {
            let bogus_sig = vec![0u8; len];
            assert!(
                matches!(
                    verify(&pk, pae, &bogus_sig),
                    Err(Error::BlsThresholdSignatureDecode)
                ),
                "signature length {len} (!= {SIGNATURE_SIZE}) must be rejected before pairing"
            );
        }
    }

    /// Same gate on the other operand: a wrong-length cohort public
    /// key (not `PUBLIC_KEY_SIZE` = 96 bytes) must be rejected before
    /// any pairing work — even paired with an otherwise well-formed
    /// signature.
    #[test]
    fn verify_rejects_wrong_length_cohort_key_before_pairing() {
        let (sharing, shares) = deal_3_of_4();
        let pae = b"DSSEv1 4 test 2 hi";
        let mut partials_bytes: Vec<Vec<u8>> = Vec::with_capacity(3);
        for s in shares.iter().take(3) {
            let mut signer = ThresholdSigner::new(s.clone(), sharing.clone());
            partials_bytes.push(signer.sign(pae).expect("partial"));
        }
        let agg_sig = aggregate(&sharing, &partials_bytes).expect("aggregate");

        for len in [0, 1, PUBLIC_KEY_SIZE - 1, PUBLIC_KEY_SIZE + 1, 256] {
            let bogus_pk = vec![0u8; len];
            assert!(
                matches!(
                    verify(&bogus_pk, pae, &agg_sig),
                    Err(Error::BlsThresholdPublicKeyDecode)
                ),
                "public key length {len} (!= {PUBLIC_KEY_SIZE}) must be rejected before pairing"
            );
        }
    }

    /// The DSSE namespace literal used for domain separation appears
    /// once in code and is shared by `ThresholdSigner::sign` and
    /// `verify`, so an accidental edit to one call site (but not the
    /// other) would re-verify against itself internally and pass every
    /// other test in this module. Pin the exact bytes directly.
    #[test]
    fn namespace_literal_is_pinned() {
        assert_eq!(NAMESPACE, b"mkit-attest/dsse/v1");
    }

    /// Insufficient threshold (1 of 4) returns
    /// `BlsThresholdInsufficientPartials` rather than producing a
    /// signature that would fail verify downstream.
    #[test]
    fn insufficient_threshold_returns_error() {
        let (sharing, shares) = deal_3_of_4();
        let pae = b"DSSEv1 4 test 2 hi";

        // One partial — below threshold of 3.
        let mut signer = ThresholdSigner::new(shares[0].clone(), sharing.clone());
        let only = signer.sign(pae).expect("partial");
        let partials = vec![only];

        match aggregate(&sharing, &partials) {
            Err(Error::BlsThresholdInsufficientPartials) => {}
            other => panic!("expected BlsThresholdInsufficientPartials, got {other:?}"),
        }
    }

    /// Two of three insufficient: with n=4 the quorum is 3, so 2
    /// partials must also fail.
    #[test]
    fn two_of_four_also_insufficient() {
        let (sharing, shares) = deal_3_of_4();
        let pae = b"DSSEv1 4 test 2 hi";

        let mut partials_bytes: Vec<Vec<u8>> = Vec::with_capacity(2);
        for s in shares.iter().take(2) {
            let mut signer = ThresholdSigner::new(s.clone(), sharing.clone());
            partials_bytes.push(signer.sign(pae).expect("partial"));
        }

        assert!(matches!(
            aggregate(&sharing, &partials_bytes),
            Err(Error::BlsThresholdInsufficientPartials)
        ));
    }

    /// Tamper: flip a bit inside one partial. Decoding may succeed
    /// (the bytes still decode as a G2 point) but the recovered
    /// aggregate must fail verify. We assert verify fails — the
    /// crypto semantics are what matter.
    #[test]
    fn tampered_partial_fails_aggregate_verify() {
        let (sharing, shares) = deal_3_of_4();
        let pae = b"DSSEv1 28 application/vnd.in-toto+json 2 {}";

        let mut partials_bytes: Vec<Vec<u8>> = Vec::with_capacity(3);
        for s in shares.iter().take(3) {
            let mut signer = ThresholdSigner::new(s.clone(), sharing.clone());
            partials_bytes.push(signer.sign(pae).expect("partial"));
        }

        // Flip a bit in the *value* half of partial 1 (skip the
        // Participant index prefix at the front).
        //
        // PartialSignature wire form: <index><signature_bytes>. The
        // index is a small fixed-size prefix (4 bytes); we mutate
        // well past it so we're guaranteed to hit the signature.
        let last = partials_bytes[1].len() - 1;
        partials_bytes[1][last] ^= 0x01;

        // Either: decode fails outright (bad encoding) — that's
        // BlsThresholdPartialDecode, which is also a valid tamper
        // outcome. OR: decode succeeds but verify fails. Both are
        // acceptable rejections; what we care about is that the
        // tampered aggregate is NOT accepted.
        match aggregate(&sharing, &partials_bytes) {
            Err(Error::BlsThresholdPartialDecode) => {
                // Decoder caught the tamper. Done.
            }
            Ok(agg_sig) => {
                let pk = sharing.public().encode().to_vec();
                assert!(
                    matches!(
                        verify(&pk, pae, &agg_sig),
                        Err(Error::BlsThresholdVerifyFailed)
                    ),
                    "tampered partial must not produce a verifying aggregate"
                );
            }
            other => panic!("unexpected aggregate result on tampered partial: {other:?}"),
        }
    }

    /// Tamper on the message: a signature aggregated over `pae_signed`
    /// must not verify against a different `pae_other`. Crypto sanity
    /// — paired with the tampered-partial test above to cover both
    /// sides.
    #[test]
    fn aggregated_signature_does_not_verify_wrong_message() {
        let (sharing, shares) = deal_3_of_4();
        let pae_signed = b"DSSEv1 1 a 1 b";
        let pae_other = b"DSSEv1 1 a 1 c";

        let mut partials_bytes: Vec<Vec<u8>> = Vec::with_capacity(3);
        for s in shares.iter().take(3) {
            let mut signer = ThresholdSigner::new(s.clone(), sharing.clone());
            partials_bytes.push(signer.sign(pae_signed).expect("partial"));
        }
        let agg_sig = aggregate(&sharing, &partials_bytes).expect("aggregate");
        let pk = sharing.public().encode().to_vec();

        verify(&pk, pae_signed, &agg_sig).expect("signed message verifies");
        match verify(&pk, pae_other, &agg_sig) {
            Err(Error::BlsThresholdVerifyFailed) => {}
            other => panic!("expected verify failure on wrong message, got {other:?}"),
        }
    }

    /// Algorithm enum integration: build a `SignerFrame` carrying
    /// `algorithm = ALGORITHM_BLS12381_THRESHOLD` and round-trip it
    /// through the buffa codegen — the variant survives.
    ///
    /// This guards against the proto enum integer drifting (5) and
    /// confirms the new variant is wired through `mkit-rpc`'s codegen.
    #[test]
    fn algorithm_enum_round_trips_through_buffa() {
        use buffa::Message;
        use mkit_rpc::mkit::rpc::v1::Algorithm as RpcAlgorithm;
        use mkit_rpc::mkit::rpc::v1::signer::{SignRequest, SignerFrame, signer_frame};

        let frame = SignerFrame {
            body: Some(signer_frame::Body::SignRequest(Box::new(
                SignRequest::default()
                    .with_algorithm(RpcAlgorithm::Bls12381Threshold)
                    .with_payload(b"DSSEv1 1 a 1 b".to_vec()),
            ))),
            ..Default::default()
        };

        let bytes = frame.encode_to_vec();
        let decoded = SignerFrame::decode(&mut &bytes[..]).expect("decode");
        let Some(signer_frame::Body::SignRequest(req)) = decoded.body else {
            panic!("expected SignRequest body");
        };
        assert_eq!(req.algorithm, Some(RpcAlgorithm::Bls12381Threshold.into()),);
        // Pin the wire integer: this test fails if anyone renumbers
        // the enum.
        assert_eq!(RpcAlgorithm::Bls12381Threshold as i32, 5);
    }
}
