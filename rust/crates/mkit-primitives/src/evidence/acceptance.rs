//! Canonical cross-process facts from a trusted verifier host.
//!
//! These bytes are not an attestation and cannot construct verified packs,
//! closure proofs, or guarded decisions. See SPEC-ACCEPTANCE-EVIDENCE.

use super::{RepositoryId, RulesetId};
use crate::error::{BoundedDetail, Failure, FailureCode, Location};
use mkit_core::{
    hash,
    object::{Object, ObjectType},
};

mod verified;
pub use verified::{
    AcceptanceEvidenceBinding, AcceptanceEvidenceBuildCfg, AcceptanceEvidenceInput,
};

/// Evidence format version, independent of crate and ruleset versions.
pub const FORMAT_VERSION: u16 = 1;
/// Permanent digest domain; followed by one NUL byte and canonical encoding.
pub const DIGEST_DOMAIN: &[u8] = b"mkit-acceptance-evidence:v1";

/// Explicit finite decode and recheck limits. Zero permits no corresponding data.
#[derive(Clone, Debug)]
pub struct AcceptanceEvidenceDecodeCfg {
    /// Maximum canonical envelope bytes, including fixed fields.
    pub max_envelope_bytes: u32,
    /// Maximum opaque operation identifier bytes.
    pub max_operation_bytes: u32,
    /// Maximum number of unique heads.
    pub max_heads: u32,
    /// Maximum canonical bytes of one head.
    pub max_head_bytes: u32,
    /// Maximum sum of canonical head byte lengths.
    pub max_total_head_bytes: u32,
    /// Maximum number of unique relied-on member packs.
    pub max_external_dependencies: u32,
    /// Only this normative ruleset is accepted.
    pub ruleset_id: RulesetId,
    /// Only this profile and effective-limits digest is accepted.
    pub profile_limits_digest: hash::Hash,
}

/// Pack summary, without an object-count-sized member list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackFacts {
    /// Whole-pack content address.
    pub id: hash::Hash,
    /// Exact frozen pack length.
    pub len: u64,
    /// Number of entries, including duplicate occurrences.
    pub object_count: u64,
    /// Number of delta entries; at most the object count.
    pub delta_count: u64,
    /// Object-set commitment produced by verification.
    pub object_set_root: hash::Hash,
}

/// Live membership versions the writer must guard atomically.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MembershipWitness {
    /// Membership incarnation.
    pub generation: u64,
    /// Removal version.
    pub removal_version: u64,
}

/// Signature outcome recorded by the trusted verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureResult {
    /// An individual signature verified successfully.
    Valid,
}

/// A borrowed canonical head record. Its facts are host assertions until rechecked.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HeadFact<'a> {
    /// Canonical object id.
    pub object_id: hash::Hash,
    /// Core object kind: commit, remix, or tag.
    pub kind: ObjectType,
    /// Embedded Ed25519 signer key.
    pub signer: [u8; 32],
    /// Recorded individual signature result.
    pub signature_result: SignatureResult,
    /// Canonical head object, including its signature.
    pub canonical_bytes: &'a [u8],
}

/// Strictly decoded, immutable evidence envelope. Authentication remains the host's job.
#[must_use]
#[derive(PartialEq, Eq)]
pub struct AcceptanceEvidence {
    bytes: Vec<u8>,
    ruleset_id: RulesetId,
    profile_limits_digest: hash::Hash,
    repository: RepositoryId,
    operation: std::ops::Range<usize>,
    epoch: u64,
    pack: PackFacts,
    heads: std::ops::Range<usize>,
    dependencies: std::ops::Range<usize>,
    witness: MembershipWitness,
    denial_version: u64,
}

impl std::fmt::Debug for HeadFact<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeadFact")
            .field("kind", &self.kind)
            .field("signature_result", &self.signature_result)
            .field("canonical_len", &self.canonical_bytes.len())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for AcceptanceEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcceptanceEvidence")
            .field("encoded_len", &self.bytes.len())
            .field("ruleset_id", &self.ruleset_id)
            .finish_non_exhaustive()
    }
}

type Result<T> = std::result::Result<T, Failure>;

fn failure(code: FailureCode) -> Failure {
    Failure {
        code,
        location: Location::default(),
        detail: BoundedDetail::None,
    }
}

impl AcceptanceEvidence {
    /// Decode canonical bytes with explicit limits, without authenticating their origin.
    ///
    /// Decoding performs no trust step: it does not authenticate the sender. The
    /// host must establish that the complete envelope came from its trusted verifier
    /// in the same trust domain. It is not a remote attestation, and a digest alone
    /// provides no authentication. The writer must check the frozen binding and live
    /// membership/denial guards.
    ///
    /// The caller budgets its already allocated input separately. The decoder retains
    /// exactly one envelope copy and constant metadata. Work is linear in input bytes
    /// and record counts; no pack pages or object-set members are accessed.
    /// Nested object validity and head metadata are checked by [`Self::recheck_heads`].
    ///
    /// # Examples
    /// ```
    /// use mkit_primitives::evidence::{RepositoryId, RulesetId, acceptance::{
    ///     AcceptanceEvidence, AcceptanceEvidenceDecodeCfg,
    /// }};
    /// let cfg = AcceptanceEvidenceDecodeCfg {
    ///     max_envelope_bytes: 206, max_operation_bytes: 0, max_heads: 0,
    ///     max_head_bytes: 0, max_total_head_bytes: 0,
    ///     max_external_dependencies: 0, ruleset_id: RulesetId(1),
    ///     profile_limits_digest: [0; 32],
    /// };
    /// // Minimal envelope: empty operation, heads, and dependencies.
    /// let mut bytes = vec![0; 206];
    /// bytes[..4].copy_from_slice(b"MKAE");
    /// bytes[4..6].copy_from_slice(&1_u16.to_le_bytes());
    /// bytes[6..10].copy_from_slice(&1_u32.to_le_bytes());
    /// let evidence = AcceptanceEvidence::decode(&bytes, &cfg)?;
    /// evidence.check_binding(&[0; 32], 0, &RepositoryId([0; 32]), &[], 0)?;
    /// assert_eq!(evidence.encode(), bytes);
    /// # Ok::<(), mkit_primitives::error::Failure>(())
    /// ```
    ///
    /// # Errors
    /// Rejects oversize, unsupported, truncated, unordered, duplicate, contradictory,
    /// unknown-tag, profile-mismatched, or trailing data before retaining any copy.
    pub fn decode(bytes: &[u8], cfg: &AcceptanceEvidenceDecodeCfg) -> Result<Self> {
        cap(bytes.len(), cfg.max_envelope_bytes)?;
        let mut r = Cursor::new(bytes);
        if r.take(4)? != b"MKAE" {
            return Err(failure(FailureCode::NonCanonicalEvidence));
        }
        if r.u16()? != FORMAT_VERSION {
            return Err(failure(FailureCode::UnsupportedEvidenceVersion));
        }
        let ruleset_id = RulesetId(r.u32()?);
        let profile_limits_digest = r.fixed()?;
        if ruleset_id != cfg.ruleset_id || profile_limits_digest != cfg.profile_limits_digest {
            return Err(failure(FailureCode::EvidenceProfileMismatch));
        }
        let repository = RepositoryId(r.fixed()?);
        let operation = r.variable_range(cfg.max_operation_bytes)?;
        let epoch = r.u64()?;
        let pack = PackFacts {
            id: r.fixed()?,
            len: r.u64()?,
            object_count: r.u64()?,
            delta_count: r.u64()?,
            object_set_root: r.fixed()?,
        };
        if pack.delta_count > pack.object_count {
            return Err(failure(FailureCode::NonCanonicalEvidence));
        }
        let count = r.u32()?;
        limit(count, cfg.max_heads)?;
        let head_start = r.pos;
        let mut previous = None;
        let mut total = 0_u32;
        for _ in 0..count {
            let head = r.head(cfg.max_head_bytes)?;
            if previous.is_some_and(|id| id >= head.object_id) {
                return Err(failure(FailureCode::NonCanonicalEvidence));
            }
            previous = Some(head.object_id);
            total = total
                .checked_add(
                    u32::try_from(head.canonical_bytes.len())
                        .map_err(|_| failure(FailureCode::ResourceLimit))?,
                )
                .ok_or(failure(FailureCode::ResourceLimit))?;
            limit(total, cfg.max_total_head_bytes)?;
        }
        let heads = head_start..r.pos;
        let count = r.u32()?;
        limit(count, cfg.max_external_dependencies)?;
        let dependency_start = r.pos;
        previous = None;
        for _ in 0..count {
            let id = r.fixed::<32>()?;
            if previous.is_some_and(|prev| prev >= id) {
                return Err(failure(FailureCode::NonCanonicalEvidence));
            }
            previous = Some(id);
        }
        let dependencies = dependency_start..r.pos;
        let witness = MembershipWitness {
            generation: r.u64()?,
            removal_version: r.u64()?,
        };
        let denial_version = r.u64()?;
        if r.pos != bytes.len() {
            return Err(failure(FailureCode::NonCanonicalEvidence));
        }
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| failure(FailureCode::ResourceLimit))?;
        owned.extend_from_slice(bytes);
        Ok(Self {
            bytes: owned,
            ruleset_id,
            profile_limits_digest,
            repository,
            operation,
            epoch,
            pack,
            heads,
            dependencies,
            witness,
            denial_version,
        })
    }

    /// Exact canonical encoding, with no embedded digest and no allocation.
    #[must_use]
    pub fn encode(&self) -> &[u8] {
        &self.bytes
    }

    /// Exact encoded size, already checked against the finite decode budget.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.bytes.len()
    }

    /// BLAKE3(domain || NUL || canonical encoding); no digest field is encoded.
    #[must_use]
    pub fn digest(&self) -> hash::Hash {
        let mut h = hash::Hasher::new();
        h.update(DIGEST_DOMAIN).update(&[0]).update(&self.bytes);
        h.finalize()
    }

    /// Check all replay bindings against the writer's immutable frozen record.
    ///
    /// # Errors
    /// Refuses any differing pack id, exact length, repository, operation, or epoch.
    pub fn check_binding(
        &self,
        frozen_pack_id: &hash::Hash,
        frozen_len: u64,
        repository: &RepositoryId,
        operation: &[u8],
        epoch: u64,
    ) -> Result<()> {
        if self.pack.id != *frozen_pack_id
            || self.pack.len != frozen_len
            || &self.repository != repository
            || self.operation() != operation
            || self.epoch != epoch
        {
            return Err(failure(FailureCode::EvidenceBindingMismatch));
        }
        Ok(())
    }

    /// Recompute every head id and individually verify its embedded signature.
    ///
    /// Processes one bounded head at a time with core's canonical decoder and serial
    /// verifier. Temporary decoded fields and signing bytes are bounded by that head's
    /// encoded length and core's parent/source caps. This neither verifies the pack nor
    /// establishes closure, authorization, current membership, or replay protection.
    ///
    /// # Errors
    /// Refuses malformed canonical objects, metadata/id mismatches, or bad signatures.
    pub fn recheck_heads(&self) -> Result<()> {
        for head in self.heads() {
            checked_head(head.canonical_bytes, Some(head))?;
        }
        Ok(())
    }

    /// Normative ruleset identifier.
    #[must_use]
    pub const fn ruleset_id(&self) -> RulesetId {
        self.ruleset_id
    }
    /// Profile and effective-limits commitment.
    #[must_use]
    pub const fn profile_limits_digest(&self) -> hash::Hash {
        self.profile_limits_digest
    }
    /// Opaque host repository identity.
    #[must_use]
    pub const fn repository(&self) -> RepositoryId {
        self.repository
    }
    /// Opaque host operation identity.
    #[must_use]
    pub fn operation(&self) -> &[u8] {
        &self.bytes[self.operation.clone()]
    }
    /// Replay epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
    /// Frozen pack summary.
    #[must_use]
    pub const fn pack(&self) -> PackFacts {
        self.pack
    }
    /// Membership versions to compare atomically at acceptance.
    #[must_use]
    pub const fn witness(&self) -> MembershipWitness {
        self.witness
    }
    /// Denial version to compare atomically at acceptance.
    #[must_use]
    pub const fn denial_version(&self) -> u64 {
        self.denial_version
    }
    /// Heads in strictly ascending object-id order.
    pub fn heads(&self) -> impl Iterator<Item = HeadFact<'_>> {
        let mut r = Cursor::new(&self.bytes[self.heads.clone()]);
        std::iter::from_fn(move || {
            if r.pos == r.bytes.len() {
                None
            } else {
                r.head(u32::MAX).ok()
            }
        })
    }
    /// Relied-on member pack ids in strictly ascending byte order.
    pub fn external_dependencies(&self) -> impl Iterator<Item = hash::Hash> + '_ {
        self.bytes[self.dependencies.clone()]
            .chunks_exact(32)
            .filter_map(|b| b.try_into().ok())
    }
}

fn checked_head<'a>(bytes: &'a [u8], expected: Option<HeadFact<'_>>) -> Result<HeadFact<'a>> {
    let object = mkit_core::serialize::deserialize(bytes)
        .map_err(|_| failure(FailureCode::NonCanonicalObject))?;
    let (kind, signer) = match &object {
        Object::Commit(c) => (ObjectType::Commit, c.signer),
        Object::Remix(c) => (ObjectType::Remix, c.signer),
        Object::Tag(c) => (ObjectType::Tag, c.signer),
        _ => return Err(failure(FailureCode::EvidenceHeadMismatch)),
    };
    let object_id = mkit_core::object::id_from_object(&object, bytes);
    if let Some(expected) = expected {
        if kind != expected.kind || signer != expected.signer {
            return Err(failure(FailureCode::EvidenceHeadMismatch));
        }
        if object_id != expected.object_id {
            return Err(failure(FailureCode::ObjectHashMismatch));
        }
    }
    mkit_core::sign::verify_object_signature(&object)
        .map_err(|_| failure(FailureCode::BadSignature))?;
    Ok(HeadFact {
        object_id,
        kind,
        signer,
        signature_result: SignatureResult::Valid,
        canonical_bytes: bytes,
    })
}

fn cap(actual: usize, maximum: u32) -> Result<()> {
    if u64::try_from(actual).map_err(|_| failure(FailureCode::ResourceLimit))? > u64::from(maximum)
    {
        return Err(failure(FailureCode::ResourceLimit));
    }
    Ok(())
}
fn limit(actual: u32, maximum: u32) -> Result<()> {
    if actual > maximum {
        return Err(failure(FailureCode::ResourceLimit));
    }
    Ok(())
}
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        // Check available bytes before adding offsets, so a missing u32::MAX
        // body has the same EOF classification on 32-bit and 64-bit targets.
        let remaining = self
            .bytes
            .get(self.pos..)
            .ok_or(failure(FailureCode::UnexpectedEof))?;
        let b = remaining
            .get(..n)
            .ok_or(failure(FailureCode::UnexpectedEof))?;
        self.pos = self
            .pos
            .checked_add(n)
            .ok_or(failure(FailureCode::ResourceLimit))?;
        Ok(b)
    }
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| failure(FailureCode::UnexpectedEof))
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.fixed()?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.fixed()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.fixed()?))
    }
    fn variable_range(&mut self, max: u32) -> Result<std::ops::Range<usize>> {
        let len = self.u32()?;
        limit(len, max)?;
        let start = self.pos;
        self.take(usize::try_from(len).map_err(|_| failure(FailureCode::ResourceLimit))?)?;
        Ok(start..self.pos)
    }
    fn head(&mut self, max: u32) -> Result<HeadFact<'a>> {
        let object_id = self.fixed()?;
        let kind = match self.take(1)?[0] {
            3 => ObjectType::Commit,
            4 => ObjectType::Remix,
            7 => ObjectType::Tag,
            _ => return Err(failure(FailureCode::NonCanonicalEvidence)),
        };
        let signer = self.fixed()?;
        if self.take(1)? != [1] {
            return Err(failure(FailureCode::NonCanonicalEvidence));
        }
        let range = self.variable_range(max)?;
        let canonical_bytes = &self.bytes[range];
        if canonical_bytes.first().copied() != Some(kind as u8) {
            return Err(failure(FailureCode::NonCanonicalEvidence));
        }
        Ok(HeadFact {
            object_id,
            kind,
            signer,
            signature_result: SignatureResult::Valid,
            canonical_bytes,
        })
    }
}
