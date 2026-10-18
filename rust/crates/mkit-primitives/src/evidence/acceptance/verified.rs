//! Bounded export from private in-process artifacts; no artifact wire form.

use super::{
    AcceptanceEvidence, AcceptanceEvidenceDecodeCfg, HeadFact, MembershipWitness, PackFacts,
    Result, cap, checked_head, failure, limit,
};
use crate::{
    closure::{
        self, ClosureProof,
        output::{PageDecodeCfg, decode_witness},
    },
    error::FailureCode,
    evidence::{RepositoryId, RulesetBinding},
    pack_verify::VerifiedPack,
};
use mkit_core::hash::{Hash, ZERO};
use std::collections::HashSet;

/// Host operation binding. Membership and denial versions are separate observations.
#[derive(Clone, Copy)]
pub struct AcceptanceEvidenceBinding<'a> {
    /// Exact logical repository of the closure proof.
    pub repository: RepositoryId,
    /// Opaque operation identity, under the envelope's byte cap.
    pub operation: &'a [u8],
    /// Host replay epoch.
    pub epoch: u64,
}

/// Finite export budgets, independent of the immutable evidence format.
#[derive(Debug, Clone)]
pub struct AcceptanceEvidenceBuildCfg {
    /// Output caps, supported ruleset, and the host's profile/limits commitment.
    pub envelope: AcceptanceEvidenceDecodeCfg,
    /// Maximum supplied head occurrences, including duplicate requested heads.
    pub max_head_occurrences: u32,
    /// Maximum witness pages consumed, checked against the sealed proof count.
    pub max_witness_pages: u64,
    /// Shared cumulative witness-byte allowance; never reset between pages.
    pub max_total_witness_bytes: u64,
    /// Finite per-page authentication and decoding allowances.
    pub witness_page: PageDecodeCfg,
}

/// Borrowed canonical heads and a streaming acquisition of linked witness bytes.
///
/// Heads must preserve the closure's original requested order and duplicates.
/// Witnesses start at `ClosureProof::relied_on_members()` and follow `previous`.
/// The caller budgets input storage separately; witness pages need not be retained
/// together. The iterator is polled at most the committed count plus one times.
pub struct AcceptanceEvidenceInput<'a, I> {
    /// Canonical signed commit, remix, or tag bytes in closure request order.
    pub heads: &'a [&'a [u8]],
    /// Encoded witness pages in authenticated chain order.
    pub witness_pages: I,
}

impl std::fmt::Debug for AcceptanceEvidenceBinding<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcceptanceEvidenceBinding")
            .field("operation_len", &self.operation.len())
            .finish_non_exhaustive()
    }
}
impl<I> std::fmt::Debug for AcceptanceEvidenceInput<'_, I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcceptanceEvidenceInput")
            .field("head_occurrences", &self.heads.len())
            .finish_non_exhaustive()
    }
}

impl AcceptanceEvidence {
    /// Export checked bounded facts from sealed verification and closure artifacts.
    ///
    /// This authenticates canonical heads and the complete relied-on witness chain,
    /// checks cross-artifact roots, rulesets and repository, and takes pack facts
    /// only from `verified`. It never constructs or serializes either artifact.
    /// Host versions and the configured profile/limits commitment remain caller
    /// observations. Origin authentication, live guards and replay stay with the host.
    ///
    /// Supplied head occurrences share the cumulative head-byte cap, including
    /// duplicates. Scratch retains one bounded borrowed head table and a fallibly
    /// allocated set of at most `max_external_dependencies` supplier ids. Output
    /// construction temporarily holds at most two envelope-sized buffers; nested
    /// head decoding uses the same per-object bounds as `recheck_heads`. Witness
    /// work is linear in consumed bytes/count with bounded supplier-set operations.
    ///
    /// # Errors
    /// Returns binding/profile refusals for differing artifacts or requested heads,
    /// object/signature refusals for invalid heads, `InvalidResponse` for a missing,
    /// extra, reordered or unauthenticated witness page, and `ResourceLimit` for
    /// exhausted finite budgets or allocation.
    pub fn from_verified<P: AsRef<[u8]>>(
        verified: &VerifiedPack,
        proof: &ClosureProof,
        binding: AcceptanceEvidenceBinding<'_>,
        witness: MembershipWitness,
        denial_version: u64,
        input: AcceptanceEvidenceInput<'_, impl Iterator<Item = P>>,
        cfg: &AcceptanceEvidenceBuildCfg,
    ) -> Result<Self> {
        check_artifact_binding(
            verified.object_set_root(),
            verified.ruleset(),
            proof,
            binding,
            cfg,
        )?;
        cap(binding.operation.len(), cfg.envelope.max_operation_bytes)?;
        let heads = prepare_heads(input.heads, proof.heads_root(), cfg)?;
        let dependencies = supplier_ids(proof, input.witness_pages, cfg)?;
        let pack = PackFacts {
            id: verified.pack_id(),
            len: verified.len(),
            object_count: verified.counts().entries,
            delta_count: verified.counts().delta_entries,
            object_set_root: verified.object_set_root(),
        };
        encode(
            binding,
            witness,
            denial_version,
            pack,
            &heads,
            &dependencies,
            &cfg.envelope,
        )
    }
}

fn check_artifact_binding(
    object_set_root: Hash,
    ruleset: RulesetBinding,
    proof: &ClosureProof,
    binding: AcceptanceEvidenceBinding<'_>,
    cfg: &AcceptanceEvidenceBuildCfg,
) -> Result<()> {
    if ruleset != proof.ruleset() || ruleset.ruleset != cfg.envelope.ruleset_id {
        return Err(failure(FailureCode::EvidenceProfileMismatch));
    }
    if object_set_root != proof.object_set_root() || proof.repository() != binding.repository {
        return Err(failure(FailureCode::EvidenceBindingMismatch));
    }
    Ok(())
}

fn prepare_heads<'a>(
    bytes: &[&'a [u8]],
    expected_root: Hash,
    cfg: &AcceptanceEvidenceBuildCfg,
) -> Result<Vec<HeadFact<'a>>> {
    cap(bytes.len(), cfg.max_head_occurrences)?;
    let total = bytes.iter().try_fold(0u32, |total, bytes| {
        cap(bytes.len(), cfg.envelope.max_head_bytes)?;
        let len = u32::try_from(bytes.len()).map_err(|_| failure(FailureCode::ResourceLimit))?;
        total
            .checked_add(len)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))
    })?;
    limit(total, cfg.envelope.max_total_head_bytes)?;
    let mut heads = Vec::new();
    heads
        .try_reserve_exact(bytes.len())
        .map_err(|_| failure(FailureCode::ResourceLimit))?;
    for bytes in bytes {
        heads.push(checked_head(bytes, None)?);
    }
    if closure::heads_root(heads.iter().map(|head| head.object_id))? != expected_root {
        return Err(failure(FailureCode::EvidenceBindingMismatch));
    }
    heads.sort_unstable_by_key(|head| head.object_id);
    heads.dedup_by_key(|head| head.object_id);
    cap(heads.len(), cfg.envelope.max_heads)?;
    Ok(heads)
}

fn supplier_ids<P: AsRef<[u8]>>(
    proof: &ClosureProof,
    mut pages: impl Iterator<Item = P>,
    cfg: &AcceptanceEvidenceBuildCfg,
) -> Result<Vec<Hash>> {
    let sequence = proof.external_witnesses();
    if sequence.count > cfg.max_witness_pages {
        return Err(failure(FailureCode::ResourceLimit));
    }
    let mut next = proof.relied_on_members();
    if next.map_or(ZERO, |page| page.digest) != sequence.root {
        return Err(failure(FailureCode::EvidenceBindingMismatch));
    }
    let mut suppliers = HashSet::new();
    let mut total_bytes = 0u64;
    for _ in 0..sequence.count {
        let page = next.ok_or_else(|| failure(FailureCode::InvalidResponse))?;
        let acquired = pages
            .next()
            .ok_or_else(|| failure(FailureCode::InvalidResponse))?;
        let bytes = acquired.as_ref();
        total_bytes = total_bytes
            .checked_add(
                u64::try_from(bytes.len()).map_err(|_| failure(FailureCode::ResourceLimit))?,
            )
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        if total_bytes > cfg.max_total_witness_bytes {
            return Err(failure(FailureCode::ResourceLimit));
        }
        let decoded = decode_witness(page, bytes, cfg.witness_page)?;
        // Defense in depth: the page digest already binds every fact byte.
        if decoded.fact.repository != proof.repository() || decoded.fact.incarnation != proof.view()
        {
            return Err(failure(FailureCode::EvidenceBindingMismatch));
        }
        let supplier = decoded.fact.supplier.id;
        if !suppliers.contains(&supplier) {
            let count =
                u32::try_from(suppliers.len()).map_err(|_| failure(FailureCode::ResourceLimit))?;
            if count >= cfg.envelope.max_external_dependencies {
                return Err(failure(FailureCode::ResourceLimit));
            }
            suppliers
                .try_reserve(1)
                .map_err(|_| failure(FailureCode::ResourceLimit))?;
            suppliers.insert(supplier);
        }
        next = decoded.previous;
    }
    if next.is_some() || pages.next().is_some() {
        return Err(failure(FailureCode::InvalidResponse));
    }
    let mut sorted = Vec::new();
    sorted
        .try_reserve_exact(suppliers.len())
        .map_err(|_| failure(FailureCode::ResourceLimit))?;
    sorted.extend(suppliers);
    sorted.sort_unstable();
    Ok(sorted)
}

fn encode(
    binding: AcceptanceEvidenceBinding<'_>,
    witness: MembershipWitness,
    denial_version: u64,
    pack: PackFacts,
    heads: &[HeadFact<'_>],
    dependencies: &[Hash],
    cfg: &AcceptanceEvidenceDecodeCfg,
) -> Result<AcceptanceEvidence> {
    let mut len = 206u64 + binding.operation.len() as u64;
    for head in heads {
        len = len
            .checked_add(70 + head.canonical_bytes.len() as u64)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
    }
    len = len
        .checked_add(dependencies.len() as u64 * 32)
        .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
    if len > u64::from(cfg.max_envelope_bytes) {
        return Err(failure(FailureCode::ResourceLimit));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(usize::try_from(len).map_err(|_| failure(FailureCode::ResourceLimit))?)
        .map_err(|_| failure(FailureCode::ResourceLimit))?;
    bytes.extend_from_slice(b"MKAE");
    bytes.extend_from_slice(&super::FORMAT_VERSION.to_le_bytes());
    bytes.extend_from_slice(&cfg.ruleset_id.0.to_le_bytes());
    bytes.extend_from_slice(&cfg.profile_limits_digest);
    bytes.extend_from_slice(&binding.repository.0);
    let count = |n| u32::try_from(n).map_err(|_| failure(FailureCode::ResourceLimit));
    bytes.extend_from_slice(&count(binding.operation.len())?.to_le_bytes());
    bytes.extend_from_slice(binding.operation);
    bytes.extend_from_slice(&binding.epoch.to_le_bytes());
    bytes.extend_from_slice(&pack.id);
    bytes.extend_from_slice(&pack.len.to_le_bytes());
    bytes.extend_from_slice(&pack.object_count.to_le_bytes());
    bytes.extend_from_slice(&pack.delta_count.to_le_bytes());
    bytes.extend_from_slice(&pack.object_set_root);
    bytes.extend_from_slice(&count(heads.len())?.to_le_bytes());
    for head in heads {
        bytes.extend_from_slice(&head.object_id);
        bytes.push(head.kind as u8);
        bytes.extend_from_slice(&head.signer);
        bytes.push(1);
        bytes.extend_from_slice(&count(head.canonical_bytes.len())?.to_le_bytes());
        bytes.extend_from_slice(head.canonical_bytes);
    }
    bytes.extend_from_slice(&count(dependencies.len())?.to_le_bytes());
    for dependency in dependencies {
        bytes.extend_from_slice(dependency);
    }
    bytes.extend_from_slice(&witness.generation.to_le_bytes());
    bytes.extend_from_slice(&witness.removal_version.to_le_bytes());
    bytes.extend_from_slice(&denial_version.to_le_bytes());
    AcceptanceEvidence::decode(&bytes, cfg)
}

#[cfg(test)]
mod tests;
