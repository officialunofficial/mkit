//! Sealed acceptance basis: what a ticketed acceptance relied on.
//!
//! A ticketed advance is accepted only over a basis. The basis carries the
//! mutable facts that acceptance relied on, as typed guards the decision adds
//! to its guard set, so that no sealed artifact can be forgotten by a caller:
//!
//! - [`AcceptanceBasis::from_verified`] derives them from the sealed
//!   [`VerifiedPack`] and [`ClosureProof`] and the proof's relied-on witness
//!   chain;
//! - [`AcceptanceBasis::from_evidence`] derives them from decoded
//!   [`AcceptanceEvidence`], for a writer that never holds the artifacts;
//! - [`AcceptanceBasis::attested_by_host`] is the one explicit trust path for
//!   a host that verified with its own pipeline.
//!
//! Every constructor draws on the same [`RequiredGuard`] vocabulary, so a host
//! lowers any of them through one path. The type has private fields, no
//! public constructor, and no decoder: it cannot be built or deserialized
//! outside this crate.
//!
//! ```compile_fail
//! use mkit_primitives::decision::AcceptanceBasis;
//! fn forge() -> AcceptanceBasis {
//!     AcceptanceBasis { repository: mkit_primitives::evidence::RepositoryId([0; 32]), guards: vec![] }
//! }
//! ```

use super::{Observed, RequiredGuard};
use crate::{
    closure::{
        ClosureProof,
        output::{PageDecodeCfg, decode_witness},
        pair::PairCoverage,
    },
    error::{BoundedDetail, Failure, FailureCode, Location},
    evidence::{
        MemberFact, PackSource, RepositoryId,
        acceptance::{AcceptanceEvidence, MembershipWitness},
    },
    pack_verify::VerifiedPack,
};
use mkit_core::hash::{self, Hash, ZERO};
use std::collections::BTreeMap;

/// Permanent digest domain of the `from_verified` root binding.
pub const BASIS_DIGEST_DOMAIN: &[u8] = b"mkit-acceptance-basis:v1";

fn failure(code: FailureCode) -> Failure {
    Failure {
        code,
        location: Location::default(),
        detail: BoundedDetail::None,
    }
}

/// Hard ceiling on distinct relied-on dependencies one basis guards.
pub const MAX_BASIS_DEPENDENCIES: u32 = 4096;

/// Explicit finite allowances for deriving a basis from sealed artifacts.
#[derive(Debug, Clone, Copy)]
pub struct BasisCfg {
    /// Most witness pages consumed, checked against the sealed proof count.
    pub max_witness_pages: u64,
    /// Cumulative witness bytes; never reset between pages.
    pub max_total_witness_bytes: u64,
    /// Most distinct relied-on dependencies guarded, at most
    /// [`MAX_BASIS_DEPENDENCIES`].
    pub max_dependencies: u32,
    /// Per-page authentication and decoding allowances.
    pub witness_page: PageDecodeCfg,
}

/// Facts a host that verifies with its own pipeline already holds.
///
/// **Trust boundary.** Building a basis from this struct asserts, on the
/// host's authority alone, that the pack's integrity and closure were
/// verified. The primitive cannot check that. The decision derives guards only
/// from the fields present here: anything an attestation does not carry is a
/// guard the host owns and must enforce itself, outside this crate's guard set.
/// This is the only explicit, greppable trust path into a ticketed acceptance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAttestation {
    /// Repository the acceptance is for.
    pub repository: RepositoryId,
    /// Packs the attestation covers, by identity and exact length. A ticketed
    /// advance whose packs are not all listed is refused. Empty makes no
    /// pack-identity claim (every pack is covered): an explicit host choice.
    pub packs: Vec<PackSource>,
    /// Root binding the host froze for this acceptance, when it keeps one.
    pub root: Option<Hash>,
    /// Membership witness to guard, when the host has one.
    pub membership: Option<MembershipWitness>,
    /// Global denial version to guard, when the host has one.
    pub denial_version: Option<u64>,
    /// Relied-on dependencies the host observed, each guarded exactly.
    pub dependencies: Vec<MemberFact>,
}

/// Sealed record of what an acceptance relied on, as owned typed guards.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct AcceptanceBasis {
    repository: RepositoryId,
    /// Packs (id, exact length) this basis covers; empty covers any pack.
    packs: Vec<(Hash, u64)>,
    guards: Vec<RequiredGuard>,
}

impl AcceptanceBasis {
    /// Derive the basis from sealed verification and closure artifacts.
    ///
    /// Guards: a Membership and a Publication guard for every relied-on
    /// dependency in the proof's witness chain and for every external delta
    /// base in `external_bases`, the global denial version, and a root binding
    /// over the pack's identity and length, its object-set root and the closure
    /// root (requested heads and witness chain).
    ///
    /// `external_bases` are the membership facts the host supplied while the
    /// pack was verified. The verification evidence pages are scoped to that
    /// run, so the primitive cannot re-derive them: completeness against the
    /// sealed dependency sequence is the host's obligation. `coverage`, when given, must
    /// describe the same repository, view and ruleset as the proof; it is
    /// validated only and contributes no guard. Two witnesses that disagree on
    /// one supplier's published or held state are inconsistent observations
    /// and make the decision `InvalidResponse`.
    ///
    /// At most [`MAX_BASIS_DEPENDENCIES`] distinct dependencies are guarded,
    /// whatever the configured allowance; the guards number twice that plus two,
    /// so a decision's guard limit must admit them or it fails with
    /// `ResourceLimit`.
    ///
    /// # Errors
    /// Binding refusals for differing artifacts, `InvalidResponse` for a
    /// missing, extra, reordered or unauthenticated witness page, and
    /// `ResourceLimit` for an exhausted allowance.
    pub fn from_verified<P: AsRef<[u8]>>(
        verified: &VerifiedPack,
        proof: &ClosureProof,
        coverage: Option<&PairCoverage>,
        denial_version: u64,
        witness_pages: impl Iterator<Item = P>,
        external_bases: &[MemberFact],
        cfg: &BasisCfg,
    ) -> Result<Self, Failure> {
        if verified.ruleset() != proof.ruleset()
            || verified.object_set_root() != proof.object_set_root()
        {
            return Err(failure(FailureCode::EvidenceBindingMismatch));
        }
        if let Some(coverage) = coverage
            && (coverage.repository() != proof.repository()
                || coverage.view() != proof.view()
                || coverage.ruleset() != proof.ruleset())
        {
            return Err(failure(FailureCode::EvidenceBindingMismatch));
        }
        let repository = proof.repository();
        let mut facts = witness_facts(proof, witness_pages, cfg)?;
        merge_external_bases(&mut facts, external_bases, repository, cfg)?;
        let mut guards = Vec::new();
        guards
            .try_reserve_exact(facts.len() * 2 + 2)
            .map_err(|_| failure(FailureCode::ResourceLimit))?;
        for fact in &facts {
            guards.push(member_guard(repository, fact));
            guards.push(publication_guard(repository, fact));
        }
        guards.push(RequiredGuard::DenialVersion {
            version: denial_version,
        });
        guards.push(RequiredGuard::Binding {
            digest: verified_root(verified, proof),
        });
        Ok(Self {
            repository,
            packs: vec![(verified.pack_id(), verified.len())],
            guards,
        })
    }

    /// Derive the basis from decoded acceptance evidence, for decide-at-writer.
    ///
    /// Exactly three guards: one repository-scoped membership witness over the
    /// pair (generation, removal version), compared atomically; the one global
    /// denial version; and the evidence digest as the root binding. Every other
    /// evidence field is checked by decode, `check_binding` or `recheck_heads`,
    /// or is covered by the digest the host compares against its frozen record.
    pub fn from_evidence(evidence: &AcceptanceEvidence) -> Self {
        let witness = evidence.witness();
        let pack = evidence.pack();
        Self {
            repository: evidence.repository(),
            packs: vec![(pack.id, pack.len)],
            guards: vec![
                RequiredGuard::MembershipWitness {
                    repository: evidence.repository(),
                    generation: witness.generation,
                    removal_version: witness.removal_version,
                },
                RequiredGuard::DenialVersion {
                    version: evidence.denial_version(),
                },
                RequiredGuard::Binding {
                    digest: evidence.digest(),
                },
            ],
        }
    }

    /// Assert, on the host's authority, that it verified integrity and closure.
    ///
    /// See [`HostAttestation`] for the trust boundary: guards come only from
    /// the fields present, and the host owns every guard it does not carry.
    pub fn attested_by_host(attestation: HostAttestation) -> Self {
        let HostAttestation {
            repository,
            packs,
            root,
            membership,
            denial_version,
            dependencies,
        } = attestation;
        // Proportional to the attestation the host already allocated.
        let mut guards = Vec::with_capacity(dependencies.len() * 2 + 3);
        if let Some(witness) = membership {
            guards.push(RequiredGuard::MembershipWitness {
                repository,
                generation: witness.generation,
                removal_version: witness.removal_version,
            });
        }
        if let Some(version) = denial_version {
            guards.push(RequiredGuard::DenialVersion { version });
        }
        for fact in &dependencies {
            guards.push(member_guard(repository, fact));
            guards.push(publication_guard(repository, fact));
        }
        if let Some(digest) = root {
            guards.push(RequiredGuard::Binding { digest });
        }
        Self {
            repository,
            packs: packs.iter().map(|pack| (pack.id, pack.len)).collect(),
            guards,
        }
    }

    /// Whether this basis covers a pack of this identity and exact length.
    #[must_use]
    pub fn covers(&self, id: &Hash, len: u64) -> bool {
        self.packs.is_empty() || self.packs.iter().any(|pack| pack.0 == *id && pack.1 == len)
    }

    /// Repository the acceptance is for.
    #[must_use]
    pub const fn repository(&self) -> RepositoryId {
        self.repository
    }

    /// The typed guards this basis contributes to a decision.
    #[must_use]
    pub fn guards(&self) -> &[RequiredGuard] {
        &self.guards
    }
}

fn member_guard(repository: RepositoryId, fact: &MemberFact) -> RequiredGuard {
    RequiredGuard::Membership {
        repository,
        object: fact.object,
        expected: Observed::Present {
            value: fact.clone(),
            revision: fact.revision,
        },
    }
}

fn publication_guard(repository: RepositoryId, fact: &MemberFact) -> RequiredGuard {
    RequiredGuard::DependencyPublication {
        repository,
        object: fact.object,
        supplier: fact.supplier.id,
        published: fact.published,
        held: fact.held,
    }
}

fn verified_root(verified: &VerifiedPack, proof: &ClosureProof) -> Hash {
    let mut h = hash::Hasher::new();
    h.update(BASIS_DIGEST_DOMAIN)
        .update(&[0])
        .update(&verified.pack_id())
        .update(&verified.len().to_le_bytes())
        .update(&verified.object_set_root())
        .update(&proof.heads_root())
        .update(&proof.external_witnesses().root);
    h.finalize()
}

/// Authenticated relied-on facts, deduplicated by object and bounded.
fn witness_facts<P: AsRef<[u8]>>(
    proof: &ClosureProof,
    mut pages: impl Iterator<Item = P>,
    cfg: &BasisCfg,
) -> Result<Vec<MemberFact>, Failure> {
    let sequence = proof.external_witnesses();
    if sequence.count > cfg.max_witness_pages {
        return Err(failure(FailureCode::ResourceLimit));
    }
    let mut next = proof.relied_on_members();
    if next.map_or(ZERO, |page| page.digest) != sequence.root {
        return Err(failure(FailureCode::EvidenceBindingMismatch));
    }
    let max_dependencies = cfg.max_dependencies.min(MAX_BASIS_DEPENDENCIES) as usize;
    let mut facts: Vec<MemberFact> = Vec::new();
    let mut index: BTreeMap<Hash, usize> = BTreeMap::new();
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
        if decoded.fact.repository != proof.repository() || decoded.fact.incarnation != proof.view()
        {
            return Err(failure(FailureCode::EvidenceBindingMismatch));
        }
        match index.get(&decoded.fact.object) {
            Some(&at) if facts[at] != decoded.fact => {
                return Err(failure(FailureCode::InvalidResponse));
            }
            Some(_) => {}
            None => {
                if facts.len() >= max_dependencies {
                    return Err(failure(FailureCode::ResourceLimit));
                }
                facts
                    .try_reserve(1)
                    .map_err(|_| failure(FailureCode::ResourceLimit))?;
                index.insert(decoded.fact.object, facts.len());
                facts.push(decoded.fact);
            }
        }
        next = decoded.previous;
    }
    if next.is_some() || pages.next().is_some() {
        return Err(failure(FailureCode::InvalidResponse));
    }
    Ok(facts)
}

/// Add the external delta-base facts the host supplied during verification.
///
/// The primitive cannot recompute them: the verification evidence pages are
/// scoped to the run, so completeness against the sealed dependency sequence is
/// the host's obligation (SPEC-PRIMITIVE-EVIDENCE 4.4). Each fact must belong to
/// the proof's repository; a fact repeated for one object must be identical.
fn merge_external_bases(
    facts: &mut Vec<MemberFact>,
    bases: &[MemberFact],
    repository: RepositoryId,
    cfg: &BasisCfg,
) -> Result<(), Failure> {
    let max = cfg.max_dependencies.min(MAX_BASIS_DEPENDENCIES) as usize;
    for base in bases {
        if base.repository != repository {
            return Err(failure(FailureCode::EvidenceBindingMismatch));
        }
        match facts.iter().find(|fact| fact.object == base.object) {
            Some(prior) if prior != base => return Err(failure(FailureCode::InvalidResponse)),
            Some(_) => {}
            None => {
                if facts.len() >= max {
                    return Err(failure(FailureCode::ResourceLimit));
                }
                facts
                    .try_reserve(1)
                    .map_err(|_| failure(FailureCode::ResourceLimit))?;
                facts.push(base.clone());
            }
        }
    }
    Ok(())
}
