//! Resulting-pair coverage: a sans-IO pull machine over chain and object facts.
//!
//! The primitive owns the graph semantics of SPEC-SERVER §10.2 condition 2:
//! every packmap-chain pack is published or added, the head's reachable
//! closure is contained in chain packs, and external delta suppliers are
//! recorded separately so a pair's own additions never satisfy them. The host
//! owns storage, cost and byte accounting, reference caps, and refusal
//! mapping. No result here authorizes publication.

use super::Coverage;
use crate::{
    error::{BoundedDetail, Failure, FailureCode, Location},
    evidence::{RepositoryId, Revision, RulesetBinding},
    pack_verify::{Acquisition, RequestId},
};
use mkit_core::{hash::Hash, object::ObjectType};
use std::collections::{BTreeSet, VecDeque};

mod checkpoint;
#[cfg(test)]
mod tests;

/// Configured publication-verification surfaces that retain pair coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairConfig {
    /// At least one inspector is configured.
    pub inspectors: bool,
    /// Pack-level takedown denial is configured.
    pub takedown: bool,
    /// A custom publication-verification policy is configured.
    pub custom_policy: bool,
}
/// The write shape under consideration; any deleted ref is a deletion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PairWrite {
    /// Every written ref receives a value.
    Advance,
    /// At least one written ref is deleted.
    Deletion,
}
/// Why resulting-pair coverage is not required for one write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PairExemption {
    /// Deletions establish an immediate boundary without coverage.
    Deletion,
    /// The immediate path without inspectors, takedown, or custom policy.
    ImmediateUninspected,
}
/// Whether the resulting pair requires coverage evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PairRequirement {
    /// Coverage is waived for the stated reason.
    Exempt(PairExemption),
    /// The resulting pair must be coverage-verified before apply.
    Required,
}
/// Whether resulting-pair coverage applies to one write.
///
/// A deletion is always exempt. The published-source form gets no separate
/// exemption: it is exempt only under `ImmediateUninspected`, and with any
/// configured policy the destination retains coverage. Direct-child closure
/// never implies pair coverage. An empty `refs` operation is a host-level
/// question outside this rule.
#[must_use]
pub const fn pair_requirement(config: PairConfig, write: PairWrite) -> PairRequirement {
    match write {
        PairWrite::Deletion => PairRequirement::Exempt(PairExemption::Deletion),
        PairWrite::Advance => {
            if !config.inspectors && !config.takedown && !config.custom_policy {
                PairRequirement::Exempt(PairExemption::ImmediateUninspected)
            } else {
                PairRequirement::Required
            }
        }
    }
}

/// The resulting live head and packmap of an advance.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResultingPair {
    /// Branch head or non-branch target.
    pub head: Option<Hash>,
    /// Packmap chain tip of a branch.
    pub packmap: Option<Hash>,
    /// Whether the pair is the shared head/packmap branch sequence.
    pub branch: bool,
}
/// Caller execution ceilings; every bound is supplied, none is a protocol constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairLimits {
    /// Distinct packmap-chain nodes.
    pub chain: u32,
    /// Distinct packs listed by chain nodes.
    pub packs: u32,
    /// Traversal frontier: visited plus queued plus the next discovery.
    pub discovered: u32,
    /// Chain, listed, and located packs relied upon.
    pub dependencies: u32,
    /// External delta suppliers, including the cleared set's.
    pub suppliers: u32,
    /// Cleared objects a boundary answer may carry.
    pub cleared: u32,
    /// External delta-base hops per located member.
    pub max_delta_depth: u32,
    /// Cumulative abstract work charged per request, answer, child, and pack.
    pub work: u64,
}
/// Live machine counters; defensive diagnostics with no refusal meaning.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PairCounts {
    /// Distinct chain nodes applied.
    pub chain: u64,
    /// Distinct chain-listed packs.
    pub packs: u64,
    /// Popped objects, including cleared skips.
    pub visited: u64,
    /// Frontier entries awaiting a visit.
    pub queued: u64,
    /// Relied-on packs.
    pub dependencies: u64,
    /// Walk suppliers, excluding the cleared set until completion.
    pub suppliers: u64,
    /// Suppliers carried by the boundary answer.
    pub cleared_suppliers: u64,
}
/// Semantic check active at a failure, preserving the host's refusal mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PairCheck {
    /// A branch head had no reconstructing packmap.
    UnpairedHead,
    /// A chain node could not be acquired.
    ChainNode {
        /// Requested node.
        pack: Hash,
    },
    /// A chain node repeated an earlier node.
    ChainRepeat {
        /// Repeated node.
        pack: Hash,
    },
    /// A walked object could not be acquired.
    Object {
        /// Requested object.
        object: Hash,
    },
    /// The head's kind is outside commit, remix, and tag.
    Head {
        /// Offending head object.
        object: Hash,
    },
    /// An external delta base is absent or over depth.
    Base {
        /// Requested base object.
        object: Hash,
        /// Hop depth when the failure occurred.
        depth: u32,
    },
    /// A configured allowance was exhausted.
    Bound(PairBound),
}
/// Which machine allowance failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PairBound {
    /// Distinct chain nodes.
    Chain,
    /// Distinct listed packs.
    Packs,
    /// Traversal frontier discoveries.
    Discovered,
    /// Relied-on packs.
    Dependencies,
    /// External suppliers.
    Suppliers,
    /// Boundary cleared objects.
    Cleared,
    /// Cumulative abstract work.
    Work,
}
/// One host acquisition; repeated polling returns the same outstanding request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum PairRequest {
    /// One packmap-chain node. A non-addition must be a live unheld member.
    PackmapNode {
        /// Run-bound request identity.
        request: RequestId,
        /// Node to acquire.
        pack: Hash,
        /// Whether the pair's own additions supply this node.
        addition: bool,
    },
    /// The fork boundary's cleared set, after a flagged chain node.
    Boundary {
        /// Run-bound request identity.
        request: RequestId,
    },
    /// One walked object's verified fact.
    Object {
        /// Run-bound request identity.
        request: RequestId,
        /// Object to acquire.
        object: Hash,
        /// Whether this is the pair's head; its kind is checked.
        head: bool,
        /// Whether the supplier must be a chain-listed pack.
        restricted: bool,
    },
    /// One external delta-base hop.
    Base {
        /// Run-bound request identity.
        request: RequestId,
        /// Pack the walked object was located in.
        origin: Hash,
        /// Base object to acquire.
        object: Hash,
        /// Current hop depth, zero at the located member.
        depth: u32,
    },
}
/// An exact answer to the outstanding request.
#[derive(Debug)]
#[must_use]
pub enum PairResponse<'a> {
    /// Packmap node facts or explicit acquisition failure.
    PackmapNode {
        /// Echoed request identity.
        request: RequestId,
        /// Echoed node identity.
        pack: Hash,
        /// Acquired node facts.
        value: Acquisition<PackmapNode<'a>>,
    },
    /// The fork boundary's cleared set.
    Boundary {
        /// Echoed request identity.
        request: RequestId,
        /// Acquired cleared set.
        value: Acquisition<ClearedSet<'a>>,
    },
    /// One walked object's verified fact.
    Object {
        /// Echoed request identity.
        request: RequestId,
        /// Echoed object identity.
        object: Hash,
        /// Acquired object fact.
        value: Acquisition<ObjectFact<'a>>,
    },
    /// One delta-base hop.
    Base {
        /// Echoed request identity.
        request: RequestId,
        /// Echoed base identity.
        object: Hash,
        /// Acquired base fact.
        value: Acquisition<BaseFact>,
    },
}
/// Verified packmap-node facts supplied by the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackmapNode<'a> {
    /// Previous chain node, ending the chain when absent.
    pub prev: Option<Hash>,
    /// Packs this node lists.
    pub packs: &'a [Hash],
    /// Whether this node carries the fork boundary flag.
    pub boundary: bool,
}
/// The fork boundary's cleared set and its external-base suppliers.
///
/// Both lists are sorted strictly ascending; any other order is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearedSet<'a> {
    /// Cleared commits and trees a walk may skip.
    pub objects: &'a [Hash],
    /// Inherited packs supplying only external delta bases.
    pub suppliers: &'a [Hash],
}
/// Verified fact for one walked object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectFact<'a> {
    /// Pack supplying the object; restricted walks require a listed pack.
    pub pack: Hash,
    /// Canonical kind.
    pub kind: ObjectType,
    /// Reachable children in canonical order.
    pub children: &'a [Hash],
    /// Other packs this object's resolution relied on (delta intermediates).
    pub suppliers: &'a [Hash],
    /// External delta base, starting a bounded hop sequence.
    pub base: Option<Hash>,
}
/// Verified fact for one delta-base hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaseFact {
    /// Pack supplying the base.
    pub pack: Hash,
    /// The base's own external base, continuing the hop sequence.
    pub base: Option<Hash>,
}
/// Pull-machine outcome. Only terminal results establish coverage.
#[derive(Debug)]
#[must_use]
#[non_exhaustive]
pub enum PairStep<'a> {
    /// Supply the exact outstanding request.
    Request(&'a PairRequest),
    /// One bounded internal transition completed.
    Progress,
    /// Every obligation completed; coverage is established, not authority.
    Covered(PairCoverage),
}
const FLAG_HEAD_CHECKED: u8 = 1;
const FLAG_BOUNDARY_SEEN: u8 = 2;
const FLAG_BOUNDARY_DONE: u8 = 4;
/// A delta-base cursor position between hops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BaseCursor {
    origin: Hash,
    next: Hash,
    depth: u32,
}
/// Decoder configuration for a local pair-coverage checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairCheckpointCfg {
    /// Maximum encoded checkpoint bytes, checked before hashing or allocation.
    pub max_bytes: u32,
}
/// Immutable parameters a checkpoint must match to resume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairResume<'a> {
    /// Expected resulting pair.
    pub pair: ResultingPair,
    /// Expected own additions.
    pub additions: &'a [Hash],
    /// Expected repository.
    pub repository: RepositoryId,
    /// Expected repository view.
    pub view: Revision,
    /// Expected ruleset binding.
    pub ruleset: RulesetBinding,
    /// Expected execution limits.
    pub limits: PairLimits,
    /// Expected boundary honor flag.
    pub honor_cleared: bool,
}
/// Sealed resulting-pair coverage. Only this module can construct it.
///
/// Denial, inspection, publication state, and authorization are not part of
/// this evidence and stay separate host guards; coverage alone never
/// authorizes publication.
///
/// ```compile_fail
/// use mkit_primitives::{closure::pair::*, closure::Coverage, evidence::*};
/// fn forge(repository: RepositoryId, view: Revision, ruleset: RulesetBinding,
///          pair: ResultingPair) -> PairCoverage {
///     PairCoverage { repository, view, ruleset, pair,
///         dependencies: vec![], external_suppliers: vec![] }
/// }
/// ```
#[derive(Debug)]
#[must_use]
pub struct PairCoverage {
    repository: RepositoryId,
    view: Revision,
    ruleset: RulesetBinding,
    pair: ResultingPair,
    dependencies: Vec<Hash>,
    external_suppliers: Vec<Hash>,
}
impl PairCoverage {
    /// A coverage no walk produced, for this crate's tests of consumers only.
    #[cfg(test)]
    pub(crate) fn for_tests(
        repository: RepositoryId,
        view: Revision,
        ruleset: RulesetBinding,
    ) -> Self {
        Self {
            repository,
            view,
            ruleset,
            pair: ResultingPair::default(),
            dependencies: Vec::new(),
            external_suppliers: Vec::new(),
        }
    }
    /// Repository whose membership was observed.
    #[must_use]
    pub const fn repository(&self) -> RepositoryId {
        self.repository
    }
    /// Exact repository view the walk observed.
    #[must_use]
    pub const fn view(&self) -> Revision {
        self.view
    }
    /// Established ruleset.
    #[must_use]
    pub const fn ruleset(&self) -> RulesetBinding {
        self.ruleset
    }
    /// Covered resulting pair.
    #[must_use]
    pub const fn pair(&self) -> ResultingPair {
        self.pair
    }
    /// Explicit coverage scope.
    #[must_use]
    pub const fn coverage(&self) -> Coverage {
        Coverage::ResultingPair
    }
    /// Sorted unique relied-on packs: chain nodes, listed packs, and located packs.
    #[must_use]
    pub fn dependencies(&self) -> &[Hash] {
        &self.dependencies
    }
    /// Sorted unique external delta suppliers, including cleared-set suppliers.
    #[must_use]
    pub fn external_suppliers(&self) -> &[Hash] {
        &self.external_suppliers
    }
}

/// Sans-IO resulting-pair coverage machine.
///
/// The host drives `step` and answers each request exactly once. Trusted
/// host facts are observations, not remote attestations. Lost state can be
/// carried in a local [`PairWalker::checkpoint`] and resumed under a fresh
/// generation; a checkpoint never creates coverage.
///
/// ```
/// use mkit_primitives::{closure::pair::*, error::Failure,
///     evidence::{RepositoryId, Revision, RulesetBinding, RulesetId, ProfileId}};
/// let pair = ResultingPair { head: None, packmap: None, branch: false };
/// let limits = PairLimits { chain: 8, packs: 8, discovered: 8, dependencies: 8,
///     suppliers: 8, cleared: 8, max_delta_depth: 8, work: 1_000 };
/// let mut walker = PairWalker::new(pair, &[], RepositoryId([1; 32]),
///     Revision([2; 32]), RulesetBinding { ruleset: RulesetId(1),
///     profile: ProfileId::Indexed }, limits, false, 1)?;
/// let proof = loop {
///     match walker.step()? {
///         PairStep::Progress => {},
///         PairStep::Covered(proof) => break proof,
///         _ => return Err("unexpected acquisition for an empty pair".into()),
///     }
/// };
/// assert!(proof.dependencies().is_empty());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
#[must_use]
pub struct PairWalker {
    pair: ResultingPair,
    additions: Vec<Hash>,
    repository: RepositoryId,
    view: Revision,
    ruleset: RulesetBinding,
    limits: PairLimits,
    honor_cleared: bool,
    generation: u64,
    sequence: u64,
    flags: u8,
    next: Option<Hash>,
    chain: Vec<Hash>,
    packs: Vec<Hash>,
    cleared_objects: BTreeSet<Hash>,
    cleared_suppliers: Vec<Hash>,
    queue: VecDeque<Hash>,
    queued: BTreeSet<Hash>,
    visited: BTreeSet<Hash>,
    cursor: Option<BaseCursor>,
    dependencies: Vec<Hash>,
    suppliers: Vec<Hash>,
    request: Option<PairRequest>,
    work: u64,
    context: Option<PairCheck>,
    failed: bool,
    finished: bool,
}
impl PairWalker {
    /// Start a run for one resulting pair.
    ///
    /// Additions are canonicalized to a sorted unique set. A head counts as the
    /// first discovery. The branch-with-head-without-packmap condition fails on
    /// the first `step`, not here, so hosts keep one refusal mapping.
    ///
    /// # Errors
    /// Returns `ResourceLimit` for an empty discovery allowance covering the
    /// head or for allocation failure.
    pub fn new(
        pair: ResultingPair,
        additions: &[Hash],
        repository: RepositoryId,
        view: Revision,
        ruleset: RulesetBinding,
        limits: PairLimits,
        honor_cleared: bool,
        generation: u64,
    ) -> Result<Self, Failure> {
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(additions.len())
            .map_err(|_| failure(FailureCode::ResourceLimit))?;
        owned.extend_from_slice(additions);
        owned.sort_unstable();
        owned.dedup();
        let mut queue = VecDeque::new();
        let mut queued = BTreeSet::new();
        if let Some(head) = pair.head {
            if limits.discovered == 0 {
                return Err(failure(FailureCode::ResourceLimit));
            }
            queue.try_reserve_exact(1).map_err(|_| resource())?;
            queue.push_back(head);
            queued.insert(head);
        }
        Ok(Self {
            pair,
            additions: owned,
            repository,
            view,
            ruleset,
            limits,
            honor_cleared,
            generation,
            sequence: 0,
            flags: 0,
            next: pair.packmap,
            chain: Vec::new(),
            packs: Vec::new(),
            cleared_objects: BTreeSet::new(),
            cleared_suppliers: Vec::new(),
            queue,
            queued,
            visited: BTreeSet::new(),
            cursor: None,
            dependencies: Vec::new(),
            suppliers: Vec::new(),
            request: None,
            work: 0,
            context: None,
            failed: false,
            finished: false,
        })
    }
    /// Semantic attribution after failure, if a content check was active.
    #[must_use]
    pub const fn failure_context(&self) -> Option<PairCheck> {
        if self.failed { self.context } else { None }
    }
    /// Live counters; no value here establishes coverage.
    #[must_use]
    pub fn counts(&self) -> PairCounts {
        PairCounts {
            chain: self.chain.len() as u64,
            packs: self.packs.len() as u64,
            visited: self.visited.len() as u64,
            queued: self.queue.len() as u64,
            dependencies: self.dependencies.len() as u64,
            suppliers: self.suppliers.len() as u64,
            cleared_suppliers: self.cleared_suppliers.len() as u64,
        }
    }
    /// Sorted unique packs the chain listed; hosts restrict object lookup to these.
    #[must_use]
    pub fn chain_packs(&self) -> &[Hash] {
        &self.packs
    }
    /// Sorted unique walk suppliers, excluding the cleared set until completion.
    #[must_use]
    pub fn suppliers(&self) -> &[Hash] {
        &self.suppliers
    }
    /// Sorted unique suppliers the boundary answer carried.
    #[must_use]
    pub fn cleared_suppliers(&self) -> &[Hash] {
        &self.cleared_suppliers
    }
    /// The next chain node not yet requested; `None` outside the chain phase
    /// and while a request is outstanding.
    #[must_use]
    pub fn pending_packmap(&self) -> Option<Hash> {
        if self.request.is_none() {
            self.next
        } else {
            None
        }
    }
    /// Poll once. Internal transitions are finite; an outstanding request repeats.
    ///
    /// # Errors
    /// Refuses unpaired heads, missing or repeated chain nodes, missing
    /// objects, excessive delta depth, invalid facts, and exhausted limits.
    /// After any failure, start a fresh generation.
    pub fn step(&mut self) -> Result<PairStep<'_>, Failure> {
        if self.failed || self.finished {
            return Err(failure(FailureCode::InvalidResponse));
        }
        if self.request.is_none() {
            if let Err(error) = self.advance() {
                self.failed = true;
                return Err(error);
            }
            if self.request.is_none()
                && self.next.is_none()
                && self.cursor.is_none()
                && self.queue.is_empty()
                && !self.boundary_ready()
            {
                if let Err(error) = self.merge_cleared() {
                    self.failed = true;
                    return Err(error);
                }
                self.finished = true;
                return Ok(PairStep::Covered(self.coverage()));
            }
        }
        if let Some(request) = &self.request {
            return Ok(PairStep::Request(request));
        }
        Ok(PairStep::Progress)
    }
    /// Supply exactly one requested response.
    ///
    /// # Errors
    /// Returns `InvalidResponse` for stale, unsolicited, or mismatched echoes
    /// and for invalid facts; `UnavailableInput` for acquisition loss;
    /// `MissingClosure`/`ExternalBaseAbsent` for authoritative absence;
    /// `ResourceLimit` for exhausted allowances. Any failure poisons the run.
    pub fn answer(&mut self, response: PairResponse<'_>) -> Result<(), Failure> {
        if self.failed || self.finished {
            return Err(failure(FailureCode::InvalidResponse));
        }
        let result = self.answer_inner(response);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    /// Encode the current state as a local checkpoint.
    ///
    /// Only a walker with no outstanding request that has neither failed nor
    /// finished can be checkpointed. The trailing checksum detects local
    /// corruption only; it does not authenticate a malicious host.
    ///
    /// # Errors
    /// Returns `InvalidResponse` when a request is outstanding or the run is
    /// finished or failed, and `ResourceLimit` on allocation failure.
    pub fn checkpoint(&self) -> Result<Vec<u8>, Failure> {
        if self.failed || self.finished || self.request.is_some() {
            return Err(failure(FailureCode::InvalidResponse));
        }
        checkpoint::encode(self)
    }
    /// Resume a checkpoint under a fresh generation.
    ///
    /// The checkpoint is decoded strictly, verified against `expected`, and its
    /// corruption checksum recomputed. A resumed walk whose boundary was
    /// applied re-requests it once before the next walk step, because the
    /// cleared set is host state, not checkpoint content.
    ///
    /// # Errors
    /// Returns `InvalidCheckpoint` for malformed bytes, a bad checksum, an
    /// inconsistent machine state, or any `expected` mismatch, and
    /// `ResourceLimit` on allocation failure.
    pub fn resume(
        bytes: &[u8],
        cfg: PairCheckpointCfg,
        expected: &PairResume<'_>,
        generation: u64,
    ) -> Result<Self, Failure> {
        checkpoint::decode(bytes, cfg, expected, generation)
    }
    /// Validate checkpoint bytes without binding a run.
    ///
    /// Hosts use this to refuse a corrupt stored checkpoint; resuming still
    /// requires `resume` with the exact expected parameters.
    ///
    /// # Errors
    /// Returns `InvalidCheckpoint` for any malformed, inconsistent, or
    /// corrupt encoding.
    pub fn validate_checkpoint(bytes: &[u8], cfg: PairCheckpointCfg) -> Result<(), Failure> {
        checkpoint::validate(bytes, cfg)
    }
    fn id(&mut self) -> Result<RequestId, Failure> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        Ok(RequestId {
            generation: self.generation,
            sequence: self.sequence,
        })
    }
    fn charge(&mut self, n: u64) -> Result<(), Failure> {
        self.work = self
            .work
            .checked_add(n)
            .filter(|used| *used <= self.limits.work)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        Ok(())
    }
    fn head_checked(&self) -> bool {
        self.flags & FLAG_HEAD_CHECKED != 0
    }
    fn boundary_seen(&self) -> bool {
        self.flags & FLAG_BOUNDARY_SEEN != 0
    }
    fn boundary_done(&self) -> bool {
        self.flags & FLAG_BOUNDARY_DONE != 0
    }
    fn boundary_ready(&self) -> bool {
        self.next.is_none() && self.boundary_seen() && self.honor_cleared && !self.boundary_done()
    }
    fn coverage(&self) -> PairCoverage {
        PairCoverage {
            repository: self.repository,
            view: self.view,
            ruleset: self.ruleset,
            pair: self.pair,
            dependencies: self.dependencies.clone(),
            external_suppliers: self.suppliers.clone(),
        }
    }
    fn merge_cleared(&mut self) -> Result<(), Failure> {
        let suppliers = std::mem::take(&mut self.cleared_suppliers);
        for supplier in suppliers {
            insert_sorted(
                &mut self.suppliers,
                supplier,
                u64::from(self.limits.suppliers),
            )
            .map_err(|error| self.bound(PairBound::Suppliers, error))?;
        }
        Ok(())
    }
    fn bound(&mut self, check: PairBound, error: Failure) -> Failure {
        self.context = Some(PairCheck::Bound(check));
        error
    }
    fn fail(&mut self, context: PairCheck, code: FailureCode) -> Failure {
        self.context = Some(context);
        failure(code)
    }
    fn advance(&mut self) -> Result<(), Failure> {
        self.charge(1)
            .map_err(|error| self.bound(PairBound::Work, error))?;
        if !self.head_checked() {
            self.flags |= FLAG_HEAD_CHECKED;
            if self.pair.branch && self.pair.head.is_some() && self.pair.packmap.is_none() {
                return Err(self.fail(PairCheck::UnpairedHead, FailureCode::MissingClosure));
            }
        }
        if let Some(pack) = self.next {
            if self.chain.contains(&pack) {
                return Err(self.fail(PairCheck::ChainRepeat { pack }, FailureCode::PackmapCycle));
            }
            let addition = self.additions.binary_search(&pack).is_ok();
            self.request = Some(PairRequest::PackmapNode {
                request: self.id()?,
                pack,
                addition,
            });
            return Ok(());
        }
        if self.boundary_ready() {
            self.flags |= FLAG_BOUNDARY_DONE;
            self.request = Some(PairRequest::Boundary {
                request: self.id()?,
            });
            return Ok(());
        }
        if let Some(cursor) = self.cursor {
            if cursor.depth >= self.limits.max_delta_depth {
                return Err(self.fail(
                    PairCheck::Base {
                        object: cursor.next,
                        depth: cursor.depth,
                    },
                    FailureCode::DeltaChainTooDeep,
                ));
            }
            self.request = Some(PairRequest::Base {
                request: self.id()?,
                origin: cursor.origin,
                object: cursor.next,
                depth: cursor.depth,
            });
            return Ok(());
        }
        let Some(object) = self.queue.pop_front() else {
            return Ok(());
        };
        self.queued.remove(&object);
        self.visited.insert(object);
        if self.pair.head != Some(object) && self.cleared_objects.contains(&object) {
            return Ok(());
        }
        self.request = Some(PairRequest::Object {
            request: self.id()?,
            object,
            head: self.pair.head == Some(object),
            restricted: self.pair.packmap.is_some(),
        });
        Ok(())
    }
    fn answer_inner(&mut self, response: PairResponse<'_>) -> Result<(), Failure> {
        match (self.request.clone(), response) {
            (
                Some(PairRequest::PackmapNode {
                    request,
                    pack: expected,
                    ..
                }),
                PairResponse::PackmapNode {
                    request: echo,
                    pack,
                    value,
                },
            ) if echo == request && pack == expected => {
                return self.answer_packmap(pack, value);
            }
            (
                Some(PairRequest::Boundary { request }),
                PairResponse::Boundary {
                    request: echo,
                    value,
                },
            ) if echo == request => {
                return self.answer_boundary(value);
            }
            (
                Some(PairRequest::Object {
                    request,
                    object: expected,
                    head,
                    restricted,
                }),
                PairResponse::Object {
                    request: echo,
                    object,
                    value,
                },
            ) if echo == request && object == expected => {
                return self.answer_object(object, head, restricted, value);
            }
            (
                Some(PairRequest::Base {
                    request,
                    origin,
                    object: expected,
                    depth,
                }),
                PairResponse::Base {
                    request: echo,
                    object,
                    value,
                },
            ) if echo == request && object == expected => {
                return self.answer_base(origin, object, depth, &value);
            }
            _ => {}
        }
        Err(failure(FailureCode::InvalidResponse))
    }
    fn answer_packmap(
        &mut self,
        pack: Hash,
        value: Acquisition<PackmapNode<'_>>,
    ) -> Result<(), Failure> {
        let node = self.present(value, PairCheck::ChainNode { pack })?;
        self.charge(1 + node.packs.len() as u64)
            .map_err(|error| self.bound(PairBound::Work, error))?;
        insert_sorted(&mut self.chain, pack, u64::from(self.limits.chain))
            .map_err(|error| self.bound(PairBound::Chain, error))?;
        insert_sorted(
            &mut self.dependencies,
            pack,
            u64::from(self.limits.dependencies),
        )
        .map_err(|error| self.bound(PairBound::Dependencies, error))?;
        for listed in node.packs {
            insert_sorted(&mut self.packs, *listed, u64::from(self.limits.packs))
                .map_err(|error| self.bound(PairBound::Packs, error))?;
            insert_sorted(
                &mut self.dependencies,
                *listed,
                u64::from(self.limits.dependencies),
            )
            .map_err(|error| self.bound(PairBound::Dependencies, error))?;
        }
        if node.boundary {
            self.flags |= FLAG_BOUNDARY_SEEN;
        }
        self.next = node.prev;
        self.request = None;
        Ok(())
    }
    fn answer_boundary(&mut self, value: Acquisition<ClearedSet<'_>>) -> Result<(), Failure> {
        let cleared = match value {
            Acquisition::Present(cleared) => cleared,
            Acquisition::Absent | Acquisition::Unavailable => {
                return Err(failure(FailureCode::UnavailableInput));
            }
        };
        if cleared.objects.len() as u64 > u64::from(self.limits.cleared) {
            return Err(self.bound(PairBound::Cleared, failure(FailureCode::ResourceLimit)));
        }
        if !strictly_ascending(cleared.objects) || !strictly_ascending(cleared.suppliers) {
            return Err(failure(FailureCode::InvalidResponse));
        }
        self.charge(1 + cleared.objects.len() as u64 + cleared.suppliers.len() as u64)
            .map_err(|error| self.bound(PairBound::Work, error))?;
        self.cleared_objects = cleared.objects.iter().copied().collect();
        let mut suppliers = Vec::new();
        suppliers
            .try_reserve_exact(cleared.suppliers.len())
            .map_err(|_| resource())?;
        suppliers.extend_from_slice(cleared.suppliers);
        self.cleared_suppliers = suppliers;
        self.request = None;
        Ok(())
    }
    fn answer_object(
        &mut self,
        object: Hash,
        head: bool,
        restricted: bool,
        value: Acquisition<ObjectFact<'_>>,
    ) -> Result<(), Failure> {
        let fact = self.present(value, PairCheck::Object { object })?;
        if restricted && self.packs.binary_search(&fact.pack).is_err() {
            return Err(failure(FailureCode::InvalidResponse));
        }
        if head
            && !matches!(
                fact.kind,
                ObjectType::Commit | ObjectType::Remix | ObjectType::Tag
            )
        {
            return Err(self.fail(PairCheck::Head { object }, FailureCode::WrongKind));
        }
        self.charge(1 + fact.children.len() as u64 + fact.suppliers.len() as u64)
            .map_err(|error| self.bound(PairBound::Work, error))?;
        insert_sorted(
            &mut self.dependencies,
            fact.pack,
            u64::from(self.limits.dependencies),
        )
        .map_err(|error| self.bound(PairBound::Dependencies, error))?;
        for supplier in fact.suppliers {
            insert_sorted(
                &mut self.suppliers,
                *supplier,
                u64::from(self.limits.suppliers),
            )
            .map_err(|error| self.bound(PairBound::Suppliers, error))?;
        }
        for child in fact.children {
            if !self.visited.contains(child) && !self.queued.contains(child) {
                if self.visited.len() as u64 + self.queue.len() as u64
                    >= u64::from(self.limits.discovered)
                {
                    return Err(
                        self.bound(PairBound::Discovered, failure(FailureCode::ResourceLimit))
                    );
                }
                self.queue.try_reserve(1).map_err(|_| resource())?;
                self.queue.push_back(*child);
                self.queued.insert(*child);
            }
        }
        self.cursor = fact.base.map(|next| BaseCursor {
            origin: fact.pack,
            next,
            depth: 0,
        });
        self.request = None;
        Ok(())
    }
    fn answer_base(
        &mut self,
        origin: Hash,
        object: Hash,
        depth: u32,
        value: &Acquisition<BaseFact>,
    ) -> Result<(), Failure> {
        let fact = match *value {
            Acquisition::Present(fact) => fact,
            Acquisition::Absent => {
                return Err(self.fail(
                    PairCheck::Base { object, depth },
                    FailureCode::ExternalBaseAbsent,
                ));
            }
            Acquisition::Unavailable => {
                return Err(failure(FailureCode::UnavailableInput));
            }
        };
        self.charge(1)
            .map_err(|error| self.bound(PairBound::Work, error))?;
        if fact.pack != origin {
            insert_sorted(
                &mut self.suppliers,
                fact.pack,
                u64::from(self.limits.suppliers),
            )
            .map_err(|error| self.bound(PairBound::Suppliers, error))?;
        }
        self.cursor = fact.base.map(|next| BaseCursor {
            origin,
            next,
            depth: depth.saturating_add(1),
        });
        self.request = None;
        Ok(())
    }
    fn present<T>(&mut self, value: Acquisition<T>, context: PairCheck) -> Result<T, Failure> {
        match value {
            Acquisition::Present(value) => Ok(value),
            Acquisition::Absent => Err(self.fail(context, FailureCode::MissingClosure)),
            Acquisition::Unavailable => Err(failure(FailureCode::UnavailableInput)),
        }
    }
}
fn strictly_ascending(ids: &[Hash]) -> bool {
    ids.windows(2).all(|pair| pair[0] < pair[1])
}
fn insert_sorted(list: &mut Vec<Hash>, id: Hash, limit: u64) -> Result<(), Failure> {
    if let Err(index) = list.binary_search(&id) {
        if list.len() as u64 >= limit {
            return Err(failure(FailureCode::ResourceLimit));
        }
        list.try_reserve_exact(1).map_err(|_| resource())?;
        list.insert(index, id);
    }
    Ok(())
}
fn resource() -> Failure {
    failure(FailureCode::ResourceLimit)
}
fn failure(code: FailureCode) -> Failure {
    Failure {
        code,
        location: Location::default(),
        detail: BoundedDetail::None,
    }
}
