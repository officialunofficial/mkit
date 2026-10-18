//! Cooperative direct-child traversal with bounded edge windows and paged state.

use super::{
    ClosureProof, Coverage, InPackObject, InPackObjectView, MembershipAnswer, MembershipRequest,
    MembershipResponse,
    journal::{Journal, Lookup, Record, State},
    limits::ClosureLimits,
    output::{MissingObject, MissingReason, MissingSet, encode_missing, encode_witness},
};
use crate::{
    error::{BoundedDetail, Failure, FailureCode, Location},
    evidence::{MemberFact, PageCommitment, RepositoryId, Revision, RulesetBinding},
    pack_verify::{Acquisition, EvidenceSequence, RequestId, VerifiedPack},
};
use mkit_core::{
    hash::{Hash, ZERO},
    object::ObjectType,
};

mod acquisition;
mod traversal;

/// Exact immutable canonical source requested for a file-integrity check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalSource {
    /// Repository member used as a chunk, with exact supplier and source version.
    Member(MemberFact),
}
impl CanonicalSource {
    fn len(&self) -> u64 {
        match self {
            Self::Member(fact) => fact.canonical_len,
        }
    }
}
/// One host acquisition. Repeated polling returns the same outstanding request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum ClosureRequest {
    /// One frontier batch, never a per-ID callback loop.
    Membership(MembershipRequest),
    /// Canonical bytes needed for external chunk integrity.
    Canonical {
        /// Run-bound request identity.
        request: RequestId,
        /// Exact immutable source; the entire finite canonical object is requested.
        source: CanonicalSource,
    },
    /// A previously acknowledged visited-state page.
    Page {
        /// Run-bound request identity.
        request: RequestId,
        /// Exact authenticated page.
        page: PageCommitment,
    },
}
/// An exact answer to the outstanding acquisition.
#[derive(Debug)]
#[must_use]
pub enum ClosureResponse<'a> {
    /// Complete, ordered answers for one membership frontier.
    Membership(MembershipResponse),
    /// Exact canonical bytes, or explicit acquisition failure.
    Canonical {
        /// Echoed request identity.
        request: RequestId,
        /// Echoed source binding.
        source: CanonicalSource,
        /// Acquired canonical bytes.
        value: Acquisition<&'a [u8]>,
    },
    /// A retained state page; a lost page cannot establish absence.
    Page {
        /// Echoed request identity.
        request: RequestId,
        /// Echoed commitment.
        page: PageCommitment,
        /// Acquired encoded page.
        value: Acquisition<&'a [u8]>,
    },
}
/// One outstanding retention event. Acknowledgement precedes dependent progress.
#[derive(Debug)]
#[must_use]
pub struct ClosurePage<'a> {
    /// Run-bound retention identity.
    pub request: RequestId,
    /// Exact page commitment.
    pub page: PageCommitment,
    /// Bounded immutable bytes to retain.
    pub bytes: &'a [u8],
}
/// Defensive diagnostics; these introduce no new content refusal.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClosureDiagnostics {
    /// Gray-node edges, distinguished from shared black-node structure.
    pub cycles: u64,
    /// Tree/tag kind hints that disagree with known kinds.
    pub kind_mismatches: u64,
}
/// Semantic check active at a failure, allowing a host to preserve its refusal mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClosureCheck {
    /// Advanced-head kind or membership obligation.
    Head,
    /// Ordinary direct-child availability.
    Reference,
    /// Canonical Blob integrity for one manifest occurrence.
    Chunk {
        /// Manifest requiring the chunk.
        manifest: Hash,
        /// Occurrence ordinal, including repeated IDs.
        ordinal: u64,
    },
    /// Ordered cumulative and final manifest length.
    Manifest,
}
/// Fixed-size semantic attribution. It carries no byte buffers or public refusal text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClosureFailureContext {
    /// Object checked when the failure occurred.
    pub object: Hash,
    /// Exact semantic obligation; transport mapping remains host policy.
    pub check: ClosureCheck,
}
/// Pull-machine outcome. Only terminal results establish complete checks.
#[derive(Debug)]
#[must_use]
pub enum ClosureStep<'a> {
    /// Supply facts or bytes for the exact outstanding request.
    Request(&'a ClosureRequest),
    /// Retain and acknowledge this page before continuing.
    Retain(ClosurePage<'a>),
    /// One bounded internal transition completed.
    Progress,
    /// Every direct-child and file-integrity check completed successfully.
    Closed(ClosureProof),
    /// All checks completed; this is the complete sorted, deduplicated missing set.
    Missing(MissingSet),
}
#[derive(Debug, Clone, Copy)]
struct Visit {
    id: Hash,
    head: bool,
    depth: u64,
    reason: Option<MissingReason>,
    expected: Option<ObjectType>,
    chunk: bool,
}
#[derive(Debug)]
struct Frame {
    object: Option<InPackObject>,
    depth: u64,
    cursor: u64,
    window: Vec<Visit>,
    processed: usize,
    prefetch: usize,
    total: Option<u64>,
    chunks: Option<u64>,
    chunk_sum: u64,
    missing_chunk: bool,
    /// A chunk fault was deferred; the manifest total can no longer be judged.
    faulted: bool,
}
impl Frame {
    fn seeds() -> Self {
        Self {
            object: None,
            depth: 0,
            cursor: 0,
            window: Vec::new(),
            processed: 0,
            prefetch: 0,
            total: None,
            chunks: None,
            chunk_sum: 0,
            missing_chunk: false,
            faulted: false,
        }
    }
    fn object(object: InPackObject, depth: u64, total: Option<u64>, chunks: Option<u64>) -> Self {
        Self {
            object: Some(object),
            depth,
            total,
            chunks,
            ..Self::seeds()
        }
    }
}
#[derive(Debug, Clone, Copy)]
enum Phase {
    Fill,
    Prefetch,
    StoreAnswers(usize),
    Witness(usize),
    Process,
    Visit(Visit),
    FinishFrame,
    FinishMissing,
}
#[derive(Debug, Clone, Copy)]
enum Retention {
    Journal,
    Witness,
    Missing,
}
#[derive(Debug)]
struct PendingPage {
    request: RequestId,
    page: PageCommitment,
    bytes: Vec<u8>,
    kind: Retention,
}

/// Sans-IO direct-child closure over a supplied immutable verified-object view.
///
/// The view must agree with the sealed `VerifiedPack` passed to `new`, which
/// supplies the object-set root and ruleset.
/// Membership facts are trusted host observations in exactly the requested
/// repository and incarnation. No result grants authorization or publication.
/// Lost state can be recovered by replaying retained pages, or by starting a new
/// generation from the same immutable view; a checkpoint never creates a proof.
///
/// ```
/// use mkit_primitives::{closure::*, closure::limits::ClosureLimits, error::Failure,
///     pack_verify::VerifiedPack, evidence::{RepositoryId, Revision, RulesetBinding, RulesetId, ProfileId}};
/// struct Empty;
/// impl InPackObjectView for Empty {
///     fn object_set_root(&self) -> [u8;32] { [0;32] }
///     fn retained_bytes(&self) -> u64 { 0 }
///     fn object_count(&self) -> u64 { 0 }
///     fn object(&self, _: &[u8;32]) -> Result<Option<InPackObject>,Failure> { Ok(None) }
///     fn edge(&self, _: &[u8;32], _:u64) -> Result<Option<ObjectEdge>,Failure> { Ok(None) }
///     fn object_at(&self, _:u64) -> Result<Option<InPackObject>,Failure> { Ok(None) }
/// }
/// // `verified` is the sealed result of the verify driver for the pack whose
/// // objects `Empty` serves; its root and ruleset must match the view's.
/// fn close(verified: &VerifiedPack) -> Result<(), Box<dyn std::error::Error>> {
///     let rules = RulesetBinding {ruleset:RulesetId(1),profile:ProfileId::Indexed};
///     let mut walker=ClosureWalker::new(Empty, verified, &[], RepositoryId([1;32]),
///         Revision([2;32]), rules, ClosureLimits::indexed(), 1)?;
///     let proof=loop {
///         match walker.step()? {
///             ClosureStep::Progress => {},
///             ClosureStep::Closed(proof) => break proof,
///             _ => return Err("unexpected acquisition in an empty view".into()),
///         }
///     };
///     assert_eq!(proof.coverage(),Coverage::DirectChildren);
///     Ok(())
/// }
/// ```
#[derive(Debug)]
#[must_use]
pub struct ClosureWalker<V> {
    view: V,
    view_bytes: u64,
    object_set_root: Hash,
    object_count: u64,
    repository: RepositoryId,
    revision: Revision,
    ruleset: RulesetBinding,
    limits: ClosureLimits,
    generation: u64,
    sequence: u64,
    heads: Vec<Hash>,
    heads_root: Hash,
    frames: Vec<Frame>,
    phase: Phase,
    journal: Journal,
    wanted: Vec<Hash>,
    answers: Vec<MembershipAnswer>,
    request: Option<ClosureRequest>,
    retention: Option<PendingPage>,
    witnesses: Option<PageCommitment>,
    witness_count: u64,
    missing: Vec<MissingObject>,
    missing_root: Option<PageCommitment>,
    missing_count: u64,
    items: u64,
    edges: u64,
    decoded: u64,
    work: u64,
    evidence_bytes: u64,
    evidence_pages: u64,
    diagnostics: ClosureDiagnostics,
    context: Option<ClosureFailureContext>,
    /// The first file-integrity fault in traversal order. It is reported only
    /// after the whole closure is known to be complete, so absent objects take
    /// precedence over it, as in both server paths.
    deferred: Option<(Failure, Option<ClosureFailureContext>)>,
    failed: bool,
    finished: bool,
}
impl<V: InPackObjectView> ClosureWalker<V> {
    /// Start a run over every supplied object, including surplus manifests, and heads.
    ///
    /// The object-set root and ruleset come from `verified`; the view must
    /// agree with both.
    ///
    /// # Errors
    /// Returns `ResourceLimit` for invalid or insufficient finite allowances and
    /// `EvidenceBindingMismatch` when the view or ruleset differs from `verified`.
    pub fn new(
        view: V,
        verified: &VerifiedPack,
        heads: &[Hash],
        repository: RepositoryId,
        revision: Revision,
        ruleset: RulesetBinding,
        limits: ClosureLimits,
        generation: u64,
    ) -> Result<Self, Failure> {
        let object_count = view.object_count();
        // The object-set root comes from the sealed verification, not from the
        // host-implemented view: a view answering with another root, or under
        // another ruleset, cannot seal a proof for this pack.
        let object_set_root = verified.object_set_root();
        if view.object_set_root() != object_set_root || verified.ruleset() != ruleset {
            return Err(failure(FailureCode::EvidenceBindingMismatch));
        }
        if limits.items > 10_000_000 || limits.membership_batch == 0 || object_count > limits.items
        {
            return Err(failure(FailureCode::ResourceLimit));
        }
        let view_bytes = view.retained_bytes();
        let startup = 128 * 1024u64
            + heads.len() as u64 * 32
            + u64::from(limits.membership_batch) * 2048
            + 512;
        let startup_work = heads.len() as u64 * 32 + 32;
        let startup = startup
            .checked_add(view_bytes)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        if startup > limits.resident_bytes || startup_work > limits.work {
            return Err(failure(FailureCode::ResourceLimit));
        }
        let mut owned_heads = Vec::new();
        owned_heads
            .try_reserve_exact(heads.len())
            .map_err(|_| failure(FailureCode::ResourceLimit))?;
        owned_heads.extend_from_slice(heads);
        // Bind the exact requested sequence, including duplicate head occurrences.
        let heads_root = super::heads_root(heads.iter().copied())?;
        let mut frames = Vec::new();
        frames
            .try_reserve(1)
            .map_err(|_| failure(FailureCode::ResourceLimit))?;
        frames.push(Frame::seeds());
        let mut result = Self {
            view,
            view_bytes,
            object_count,
            object_set_root,
            repository,
            revision,
            ruleset,
            limits,
            generation,
            sequence: 0,
            heads: owned_heads,
            heads_root,
            frames,
            phase: Phase::Fill,
            journal: Journal::new(),
            wanted: Vec::new(),
            answers: Vec::new(),
            request: None,
            retention: None,
            witnesses: None,
            witness_count: 0,
            missing: Vec::new(),
            missing_root: None,
            missing_count: 0,
            items: 0,
            edges: 0,
            decoded: 0,
            work: startup_work,
            evidence_bytes: 0,
            evidence_pages: 0,
            diagnostics: ClosureDiagnostics::default(),
            context: None,
            deferred: None,
            failed: false,
            finished: false,
        };
        result.resident(0)?;
        Ok(result)
    }
    /// Diagnostics do not turn existence-only tree/tag edges into type refusals.
    #[must_use]
    pub const fn diagnostics(&self) -> ClosureDiagnostics {
        self.diagnostics
    }
    /// Semantic attribution after failure, if a content obligation was active.
    /// Acquisition/protocol failures can have no content context. This does not
    /// prescribe refusal codes or precedence for the host.
    #[must_use]
    pub const fn failure_context(&self) -> Option<ClosureFailureContext> {
        if self.failed { self.context } else { None }
    }
    /// Poll once. Internal transitions have finite work; acquisition and retention repeat.
    ///
    /// # Errors
    /// Refuses exhausted resources, invalid facts, corrupt canonical bytes, and
    /// unavailable input. After any failure, start a fresh generation.
    pub fn step(&mut self) -> Result<ClosureStep<'_>, Failure> {
        if self.failed || self.finished {
            return Err(failure(FailureCode::InvalidResponse));
        }
        if self.request.is_none()
            && self.retention.is_none()
            && let Err(error) = self.advance()
        {
            self.failed = true;
            return Err(error);
        }
        if let Some(request) = &self.request {
            return Ok(ClosureStep::Request(request));
        }
        if let Some(page) = &self.retention {
            return Ok(ClosureStep::Retain(ClosurePage {
                request: page.request,
                page: page.page,
                bytes: &page.bytes,
            }));
        }
        if self.frames.is_empty() && self.missing.is_empty() {
            if self.missing_count == 0
                && let Some((fault, context)) = self.deferred.take()
            {
                self.failed = true;
                self.context = context;
                return Err(fault);
            }
            self.finished = true;
            if self.missing_count > 0 {
                return Ok(ClosureStep::Missing(MissingSet::seal(
                    self.missing_root,
                    self.missing_count,
                )));
            }
            return Ok(ClosureStep::Closed(ClosureProof {
                repository: self.repository,
                view: self.revision,
                ruleset: self.ruleset,
                coverage: Coverage::DirectChildren,
                object_set_root: self.object_set_root,
                heads_root: self.heads_root,
                witness_page: self.witnesses,
                external_witnesses: EvidenceSequence {
                    root: self.witnesses.map_or(ZERO, |p| p.digest),
                    count: self.witness_count,
                },
            }));
        }
        Ok(ClosureStep::Progress)
    }
    /// Supply exactly one requested response. Partial and duplicate batches refuse.
    ///
    /// # Errors
    /// Returns `InvalidResponse` for stale, unsolicited, reordered, or contradictory
    /// answers; `UnavailableInput` for acquisition loss; resource/integrity failures
    /// remain distinct. Any failure invalidates this run.
    pub fn answer(&mut self, response: ClosureResponse<'_>) -> Result<(), Failure> {
        if self.failed || self.finished {
            return Err(failure(FailureCode::InvalidResponse));
        }
        let result = self.answer_inner(response);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    /// Acknowledge exact durable retention. A lost acknowledgement can be repeated
    /// by polling the unchanged event; an unsolicited acknowledgement refuses.
    ///
    /// # Errors
    /// Returns `InvalidResponse` for an incorrect identity, page, or phase.
    pub fn acknowledge(&mut self, request: RequestId, page: PageCommitment) -> Result<(), Failure> {
        if self.failed || self.finished {
            return Err(failure(FailureCode::InvalidResponse));
        }
        let Some(pending) = &self.retention else {
            self.failed = true;
            return Err(failure(FailureCode::InvalidResponse));
        };
        if pending.request != request || pending.page != page {
            self.failed = true;
            return Err(failure(FailureCode::InvalidResponse));
        }
        match pending.kind {
            Retention::Journal => self.journal.acknowledge(page)?,
            Retention::Witness => {
                self.witnesses = Some(page);
                self.witness_count += 1;
            }
            Retention::Missing => {
                self.missing_root = Some(page);
            }
        }
        self.retention = None;
        Ok(())
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
        charge(&mut self.work, n, self.limits.work)
    }
    /// Record a file-integrity fault of the active obligation and keep walking.
    /// Only the first is kept: traversal order is wire order of discovery.
    fn defer_only(&mut self, fault: Failure) {
        if self.deferred.is_none() {
            self.deferred = Some((fault, self.context));
        }
    }
    fn defer(&mut self, fault: Failure) {
        self.defer_only(fault);
        if let Some(frame) = self.frames.last_mut() {
            frame.faulted = true;
        }
    }
    fn resident(&mut self, extra: u64) -> Result<(), Failure> {
        // Conservative reservations include vector capacity and the maximum
        // complete membership response, journal decode, and canonical scratch.
        self.charge(self.frames.len() as u64 + self.missing.len() as u64 + 1)?;
        let mut bytes = (128 * 1024u64)
            .checked_add(self.view_bytes)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        bytes = bytes
            .checked_add(self.heads.capacity() as u64 * 32)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        bytes = bytes
            .checked_add(self.frames.capacity() as u64 * 512)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        for frame in &self.frames {
            bytes = bytes
                .checked_add(frame.window.capacity() as u64 * 256)
                .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        }
        bytes = bytes
            .checked_add(u64::from(self.limits.membership_batch) * 2048)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        bytes = bytes
            .checked_add(answer_bytes(self.answers.capacity())?)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        bytes = bytes
            .checked_add(self.missing.capacity() as u64 * 128)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        for missing in &self.missing {
            bytes = bytes
                .checked_add(missing.reasons.capacity() as u64 * 128)
                .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        }
        if bytes
            .checked_add(extra)
            .is_none_or(|n| n > self.limits.resident_bytes)
        {
            return Err(failure(FailureCode::ResourceLimit));
        }
        Ok(())
    }
    fn retain(
        &mut self,
        page: PageCommitment,
        bytes: Vec<u8>,
        kind: Retention,
    ) -> Result<(), Failure> {
        self.resident(bytes.capacity() as u64)?;
        charge(
            &mut self.evidence_bytes,
            page.len,
            self.limits.evidence_bytes,
        )?;
        charge(&mut self.evidence_pages, 1, self.limits.evidence_pages)?;
        self.charge(page.len)?;
        self.retention = Some(PendingPage {
            request: self.id()?,
            page,
            bytes,
            kind,
        });
        Ok(())
    }
    fn put(&mut self, id: Hash, record: &Record) -> Result<(), Failure> {
        let (page, bytes) = self.journal.put(id, record)?;
        self.retain(page, bytes, Retention::Journal)
    }
    fn lookup(&mut self, id: &Hash) -> Result<Lookup, Failure> {
        self.charge(1)?;
        match self.journal.lookup(id)? {
            Lookup::Found(record) => Ok(Lookup::Found(record)),
            Lookup::NeedPage(page) => {
                self.request = Some(ClosureRequest::Page {
                    request: self.id()?,
                    page,
                });
                Ok(Lookup::NeedPage(page))
            }
        }
    }
    fn acquire(&mut self, source: CanonicalSource) -> Result<(), Failure> {
        if source.len() > self.limits.object_bytes {
            return Err(failure(FailureCode::ResourceLimit));
        }
        self.resident(source.len())?;
        self.request = Some(ClosureRequest::Canonical {
            request: self.id()?,
            source,
        });
        Ok(())
    }
}
fn check_kind(visit: Visit, kind: ObjectType) -> Result<(), Failure> {
    if (visit.head
        && !matches!(
            kind,
            ObjectType::Commit | ObjectType::Remix | ObjectType::Tag
        ))
        || (visit.chunk && kind != ObjectType::Blob)
    {
        return Err(failure(FailureCode::WrongKind));
    }
    Ok(())
}
fn present<T>(value: Acquisition<T>) -> Result<T, Failure> {
    match value {
        Acquisition::Present(value) => Ok(value),
        Acquisition::Absent | Acquisition::Unavailable => {
            Err(failure(FailureCode::UnavailableInput))
        }
    }
}
fn answer_bytes(capacity: usize) -> Result<u64, Failure> {
    (capacity as u64)
        .checked_mul(std::mem::size_of::<MembershipAnswer>() as u64)
        .ok_or_else(|| failure(FailureCode::ResourceLimit))
}
fn charge(value: &mut u64, n: u64, max: u64) -> Result<(), Failure> {
    *value = value
        .checked_add(n)
        .filter(|v| *v <= max)
        .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
    Ok(())
}
fn failure(code: FailureCode) -> Failure {
    Failure {
        code,
        location: Location::default(),
        detail: BoundedDetail::None,
    }
}
