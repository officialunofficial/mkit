//! Bounded all-entry verification: streaming decode, authenticated evidence
//! indexes, and sealed `VerifiedPack` construction.
//!
//! The driver pulls immutable pack windows through the caller, resolves every
//! entry in wire order, and commits evidence into paged copy-on-write indexes.
//! Canonical bytes it emits stay provisional until the whole-pack trailer and
//! every signature have been checked; only the terminal [`Step::Complete`]
//! seals a `VerifiedPack`.
mod checkpoints;
mod compute;
mod scheduling;
pub use compute::{
    ComputeConfig, ComputeDisposition, ComputeJob, ComputeOperation, ComputeOutput, ComputePermits,
    ComputeRequest,
};
mod index;
pub mod records;
#[cfg(test)]
mod tests;

use super::{
    Acquisition, ByteRange, ByteSource, EvidencePage, EvidenceSequence, ObjectPurpose, PackCounts,
    Request, RequestId, Response, Step, VerifiedPack,
    framing::{CANONICAL_BYTES, DECODER_SCRATCH, DELTA_BYTES, FRAME_BYTES, map_core},
    integrity::MAX_PACK_BYTES,
    resources::{ResourceUsage, Resources},
};
use crate::{
    closure::edges::{edge_at, edge_count},
    codec::{Budget, failure},
    error::{Failure, FailureCode},
    evidence::{
        MemberFact, PackSource, PageCommitment, PageKind, ProfileId, RepositoryId, RulesetBinding,
        checkpoint::Checkpoint,
        pages::{EncodedPage, EvidenceBinding, INDEXED_RULESET},
    },
    limits::{EvidenceLimits, IndexedProfile, VerifyLimits},
};
use index::{Descent, Event, Index, Op, Sequence, Spine, ordinal_key};
use mkit_core::{
    hash::Hash,
    object::{Object, ObjectType},
    pack::{
        DecodeLimits, DeltaBaseSource, PackEntry, PackError, decode_entry_with,
        window::{FrameInfo, Step as CoreStep, WindowReader},
    },
    serialize::deserialize,
};
use records::{
    DependencyRecord, Domain, HeadRecord, ObjectRecord, OccurrenceRecord, OrdinalRecord, Signature,
};
use std::collections::VecDeque;

/// Index identity for the shared operation plumbing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Which {
    Objects,
    Ordinals,
    Occurrences,
    Dependencies,
    Referenced,
    Heads,
}
const SEQUENCES: [Which; 4] = [
    Which::Occurrences,
    Which::Dependencies,
    Which::Ordinals,
    Which::Heads,
];

fn kind_of(which: Which) -> PageKind {
    match which {
        Which::Objects | Which::Referenced => PageKind::Objects,
        Which::Ordinals => PageKind::Ordinals,
        Which::Occurrences => PageKind::Occurrences,
        Which::Dependencies => PageKind::Dependencies,
        Which::Heads => PageKind::Heads,
    }
}

fn invalid() -> Failure {
    failure(FailureCode::InvalidResponse)
}

fn resource() -> Failure {
    failure(FailureCode::ResourceLimit)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Emit the six canonical empty root pages.
    Roots,
    Header,
    Drain,
    Entries,
    Seal,
    Complete,
    Failed,
}

/// What an outstanding byte-range request feeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum For {
    /// Header, integrity pass, or window reads against the pack source.
    Input,
    /// In-pack delta base canonical bytes.
    Base,
    /// External delta base canonical bytes.
    External,
}

/// One outstanding acquisition; reissued unchanged until answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pending {
    Bytes {
        request: RequestId,
        source: ByteSource,
        range: ByteRange,
        for_: For,
    },
    Member {
        request: RequestId,
        object: Hash,
    },
    Page {
        request: RequestId,
        page: PageCommitment,
    },
}

/// Continuation invoked when an index operation finishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Then {
    /// Objects-map descend for a delta base.
    Base,
    /// Objects-map descend for the decoded object id.
    Object,
    /// Object record insert completed.
    ObjectInserted,
    /// Referenced-map descend for one edge target.
    Referenced,
    /// Referenced-map insert completed.
    ReferencedInserted,
    /// A sequence flush stage finished (`rightmost` marks the descend phase).
    Flush { seq: Which, rightmost: bool },
    /// Ordinals-sequence descend during the seal loop.
    SealOrdinal,
    /// Objects-map descend during the seal loop.
    SealObject,
    /// Referenced-map descend during the seal loop.
    SealReferenced,
    /// Index audit during resume completed.
    Audit { next: usize },
}

/// A live index operation and its resumption.
#[derive(Debug)]
struct Live {
    index: Which,
    op: Op,
    then: Then,
}

/// Per-entry pipeline stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Resolve the delta base (in-pack or external).
    Base,
    /// Decode, canonical validation, signature, and edge extraction.
    Decode,
    /// Wait for the library-created worker output.
    Compute,
    /// Emit provisional canonical fragments.
    Fragments,
    /// Objects-map descend for the decoded id.
    ObjectDescend,
    /// Buffered record appends.
    Records,
    /// Object-map insert for first occurrences.
    ObjectInsert,
    /// Referenced marks for each edge target.
    Referenced,
    /// Pending sequence flushes.
    Flush,
    /// Entry complete; return to the reader.
    Done,
}

/// In-flight entry state between suspension points.
#[derive(Debug)]
struct Work {
    entry: Option<PackEntry<'static>>,
    info: FrameInfo,
    ordinal: u64,
    stage: Stage,
    /// Delta base id when the entry is a delta.
    base: Option<Hash>,
    /// External membership fact for an external base.
    fact: Option<MemberFact>,
    /// Effective base depth for depth accounting.
    base_depth: u32,
    /// Served and validated canonical base bytes.
    base_bytes: Option<Vec<u8>>,
    /// Resident charge held for `base_bytes`.
    base_len: u64,
    /// Decoded object.
    object: Option<Object>,
    id: Hash,
    bytes: Vec<u8>,
    kind: ObjectType,
    canonical_len: u64,
    depth: u32,
    signature: Signature,
    signer: Hash,
    digest: Hash,
    /// Record state.
    first: bool,
    descent: Option<Box<Descent>>,
    dep_start: u64,
    dep_count: u64,
    ext_start: u64,
    ext_count: u64,
    emitted: u64,
    edge_total: u64,
    edge_next: u64,
    chunk_total: u64,
    chunk_count: u64,
}

/// Seal-phase stage: head enumeration over the committed ordinals sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SealStage {
    /// Flush buffered sequences.
    Flush,
    /// Enumerate ordinals, descends, and head appends.
    Heads,
}
/// In-flight head enumeration.
#[derive(Debug)]
struct Seal {
    next: u64,
    stage: SealStage,
    candidate: Hash,
    kind: ObjectType,
    first_ordinal: u64,
    page: PageCommitment,
    position: u64,
}

/// Bounded pull driver for indexed all-entry verification.
///
/// It never buffers a whole pack, never fabricates absence, and commits roots
/// only after the host acknowledges each emitted page. Constructing
/// `VerifiedPack` grants no repository membership or read permission.
#[derive(Debug)]
pub struct VerifyDriver {
    source: PackSource,
    repository: RepositoryId,
    ruleset: RulesetBinding,
    profile: IndexedProfile,
    limits: VerifyLimits,
    generation: u64,
    sequence: u64,
    pending: Option<Pending>,
    phase: Phase,
    deferred_failure: Option<Failure>,
    acquired_hash_end: u64,
    reader: Option<WindowReader>,
    resources: Resources,
    objects: Index,
    ordinals: Sequence,
    occurrences: Sequence,
    dependencies: Sequence,
    referenced: Index,
    heads: Sequence,
    roots: VecDeque<EncodedPage>,
    op: Option<Live>,
    work: Option<Work>,
    seal: Option<Seal>,
    retained: Option<EncodedPage>,
    ordinal: u64,
    payload: u64,
    trailer: Hash,
    retention_count: u64,
    last_retained: Option<PageCommitment>,
    decoded: u64,
    delta_entries: u64,
    edges: u64,
    external_lookups: u64,
    header: Option<(u32, u32)>,
    /// Lowest object id whose signature failed, and its wire ordinal.
    signature_failure: Option<(Hash, u64)>,
    decoder_reservation: u64,
    complete: Option<VerifiedPack>,
    checkpoint: Option<Checkpoint>,
    scheduler: Option<Box<scheduling::Scheduler>>,
}

/// A single-entry delta-base provider holding collected, verified base bytes.
#[derive(Debug)]
struct OneBase {
    id: Hash,
    bytes: Option<Vec<u8>>,
}

impl DeltaBaseSource for OneBase {
    const VERIFIED: bool = true;
    fn base(&mut self, id: &Hash) -> Result<Option<Vec<u8>>, PackError> {
        Ok(if self.id == *id {
            self.bytes.take()
        } else {
            None
        })
    }
}

impl VerifyDriver {
    /// Starts an indexed all-entry verification run.
    ///
    /// # Errors
    /// Refuses short/oversized sources, impossible execution budgets, and
    /// arithmetic overflow before acquiring bytes or allocating state.
    pub fn new(
        source: PackSource,
        repository: RepositoryId,
        profile: IndexedProfile,
        limits: VerifyLimits,
        generation: u64,
    ) -> Result<Self, Failure> {
        if source.len < 44 {
            return Err(failure(FailureCode::PackfileTooShort));
        }
        if source.len > MAX_PACK_BYTES || source.len > profile.pack_bytes {
            return Err(failure(FailureCode::PackfileTooLarge));
        }
        let mut resources = Resources::new(limits)?;
        let decoder_reservation = Self::decoder_baseline(limits)?;
        resources.reserve(
            u64::try_from(std::mem::size_of::<Self>())
                .map_err(|_| failure(FailureCode::ResourceLimit))?,
        )?;
        resources.reserve(decoder_reservation)?;
        let reader = WindowReader::new_one_pass(
            source.len,
            limits.acquisition_bytes,
            Self::decode_limits(),
            Some(source.id),
        )
        .map_err(|error| map_core(&error))?;
        let binding = Self::binding(source, repository);
        let evidence = EvidenceLimits {
            page_bytes: limits.page_bytes,
            allocated_bytes: limits.page_bytes,
            ..EvidenceLimits::indexed()
        };
        let (objects, p0) = Index::new(kind_of(Which::Objects), binding, evidence)?;
        let (ordinals, p1) = Sequence::new(kind_of(Which::Ordinals), binding, evidence)?;
        let (occurrences, p2) = Sequence::new(kind_of(Which::Occurrences), binding, evidence)?;
        let (dependencies, p3) = Sequence::new(kind_of(Which::Dependencies), binding, evidence)?;
        let (referenced, p4) = Index::new(kind_of(Which::Referenced), binding, evidence)?;
        let (heads, p5) = Sequence::new(kind_of(Which::Heads), binding, evidence)?;
        let mut driver = Self {
            source,
            repository,
            ruleset: binding.ruleset,
            profile,
            limits,
            generation,
            sequence: 0,
            pending: None,
            phase: Phase::Roots,
            deferred_failure: None,
            acquired_hash_end: 0,
            reader: Some(reader),
            resources,
            objects,
            ordinals,
            occurrences,
            dependencies,
            referenced,
            heads,
            roots: VecDeque::new(),
            op: None,
            work: None,
            seal: None,
            retained: None,
            ordinal: 0,
            payload: 0,
            trailer: [0; 32],
            retention_count: 0,
            last_retained: None,
            decoded: 0,
            delta_entries: 0,
            edges: 0,
            external_lookups: 0,
            header: None,
            signature_failure: None,
            decoder_reservation,
            complete: None,
            checkpoint: None,
            scheduler: None,
        };
        driver
            .roots
            .try_reserve_exact(6)
            .map_err(|_| failure(FailureCode::ResourceLimit))?;
        for page in [p0, p1, p2, p3, p4, p5] {
            driver.roots.push_back(page);
        }
        Ok(driver)
    }

    fn binding(source: PackSource, repository: RepositoryId) -> EvidenceBinding {
        EvidenceBinding {
            source,
            repository,
            ruleset: RulesetBinding {
                ruleset: INDEXED_RULESET,
                profile: ProfileId::Indexed,
            },
        }
    }

    /// Cumulative and peak accounting, including conservative decoder scratch.
    #[must_use]
    pub const fn usage(&self) -> ResourceUsage {
        self.resources.usage()
    }

    fn index_mut(&mut self, which: Which) -> &mut Index {
        match which {
            Which::Objects => &mut self.objects,
            Which::Ordinals => self.ordinals.index(),
            Which::Occurrences => self.occurrences.index(),
            Which::Dependencies => self.dependencies.index(),
            Which::Referenced => &mut self.referenced,
            Which::Heads => self.heads.index(),
        }
    }

    fn sequence_mut(&mut self, which: Which) -> Result<&mut Sequence, Failure> {
        match which {
            Which::Ordinals => Ok(&mut self.ordinals),
            Which::Occurrences => Ok(&mut self.occurrences),
            Which::Dependencies => Ok(&mut self.dependencies),
            Which::Heads => Ok(&mut self.heads),
            Which::Objects | Which::Referenced => Err(invalid()),
        }
    }

    fn request_id(&mut self) -> Result<RequestId, Failure> {
        let request = RequestId {
            generation: self.generation,
            sequence: self.sequence,
        };
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        Ok(request)
    }

    /// Parks `pending` and returns its request step.
    fn issue(&mut self, pending: Pending) -> Step<'static> {
        self.pending = Some(pending);
        Self::step_of(self.repository, pending)
    }

    fn step_of(repository: RepositoryId, pending: Pending) -> Step<'static> {
        match pending {
            Pending::Bytes {
                request,
                source,
                range,
                ..
            } => Step::Request(Request::Bytes {
                request,
                source,
                range,
            }),
            Pending::Member { request, object } => Step::Request(Request::ExternalObject {
                request,
                repository,
                object,
                purpose: ObjectPurpose::DeltaBase,
            }),
            Pending::Page { request, page } => {
                Step::Request(Request::EvidencePage { request, page })
            }
        }
    }

    /// Advances one bounded transition.
    ///
    /// # Errors
    /// Preserves content, resource, and evidence failures; a terminal failure
    /// makes the driver inert. Requests remain stable until a matching reply
    /// is supplied.
    pub fn step(&mut self) -> Result<Step<'_>, Failure> {
        self.release_checkpoint()?;
        if self.phase == Phase::Failed {
            return Err(invalid());
        }
        if self.retained.is_some() {
            return self.retention_event();
        }
        if let Some(pending) = self.pending {
            return Ok(Self::step_of(self.repository, pending));
        }
        if self.op.is_some() {
            let result = self.drive_op();
            return match result {
                Err(error) if self.phase == Phase::Entries && Self::entry_refusal(&error) => {
                    self.defer_failure(error)?;
                    Ok(Step::Progress)
                }
                Err(error) => {
                    self.phase = Phase::Failed;
                    Err(error)
                }
                result => result,
            };
        }
        if let Some(page) = self.roots.pop_front() {
            self.resources.reserve(self.limits.page_bytes)?;
            let len = page.bytes().len() as u64;
            self.resources.evidence(len)?;
            self.retained = Some(page);
            return self.retention_event();
        }
        if self.phase == Phase::Entries
            && let Some(request) = self.compute_request()
        {
            return Ok(request);
        }
        // Provisional fragments borrow the in-flight entry; emit them ahead of
        // the `'static` phase match so the terminal-failure flag can settle.
        if self.phase == Phase::Entries
            && self
                .work
                .as_ref()
                .is_some_and(|work| work.stage == Stage::Fragments)
        {
            return self.emit_fragment();
        }
        let result: Result<Step<'static>, Failure> = match self.phase {
            Phase::Roots => {
                self.phase = Phase::Header;
                self.start_input()
            }
            Phase::Header => self.start_input(),
            Phase::Drain => self.advance_drain(),
            Phase::Entries => self.advance_entries(),
            Phase::Seal => self.advance_seal(),
            Phase::Complete => self
                .complete
                .clone()
                .map(Step::Complete)
                .ok_or_else(invalid),
            Phase::Failed => Err(invalid()),
        };
        let result = match result {
            Err(error) if self.phase == Phase::Entries && Self::entry_refusal(&error) => {
                self.defer_failure(error)?;
                Ok(Step::Progress)
            }
            result => result,
        };
        if result.is_err() && self.phase != Phase::Failed {
            self.phase = Phase::Failed;
        }
        result
    }

    fn start_input(&mut self) -> Result<Step<'static>, Failure> {
        let reader = self.reader.as_mut().ok_or_else(invalid)?;
        match reader.step().map_err(|error| map_core(&error))? {
            CoreStep::NeedWindow(range) => self.request_input(range.offset, range.len),
            _ => Err(invalid()),
        }
    }

    fn request_input(&mut self, offset: u64, len: u64) -> Result<Step<'static>, Failure> {
        let request = self.request_id()?;
        Ok(self.issue(Pending::Bytes {
            request,
            source: ByteSource::Pack(self.source),
            range: ByteRange { offset, len },
            for_: For::Input,
        }))
    }

    fn retention_event(&self) -> Result<Step<'_>, Failure> {
        let page = self.retained.as_ref().ok_or_else(invalid)?;
        Ok(Step::RetainEvidence(EvidencePage {
            commitment: page.commitment(),
            bytes: page.bytes(),
        }))
    }

    /// Acknowledges exactly the outstanding page.
    ///
    /// # Errors
    /// Wrong, unsolicited, and duplicate acknowledgements are `InvalidResponse`
    /// and preserve the outstanding retention request.
    pub fn acknowledge_retention(&mut self, commitment: PageCommitment) -> Result<(), Failure> {
        self.release_checkpoint()?;
        if self.phase == Phase::Failed {
            return Err(invalid());
        }
        let retained = self.retained.take().ok_or_else(invalid)?;
        if retained.commitment() != commitment {
            self.retained = Some(retained);
            return Err(invalid());
        }
        if self.op.is_some() {
            let mut live = self.op.take().ok_or_else(invalid)?;
            let result = Index::acknowledge(&mut live.op, commitment);
            self.op = Some(live);
            if let Err(failure) = result {
                self.retained = Some(retained);
                return Err(failure);
            }
        }
        self.resources.release(self.limits.page_bytes)?;
        self.retention_count = self
            .retention_count
            .checked_add(1)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        self.last_retained = Some(commitment);
        Ok(())
    }

    /// Supplies exactly the outstanding acquisition.
    ///
    /// # Errors
    /// Wrong identities, stale/duplicate replies, and wrong lengths are
    /// `InvalidResponse` and leave the request pending. `Unavailable`
    /// acquisition is `UnavailableInput`; it never proves absence.
    pub fn supply(&mut self, response: Response<'_>) -> Result<(), Failure> {
        self.release_checkpoint()?;
        if self.phase == Phase::Failed {
            return Err(invalid());
        }
        let pending = self.pending.ok_or_else(invalid)?;
        match (pending, response) {
            (
                Pending::Bytes {
                    request,
                    source,
                    range,
                    for_,
                },
                Response::Bytes {
                    request: id,
                    source: src,
                    range: rng,
                    value,
                },
            ) => {
                if request != id || source != src || range != rng {
                    return Err(invalid());
                }
                let Acquisition::Present(bytes) = value else {
                    return Err(failure(FailureCode::UnavailableInput));
                };
                if u64::try_from(bytes.len()).ok() != Some(range.len) {
                    return Err(invalid());
                }
                self.pending = None;
                match for_ {
                    For::Input => self.accept_input(range.offset, bytes),
                    For::Base | For::External => {
                        // Served base bytes are deserialized, hashed, and
                        // copied before the entry decodes: the same three
                        // passes integrity feeds pay.
                        self.accept_base_input(for_ == For::External, range, bytes)
                    }
                }
            }
            (
                Pending::Member { request, object },
                Response::ExternalObject { request: id, value },
            ) => {
                if request != id {
                    return Err(invalid());
                }
                let fact = match value {
                    Acquisition::Present(fact) => fact,
                    Acquisition::Absent => {
                        self.pending = None;
                        return self.defer_failure(failure(FailureCode::ExternalBaseAbsent));
                    }
                    Acquisition::Unavailable => {
                        return Err(failure(FailureCode::UnavailableInput));
                    }
                };
                match self.accept_member(object, fact) {
                    Err(error) if Self::entry_refusal(&error) => {
                        self.pending = None;
                        self.defer_failure(error)
                    }
                    result => result,
                }
            }
            (
                Pending::Page { request, page },
                Response::EvidencePage {
                    request: id,
                    page: commitment,
                    value,
                },
            ) => {
                if request != id || page != commitment {
                    return Err(invalid());
                }
                let Acquisition::Present(bytes) = value else {
                    return Err(failure(FailureCode::UnavailableInput));
                };
                self.pending = None;
                let mut live = self.op.take().ok_or_else(invalid)?;
                let mut budget = Budget::new(self.limits.work, self.limits.resident_bytes);
                let result = self
                    .index_mut(live.index)
                    .feed(&mut live.op, bytes, &mut budget);
                let used = self.limits.work.saturating_sub(budget.remaining());
                self.op = Some(live);
                let charged = self.resources.work(used);
                match result.and(charged) {
                    Err(error) if self.phase == Phase::Entries && Self::entry_refusal(&error) => {
                        self.defer_failure(error)
                    }
                    result => result,
                }
            }
            _ => Err(invalid()),
        }
    }

    fn accept_base_input(
        &mut self,
        external: bool,
        range: ByteRange,
        bytes: &[u8],
    ) -> Result<(), Failure> {
        let result = (|| {
            self.resources
                .work(range.len.checked_mul(3).ok_or_else(resource)?)?;
            self.accept_base(external, range, bytes)
        })();
        match result {
            Err(error) if Self::entry_refusal(&error) => self.defer_failure(error),
            result => result,
        }
    }

    fn accept_member(&mut self, object: Hash, fact: MemberFact) -> Result<(), Failure> {
        if fact.repository != self.repository || fact.object != object {
            return Err(invalid());
        }
        if fact.held || !fact.published {
            self.pending = None;
            return self.defer_failure(failure(FailureCode::ExternalBaseAbsent));
        }
        // A fact that cannot name servable canonical bytes is a protocol
        // violation, not a missing member.
        if fact.canonical_len == 0 || fact.canonical_len > CANONICAL_BYTES {
            return Err(invalid());
        }
        self.resources.charge_external()?;
        let external_lookups = self
            .external_lookups
            .checked_add(1)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        if external_lookups > self.limits.external_lookups {
            return Err(failure(FailureCode::ResourceLimit));
        }
        self.external_lookups = external_lookups;
        self.pending = None;
        let canonical_len = fact.canonical_len;
        let binding = fact.canonical_binding;
        let work = self.work.as_mut().ok_or_else(invalid)?;
        work.fact = Some(fact);
        let request = self.request_id()?;
        let pending = Pending::Bytes {
            request,
            source: ByteSource::Canonical {
                object,
                len: canonical_len,
                binding,
            },
            range: ByteRange {
                offset: 0,
                len: canonical_len,
            },
            for_: For::External,
        };
        self.pending = Some(pending);
        Ok(())
    }

    fn accept_input(&mut self, offset: u64, bytes: &[u8]) -> Result<(), Failure> {
        let result = (|| {
            if self.phase == Phase::Header {
                self.accept_header(bytes)?;
                self.resources
                    .protect_work(self.source.len.checked_mul(3).ok_or_else(resource)?)?;
                self.loan_compute_control()?;
                self.phase = Phase::Entries;
            }
            if !matches!(self.phase, Phase::Entries | Phase::Drain) {
                return Err(invalid());
            }
            let len = u64::try_from(bytes.len()).map_err(|_| resource())?;
            let end = offset.checked_add(len).ok_or_else(resource)?;
            let fresh = end.saturating_sub(self.acquired_hash_end).min(len);
            let memory = self
                .reader
                .as_ref()
                .ok_or_else(invalid)?
                .memory_bound(0)
                .checked_add(len.checked_mul(2).ok_or_else(resource)?)
                .and_then(|n| n.checked_add(64 << 10))
                .ok_or_else(resource)?;
            self.resize_decoder(memory.max(Self::decoder_baseline(self.limits)?))?;
            self.resources
                .work((len - fresh).checked_mul(3).ok_or_else(resource)?)?;
            self.resources
                .integrity_work(fresh.checked_mul(3).ok_or_else(resource)?)?;
            self.reader
                .as_mut()
                .ok_or_else(invalid)?
                .feed(offset, bytes)
                .map_err(|error| map_core(&error))?;
            self.acquired_hash_end = self.acquired_hash_end.max(end);
            Ok(())
        })();
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result
    }

    fn accept_header(&mut self, bytes: &[u8]) -> Result<(), Failure> {
        if bytes.get(..4) != Some(b"MKIT") {
            return Err(failure(FailureCode::InvalidMagic));
        }
        let version = u32::from_le_bytes(
            bytes
                .get(4..8)
                .ok_or_else(|| failure(FailureCode::UnexpectedEof))?
                .try_into()
                .map_err(|_| failure(FailureCode::UnexpectedEof))?,
        );
        if !matches!(version, 1 | 2) {
            return Err(failure(FailureCode::UnsupportedPackVersion));
        }
        let count = u32::from_le_bytes(
            bytes
                .get(8..12)
                .ok_or_else(|| failure(FailureCode::UnexpectedEof))?
                .try_into()
                .map_err(|_| failure(FailureCode::UnexpectedEof))?,
        );
        self.header = Some((version, count));
        Ok(())
    }

    fn accept_base(
        &mut self,
        external: bool,
        range: ByteRange,
        bytes: &[u8],
    ) -> Result<(), Failure> {
        let work = self.work.as_mut().ok_or_else(invalid)?;
        let base = work.base.ok_or_else(invalid)?;
        // Served canonical bytes must deserialize to the storable object the
        // request named; anything else breaks the acquisition contract.
        let object = deserialize(bytes).map_err(|_| invalid())?;
        if mkit_core::object::id_from_object(&object, bytes) != base
            || bytes.len() as u64 != range.len
        {
            return Err(invalid());
        }
        let depth = if external {
            let fact = work.fact.as_ref().ok_or_else(invalid)?;
            if fact.canonical_len != bytes.len() as u64
                || fact.object != base
                || fact.kind != object.object_type()
            {
                return Err(invalid());
            }
            fact.delta_depth
        } else {
            work.base_depth
        };
        work.base_depth = depth;
        let base_len =
            u64::try_from(bytes.len()).map_err(|_| failure(FailureCode::ResourceLimit))?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| failure(FailureCode::ResourceLimit))?;
        self.resources.reserve(base_len)?;
        owned.extend_from_slice(bytes);
        work.base_len = base_len;
        work.base_bytes = Some(owned);
        work.stage = Stage::Decode;
        Ok(())
    }

    /// Record only the first content verdict, then finish authenticating the
    /// immutable source. Later entries cannot change this wire-order choice.
    fn defer_failure(&mut self, error: Failure) -> Result<(), Failure> {
        if self.deferred_failure.is_none() {
            self.deferred_failure = Some(error);
        }
        if let Some(work) = self.work.take() {
            self.resources.release(work.base_len)?;
        }
        self.op = None;
        self.discard_compute();
        self.phase = Phase::Drain;
        // Mark the reader before permitting a checkpoint of this drain. A
        // returned request is replayed by advance_drain without acquiring it.
        if let Err(error) = self.reader.as_mut().ok_or_else(invalid)?.integrity_step() {
            self.phase = Phase::Failed;
            return Err(map_core(&error));
        }
        Ok(())
    }

    fn entry_refusal(error: &Failure) -> bool {
        matches!(
            error.code,
            FailureCode::UnexpectedEof
                | FailureCode::InvalidEntryType
                | FailureCode::TooManyObjects
                | FailureCode::PackfileTooLarge
                | FailureCode::ZstdEntryTruncated
                | FailureCode::DeltaEntryTruncated
                | FailureCode::NonStorableObject
                | FailureCode::TrailingData
                | FailureCode::DecompressionFailed
                | FailureCode::DecompressedSizeMismatch
                | FailureCode::DecompressionLimitExceeded
                | FailureCode::InvalidDelta
                | FailureCode::DeltaBaseMismatch
                | FailureCode::DeltaSizeMismatch
                | FailureCode::NonCanonicalObject
                | FailureCode::ObjectHashMismatch
                | FailureCode::DeltaChainTooDeep
                | FailureCode::ExternalBaseAbsent
                | FailureCode::ResourceLimit
                | FailureCode::UnsupportedCapability
        )
    }

    fn advance_drain(&mut self) -> Result<Step<'static>, Failure> {
        match self
            .reader
            .as_mut()
            .ok_or_else(invalid)?
            .integrity_step()
            .map_err(|error| map_core(&error))?
        {
            CoreStep::NeedWindow(range) => self.request_input(range.offset, range.len),
            CoreStep::Done(_) => Err(self.deferred_failure.take().ok_or_else(invalid)?),
            _ => Err(invalid()),
        }
    }

    const fn canonical_workspace() -> u64 {
        // Entry/canonical ownership, deserialized objects and transient clones
        // share this allowance; reader carry and zstd scratch are separate.
        8 * CANONICAL_BYTES + (64 << 10)
    }

    fn decoder_baseline(limits: VerifyLimits) -> Result<u64, Failure> {
        limits
            .acquisition_bytes
            .checked_mul(2)
            .and_then(|n| n.checked_add(Self::canonical_workspace()))
            .ok_or_else(resource)
    }

    fn resize_decoder(&mut self, bytes: u64) -> Result<(), Failure> {
        if bytes > self.decoder_reservation {
            self.resources.reserve(bytes - self.decoder_reservation)?;
        } else {
            self.resources.release(self.decoder_reservation - bytes)?;
        }
        self.decoder_reservation = bytes;
        Ok(())
    }

    fn read_entry_step(&mut self) -> Result<CoreStep, Failure> {
        let memory = self
            .reader
            .as_ref()
            .ok_or_else(invalid)?
            .memory_bound(DECODER_SCRATCH)
            .checked_add(64 << 10)
            .ok_or_else(resource)?;
        self.resize_decoder(memory.max(Self::decoder_baseline(self.limits)?))?;
        let result = self
            .reader
            .as_mut()
            .ok_or_else(invalid)?
            .step()
            .map_err(|error| map_core(&error));
        if result.is_ok() {
            let memory = self
                .reader
                .as_ref()
                .ok_or_else(invalid)?
                .memory_bound(0)
                .checked_add(64 << 10)
                .ok_or_else(resource)?;
            self.resize_decoder(memory.max(Self::decoder_baseline(self.limits)?))?;
        }
        result
    }

    fn decode_limits() -> DecodeLimits {
        DecodeLimits::default()
            .with_max_decoded_bytes(CANONICAL_BYTES)
            .with_entry_geometry(FRAME_BYTES, DELTA_BYTES)
    }

    fn advance_entries(&mut self) -> Result<Step<'static>, Failure> {
        if self.work.is_some() {
            return self.advance_work();
        }
        if self.scheduler.is_some() {
            return self.advance_scheduled();
        }
        match self.read_entry_step()? {
            CoreStep::NeedWindow(range) => self.request_input(range.offset, range.len),
            CoreStep::Entry(entry) => {
                let info = self
                    .reader
                    .as_ref()
                    .and_then(WindowReader::last_frame)
                    .ok_or_else(invalid)?;
                self.start_entry(entry, info)
            }
            CoreStep::Done(summary) => self.entries_done(summary.version, summary.entry_count),
            _ => Err(invalid()),
        }
    }

    fn start_entry(
        &mut self,
        entry: PackEntry<'static>,
        info: FrameInfo,
    ) -> Result<Step<'static>, Failure> {
        self.resources.work(1)?;
        let ordinal = self.ordinal;
        let base = match &entry {
            PackEntry::Delta { base, .. } => Some(*base),
            PackEntry::Raw { .. } => None,
        };
        self.ordinal = ordinal
            .checked_add(1)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        self.payload = self
            .payload
            .checked_add(
                info.length
                    .checked_sub(5)
                    .ok_or_else(|| failure(FailureCode::InvalidResponse))?,
            )
            .ok_or_else(|| failure(FailureCode::PackfileTooLarge))?;
        self.work = Some(Work {
            entry: Some(entry),
            info,
            ordinal,
            stage: if base.is_some() {
                Stage::Base
            } else {
                Stage::Decode
            },
            base,
            fact: None,
            base_depth: 0,
            base_bytes: None,
            base_len: 0,
            object: None,
            id: [0; 32],
            bytes: Vec::new(),
            kind: ObjectType::Blob,
            canonical_len: 0,
            depth: 0,
            signature: Signature::None,
            signer: [0; 32],
            digest: [0; 32],
            first: false,
            descent: None,
            dep_start: 0,
            dep_count: 0,
            ext_start: 0,
            ext_count: 0,
            emitted: 0,
            edge_total: 0,
            edge_next: 0,
            chunk_total: 0,
            chunk_count: 0,
        });
        self.advance_work()
    }

    fn entries_done(&mut self, version: u32, entry_count: u32) -> Result<Step<'static>, Failure> {
        if self.header != Some((version, entry_count)) || self.ordinal != u64::from(entry_count) {
            return Err(failure(FailureCode::SourceChanged));
        }
        self.trailer = self
            .reader
            .as_ref()
            .and_then(WindowReader::trailer)
            .ok_or_else(invalid)?;
        self.reader = None;
        // Decoding finished; deferred signature selection fires here,
        // before any further evidence work.
        if self.signature_failure.is_some() {
            return Err(failure(FailureCode::BadSignature));
        }
        self.phase = Phase::Seal;
        self.seal = Some(Seal {
            next: 0,
            stage: SealStage::Flush,
            candidate: [0; 32],
            kind: ObjectType::Blob,
            first_ordinal: 0,
            page: PageCommitment {
                digest: [0; 32],
                kind: PageKind::Objects,
                len: 0,
                items: 0,
            },
            position: 0,
        });
        Ok(Step::Progress)
    }

    fn advance_work(&mut self) -> Result<Step<'static>, Failure> {
        let stage = self.work.as_ref().ok_or_else(invalid)?.stage;
        match stage {
            Stage::Base => self.begin_base(),
            Stage::Decode => self.finish_decode(),
            Stage::Compute => self.finish_compute(),
            Stage::Fragments => Ok(Step::Progress),
            Stage::ObjectDescend => self.begin_object_descend(),
            Stage::Records => self.append_records(),
            Stage::ObjectInsert => self.begin_object_insert(),
            Stage::Referenced => self.advance_referenced(),
            Stage::Flush => self.advance_flush(),
            Stage::Done => {
                self.retire_compute()?;
                self.work = None;
                Ok(Step::Progress)
            }
        }
    }

    fn begin_base(&mut self) -> Result<Step<'static>, Failure> {
        let base = self
            .work
            .as_ref()
            .and_then(|work| work.base)
            .ok_or_else(invalid)?;
        self.op = Some(Live {
            index: Which::Objects,
            op: self.objects.descend(base),
            then: Then::Base,
        });
        self.drive_op()
    }

    fn finish_decode(&mut self) -> Result<Step<'static>, Failure> {
        if self.scheduler.is_some() {
            return self.dispatch_entry();
        }
        let work = self.work.as_mut().ok_or_else(invalid)?;
        let entry = work.entry.take().ok_or_else(invalid)?;
        let mut bases = OneBase {
            id: work.base.unwrap_or([0; 32]),
            bytes: work.base_bytes.take(),
        };
        let (id, bytes) = decode_entry_with(entry, &mut bases, Self::decode_limits())
            .map_err(|error| map_core(&error))?;
        let base_len = std::mem::take(&mut work.base_len);
        self.resources.release(base_len)?;
        let object = deserialize(&bytes).map_err(|_| failure(FailureCode::NonCanonicalObject))?;
        self.finish_canonical(id, bytes, object, None)
    }

    fn finish_canonical(
        &mut self,
        id: Hash,
        bytes: Vec<u8>,
        object: Object,
        signature: Option<Result<compute::SignatureFacts, Failure>>,
    ) -> Result<Step<'static>, Failure> {
        let work = self.work.as_mut().ok_or_else(invalid)?;
        let kind = object.object_type();
        let canonical_len =
            u64::try_from(bytes.len()).map_err(|_| failure(FailureCode::ResourceLimit))?;
        // Canonical passes: deserialize, validate, and hash the object once.
        self.resources.work(canonical_len)?;
        let decoded = self
            .decoded
            .checked_add(canonical_len)
            .ok_or_else(|| failure(FailureCode::PackfileTooLarge))?;
        if decoded > self.profile.decoded_bytes || decoded > self.limits.decoded_bytes {
            return Err(failure(FailureCode::PackfileTooLarge));
        }
        self.decoded = decoded;
        if work.base.is_some() {
            self.delta_entries = self
                .delta_entries
                .checked_add(1)
                .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        }
        // Effective depth: an external base contributes its recorded depth.
        let depth = if work.base.is_some() {
            work.base_depth
                .checked_add(1)
                .ok_or_else(|| failure(FailureCode::DeltaChainTooDeep))?
        } else {
            0
        };
        if depth > self.profile.delta_depth {
            return Err(failure(FailureCode::DeltaChainTooDeep));
        }
        let facts = match signature {
            Some(facts) => facts?,
            None => compute::signature_facts(&object)?,
        };
        let compute::SignatureFacts {
            signature,
            signer,
            digest,
            ..
        } = facts;
        if signature == Signature::Invalid
            && self.signature_failure.is_none_or(|(prior, _)| id < prior)
        {
            self.signature_failure = Some((id, work.ordinal));
        }
        work.edge_total = edge_count(&object);
        if let Object::ChunkedBlob(manifest) = &object {
            work.chunk_total = manifest.total_size;
            work.chunk_count = manifest.chunks.len() as u64;
        }
        let edges = self
            .edges
            .checked_add(work.edge_total)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        if edges > self.limits.dependency_edges {
            return Err(failure(FailureCode::ResourceLimit));
        }
        self.edges = edges;
        work.object = Some(object);
        work.id = id;
        work.bytes = bytes;
        work.kind = kind;
        work.canonical_len = canonical_len;
        work.depth = depth;
        work.signature = signature;
        if signature == Signature::None {
            work.signer = [0; 32];
            work.digest = [0; 32];
        } else {
            work.signer = signer;
            work.digest = digest;
        }
        work.stage = Stage::Fragments;
        Ok(Step::Progress)
    }

    fn emit_fragment(&mut self) -> Result<Step<'_>, Failure> {
        let Some(work) = self.work.as_mut() else {
            self.phase = Phase::Failed;
            return Err(invalid());
        };
        let total = work.bytes.len() as u64;
        if work.emitted >= total {
            work.stage = Stage::ObjectDescend;
            return Ok(Step::Progress);
        }
        let chunk = (total - work.emitted).min(self.limits.acquisition_bytes);
        let offset = work.emitted;
        work.emitted += chunk;
        let start = usize::try_from(offset).map_err(|_| resource())?;
        let end = start + usize::try_from(chunk).map_err(|_| resource())?;
        Ok(Step::ProvisionalObject(super::ObjectFragment {
            ordinal: work.ordinal,
            offset,
            bytes: &work.bytes[start..end],
        }))
    }

    fn begin_object_descend(&mut self) -> Result<Step<'static>, Failure> {
        let id = self.work.as_ref().ok_or_else(invalid)?.id;
        self.op = Some(Live {
            index: Which::Objects,
            op: self.objects.descend(id),
            then: Then::Object,
        });
        self.drive_op()
    }

    fn append_records(&mut self) -> Result<Step<'static>, Failure> {
        // External facts precede their consuming occurrence so its record can
        // carry the exact dependency span.
        let work = self.work.as_mut().ok_or_else(invalid)?;
        work.ext_start = self.dependencies.committed() + self.dependencies.pending() as u64;
        if let Some(fact) = work.fact.clone() {
            work.ext_count = 1;
            let value = DependencyRecord::External {
                consumed_ordinal: work.ordinal,
                child: work.id,
                fact,
            }
            .to_bytes();
            let len =
                u64::try_from(value.len()).map_err(|_| failure(FailureCode::ResourceLimit))?;
            self.resources.reserve(len)?;
            self.dependencies.append(value);
        }
        work.dep_start = self.dependencies.committed() + self.dependencies.pending() as u64;
        if work.first {
            let subject = work.id;
            let subject_ordinal = work.ordinal;
            let total = work.edge_total;
            let object = work.object.clone().ok_or_else(invalid)?;
            for ordinal in 0..total {
                let edge = edge_at(&object, ordinal).ok_or_else(invalid)?;
                let value = DependencyRecord::Edge {
                    subject,
                    subject_ordinal,
                    edge,
                }
                .to_bytes();
                let len =
                    u64::try_from(value.len()).map_err(|_| failure(FailureCode::ResourceLimit))?;
                self.resources.reserve(len)?;
                self.dependencies.append(value);
            }
            work.dep_count = total;
        }
        let value = OccurrenceRecord {
            object: work.id,
            kind: work.kind,
            canonical_len: work.canonical_len,
            frame_offset: work.info.offset,
            frame_len: work.info.length,
            wire_type: work.info.wire_type,
            from_delta: work.base.is_some(),
            delta_base: work.base.unwrap_or([0; 32]),
            delta_depth: work.depth,
            signature: work.signature,
            first: work.first,
            domain: Domain::for_kind(work.kind),
            signer: work.signer,
            signing_digest: work.digest,
            ext_start: work.ext_start,
            ext_count: work.ext_count,
        }
        .to_bytes();
        let len = u64::try_from(value.len()).map_err(|_| failure(FailureCode::ResourceLimit))?;
        self.resources.reserve(len)?;
        self.occurrences.append(value);
        if work.first {
            let value = OrdinalRecord {
                object: work.id,
                kind: work.kind,
                canonical_len: work.canonical_len,
            }
            .to_bytes();
            let len =
                u64::try_from(value.len()).map_err(|_| failure(FailureCode::ResourceLimit))?;
            self.resources.reserve(len)?;
            self.ordinals.append(value);
            work.stage = Stage::ObjectInsert;
        } else {
            work.stage = Stage::Flush;
        }
        Ok(Step::Progress)
    }

    fn begin_object_insert(&mut self) -> Result<Step<'static>, Failure> {
        let work = self.work.as_mut().ok_or_else(invalid)?;
        let mut descent = *work.descent.take().ok_or_else(invalid)?;
        let mut records = std::mem::take(&mut descent.records);
        let record = ObjectRecord {
            kind: work.kind,
            canonical_len: work.canonical_len,
            first_ordinal: work.ordinal,
            delta_depth: work.depth,
            signature: work.signature,
            domain: Domain::for_kind(work.kind),
            signer: work.signer,
            signing_digest: work.digest,
            dep_start: work.dep_start,
            dep_count: work.dep_count,
            chunk_total: work.chunk_total,
            chunk_count: work.chunk_count,
        };
        records.insert(descent.position, (work.id, record.to_bytes()));
        self.op = Some(Live {
            index: Which::Objects,
            op: Index::rewrite(descent, records, false, 1, false),
            then: Then::ObjectInserted,
        });
        self.drive_op()
    }

    fn advance_referenced(&mut self) -> Result<Step<'static>, Failure> {
        let work = self.work.as_mut().ok_or_else(invalid)?;
        if work.edge_next >= work.edge_total {
            work.stage = Stage::Flush;
            return Ok(Step::Progress);
        }
        let object = work.object.as_ref().ok_or_else(invalid)?;
        let target = edge_at(object, work.edge_next).ok_or_else(invalid)?.target;
        self.op = Some(Live {
            index: Which::Referenced,
            op: self.referenced.descend(target),
            then: Then::Referenced,
        });
        self.drive_op()
    }

    fn advance_flush(&mut self) -> Result<Step<'static>, Failure> {
        for seq in SEQUENCES {
            let sequence = self.sequence_mut(seq)?;
            if sequence.pending() == 0 {
                continue;
            }
            let op = sequence.flush()?;
            let rightmost = matches!(
                op,
                Op::Descend {
                    rightmost: true,
                    ..
                }
            );
            self.op = Some(Live {
                index: seq,
                op,
                then: Then::Flush { seq, rightmost },
            });
            return self.drive_op();
        }
        let work = self.work.as_mut().ok_or_else(invalid)?;
        work.stage = Stage::Done;
        Ok(Step::Progress)
    }

    fn drive_op(&mut self) -> Result<Step<'static>, Failure> {
        let mut live = self.op.take().ok_or_else(invalid)?;
        let event = self.index_mut(live.index).poll(&mut live.op);
        match event {
            Err(failure) => {
                self.op = Some(live);
                Err(failure)
            }
            Ok(Event::Page(commitment)) => {
                self.op = Some(live);
                self.resources.work(1)?;
                let request = self.request_id()?;
                Ok(self.issue(Pending::Page {
                    request,
                    page: commitment,
                }))
            }
            Ok(Event::Emit(page)) => {
                self.op = Some(live);
                let len = page.bytes().len() as u64;
                // Emitted pages were decoded, authenticated, and encoded; the
                // passes mirror the four framing charges per produced page.
                self.resources.work(
                    len.checked_mul(4)
                        .ok_or_else(|| failure(FailureCode::ResourceLimit))?,
                )?;
                self.resources.reserve(self.limits.page_bytes)?;
                self.resources.evidence(len)?;
                self.retained = Some(page);
                Ok(Step::Progress)
            }
            Ok(Event::Descended(descent)) => self.after_descend(&live, *descent),
            Ok(Event::Done { spine }) => self.after_done(&live, spine),
        }
    }

    fn after_descend(&mut self, live: &Live, descent: Descent) -> Result<Step<'static>, Failure> {
        match live.then {
            Then::Base => self.base_route(&descent),
            Then::Object => {
                let work = self.work.as_mut().ok_or_else(invalid)?;
                work.first = !descent.found;
                work.descent = if descent.found {
                    None
                } else {
                    Some(Box::new(descent))
                };
                work.stage = Stage::Records;
                Ok(Step::Progress)
            }
            Then::Referenced => {
                if descent.found {
                    return self.next_edge();
                }
                let target = self.edge_target()?;
                let mut records = descent.records.clone();
                records.insert(descent.position, (target, Vec::new()));
                self.op = Some(Live {
                    index: Which::Referenced,
                    op: Index::rewrite(descent, records, false, 1, false),
                    then: Then::ReferencedInserted,
                });
                self.drive_op()
            }
            Then::Flush { seq, rightmost } => {
                if !rightmost {
                    return Err(invalid());
                }
                // The descended leaf becomes the sequence spine; its record
                // bytes are resident from here and release with the flush.
                let spine_bytes = descent
                    .records
                    .iter()
                    .map(|(_, value)| u64::try_from(value.len()).unwrap_or(u64::MAX))
                    .fold(0, u64::saturating_add);
                self.resources.reserve(spine_bytes)?;
                let op = self.sequence_mut(seq)?.graft(descent);
                self.op = Some(Live {
                    index: seq,
                    op,
                    then: Then::Flush {
                        seq,
                        rightmost: false,
                    },
                });
                self.drive_op()
            }
            Then::SealOrdinal => self.seal_ordinal(&descent),
            Then::SealObject => self.seal_object(&descent),
            Then::SealReferenced => self.seal_referenced(&descent),
            _ => Err(invalid()),
        }
    }

    fn after_done(
        &mut self,
        live: &Live,
        spine: Option<Box<Spine>>,
    ) -> Result<Step<'static>, Failure> {
        match live.then {
            Then::ObjectInserted => {
                let work = self.work.as_mut().ok_or_else(invalid)?;
                work.stage = Stage::Referenced;
                Ok(Step::Progress)
            }
            Then::ReferencedInserted => self.next_edge(),
            Then::Flush { seq, rightmost } => {
                if rightmost {
                    return Err(invalid());
                }
                let drained = self.sequence_mut(seq)?.drained();
                self.resources.release(drained)?;
                let retained = spine.as_ref().map_or(0, |spine| {
                    spine
                        .records
                        .iter()
                        .map(|(_, value)| u64::try_from(value.len()).unwrap_or(u64::MAX))
                        .fold(0, u64::saturating_add)
                });
                self.resources.reserve(retained)?;
                self.sequence_mut(seq)?.set_spine(spine);
                if self.phase == Phase::Seal {
                    self.advance_seal()
                } else {
                    self.advance_flush()
                }
            }
            Then::Audit { next } => self.resume_audit(next),
            _ => Err(invalid()),
        }
    }

    fn base_route(&mut self, descent: &Descent) -> Result<Step<'static>, Failure> {
        let base = self
            .work
            .as_ref()
            .and_then(|work| work.base)
            .ok_or_else(invalid)?;
        if descent.found {
            let value = descent.value().ok_or_else(invalid)?;
            let record = ObjectRecord::from_bytes(value)
                .map_err(|_| failure(FailureCode::InvalidEvidence))?;
            let work = self.work.as_mut().ok_or_else(invalid)?;
            work.base_depth = record.delta_depth;
            let request = self.request_id()?;
            return Ok(self.issue(Pending::Bytes {
                request,
                source: ByteSource::Canonical {
                    object: base,
                    len: record.canonical_len,
                    binding: self.source.binding,
                },
                range: ByteRange {
                    offset: 0,
                    len: record.canonical_len,
                },
                for_: For::Base,
            }));
        }
        let request = self.request_id()?;
        Ok(self.issue(Pending::Member {
            request,
            object: base,
        }))
    }

    fn edge_target(&self) -> Result<Hash, Failure> {
        let work = self.work.as_ref().ok_or_else(invalid)?;
        let object = work.object.as_ref().ok_or_else(invalid)?;
        Ok(edge_at(object, work.edge_next).ok_or_else(invalid)?.target)
    }

    fn next_edge(&mut self) -> Result<Step<'static>, Failure> {
        let work = self.work.as_mut().ok_or_else(invalid)?;
        work.edge_next += 1;
        Ok(Step::Progress)
    }

    fn seal_ordinal(&mut self, descent: &Descent) -> Result<Step<'static>, Failure> {
        let value = descent.value().ok_or_else(invalid)?;
        let record =
            OrdinalRecord::from_bytes(value).map_err(|_| failure(FailureCode::InvalidEvidence))?;
        let seal = self.seal.as_mut().ok_or_else(invalid)?;
        seal.candidate = record.object;
        seal.kind = record.kind;
        let id = record.object;
        self.op = Some(Live {
            index: Which::Objects,
            op: self.objects.descend(id),
            then: Then::SealObject,
        });
        self.drive_op()
    }

    fn seal_object(&mut self, descent: &Descent) -> Result<Step<'static>, Failure> {
        let value = descent.value().ok_or_else(invalid)?;
        let record =
            ObjectRecord::from_bytes(value).map_err(|_| failure(FailureCode::InvalidEvidence))?;
        let seal = self.seal.as_mut().ok_or_else(invalid)?;
        seal.first_ordinal = record.first_ordinal;
        seal.page = descent.leaf;
        seal.position = descent.position as u64;
        let id = seal.candidate;
        self.op = Some(Live {
            index: Which::Referenced,
            op: self.referenced.descend(id),
            then: Then::SealReferenced,
        });
        self.drive_op()
    }

    fn seal_referenced(&mut self, descent: &Descent) -> Result<Step<'static>, Failure> {
        let seal = self.seal.as_mut().ok_or_else(invalid)?;
        if !descent.found {
            let record = HeadRecord {
                object: seal.candidate,
                kind: seal.kind,
                occurrence_ordinal: seal.first_ordinal,
                page: seal.page,
                ordinal_in_page: seal.position,
            };
            let value = record.to_bytes();
            let len =
                u64::try_from(value.len()).map_err(|_| failure(FailureCode::ResourceLimit))?;
            self.resources.reserve(len)?;
            self.heads.append(value);
        }
        seal.next += 1;
        self.advance_seal()
    }

    fn advance_seal(&mut self) -> Result<Step<'static>, Failure> {
        let stage = self.seal.as_ref().ok_or_else(invalid)?.stage;
        match stage {
            SealStage::Flush => {
                for seq in SEQUENCES {
                    let sequence = self.sequence_mut(seq)?;
                    if sequence.pending() == 0 {
                        continue;
                    }
                    let op = sequence.flush()?;
                    let rightmost = matches!(
                        op,
                        Op::Descend {
                            rightmost: true,
                            ..
                        }
                    );
                    self.op = Some(Live {
                        index: seq,
                        op,
                        then: Then::Flush { seq, rightmost },
                    });
                    return self.drive_op();
                }
                let seal = self.seal.as_mut().ok_or_else(invalid)?;
                seal.stage = SealStage::Heads;
                Ok(Step::Progress)
            }
            SealStage::Heads => {
                // Heads flushes ride the same operation plumbing.
                let heads = self.sequence_mut(Which::Heads)?;
                if heads.needs_flush() {
                    let op = heads.flush()?;
                    let rightmost = matches!(
                        op,
                        Op::Descend {
                            rightmost: true,
                            ..
                        }
                    );
                    self.op = Some(Live {
                        index: Which::Heads,
                        op,
                        then: Then::Flush {
                            seq: Which::Heads,
                            rightmost,
                        },
                    });
                    return self.drive_op();
                }
                let seal = self.seal.as_ref().ok_or_else(invalid)?;
                if seal.next >= self.ordinals.committed() {
                    if self.heads.pending() != 0 {
                        let op = self.heads.flush()?;
                        let rightmost = matches!(
                            op,
                            Op::Descend {
                                rightmost: true,
                                ..
                            }
                        );
                        self.op = Some(Live {
                            index: Which::Heads,
                            op,
                            then: Then::Flush {
                                seq: Which::Heads,
                                rightmost,
                            },
                        });
                        return self.drive_op();
                    }
                    return self.finish_seal();
                }
                let next = seal.next;
                self.op = Some(Live {
                    index: Which::Ordinals,
                    op: self.ordinals.index().descend(ordinal_key(next)),
                    then: Then::SealOrdinal,
                });
                self.drive_op()
            }
        }
    }

    fn finish_seal(&mut self) -> Result<Step<'static>, Failure> {
        self.seal = None;
        self.resources.release(self.decoder_reservation)?;
        self.reclaim_compute_control()?;
        let counts = PackCounts {
            entries: self.ordinal,
            objects: self.ordinals.committed(),
            delta_entries: self.delta_entries,
            wire_payload_bytes: self.payload,
            decoded_bytes: self.decoded,
        };
        self.complete = Some(VerifiedPack::seal(
            self.source,
            counts,
            self.header.ok_or_else(invalid)?.0,
            self.trailer,
            self.ruleset,
            self.profile,
            self.limits,
            self.objects.commitment().digest,
            EvidenceSequence {
                root: self.occurrences.commitment().digest,
                count: self.occurrences.committed(),
            },
            EvidenceSequence {
                root: self.dependencies.commitment().digest,
                count: self.dependencies.committed(),
            },
            EvidenceSequence {
                root: self.ordinals.commitment().digest,
                count: self.ordinals.committed(),
            },
            EvidenceSequence {
                root: self.heads.commitment().digest,
                count: self.heads.committed(),
            },
        ));
        self.phase = Phase::Complete;
        Ok(Step::Progress)
    }
}

impl Resources {
    fn charge_external(&mut self) -> Result<(), Failure> {
        self.work(1)
    }
}
