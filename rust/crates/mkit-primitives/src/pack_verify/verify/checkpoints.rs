//! Checkpoint ownership and strict drained-boundary snapshots for verify runs.
//!
//! A normal verify checkpoint exists at a fully committed entry boundary.
//! Its exact cursor preserves acquired hash frontiers without rereading a
//! consumed prefix. Resume authenticates every committed evidence index before
//! decoding continues; lost pages fail as `UnavailableInput`, never as absence.
//! Integrity-only drains retain the first refusal and acquired hash frontiers;
//! their evidence indices are inert and cannot produce verified artifacts.
use super::{
    Failure, FailureCode, Live, PackSource, Phase, RepositoryId, Resources, Step, Then,
    VerifyDriver, Which, WindowReader, failure,
    index::{Index, Sequence},
    kind_of,
};
use crate::evidence::checkpoint::{
    self, Checkpoint, CheckpointMeta, CheckpointPhase, CheckpointView, DeferredFailure,
    IndexCheckpoint, VerifyCheckpoint,
};
use crate::limits::{EvidenceLimits, IndexedProfile, VerifyLimits};
use mkit_core::pack::window::WindowCursor;

const AUDIT_ORDER: [Which; 6] = [
    Which::Objects,
    Which::Ordinals,
    Which::Occurrences,
    Which::Dependencies,
    Which::Referenced,
    Which::Heads,
];

impl VerifyDriver {
    /// Restores a trusted-at-rest snapshot under the exact original bindings.
    ///
    /// Assign a fresh generation so delayed replies from the prior run cannot
    /// satisfy new acquisitions. Cumulative work, evidence, and peak accounting
    /// survive restart; restored allocations are charged again. Before entry
    /// decoding continues, every committed evidence index is authenticated
    /// page by page against the caller's retained-page store. Integrity-only
    /// snapshots resume only hashing and their deferred terminal refusal;
    /// partial evidence records are discarded and never audited or sealed.
    ///
    /// # Errors
    /// Refuses changed sources, repositories, profiles or limits, reused run
    /// generations, invalid state, inconsistent cursor bindings, framing
    /// (version-1) checkpoints, and exhaustion.
    pub fn resume(
        source: PackSource,
        repository: RepositoryId,
        profile: IndexedProfile,
        limits: VerifyLimits,
        generation: u64,
        checkpoint: &Checkpoint,
    ) -> Result<Self, Failure> {
        let meta = checkpoint.meta();
        if meta.source != source {
            return Err(failure(FailureCode::SourceChanged));
        }
        if meta.repository != repository
            || meta.profile != profile
            || meta.limits != limits
            || meta.generation == generation
            || !matches!(meta.phase, CheckpointPhase::Decode | CheckpointPhase::Drain)
        {
            return Err(failure(FailureCode::InvalidCheckpoint));
        }
        let workspace = limits
            .checkpoint_bytes
            .checked_add(8192)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        let mut resources = Resources::resume(limits, meta.usage)?;
        resources.reserve(std::mem::size_of::<Self>() as u64)?;
        resources.reserve(workspace)?;
        let state = checkpoint.decode(limits)?;
        let acquired_hash_end = WindowCursor::from_bytes(&state.cursor)
            .map_err(|_| failure(FailureCode::InvalidCheckpoint))?
            .metadata()
            .map_err(|_| failure(FailureCode::InvalidCheckpoint))?
            .acquired_end()
            .ok_or_else(|| failure(FailureCode::InvalidCheckpoint))?;
        let integrity_work = source
            .len
            .checked_sub(acquired_hash_end)
            .and_then(|remaining| remaining.checked_mul(3))
            .ok_or_else(|| failure(FailureCode::InvalidCheckpoint))?;
        resources.protect_work(integrity_work)?;
        resources.work(
            (checkpoint.bytes().len() as u64)
                .checked_mul(4)
                .and_then(|n| n.checked_add(8192))
                .ok_or_else(|| failure(FailureCode::ResourceLimit))?,
        )?;
        let mut machine = Self::new(source, repository, profile, limits, generation)?;
        let verify = state
            .verify
            .ok_or_else(|| failure(FailureCode::InvalidCheckpoint))?;
        machine.restore_decode(&meta, &state.cursor, &verify, &mut resources)?;
        resources.release(workspace)?;
        machine.resources = resources;
        machine.acquired_hash_end = acquired_hash_end;
        machine.header = meta.header;
        machine.sequence = meta.sequence;
        machine.ordinal = meta.ordinal;
        machine.payload = meta.payload;
        machine.trailer = meta.trailer;
        machine.retention_count = meta.retention_count;
        machine.last_retained = meta.last_retained;
        machine.decoded = verify.decoded;
        machine.delta_entries = verify.delta_entries;
        machine.edges = verify.edges;
        machine.external_lookups = verify.external_lookups;
        machine.signature_failure = verify.signature_failure;
        machine.deferred_failure = verify.deferred_failure.map(DeferredFailure::failure);
        machine.roots.clear();
        if machine.phase == Phase::Entries {
            machine.op = Some(Live {
                index: AUDIT_ORDER[0],
                op: machine.index_mut(AUDIT_ORDER[0]).audit(),
                then: Then::Audit { next: 1 },
            });
        }
        Ok(machine)
    }

    fn restore_decode(
        &mut self,
        meta: &CheckpointMeta,
        cursor_bytes: &[u8],
        verify: &VerifyCheckpoint,
        resources: &mut Resources,
    ) -> Result<(), Failure> {
        resources.reserve(self.decoder_reservation)?;
        let cursor = WindowCursor::from_bytes(cursor_bytes)
            .map_err(|_| failure(FailureCode::InvalidCheckpoint))?;
        let view = cursor
            .metadata()
            .map_err(|_| failure(FailureCode::InvalidCheckpoint))?;
        let position = meta
            .ordinal
            .checked_mul(5)
            .and_then(|n| n.checked_add(12))
            .and_then(|n| n.checked_add(meta.payload))
            .ok_or_else(|| failure(FailureCode::InvalidCheckpoint))?;
        if view.pack_len() != self.source.len
            || view.window_size() != self.limits.acquisition_bytes
            || !view.exact()
            || view.integrity_only() != (meta.phase == CheckpointPhase::Drain)
            || (meta.phase == CheckpointPhase::Decode
                && (view.position() != position
                    || view.payload_sum() != meta.payload
                    || u64::from(view.entry_index()) != meta.ordinal))
            || Some((view.pack_version(), view.entry_count())) != meta.header
            || view.expected_pack_id() != Some(self.source.id)
        {
            return Err(failure(FailureCode::InvalidCheckpoint));
        }
        self.reader = Some(
            WindowReader::resume(&cursor, Self::decode_limits())
                .map_err(|_| failure(FailureCode::InvalidCheckpoint))?,
        );
        let binding = Self::binding(self.source, self.repository);
        let evidence = EvidenceLimits {
            page_bytes: self.limits.page_bytes,
            allocated_bytes: self.limits.page_bytes,
            ..EvidenceLimits::indexed()
        };
        self.objects = Index::resume(
            kind_of(Which::Objects),
            binding,
            evidence,
            verify.objects.commitment,
            verify.objects.count,
        )?;
        self.ordinals = Sequence::resume(
            kind_of(Which::Ordinals),
            binding,
            evidence,
            verify.ordinals.commitment,
            verify.ordinals.count,
        )?;
        self.occurrences = Sequence::resume(
            kind_of(Which::Occurrences),
            binding,
            evidence,
            verify.occurrences.commitment,
            verify.occurrences.count,
        )?;
        self.dependencies = Sequence::resume(
            kind_of(Which::Dependencies),
            binding,
            evidence,
            verify.dependencies.commitment,
            verify.dependencies.count,
        )?;
        self.referenced = Index::resume(
            kind_of(Which::Referenced),
            binding,
            evidence,
            verify.referenced.commitment,
            verify.referenced.count,
        )?;
        self.heads = Sequence::resume(
            kind_of(Which::Heads),
            binding,
            evidence,
            verify.heads.commitment,
            verify.heads.count,
        )?;
        self.phase = if meta.phase == CheckpointPhase::Drain {
            Phase::Drain
        } else {
            Phase::Entries
        };
        Ok(())
    }

    pub(super) fn resume_audit(&mut self, next: usize) -> Result<Step<'static>, Failure> {
        if next >= AUDIT_ORDER.len() {
            return Ok(Step::Progress);
        }
        let which = AUDIT_ORDER[next];
        self.op = Some(Live {
            index: which,
            op: self.index_mut(which).audit(),
            then: Then::Audit { next: next + 1 },
        });
        self.drive_op()
    }

    fn checkpoint_reservation(&self) -> Result<u64, Failure> {
        self.limits
            .checkpoint_bytes
            .checked_add(8192)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))
    }

    pub(super) fn release_checkpoint(&mut self) -> Result<(), Failure> {
        if self.checkpoint.take().is_some() {
            self.resources.release(self.checkpoint_reservation()?)?;
        }
        Ok(())
    }

    /// Encodes a snapshot at an entry boundary or during integrity-only draining.
    ///
    /// Every buffered record must be under its sequence root: the boundary is
    /// reached only right after a flush finished at an entry end. The borrowed
    /// output remains charged until the next mutable call. Persist it in
    /// trusted storage together with every acknowledged evidence page. A drain
    /// carries only committed index roots: discarded partial records cannot
    /// affect its terminal refusal and never establish verified status.
    ///
    /// # Errors
    /// `CheckpointNotReady` preserves progress outside the drained boundary:
    /// an entry, operation, request, or retention acknowledgement is
    /// unfinished, buffered records are uncommitted, or the run already ended.
    /// Exhaustion is `ResourceLimit`.
    pub fn checkpoint(&mut self) -> Result<&Checkpoint, Failure> {
        self.release_checkpoint()?;
        let draining = self.phase == Phase::Drain;
        if !matches!(self.phase, Phase::Entries | Phase::Drain)
            || !self.compute_checkpointable()
            || self.work.is_some()
            || self.op.is_some()
            || self.pending.is_some()
            || self.retained.is_some()
            || (!draining && !self.roots.is_empty())
            || self.reader.is_none()
            || (!draining
                && [
                    &self.ordinals,
                    &self.occurrences,
                    &self.dependencies,
                    &self.heads,
                ]
                .iter()
                .any(|sequence| sequence.pending() != 0))
        {
            return Err(failure(FailureCode::CheckpointNotReady));
        }
        let reservation = self.checkpoint_reservation()?;
        self.resources.reserve(reservation)?;
        let result = (|| {
            let suffix_work = self.checkpoint_cursor_work();
            self.resources.work(
                suffix_work
                    .checked_add(3 * 8192)
                    .ok_or_else(|| failure(FailureCode::ResourceLimit))?,
            )?;
            let cursor = self
                .checkpoint_cursor()
                .ok_or_else(|| failure(FailureCode::CheckpointNotReady))?
                .to_bytes();
            let mut usage = self.resources.usage();
            usage.resident_bytes = 0;
            let checkpoint_of = |index: &Index| IndexCheckpoint {
                commitment: index.commitment(),
                count: index.count(),
            };
            let sequence_of = |sequence: &Sequence| IndexCheckpoint {
                commitment: sequence.commitment(),
                count: sequence.committed(),
            };
            checkpoint::encode(
                &CheckpointView {
                    meta: CheckpointMeta {
                        source: self.source,
                        repository: self.repository,
                        ruleset: self.ruleset,
                        limits: self.limits,
                        profile: self.profile,
                        generation: self.generation,
                        sequence: self.sequence,
                        phase: if draining {
                            CheckpointPhase::Drain
                        } else {
                            CheckpointPhase::Decode
                        },
                        header: self.header,
                        ordinal: self.ordinal,
                        payload: self.payload,
                        trailer: self.trailer,
                        retention_count: self.retention_count,
                        last_retained: self.last_retained,
                        usage,
                    },
                    integrity: None,
                    cursor: &cursor,
                    verify: Some(VerifyCheckpoint {
                        objects: checkpoint_of(&self.objects),
                        ordinals: sequence_of(&self.ordinals),
                        occurrences: sequence_of(&self.occurrences),
                        dependencies: sequence_of(&self.dependencies),
                        referenced: checkpoint_of(&self.referenced),
                        heads: sequence_of(&self.heads),
                        delta_entries: self.delta_entries,
                        decoded: self.decoded,
                        edges: self.edges,
                        external_lookups: self.external_lookups,
                        signature_failure: self.signature_failure,
                        deferred_failure: self.deferred_failure.as_ref().map(DeferredFailure::from),
                    }),
                },
                self.limits,
            )
        })();
        match result {
            Ok(checkpoint) => {
                self.checkpoint = Some(checkpoint);
                self.checkpoint
                    .as_ref()
                    .ok_or_else(|| failure(FailureCode::InvalidCheckpoint))
            }
            Err(error) => {
                self.resources.release(reservation)?;
                Err(error)
            }
        }
    }
}
