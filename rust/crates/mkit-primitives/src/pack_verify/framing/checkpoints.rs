//! Checkpoint ownership and strict safe-boundary snapshots.
use super::super::integrity::RestoredIntegrity;
use super::{
    Failure, FailureCode, FramedPack, FramingDriver, INDEXED_RULESET, IndexedProfile,
    IntegrityPass, PackSource, Phase, ProfileId, RepositoryId, Resources, RulesetBinding,
    VerifyLimits, WindowReader, failure,
};
use crate::evidence::checkpoint::{
    self, Checkpoint, CheckpointMeta, CheckpointPhase, CheckpointView, IntegrityView,
};
use mkit_core::pack::window::WindowCursor;

impl FramingDriver {
    /// Restores a trusted-at-rest snapshot under the exact original bindings.
    ///
    /// Assign a fresh generation so delayed replies from the prior run cannot
    /// satisfy new acquisitions. Cumulative work, evidence, and peak accounting
    /// survive restart; restored allocations are charged again.
    ///
    /// # Errors
    /// Refuses changed sources, repositories, profiles or limits, reused run
    /// generations, invalid state, inconsistent cursor bindings, and exhaustion.
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
        {
            return Err(failure(FailureCode::InvalidCheckpoint));
        }
        let workspace = limits
            .checkpoint_bytes
            .checked_add(8192)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        let integrity_reservation = IntegrityPass::reservation(source.len)?;
        let mut resources = Resources::resume(limits, meta.usage)?;
        resources.reserve(std::mem::size_of::<Self>() as u64)?;
        resources.reserve(integrity_reservation)?;
        resources.reserve(workspace)?;
        resources.work(
            (checkpoint.bytes().len() as u64)
                .checked_mul(4)
                .and_then(|n| n.checked_add(8192))
                .ok_or_else(|| failure(FailureCode::ResourceLimit))?,
        )?;
        // The opaque envelope caches already validated fixed metadata. Admit
        // cumulative work and all transient allocations before re-decoding.
        let mut machine = Self::new(source, repository, profile, limits, generation)?;
        let state = checkpoint.decode(limits)?;
        match meta.phase {
            CheckpointPhase::Header => machine.phase = Phase::Header,
            CheckpointPhase::Drain => return Err(failure(FailureCode::InvalidCheckpoint)),
            CheckpointPhase::Integrity => {
                let frontier = state
                    .integrity
                    .ok_or_else(|| failure(FailureCode::InvalidCheckpoint))?;
                machine.integrity = None;
                machine.integrity = Some(IntegrityPass::resume(
                    source,
                    RestoredIntegrity {
                        offset: frontier.offset,
                        whole_cvs: frontier.whole_cvs,
                        trailer_cvs: frontier.trailer_cvs,
                        whole_root: frontier.whole_root,
                        trailer_root: frontier.trailer_root,
                        trailer: frontier.trailer,
                        trailer_used: frontier.trailer_used,
                    },
                )?);
                machine.phase = Phase::Integrity;
            }
            CheckpointPhase::Decode => {
                machine.resume_decode(&meta, &state.cursor, &mut resources)?;
            }
            CheckpointPhase::Complete => {
                machine.integrity = None;
                resources.release(machine.integrity_reservation)?;
                let (version, entries) = meta
                    .header
                    .ok_or_else(|| failure(FailureCode::InvalidCheckpoint))?;
                machine.complete = Some(FramedPack {
                    source,
                    version,
                    entries,
                    wire_payload: meta.payload,
                    trailer: meta.trailer,
                    frame_evidence: meta.last_retained,
                });
                machine.phase = Phase::Complete;
            }
        }
        drop(state.cursor);
        resources.release(workspace)?;
        machine.resources = resources;
        machine.header = meta.header;
        machine.sequence = meta.sequence;
        machine.ordinal = meta.ordinal;
        machine.payload = meta.payload;
        machine.trailer = meta.trailer;
        machine.retention_count = meta.retention_count;
        machine.last_retained = meta.last_retained;
        if let Some(page) = meta.last_retained {
            machine.recovery = Some(super::recovery::Recovery {
                page,
                remaining: meta.ordinal,
                end: 12 + meta.ordinal * 5 + meta.payload,
            });
        }
        Ok(machine)
    }

    fn resume_decode(
        &mut self,
        meta: &CheckpointMeta,
        cursor_bytes: &[u8],
        resources: &mut Resources,
    ) -> Result<(), Failure> {
        self.integrity = None;
        resources.release(self.integrity_reservation)?;
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
            || view.position() != position
            || view.payload_sum() != meta.payload
            || Some((view.pack_version(), view.entry_count())) != meta.header
            || u64::from(view.entry_index()) != meta.ordinal
            || view.expected_pack_id() != Some(self.source.id)
        {
            return Err(failure(FailureCode::InvalidCheckpoint));
        }
        self.reader = Some(
            WindowReader::resume(&cursor, Self::decode_limits())
                .map_err(|_| failure(FailureCode::InvalidCheckpoint))?,
        );
        self.phase = Phase::Decode;
        Ok(())
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

    /// Encodes a snapshot at a safe integrity, entry, or evidence boundary.
    ///
    /// The borrowed output remains charged until the next mutable call. Persist
    /// it in trusted storage together with every acknowledged evidence page.
    /// A checksum detects accidental corruption; it authenticates no host state.
    ///
    /// # Errors
    /// `CheckpointNotReady` preserves progress when an entry, hash subtree, or
    /// retention acknowledgment is unfinished. Exhaustion is `ResourceLimit`.
    pub fn checkpoint(&mut self) -> Result<&Checkpoint, Failure> {
        self.release_checkpoint()?;
        if self.active.is_some()
            || self.pending_frame.is_some()
            || self.retained.is_some()
            || self.recovery.is_some()
            || self.phase == Phase::Failed
        {
            return Err(failure(FailureCode::CheckpointNotReady));
        }
        let phase = match self.phase {
            Phase::Header => CheckpointPhase::Header,
            Phase::Integrity => CheckpointPhase::Integrity,
            Phase::Decode => CheckpointPhase::Decode,
            Phase::Complete => CheckpointPhase::Complete,
            Phase::Failed => return Err(failure(FailureCode::CheckpointNotReady)),
        };
        let frontier = if self.phase == Phase::Integrity {
            Some(
                self.integrity
                    .as_ref()
                    .and_then(IntegrityPass::frontier)
                    .ok_or_else(|| failure(FailureCode::CheckpointNotReady))?,
            )
        } else {
            None
        };
        let reservation = self.checkpoint_reservation()?;
        self.resources.reserve(reservation)?;
        // Reserve cursor copies, finalization and envelope encoding before
        // invoking core. Window acquisition already prepaid the incremental
        // prefix pass; repeated checkpoints do not hash that window again.
        // Frontier copying is bounded by 518 CVs per stream and a 4 KiB cursor.
        let work = 3 * (369 + 8 + 49 + 47 + 64 + 2 * 518 * 32 + 4096);
        let result = (|| {
            self.resources.work(work)?;
            let cursor = if self.phase == Phase::Decode {
                self.reader
                    .as_ref()
                    .and_then(WindowReader::checkpoint)
                    .ok_or_else(|| failure(FailureCode::CheckpointNotReady))?
                    .to_bytes()
            } else {
                Vec::new()
            };
            let mut usage = self.resources.usage();
            usage.resident_bytes = 0;
            checkpoint::encode(
                &CheckpointView {
                    meta: CheckpointMeta {
                        source: self.source,
                        repository: self.repository,
                        ruleset: RulesetBinding {
                            ruleset: INDEXED_RULESET,
                            profile: ProfileId::Indexed,
                        },
                        limits: self.limits,
                        profile: self.profile,
                        generation: self.generation,
                        sequence: self.sequence,
                        phase,
                        header: self.header,
                        ordinal: self.ordinal,
                        payload: self.payload,
                        trailer: self.trailer,
                        retention_count: self.retention_count,
                        last_retained: self.last_retained,
                        usage,
                    },
                    integrity: frontier.map(|f| IntegrityView {
                        offset: f.offset,
                        whole_cvs: f.whole_cvs,
                        trailer_cvs: f.trailer_cvs,
                        whole_root: f.whole_root,
                        trailer_root: f.trailer_root,
                        trailer: f.trailer,
                        trailer_used: f.trailer_used,
                    }),
                    cursor: &cursor,
                    verify: None,
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

#[cfg(test)]
mod tests {
    use super::super::MAX_PACK_BYTES;
    use super::*;
    use crate::evidence::{PageCommitment, SourceBinding};
    use crate::pack_verify::{Acquisition, Request, Response, framing::FramingStep};
    use mkit_core::hash;

    #[test]
    fn header_checkpoint_restarts_with_fresh_requests_and_preserves_work() {
        let mut bytes = b"MKIT\x01\0\0\0\0\0\0\0".to_vec();
        bytes.extend_from_slice(&hash::hash(&bytes));
        let source = PackSource {
            id: hash::hash(&bytes),
            len: 44,
            binding: SourceBinding([7; 32]),
        };
        let repository = RepositoryId([9; 32]);
        let profile = IndexedProfile {
            pack_bytes: MAX_PACK_BYTES,
            decoded_bytes: 4 << 30,
            delta_depth: 50,
        };
        let limits = VerifyLimits::indexed();
        let mut machine = FramingDriver::new(source, repository, profile, limits, 17).unwrap();
        let snapshot = machine.checkpoint().unwrap();
        let snapshot = Checkpoint::from_bytes(snapshot.bytes(), limits).unwrap();
        let before = machine.usage();
        assert!(before.resident_bytes >= limits.checkpoint_bytes);
        assert!(FramingDriver::resume(source, repository, profile, limits, 17, &snapshot).is_err());
        let mut changed = source;
        changed.binding = SourceBinding([8; 32]);
        assert_eq!(
            FramingDriver::resume(changed, repository, profile, limits, 18, &snapshot)
                .unwrap_err()
                .code,
            FailureCode::SourceChanged
        );
        let mut resumed =
            FramingDriver::resume(source, repository, profile, limits, 18, &snapshot).unwrap();
        assert!(resumed.usage().work > before.work);
        let FramingStep::Request(Request::Bytes { request, .. }) = resumed.step().unwrap() else {
            panic!()
        };
        assert_eq!(request.generation, 18);
        let _ = machine.step().unwrap();
        assert!(machine.usage().resident_bytes < before.resident_bytes);
    }

    #[test]
    fn integrity_checkpoints_restore_both_initial_and_completed_frontiers() {
        let mut bytes = b"MKIT\x01\0\0\0\0\0\0\0".to_vec();
        bytes.extend_from_slice(&hash::hash(&bytes));
        let source = PackSource {
            id: hash::hash(&bytes),
            len: 44,
            binding: SourceBinding([7; 32]),
        };
        let repository = RepositoryId([9; 32]);
        let profile = IndexedProfile {
            pack_bytes: MAX_PACK_BYTES,
            decoded_bytes: 4 << 30,
            delta_depth: 50,
        };
        let limits = VerifyLimits::indexed();
        let mut machine = FramingDriver::new(source, repository, profile, limits, 17).unwrap();
        // Header acceptance exposes the initial integrity frontier.
        for completed in [false, true] {
            let FramingStep::Request(Request::Bytes {
                request,
                source,
                range,
            }) = machine.step().unwrap()
            else {
                panic!()
            };
            let begin = usize::try_from(range.offset).unwrap();
            let end = begin + usize::try_from(range.len).unwrap();
            machine
                .supply(Response::Bytes {
                    request,
                    source,
                    range,
                    value: Acquisition::Present(&bytes[begin..end]),
                })
                .unwrap();
            let snapshot =
                Checkpoint::from_bytes(machine.checkpoint().unwrap().bytes(), limits).unwrap();
            let mut resumed = FramingDriver::resume(
                source_pack(source),
                repository,
                profile,
                limits,
                18,
                &snapshot,
            )
            .unwrap();
            if completed {
                assert!(matches!(resumed.step().unwrap(), FramingStep::Progress));
            } else {
                assert!(matches!(
                    resumed.step().unwrap(),
                    FramingStep::Request(Request::Bytes {
                        range: super::super::ByteRange { offset: 0, len: 44 },
                        ..
                    })
                ));
            }
        }
    }

    fn source_pack(source: super::super::ByteSource) -> PackSource {
        let super::super::ByteSource::Pack(source) = source else {
            panic!()
        };
        source
    }

    #[test]
    fn complete_resume_authenticates_every_page_and_loss_never_completes() {
        let bytes = include_bytes!("../../../fixtures/framing/earlier-delta-base.bin");
        let source = PackSource {
            id: hash::hash(bytes),
            len: bytes.len() as u64,
            binding: SourceBinding([7; 32]),
        };
        let repository = RepositoryId([9; 32]);
        let profile = IndexedProfile {
            pack_bytes: MAX_PACK_BYTES,
            decoded_bytes: 4 << 30,
            delta_depth: 50,
        };
        let limits = VerifyLimits::indexed();
        let mut machine = FramingDriver::new(source, repository, profile, limits, 17).unwrap();
        let (pages, original) = complete_with_pages(&mut machine, bytes);
        let snapshot =
            Checkpoint::from_bytes(machine.checkpoint().unwrap().bytes(), limits).unwrap();
        check_lost_pages(
            source, repository, profile, limits, &snapshot, &pages, original,
        );
    }

    fn complete_with_pages(
        machine: &mut FramingDriver,
        bytes: &[u8],
    ) -> (Vec<(PageCommitment, Vec<u8>)>, FramedPack) {
        let mut pages = Vec::new();
        let original = loop {
            match machine.step().unwrap() {
                FramingStep::Request(Request::Bytes {
                    request,
                    source,
                    range,
                }) => {
                    let begin = usize::try_from(range.offset).unwrap();
                    machine
                        .supply(Response::Bytes {
                            request,
                            source,
                            range,
                            value: Acquisition::Present(
                                &bytes[begin..begin + usize::try_from(range.len).unwrap()],
                            ),
                        })
                        .unwrap();
                }
                FramingStep::RetainEvidence(page) => {
                    let commitment = page.commitment;
                    pages.push((commitment, page.bytes.to_vec()));
                    assert_eq!(
                        machine.checkpoint().unwrap_err().code,
                        FailureCode::CheckpointNotReady
                    );
                    machine.acknowledge_retention(commitment).unwrap();
                }
                FramingStep::Frame(_) => assert_eq!(
                    machine.checkpoint().unwrap_err().code,
                    FailureCode::CheckpointNotReady
                ),
                FramingStep::Progress => (),
                FramingStep::Complete(pack) => break pack,
                FramingStep::Request(_) => panic!(),
            }
        };
        (pages, original)
    }

    fn check_lost_pages(
        source: PackSource,
        repository: RepositoryId,
        profile: IndexedProfile,
        limits: VerifyLimits,
        snapshot: &Checkpoint,
        pages: &[(PageCommitment, Vec<u8>)],
        original: FramedPack,
    ) {
        // The root page alone is insufficient: any predecessor loss blocks.
        for lost in 0..=pages.len() {
            let mut restored =
                FramingDriver::resume(source, repository, profile, limits, 18, snapshot).unwrap();
            let mut count = 0;
            loop {
                match restored.step().unwrap() {
                    FramingStep::Request(Request::EvidencePage { request, page }) => {
                        let index = pages.iter().position(|(key, _)| *key == page).unwrap();
                        let value = if index == lost {
                            Acquisition::Unavailable
                        } else {
                            Acquisition::Present(pages[index].1.as_slice())
                        };
                        let result = restored.supply(Response::EvidencePage {
                            request,
                            page,
                            value,
                        });
                        if index == lost {
                            assert_eq!(result.unwrap_err().code, FailureCode::UnavailableInput);
                            assert!(matches!(
                                restored.step().unwrap(),
                                FramingStep::Request(Request::EvidencePage { .. })
                            ));
                            break;
                        }
                        result.unwrap();
                        count += 1;
                    }
                    FramingStep::Complete(pack) => {
                        assert_eq!(lost, pages.len());
                        assert_eq!(pack, original);
                        assert_eq!(count, 3);
                        break;
                    }
                    _ => panic!("resume advanced without recovering its pages"),
                }
            }
        }
        let mut restored =
            FramingDriver::resume(source, repository, profile, limits, 18, snapshot).unwrap();
        let FramingStep::Request(Request::EvidencePage { request, page }) =
            restored.step().unwrap()
        else {
            panic!()
        };
        let mut corrupted = pages.last().unwrap().1.clone();
        *corrupted.last_mut().unwrap() ^= 1;
        assert!(
            restored
                .supply(Response::EvidencePage {
                    request,
                    page,
                    value: Acquisition::Present(&corrupted)
                })
                .is_err()
        );
        assert_eq!(
            restored.step().unwrap_err().code,
            FailureCode::InvalidResponse
        );
    }
}

#[cfg(test)]
#[path = "resume_tests.rs"]
mod resume_tests;
