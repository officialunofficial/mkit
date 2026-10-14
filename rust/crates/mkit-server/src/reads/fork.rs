//! Typed destination fork evidence, independent of durable row encodings.

use std::collections::BTreeSet;

use mkit_core::hash::{Hash, hash};

use super::{ReadAccess, failure};
use crate::ServerError;
use crate::fork::{self, Failure, ForkJobV1, ForkResult, ForkSpec, Phase};
use crate::replay::{ReplayState, StoredResult};
use crate::store::{NamespaceStore, Value, codec, keys};

/// The original request identity retained after trusted signature verification.
/// This is evidence for a completed operation, not authority to execute one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkReplayIdentity {
    /// Original authenticated replay scope.
    pub scope: Hash,
    /// Original authenticated request fingerprint.
    pub fingerprint: Hash,
    /// Original signed envelope expiry, in Unix milliseconds.
    pub expires_at_ms: i64,
}

/// One member pack in the retained fork inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ForkPack {
    /// Pack identifier.
    pub id: Hash,
    /// Stored pack bytes.
    pub bytes: u64,
    /// Indexed objects in the pack.
    pub objects: u64,
    /// Whether this pack is a packmap node.
    pub is_packmap: bool,
    /// Whether this pack was inherited as an external delta base.
    pub is_delta_base: bool,
}

/// Authority facts retained when the original operation was accepted.
/// These facts do not replace current destination authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ForkAuthority {
    /// Original namespace authority generation, if applicable.
    pub generation: Option<u64>,
    /// Original grant epoch, if applicable.
    pub grant_epoch: Option<u64>,
    /// Whether the original operation could create the namespace.
    pub creates_namespace: bool,
}

/// Admission identity an embedder can compare with its own retained landing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ForkReservation {
    /// Reservation identifier accepted by the original admission hook.
    pub id: String,
    /// Upper bound of inherited bytes admitted for that operation.
    pub declared_bytes: u64,
}

/// A destination job's current lifecycle and retained completion evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ForkJobStatus {
    /// Current phase.
    pub phase: Phase,
    /// Terminal refusal, when present.
    pub failure: Option<Failure>,
    /// Consistent completed result; absent before completion.
    pub result: Option<ForkResult>,
    /// The inherited inventory, complete when the job is done.
    pub packs: Vec<ForkPack>,
    /// Authority facts retained by the job.
    pub authority: Option<ForkAuthority>,
    /// Original signed replay identity, when supplied.
    pub replay: Option<ForkReplayIdentity>,
    /// Original admission reservation, when supplied.
    pub reservation: Option<ForkReservation>,
}

/// A completed fork with its original replay and reservation checked live.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecoveredFork {
    /// Completed lineage result.
    pub result: ForkResult,
    /// Exact inherited pack inventory.
    pub packs: Vec<ForkPack>,
    /// Original admission reservation, for retained landing verification.
    pub reservation: ForkReservation,
    /// Original authority facts, for retained landing verification.
    pub authority: ForkAuthority,
}

impl<N: NamespaceStore> ReadAccess<'_, N> {
    /// Read a destination job matching the exact original fork specification.
    ///
    /// The caller must authorize the destination before calling this method.
    /// It applies no source visibility or destination authorization policy.
    /// No rows are cached, and no raw keys or encoded values are returned.
    ///
    /// # Errors
    /// Invalid fork specifications, storage failure, corrupt rows, or conflicting
    /// retained bindings fail closed.
    pub async fn fork_job_status(
        &self,
        spec: &ForkSpec,
    ) -> Result<Option<ForkJobStatus>, ServerError> {
        let Some(job) = self.bound_fork(spec).await? else {
            return Ok(None);
        };
        if job.phase == Phase::Done {
            validate_done(&job, spec)?;
        }
        Ok(Some(status(&job)))
    }

    /// Recover completed membership using the original authenticated replay identity.
    ///
    /// The caller must authorize the current destination and compare the returned
    /// reservation and authority facts with its trusted retained landing evidence.
    /// Supplied replay values must come from that evidence, not an untrusted request.
    /// This does not authenticate an expired envelope, admit work, read the source,
    /// publish refs, or run effects. Missing, pending, and failed jobs return `None`.
    /// All evidence is read afresh, with replay and reservation in one batch.
    /// This query accepts authority-fenced owner admissions with no quota charges,
    /// grant, or namespace cap. A fork that created its destination namespace is
    /// accepted too: namespace creation changes neither the reservation nor the
    /// replay record, so the same settlement proves it, and the namespace record
    /// must still be present and well formed (read in the same batch), so a later
    /// removal of that record, for example by a takedown, makes it fail closed. A grant
    /// epoch is never accepted: the pipeline records none, and the grant a
    /// later epoch may have revoked cannot be proven from retained evidence.
    /// Other jobs remain readable through `fork_job_status`; authenticated
    /// retries use `Pipeline::fork_repo`.
    ///
    /// # Errors
    /// Conflicting, corrupt, incomplete, or pruned completion evidence fails closed.
    pub async fn recover_completed_fork(
        &self,
        spec: &ForkSpec,
        original: &ForkReplayIdentity,
    ) -> Result<Option<RecoveredFork>, ServerError> {
        let Some(job) = self.bound_fork(spec).await? else {
            return Ok(None);
        };
        if job.phase != Phase::Done {
            return Ok(None);
        }
        let result = validate_done(&job, spec)?;
        let fence = job.fence.as_ref().ok_or_else(failure)?;
        if fence.authority_generation.is_none() || fence.grant_epoch.is_some() {
            return Err(failure());
        }
        let creates_namespace = fence.create_namespace;
        let repository = identity(&spec.dest);
        let settle = validate_settlement(&job, original, &repository, result)?;
        let mut wanted = vec![
            keys::replay(&original.scope),
            keys::reservation(&settle.rid).map_err(|_| failure())?,
        ];
        if creates_namespace {
            wanted.push(keys::namespace_record());
        }
        let rows = self
            .store
            .get_many(&self.shards.coordinator(&spec.dest.namespace), &wanted)
            .await
            .map_err(|_| failure())?;
        let (replay_row, reservation_row) = match rows.as_slice() {
            [Some(replay), Some(reservation)] if !creates_namespace => (replay, reservation),
            [Some(replay), Some(reservation), Some(namespace)] if creates_namespace => {
                codec::decode_namespace_record(namespace).map_err(|_| failure())?;
                (replay, reservation)
            }
            _ => return Err(failure()),
        };
        let replay = codec::decode_replay_record(replay_row).map_err(|_| failure())?;
        if replay.fingerprint != original.fingerprint
            || replay.expires_at_ms != original.expires_at_ms
            || replay.state != ReplayState::Committed(StoredResult::Fork)
        {
            return Err(failure());
        }
        match codec::decode_reservation(reservation_row).map_err(|_| failure())? {
            codec::ReservationV1::Committed {
                repository: committed_repo,
                bytes_stored,
                new_to_repo,
                new_to_store: 0,
                refs,
                procedure: codec::StoredProcedure::Fork,
                ..
            } if committed_repo == repository
                && bytes_stored == result.pack_bytes
                && new_to_repo == result.pack_bytes
                && refs.is_empty() => {}
            _ => return Err(failure()),
        }
        let status = status(&job);
        Ok(Some(RecoveredFork {
            result: result.clone(),
            packs: status.packs,
            reservation: status.reservation.ok_or_else(failure)?,
            authority: status.authority.ok_or_else(failure)?,
        }))
    }

    async fn bound_fork(&self, spec: &ForkSpec) -> Result<Option<ForkJobV1>, ServerError> {
        if spec.source == spec.dest
            || !crate::refs::is_served_ref_name(&spec.source_ref)
            || !spec.source_ref.starts_with("refs/heads/")
        {
            return Err(ServerError::invalid_argument("invalid fork specification"));
        }
        let Some((job, _)) = fork::read_job(&self.store, self.shards, &spec.dest)
            .await
            .map_err(|_| failure())?
        else {
            return Ok(None);
        };
        if job.binding != fork::binding(spec)
            || job.dest_ns != spec.dest.namespace.as_str()
            || job.dest_repo != spec.dest.name.as_str()
            || job.source_ns != spec.source.namespace.as_str()
            || job.source_repo != spec.source.name.as_str()
            || job.source_ref != spec.source_ref
            || job.tip != spec.expected_tip
            || job.visibility != spec.visibility_name()
            || (job.phase != Phase::Done && job.result.is_some())
            || (job.phase != Phase::Failed && job.failure.is_some())
            || (job.phase == Phase::Failed && job.failure.is_none())
        {
            return Err(failure());
        }
        Ok(Some(job))
    }
}

fn validate_settlement<'a>(
    job: &'a ForkJobV1,
    original: &ForkReplayIdentity,
    repository: &str,
    result: &ForkResult,
) -> Result<&'a fork::SettleV1, ServerError> {
    let settle = job.settle.as_ref().ok_or_else(failure)?;
    let replay = settle.replay.as_ref().ok_or_else(failure)?;
    if settle.rid.is_empty()
        || settle.rid.len() > 256
        || settle.pending.len() > 4096
        || settle.repository != repository
        || replay.scope != original.scope
        || replay.fingerprint != original.fingerprint
        || replay.expires_at_ms != original.expires_at_ms
        || settle.declared_bytes < result.pack_bytes
        || !settle.charges.is_empty()
        || settle.namespace_cap.is_some()
    {
        return Err(failure());
    }
    match codec::decode_reservation(&Value::new(settle.pending.clone())).map_err(|_| failure())? {
        codec::ReservationV1::Pending {
            repository: pending_repo,
            procedure: codec::StoredProcedure::Fork,
            op: codec::PendingOp::Write,
            ..
        } if pending_repo == repository => {}
        _ => return Err(failure()),
    }
    Ok(settle)
}

fn identity(repo: &crate::RepoId) -> String {
    crate::store::repo_storage::identity(&repo.namespace, &repo.name)
}

fn status(job: &ForkJobV1) -> ForkJobStatus {
    ForkJobStatus {
        phase: job.phase,
        failure: job.failure,
        result: job.result.clone(),
        packs: job
            .packs
            .iter()
            .map(|pack| ForkPack {
                id: pack.id,
                bytes: pack.len,
                objects: pack.objects,
                is_packmap: pack.node,
                is_delta_base: pack.base,
            })
            .collect(),
        authority: job.fence.as_ref().map(|fence| ForkAuthority {
            generation: fence.authority_generation,
            grant_epoch: fence.grant_epoch,
            creates_namespace: fence.create_namespace,
        }),
        replay: job
            .settle
            .as_ref()
            .and_then(|settle| settle.replay.as_ref())
            .map(|replay| ForkReplayIdentity {
                scope: replay.scope,
                fingerprint: replay.fingerprint,
                expires_at_ms: replay.expires_at_ms,
            }),
        reservation: job
            .settle
            .as_ref()
            .filter(|settle| !settle.rid.is_empty())
            .map(|settle| ForkReservation {
                id: settle.rid.clone(),
                declared_bytes: settle.declared_bytes,
            }),
    }
}

fn validate_done<'a>(job: &'a ForkJobV1, spec: &ForkSpec) -> Result<&'a ForkResult, ServerError> {
    let result = job.result.as_ref().ok_or_else(failure)?;
    if job.failure.is_some()
        || result.source != identity(&spec.source)
        || result.source_ref != job.source_ref
        || result.tip != job.tip
        || result.packmap != job.packmap
        || result.source_sequence != job.source_sequence
        || result.pack_count == 0
        || job.packs.len() > fork::MAX_FORK_PACKS
        || result.pack_count != job.packs.len() as u64
        || result.object_count > fork::MAX_FORK_OBJECTS
        || result.pack_bytes > 1 << 30
        || result.membership_generation != fork::MEMBERSHIP_GENERATION
        || job
            .packs
            .first()
            .is_none_or(|pack| pack.id != job.packmap || !pack.node)
        || result.object_count != job.copied
    {
        return Err(failure());
    }
    let mut ids = BTreeSet::new();
    let mut bytes = 0u64;
    let mut objects = 0u64;
    for pack in &job.packs {
        if !ids.insert(pack.id) {
            return Err(failure());
        }
        bytes = bytes.checked_add(pack.len).ok_or_else(failure)?;
        objects = objects.checked_add(pack.objects).ok_or_else(failure)?;
    }
    let packed = ids
        .iter()
        .flat_map(|id| id.iter().copied())
        .collect::<Vec<_>>();
    if result.pack_bytes != bytes
        || result.object_count != objects
        || result.pack_set != hash(&packed)
    {
        return Err(failure());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fork::{FenceV1, PackRow, ReplayV1, SettleV1};
    use crate::pipeline::{D34Shards, RepoVisibility, ShardMap, SinglePartition};
    use crate::replay::ReplayRecord;
    use crate::store::Batch;
    use crate::{Clock as _, ManualClock, MemoryKv, NamespaceKey, RepoId, RepoName};
    use std::sync::Arc;

    fn spec() -> ForkSpec {
        let repo = |name| RepoId {
            namespace: NamespaceKey::from_namespace(&mkit_core::repo_identity::Namespace::Ed25519(
                [1; 32],
            )),
            name: RepoName::new(name).unwrap(),
        };
        ForkSpec {
            source: repo("source"),
            source_ref: "refs/heads/main".into(),
            expected_tip: [2; 32],
            dest: repo("destination"),
            dest_visibility: RepoVisibility::Private,
        }
    }

    fn original() -> ForkReplayIdentity {
        ForkReplayIdentity {
            scope: [4; 32],
            fingerprint: [5; 32],
            expires_at_ms: 1,
        }
    }

    fn job(spec: &ForkSpec) -> ForkJobV1 {
        let original = original();
        let result = ForkResult {
            source: identity(&spec.source),
            source_ref: spec.source_ref.clone(),
            tip: spec.expected_tip,
            source_sequence: 1,
            packmap: [3; 32],
            pack_count: 1,
            pack_bytes: 10,
            object_count: 1,
            pack_set: hash(&[3; 32]),
            membership_generation: fork::MEMBERSHIP_GENERATION,
        };
        ForkJobV1 {
            binding: fork::binding(spec),
            dest_ns: spec.dest.namespace.as_str().into(),
            dest_repo: spec.dest.name.as_str().into(),
            source_ns: spec.source.namespace.as_str().into(),
            source_repo: spec.source.name.as_str().into(),
            source_ref: spec.source_ref.clone(),
            tip: spec.expected_tip,
            packmap: result.packmap,
            source_sequence: result.source_sequence,
            source_generation: 0,
            visibility: "private".into(),
            created_ms: 0,
            expires_ms: 1,
            phase: Phase::Done,
            packs: vec![PackRow {
                id: [3; 32],
                len: 10,
                objects: 1,
                node: true,
                base: false,
            }],
            cursor: 0,
            deps: Vec::new(),
            part: 0,
            lanes: Vec::new(),
            after: None,
            scanned: 1,
            copied: 1,
            failure: None,
            settle: Some(SettleV1 {
                rid: "reservation".into(),
                pending: codec::encode_reservation(&codec::ReservationV1::pending(
                    identity(&spec.dest),
                    0,
                    1,
                    codec::PendingOp::Write,
                    codec::StoredProcedure::Fork,
                ))
                .as_bytes()
                .to_vec(),
                repository: identity(&spec.dest),
                replay: Some(ReplayV1 {
                    scope: original.scope,
                    fingerprint: original.fingerprint,
                    expires_at_ms: original.expires_at_ms,
                }),
                charges: Vec::new(),
                namespace_cap: None,
                declared_bytes: 10,
            }),
            fence: Some(FenceV1 {
                authority_generation: Some(1),
                grant_epoch: None,
                create_namespace: false,
            }),
            result: Some(result),
        }
    }

    async fn write_job(store: &MemoryKv, shards: &dyn ShardMap, spec: &ForkSpec, job: &ForkJobV1) {
        store
            .apply(
                &shards.coordinator(&spec.dest.namespace),
                Batch::new().put(
                    keys::fork_job(&spec.dest.name),
                    fork::encode_job(job).unwrap(),
                ),
            )
            .await
            .unwrap();
    }

    async fn settle(store: &MemoryKv, shards: &dyn ShardMap, spec: &ForkSpec) {
        let original = original();
        let replay = codec::encode_replay_record(&ReplayRecord {
            fingerprint: original.fingerprint,
            expires_at_ms: original.expires_at_ms,
            state: ReplayState::Committed(StoredResult::Fork),
        });
        let reservation = codec::encode_reservation(&codec::ReservationV1::committed(
            identity(&spec.dest),
            1,
            10,
            10,
            0,
            Vec::new(),
            codec::StoredProcedure::Fork,
        ));
        store
            .apply(
                &shards.coordinator(&spec.dest.namespace),
                Batch::new()
                    .put(keys::replay(&original.scope), replay)
                    .put(keys::reservation("reservation").unwrap(), reservation),
            )
            .await
            .unwrap();
    }

    #[test]
    fn fork_status_routes_absence_corruption_and_complete_inventory() {
        futures_executor::block_on(async {
            for shards in [&SinglePartition as &dyn ShardMap, &D34Shards] {
                let store = MemoryKv::default();
                let spec = spec();
                let reads = ReadAccess::new(&store, shards, RepoVisibility::Public, true);
                assert!(reads.fork_job_status(&spec).await.unwrap().is_none());
                store
                    .apply(
                        &shards.coordinator(&spec.dest.namespace),
                        Batch::new().put(keys::fork_job(&spec.dest.name), Value::new(vec![255])),
                    )
                    .await
                    .unwrap();
                assert!(reads.fork_job_status(&spec).await.is_err());
                let mut job = job(&spec);
                write_job(&store, shards, &spec, &job).await;
                let status = reads.fork_job_status(&spec).await.unwrap().unwrap();
                assert_eq!(status.result, job.result);
                assert_eq!(status.packs[0].bytes, 10);
                assert_eq!(status.authority.unwrap().generation, Some(1));
                let completed = job.clone();
                job.phase = Phase::Copy;
                write_job(&store, shards, &spec, &job).await;
                assert!(reads.fork_job_status(&spec).await.is_err());
                job = completed;
                job.packs.push(job.packs[0]);
                write_job(&store, shards, &spec, &job).await;
                assert!(reads.fork_job_status(&spec).await.is_err());
            }
        });
    }

    #[test]
    fn completed_recovery_checks_live_original_settlement_without_reauthenticating_expiry() {
        futures_executor::block_on(async {
            for shards in [&SinglePartition as &dyn ShardMap, &D34Shards] {
                let clock = Arc::new(ManualClock::new(1_000));
                assert!(clock.now_ms() > original().expires_at_ms);
                let store = MemoryKv::with_clock(clock);
                let spec = spec();
                let reads = ReadAccess::new(&store, shards, RepoVisibility::Public, true);
                let original = original();
                assert!(
                    reads
                        .recover_completed_fork(&spec, &original)
                        .await
                        .unwrap()
                        .is_none()
                );
                let mut job = job(&spec);
                write_job(&store, shards, &spec, &job).await;
                assert!(
                    reads
                        .recover_completed_fork(&spec, &original)
                        .await
                        .is_err()
                );
                settle(&store, shards, &spec).await;
                let recovered = reads
                    .recover_completed_fork(&spec, &original)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(Some(recovered.result), job.result);
                assert_eq!(recovered.reservation.id, "reservation");
                let wrong = ForkReplayIdentity {
                    fingerprint: [9; 32],
                    ..original.clone()
                };
                assert!(reads.recover_completed_fork(&spec, &wrong).await.is_err());
                store
                    .apply(
                        &shards.coordinator(&spec.dest.namespace),
                        Batch::new().put(keys::replay(&original.scope), Value::new(vec![255])),
                    )
                    .await
                    .unwrap();
                assert!(
                    reads
                        .recover_completed_fork(&spec, &original)
                        .await
                        .is_err()
                );
                settle(&store, shards, &spec).await;
                store
                    .apply(
                        &shards.coordinator(&spec.dest.namespace),
                        Batch::new().put(
                            keys::reservation("reservation").unwrap(),
                            codec::encode_reservation(&codec::ReservationV1::committed(
                                identity(&spec.dest),
                                1,
                                10,
                                10,
                                1,
                                Vec::new(),
                                codec::StoredProcedure::Fork,
                            )),
                        ),
                    )
                    .await
                    .unwrap();
                assert!(
                    reads
                        .recover_completed_fork(&spec, &original)
                        .await
                        .is_err()
                );
                job.phase = Phase::Copy;
                job.result = None;
                write_job(&store, shards, &spec, &job).await;
                assert!(
                    reads
                        .recover_completed_fork(&spec, &original)
                        .await
                        .unwrap()
                        .is_none()
                );
            }
        });
    }

    #[test]
    fn completion_inventory_and_binding_fail_closed() {
        let spec = spec();
        let valid = job(&spec);
        let mutations: [fn(&mut ForkJobV1); 8] = [
            |job| job.result.as_mut().unwrap().pack_bytes += 1,
            |job| job.result.as_mut().unwrap().pack_set = [0; 32],
            |job| job.result.as_mut().unwrap().membership_generation += 1,
            |job| job.result.as_mut().unwrap().source_sequence += 1,
            |job| job.packs[0].node = false,
            |job| job.copied += 1,
            |job| job.failure = Some(Failure::Denied),
            |job| job.packs[0].len = u64::MAX,
        ];
        for mutate in mutations {
            let mut corrupt = valid.clone();
            mutate(&mut corrupt);
            assert!(validate_done(&corrupt, &spec).is_err());
        }
        futures_executor::block_on(async {
            let store = MemoryKv::default();
            let mut corrupt = valid;
            corrupt.binding = [0; 32];
            write_job(&store, &D34Shards, &spec, &corrupt).await;
            let reads = ReadAccess::new(&store, &D34Shards, RepoVisibility::Public, true);
            assert!(reads.fork_job_status(&spec).await.is_err());
            assert!(
                reads
                    .recover_completed_fork(&spec, &original())
                    .await
                    .is_err()
            );
        });
    }

    #[test]
    fn recovery_corrupt_rows_and_pending_payload_fail_closed_on_both_routes() {
        futures_executor::block_on(async {
            for shards in [&SinglePartition as &dyn ShardMap, &D34Shards] {
                let spec = spec();
                let original = original();
                for key in [
                    keys::fork_job(&spec.dest.name),
                    keys::replay(&original.scope),
                    keys::reservation("reservation").unwrap(),
                ] {
                    let store = MemoryKv::default();
                    write_job(&store, shards, &spec, &job(&spec)).await;
                    settle(&store, shards, &spec).await;
                    let reads = ReadAccess::new(&store, shards, RepoVisibility::Public, true);
                    assert!(
                        reads
                            .recover_completed_fork(&spec, &original)
                            .await
                            .unwrap()
                            .is_some()
                    );
                    store
                        .apply(
                            &shards.coordinator(&spec.dest.namespace),
                            Batch::new().put(key, Value::new(vec![255])),
                        )
                        .await
                        .unwrap();
                    assert!(
                        reads
                            .recover_completed_fork(&spec, &original)
                            .await
                            .is_err()
                    );
                }
                let store = MemoryKv::default();
                let mut corrupt = job(&spec);
                corrupt.settle.as_mut().unwrap().pending = vec![255];
                write_job(&store, shards, &spec, &corrupt).await;
                settle(&store, shards, &spec).await;
                let reads = ReadAccess::new(&store, shards, RepoVisibility::Public, true);
                assert!(
                    reads
                        .recover_completed_fork(&spec, &original)
                        .await
                        .is_err()
                );
            }
        });
    }

    #[test]
    fn pending_and_failed_status_requires_the_exact_retained_binding() {
        futures_executor::block_on(async {
            let mutations: [fn(&mut ForkJobV1); 7] = [
                |job| job.binding = [0; 32],
                |job| job.dest_ns.push('x'),
                |job| job.dest_repo.push('x'),
                |job| job.source_ns.push('x'),
                |job| job.source_repo.push('x'),
                |job| job.source_ref.push('x'),
                |job| job.tip = [0; 32],
            ];
            for shards in [&SinglePartition as &dyn ShardMap, &D34Shards] {
                let store = MemoryKv::default();
                let spec = spec();
                let reads = ReadAccess::new(&store, shards, RepoVisibility::Public, true);
                let mut pending = job(&spec);
                pending.phase = Phase::Copy;
                pending.result = None;
                write_job(&store, shards, &spec, &pending).await;
                let status = reads.fork_job_status(&spec).await.unwrap().unwrap();
                assert_eq!(status.phase, Phase::Copy);
                assert!(status.result.is_none());
                for mutate in mutations {
                    let mut corrupt = pending.clone();
                    mutate(&mut corrupt);
                    write_job(&store, shards, &spec, &corrupt).await;
                    assert!(reads.fork_job_status(&spec).await.is_err());
                    assert!(
                        reads
                            .recover_completed_fork(&spec, &original())
                            .await
                            .is_err()
                    );
                }
                pending.phase = Phase::Failed;
                pending.failure = Some(Failure::Denied);
                write_job(&store, shards, &spec, &pending).await;
                let status = reads.fork_job_status(&spec).await.unwrap().unwrap();
                assert_eq!(status.failure, Some(Failure::Denied));
                assert!(status.result.is_none());
                assert!(
                    reads
                        .recover_completed_fork(&spec, &original())
                        .await
                        .unwrap()
                        .is_none()
                );
            }
        });
    }

    async fn put_namespace(store: &MemoryKv, shards: &dyn ShardMap, spec: &ForkSpec) {
        store
            .apply(
                &shards.coordinator(&spec.dest.namespace),
                Batch::new().put(
                    keys::namespace_record(),
                    codec::encode_namespace_record(&codec::NamespaceRecord {
                        created_at_ms: 1,
                        config_version: 1,
                    }),
                ),
            )
            .await
            .unwrap();
    }

    fn creating(spec: &ForkSpec) -> ForkJobV1 {
        let mut job = job(spec);
        job.fence.as_mut().unwrap().create_namespace = true;
        job
    }

    #[test]
    fn a_fork_that_created_the_namespace_is_recovered_and_a_plain_one_still_is() {
        futures_executor::block_on(async {
            for shards in [&SinglePartition as &dyn ShardMap, &D34Shards] {
                for create in [false, true] {
                    let store = MemoryKv::default();
                    let spec = spec();
                    let reads = ReadAccess::new(&store, shards, RepoVisibility::Public, true);
                    let job = if create { creating(&spec) } else { job(&spec) };
                    write_job(&store, shards, &spec, &job).await;
                    settle(&store, shards, &spec).await;
                    if create {
                        // The namespace record is part of the evidence.
                        assert!(
                            reads
                                .recover_completed_fork(&spec, &original())
                                .await
                                .is_err()
                        );
                        store
                            .apply(
                                &shards.coordinator(&spec.dest.namespace),
                                Batch::new().put(keys::namespace_record(), Value::new(vec![255])),
                            )
                            .await
                            .unwrap();
                        assert!(
                            reads
                                .recover_completed_fork(&spec, &original())
                                .await
                                .is_err()
                        );
                        put_namespace(&store, shards, &spec).await;
                    }
                    let recovered = reads
                        .recover_completed_fork(&spec, &original())
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(Some(&recovered.result), job.result.as_ref());
                    assert_eq!(recovered.authority.creates_namespace, create);
                    assert_eq!(recovered.reservation.declared_bytes, 10);
                }
            }
        });
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn a_namespace_creating_fork_fails_closed_on_each_mismatched_field() {
        type Mutation = fn(&mut ForkJobV1);
        fn replay(job: &mut ForkJobV1) -> &mut ReplayV1 {
            job.settle.as_mut().unwrap().replay.as_mut().unwrap()
        }
        let job_mutations: [Mutation; 10] = [
            |job| job.fence.as_mut().unwrap().grant_epoch = Some(1),
            |job| job.fence.as_mut().unwrap().authority_generation = None,
            |job| replay(job).scope = [9; 32],
            |job| replay(job).fingerprint = [9; 32],
            |job| replay(job).expires_at_ms += 1,
            |job| job.settle.as_mut().unwrap().replay = None,
            |job| job.settle.as_mut().unwrap().rid = "other".into(),
            |job| job.settle.as_mut().unwrap().repository.push('x'),
            |job| job.settle.as_mut().unwrap().declared_bytes = 9,
            |job| {
                job.settle.as_mut().unwrap().namespace_cap = Some(crate::fork::ChargeV1 {
                    scope: "s".into(),
                    bytes: 1,
                    window_ms: 1,
                    max_ops: 1,
                    max_bytes: 1,
                });
            },
        ];
        futures_executor::block_on(async {
            let spec = spec();
            for shards in [&SinglePartition as &dyn ShardMap, &D34Shards] {
                for mutate in job_mutations {
                    let store = MemoryKv::default();
                    let mut job = creating(&spec);
                    mutate(&mut job);
                    write_job(&store, shards, &spec, &job).await;
                    settle(&store, shards, &spec).await;
                    put_namespace(&store, shards, &spec).await;
                    let reads = ReadAccess::new(&store, shards, RepoVisibility::Public, true);
                    assert!(
                        reads
                            .recover_completed_fork(&spec, &original())
                            .await
                            .is_err()
                    );
                }
                // Reservation rows that disagree with the completed result.
                let committed = |repository: String, stored: u64, repo: u64, store: u64| {
                    codec::encode_reservation(&codec::ReservationV1::committed(
                        repository,
                        1,
                        stored,
                        repo,
                        store,
                        Vec::new(),
                        codec::StoredProcedure::Fork,
                    ))
                };
                let dest = identity(&spec.dest);
                let reservations = [
                    committed(dest.clone(), 10, 10, 1),
                    committed(dest.clone(), 11, 10, 0),
                    committed(dest.clone(), 10, 11, 0),
                    committed(format!("{dest}x"), 10, 10, 0),
                    codec::encode_reservation(&codec::ReservationV1::committed(
                        dest.clone(),
                        1,
                        10,
                        10,
                        0,
                        vec![codec::OutcomeRef {
                            name: "refs/heads/main".into(),
                            new: None,
                            deleted: true,
                        }],
                        codec::StoredProcedure::Fork,
                    )),
                ];
                for reservation in reservations {
                    let store = MemoryKv::default();
                    write_job(&store, shards, &spec, &creating(&spec)).await;
                    settle(&store, shards, &spec).await;
                    put_namespace(&store, shards, &spec).await;
                    store
                        .apply(
                            &shards.coordinator(&spec.dest.namespace),
                            Batch::new()
                                .put(keys::reservation("reservation").unwrap(), reservation),
                        )
                        .await
                        .unwrap();
                    let reads = ReadAccess::new(&store, shards, RepoVisibility::Public, true);
                    assert!(
                        reads
                            .recover_completed_fork(&spec, &original())
                            .await
                            .is_err()
                    );
                }
                // A missing replay or reservation row, with the namespace present.
                for missing in [
                    keys::replay(&original().scope),
                    keys::reservation("reservation").unwrap(),
                ] {
                    let store = MemoryKv::default();
                    write_job(&store, shards, &spec, &creating(&spec)).await;
                    settle(&store, shards, &spec).await;
                    put_namespace(&store, shards, &spec).await;
                    store
                        .apply(
                            &shards.coordinator(&spec.dest.namespace),
                            Batch::new().delete(missing),
                        )
                        .await
                        .unwrap();
                    let reads = ReadAccess::new(&store, shards, RepoVisibility::Public, true);
                    assert!(
                        reads
                            .recover_completed_fork(&spec, &original())
                            .await
                            .is_err()
                    );
                }
                // Replay records that are not the committed original.
                let replays = [
                    ([5; 32], 1, ReplayState::InFlight { resumable: false }),
                    ([5; 32], 1, ReplayState::Committed(StoredResult::UploadPack)),
                    ([9; 32], 1, ReplayState::Committed(StoredResult::Fork)),
                    ([5; 32], 2, ReplayState::Committed(StoredResult::Fork)),
                ];
                for (fingerprint, expires_at_ms, state) in replays {
                    let store = MemoryKv::default();
                    write_job(&store, shards, &spec, &creating(&spec)).await;
                    settle(&store, shards, &spec).await;
                    put_namespace(&store, shards, &spec).await;
                    store
                        .apply(
                            &shards.coordinator(&spec.dest.namespace),
                            Batch::new().put(
                                keys::replay(&original().scope),
                                codec::encode_replay_record(&ReplayRecord {
                                    fingerprint,
                                    expires_at_ms,
                                    state,
                                }),
                            ),
                        )
                        .await
                        .unwrap();
                    let reads = ReadAccess::new(&store, shards, RepoVisibility::Public, true);
                    assert!(
                        reads
                            .recover_completed_fork(&spec, &original())
                            .await
                            .is_err()
                    );
                }
            }
        });
    }

    #[test]
    fn recovery_agrees_with_the_internal_completed_fork_check() {
        use crate::fork::CompletedFork;
        type Mutation = fn(&mut ForkJobV1);
        let mutations: [Option<Mutation>; 6] = [
            None,
            Some(|job| job.binding = [0; 32]),
            Some(|job| job.tip = [0; 32]),
            Some(|job| job.source_repo.push('x')),
            Some(|job| job.result.as_mut().unwrap().source_sequence += 1),
            Some(|job| job.phase = Phase::Copy),
        ];
        futures_executor::block_on(async {
            let spec = spec();
            for create in [false, true] {
                for mutate in mutations {
                    let store = MemoryKv::default();
                    let mut job = if create { creating(&spec) } else { job(&spec) };
                    if let Some(mutate) = mutate {
                        mutate(&mut job);
                    }
                    write_job(&store, &D34Shards, &spec, &job).await;
                    settle(&store, &D34Shards, &spec).await;
                    put_namespace(&store, &D34Shards, &spec).await;
                    let reads = ReadAccess::new(&store, &D34Shards, RepoVisibility::Public, true);
                    let recovered = matches!(
                        reads.recover_completed_fork(&spec, &original()).await,
                        Ok(Some(_))
                    );
                    // Typed recovery never accepts a job the internal check refuses,
                    // and for these fixtures it accepts exactly the ones it accepts.
                    assert_eq!(recovered, CompletedFork::check(&job, &spec).is_some());
                }
            }
        });
    }
}
