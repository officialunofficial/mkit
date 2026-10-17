//! Versioned final source proof across bounded, durable slices.
//!
//! Every observation is captured before any pack is proved and guarded after
//! every pack has been proved. Unchanged, non-repeating versions establish a
//! common stable interval containing the entire pack-proof pass. Foreign-owner
//! changes after that interval retain §9.9's proof-to-acceptance ordering.

use serde::{Deserialize, Serialize};

use super::{ForkEnv, ForkError, ForkJobV1};
use crate::budget::SliceBudget;
use crate::indexed::budget::Budgeted;
use crate::store::{
    Batch, BatchOutcome, Cursor, Key, NamespaceStore, Partition, Precondition, StoreError, Value,
    Write, codec, keys, publication,
};
use mkit_core::hash::Hash;

// Leave ample room for the job-row guard and checkpoint beside evidence writes.
const EVIDENCE_WRITES: usize = 16;
const CALL_RESERVE: u32 = 60;
const DIRECTORY_SHARDS: u16 = 16;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
enum Stage {
    #[default]
    Source,
    Index,
    DirectoryVersions,
    Packs,
    DirectorySubjects,
    Proving,
    Validating,
    Complete,
}

/// Durable cursors for a coherent source proof. Observations live in separate
/// coordinator rows, so descriptor discovery does not enlarge the job row.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofV1 {
    stage: Stage,
    cursor: u32,
    evidence: u32,
    validated: u32,
    policy_validated: bool,
    directory_shard: u16,
    directory_after: Option<Vec<u8>>,
    directory_last: bool,
    // At most one validated directory page (64 subjects), never the directory.
    subjects: Vec<Hash>,
}

impl ProofV1 {
    /// Whether all version captures precede the pack-proof pass.
    pub(super) fn captured(&self) -> bool {
        matches!(
            self.stage,
            Stage::Proving | Stage::Validating | Stage::Complete
        )
    }

    /// Whether pack, pair and policy proof reads have all finished. Resuming
    /// validation must not start another proof pass after some guards ran.
    pub(super) fn validation_started(&self) -> bool {
        matches!(self.stage, Stage::Validating | Stage::Complete)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    binding: Hash,
    ordinal: u32,
    partition: Vec<u8>,
    observations: Vec<Observation>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    key: Vec<u8>,
    value: Option<Vec<u8>>,
}

fn corrupt() -> StoreError {
    StoreError::Corrupt("invalid fork source proof evidence".into())
}

fn encode(evidence: &Evidence) -> Result<Value, StoreError> {
    let mut bytes = vec![codec::CODEC_V1];
    serde_json::to_writer(&mut bytes, evidence).map_err(|_| corrupt())?;
    if bytes.len() > crate::store::MAX_VALUE_BYTES {
        return Err(StoreError::Invalid(
            "fork proof evidence exceeds value limit".into(),
        ));
    }
    Ok(Value::new(bytes))
}

fn decode(raw: &Value, job: &ForkJobV1, ordinal: u32) -> Result<Evidence, StoreError> {
    let Some((&codec::CODEC_V1, body)) = raw.as_bytes().split_first() else {
        return Err(corrupt());
    };
    let evidence: Evidence = serde_json::from_slice(body).map_err(|_| corrupt())?;
    if evidence.binding != job.binding
        || evidence.ordinal != ordinal
        || evidence.observations.is_empty()
    {
        return Err(corrupt());
    }
    Ok(evidence)
}

fn append(
    job: &mut ForkJobV1,
    batch: &mut Batch,
    partition: &Partition,
    wanted: &[Key],
    rows: Vec<Option<Value>>,
) -> Result<(), ForkError> {
    if rows.len() != wanted.len() || wanted.is_empty() {
        return Err(corrupt().into());
    }
    let ordinal = job.proof.evidence;
    let evidence = Evidence {
        binding: job.binding,
        ordinal,
        partition: partition.encode()?.to_vec(),
        observations: wanted
            .iter()
            .zip(rows)
            .map(|(key, value)| Observation {
                key: key.as_bytes().to_vec(),
                value: value.map(|raw| raw.as_bytes().to_vec()),
            })
            .collect(),
    };
    batch.writes.push(Write::Put(
        keys::fork_proof_evidence(&job.dest()?.name, ordinal),
        encode(&evidence)?,
    ));
    job.proof.evidence = ordinal.checked_add(1).ok_or(ForkError::TooLarge)?;
    Ok(())
}

async fn capture_source<S: NamespaceStore>(
    store: &S,
    env: &ForkEnv<'_, impl NamespaceStore>,
    job: &mut ForkJobV1,
    batch: &mut Batch,
) -> Result<(), ForkError> {
    let source = job.source()?;
    job.source_access.check_policy(env, &source)?;
    let partition = env.shards.ref_shard(&source, &job.source_ref);
    let key = keys::publication(&source.name, &publication::sequence_ref(&job.source_ref));
    let raw = store.get(&partition, &key).await?;
    let row = publication::Publication::decode(raw.as_ref())?;
    if row.value.head != Some(job.tip)
        || row.value.packmap != Some(job.packmap)
        || row.generation != job.source_generation
        || row.sequence != job.source_sequence
    {
        return Err(ForkError::NotFound);
    }
    append(job, batch, &partition, &[key], vec![raw])?;
    let partition = env.shards.coordinator(&source.namespace);
    let wanted = [
        keys::repo_visibility(&source.name),
        keys::repo_visibility_revision(&source.name),
    ];
    let rows = store.get_many(&partition, &wanted).await?;
    if rows.len() != 2 {
        return Err(corrupt().into());
    }
    if rows[0].as_ref().map(Value::as_bytes) != job.source_access.visibility.as_deref()
        || rows[1].as_ref().map(Value::as_bytes) != job.source_access.revision.as_deref()
    {
        return Err(ForkError::NotFound);
    }
    append(job, batch, &partition, &wanted, rows)?;
    job.proof.stage = Stage::Index;
    Ok(())
}

#[derive(Clone, Copy)]
enum CapturedKind {
    Revision,
    Pack,
    Subject,
}

async fn capture_one<S: NamespaceStore>(
    store: &S,
    job: &mut ForkJobV1,
    batch: &mut Batch,
    partition: &Partition,
    key: Key,
    kind: CapturedKind,
) -> Result<(), ForkError> {
    let raw = store.get(partition, &key).await?;
    match kind {
        CapturedKind::Revision => {
            raw.as_ref().map(codec::decode_u64).transpose()?;
        }
        CapturedKind::Pack | CapturedKind::Subject => {
            let state = raw.as_ref().map(codec::decode_object_state).transpose()?;
            if matches!(kind, CapturedKind::Pack) && state.is_some_and(|state| state.deleting) {
                return Err(ForkError::NotFound);
            }
        }
    }
    append(job, batch, partition, &[key], vec![raw])
}

/// Source mutation stamps are part of the sharded fork deployment contract.
/// Namespace-only writers do not maintain them; accepting those snapshots would
/// certify incomplete evidence. Completed receipts do not use this check.
pub(super) fn require_versioned_source<S>(
    env: &ForkEnv<'_, S>,
    source: &crate::RepoId,
) -> Result<(), ForkError> {
    let indices = env.shards.object_index_partitions(source);
    if indices.is_empty()
        || indices
            .iter()
            .any(|p| !matches!(p, Partition::RepoIndex { .. }))
    {
        return Err(ForkError::Unavailable(
            "fork source requires sharded repository indexes",
        ));
    }
    Ok(())
}

/// Capture every version before any pack-proof read. The returned evidence
/// writes MUST commit atomically with the mutated job checkpoint. A true result
/// means capture is complete; the caller still commits this batch before
/// entering the pack-proof pass.
pub(super) async fn advance_capture<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    job: &mut ForkJobV1,
    budget: &SliceBudget,
) -> Result<(Batch, bool), ForkError> {
    let store = Budgeted::new(env.store, budget);
    let source = job.source()?;
    let indices = env.shards.object_index_partitions(&source);
    let mut batch = Batch::new();
    while batch.writes.len() < EVIDENCE_WRITES && budget.remaining() >= CALL_RESERVE {
        match job.proof.stage {
            Stage::Source => capture_source(&store, env, job, &mut batch).await?,
            Stage::Index => {
                if let Some(partition) = indices.get(job.proof.cursor as usize) {
                    capture_one(
                        &store,
                        job,
                        &mut batch,
                        partition,
                        keys::fork_index_revision(),
                        CapturedKind::Revision,
                    )
                    .await?;
                    job.proof.cursor += 1;
                } else {
                    job.proof.cursor = 0;
                    job.proof.stage = Stage::DirectoryVersions;
                }
            }
            Stage::DirectoryVersions => {
                if env.takedown_denial && job.proof.cursor < u32::from(DIRECTORY_SHARDS) {
                    let partition = Partition::ContentShard(
                        u16::try_from(job.proof.cursor).map_err(|_| corrupt())?,
                    );
                    capture_one(
                        &store,
                        job,
                        &mut batch,
                        &partition,
                        keys::denial_directory_revision(),
                        CapturedKind::Revision,
                    )
                    .await?;
                    job.proof.cursor += 1;
                } else {
                    job.proof.cursor = 0;
                    job.proof.stage = Stage::Packs;
                }
            }
            Stage::Packs => {
                if let Some(id) = job.packs.get(job.proof.cursor as usize).map(|pack| pack.id) {
                    capture_one(
                        &store,
                        job,
                        &mut batch,
                        &crate::store::content_shard(&id),
                        keys::object_state(&id),
                        CapturedKind::Pack,
                    )
                    .await?;
                    job.proof.cursor += 1;
                } else {
                    job.proof.cursor = 0;
                    job.proof.stage = Stage::DirectorySubjects;
                }
            }
            Stage::DirectorySubjects => {
                if !env.takedown_denial || job.proof.directory_shard >= DIRECTORY_SHARDS {
                    job.proof.stage = Stage::Proving;
                } else {
                    capture_subject(&store, job, &mut batch).await?;
                }
            }
            Stage::Proving | Stage::Validating | Stage::Complete => return Ok((batch, true)),
        }
    }
    Ok((batch, job.proof.captured()))
}

async fn capture_subject<S: NamespaceStore>(
    store: &S,
    job: &mut ForkJobV1,
    batch: &mut Batch,
) -> Result<(), ForkError> {
    if let Some(id) = job.proof.subjects.last().copied() {
        capture_one(
            store,
            job,
            batch,
            &crate::store::content_shard(&id),
            keys::object_state(&id),
            CapturedKind::Subject,
        )
        .await?;
        job.proof.subjects.pop();
    } else if job.proof.directory_last {
        job.proof.directory_shard += 1;
        job.proof.directory_after = None;
        job.proof.directory_last = false;
    } else {
        let after = job
            .proof
            .directory_after
            .as_ref()
            .map(|raw| Cursor::new(raw.clone()));
        let page = crate::takedown::directory::proof_page(
            store,
            job.proof.directory_shard,
            after.as_ref(),
        )
        .await?;
        job.proof.subjects = page
            .entries
            .iter()
            .map(|(key, value)| crate::takedown::directory::proof_subject(key, value))
            .collect::<Result<_, _>>()?;
        job.proof.directory_last = page.next.is_none();
        job.proof.directory_after = page.next.map(|cursor| cursor.as_bytes().to_vec());
    }
    Ok(())
}

/// Begin checking captured versions only after the entire pack-proof pass.
/// Calling this again while checking preserves the durable validation cursor.
pub(super) fn start_validation(job: &mut ForkJobV1) {
    if job.proof.stage == Stage::Proving {
        job.proof.stage = Stage::Validating;
        job.proof.validated = 0;
    }
}

/// Guard every captured version after all pack proofs. These foreign-owner
/// checks have no writes: they establish the source certificate, and the caller
/// guards the certificate's job checkpoint in its advancing coordinator commit.
pub(super) async fn validate_slice<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    job: &mut ForkJobV1,
    budget: &SliceBudget,
) -> Result<bool, ForkError> {
    if job.proof.stage == Stage::Complete {
        return Ok(true);
    }
    if job.proof.stage != Stage::Validating {
        return Err(ForkError::Unavailable("fork source proof incomplete"));
    }
    if !job.proof.policy_validated {
        job.source_access.check_policy(env, &job.source()?)?;
        job.proof.policy_validated = true;
    }
    let store = Budgeted::new(env.store, budget);
    let destination = job.dest()?;
    let coordinator = env.shards.coordinator(&destination.namespace);
    while job.proof.validated < job.proof.evidence {
        if budget.remaining() < CALL_RESERVE {
            return Ok(false);
        }
        let ordinal = job.proof.validated;
        let raw = store
            .get(
                &coordinator,
                &keys::fork_proof_evidence(&destination.name, ordinal),
            )
            .await?
            .ok_or_else(corrupt)?;
        let evidence = decode(&raw, job, ordinal)?;
        let partition = Partition::decode(&evidence.partition)?;
        let mut batch = Batch::new().require(Precondition::NotAfter(
            env.now().saturating_add(super::CONTENT_WINDOW),
        ));
        for observation in evidence.observations {
            let key = Key::new(observation.key);
            batch.preconditions.push(match observation.value {
                Some(bytes) => Precondition::Equals(key, Value::new(bytes)),
                None => Precondition::Absent(key),
            });
        }
        match store.apply(&partition, batch).await? {
            BatchOutcome::Committed => job.proof.validated += 1,
            BatchOutcome::PreconditionFailed { .. } => return Err(ForkError::NotFound),
            BatchOutcome::DeadlinePassed { .. } => {
                return Err(ForkError::Unavailable("fork source proof deadline"));
            }
        }
    }
    job.proof.stage = Stage::Complete;
    Ok(true)
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    use crate::pipeline::clearance::PublicationPolicy;
    use crate::rt::BoxFuture;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    struct Policy {
        version: AtomicU64,
        available: AtomicBool,
    }

    impl PublicationPolicy for Policy {
        fn prepare<'a>(
            &'a self,
            _: &'a crate::op::Operation,
            _: &'a publication::Pair,
        ) -> BoxFuture<'a, Result<publication::Advance, crate::ServerError>> {
            Box::pin(async { Err(crate::ServerError::unavailable("unused preparation")) })
        }
        fn pack_available(&self, _: &crate::RepoId, _: &Hash) -> bool {
            self.available.load(Ordering::SeqCst)
        }
        fn fork_version(&self, _: &crate::RepoId) -> Option<Hash> {
            let mut version = [0; 32];
            version[..8].copy_from_slice(&self.version.load(Ordering::SeqCst).to_be_bytes());
            Some(version)
        }
    }

    #[test]
    fn policy_returning_to_available_does_not_restore_a_captured_fork_version() {
        let policy = Policy {
            version: AtomicU64::new(1),
            available: AtomicBool::new(true),
        };
        let source = crate::RepoId {
            namespace: crate::NamespaceKey::deployment_default(),
            name: crate::RepoName::new("source").expect("valid repository"),
        };
        let captured = super::super::SourceAccessV1::default()
            .with_policy(Some(&policy), &source)
            .expect("versioned policy");
        policy.available.store(false, Ordering::SeqCst);
        policy.version.store(2, Ordering::SeqCst);
        policy.available.store(true, Ordering::SeqCst);
        policy.version.store(3, Ordering::SeqCst);
        let current = super::super::SourceAccessV1::default()
            .with_policy(Some(&policy), &source)
            .expect("versioned policy");
        assert!(policy.pack_available(&source, &[0; 32]));
        assert_ne!(captured, current);
        // Replacing the configured policy with no policy also changes the
        // certificate, even though both currently permit the same pack.
        assert_ne!(captured, super::super::SourceAccessV1::default());
    }

    struct Unversioned;
    impl PublicationPolicy for Unversioned {
        fn prepare<'a>(
            &'a self,
            _: &'a crate::op::Operation,
            _: &'a publication::Pair,
        ) -> BoxFuture<'a, Result<publication::Advance, crate::ServerError>> {
            Box::pin(async { Err(crate::ServerError::unavailable("unused preparation")) })
        }
        fn pack_available(&self, _: &crate::RepoId, _: &Hash) -> bool {
            true
        }
    }

    #[test]
    fn an_unversioned_custom_policy_cannot_supply_source_acceptance_evidence() {
        let source = crate::RepoId {
            namespace: crate::NamespaceKey::deployment_default(),
            name: crate::RepoName::new("source").expect("valid repository"),
        };
        assert_eq!(
            super::super::SourceAccessV1::default().with_policy(Some(&Unversioned), &source),
            Err(ForkError::NotFound)
        );
    }
}

#[cfg(all(test, feature = "memory"))]
mod evidence_tests {
    #![allow(clippy::unwrap_used, clippy::too_many_lines)]
    use super::*;
    use crate::MemoryKv;
    use crate::fork::{FenceRowsV1, ForkLimits, PackRow, Phase, SourceAccessV1};
    use crate::pipeline::{D34Shards, ShardMap};
    use crate::rt::ManualClock;
    use crate::store::{BlockEntry, ContentIndex};
    use futures_executor::block_on;
    use std::sync::Arc;

    fn job() -> ForkJobV1 {
        ForkJobV1 {
            binding: [1; 32],
            dest_ns: crate::NamespaceKey::deployment_default().as_str().into(),
            dest_repo: "destination".into(),
            source_ns: crate::NamespaceKey::deployment_default().as_str().into(),
            source_repo: "source".into(),
            source_ref: "refs/heads/main".into(),
            tip: [2; 32],
            packmap: [3; 32],
            source_sequence: 1,
            source_generation: 0,
            visibility: "public".into(),
            created_ms: 0,
            expires_ms: 100_000,
            phase: Phase::Accept,
            packs: vec![PackRow {
                id: [3; 32],
                len: 1,
                objects: 1,
                node: true,
                base: false,
            }],
            cursor: 0,
            deps: Vec::new(),
            part: 0,
            lanes: Vec::new(),
            after: None,
            scanned: 0,
            copied: 0,
            failure: None,
            settle: None,
            fence: None,
            fence_rows: FenceRowsV1::default(),
            source_access: SourceAccessV1::default(),
            proof: ProofV1::default(),
            accepted: None,
            result: None,
        }
    }

    fn env<'a>(store: &'a MemoryKv, clock: &'a ManualClock) -> ForkEnv<'a, MemoryKv> {
        ForkEnv {
            store,
            shards: &D34Shards,
            clock,
            takedown_denial: true,
            extract_min_bytes: None,
            limits: ForkLimits::default(),
            publication_policy: None,
        }
    }

    async fn initialize(store: &MemoryKv, job: &ForkJobV1) {
        let source = job.source().unwrap();
        let row = publication::Publication {
            sequence: 1,
            published: 1,
            value: publication::Pair {
                head: Some(job.tip),
                packmap: Some(job.packmap),
            },
            ..publication::Publication::default()
        };
        assert_eq!(
            store
                .apply(
                    &D34Shards.ref_shard(&source, &job.source_ref),
                    Batch::new().put(
                        keys::publication(&source.name, &job.source_ref),
                        row.encode().unwrap()
                    ),
                )
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
    }

    /// Persist the returned observations with the cursor, then reconstruct the
    /// job from storage before every continuation, as a replacement driver does.
    async fn capture(env: &ForkEnv<'_, MemoryKv>, mut job: ForkJobV1) -> (ForkJobV1, usize) {
        let destination = job.dest().unwrap();
        let coordinator = D34Shards.coordinator(&destination.namespace);
        let mut checkpoints = 0;
        loop {
            let (batch, done) = advance_capture(env, &mut job, &SliceBudget::new(600))
                .await
                .unwrap();
            let batch = batch.put(
                keys::fork_job(&destination.name),
                super::super::encode_job(&job).unwrap(),
            );
            assert_eq!(
                env.store.apply(&coordinator, batch).await.unwrap(),
                BatchOutcome::Committed
            );
            job = super::super::decode_job(
                &env.store
                    .get(&coordinator, &keys::fork_job(&destination.name))
                    .await
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            checkpoints += 1;
            if done {
                return (job, checkpoints);
            }
            assert!(checkpoints < 20);
        }
    }

    #[test]
    fn evidence_refuses_wrong_binding_wrong_ordinal_and_empty_observations() {
        let job = job();
        let mut evidence = Evidence {
            binding: job.binding,
            ordinal: 7,
            partition: Partition::ContentShard(0).encode().unwrap().to_vec(),
            observations: vec![Observation {
                key: keys::denial_directory_revision().as_bytes().to_vec(),
                value: None,
            }],
        };
        assert!(decode(&encode(&evidence).unwrap(), &job, 7).is_ok());
        assert!(decode(&encode(&evidence).unwrap(), &job, 8).is_err());
        evidence.binding = [9; 32];
        assert!(decode(&encode(&evidence).unwrap(), &job, 7).is_err());
        evidence.binding = job.binding;
        evidence.observations.clear();
        assert!(decode(&encode(&evidence).unwrap(), &job, 7).is_err());
        assert!(decode(&Value::new(vec![2]), &job, 7).is_err());
    }

    #[test]
    fn captured_evidence_survives_driver_replacement_and_guarded_validation() {
        block_on(async {
            let clock = Arc::new(ManualClock::new(0));
            let store = MemoryKv::with_clock(clock.clone());
            let initial = job();
            initialize(&store, &initial).await;
            let (mut job, checkpoints) = capture(&env(&store, &clock), initial).await;
            assert!(checkpoints >= 3, "capture must cross durable checkpoints");
            assert!(job.proof.captured());
            assert_eq!(
                job.cursor, 0,
                "version capture never advances the pack proof"
            );
            assert!(job.accepted.is_none());
            start_validation(&mut job);
            assert!(
                validate_slice(&env(&store, &clock), &mut job, &SliceBudget::new(600))
                    .await
                    .unwrap()
            );
            assert_eq!(job.proof.validated, job.proof.evidence);
            assert!(
                job.accepted.is_none(),
                "certificate is not an acceptance receipt"
            );
        });
    }

    #[test]
    fn source_index_and_directory_moves_invalidate_the_final_guard() {
        block_on(async {
            for directory in [false, true] {
                let clock = Arc::new(ManualClock::new(0));
                let store = MemoryKv::with_clock(clock.clone());
                let initial = job();
                initialize(&store, &initial).await;
                let source = initial.source().unwrap();
                let (mut job, _) = capture(&env(&store, &clock), initial).await;
                // This is the final source-proof boundary: all initial
                // captures are durable, before the source changes.
                if directory {
                    crate::takedown::directory::reserve(&store, &[0x90; 32], 0)
                        .await
                        .unwrap();
                } else {
                    let partition = D34Shards.object_index(&source, &[0x90; 32]);
                    assert_eq!(
                        store
                            .apply(
                                &partition,
                                Batch::new().increment(keys::fork_index_revision())
                            )
                            .await
                            .unwrap(),
                        BatchOutcome::Committed
                    );
                }
                start_validation(&mut job);
                assert_eq!(
                    validate_slice(&env(&store, &clock), &mut job, &SliceBudget::new(600)).await,
                    Err(ForkError::NotFound)
                );
                assert!(job.accepted.is_none());
            }
        });
    }

    #[test]
    fn namespace_only_sources_do_not_certify_unversioned_membership() {
        let clock = Arc::new(ManualClock::new(0));
        let store = MemoryKv::with_clock(clock.clone());
        let mut environment = env(&store, &clock);
        environment.shards = &crate::pipeline::SinglePartition;
        assert!(matches!(
            require_versioned_source(&environment, &job().source().unwrap()),
            Err(ForkError::Unavailable(_))
        ));
    }

    #[test]
    fn an_empty_registered_descriptor_remains_part_of_the_final_guard() {
        block_on(async {
            let clock = Arc::new(ManualClock::new(0));
            let store = MemoryKv::with_clock(clock.clone());
            let initial = job();
            initialize(&store, &initial).await;
            let subject = [0x90; 32];
            let index = ContentIndex::new(crate::store::BorrowedStore(&store));
            let capability = crate::takedown::DenialCapability::for_test();
            index
                .block(&capability, &subject, &BlockEntry::new("denied", 0), 0)
                .await
                .unwrap();
            index.unblock(&subject, 0).await.unwrap();
            let (mut job, _) = capture(&env(&store, &clock), initial).await;
            // Registration does not move again; the previously empty subject
            // becomes denied, then clear again with a different content seq.
            index
                .block(
                    &capability,
                    &subject,
                    &BlockEntry::new("denied again", 0),
                    0,
                )
                .await
                .unwrap();
            index.unblock(&subject, 0).await.unwrap();
            start_validation(&mut job);
            assert_eq!(
                validate_slice(&env(&store, &clock), &mut job, &SliceBudget::new(600)).await,
                Err(ForkError::NotFound)
            );
            assert!(job.accepted.is_none());
        });
    }
}
