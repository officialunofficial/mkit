//! Reference-only writer races against durable fork registration and clearance.
#![cfg(feature = "memory")]
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
mod fork_support;
use fork_support::*;
use mkit_attest::grant::Visibility;
use mkit_core::hash::hash;
use mkit_core::protocol::AdvanceOutcome;
use mkit_core::refs::RefWriteCondition;
use mkit_server::fork::{Failure, ForkEnv, ForkJobV1, ForkLimits, ForkSpec, Phase};
use mkit_server::pipeline::{Hooks, Pipeline};
use mkit_server::store::adapter_spi::{codec, keys};
use mkit_server::{
    Batch, BlobKey, Clock as _, NamespaceStore, Procedure, RefUpdate, RepoId, RepoName,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

fn env(source: &Source) -> ForkEnv<'_, Counting> {
    ForkEnv {
        publication_policy: None,
        store: &source.store,
        shards: source.shards.as_ref(),
        clock: source.clock.as_ref(),
        takedown_denial: true,
        extract_min_bytes: None,
        limits: ForkLimits::default(),
    }
}

fn destination(source: &Source) -> RepoId {
    RepoId {
        namespace: source.repo.namespace.clone(),
        name: RepoName::new("destination").unwrap(),
    }
}

async fn start(source: &Source) {
    mkit_server::fork::start(
        &env(source),
        &ForkSpec {
            source: source.repo.clone(),
            source_ref: "refs/heads/main".into(),
            expected_tip: source.head,
            dest: destination(source),
            dest_visibility: Visibility::Public,
        },
        None,
    )
    .await
    .unwrap();
}

async fn job(source: &Source) -> ForkJobV1 {
    mkit_server::fork::read_job(
        source.store.inner.as_ref(),
        source.shards.as_ref(),
        &destination(source),
    )
    .await
    .unwrap()
    .unwrap()
    .0
}

async fn stop_at(source: &Source, phase: Phase) {
    for _ in 0..100 {
        let current = job(source).await;
        if current.phase == phase {
            return;
        }
        assert!(!current.finished(), "ended before {phase:?}: {current:?}");
        let store = source.store.clone();
        *source.store.trigger.lock().unwrap() = Some((
            "fj",
            Arc::new(move || {
                let store = store.clone();
                Box::pin(async move {
                    store.crash_after(1, true);
                })
            }),
        ));
        let _ = mkit_server::fork::step(
            &env(source),
            &destination(source),
            &mkit_server::budget::SliceBudget::new(600),
        )
        .await;
    }
    panic!("did not reach {phase:?}");
}

async fn finish(source: &Source) -> ForkJobV1 {
    for _ in 0..100 {
        let report = mkit_server::fork::step(
            &env(source),
            &destination(source),
            &mkit_server::budget::SliceBudget::new(600),
        )
        .await
        .unwrap();
        if report.job.finished() {
            return report.job;
        }
    }
    panic!("fork did not finish");
}

async fn barrier(source: &Source) -> Option<mkit_server::Value> {
    let id = destination(source);
    source
        .store
        .inner
        .get(
            &source.shards.coordinator(&id.namespace),
            &keys::fork_barrier(&id.name),
        )
        .await
        .unwrap()
}

async fn assert_upload_refused(writer: &mut Source) {
    let auth = writer.authenticate(Procedure::BeginUpload, writer.nonce + 1);
    writer.nonce += 1;
    let error = writer
        .pipe
        .begin_upload(&auth, "refs/heads/main", &[9; 32], 64)
        .await
        .unwrap_err();
    assert_eq!(error.code(), mkit_server::Code::Unavailable);
    assert_eq!(error.public_message(), "fork activation pending; retry");
}

#[tokio::test]
async fn an_actual_writer_creates_the_destination_before_register_and_the_fork_refuses() {
    let source = Source::build("source", 4).await;
    start(&source).await;
    stop_at(&source, Phase::Register).await;
    let mut writer = source.at("destination");
    let (bytes, tip, _) = tree_pack(2, 8, 100, vec![], b"writer");
    let pack = hash(&bytes);
    let map = writer.try_push(bytes, tip, None, &[pack]).await.unwrap();
    let refused = finish(&source).await;
    assert_eq!(refused.phase, Phase::Failed);
    assert_eq!(refused.failure, Some(Failure::Changed));
    assert!(refused.accepted.is_none());
    assert!(barrier(&source).await.is_none());
    assert_eq!(
        writer.published("refs/heads/main").await,
        Some((Some(tip), Some(map)))
    );
}

#[tokio::test]
async fn actual_register_wins_before_a_new_writers_atomic_lease_grant() {
    let source = Arc::new(Source::build("source", 4).await);
    start(&source).await;
    stop_at(&source, Phase::Register).await;
    let writer = source.at("destination");
    let auth = writer.authenticate(Procedure::BeginUpload, writer.nonce + 1);
    let competing = source.clone();
    let fired = Arc::new(AtomicBool::new(false));
    let observed = fired.clone();
    // BeginUpload obtains a coordinator lease before its ticket batch. Pause
    // before that grant creates rr: once a usable lease exists, Register must
    // refuse instead. The stale grant and real Register share this atomic row.
    *source.store.trigger.lock().unwrap() = Some((
        "rr",
        Arc::new(move || {
            let competing = competing.clone();
            observed.store(true, Ordering::SeqCst);
            Box::pin(async move {
                stop_at(&competing, Phase::Copy).await;
            })
        }),
    ));
    let error = writer
        .pipe
        .begin_upload(&auth, "refs/heads/main", &[9; 32], 64)
        .await
        .unwrap_err();
    assert!(
        fired.load(Ordering::SeqCst),
        "writer never reached its atomic creation grant"
    );
    assert_eq!(error.code(), mkit_server::Code::Unavailable);
    assert_eq!(error.public_message(), "fork activation pending; retry");
    assert_eq!(job(&source).await.phase, Phase::Copy);
    assert!(barrier(&source).await.is_some());
    assert_eq!(finish(&source).await.phase, Phase::Done);
    assert!(barrier(&source).await.is_none());
}

#[tokio::test]
async fn actual_writes_wait_before_acceptance_and_after_acceptance_until_clearance() {
    let source = Source::build("source", 4).await;
    start(&source).await;
    let mut writer = source.at("destination");
    for phase in [Phase::Copy, Phase::Publish] {
        stop_at(&source, phase).await;
        let before = job(&source).await;
        assert_eq!(before.accepted.is_some(), phase == Phase::Publish);
        assert_upload_refused(&mut writer).await;
        let auth = writer.authenticate(Procedure::AdvanceRefs, writer.nonce + 1);
        writer.nonce += 1;
        let error = writer
            .pipe
            .advance_refs(
                &auth,
                RefUpdate {
                    name: "refs/heads/main".into(),
                    condition: RefWriteCondition::Missing,
                    new: Some(source.head),
                },
                RefUpdate {
                    name: "refs/mkit/packmap/main".into(),
                    condition: RefWriteCondition::Missing,
                    new: Some(source.packmap),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), mkit_server::Code::Unavailable);
        assert_eq!(error.public_message(), "fork activation pending; retry");
        assert_eq!(job(&source).await, before);
    }
    assert_eq!(finish(&source).await.phase, Phase::Done);
    let auth = writer.authenticate(Procedure::BeginUpload, writer.nonce + 1);
    assert!(
        writer
            .pipe
            .begin_upload(&auth, "refs/heads/main", &[9; 32], 64)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn an_already_usable_leased_writer_commits_and_real_registration_refuses() {
    let source = Arc::new(Source::build("source", 4).await);
    start(&source).await;
    stop_at(&source, Phase::Register).await;
    let mut writer = source.at("destination");
    let (bytes, tip, _) = tree_pack(2, 8, 100, vec![], b"writer");
    let pack = hash(&bytes);
    let map = writer.try_push(bytes, tip, None, &[pack]).await.unwrap();
    let shard = writer.shards.ref_shard(&writer.repo, "refs/heads/main");
    let lease = writer
        .store
        .inner
        .get(&shard, &keys::epoch_lease())
        .await
        .unwrap()
        .unwrap();
    assert!(
        codec::decode_epoch_lease(&lease).unwrap().expires_at_ms
            > u64::try_from(writer.clock.now_ms()).unwrap()
    );
    let competing = source.clone();
    let fired = Arc::new(AtomicBool::new(false));
    let observed = fired.clone();
    // This is an actual leased ref commit. A fork-winning ordering cannot
    // exist: granting the usable lease already created authoritative rr.
    *source.store.trigger.lock().unwrap() = Some((
        "pp",
        Arc::new(move || {
            let competing = competing.clone();
            observed.store(true, Ordering::SeqCst);
            Box::pin(async move {
                let refused = finish(&competing).await;
                assert_eq!(refused.failure, Some(Failure::Changed));
                assert!(barrier(&competing).await.is_none());
            })
        }),
    ));
    let nonce = writer.next_nonce();
    let auth = writer.authenticate(Procedure::AdvanceRefs, nonce);
    let outcome = writer
        .pipe
        .advance_refs(
            &auth,
            RefUpdate {
                name: "refs/heads/main".into(),
                condition: RefWriteCondition::Match(tip),
                new: None,
            },
            RefUpdate {
                name: "refs/mkit/packmap/main".into(),
                condition: RefWriteCondition::Match(map),
                new: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(outcome, AdvanceOutcome::Committed);
    assert!(
        fired.load(Ordering::SeqCst),
        "writer never reached its physical ref commit"
    );
    assert_eq!(
        writer
            .store
            .inner
            .get(&shard, &keys::epoch_lease())
            .await
            .unwrap(),
        Some(lease),
        "writer must use the existing lease"
    );
    assert!(writer.published("refs/heads/main").await.is_none());
    assert!(barrier(&source).await.is_none());
}

#[tokio::test]
async fn a_failed_registered_destination_stays_inert_after_expiry_and_pipeline_restart() {
    let source = Source::build("source", 4).await;
    start(&source).await;
    stop_at(&source, Phase::Copy).await;
    source
        .store
        .inner
        .apply(
            &source
                .shards
                .membership(&source.repo, &BlobKey::pack(source.pack)),
            Batch::new().delete(keys::published_member(&source.repo.name, &source.pack)),
        )
        .await
        .unwrap();
    let failed = finish(&source).await;
    assert_eq!(failed.phase, Phase::Failed);
    assert_eq!(failed.failure, Some(Failure::NotFound));
    let locked = barrier(&source).await.unwrap();
    let past_expiry = i64::try_from(failed.expires_ms).unwrap() + 1;
    source.clock.advance(past_expiry - source.clock.now_ms());
    let mut restarted = source.at("destination");
    restarted.pipe = Arc::new(
        Pipeline::new(
            source.blobs.clone(),
            source.store.clone(),
            Hooks::new(),
            Source::config(source.namespace),
            source.clock.clone(),
            Arc::new(mkit_server::NoopMetrics),
        )
        .unwrap(),
    );
    for _ in 0..3 {
        assert_eq!(finish(&source).await, failed);
        assert_upload_refused(&mut restarted).await;
        assert_eq!(barrier(&source).await, Some(locked.clone()));
    }
}
