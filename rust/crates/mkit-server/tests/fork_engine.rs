//! The fork engine against a published source repository.
#![cfg(feature = "memory")]
#![allow(
    clippy::unwrap_used,
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::match_same_arms
)]
mod fork_support;
use fork_support::*;
use futures::StreamExt as _;
use mkit_attest::grant::Visibility;
use mkit_core::hash::Hash;
use mkit_server::BlobKey;
use mkit_server::Clock as _;
use mkit_server::MemoryKv;
use mkit_server::store::{BlockEntry, ContentIndex, Holder};
use mkit_server::{
    NamespaceStore, RepoId, RepoName,
    budget::SliceBudget,
    fork::{ForkEnv, ForkLimits, ForkSpec, Phase, StartOutcome},
    store::adapter_spi::{keys, publication::Witness},
};
use std::sync::Arc;

fn dest(source: &Source, name: &str) -> RepoId {
    RepoId {
        namespace: source.repo.namespace.clone(),
        name: RepoName::new(name).unwrap(),
    }
}

fn spec(source: &Source, name: &str) -> ForkSpec {
    ForkSpec {
        source: source.repo.clone(),
        source_ref: "refs/heads/main".into(),
        expected_tip: source.head,
        dest: dest(source, name),
        dest_visibility: Visibility::Public,
    }
}

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

async fn run(source: &Source, name: &str) -> mkit_server::fork::ForkJobV1 {
    let env = env(source);
    let dest = dest(source, name);
    for _ in 0..200 {
        let report = mkit_server::fork::step(&env, &dest, &SliceBudget::new(600))
            .await
            .unwrap();
        if report.job.finished() {
            return report.job;
        }
    }
    panic!("fork did not finish");
}

#[tokio::test]
async fn forks_a_published_branch_into_an_empty_repository() {
    let source = Source::build("source", 40).await;
    let env = env(&source);
    let started = mkit_server::fork::start(&env, &spec(&source, "forked"), None)
        .await
        .unwrap();
    assert!(matches!(started, StartOutcome::Started(_)));
    let job = run(&source, "forked").await;
    assert_eq!(job.phase, Phase::Done, "{:?}", job.failure);
    let result = job.result.unwrap();
    assert_eq!(result.tip, source.head);
    assert_eq!(result.packmap, source.packmap);
    assert_eq!(result.pack_count, 2);
    // 40 blobs, a tree and a commit.
    assert_eq!(result.object_count, 42);
    let dest = dest(&source, "forked");
    // The packmap head is a flagged member; the data pack is a plain one.
    for (pack, flagged) in [(source.packmap, true), (source.pack, false)] {
        let p = source
            .shards
            .membership(&dest, &mkit_server::BlobKey::pack(pack));
        for key in [
            keys::membership(&dest.name, &pack),
            keys::published_member(&dest.name, &pack),
        ] {
            let raw = source.store.inner.get(&p, &key).await.unwrap().unwrap();
            let witness = Witness::decode(&raw).unwrap();
            assert!(witness.published && !witness.held);
            assert_eq!(witness.boundary, flagged);
        }
    }
    // No ref exists.
    let (start, end) = keys::ref_index_prefix_range(&dest.name, "");
    for p in source.shards.ref_index_partitions(&dest) {
        assert_eq!(
            source
                .store
                .inner
                .scan(&p, &start, &end, None, 1)
                .await
                .unwrap()
                .entries,
            [] as [(mkit_server::Key, mkit_server::Value); 0]
        );
    }
    // The cleared set holds the commit and the tree only.
    let c = source.shards.coordinator(&dest.namespace);
    let raw = source
        .store
        .inner
        .get(&c, &keys::fork_set(&dest.name, 0))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(raw.as_bytes().len(), 64);
    let ids: Vec<Hash> = raw
        .as_bytes()
        .chunks(32)
        .map(|c| c.try_into().unwrap())
        .collect();
    assert!(ids.contains(&source.head) && ids.contains(&source.tree));
}

async fn dest_state(
    source: &Source,
    dest: &RepoId,
) -> std::collections::BTreeMap<(String, Vec<u8>), Vec<u8>> {
    use mkit_server::Key;
    let mut out = std::collections::BTreeMap::new();
    let mut partitions = source.shards.object_index_partitions(dest);
    partitions.push(source.shards.coordinator(&dest.namespace));
    for p in partitions {
        let page = source
            .store
            .inner
            .scan(&p, &Key::new(vec![]), &Key::new(vec![255]), None, 100_000)
            .await
            .unwrap();
        for (key, value) in page.entries {
            let Some(parsed) = keys::parse(&key) else {
                continue;
            };
            use mkit_server::store::adapter_spi::keys::ParsedKey as K;
            let mine = match &parsed {
                K::ObjectIndex { repo, .. } | K::Membership { repo, .. } => *repo == dest.name,
                K::PublishedMember { repo, .. }
                | K::RepoStoragePack { repo, .. }
                | K::RepoStorage(repo) => *repo == dest.name,
                K::ForkSet { repo, .. } => *repo == dest.name,
                _ => false,
            };
            if mine {
                out.insert(
                    (format!("{p:?}"), key.as_bytes().to_vec()),
                    value.as_bytes().to_vec(),
                );
            }
        }
    }
    out
}

#[tokio::test]
async fn tip_mismatch_and_absent_refs_are_the_two_source_side_answers() {
    let source = Source::build("source", 4).await;
    let env = env(&source);
    let mut wrong = spec(&source, "forked");
    wrong.expected_tip = [9; 32];
    assert_eq!(
        mkit_server::fork::start(&env, &wrong, None)
            .await
            .unwrap_err(),
        mkit_server::fork::ForkError::TipChanged
    );
    for name in ["refs/heads/absent", "refs/tags/v1", "main", "refs/heads/"] {
        let mut absent = spec(&source, "forked");
        absent.source_ref = name.into();
        assert_eq!(
            mkit_server::fork::start(&env, &absent, None)
                .await
                .unwrap_err(),
            mkit_server::fork::ForkError::NotFound,
            "{name}"
        );
    }
    let mut unknown = spec(&source, "forked");
    unknown.source.name = RepoName::new("nowhere").unwrap();
    let a = mkit_server::fork::start(&env, &unknown, None)
        .await
        .unwrap_err();
    assert_eq!(a.error().public_message(), "source not found");
    assert_eq!(a, mkit_server::fork::ForkError::NotFound);
    // Nothing was written for any refusal.
    assert!(
        mkit_server::fork::read_job(env.store, env.shards, &dest(&source, "forked"))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn the_same_binding_resumes_and_another_is_refused() {
    let source = Source::build("source", 4).await;
    let env = env(&source);
    let first = mkit_server::fork::start(&env, &spec(&source, "forked"), None)
        .await
        .unwrap();
    let again = mkit_server::fork::start(&env, &spec(&source, "forked"), None)
        .await
        .unwrap();
    assert!(matches!(again, StartOutcome::Existing(_)));
    assert_eq!(first.job().binding, again.job().binding);
    let mut private = spec(&source, "forked");
    private.dest_visibility = Visibility::Private;
    assert_eq!(
        mkit_server::fork::start(&env, &private, None)
            .await
            .unwrap_err(),
        mkit_server::fork::ForkError::NotEmpty
    );
    let done = run(&source, "forked").await;
    assert_eq!(done.phase, Phase::Done);
    // A finished fork answers a replay with the same result.
    let replay = mkit_server::fork::start(&env, &spec(&source, "forked"), None)
        .await
        .unwrap();
    assert_eq!(replay.job().result, done.result);
    assert_eq!(
        mkit_server::fork::ForkError::NotEmpty
            .error()
            .public_message(),
        "destination not empty"
    );
}

#[tokio::test]
async fn a_destination_with_refs_or_members_is_not_empty() {
    let source = Source::build("source", 4).await;
    let env = env(&source);
    // The source itself has refs and members.
    let mut into_source = spec(&source, "source");
    into_source.dest = source.repo.clone();
    assert_eq!(
        mkit_server::fork::start(&env, &into_source, None)
            .await
            .unwrap_err(),
        mkit_server::fork::ForkError::NotEmpty
    );
    // A forked destination is not a fork destination any more.
    mkit_server::fork::start(&env, &spec(&source, "one"), None)
        .await
        .unwrap();
    assert_eq!(run(&source, "one").await.phase, Phase::Done);
    let mut other = spec(&source, "two");
    other.dest = dest(&source, "one");
    other.dest_visibility = Visibility::Private;
    assert_eq!(
        mkit_server::fork::start(&env, &other, None)
            .await
            .unwrap_err(),
        mkit_server::fork::ForkError::NotEmpty
    );
}

#[tokio::test]
async fn a_crash_at_every_write_resumes_to_the_same_destination() {
    let reference = {
        let source = Source::build("source", 12).await;
        mkit_server::fork::start(&env(&source), &spec(&source, "forked"), None)
            .await
            .unwrap();
        source
            .store
            .record
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(run(&source, "forked").await.phase, Phase::Done);
        let writes = source.store.log.lock().unwrap().len();
        (dest_state(&source, &dest(&source, "forked")).await, writes)
    };
    assert!(reference.1 >= 8, "{} applies", reference.1);
    for lost_reply in [false, true] {
        for crash_at in 1..=i64::try_from(reference.1).unwrap() {
            let source = Source::build("source", 12).await;
            let env = env(&source);
            mkit_server::fork::start(&env, &spec(&source, "forked"), None)
                .await
                .unwrap();
            source.store.crash_after(crash_at, lost_reply);
            let dest_id = dest(&source, "forked");
            let mut failures = 0;
            let job = loop {
                match mkit_server::fork::step(&env, &dest_id, &SliceBudget::new(600)).await {
                    Ok(report) if report.job.finished() => break report.job,
                    Ok(_) => {}
                    Err(_) => failures += 1,
                }
                assert!(failures < 4, "crash {crash_at} lost_reply {lost_reply}");
            };
            assert_eq!(job.phase, Phase::Done, "crash {crash_at} {lost_reply}");
            assert_eq!(
                dest_state(&source, &dest_id).await,
                reference.0,
                "crash at apply {crash_at}, lost reply {lost_reply}"
            );
        }
    }
}

fn denial(mut cfg: mkit_server::pipeline::PipelineConfig) -> mkit_server::pipeline::PipelineConfig {
    cfg.takedown_denial = true;
    cfg
}

async fn forked(files: u32) -> (Source, mkit_server::fork::ForkJobV1) {
    let source = Source::build_with("source", files, denial).await;
    mkit_server::fork::start(&env(&source), &spec(&source, "forked"), None)
        .await
        .unwrap();
    let job = run(&source, "forked").await;
    assert_eq!(job.phase, Phase::Done, "{:?}", job.failure);
    (source, job)
}

#[tokio::test]
async fn a_remix_commit_on_the_inherited_tree_publishes_without_walking_it() {
    for takedown_denial in [true, false] {
        let source = Source::build_with("source", 100, |mut cfg| {
            cfg.takedown_denial = takedown_denial;
            cfg
        })
        .await;
        let mut env = env(&source);
        env.takedown_denial = takedown_denial;
        mkit_server::fork::start(&env, &spec(&source, "forked"), None)
            .await
            .unwrap();
        for _ in 0..200 {
            if mkit_server::fork::step(&env, &dest(&source, "forked"), &SliceBudget::new(600))
                .await
                .unwrap()
                .job
                .finished()
            {
                break;
            }
        }
        let mut remix = source.at("forked");
        let (bytes, head) = commit_pack(source.tree, vec![], b"remix");
        let pack = mkit_core::hash::hash(&bytes);
        let before = source.store.calls();
        source
            .store
            .scans
            .store(0, std::sync::atomic::Ordering::SeqCst);
        let map = remix.push(bytes, head, Some(source.packmap), &[pack]).await;
        let calls = source.store.calls() - before;
        assert_eq!(
            remix.published("refs/heads/main").await,
            Some((Some(head), Some(map)))
        );
        // The 100 inherited blobs were never walked: the whole push, uploads,
        // verification and publication included, stays far below one call per
        // inherited object, and the walk made no per-object index scan.
        assert!(calls < 600, "{calls} calls with denial {takedown_denial}");
        let scans = source.store.scans.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            scans < 40,
            "{scans} index scans with denial {takedown_denial}"
        );
    }
}

#[tokio::test]
async fn without_the_inherited_packmap_head_the_inherited_tree_is_not_skipped() {
    let (source, _) = forked(40).await;
    let mut remix = source.at("forked");
    let (bytes, head) = commit_pack(source.tree, vec![], b"remix");
    let pack = mkit_core::hash::hash(&bytes);
    // A packmap that does not chain to the inherited head and lists no
    // inherited pack cannot serve the inherited objects, so the walk may not
    // rely on the cleared set and finds the tree open.
    let refused = remix.try_push(bytes.clone(), head, None, &[pack]).await;
    assert!(refused.is_err(), "{refused:?}");
    assert!(remix.published("refs/heads/main").await.is_none());
    // The same pair with a node that lists the inherited data pack but still
    // does not chain to the flagged head is complete, and is walked in full:
    // an index scan for every inherited object.
    source
        .store
        .scans
        .store(0, std::sync::atomic::Ordering::SeqCst);
    remix
        .try_push(bytes, head, None, &[source.pack, pack])
        .await
        .unwrap();
    let scans = source.store.scans.load(std::sync::atomic::Ordering::SeqCst);
    assert!(scans >= 42, "{scans} index scans");
}

#[tokio::test]
async fn the_inline_walk_skips_cleared_objects_with_denial_and_a_policy() {
    // The canonical (non-resumable) walk runs when a publication policy is
    // installed; with pack-level denial on it honors the cleared set too.
    let source = Source::build_policy("source", 25, 0, true, denial).await;
    mkit_server::fork::start(&env(&source), &spec(&source, "forked"), None)
        .await
        .unwrap();
    assert_eq!(run(&source, "forked").await.phase, Phase::Done);
    let mut remix = source.at("forked");
    let (bytes, head) = commit_pack(source.tree, vec![], b"remix");
    let pack = mkit_core::hash::hash(&bytes);
    source
        .store
        .scans
        .store(0, std::sync::atomic::Ordering::SeqCst);
    remix.push(bytes, head, Some(source.packmap), &[pack]).await;
    let scans = source.store.scans.load(std::sync::atomic::Ordering::SeqCst);
    assert!(scans < 12, "{scans} index scans");
}

/// Fork a repository of `objects` objects, push a remix commit on its tree and
/// report the instruments: modeled time at 50 ms per call, steps, the cleared
/// set and the remix's index scans (one per walked object).
async fn measure(files: u32, extra: u32) {
    let objects = files + extra + 2;
    let source = Source::build_full("source", files, extra, denial).await;
    let env = env(&source);
    source
        .store
        .latency_ms
        .store(50, std::sync::atomic::Ordering::SeqCst);
    let before = source.store.calls();
    let started = source.clock.now_ms();
    mkit_server::fork::start(&env, &spec(&source, "forked"), None)
        .await
        .unwrap();
    let mut steps = 0;
    let job = loop {
        steps += 1;
        let report =
            mkit_server::fork::step(&env, &dest(&source, "forked"), &SliceBudget::new(600))
                .await
                .unwrap();
        if report.job.finished() {
            break report.job;
        }
    };
    assert_eq!(job.phase, Phase::Done, "{:?}", job.failure);
    let fork_calls = source.store.calls() - before;
    let fork_ms = source.clock.now_ms() - started;
    let dest_id = dest(&source, "forked");
    let c = source
        .store
        .inner
        .get(
            &source.shards.coordinator(&dest_id.namespace),
            &keys::fork_set(&dest_id.name, 0),
        )
        .await
        .unwrap()
        .map_or(0, |v| v.as_bytes().len() / 32);
    let mut remix = source.at("forked");
    let (bytes, head) = commit_pack(source.tree, vec![], b"remix");
    let pack = mkit_core::hash::hash(&bytes);
    source
        .store
        .latency_ms
        .store(0, std::sync::atomic::Ordering::SeqCst);
    source
        .store
        .scans
        .store(0, std::sync::atomic::Ordering::SeqCst);
    let before = source.store.calls();
    let started = source.clock.now_ms();
    remix.push(bytes, head, Some(source.packmap), &[pack]).await;
    let remix_calls = source.store.calls() - before;
    let _ = started;
    // Sum of work at 50 ms per call, the model the fork is quoted in.
    let remix_s = remix_calls * 50 / 1000;
    let index_scans = source.store.scans.load(std::sync::atomic::Ordering::SeqCst);
    eprintln!(
        "FORKMEASURE objects={objects} fork_calls={fork_calls} fork_s={} steps={steps} \
         cleared={c} remix_calls={remix_calls} remix_s={remix_s} remix_index_scans={index_scans}",
        fork_ms / 1000,
    );
    assert!(
        index_scans < 40,
        "{index_scans} index scans walked inherited objects"
    );
}

#[tokio::test]
async fn measures_500_objects() {
    measure(498, 0).await;
}

#[tokio::test]
#[ignore = "large fork fixture; exercised by the ignored-lane CI profile"]
async fn measures_3000_objects() {
    measure(2_998, 0).await;
}

#[tokio::test]
#[ignore = "large fork fixture; exercised by the ignored-lane CI profile"]
async fn measures_10000_objects() {
    measure(2_998, 7_000).await;
}

fn block_hook(source: &Source, id: Hash) -> Hook {
    let inner = source.store.inner.clone();
    let now = u64::try_from(source.clock.now_ms()).unwrap();
    Arc::new(move || {
        let inner = inner.clone();
        Box::pin(async move {
            ContentIndex::new(inner)
                .block(
                    &denial_capability_for_test(),
                    &id,
                    &BlockEntry::new("takedown", now),
                    now,
                )
                .await
                .unwrap();
        })
    })
}

async fn block(source: &Source, id: Hash) {
    block_hook(source, id)().await;
}

fn public_answer(error: &mkit_server::ServerError) -> (mkit_server::Code, String) {
    (error.code(), error.public_message().to_owned())
}

#[tokio::test]
async fn every_unclearable_source_is_the_same_not_found_and_leaves_nothing() {
    let absent = {
        let source = Source::build("source", 6).await;
        let mut gone = spec(&source, "forked");
        gone.source.name = RepoName::new("nowhere").unwrap();
        mkit_server::fork::start(&env(&source), &gone, None)
            .await
            .unwrap_err()
    };
    let expected = public_answer(&absent.error());
    assert_eq!(expected.1, "source not found");
    for (label, pick) in [("blob", 0_usize), ("data pack", 1), ("packmap head", 2)] {
        let source = Source::build_with("source", 6, denial).await;
        let target = match pick {
            0 => blob(3, 8).0,
            1 => source.pack,
            _ => source.packmap,
        };
        block(&source, target).await;
        let env = env(&source);
        mkit_server::fork::start(&env, &spec(&source, "forked"), None)
            .await
            .unwrap();
        let job = run(&source, "forked").await;
        assert_eq!(job.phase, Phase::Failed, "{label}");
        assert_eq!(
            public_answer(&job.failure.unwrap().error()),
            expected,
            "{label}"
        );
        let dest_id = dest(&source, "forked");
        assert!(dest_state(&source, &dest_id).await.is_empty(), "{label}");
        // A refusal before registration deletes the job: no residue at all,
        // and the same request can be made again.
        assert!(
            mkit_server::fork::read_job(env.store, env.shards, &dest_id)
                .await
                .unwrap()
                .is_none(),
            "{label}"
        );
        let counter = source
            .store
            .inner
            .get(
                &source.shards.coordinator(&dest_id.namespace),
                &keys::repo_storage(&dest_id.name),
            )
            .await
            .unwrap();
        assert!(counter.is_none(), "{label}: nothing registered or counted");
    }
}

#[tokio::test]
async fn a_takedown_during_activation_withholds_clearance_without_changing_acceptance() {
    use mkit_server::fork::ForkError;
    let source = Source::build_with("source", 6, denial).await;
    let fork_env = env(&source);
    let id = dest(&source, "forked");
    let settle = settlement::admit(&source, &id).await;
    mkit_server::fork::start(&fork_env, &spec(&source, "forked"), Some(settle))
        .await
        .unwrap();
    stop_at_fork_phase(&source, &fork_env, &id, Phase::Publish).await;
    let accepted = job_of(&source, &id).await.accepted.unwrap();
    let outcome = settlement::outcome(&source, &id).await;
    let blocked = blob(2, 8).0;
    // The block lands after the live proof but before the membership commit.
    *source.store.trigger.lock().unwrap() = Some(("pm", block_hook(&source, blocked)));
    assert!(matches!(
        drive(&fork_env, &id).await,
        Err(ForkError::Unavailable("fork clearance pending"))
    ));
    let pending = job_of(&source, &id).await;
    assert_eq!(pending.phase, Phase::Publish);
    assert_eq!(pending.accepted, Some(accepted.clone()));
    assert!(pending.result.is_none());
    assert_eq!(settlement::outcome(&source, &id).await, outcome);
    assert!(member(&source, &id, source.packmap).await.is_none());
    // A later clearance driver resumes the same acceptance after denial ends.
    ContentIndex::new(source.store.inner.clone())
        .unblock(&blocked, u64::try_from(source.clock.now_ms()).unwrap())
        .await
        .unwrap();
    let done = drive(&fork_env, &id).await.unwrap();
    assert_eq!(done.phase, Phase::Done);
    assert_eq!(done.result, Some(accepted));
    assert_eq!(settlement::outcome(&source, &id).await, outcome);
}

#[tokio::test]
async fn storage_is_counted_once_with_one_change_outcome() {
    use mkit_server::store::adapter_spi::codec::{self, ReservationV1};
    let (source, job) = forked(30).await;
    let dest_id = dest(&source, "forked");
    let coordinator = source.shards.coordinator(&dest_id.namespace);
    let counter = source
        .store
        .inner
        .get(&coordinator, &keys::repo_storage(&dest_id.name))
        .await
        .unwrap()
        .unwrap();
    let counter = codec::decode_repo_storage(&counter).unwrap();
    let result = job.result.unwrap();
    assert_eq!(counter.stored_bytes, result.pack_bytes);
    assert_eq!(counter.version, 1);
    let (start, end) = keys::class_range(keys::TAG_RESERVATION);
    let outcomes = source
        .store
        .inner
        .scan(&coordinator, &start, &end, None, 100)
        .await
        .unwrap()
        .entries;
    let changes: Vec<_> = outcomes
        .iter()
        .filter_map(|(_, v)| match codec::decode_reservation(v).unwrap() {
            ReservationV1::RepoStorageChanged {
                repository,
                stored_bytes,
                ..
            } if repository.ends_with("/forked") => Some(stored_bytes),
            _ => None,
        })
        .collect();
    assert_eq!(changes, vec![result.pack_bytes]);
    // Driving a finished job again changes nothing.
    let again = mkit_server::fork::step(&env(&source), &dest_id, &SliceBudget::new(600))
        .await
        .unwrap();
    assert!(!again.progressed);
}

#[tokio::test]
async fn holder_copy_uses_the_deployments_denial_mode() {
    for denial in [false, true] {
        let source = Source::build("source", 2).await;
        let index = ContentIndex::new(source.store.inner.clone());
        let from = Holder::new(source.repo.namespace.clone(), source.repo.name.clone());
        let object = blob(1, 8).0;
        index
            .add_holder(
                &object,
                &from,
                &[7; 32],
                None,
                u64::try_from(source.clock.now_ms()).unwrap(),
            )
            .await
            .unwrap();
        let mut env = env(&source);
        env.takedown_denial = denial;
        env.extract_min_bytes = Some(1);
        source
            .store
            .denial_reads
            .store(0, std::sync::atomic::Ordering::SeqCst);
        mkit_server::fork::start(&env, &spec(&source, "forked"), None)
            .await
            .unwrap();
        let dest_id = dest(&source, "forked");
        let mut finished = false;
        for _ in 0..50 {
            let job = mkit_server::fork::step(&env, &dest_id, &SliceBudget::new(600))
                .await
                .unwrap()
                .job;
            if job.finished() {
                assert_eq!(job.phase, Phase::Done, "{:?}", job.failure);
                finished = true;
                break;
            }
        }
        assert!(finished);
        let to = Holder::new(dest_id.namespace.clone(), dest_id.name.clone());
        assert!(index.holder_record(&object, &to).await.unwrap().is_some());
        let reads = source
            .store
            .denial_reads
            .load(std::sync::atomic::Ordering::SeqCst);
        if denial {
            assert!(reads > 0);
        } else {
            assert_eq!(reads, 0, "fork keeps holder writes without denial reads");
        }
    }
}

#[tokio::test]
async fn holders_are_copied_for_extracted_objects_the_source_holds() {
    let source = Source::build("source", 6).await;
    let now = u64::try_from(source.clock.now_ms()).unwrap();
    let index = ContentIndex::new(source.store.inner.clone());
    let from = Holder::new(source.repo.namespace.clone(), source.repo.name.clone());
    for n in [1, 3] {
        index
            .add_holder(&blob(n, 8).0, &from, &[7; 32], None, now)
            .await
            .unwrap();
    }
    let mut env = env(&source);
    env.extract_min_bytes = Some(1);
    mkit_server::fork::start(&env, &spec(&source, "forked"), None)
        .await
        .unwrap();
    let dest_id = dest(&source, "forked");
    for _ in 0..50 {
        if mkit_server::fork::step(&env, &dest_id, &SliceBudget::new(600))
            .await
            .unwrap()
            .job
            .finished()
        {
            break;
        }
    }
    let to = Holder::new(dest_id.namespace.clone(), dest_id.name.clone());
    for n in 0..6 {
        let held = index
            .holder_record(&blob(n, 8).0, &to)
            .await
            .unwrap()
            .is_some();
        assert_eq!(held, n == 1 || n == 3, "blob {n}");
    }
    // A blocked extracted object refuses the fork instead of being held.
    let source = Source::build("source", 6).await;
    let index = ContentIndex::new(source.store.inner.clone());
    index
        .add_holder(&blob(1, 8).0, &from, &[7; 32], None, now)
        .await
        .unwrap();
    block(&source, blob(1, 8).0).await;
    let mut env = self::env(&source);
    env.extract_min_bytes = Some(1);
    mkit_server::fork::start(&env, &spec(&source, "forked"), None)
        .await
        .unwrap();
    for _ in 0..50 {
        let job = mkit_server::fork::step(&env, &dest_id, &SliceBudget::new(600))
            .await
            .unwrap()
            .job;
        if job.finished() {
            assert_eq!(job.phase, Phase::Failed);
            break;
        }
    }
}

#[tokio::test]
async fn a_takedown_after_the_fork_still_stops_the_remix_advance() {
    // Skipping a cleared tree waives the structural walk only: an object
    // under it, or its pack, still fails the advance-time denial proof of the
    // dependency packs the packmap chain lists.
    for victim in ["blob", "tree", "commit", "data pack"] {
        // The same two takedowns stop a push in an ordinary repository; a
        // packmap node is not a takedown subject there either.
        let (source, _) = forked(8).await;
        let target = match victim {
            "blob" => blob(5, 8).0,
            "tree" => source.tree,
            "commit" => source.head,
            _ => source.pack,
        };
        block(&source, target).await;
        let mut remix = source.at("forked");
        let (bytes, head) = commit_pack(source.tree, vec![], b"remix");
        let pack = mkit_core::hash::hash(&bytes);
        let refused = remix
            .try_push(bytes, head, Some(source.packmap), &[pack])
            .await;
        assert_eq!(refused.unwrap_err(), "object blocked", "{victim}");
        assert!(
            remix.published("refs/heads/main").await.is_none(),
            "{victim}"
        );
    }
}

#[tokio::test]
async fn the_destination_chain_serves_the_inherited_packs_without_verification_state() {
    use mkit_core::protocol::PackKey;
    use mkit_server::BeginUploadResult;
    let (source, _) = forked(8).await;
    let mut remix = source.at("forked");
    // Before any ref exists the inherited pack is a member.
    let n = remix.next_nonce();
    let auth = remix.authenticate(mkit_server::Procedure::PackExists, n);
    assert!(
        remix
            .pipe
            .pack_exists(&auth, PackKey(source.pack))
            .await
            .unwrap()
    );
    // `BeginUpload` decides presence from the consuming ref shard's own
    // membership rows, as it does for a pack another ref consumed: a client
    // that re-sends an inherited pack gets an ordinary ticket.
    let n = remix.next_nonce();
    let auth = remix.authenticate(mkit_server::Procedure::BeginUpload, n);
    assert!(matches!(
        remix
            .pipe
            .begin_upload(&auth, "refs/heads/main", &source.pack, 1)
            .await
            .unwrap(),
        BeginUploadResult::Ticket { .. }
    ));
    // No verification state was copied or written.
    let (start, end) = keys::class_range(keys::TAG_VERIFICATION);
    for p in source.shards.object_index_partitions(&remix.repo) {
        let rows = source
            .store
            .inner
            .scan(&p, &start, &end, None, 10)
            .await
            .unwrap();
        assert_eq!(
            rows.entries,
            [] as [(mkit_server::Key, mkit_server::Value); 0]
        );
    }
    let (bytes, head) = commit_pack(source.tree, vec![], b"remix");
    let pack = mkit_core::hash::hash(&bytes);
    let map = remix.push(bytes, head, Some(source.packmap), &[pack]).await;
    // A clone walks the packmap chain: new node, the inherited head, and the
    // inherited data pack it lists.
    let node = |id: Hash| {
        let blobs = source.blobs.clone();
        async move {
            use mkit_server::BlobStore;
            let body = blobs.get(&BlobKey::pack(id), None).await.unwrap().unwrap();
            let mkit_server::BlobBody::Bytes(bytes) = body else {
                panic!("stream")
            };
            mkit_core::transfer::decode_packlist(&bytes).unwrap()
        }
    };
    let top = node(map).await;
    assert_eq!(top.prev, Some(source.packmap));
    assert_eq!(top.packs, vec![pack]);
    let inherited = node(source.packmap).await;
    assert_eq!(inherited.packs, vec![source.pack]);
    // The inherited pack downloads through the destination.
    let n = remix.next_nonce();
    let auth = remix.authenticate(mkit_server::Procedure::DownloadPack, n);
    let mut stream = remix
        .pipe
        .download(&auth, PackKey(source.pack))
        .await
        .unwrap();
    assert!(stream.chunks.next().await.is_some());
    // Reusing an inherited pack in an ordinary push works as well: the walk
    // is the full one, since this chain does not name the inherited head.
    let mut reuse = source.at("forked");
    let (bytes, head) = commit_pack(source.tree, vec![], b"reuse");
    let pack = mkit_core::hash::hash(&bytes);
    reuse
        .push_to(
            "refs/heads/reuse",
            bytes,
            head,
            None,
            &[source.pack, pack],
            true,
        )
        .await;
}

mod settlement {
    use super::*;
    use mkit_server::Batch;
    use mkit_server::fork::{ChargeV1, ReplayV1, SettleV1};
    use mkit_server::store::adapter_spi::{
        codec::{self, PendingOp, ReservationV1, StoredProcedure},
        outbox::OutboxBuilder,
    };

    pub(super) const RID: &str = "fork-reservation-1";

    pub(super) async fn admit(source: &Source, dest: &RepoId) -> SettleV1 {
        let now = u64::try_from(source.clock.now_ms()).unwrap();
        let repository = format!("{}/{}", dest.namespace.as_str(), dest.name.as_str());
        let pending = ReservationV1::pending(
            repository.clone(),
            now,
            now + mkit_server::fork::JOB_TTL_MS + 60_000,
            PendingOp::Write,
            StoredProcedure::Fork,
        );
        let mut builder = OutboxBuilder::new(None, None).unwrap();
        builder.pending(RID, None, &pending);
        let mut batch = Batch::new();
        builder
            .try_finish(&mut batch.preconditions, &mut batch.writes)
            .unwrap();
        assert_eq!(
            source
                .store
                .inner
                .apply(&source.shards.coordinator(&dest.namespace), batch)
                .await
                .unwrap(),
            mkit_server::BatchOutcome::Committed
        );
        SettleV1 {
            rid: RID.into(),
            pending: codec::encode_reservation(&pending).as_bytes().to_vec(),
            repository,
            replay: Some(ReplayV1 {
                scope: [3; 32],
                fingerprint: [4; 32],
                expires_at_ms: i64::try_from(now).unwrap() + 300_000,
            }),
            charges: vec![ChargeV1 {
                scope: mkit_server::quota::QuotaScope::for_signer(&dest.namespace, &[1; 32])
                    .as_str()
                    .to_owned(),
                bytes: 0,
                window_ms: 3_600_000,
                max_ops: 10,
                max_bytes: 1 << 30,
            }],
            namespace_cap: None,
            declared_bytes: 1 << 40,
        }
    }

    pub(super) async fn outcome(source: &Source, dest: &RepoId) -> ReservationV1 {
        let raw = source
            .store
            .inner
            .get(
                &source.shards.coordinator(&dest.namespace),
                &keys::reservation(RID).unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        codec::decode_reservation(&raw).unwrap()
    }
}

#[tokio::test]
async fn acceptance_commits_outcome_and_replay_before_clearance_and_never_resettles() {
    use mkit_server::store::adapter_spi::codec::{self, ReservationV1, StoredProcedure};
    let source = Source::build("source", 6).await;
    let env = env(&source);
    let dest_id = dest(&source, "forked");
    let settle = settlement::admit(&source, &dest_id).await;
    mkit_server::fork::start(&env, &spec(&source, "forked"), Some(settle))
        .await
        .unwrap();
    // Stop before acceptance, then lose each advancing reply until the saved
    // result and terminal settlement exist while membership is still absent.
    stop_at_fork_phase(&source, &env, &dest_id, Phase::Accept).await;
    assert!(matches!(
        settlement::outcome(&source, &dest_id).await,
        ReservationV1::Pending { .. }
    ));
    stop_at_fork_phase(&source, &env, &dest_id, Phase::Publish).await;
    let accepted = job_of(&source, &dest_id).await;
    assert!(accepted.result.is_none());
    assert!(accepted.accepted.is_some());
    for pack in accepted.packs.iter().map(|pack| pack.id) {
        assert!(member(&source, &dest_id, pack).await.is_none());
    }
    let coordinator = source.shards.coordinator(&dest_id.namespace);
    let replay_key = keys::replay(&[3; 32]);
    let scope = mkit_server::quota::QuotaScope::for_signer(&dest_id.namespace, &[1; 32]);
    let outcome_at_acceptance = settlement::outcome(&source, &dest_id).await;
    let ReservationV1::Committed {
        procedure,
        bytes_stored,
        refs,
        ..
    } = settlement::outcome(&source, &dest_id).await
    else {
        panic!("expected a committed outcome")
    };
    assert_eq!(procedure, StoredProcedure::Fork);
    assert_eq!(bytes_stored, accepted.accepted.clone().unwrap().pack_bytes);
    assert_eq!(refs, [] as [mkit_server::store::OutcomeRef; 0]);
    let replay = source
        .store
        .inner
        .get(&coordinator, &replay_key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        codec::decode_replay_record(&replay).unwrap().state,
        mkit_server::ReplayState::Committed(mkit_server::StoredResult::Fork)
    );
    let quota = source
        .store
        .inner
        .get(&coordinator, &keys::quota(&scope))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(codec::decode_quota_state(&quota).unwrap().ops, 1);
    let job = run(&source, "forked").await;
    assert_eq!(job.phase, Phase::Done);
    assert_eq!(job.result, accepted.accepted);
    assert_eq!(
        settlement::outcome(&source, &dest_id).await,
        outcome_at_acceptance
    );
    assert_eq!(
        source
            .store
            .inner
            .get(&coordinator, &replay_key)
            .await
            .unwrap(),
        Some(replay)
    );
    assert_eq!(
        source
            .store
            .inner
            .get(&coordinator, &keys::quota(&scope))
            .await
            .unwrap(),
        Some(quota)
    );
}

#[tokio::test]
async fn a_refused_expired_or_orphaned_fork_aborts_its_reservation_and_holds_nothing() {
    use mkit_server::store::adapter_spi::codec::{AbortReason, ReservationV1};
    // A terminal refusal.
    let source = Source::build_with("source", 6, denial).await;
    block(&source, blob(1, 8).0).await;
    let dest_id = dest(&source, "forked");
    let settle = settlement::admit(&source, &dest_id).await;
    mkit_server::fork::start(&env(&source), &spec(&source, "forked"), Some(settle))
        .await
        .unwrap();
    assert_eq!(run(&source, "forked").await.phase, Phase::Failed);
    let ReservationV1::Aborted { detail, reason, .. } =
        settlement::outcome(&source, &dest_id).await
    else {
        panic!("a refusal aborts the reservation")
    };
    assert_eq!(
        (reason, detail.as_str()),
        (AbortReason::Unspecified, "source not found")
    );
    // The reservation outlives the apply window but not the job: past the
    // job's expiry the next step aborts it and writes no membership.
    let source = Source::build("source", 6).await;
    let settle = settlement::admit(&source, &dest_id).await;
    mkit_server::fork::start(&env(&source), &spec(&source, "forked"), Some(settle))
        .await
        .unwrap();
    source
        .clock
        .advance(i64::try_from(mkit_server::fork::JOB_TTL_MS).unwrap() + 1);
    let job = run(&source, "forked").await;
    assert_eq!(job.phase, Phase::Failed);
    let ReservationV1::Aborted { detail, .. } = settlement::outcome(&source, &dest_id).await else {
        panic!("expiry aborts the reservation")
    };
    assert_eq!(detail, "fork expired");
    assert!(dest_state(&source, &dest_id).await.is_empty());
    // A reservation settled elsewhere (reconcile) stops the job at its next slice.
    let source = Source::build("source", 6).await;
    let settle = settlement::admit(&source, &dest_id).await;
    mkit_server::fork::start(
        &env(&source),
        &spec(&source, "forked"),
        Some(settle.clone()),
    )
    .await
    .unwrap();
    let coordinator = source.shards.coordinator(&dest_id.namespace);
    let key = keys::reservation(settlement::RID).unwrap();
    let rows = source
        .store
        .inner
        .get_many(
            &coordinator,
            &[keys::outbox_sequence(), keys::outcome_backlog()],
        )
        .await
        .unwrap();
    let mut builder = mkit_server::store::adapter_spi::outbox::OutboxBuilder::new(
        rows[0].as_ref(),
        rows[1].as_ref(),
    )
    .unwrap();
    builder.outcome(
        settlement::RID,
        &mkit_server::Value::new(settle.pending.clone()),
        mkit_server::store::adapter_spi::outbox::Terminal::new(ReservationV1::aborted(
            settle.repository.clone(),
            1,
            AbortReason::Abandoned,
            String::new(),
            mkit_server::store::adapter_spi::codec::StoredProcedure::Fork,
        ))
        .unwrap(),
    );
    let mut batch = mkit_server::Batch::new();
    builder
        .try_finish(&mut batch.preconditions, &mut batch.writes)
        .unwrap();
    source.store.inner.apply(&coordinator, batch).await.unwrap();
    let _ = key;
    let job = run(&source, "forked").await;
    assert_eq!(job.phase, Phase::Failed);
    assert!(dest_state(&source, &dest_id).await.is_empty());
}

#[tokio::test]
async fn the_kind_16_timer_finishes_a_fork_unattended() {
    use mkit_server::fork::ForkTimer;
    use mkit_server::timers::{TickBudget, TimerRegistry, run_due};
    let source = Source::build("source", 30).await;
    let env = env(&source);
    mkit_server::fork::start(&env, &spec(&source, "forked"), None)
        .await
        .unwrap();
    let registry = TimerRegistry::new().register(ForkTimer {
        publication_policy: None,
        store: source.store.clone(),
        shards: source.shards.clone(),
        clock: source.clock.clone(),
        takedown_denial: true,
        extract_min_bytes: None,
    });
    let coordinator = source.shards.coordinator(&source.repo.namespace);
    let dest_id = dest(&source, "forked");
    for _ in 0..50 {
        let now = u64::try_from(source.clock.now_ms()).unwrap();
        let report = run_due(
            &source.store,
            &coordinator,
            &registry,
            source.clock.as_ref(),
            now,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        let job = mkit_server::fork::read_job(env.store, env.shards, &dest_id)
            .await
            .unwrap()
            .unwrap()
            .0;
        if job.finished() {
            assert_eq!(job.phase, Phase::Done);
            // The finished job's timer is gone.
            let (start, end) = keys::class_range(keys::TAG_TIMER);
            let left = source
                .store
                .inner
                .scan(&coordinator, &start, &end, None, 100)
                .await
                .unwrap();
            assert!(left.entries.iter().all(|(k, _)| k.as_bytes()[10] != 16));
            return;
        }
        source
            .clock
            .set(i64::try_from(report.next_wake_ms.unwrap_or(now + 1_000)).unwrap());
    }
    panic!("the timer did not finish the fork");
}

#[tokio::test]
async fn the_per_pack_proof_costs_the_same_at_every_size() {
    use mkit_server::takedown::denial::require_pack_clear_sealed;
    let mut costs = Vec::new();
    for files in [10_u32, 1_000] {
        let source = Source::build_with("source", files, denial).await;
        let before = source.store.calls();
        require_pack_clear_sealed(
            &source.store,
            source.shards.as_ref(),
            &source.repo,
            &source.pack,
        )
        .await
        .unwrap();
        costs.push(source.store.calls() - before);
    }
    assert_eq!(costs[0], costs[1], "{costs:?}");
    assert!(costs[0] < 100, "{costs:?}");
}

#[tokio::test]
async fn forks_more_rows_than_one_advance_can_publish_and_refuses_past_the_limit() {
    // 4,600 rows, above the 4,096 items one advance can retain, from a closure of 102.
    let source = Source::build_full("source", 100, 4_500, denial).await;
    mkit_server::fork::start(&env(&source), &spec(&source, "forked"), None)
        .await
        .unwrap();
    let job = run(&source, "forked").await;
    assert_eq!(job.phase, Phase::Done, "{:?}", job.failure);
    assert_eq!(job.result.unwrap().object_count, 4_602);
    // A lower limit refuses uniformly and leaves nothing.
    let mut tight = env(&source);
    tight.limits = ForkLimits {
        max_objects: 4_601,
        ..ForkLimits::default()
    };
    let mut again = spec(&source, "other");
    again.dest = dest(&source, "other");
    mkit_server::fork::start(&tight, &again, None)
        .await
        .unwrap();
    let dest_id = dest(&source, "other");
    let job = loop {
        let report = mkit_server::fork::step(&tight, &dest_id, &SliceBudget::new(600))
            .await
            .unwrap();
        if report.job.finished() {
            break report.job;
        }
    };
    assert_eq!(job.phase, Phase::Failed);
    let error = job.failure.unwrap().error();
    assert_eq!(
        (error.code(), error.public_message()),
        (mkit_server::Code::ResourceExhausted, "fork too large")
    );
    assert!(dest_state(&source, &dest_id).await.is_empty());
}

#[tokio::test]
async fn a_copy_longer_than_one_apply_window_still_makes_progress() {
    // Every call costs 200 ms, so the copy alone spans several 10 s apply
    // windows; each write must carry its own deadline.
    let source = Source::build_full("source", 100, 4_500, denial).await;
    source
        .store
        .latency_ms
        .store(200, std::sync::atomic::Ordering::SeqCst);
    mkit_server::fork::start(&env(&source), &spec(&source, "forked"), None)
        .await
        .unwrap();
    let job = run(&source, "forked").await;
    assert_eq!(job.phase, Phase::Done, "{:?}", job.failure);
}

#[tokio::test]
async fn a_refusal_before_registration_can_be_retried() {
    let source = Source::build("source", 10).await;
    let mut tight = env(&source);
    tight.limits = ForkLimits {
        max_packs: 1,
        ..ForkLimits::default()
    };
    let dest_id = dest(&source, "forked");
    mkit_server::fork::start(&tight, &spec(&source, "forked"), None)
        .await
        .unwrap();
    let job = loop {
        let report = mkit_server::fork::step(&tight, &dest_id, &SliceBudget::new(600))
            .await
            .unwrap();
        if report.job.finished() {
            break report.job;
        }
    };
    assert_eq!(job.phase, Phase::Failed);
    assert_eq!(
        job.failure.unwrap().error().public_message(),
        "fork too large"
    );
    assert!(
        mkit_server::fork::read_job(tight.store, tight.shards, &dest_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(dest_state(&source, &dest_id).await.is_empty());
    // The same request, under the real limits, now succeeds.
    mkit_server::fork::start(&env(&source), &spec(&source, "forked"), None)
        .await
        .unwrap();
    assert_eq!(run(&source, "forked").await.phase, Phase::Done);
}

#[tokio::test]
async fn a_missing_sealed_inventory_is_the_uniform_not_found() {
    let source = Source::build_with("source", 6, denial).await;
    let shard = mkit_server::store::content_shard(&source.pack);
    let page = source
        .store
        .inner
        .scan(
            &shard,
            &mkit_server::Key::new(vec![]),
            &mkit_server::Key::new(vec![255]),
            None,
            100_000,
        )
        .await
        .unwrap();
    let head = page
        .entries
        .iter()
        .map(|(k, _)| k.clone())
        .find(|k| {
            k.as_bytes().ends_with(b"\0inventory-head")
                && k.as_bytes().windows(32).any(|w| w == source.pack)
        })
        .unwrap();
    source
        .store
        .inner
        .apply(&shard, mkit_server::Batch::new().delete(head))
        .await
        .unwrap();
    mkit_server::fork::start(&env(&source), &spec(&source, "forked"), None)
        .await
        .unwrap();
    let job = run(&source, "forked").await;
    assert_eq!(job.phase, Phase::Failed);
    assert_eq!(
        job.failure.unwrap().error().public_message(),
        "source not found"
    );
}

#[tokio::test]
async fn publish_never_overwrites_a_membership_it_did_not_write() {
    use mkit_server::BlobKey;
    // A hold a takedown set on a destination row is not replaced by the
    // fork's replay or by a racing writer.
    let source = Source::build("source", 6).await;
    let dest_id = dest(&source, "forked");
    let env = env(&source);
    mkit_server::fork::start(&env, &spec(&source, "forked"), None)
        .await
        .unwrap();
    let held = Witness {
        generation: 0,
        sequence: 0,
        published: true,
        held: true,
        boundary: false,
    }
    .encode();
    let target = source
        .shards
        .membership(&dest_id, &BlobKey::pack(source.pack));
    source
        .store
        .inner
        .apply(
            &target,
            mkit_server::Batch::new()
                .put(keys::membership(&dest_id.name, &source.pack), held.clone())
                .put(
                    keys::published_member(&dest_id.name, &source.pack),
                    held.clone(),
                ),
        )
        .await
        .unwrap();
    let job = run(&source, "forked").await;
    assert_eq!(job.phase, Phase::Failed);
    assert_eq!(
        job.failure.unwrap().error().public_message(),
        "destination not empty"
    );
    let row = source
        .store
        .inner
        .get(&target, &keys::membership(&dest_id.name, &source.pack))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row, held);
}

#[tokio::test]
async fn a_ref_created_during_the_job_stops_it_before_registration() {
    let source = Source::build("source", 6).await;
    let dest_id = dest(&source, "forked");
    let env = env(&source);
    mkit_server::fork::start(&env, &spec(&source, "forked"), None)
        .await
        .unwrap();
    let (key, partition) = (
        keys::ref_index_key(&dest_id.name, "refs/heads/main"),
        source.shards.ref_index(&dest_id, "refs/heads/main"),
    );
    source
        .store
        .inner
        .apply(
            &partition,
            mkit_server::Batch::new().put(key, mkit_server::Value::new(vec![1; 32])),
        )
        .await
        .unwrap();
    let job = run(&source, "forked").await;
    assert_eq!(job.phase, Phase::Failed);
    assert!(dest_state(&source, &dest_id).await.is_empty());
    assert!(
        source
            .store
            .inner
            .get(
                &source.shards.coordinator(&dest_id.namespace),
                &keys::repo_record(&dest_id.name)
            )
            .await
            .unwrap()
            .is_none(),
        "the destination was never registered"
    );
}

#[tokio::test]
async fn a_copy_of_many_holders_cut_by_small_slices_matches_one_slice() {
    let files = 1_100_u32;
    let source = Source::build("source", files).await;
    let index = ContentIndex::new(source.store.inner.clone());
    let from = Holder::new(source.repo.namespace.clone(), source.repo.name.clone());
    let objects: Vec<Hash> = (0..files).map(|n| blob(n, 8).0).collect();
    for object in &objects {
        index
            .add_holder(
                object,
                &from,
                &[7; 32],
                None,
                u64::try_from(source.clock.now_ms()).unwrap(),
            )
            .await
            .unwrap();
    }
    let mut env = env(&source);
    env.extract_min_bytes = Some(1);
    let mut finished = Vec::new();
    let mut marked = false;
    for (name, calls) in [("forked", 600), ("forked-small", 330)] {
        let spec = spec(&source, name);
        mkit_server::fork::start(&env, &spec, None).await.unwrap();
        let dest_id = dest(&source, name);
        let mut slices = 0;
        let job = loop {
            slices += 1;
            let report = mkit_server::fork::step(&env, &dest_id, &SliceBudget::new(calls))
                .await
                .unwrap();
            assert!(slices < 500, "{:?}", report.job.phase);
            // A slice that ends inside a page leaves the holder mark behind.
            marked |= report.job.lanes.iter().any(|lane| lane.held.is_some());
            if report.job.finished() {
                break report.job;
            }
        };
        assert_eq!(job.phase, Phase::Done, "{:?}", job.failure);
        let to = Holder::new(dest_id.namespace.clone(), dest_id.name.clone());
        for object in &objects {
            assert!(index.holder_record(object, &to).await.unwrap().is_some());
        }
        finished.push((job.result.unwrap().object_count, slices));
    }
    assert_eq!(finished[0].0, finished[1].0);
    assert!(finished[1].1 > finished[0].1, "{finished:?}");
    assert!(marked, "no slice ended inside a page of holders");
}

#[tokio::test]
async fn a_fork_spanning_many_small_slices_ends_where_one_big_slice_does() {
    let mut source = Source::build_with("source", 4, denial).await;
    // History: 24 more commits, each a new tree and two more packs for the
    // chain, so planning, the tree pass, the walk and the copy all need
    // several slices of 400 calls.
    let mut prev_map = source.packmap;
    let mut parent = source.head;
    for n in 0..24_u32 {
        let (bytes, head, _) = tree_pack(3, 8, 1_000 + n * 10, vec![parent], b"more");
        let pack = mkit_core::hash::hash(&bytes);
        prev_map = source.push(bytes, head, Some(prev_map), &[pack]).await;
        parent = head;
    }
    let mut spec_big = spec(&source, "forked");
    spec_big.expected_tip = parent;
    let mut spec_small = spec_big.clone();
    spec_small.dest = dest(&source, "forked-small");
    let env = env(&source);
    mkit_server::fork::start(&env, &spec_big, None)
        .await
        .unwrap();
    mkit_server::fork::start(&env, &spec_small, None)
        .await
        .unwrap();
    let big = run(&source, "forked").await;
    assert_eq!(big.phase, Phase::Done, "{:?}", big.failure);
    let small_id = dest(&source, "forked-small");
    let mut steps = 0;
    let small = loop {
        steps += 1;
        assert!(steps < 500);
        let report = mkit_server::fork::step(&env, &small_id, &SliceBudget::new(330))
            .await
            .unwrap();
        if report.job.finished() {
            break report.job;
        }
    };
    assert_eq!(small.phase, Phase::Done, "{:?}", small.failure);
    assert!(steps > 5, "{steps} slices");
    assert_eq!(
        small.result.as_ref().unwrap().pack_count,
        big.result.as_ref().unwrap().pack_count
    );
    assert_eq!(
        small.result.unwrap().object_count,
        big.result.unwrap().object_count
    );
    // 25 commits and 25 trees are cleared.
    let read = |id: RepoId| {
        let store = source.store.inner.clone();
        let coordinator = source.shards.coordinator(&id.namespace);
        async move {
            store
                .get(&coordinator, &keys::fork_set(&id.name, 0))
                .await
                .unwrap()
                .unwrap()
        }
    };
    assert_eq!(read(small_id).await, read(dest(&source, "forked")).await);
    assert_eq!(
        read(dest(&source, "forked")).await.as_bytes().len(),
        50 * 32
    );
}

#[tokio::test]
async fn the_per_pack_proof_with_active_descriptors_costs_the_same_at_every_size() {
    use mkit_server::takedown::denial::require_pack_clear_sealed;
    let mut costs = Vec::new();
    for files in [10_u32, 1_000] {
        let source = Source::build_with("source", files, denial).await;
        // An active takedown of something unrelated.
        block(&source, [9; 32]).await;
        let before = source.store.calls();
        require_pack_clear_sealed(
            &source.store,
            source.shards.as_ref(),
            &source.repo,
            &source.pack,
        )
        .await
        .unwrap();
        costs.push(source.store.calls() - before);
    }
    assert_eq!(costs[0], costs[1], "{costs:?}");
    assert!(costs[0] < 100, "{costs:?}");
}

#[tokio::test]
async fn without_pack_level_denial_the_cleared_set_is_not_honored() {
    // Denial off still walks the inherited closure instead of relying on the
    // cleared set; the canonical walk requires membership but ignores blocks.
    let source = Source::build_policy("source", 20, 0, true, |cfg| cfg).await;
    let mut env = env(&source);
    env.takedown_denial = false;
    mkit_server::fork::start(&env, &spec(&source, "forked"), None)
        .await
        .unwrap();
    let dest_id = dest(&source, "forked");
    for _ in 0..50 {
        if mkit_server::fork::step(&env, &dest_id, &SliceBudget::new(600))
            .await
            .unwrap()
            .job
            .finished()
        {
            break;
        }
    }
    // Block rows are ignored while denial is disabled.
    block(&source, blob(7, 8).0).await;
    let mut remix = source.at("forked");
    let (bytes, head) = commit_pack(source.tree, vec![], b"remix");
    let pack = mkit_core::hash::hash(&bytes);
    let published = remix
        .try_push(bytes, head, Some(source.packmap), &[pack])
        .await
        .unwrap();
    // Removing a cleared inherited object's index must still close the next
    // publication: the cleared set cannot bypass ordinary member lookup.
    let id = blob(7, 8).0;
    let partition = source.shards.object_index(&dest_id, &id);
    let (start, end) = keys::object_index_range(&dest_id.name, &id);
    let rows = source
        .store
        .inner
        .scan(&partition, &start, &end, None, 100)
        .await
        .unwrap();
    assert_ne!(
        rows.entries,
        [] as [(mkit_server::Key, mkit_server::Value); 0]
    );
    let mut batch = mkit_server::Batch::new();
    for (key, _) in rows.entries {
        batch = batch.delete(key);
    }
    source.store.inner.apply(&partition, batch).await.unwrap();
    let (bytes, next) = commit_pack(source.tree, vec![head], b"missing inherited member");
    let pack = mkit_core::hash::hash(&bytes);
    assert_eq!(
        remix
            .try_push(bytes, next, Some(published), &[pack])
            .await
            .unwrap_err(),
        "repository membership not yet visible"
    );
}

async fn fork_timers(store: &MemoryKv, coordinator: &mkit_server::Partition) -> usize {
    let (start, end) = keys::class_range(keys::TAG_TIMER);
    store
        .scan(coordinator, &start, &end, None, 100)
        .await
        .unwrap()
        .entries
        .into_iter()
        .filter(|(k, _)| k.as_bytes()[10] == 16)
        .count()
}

#[tokio::test]
async fn a_refused_start_leaves_no_timer_and_a_stale_timer_ends() {
    use mkit_server::fork::ForkTimer;
    use mkit_server::timers::{TickBudget, TimerRegistry, run_due};
    let source = Source::build("source", 6).await;
    let mut tight = env(&source);
    tight.limits = ForkLimits {
        max_packs: 1,
        ..ForkLimits::default()
    };
    mkit_server::fork::start(&tight, &spec(&source, "forked"), None)
        .await
        .unwrap();
    let dest_id = dest(&source, "forked");
    mkit_server::fork::step(&tight, &dest_id, &SliceBudget::new(600))
        .await
        .unwrap();
    let coordinator = source.shards.coordinator(&dest_id.namespace);
    assert_eq!(
        fork_timers(source.store.inner.as_ref(), &coordinator).await,
        1,
        "the start's timer is still queued"
    );
    let registry = TimerRegistry::new().register(ForkTimer {
        publication_policy: None,
        store: source.store.clone(),
        shards: source.shards.clone(),
        clock: source.clock.clone(),
        takedown_denial: true,
        extract_min_bytes: None,
    });
    run_due(
        &source.store,
        &coordinator,
        &registry,
        source.clock.as_ref(),
        u64::try_from(source.clock.now_ms()).unwrap(),
        &TickBudget::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        fork_timers(source.store.inner.as_ref(), &coordinator).await,
        0,
        "the timer ended with the job"
    );
}

#[tokio::test]
async fn many_active_takedowns_and_many_packs_still_finish_in_small_slices() {
    let mut source = Source::build_with("source", 4, denial).await;
    let mut prev_map = source.packmap;
    let mut parent = source.head;
    for n in 0..10_u32 {
        let (bytes, head, _) = tree_pack(2, 8, 2_000 + n * 10, vec![parent], b"more");
        let pack = mkit_core::hash::hash(&bytes);
        prev_map = source.push(bytes, head, Some(prev_map), &[pack]).await;
        parent = head;
    }
    for n in 0..40_u8 {
        block(&source, [200 + n; 32]).await;
    }
    let mut request = spec(&source, "forked");
    request.expected_tip = parent;
    let env = env(&source);
    mkit_server::fork::start(&env, &request, None)
        .await
        .unwrap();
    let dest_id = dest(&source, "forked");
    let mut steps = 0;
    let job = loop {
        steps += 1;
        if steps >= 2_000 {
            let j = mkit_server::fork::read_job(env.store, env.shards, &dest_id)
                .await
                .unwrap()
                .unwrap()
                .0;
            panic!(
                "the fork stalled in {:?} cursor {} of {} packs",
                j.phase,
                j.cursor,
                j.packs.len()
            );
        }
        // 40 active descriptors make one pack's proof about 260 calls: two
        // units (write, check) per pack, none lost between slices.
        let report = mkit_server::fork::step(&env, &dest_id, &SliceBudget::new(600))
            .await
            .unwrap();
        if report.job.finished() {
            break report.job;
        }
    };
    assert_eq!(job.phase, Phase::Done, "{:?}", job.failure);
    assert!(steps > 20, "{steps}");
}

#[tokio::test]
async fn working_sets_past_their_limit_are_fork_too_large() {
    let mut source = Source::build_with("source", 3, denial).await;
    let mut prev_map = source.packmap;
    let mut parent = source.head;
    for n in 0..6_u32 {
        let (bytes, head, _) = tree_pack(2, 8, 3_000 + n * 10, vec![parent], b"more");
        let pack = mkit_core::hash::hash(&bytes);
        prev_map = source.push(bytes, head, Some(prev_map), &[pack]).await;
        parent = head;
    }
    let mut tight = env(&source);
    tight.limits = ForkLimits {
        max_set_ids: 5,
        ..ForkLimits::default()
    };
    let mut request = spec(&source, "forked");
    request.expected_tip = parent;
    mkit_server::fork::start(&tight, &request, None)
        .await
        .unwrap();
    let dest_id = dest(&source, "forked");
    let job = loop {
        let report = mkit_server::fork::step(&tight, &dest_id, &SliceBudget::new(600))
            .await
            .unwrap();
        if report.job.finished() {
            break report.job;
        }
    };
    assert_eq!(job.phase, Phase::Failed);
    assert_eq!(
        job.failure.unwrap().error().public_message(),
        "fork too large"
    );
    assert!(dest_state(&source, &dest_id).await.is_empty());
}

#[tokio::test]
async fn two_steppers_on_one_job_end_where_one_does() {
    let reference = {
        let source = Source::build("source", 20).await;
        mkit_server::fork::start(&env(&source), &spec(&source, "forked"), None)
            .await
            .unwrap();
        assert_eq!(run(&source, "forked").await.phase, Phase::Done);
        dest_state(&source, &dest(&source, "forked")).await
    };
    let source = Source::build("source", 20).await;
    let env = env(&source);
    mkit_server::fork::start(&env, &spec(&source, "forked"), None)
        .await
        .unwrap();
    let dest_id = dest(&source, "forked");
    for _ in 0..20 {
        let (budget_a, budget_b) = (SliceBudget::new(330), SliceBudget::new(330));
        let (a, b) = tokio::join!(
            mkit_server::fork::step(&env, &dest_id, &budget_a),
            mkit_server::fork::step(&env, &dest_id, &budget_b),
        );
        let (a, b) = (a.unwrap(), b.unwrap());
        if a.job.finished() && b.job.finished() {
            break;
        }
    }
    let job = mkit_server::fork::read_job(env.store, env.shards, &dest_id)
        .await
        .unwrap()
        .unwrap()
        .0;
    assert_eq!(job.phase, Phase::Done);
    assert_eq!(dest_state(&source, &dest_id).await, reference);
}

#[tokio::test]
async fn a_shard_map_that_cannot_list_its_index_shards_cannot_fork() {
    let source = Source::build("source", 4).await;
    let opaque = Opaque(mkit_server::pipeline::D34Shards);
    let mut env = env(&source);
    env.shards = &opaque;
    assert_eq!(
        mkit_server::fork::start(&env, &spec(&source, "forked"), None)
            .await
            .unwrap_err(),
        mkit_server::fork::ForkError::Unavailable("fork shard map")
    );
}

#[tokio::test]
async fn settlement_survives_a_crash_at_every_write() {
    use mkit_server::store::adapter_spi::codec::{self, ReservationV1};
    let (writes, quota_ops) = {
        let source = Source::build("source", 8).await;
        let dest_id = dest(&source, "forked");
        let settle = settlement::admit(&source, &dest_id).await;
        mkit_server::fork::start(&env(&source), &spec(&source, "forked"), Some(settle))
            .await
            .unwrap();
        source
            .store
            .record
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(run(&source, "forked").await.phase, Phase::Done);
        (source.store.log.lock().unwrap().len(), 1_u32)
    };
    for lost_reply in [false, true] {
        for crash_at in 1..=i64::try_from(writes).unwrap() {
            let source = Source::build("source", 8).await;
            let env = env(&source);
            let dest_id = dest(&source, "forked");
            let settle = settlement::admit(&source, &dest_id).await;
            mkit_server::fork::start(&env, &spec(&source, "forked"), Some(settle))
                .await
                .unwrap();
            source.store.crash_after(crash_at, lost_reply);
            let mut failures = 0;
            let job = loop {
                match mkit_server::fork::step(&env, &dest_id, &SliceBudget::new(600)).await {
                    Ok(report) if report.job.finished() => break report.job,
                    Ok(_) => {}
                    Err(_) => failures += 1,
                }
                assert!(failures < 4);
            };
            assert_eq!(job.phase, Phase::Done, "crash {crash_at} {lost_reply}");
            // Exactly one terminal outcome, one replay record, one charge.
            assert!(matches!(
                settlement::outcome(&source, &dest_id).await,
                ReservationV1::Committed { .. }
            ));
            let coordinator = source.shards.coordinator(&dest_id.namespace);
            let scope = mkit_server::quota::QuotaScope::for_signer(&dest_id.namespace, &[1; 32]);
            let quota = source
                .store
                .inner
                .get(&coordinator, &keys::quota(&scope))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(codec::decode_quota_state(&quota).unwrap().ops, quota_ops);
            let counter = source
                .store
                .inner
                .get(&coordinator, &keys::repo_storage(&dest_id.name))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(codec::decode_repo_storage(&counter).unwrap().version, 1);
        }
    }
}

async fn fork_with_descriptors(descriptors: u8) -> (Source, mkit_server::fork::ForkJobV1) {
    let source = Source::build_with("source", 4, denial).await;
    for n in 0..descriptors {
        block(&source, [100 + n; 32]).await;
    }
    mkit_server::fork::start(&env(&source), &spec(&source, "forked"), None)
        .await
        .unwrap();
    let job = run(&source, "forked").await;
    (source, job)
}

#[tokio::test]
async fn a_proof_that_just_fits_a_slice_forks_and_one_that_cannot_is_refused_before_registration() {
    // About 19 calls plus 6 per active descriptor: 70 descriptors cost about
    // 440, one proof per unit; 100 descriptors cost about 620, over a slice.
    let (source, job) = fork_with_descriptors(70).await;
    assert_eq!(job.phase, Phase::Done, "{:?}", job.failure);
    drop(source);
    let (source, job) = fork_with_descriptors(100).await;
    assert_eq!(job.phase, Phase::Failed);
    assert_eq!(
        job.failure.unwrap().error().public_message(),
        "fork too large"
    );
    let dest_id = dest(&source, "forked");
    assert!(dest_state(&source, &dest_id).await.is_empty());
    assert!(
        source
            .store
            .inner
            .get(
                &source.shards.coordinator(&dest_id.namespace),
                &keys::repo_record(&dest_id.name)
            )
            .await
            .unwrap()
            .is_none(),
        "refused before the destination was registered"
    );
}

#[tokio::test]
async fn an_already_registered_destination_is_not_a_fork_destination() {
    let source = Source::build("source", 4).await;
    let dest_id = dest(&source, "forked");
    source
        .store
        .inner
        .apply(
            &source.shards.coordinator(&dest_id.namespace),
            mkit_server::Batch::new().put(
                keys::repo_record(&dest_id.name),
                mkit_server::store::adapter_spi::codec::encode_repo_record(
                    &mkit_server::store::adapter_spi::codec::RepoRecord { created_at_ms: 1 },
                ),
            ),
        )
        .await
        .unwrap();
    assert_eq!(
        mkit_server::fork::start(&env(&source), &spec(&source, "forked"), None)
            .await
            .unwrap_err(),
        mkit_server::fork::ForkError::NotEmpty
    );
}

async fn quota_ops(source: &Source, dest_id: &RepoId) -> Option<u32> {
    let scope = mkit_server::quota::QuotaScope::for_signer(&dest_id.namespace, &[1; 32]);
    source
        .store
        .inner
        .get(
            &source.shards.coordinator(&dest_id.namespace),
            &keys::quota(&scope),
        )
        .await
        .unwrap()
        .map(|raw| {
            mkit_server::store::adapter_spi::codec::decode_quota_state(&raw)
                .unwrap()
                .ops
        })
}

#[tokio::test]
async fn quota_is_a_hard_bound_charged_once_with_the_job() {
    use mkit_server::fork::{ForkError, StartOutcome};
    let source = Source::build("source", 6).await;
    let dest_id = dest(&source, "forked");
    let settle = settlement::admit(&source, &dest_id).await;
    let started = mkit_server::fork::start(
        &env(&source),
        &spec(&source, "forked"),
        Some(settle.clone()),
    )
    .await
    .unwrap();
    assert!(matches!(started, StartOutcome::Started(_)));
    // The charge landed with the job, before any work.
    assert_eq!(quota_ops(&source, &dest_id).await, Some(1));
    assert!(
        started.job().settle.as_ref().unwrap().charges.is_empty(),
        "the stored row does not carry the applied charges"
    );
    // The same fork again is the same job and is not charged again.
    let again = mkit_server::fork::start(&env(&source), &spec(&source, "forked"), Some(settle))
        .await
        .unwrap();
    assert!(matches!(again, StartOutcome::Existing(_)));
    assert_eq!(quota_ops(&source, &dest_id).await, Some(1));
    // Running it charges nothing more.
    assert_eq!(run(&source, "forked").await.phase, Phase::Done);
    assert_eq!(quota_ops(&source, &dest_id).await, Some(1));

    // A window that cannot hold the fork refuses it before any row is
    // written: no job, no registered destination, the window untouched.
    let source = Source::build("source", 6).await;
    let dest_id = dest(&source, "forked");
    let base = settlement::admit(&source, &dest_id).await;
    let mut full = base.clone();
    full.charges[0].max_ops = 0;
    assert_eq!(
        mkit_server::fork::start(&env(&source), &spec(&source, "forked"), Some(full))
            .await
            .unwrap_err(),
        ForkError::Quota("write op quota exceeded for this window; try again later")
    );
    assert!(
        mkit_server::fork::read_job(&source.store, source.shards.as_ref(), &dest_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(quota_ops(&source, &dest_id).await, None);
    let mut bytes = base;
    bytes.charges[0].bytes = 10;
    bytes.charges[0].max_bytes = 5;
    assert_eq!(
        mkit_server::fork::start(&env(&source), &spec(&source, "forked"), Some(bytes))
            .await
            .unwrap_err(),
        ForkError::Quota("write byte quota exceeded for this window; try again later")
    );
}

#[tokio::test]
async fn a_write_by_the_same_signer_during_the_start_replans_the_charge() {
    use mkit_server::store::adapter_spi::codec;
    let source = Source::build("source", 6).await;
    let dest_id = dest(&source, "forked");
    let settle = settlement::admit(&source, &dest_id).await;
    // Another write of the signer moves the quota row just before the job
    // batch, once: the batch loses its guard and the charge is planned again.
    let (store, clock, ns) = (
        source.store.clone(),
        source.clock.clone(),
        dest_id.namespace.clone(),
    );
    let hook: Hook = Arc::new(move || {
        let (store, clock, ns) = (store.clone(), clock.clone(), ns.clone());
        Box::pin(async move {
            let scope = mkit_server::quota::QuotaScope::for_signer(&ns, &[1; 32]);
            let state = mkit_server::quota::QuotaState {
                window_start: clock.now_ms(),
                ops: 4,
                bytes: 0,
            };
            store
                .inner
                .apply(
                    &mkit_server::Partition::Coordinator(ns.clone()),
                    mkit_server::Batch::new()
                        .put(keys::quota(&scope), codec::encode_quota_state(&state)),
                )
                .await
                .unwrap();
        })
    });
    *source.store.trigger.lock().unwrap() = Some(("q", hook));
    let started = mkit_server::fork::start(&env(&source), &spec(&source, "forked"), Some(settle))
        .await
        .unwrap();
    assert!(matches!(started, StartOutcome::Started(_)));
    // The concurrent write counted, and this fork was charged on top of it.
    assert_eq!(quota_ops(&source, &dest_id).await, Some(5));
}

/// Make the next job batch lose its quota guard `left` times in a row: each
/// firing is another write of the signer, and arms the next.
fn contend(
    store: Counting,
    clock: Arc<mkit_server::ManualClock>,
    ns: mkit_server::NamespaceKey,
    left: u32,
) {
    use mkit_server::store::adapter_spi::codec;
    if left == 0 {
        return;
    }
    let armed = store.clone();
    let hook: Hook = Arc::new(move || {
        let (store, clock, ns) = (store.clone(), clock.clone(), ns.clone());
        Box::pin(async move {
            let scope = mkit_server::quota::QuotaScope::for_signer(&ns, &[1; 32]);
            let state = mkit_server::quota::QuotaState {
                window_start: clock.now_ms(),
                ops: 3 + left,
                bytes: 0,
            };
            store
                .inner
                .apply(
                    &mkit_server::Partition::Coordinator(ns.clone()),
                    mkit_server::Batch::new()
                        .put(keys::quota(&scope), codec::encode_quota_state(&state)),
                )
                .await
                .unwrap();
            contend(store, clock, ns, left - 1);
        })
    });
    *armed.trigger.lock().unwrap() = Some(("q", hook));
}

#[tokio::test]
async fn the_charge_is_replanned_three_times_and_then_the_start_is_refused() {
    use mkit_server::fork::ForkError;
    for (losses, started) in [(2, true), (3, false)] {
        let source = Source::build("source", 6).await;
        let dest_id = dest(&source, "forked");
        let settle = settlement::admit(&source, &dest_id).await;
        contend(
            source.store.clone(),
            source.clock.clone(),
            dest_id.namespace.clone(),
            losses,
        );
        let outcome =
            mkit_server::fork::start(&env(&source), &spec(&source, "forked"), Some(settle)).await;
        if started {
            assert!(matches!(outcome, Ok(StartOutcome::Started(_))));
            // The last competing write counted too, and the fork on top of it.
            assert_eq!(quota_ops(&source, &dest_id).await, Some(5));
        } else {
            assert_eq!(
                outcome.unwrap_err(),
                ForkError::Unavailable("fork start contended")
            );
            // No job and no charge: only the competing writes.
            assert!(
                mkit_server::fork::read_job(&source.store, source.shards.as_ref(), &dest_id)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(quota_ops(&source, &dest_id).await, Some(4));
        }
    }
}

#[tokio::test]
async fn the_namespace_cap_binds_a_fork_with_the_signer_charge_or_not_at_all() {
    use mkit_server::fork::{ChargeV1, ForkError};
    let cap = |max_ops: u32| ChargeV1 {
        scope: String::new(),
        bytes: 0,
        window_ms: 3_600_000,
        max_ops,
        max_bytes: 1 << 40,
    };
    let counter = |source: &Source, dest_id: &RepoId| {
        let window = mkit_server::quota::namespace_window(source.clock.now_ms(), 3_600_000);
        (
            source.shards.coordinator(&dest_id.namespace),
            keys::quota_total(window),
        )
    };
    // A namespace window that cannot hold the fork refuses it before any row,
    // and neither the namespace nor the signer is charged.
    let source = Source::build("source", 6).await;
    let dest_id = dest(&source, "forked");
    let mut settle = settlement::admit(&source, &dest_id).await;
    settle.namespace_cap = Some(cap(0));
    assert_eq!(
        mkit_server::fork::start(&env(&source), &spec(&source, "forked"), Some(settle))
            .await
            .unwrap_err(),
        ForkError::Quota("namespace write op/byte quota exceeded for this window; try again later")
    );
    let (p, key) = counter(&source, &dest_id);
    assert!(source.store.inner.get(&p, &key).await.unwrap().is_none());
    assert_eq!(quota_ops(&source, &dest_id).await, None);
    assert!(
        mkit_server::fork::read_job(&source.store, source.shards.as_ref(), &dest_id)
            .await
            .unwrap()
            .is_none()
    );
    // A window with room is charged once, with the job and the signer.
    let source = Source::build("source", 6).await;
    let dest_id = dest(&source, "forked");
    let mut settle = settlement::admit(&source, &dest_id).await;
    settle.namespace_cap = Some(cap(10));
    mkit_server::fork::start(&env(&source), &spec(&source, "forked"), Some(settle))
        .await
        .unwrap();
    assert_eq!(run(&source, "forked").await.phase, Phase::Done);
    let (p, key) = counter(&source, &dest_id);
    let usage = source.store.inner.get(&p, &key).await.unwrap().unwrap();
    assert_eq!(
        mkit_server::store::adapter_spi::codec::decode_namespace_usage(&usage)
            .unwrap()
            .ops,
        1
    );
    assert_eq!(quota_ops(&source, &dest_id).await, Some(1));
}

#[tokio::test]
async fn a_pack_set_larger_than_the_admitted_bytes_fails_the_fork_before_registration() {
    use mkit_server::store::adapter_spi::codec::{AbortReason, ReservationV1};
    let source = Source::build("source", 6).await;
    let dest_id = dest(&source, "forked");
    let mut settle = settlement::admit(&source, &dest_id).await;
    settle.declared_bytes = 1;
    mkit_server::fork::start(&env(&source), &spec(&source, "forked"), Some(settle))
        .await
        .unwrap();
    let job = run(&source, "forked").await;
    assert_eq!(job.phase, Phase::Failed);
    assert_eq!(
        job.failure.unwrap().error().public_message(),
        "fork exceeds the bytes admitted; retry"
    );
    assert!(matches!(
        settlement::outcome(&source, &dest_id).await,
        ReservationV1::Aborted {
            reason: AbortReason::Unspecified,
            ..
        }
    ));
    assert!(dest_state(&source, &dest_id).await.is_empty());
}

#[tokio::test]
async fn the_authority_a_request_was_authorized_under_is_checked_when_the_destination_registers() {
    use mkit_server::fork::FenceV1;
    use mkit_server::store::adapter_spi::codec;
    let run_with = |fence: FenceV1, dest_name: &'static str| async move {
        let source = Source::build("source", 4).await;
        let env = env(&source);
        mkit_server::fork::start_with(
            &env,
            &spec(&source, dest_name),
            None,
            Some(FenceV1 {
                authority_generation: Some(0),
                grant_epoch: Some(0),
                create_namespace: true,
            }),
        )
        .await
        .unwrap();
        for (key, generation) in [
            (keys::authority_generation(), fence.authority_generation),
            (keys::grant_epoch(), fence.grant_epoch),
        ] {
            if let Some(generation) = generation.filter(|generation| *generation != 0) {
                source
                    .store
                    .inner
                    .apply(
                        &source.shards.coordinator(&source.repo.namespace),
                        mkit_server::Batch::new().put(key, codec::encode_u64(generation)),
                    )
                    .await
                    .unwrap();
            }
        }
        let job = run(&source, dest_name).await;
        let registered = source
            .store
            .inner
            .get(
                &source.shards.coordinator(&source.repo.namespace),
                &keys::repo_record(&dest(&source, dest_name).name),
            )
            .await
            .unwrap()
            .is_some();
        (job, registered)
    };
    // The generation and epoch still hold (absent means 0).
    let ok = FenceV1 {
        authority_generation: Some(0),
        grant_epoch: Some(0),
        create_namespace: true,
    };
    let (job, registered) = run_with(ok.clone(), "forked").await;
    assert_eq!(job.phase, Phase::Done, "{:?}", job.failure);
    assert!(registered);
    // A moved generation or epoch ends the fork before it writes anything.
    for moved in [
        FenceV1 {
            authority_generation: Some(7),
            ..ok.clone()
        },
        FenceV1 {
            grant_epoch: Some(3),
            ..ok.clone()
        },
    ] {
        let (job, registered) = run_with(moved, "moved").await;
        assert_eq!(job.phase, Phase::Failed);
        // The ordinary refusal for a moved authority.
        let error = job.failure.unwrap().error();
        assert_eq!(error.code(), mkit_server::Code::PermissionDenied);
        assert!(
            [
                "namespace authority generation changed",
                "write grant epoch changed; re-authorize"
            ]
            .contains(&error.public_message()),
            "{}",
            error.public_message()
        );
        assert!(!registered);
    }
}

#[tokio::test]
async fn a_fork_does_not_create_a_namespace_where_namespaces_are_registered_by_their_authority() {
    use mkit_server::fork::FenceV1;
    let source = Source::build("source", 4).await;
    let env = env(&source);
    let mut request = spec(&source, "forked");
    request.dest = RepoId {
        namespace: mkit_server::NamespaceKey::from_namespace(
            &mkit_core::repo_identity::Namespace::Ed25519([9; 32]),
        ),
        name: RepoName::new("forked").unwrap(),
    };
    let fence = FenceV1 {
        authority_generation: None,
        grant_epoch: None,
        create_namespace: false,
    };
    mkit_server::fork::start_with(&env, &request, None, Some(fence))
        .await
        .unwrap();
    let job = loop {
        let report = mkit_server::fork::step(&env, &request.dest, &SliceBudget::new(600))
            .await
            .unwrap();
        if report.job.finished() {
            break report.job;
        }
    };
    assert_eq!(job.phase, Phase::Failed);
    let error = job.failure.unwrap().error();
    assert_eq!(
        (error.code(), error.public_message()),
        (
            mkit_server::Code::PermissionDenied,
            "namespace not registered"
        )
    );
}

#[tokio::test]
async fn a_reservation_that_the_reconciler_would_abort_before_the_job_expires_is_refused() {
    use mkit_server::store::adapter_spi::codec::{self, PendingOp, ReservationV1, StoredProcedure};
    let source = Source::build("source", 4).await;
    let dest_id = dest(&source, "forked");
    let mut settle = settlement::admit(&source, &dest_id).await;
    let now = u64::try_from(source.clock.now_ms()).unwrap();
    // The apply-window reconcile time an ordinary write would get.
    settle.pending = codec::encode_reservation(&ReservationV1::pending(
        settle.repository.clone(),
        now,
        now + 12_000,
        PendingOp::Write,
        StoredProcedure::Fork,
    ))
    .as_bytes()
    .to_vec();
    assert_eq!(
        mkit_server::fork::start(&env(&source), &spec(&source, "forked"), Some(settle))
            .await
            .unwrap_err(),
        mkit_server::fork::ForkError::Unavailable("fork reservation")
    );
    assert!(
        mkit_server::fork::read_job(env(&source).store, env(&source).shards, &dest_id)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn registration_follows_the_fence_for_namespaces_and_never_replaces_a_declared_visibility() {
    use mkit_server::fork::FenceV1;
    use mkit_server::store::adapter_spi::codec::{self, RepoVisibilityV1, StoredVisibility};
    let other = || RepoId {
        namespace: mkit_server::NamespaceKey::from_namespace(
            &mkit_core::repo_identity::Namespace::Ed25519([9; 32]),
        ),
        name: RepoName::new("forked").unwrap(),
    };
    // A fork with no fence cannot create a namespace.
    let source = Source::build("source", 4).await;
    let mut request = spec(&source, "forked");
    request.dest = other();
    mkit_server::fork::start(&env(&source), &request, None)
        .await
        .unwrap();
    let job = loop {
        let report = mkit_server::fork::step(&env(&source), &request.dest, &SliceBudget::new(600))
            .await
            .unwrap();
        if report.job.finished() {
            break report.job;
        }
    };
    assert_eq!(job.phase, Phase::Failed);
    let error = job.failure.unwrap().error();
    assert_eq!(
        (error.code(), error.public_message()),
        (
            mkit_server::Code::PermissionDenied,
            "namespace not registered"
        )
    );
    // With the fence's permission it creates the namespace record.
    let source = Source::build("source", 4).await;
    let mut request = spec(&source, "forked");
    request.dest = other();
    let fence = FenceV1 {
        authority_generation: None,
        grant_epoch: None,
        create_namespace: true,
    };
    mkit_server::fork::start_with(&env(&source), &request, None, Some(fence))
        .await
        .unwrap();
    loop {
        let report = mkit_server::fork::step(&env(&source), &request.dest, &SliceBudget::new(600))
            .await
            .unwrap();
        if report.job.finished() {
            assert_eq!(report.job.phase, Phase::Done, "{:?}", report.job.failure);
            break;
        }
    }
    assert!(
        source
            .store
            .inner
            .get(
                &source.shards.coordinator(&request.dest.namespace),
                &keys::namespace_record()
            )
            .await
            .unwrap()
            .is_some()
    );
    // A non-zero generation and epoch that still hold pass.
    let source = Source::build("source", 4).await;
    let coordinator = source.shards.coordinator(&source.repo.namespace);
    source
        .store
        .inner
        .apply(
            &coordinator,
            mkit_server::Batch::new()
                .put(keys::authority_generation(), codec::encode_u64(5))
                .put(keys::grant_epoch(), codec::encode_u64(2)),
        )
        .await
        .unwrap();
    let fence = FenceV1 {
        authority_generation: Some(5),
        grant_epoch: Some(2),
        create_namespace: false,
    };
    mkit_server::fork::start_with(&env(&source), &spec(&source, "forked"), None, Some(fence))
        .await
        .unwrap();
    assert_eq!(run(&source, "forked").await.phase, Phase::Done);
    // A visibility the owner declared for the unregistered name stands.
    for (declared, requested, expect_done) in [
        (StoredVisibility::Private, Visibility::Private, true),
        (StoredVisibility::Private, Visibility::Public, false),
    ] {
        let source = Source::build("source", 4).await;
        let dest_id = dest(&source, "forked");
        let row = codec::encode_repo_visibility(&RepoVisibilityV1 {
            visibility: declared,
            last_created_ms: 1_700_000_000_000,
            last_statement_id: Some("ab".repeat(32)),
            changed_ms: 5,
        });
        let coordinator = source.shards.coordinator(&dest_id.namespace);
        source
            .store
            .inner
            .apply(
                &coordinator,
                mkit_server::Batch::new().put(keys::repo_visibility(&dest_id.name), row.clone()),
            )
            .await
            .unwrap();
        let mut request = spec(&source, "forked");
        request.dest_visibility = requested;
        mkit_server::fork::start(&env(&source), &request, None)
            .await
            .unwrap();
        let job = run(&source, "forked").await;
        assert_eq!(job.phase == Phase::Done, expect_done, "{:?}", job.failure);
        let stored = source
            .store
            .inner
            .get(&coordinator, &keys::repo_visibility(&dest_id.name))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored, row, "the owner's declaration is untouched");
    }
}

#[tokio::test]
async fn a_moved_authority_aborts_the_reservation_with_the_epoch_mismatch_reason() {
    use mkit_server::fork::FenceV1;
    use mkit_server::store::adapter_spi::codec::{self, AbortReason, ReservationV1};
    let source = Source::build("source", 4).await;
    let dest_id = dest(&source, "forked");
    let settle = settlement::admit(&source, &dest_id).await;
    let fence = FenceV1 {
        authority_generation: Some(0),
        grant_epoch: None,
        create_namespace: true,
    };
    mkit_server::fork::start_with(
        &env(&source),
        &spec(&source, "forked"),
        Some(settle),
        Some(fence),
    )
    .await
    .unwrap();
    source
        .store
        .inner
        .apply(
            &source.shards.coordinator(&dest_id.namespace),
            mkit_server::Batch::new().put(keys::authority_generation(), codec::encode_u64(9)),
        )
        .await
        .unwrap();
    assert_eq!(run(&source, "forked").await.phase, Phase::Failed);
    let ReservationV1::Aborted { reason, .. } = settlement::outcome(&source, &dest_id).await else {
        panic!("a moved authority aborts the reservation")
    };
    assert_eq!(reason, AbortReason::EpochMismatch);
}

#[tokio::test]
async fn a_corrupt_job_row_keeps_its_timer_and_extra_index_rows_are_the_uniform_not_found() {
    use mkit_server::fork::ForkTimer;
    use mkit_server::timers::{TickBudget, TimerRegistry, run_due};
    // A row the engine cannot read is retried, never ended: a newer binary may.
    let source = Source::build("source", 4).await;
    let dest_id = dest(&source, "forked");
    mkit_server::fork::start(&env(&source), &spec(&source, "forked"), None)
        .await
        .unwrap();
    let coordinator = source.shards.coordinator(&dest_id.namespace);
    source
        .store
        .inner
        .apply(
            &coordinator,
            mkit_server::Batch::new().put(
                keys::fork_job(&dest_id.name),
                mkit_server::Value::new(b"\x01not a job".to_vec()),
            ),
        )
        .await
        .unwrap();
    let registry = TimerRegistry::new().register(ForkTimer {
        publication_policy: None,
        store: source.store.clone(),
        shards: source.shards.clone(),
        clock: source.clock.clone(),
        takedown_denial: true,
        extract_min_bytes: None,
    });
    run_due(
        &source.store,
        &coordinator,
        &registry,
        source.clock.as_ref(),
        u64::try_from(source.clock.now_ms()).unwrap(),
        &TickBudget::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        fork_timers(source.store.inner.as_ref(), &coordinator).await,
        1
    );

    // More index rows than the sealed inventories hold: an inconsistency.
    let source = Source::build("source", 4).await;
    let first = blob(0, 8).0;
    let shard = source.shards.object_index(&source.repo, &first);
    let key = keys::object_index(&source.repo.name, &first, &source.pack);
    let value = source.store.inner.get(&shard, &key).await.unwrap().unwrap();
    let located =
        mkit_server::store::adapter_spi::codec::decode_object_index(&first, &value).unwrap();
    let extra = [0xAB; 32];
    source
        .store
        .inner
        .apply(
            &source.shards.object_index(&source.repo, &extra),
            mkit_server::Batch::new().put(
                keys::object_index(&source.repo.name, &extra, &source.pack),
                mkit_server::store::adapter_spi::codec::encode_object_index(&extra, &located)
                    .unwrap(),
            ),
        )
        .await
        .unwrap();
    mkit_server::fork::start(&env(&source), &spec(&source, "forked"), None)
        .await
        .unwrap();
    let job = run(&source, "forked").await;
    assert_eq!(job.phase, Phase::Failed);
    assert_eq!(
        job.failure.unwrap().error().public_message(),
        "source not found"
    );
}

fn denial_capability_for_test() -> mkit_server::takedown::DenialCapability {
    use mkit_server::pipeline::{AuthMode, Hooks, Pipeline, PipelineConfig};
    let mut cfg = PipelineConfig::new(
        mkit_server::Addressing::Multi(mkit_server::MultiAddressing::new()),
        AuthMode::AuthV2(
            mkit_server::auth_v2::AuthV2Config::new("http://localhost", "default").unwrap(),
        ),
        mkit_server::upload::UploadLimits::new(1 << 20, 64),
    );
    cfg.indexed = Some(mkit_server::indexed::IndexedConfig::default());
    cfg.ticket_keys =
        Some(mkit_server::upload::token::TicketKeys::new(vec![("test".into(), [7; 32])]).unwrap());
    cfg.begin_upload_threshold_bytes = 0;
    cfg.takedown_denial = true;
    Pipeline::new(
        mkit_server::MemoryBlobStore::default(),
        mkit_server::MemoryKv::default(),
        Hooks::new(),
        cfg,
        std::sync::Arc::new(mkit_server::SystemClock),
        std::sync::Arc::new(mkit_server::NoopMetrics),
    )
    .unwrap()
    .denial_capability()
    .unwrap()
}

/// A first fork into a brand-new namespace, run by the real engine, is
/// recovered by the typed read; the retained settlement is the same as for a
/// fork into an existing namespace.
#[tokio::test]
async fn a_fork_that_created_its_namespace_is_recovered_by_the_typed_read() {
    use mkit_server::fork::{FenceV1, ForkSpec, StartOutcome};
    use mkit_server::reads::ForkReplayIdentity;
    let source = Source::build("source", 6).await;
    let env = env(&source);
    let reads = source.pipe.read_access();
    let fresh = mkit_core::repo_identity::Namespace::Ed25519(
        *ed25519_dalek::SigningKey::from_bytes(&[8; 32])
            .verifying_key()
            .as_bytes(),
    );
    for (created, namespace) in [
        (true, mkit_server::NamespaceKey::from_namespace(&fresh)),
        (false, source.repo.namespace.clone()),
    ] {
        let dest = RepoId {
            namespace,
            name: RepoName::new(if created { "first" } else { "second" }).unwrap(),
        };
        let spec = ForkSpec {
            source: source.repo.clone(),
            source_ref: "refs/heads/main".into(),
            expected_tip: source.head,
            dest: dest.clone(),
            dest_visibility: Visibility::Public,
        };
        let coordinator = source.shards.coordinator(&dest.namespace);
        assert_eq!(
            source
                .store
                .inner
                .get(&coordinator, &keys::namespace_record())
                .await
                .unwrap()
                .is_none(),
            created
        );
        let mut settle = settlement::admit(&source, &dest).await;
        settle.charges.clear();
        if !created {
            // Where an authority registers the namespace, its generation row
            // is the registration.
            source
                .store
                .inner
                .apply(
                    &coordinator,
                    mkit_server::Batch::new().put(
                        keys::authority_generation(),
                        mkit_server::store::adapter_spi::codec::encode_u64(1),
                    ),
                )
                .await
                .unwrap();
        }
        let fence = FenceV1 {
            authority_generation: Some(u64::from(!created)),
            grant_epoch: None,
            create_namespace: created,
        };
        let started = mkit_server::fork::start_with(&env, &spec, Some(settle), Some(fence))
            .await
            .unwrap();
        assert!(matches!(started, StartOutcome::Started(_)));
        let mut job = None;
        for _ in 0..200 {
            let report = mkit_server::fork::step(&env, &dest, &SliceBudget::new(600))
                .await
                .unwrap();
            if report.job.finished() {
                job = Some(report.job);
                break;
            }
        }
        let job = job.expect("fork did not finish");
        assert_eq!(job.phase, Phase::Done, "{:?}", job.failure);
        assert!(
            source
                .store
                .inner
                .get(&coordinator, &keys::namespace_record())
                .await
                .unwrap()
                .is_some()
        );
        let original = ForkReplayIdentity {
            scope: [3; 32],
            fingerprint: [4; 32],
            expires_at_ms: source.clock.now_ms() + 300_000,
        };
        let recovered = reads
            .recover_completed_fork(&spec, &original)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(Some(&recovered.result), job.result.as_ref());
        assert_eq!(recovered.authority.creates_namespace, created);
        assert_eq!(recovered.reservation.id, settlement::RID);
        // Losing the namespace record fails recovery closed.
        if created {
            source
                .store
                .inner
                .apply(
                    &coordinator,
                    mkit_server::Batch::new().delete(keys::namespace_record()),
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
    }
}

// ---- Round cuts: no walk without denial, a carried plan, publish waves ----

fn no_denial(
    mut cfg: mkit_server::pipeline::PipelineConfig,
) -> mkit_server::pipeline::PipelineConfig {
    cfg.takedown_denial = false;
    cfg
}

fn env_denial(source: &Source, takedown_denial: bool) -> ForkEnv<'_, Counting> {
    ForkEnv {
        takedown_denial,
        ..env(source)
    }
}

/// A source with `more` commits after the first, each a data pack and a
/// packmap node: `2 * (more + 1)` packs.
async fn long_source(
    more: u32,
    tweak: fn(mkit_server::pipeline::PipelineConfig) -> mkit_server::pipeline::PipelineConfig,
) -> Source {
    long_chain(more, tweak).await.0
}

/// [`long_source`] and its packs: the packmap nodes and the data packs, oldest
/// first.
async fn long_chain(
    more: u32,
    tweak: fn(mkit_server::pipeline::PipelineConfig) -> mkit_server::pipeline::PipelineConfig,
) -> (Source, Vec<Hash>, Vec<Hash>) {
    let mut source = Source::build_with("source", 4, tweak).await;
    let (mut map, mut parent) = (source.packmap, source.head);
    let (mut nodes, mut data) = (vec![map], vec![source.pack]);
    for n in 0..more {
        let (bytes, head, _) = tree_pack(3, 8, 1_000 + n * 10, vec![parent], b"more");
        let pack = mkit_core::hash::hash(&bytes);
        map = source.push(bytes, head, Some(map), &[pack]).await;
        parent = head;
        nodes.push(map);
        data.push(pack);
    }
    (source.head, source.packmap) = (parent, map);
    (source, nodes, data)
}

async fn drop_source_member(source: &Source, pack: Hash) {
    source
        .store
        .inner
        .apply(
            &source.shards.membership(&source.repo, &BlobKey::pack(pack)),
            mkit_server::Batch::new().delete(keys::published_member(&source.repo.name, &pack)),
        )
        .await
        .unwrap();
}

async fn drive(
    env: &ForkEnv<'_, Counting>,
    dest: &RepoId,
) -> Result<mkit_server::fork::ForkJobV1, mkit_server::fork::ForkError> {
    for _ in 0..500 {
        let report = mkit_server::fork::step(env, dest, &SliceBudget::new(600)).await?;
        if report.job.finished() {
            return Ok(report.job);
        }
    }
    panic!("fork did not finish");
}

/// Plan, start (carrying the plan if asked) and drive to the end.
async fn fork_to_end(
    source: &Source,
    env: &ForkEnv<'_, Counting>,
    name: &str,
    carry: bool,
) -> mkit_server::fork::ForkJobV1 {
    let spec = spec(source, name);
    let planned = if carry {
        mkit_server::fork::plan_fork(env, &spec).await.unwrap()
    } else {
        None
    };
    assert_eq!(
        planned.is_some(),
        carry,
        "a plan is carried exactly when asked"
    );
    mkit_server::fork::start_planned(env, &spec, None, None, planned)
        .await
        .unwrap();
    drive(env, &dest(source, name)).await.unwrap()
}

async fn job_of(source: &Source, id: &RepoId) -> mkit_server::fork::ForkJobV1 {
    mkit_server::fork::read_job(source.store.inner.as_ref(), source.shards.as_ref(), id)
        .await
        .unwrap()
        .unwrap()
        .0
}

async fn member(source: &Source, repo: &RepoId, pack: Hash) -> Option<mkit_server::Value> {
    source
        .store
        .inner
        .get(
            &source.shards.membership(repo, &BlobKey::pack(pack)),
            &keys::membership(&repo.name, &pack),
        )
        .await
        .unwrap()
}

async fn set_row(source: &Source, id: &RepoId, set: u8) -> Option<mkit_server::Value> {
    source
        .store
        .inner
        .get(
            &source.shards.coordinator(&id.namespace),
            &keys::fork_set(&id.name, set),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn without_denial_no_cleared_set_is_built_and_the_trees_phase_still_runs() {
    for takedown_denial in [false, true] {
        let source = Source::build_with(
            "source",
            10,
            if takedown_denial { denial } else { no_denial },
        )
        .await;
        let mut env = env_denial(&source, takedown_denial);
        env.extract_min_bytes = Some(65_536);
        let dest_id = dest(&source, "forked");
        *source.store.mark_key.lock().unwrap() = Some(keys::fork_job(&dest_id.name));
        let job = fork_to_end(&source, &env, "forked", true).await;
        assert_eq!(job.phase, Phase::Done, "{:?}", job.failure);
        let phases: Vec<_> = source
            .store
            .marks
            .lock()
            .unwrap()
            .iter()
            .map(|(_, bytes, _)| {
                mkit_server::fork::decode_job(&mkit_server::Value::new(bytes.clone()))
                    .unwrap()
                    .phase
            })
            .collect();
        // The manifest set is collected by the Trees phase under both modes.
        assert!(phases.contains(&Phase::Register), "{phases:?}");
        assert_eq!(phases.contains(&Phase::Walk), takedown_denial, "{phases:?}");
        // Only a deployment with denial builds the cleared set; this source
        // has no external-base packs, so no base set exists either way, and
        // the walk queue is gone once the fork is done.
        for set in [0_u8, 2, 3] {
            assert_eq!(
                set_row(&source, &dest_id, set).await.is_some(),
                takedown_denial && set == 0,
                "set {set} with denial {takedown_denial}"
            );
        }
    }
}

#[tokio::test]
async fn a_destination_forked_without_denial_still_proves_every_inherited_pack_when_denial_is_enabled()
 {
    // The fork ran while denial was off, so the destination carries the
    // boundary flag and no cleared set. A deployment that turns denial on
    // later takes a full first walk, and the advance-time proof of every
    // inherited pack still stops a takedown.
    let walk_calls = |forked_with_sets: bool| async move {
        let source = Source::build_with("source", 8, denial).await;
        let env = env_denial(&source, forked_with_sets);
        let job = fork_to_end(&source, &env, "forked", true).await;
        assert_eq!(job.phase, Phase::Done, "{:?}", job.failure);
        let id = dest(&source, "forked");
        assert_eq!(set_row(&source, &id, 0).await.is_some(), forked_with_sets);
        let mut remix = source.at("forked");
        let (bytes, head) = commit_pack(source.tree, vec![], b"remix");
        let pack = mkit_core::hash::hash(&bytes);
        let before = source.store.calls();
        remix.push(bytes, head, Some(source.packmap), &[pack]).await;
        source.store.calls() - before
    };
    let with_sets = walk_calls(true).await;
    let without_sets = walk_calls(false).await;
    assert!(
        without_sets > with_sets,
        "{without_sets} calls without the set, {with_sets} with it"
    );
    for victim in ["blob", "tree", "commit", "data pack"] {
        let source = Source::build_with("source", 8, denial).await;
        let env = env_denial(&source, false);
        let job = fork_to_end(&source, &env, "forked", true).await;
        assert_eq!(job.phase, Phase::Done, "{:?}", job.failure);
        assert!(
            set_row(&source, &dest(&source, "forked"), 0)
                .await
                .is_none()
        );
        assert!(
            set_row(&source, &dest(&source, "forked"), 3)
                .await
                .is_none()
        );
        let target = match victim {
            "blob" => blob(5, 8).0,
            "tree" => source.tree,
            "commit" => source.head,
            _ => source.pack,
        };
        block(&source, target).await;
        let mut remix = source.at("forked");
        let (bytes, head) = commit_pack(source.tree, vec![], b"remix");
        let pack = mkit_core::hash::hash(&bytes);
        assert_eq!(
            remix
                .try_push(bytes, head, Some(source.packmap), &[pack])
                .await
                .unwrap_err(),
            "object blocked",
            "{victim}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn publish_waves_end_where_the_serial_publish_does_and_write_the_head_last() {
    let source = long_source(5, no_denial).await;
    let env = env_denial(&source, false);
    // The store reports no read allowance: the serial path.
    let serial = fork_to_end(&source, &env, "serial", true).await;
    assert_eq!(serial.phase, Phase::Done, "{:?}", serial.failure);
    source
        .store
        .sleep_ms
        .store(10, std::sync::atomic::Ordering::SeqCst);
    source
        .store
        .waves
        .store(true, std::sync::atomic::Ordering::SeqCst);
    source
        .store
        .record
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let waved = fork_to_end(&source, &env, "waved", true).await;
    assert_eq!(waved.phase, Phase::Done, "{:?}", waved.failure);
    assert_eq!(waved.result, serial.result);
    assert_eq!(waved.packs.len(), 12);
    let (serial_id, waved_id) = (dest(&source, "serial"), dest(&source, "waved"));
    for pack in waved.packs.iter().map(|p| p.id) {
        let flagged = pack == source.packmap;
        let (a, b) = (
            member(&source, &serial_id, pack).await.unwrap(),
            member(&source, &waved_id, pack).await.unwrap(),
        );
        assert_eq!(a, b);
        assert_eq!(Witness::decode(&b).unwrap().boundary, flagged);
    }
    // The head's rows are the last membership rows written.
    let written: Vec<Hash> = source
        .store
        .log
        .lock()
        .unwrap()
        .iter()
        .flat_map(|(_, batch)| batch.writes.iter())
        .filter_map(|write| match write {
            mkit_server::Write::Put(key, _) => waved
                .packs
                .iter()
                .map(|p| p.id)
                .find(|id| *key == keys::membership(&waved_id.name, id)),
            mkit_server::Write::Delete(_) | mkit_server::Write::Increment(_) => None,
        })
        .collect();
    assert_eq!(written.len(), 12, "{written:?}");
    assert_eq!(written.last(), Some(&source.packmap));
    assert!(!written[..11].contains(&source.packmap));
}

#[tokio::test(start_paused = true)]
async fn acceptance_reports_its_first_source_failure_in_input_order_without_installing_membership()
{
    use std::sync::atomic::Ordering;
    for missing_first in [true, false] {
        let source = long_source(4, no_denial).await;
        source.store.sleep_ms.store(10, Ordering::SeqCst);
        source.store.waves.store(true, Ordering::SeqCst);
        let env = env_denial(&source, false);
        let spec = spec(&source, "forked");
        let planned = mkit_server::fork::plan_fork(&env, &spec).await.unwrap();
        // Preparation finishes before the final source proofs are disturbed.
        mkit_server::fork::start_planned(&env, &spec, None, None, planned)
            .await
            .unwrap();
        let dest_id = dest(&source, "forked");
        stop_at_fork_phase(&source, &env, &dest_id, Phase::Accept).await;
        let order: Vec<Hash> = job_of(&source, &dest_id)
            .await
            .packs
            .iter()
            .map(|p| p.id)
            .collect();
        // A missing member and a transient error retain the complete inherited
        // set's deterministic proof order.
        let (gone, flaky) = if missing_first {
            (order[1], order[3])
        } else {
            (order[3], order[1])
        };
        source
            .store
            .inner
            .apply(
                &source.shards.membership(&source.repo, &BlobKey::pack(gone)),
                mkit_server::Batch::new().delete(keys::published_member(&source.repo.name, &gone)),
            )
            .await
            .unwrap();
        source
            .store
            .fail_keys
            .lock()
            .unwrap()
            .push(keys::published_member(&source.repo.name, &flaky));
        let outcome = drive(&env, &dest_id).await;
        if missing_first {
            let job = outcome.unwrap();
            assert_eq!(job.phase, Phase::Failed);
            assert_eq!(job.failure, Some(mkit_server::fork::Failure::NotFound));
        } else {
            assert!(
                matches!(outcome, Err(mkit_server::fork::ForkError::Unavailable(_))),
                "{outcome:?}"
            );
            let job = job_of(&source, &dest_id).await;
            assert_eq!(job.phase, Phase::Accept);
            // A retryable failure commits nothing of its slice: the units
            // before it are repeated without installing membership.
            assert_eq!(job.cursor, 0);
        }
        assert!(
            member(&source, &dest_id, source.packmap).await.is_none(),
            "unaccepted membership is never installed"
        );
        // The retryable failure ends once the read works.
        if !missing_first {
            source.store.fail_keys.lock().unwrap().clear();
            let job = drive(&env, &dest_id).await.unwrap();
            assert_eq!(job.failure, Some(mkit_server::fork::Failure::NotFound));
            assert!(member(&source, &dest_id, source.packmap).await.is_none());
        }
    }
}

#[tokio::test(start_paused = true)]
async fn a_slice_cut_inside_a_publish_wave_resumes_with_any_driver() {
    use std::sync::atomic::Ordering;
    let source = long_source(5, no_denial).await;
    source.store.sleep_ms.store(10, Ordering::SeqCst);
    let env = env_denial(&source, false);
    let whole = fork_to_end(&source, &env, "whole", true).await;
    assert_eq!(whole.phase, Phase::Done, "{:?}", whole.failure);
    let mut seen = std::collections::BTreeSet::new();
    let mut switched = std::collections::BTreeSet::new();
    for (n, slice) in [65_u32]
        .into_iter()
        .chain((70_u32..300).step_by(3))
        .enumerate()
    {
        for switch_stage in [0_u16, 2, 3] {
            source.store.waves.store(true, Ordering::SeqCst);
            let name = format!("cut-{n}-{switch_stage}");
            let spec = spec(&source, &name);
            let planned = mkit_server::fork::plan_fork(&env, &spec).await.unwrap();
            mkit_server::fork::start_planned(&env, &spec, None, None, planned)
                .await
                .unwrap();
            let id = dest(&source, &name);
            // Begin each allowance at the same durable activation boundary,
            // so preparation cost cannot hide a cut inside its check wave.
            stop_at_fork_phase(&source, &env, &id, Phase::Publish).await;
            let mut steps = 0;
            let job = loop {
                steps += 1;
                assert!(steps < 500);
                let report = mkit_server::fork::step(&env, &id, &SliceBudget::new(slice))
                    .await
                    .unwrap();
                if report.job.finished() {
                    break report.job;
                }
                if report.job.phase == Phase::Publish && report.job.part >= 2 {
                    seen.insert((report.job.part, report.job.cursor > 0));
                    if report.job.part == switch_stage {
                        // Resume either durable stage with a driver that cannot run waves.
                        switched.insert(switch_stage);
                        source.store.waves.store(false, Ordering::SeqCst);
                    }
                }
            };
            assert_eq!(job.phase, Phase::Done, "{:?}", job.failure);
            assert_eq!(job.result, whole.result, "slice {slice}");
            for pack in whole.packs.iter().map(|p| p.id) {
                assert_eq!(
                    member(&source, &id, pack)
                        .await
                        .map(|v| v.as_bytes().to_vec()),
                    member(&source, &dest(&source, "whole"), pack)
                        .await
                        .map(|v| v.as_bytes().to_vec()),
                    "slice {slice}"
                );
            }
        }
    }
    // Writes can checkpoint a partial wave. With denial disabled, activation
    // checks consume no storage calls: final source proofs already ran before
    // acceptance. Their resumable boundary is the start of the check stage.
    assert!(seen.contains(&(2, true)), "{seen:?}");
    assert!(seen.contains(&(3, false)), "{seen:?}");
    assert!(switched.contains(&2), "{switched:?}");
    assert!(switched.contains(&3), "{switched:?}");
}

#[tokio::test]
async fn a_takedown_in_the_gap_between_the_plan_and_acceptance_refuses_before_visibility() {
    // The carried plan proves no pack again until acceptance, so a member that
    // leaves the source after the plan fails the fork after registration (the
    // destination stays registered, as for any later refusal). A job that
    // plans itself finds the same change in its Plan phase, before anything
    // is written.
    for carry in [true, false] {
        let source = Source::build_with("source", 6, no_denial).await;
        let env = env_denial(&source, false);
        let spec = spec(&source, "forked");
        let planned = if carry {
            mkit_server::fork::plan_fork(&env, &spec).await.unwrap()
        } else {
            None
        };
        source
            .store
            .inner
            .apply(
                &source
                    .shards
                    .membership(&source.repo, &BlobKey::pack(source.pack)),
                mkit_server::Batch::new()
                    .delete(keys::published_member(&source.repo.name, &source.pack)),
            )
            .await
            .unwrap();
        mkit_server::fork::start_planned(&env, &spec, None, None, planned)
            .await
            .unwrap();
        let dest_id = dest(&source, "forked");
        let job = drive(&env, &dest_id).await.unwrap();
        assert_eq!(job.failure, Some(mkit_server::fork::Failure::NotFound));
        let registered = source
            .store
            .inner
            .get(
                &source.shards.coordinator(&dest_id.namespace),
                &keys::repo_record(&dest_id.name),
            )
            .await
            .unwrap()
            .is_some();
        assert_eq!(registered, carry, "carry {carry}");
        assert!(member(&source, &dest_id, source.packmap).await.is_none());
    }
}

#[tokio::test]
async fn a_plan_that_does_not_fit_one_slice_is_made_by_the_job() {
    let source = long_source(2, no_denial).await;
    let spec = spec(&source, "forked");
    // Cap the calls the scratch plan may spend from above, as a request's own
    // allowance would: a plan that cannot finish is not carried.
    let mut found = None;
    for limit in 3..200_u32 {
        let outer = SliceBudget::new(limit);
        let capped = mkit_server::indexed::budget::Budgeted::new(&source.store, &outer);
        let env = ForkEnv {
            publication_policy: None,
            store: &capped,
            shards: source.shards.as_ref(),
            clock: source.clock.as_ref(),
            takedown_denial: false,
            extract_min_bytes: None,
            limits: ForkLimits::default(),
        };
        if matches!(mkit_server::fork::plan_fork(&env, &spec).await, Ok(None)) {
            found = Some(limit);
            break;
        }
    }
    assert!(found.is_some(), "some allowance ends the plan unfinished");
    let env = env_denial(&source, false);
    // The job plans it itself and ends where a carried plan does.
    mkit_server::fork::start_planned(&env, &spec, None, None, None)
        .await
        .unwrap();
    let dest_id = dest(&source, "forked");
    assert_eq!(job_of(&source, &dest_id).await.phase, Phase::Plan);
    let planned = drive(&env, &dest_id).await.unwrap();
    assert_eq!(planned.phase, Phase::Done, "{:?}", planned.failure);
    let carried = fork_to_end(&source, &env, "carried", true).await;
    assert_eq!(carried.result, planned.result);
}

#[tokio::test(start_paused = true)]
async fn a_plan_wave_reports_its_first_failure_in_input_order() {
    use std::sync::atomic::Ordering;
    // The head (wave one) names its predecessor node and its data pack, which
    // the second wave reads together, in that order.
    for gone_first in [true, false] {
        let (source, nodes, data) = long_chain(2, no_denial).await;
        source.store.sleep_ms.store(10, Ordering::SeqCst);
        source.store.waves.store(true, Ordering::SeqCst);
        let (node, pack) = (nodes[nodes.len() - 2], data[data.len() - 1]);
        let (gone, flaky) = if gone_first {
            (node, pack)
        } else {
            (pack, node)
        };
        drop_source_member(&source, gone).await;
        source
            .store
            .fail_keys
            .lock()
            .unwrap()
            .push(keys::published_member(&source.repo.name, &flaky));
        let outcome =
            mkit_server::fork::plan_fork(&env_denial(&source, false), &spec(&source, "forked"))
                .await;
        if gone_first {
            assert_eq!(outcome.unwrap_err(), mkit_server::fork::ForkError::NotFound);
        } else {
            assert!(
                matches!(outcome, Err(mkit_server::fork::ForkError::Unavailable(_))),
                "{outcome:?}"
            );
        }
        // Without waves the same members fail the same way: the allowance
        // changes how many reads overlap, not which failure is reported.
        source.store.waves.store(false, Ordering::SeqCst);
        let serial =
            mkit_server::fork::plan_fork(&env_denial(&source, false), &spec(&source, "forked"))
                .await;
        assert!(
            if gone_first {
                matches!(serial, Err(mkit_server::fork::ForkError::NotFound))
            } else {
                matches!(serial, Err(mkit_server::fork::ForkError::Unavailable(_)))
            },
            "{serial:?}"
        );
    }
}

#[tokio::test]
async fn a_start_refuses_a_plan_whose_source_pair_moved_and_leaves_nothing() {
    let source = Source::build_with("source", 6, no_denial).await;
    let env = env_denial(&source, false);
    let spec = spec(&source, "forked");
    let planned = mkit_server::fork::plan_fork(&env, &spec).await.unwrap();
    assert!(planned.is_some());
    // The source's membership generation moves (a lifecycle invalidation)
    // while its tip and packmap head stay: the plan is no longer the set the
    // pair publishes.
    let p = source.shards.ref_shard(&source.repo, "refs/heads/main");
    let sequence = mkit_server::store::adapter_spi::publication::sequence_ref("refs/heads/main");
    let key = keys::publication(&source.repo.name, &sequence);
    let mut row = mkit_server::store::adapter_spi::publication::read(
        source.store.inner.as_ref(),
        &p,
        &source.repo.name,
        "refs/heads/main",
    )
    .await
    .unwrap();
    row.generation += 1;
    source
        .store
        .inner
        .apply(
            &p,
            mkit_server::Batch::new().put(key, row.encode().unwrap()),
        )
        .await
        .unwrap();
    let refused = mkit_server::fork::start_planned(&env, &spec, None, None, planned)
        .await
        .unwrap_err();
    assert_eq!(refused, mkit_server::fork::ForkError::TipChanged);
    let dest_id = dest(&source, "forked");
    let coordinator = source.shards.coordinator(&dest_id.namespace);
    for key in [
        keys::fork_job(&dest_id.name),
        keys::repo_record(&dest_id.name),
    ] {
        assert!(
            source
                .store
                .inner
                .get(&coordinator, &key)
                .await
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(
        fork_timers(source.store.inner.as_ref(), &coordinator).await,
        0
    );
}

// The request reaches the absent guards first, but the timer commits first.
#[tokio::test]
async fn a_publish_guard_loser_continues_after_the_other_driver_finishes_once() {
    use std::sync::atomic::Ordering;
    let source = Arc::new(Source::build("source", 4).await);
    source.store.latency_ms.store(0, Ordering::SeqCst);
    let fork_env = env(&source);
    mkit_server::fork::start(&fork_env, &spec(&source, "forked"), None)
        .await
        .unwrap();
    let winner = source.clone();
    *source.store.trigger.lock().unwrap() = Some((
        "m",
        Arc::new(move || {
            let winner = winner.clone();
            Box::pin(async move {
                let job = drive(&env(&winner), &dest(&winner, "forked"))
                    .await
                    .unwrap();
                assert_eq!(job.phase, Phase::Done);
            })
        }),
    ));
    source.store.record.store(true, Ordering::SeqCst);
    let report =
        mkit_server::fork::step(&fork_env, &dest(&source, "forked"), &SliceBudget::new(600))
            .await
            .unwrap();
    assert_eq!(report.job.phase, Phase::Done);
    let done = source
        .store
        .committed
        .lock()
        .unwrap()
        .iter()
        .flat_map(|(_, batch)| &batch.writes)
        .filter(|write| {
            matches!(write, mkit_server::Write::Put(key, value)
            if *key == keys::fork_job(&dest(&source, "forked").name)
                && mkit_server::fork::decode_job(value).is_ok_and(|job| job.phase == Phase::Done))
        })
        .count();
    assert_eq!(done, 1);
}

#[tokio::test]
async fn a_publish_guard_loss_refuses_foreign_rows_and_retries_partial_witnesses() {
    use mkit_server::fork::ForkError;
    for (published, foreign) in [(false, true), (true, true), (false, false), (true, false)] {
        let source = Source::build("source", 4).await;
        let fork_env = env(&source);
        mkit_server::fork::start(&fork_env, &spec(&source, "forked"), None)
            .await
            .unwrap();
        let store = source.store.inner.clone();
        let id = dest(&source, "forked");
        let partition = source.shards.membership(&id, &BlobKey::pack(source.pack));
        let key = if published {
            keys::published_member(&id.name, &source.pack)
        } else {
            keys::membership(&id.name, &source.pack)
        };
        // A valid held witness is still foreign: matching generation and
        // sequence never substitutes for exact bytes. Exercise either row.
        let value = Witness {
            generation: mkit_server::fork::MEMBERSHIP_GENERATION,
            sequence: 0,
            published: true,
            held: foreign,
            boundary: false,
        }
        .encode();
        *source.store.trigger.lock().unwrap() = Some((
            "m",
            Arc::new(move || {
                let (store, partition, key, value) =
                    (store.clone(), partition.clone(), key.clone(), value.clone());
                Box::pin(async move {
                    store
                        .apply(&partition, mkit_server::Batch::new().put(key, value))
                        .await
                        .unwrap();
                })
            }),
        ));
        let result = drive(&fork_env, &id).await;
        if foreign {
            assert_eq!(
                result.unwrap_err(),
                ForkError::Unavailable("fork clearance pending")
            );
        } else {
            assert!(
                matches!(result, Err(ForkError::Unavailable("fork publish raced"))),
                "{result:?}"
            );
        }
        let job = job_of(&source, &id).await;
        assert_eq!(job.phase, Phase::Publish);
        assert!(job.accepted.is_some());
        assert!(job.result.is_none());
    }
}

#[tokio::test(start_paused = true)]
async fn an_activation_deadline_keeps_acceptance_and_redrives_without_publishing_the_head() {
    use mkit_server::fork::ForkError;
    use std::sync::atomic::Ordering;
    for waves in [true, false] {
        let source = long_source(2, no_denial).await;
        let fork_env = env_denial(&source, false);
        let request = spec(&source, "forked");
        let planned = mkit_server::fork::plan_fork(&fork_env, &request)
            .await
            .unwrap();
        mkit_server::fork::start_planned(&fork_env, &request, None, None, planned)
            .await
            .unwrap();
        let id = dest(&source, "forked");
        stop_at_fork_phase(&source, &fork_env, &id, Phase::Publish).await;
        let accepted = job_of(&source, &id).await.accepted.unwrap();
        source.store.waves.store(waves, Ordering::SeqCst);
        source.store.sleep_ms.store(10, Ordering::SeqCst);
        let clock = source.clock.clone();
        *source.store.trigger.lock().unwrap() = Some((
            "m",
            Arc::new(move || {
                let clock = clock.clone();
                Box::pin(async move {
                    clock.advance(10_001);
                })
            }),
        ));
        let outcome = drive(&fork_env, &id).await;
        assert!(
            matches!(
                outcome,
                Err(ForkError::Unavailable("fork publish deadline"))
            ),
            "{outcome:?}"
        );
        assert!(member(&source, &id, source.packmap).await.is_none());
        let pending = job_of(&source, &id).await;
        assert_eq!(pending.accepted, Some(accepted.clone()));
        assert!(pending.result.is_none());
        let done = drive(&fork_env, &id).await.unwrap();
        assert_eq!(done.result, Some(accepted));
    }
}

/// Stop on a committed phase boundary, including when its reply is lost.
async fn stop_at_fork_phase(
    source: &Source,
    fork_env: &ForkEnv<'_, Counting>,
    id: &RepoId,
    phase: Phase,
) {
    for _ in 0..100 {
        let job = job_of(source, id).await;
        if job.phase == phase {
            return;
        }
        assert!(!job.finished(), "fork ended before {phase:?}: {job:?}");
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
        let _ = mkit_server::fork::step(fork_env, id, &SliceBudget::new(600)).await;
    }
    panic!("fork did not reach {phase:?}");
}

#[tokio::test]
async fn a_fence_move_after_registration_aborts_before_acceptance_even_when_it_races_a_commit() {
    use mkit_server::fork::{Failure, FenceV1};
    use mkit_server::store::adapter_spi::codec::{self, AbortReason, ReservationV1};
    use std::sync::atomic::Ordering;
    for phase in [Phase::Copy, Phase::Count, Phase::Accept] {
        for authority in [true, false] {
            for absent in [true, false] {
                for race in [true, false] {
                    let source = Source::build("source", 4).await;
                    source.store.latency_ms.store(0, Ordering::SeqCst);
                    let id = dest(&source, "forked");
                    let coordinator = source.shards.coordinator(&id.namespace);
                    let key = if authority {
                        keys::authority_generation()
                    } else {
                        keys::grant_epoch()
                    };
                    let generation = if absent { 0 } else { 5 };
                    if !absent {
                        source
                            .store
                            .inner
                            .apply(
                                &coordinator,
                                mkit_server::Batch::new()
                                    .put(key.clone(), codec::encode_u64(generation)),
                            )
                            .await
                            .unwrap();
                    }
                    let settle = settlement::admit(&source, &id).await;
                    let fence = FenceV1 {
                        authority_generation: Some(if authority { generation } else { 0 }),
                        grant_epoch: Some(if authority { 0 } else { generation }),
                        create_namespace: true,
                    };
                    mkit_server::fork::start_with(
                        &env(&source),
                        &spec(&source, "forked"),
                        Some(settle),
                        Some(fence),
                    )
                    .await
                    .unwrap();
                    stop_at_fork_phase(&source, &env(&source), &id, phase).await;
                    let store = source.store.inner.clone();
                    let hook: Hook = Arc::new(move || {
                        let (store, coordinator, key) =
                            (store.clone(), coordinator.clone(), key.clone());
                        Box::pin(async move {
                            store
                                .apply(
                                    &coordinator,
                                    mkit_server::Batch::new()
                                        .put(key, codec::encode_u64(generation + 1)),
                                )
                                .await
                                .unwrap();
                        })
                    });
                    if race {
                        *source.store.trigger.lock().unwrap() = Some(("fj", hook));
                    } else {
                        hook().await;
                    }
                    let job = drive(&env(&source), &id).await.unwrap();
                    assert_eq!(
                        job.phase,
                        Phase::Failed,
                        "phase={phase:?} authority={authority} absent={absent} race={race}"
                    );
                    assert_eq!(
                        job.failure,
                        Some(if authority {
                            Failure::AuthorityMoved
                        } else {
                            Failure::EpochMoved
                        })
                    );
                    assert!(job.result.is_none());
                    assert!(member(&source, &id, source.pack).await.is_none());
                    assert!(matches!(
                        settlement::outcome(&source, &id).await,
                        ReservationV1::Aborted {
                            reason: AbortReason::EpochMismatch,
                            ..
                        }
                    ));
                }
            }
        }
    }
}

#[tokio::test]
async fn destination_membership_is_installed_only_after_a_durable_accepted_result() {
    let source = Arc::new(Source::build("source", 4).await);
    let id = dest(&source, "forked");
    mkit_server::fork::start(&env(&source), &spec(&source, "forked"), None)
        .await
        .unwrap();
    let observed = source.clone();
    *source.store.trigger.lock().unwrap() = Some((
        "m",
        Arc::new(move || {
            let observed = observed.clone();
            Box::pin(async move {
                let job = job_of(&observed, &dest(&observed, "forked")).await;
                assert!(
                    job.accepted.is_some(),
                    "reader-visible membership preceded guarded acceptance: {job:?}"
                );
            })
        }),
    ));
    assert_eq!(drive(&env(&source), &id).await.unwrap().phase, Phase::Done);
}

#[tokio::test]
async fn a_source_pair_change_during_membership_preparation_is_uniform_absence() {
    use mkit_server::store::adapter_spi::publication;
    let source = Source::build("source", 4).await;
    let id = dest(&source, "forked");
    mkit_server::fork::start(&env(&source), &spec(&source, "forked"), None)
        .await
        .unwrap();
    stop_at_fork_phase(&source, &env(&source), &id, Phase::Count).await;
    let partition = source.shards.ref_shard(&source.repo, "refs/heads/main");
    let sequence = publication::sequence_ref("refs/heads/main");
    let key = keys::publication(&source.repo.name, &sequence);
    let mut row = publication::read(
        source.store.inner.as_ref(),
        &partition,
        &source.repo.name,
        "refs/heads/main",
    )
    .await
    .unwrap();
    row.generation += 1;
    let store = source.store.inner.clone();
    let value = row.encode().unwrap();
    *source.store.trigger.lock().unwrap() = Some((
        "fj",
        Arc::new(move || {
            let (store, partition, key, value) =
                (store.clone(), partition.clone(), key.clone(), value.clone());
            Box::pin(async move {
                store
                    .apply(&partition, mkit_server::Batch::new().put(key, value))
                    .await
                    .unwrap();
            })
        }),
    ));
    let job = drive(&env(&source), &id).await.unwrap();
    assert_eq!(job.phase, Phase::Failed);
    assert_eq!(job.failure, Some(mkit_server::fork::Failure::NotFound));
    assert!(job.result.is_none());
    for pack in [source.pack, source.packmap] {
        assert!(member(&source, &id, pack).await.is_none());
    }
}

#[tokio::test]
async fn a_source_change_after_acceptance_does_not_change_the_saved_result_or_clearance() {
    let source = Source::build("source", 4).await;
    let id = dest(&source, "forked");
    let settle = settlement::admit(&source, &id).await;
    mkit_server::fork::start(&env(&source), &spec(&source, "forked"), Some(settle))
        .await
        .unwrap();
    stop_at_fork_phase(&source, &env(&source), &id, Phase::Publish).await;
    let accepted = job_of(&source, &id).await.accepted.unwrap();
    let outcome = settlement::outcome(&source, &id).await;
    for pack in [source.pack, source.packmap] {
        drop_source_member(&source, pack).await;
    }
    let done = drive(&env(&source), &id).await.unwrap();
    assert_eq!(done.phase, Phase::Done);
    assert_eq!(done.result, Some(accepted.clone()));
    assert_eq!(done.accepted, Some(accepted));
    assert_eq!(settlement::outcome(&source, &id).await, outcome);
    for pack in [source.pack, source.packmap] {
        assert!(member(&source, &id, pack).await.is_some());
    }
}

#[tokio::test]
async fn an_authority_move_at_the_physical_activation_commit_installs_no_member() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{Signer as _, SigningKey};
    use mkit_server::authority::{AuthorityFence, AuthorityKey, AuthorityScope};
    use mkit_server::fork::{FenceV1, ForkError};
    let source = Source::build("source", 4).await;
    let id = dest(&source, "forked");
    let settle = settlement::admit(&source, &id).await;
    mkit_server::fork::start_with(
        &env(&source),
        &spec(&source, "forked"),
        Some(settle),
        Some(FenceV1 {
            authority_generation: Some(0),
            grant_epoch: Some(0),
            create_namespace: true,
        }),
    )
    .await
    .unwrap();
    stop_at_fork_phase(&source, &env(&source), &id, Phase::Publish).await;
    let accepted = job_of(&source, &id).await.accepted.unwrap();
    let outcome = settlement::outcome(&source, &id).await;
    let signer = SigningKey::from_bytes(&[19; 32]);
    let mut config = Source::config(source.namespace);
    config.authorizer_role = mkit_server::policy::AuthorizerRole::Authority;
    config.authority_fence = Some(
        AuthorityFence::new(vec![AuthorityKey {
            key_id: "deployment".into(),
            public_key: *signer.verifying_key().as_bytes(),
            scope: AuthorityScope::Exact(
                [mkit_server::namespace::Namespace::SelfCertifying(
                    source.namespace,
                )]
                .into(),
            ),
        }])
        .unwrap(),
    );
    struct Authority;
    impl mkit_server::pipeline::Authorizer for Authority {
        async fn authorize(
            &self,
            _: &mkit_server::Operation,
        ) -> Result<mkit_server::AuthzFacts, mkit_server::ServerError> {
            let mut facts = mkit_server::AuthzFacts::default();
            facts.authority_generation = Some(0);
            Ok(facts)
        }
    }
    let defaults = mkit_server::pipeline::Hooks::new();
    let hooks = mkit_server::pipeline::Hooks {
        authorizer: Authority,
        admission: defaults.admission,
        pre_receive: defaults.pre_receive,
        receipts: defaults.receipts,
        outcomes: defaults.outcomes,
    };
    let setter = Arc::new(
        mkit_server::pipeline::Pipeline::new(
            source.blobs.clone(),
            source.store.clone(),
            hooks,
            config,
            source.clock.clone(),
            Arc::new(mkit_server::NoopMetrics),
        )
        .unwrap(),
    );
    let clock = source.clock.clone();
    let namespace = source.namespace.to_string();
    *source.store.trigger.lock().unwrap() = Some((
        "m",
        Arc::new(move || {
            let (setter, clock, namespace, signer) = (
                setter.clone(),
                clock.clone(),
                namespace.clone(),
                signer.clone(),
            );
            Box::pin(async move {
                let now = clock.now_ms();
                let body = format!(
                    "mkit-authority-generation:v1\ndeployment\n{namespace}\n1\n{AUDIENCE}\n{now}\n{}\n{}",
                    now + 240_000,
                    "01".repeat(32)
                );
                let signature = signer.sign(&mkit_core::hash::hash(body.as_bytes()));
                let wire = format!(
                    "{}.{}",
                    URL_SAFE_NO_PAD.encode(body),
                    URL_SAFE_NO_PAD.encode(signature.to_bytes())
                );
                for _ in 0..64 {
                    match setter.set_authority_generation(&wire).await {
                        Ok(generation) => {
                            assert_eq!(generation, 1);
                            return;
                        }
                        Err(error) if error.code() == mkit_server::Code::Unavailable => {}
                        Err(error) => panic!("authority move refused: {error:?}"),
                    }
                }
                panic!("authority move did not acknowledge its drained generation");
            })
        }),
    ));
    assert_eq!(
        drive(&env(&source), &id).await.unwrap_err(),
        ForkError::Moved("authority")
    );
    assert_eq!(job_of(&source, &id).await.accepted, Some(accepted));
    assert_eq!(settlement::outcome(&source, &id).await, outcome);
    for pack in [source.pack, source.packmap] {
        assert!(
            member(&source, &id, pack).await.is_none(),
            "an activation membership write committed after the authority moved"
        );
    }
}

#[tokio::test]
async fn every_coordinator_progress_commit_compares_the_recorded_authority_rows() {
    use mkit_server::fork::FenceV1;
    use mkit_server::store::adapter_spi::codec;
    use mkit_server::{Precondition, Write};
    use std::sync::atomic::Ordering;
    for absent in [true, false] {
        let source = Source::build("source", 4).await;
        let id = dest(&source, "forked");
        let coordinator = source.shards.coordinator(&id.namespace);
        let expected = codec::encode_u64(5);
        if !absent {
            source
                .store
                .inner
                .apply(
                    &coordinator,
                    mkit_server::Batch::new()
                        .put(keys::authority_generation(), expected.clone())
                        .put(keys::grant_epoch(), expected.clone()),
                )
                .await
                .unwrap();
        }
        let generation = if absent { 0 } else { 5 };
        mkit_server::fork::start_with(
            &env(&source),
            &spec(&source, "forked"),
            None,
            Some(FenceV1 {
                authority_generation: Some(generation),
                grant_epoch: Some(generation),
                create_namespace: true,
            }),
        )
        .await
        .unwrap();
        source.store.record.store(true, Ordering::SeqCst);
        assert_eq!(drive(&env(&source), &id).await.unwrap().phase, Phase::Done);
        let mut phases = Vec::new();
        for (partition, batch) in source.store.committed.lock().unwrap().iter() {
            let advancing = batch.writes.iter().find_map(|write| match write {
                Write::Put(key, value) if *key == keys::fork_job(&id.name) => {
                    Some(mkit_server::fork::decode_job(value).unwrap())
                }
                _ => None,
            });
            let Some(job) = advancing else {
                continue;
            };
            assert_eq!(partition, &coordinator);
            phases.push(job.phase);
            for key in [keys::authority_generation(), keys::grant_epoch()] {
                let guard = if absent {
                    Precondition::Absent(key)
                } else {
                    Precondition::Equals(key, expected.clone())
                };
                assert!(
                    batch.preconditions.contains(&guard),
                    "missing {guard:?} at {:?}",
                    job.phase
                );
            }
        }
        for phase in [
            Phase::Trees,
            Phase::Walk,
            Phase::Register,
            Phase::Copy,
            Phase::Count,
            Phase::Accept,
            Phase::Publish,
            Phase::Done,
        ] {
            assert!(phases.contains(&phase), "unobserved {phase:?}: {phases:?}");
        }
    }
}

#[tokio::test]
async fn a_source_policy_change_before_acceptance_is_uniform_absence() {
    use mkit_server::store::adapter_spi::codec::{self, RepoVisibilityV1, StoredVisibility};
    for visibility in [true, false] {
        let source = Source::build("source", 4).await;
        let id = dest(&source, "forked");
        mkit_server::fork::start(&env(&source), &spec(&source, "forked"), None)
            .await
            .unwrap();
        stop_at_fork_phase(&source, &env(&source), &id, Phase::Accept).await;
        let (key, value) = if visibility {
            (
                keys::repo_visibility(&source.repo.name),
                codec::encode_repo_visibility(&RepoVisibilityV1 {
                    visibility: StoredVisibility::Private,
                    last_created_ms: u64::try_from(source.clock.now_ms()).unwrap(),
                    last_statement_id: Some("ab".repeat(32)),
                    changed_ms: u64::try_from(source.clock.now_ms()).unwrap(),
                }),
            )
        } else {
            (
                keys::repo_visibility_revision(&source.repo.name),
                codec::encode_u64(1),
            )
        };
        source
            .store
            .inner
            .apply(
                &source.shards.coordinator(&source.repo.namespace),
                mkit_server::Batch::new().put(key, value),
            )
            .await
            .unwrap();
        let job = drive(&env(&source), &id).await.unwrap();
        assert_eq!(job.phase, Phase::Failed);
        assert_eq!(job.failure, Some(mkit_server::fork::Failure::NotFound));
        assert!(job.accepted.is_none());
        for pack in [source.pack, source.packmap] {
            assert!(member(&source, &id, pack).await.is_none());
        }
    }
}

#[tokio::test]
async fn accepted_clearance_outlives_construction_expiry_without_resettling() {
    use mkit_server::store::adapter_spi::codec::ReservationV1;
    let source = Source::build("source", 4).await;
    let id = dest(&source, "forked");
    let fork_env = env(&source);
    let settle = settlement::admit(&source, &id).await;
    mkit_server::fork::start(&fork_env, &spec(&source, "forked"), Some(settle))
        .await
        .unwrap();
    stop_at_fork_phase(&source, &fork_env, &id, Phase::Publish).await;
    let accepted = job_of(&source, &id).await;
    let saved = accepted.accepted.as_ref().unwrap();
    let result_bytes = serde_json::to_vec(saved).unwrap();
    assert!(accepted.result.is_none());
    assert!(matches!(
        settlement::outcome(&source, &id).await,
        ReservationV1::Committed { .. }
    ));
    for pack in accepted.packs.iter().map(|pack| pack.id) {
        assert!(member(&source, &id, pack).await.is_none());
    }
    let coordinator = source.shards.coordinator(&id.namespace);
    let barrier = keys::fork_barrier(&id.name);
    assert_eq!(
        source
            .store
            .inner
            .get(&coordinator, &barrier)
            .await
            .unwrap(),
        Some(mkit_server::Value::new(accepted.binding.to_vec()))
    );
    // Byte-for-byte settlement, replay, quota and outcome counters must survive
    // clearance unchanged; another settlement would move at least one counter.
    let scope = mkit_server::quota::QuotaScope::for_signer(&id.namespace, &[1; 32]);
    let settled_keys = [
        keys::reservation(settlement::RID).unwrap(),
        keys::replay(&[3; 32]),
        keys::quota(&scope),
        keys::outbox_sequence(),
        keys::outcome_backlog(),
    ];
    let settled = source
        .store
        .inner
        .get_many(&coordinator, &settled_keys)
        .await
        .unwrap();
    assert!(settled.iter().all(Option::is_some));
    let expired_at = i64::try_from(accepted.expires_ms).unwrap() + 1;
    source.clock.advance(expired_at - source.clock.now_ms());
    assert!(u64::try_from(source.clock.now_ms()).unwrap() > accepted.expires_ms);
    let done = drive(&fork_env, &id).await.unwrap();
    assert_eq!(done.phase, Phase::Done);
    assert_eq!(done.accepted.as_ref(), Some(saved));
    assert_eq!(
        serde_json::to_vec(done.result.as_ref().unwrap()).unwrap(),
        result_bytes
    );
    assert_eq!(
        source
            .store
            .inner
            .get_many(&coordinator, &settled_keys)
            .await
            .unwrap(),
        settled
    );
    assert!(
        source
            .store
            .inner
            .get(&coordinator, &barrier)
            .await
            .unwrap()
            .is_none(),
        "published clearance opens destination writes"
    );
    for pack in accepted.packs.iter().map(|pack| pack.id) {
        assert!(member(&source, &id, pack).await.is_some());
    }
}

#[tokio::test]
async fn activation_refuses_empty_immediate_membership_instead_of_adopting_semantic_aliases() {
    use mkit_server::fork::ForkError;
    for after_guard_loss in [false, true] {
        let source = Source::build("source", 4).await;
        let fork_env = env(&source);
        let id = dest(&source, "forked");
        mkit_server::fork::start(&fork_env, &spec(&source, "forked"), None)
            .await
            .unwrap();
        stop_at_fork_phase(&source, &fork_env, &id, Phase::Publish).await;
        let accepted = job_of(&source, &id).await.accepted.unwrap();
        assert_ne!(source.pack, accepted.packmap);
        let store = source.store.inner.clone();
        let partition = source.shards.membership(&id, &BlobKey::pack(source.pack));
        let live = keys::membership(&id.name, &source.pack);
        let published = keys::published_member(&id.name, &source.pack);
        if after_guard_loss {
            *source.store.trigger.lock().unwrap() = Some((
                "m",
                Arc::new(move || {
                    let (store, partition, live) = (store.clone(), partition.clone(), live.clone());
                    Box::pin(async move {
                        store
                            .apply(
                                &partition,
                                mkit_server::Batch::new().put(live, mkit_server::Value::default()),
                            )
                            .await
                            .unwrap();
                    })
                }),
            ));
        } else {
            store
                .apply(
                    &partition,
                    mkit_server::Batch::new()
                        .put(live, mkit_server::Value::default())
                        .put(published, mkit_server::Value::default()),
                )
                .await
                .unwrap();
        }
        assert_eq!(
            drive(&fork_env, &id).await.unwrap_err(),
            ForkError::Unavailable("fork clearance pending"),
            "after_guard_loss={after_guard_loss}"
        );
        let job = job_of(&source, &id).await;
        assert_eq!(job.accepted.as_ref(), Some(&accepted));
        assert!(job.result.is_none());
    }
}
