//! Final source proofs must not combine incompatible eligibility observations.
#![cfg(feature = "memory")]
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
mod fork_support;

use fork_support::{Counting, Source, tree_pack};
use mkit_attest::grant::Visibility;
use mkit_core::hash::Hash;
use mkit_server::fork::{ForkEnv, ForkLimits, ForkSpec, Phase};
use mkit_server::store::adapter_spi::keys;
use mkit_server::store::{BlockEntry, ContentIndex};
use mkit_server::{
    Batch, BatchOutcome, Clock, Cursor, Key, NamespaceStore, Partition, PartitionStats, ScanPage,
    StoreCapabilities, StoreError, Value, Write, budget::SliceBudget,
};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

/// Stop immediately after preparation commits, with an ancestor's data pack
/// already denied before that staging commit. All changes use block APIs.
struct StopAfterPreparation {
    store: Counting,
    capability: mkit_server::takedown::DenialCapability,
    initially_denied: Hash,
    stopped: AtomicBool,
    cut_before: Mutex<Option<(Key, SliceBudget)>>,
}

impl NamespaceStore for StopAfterPreparation {
    async fn probe(&self) -> Result<(), StoreError> {
        self.store.probe().await
    }
    fn capabilities(&self) -> StoreCapabilities {
        self.store.capabilities()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        let cut = {
            let mut pending = self.cut_before.lock().unwrap();
            if pending.as_ref().is_some_and(|(wanted, _)| wanted == key) {
                pending.take()
            } else {
                None
            }
        };
        if let Some((_, budget)) = cut {
            // Cut at the second proof, independently of the first proof's
            // backend-call cost. This models a slice spending its allowance.
            budget.charge_many(budget.remaining()).unwrap();
            assert!(budget.charge_many(1).is_err());
            return Err(StoreError::Unavailable("cut before second proof".into()));
        }
        self.store.get(p, key).await
    }
    async fn get_many(
        &self,
        p: &Partition,
        wanted: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        self.store.get_many(p, wanted).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.store.scan(p, start, end, after, limit).await
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.store.stats(p).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        let preparing = batch.writes.iter().find_map(|write| match write {
            Write::Put(key, value)
                if matches!(keys::parse(key), Some(keys::ParsedKey::ForkJob(_))) =>
            {
                mkit_server::fork::decode_job(value)
                    .ok()
                    .filter(|job| job.phase == Phase::Accept)
            }
            _ => None,
        });
        if let Some(job) = preparing
            && !self.stopped.swap(true, Ordering::SeqCst)
        {
            assert_eq!(job.packs.len(), 4);
            let now = u64::try_from(self.store.clock.now_ms()).unwrap();
            ContentIndex::new(self.store.inner.clone())
                .block(
                    &self.capability,
                    &self.initially_denied,
                    &BlockEntry::new("oldest data pack denied", now),
                    now,
                )
                .await?;
            assert_eq!(self.store.apply(p, batch).await?, BatchOutcome::Committed);
            return Err(StoreError::Unavailable("stopped after preparation".into()));
        }
        self.store.apply(p, batch).await
    }
}

async fn block(source: &Source, pack: &Hash) {
    let now = u64::try_from(source.clock.now_ms()).unwrap();
    ContentIndex::new(source.store.inner.clone())
        .block(
            &source.pipe.denial_capability().unwrap(),
            pack,
            &BlockEntry::new("first pack denied", now),
            now,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn final_source_proof_cannot_resume_across_disjoint_pack_eligibility() {
    let mut source = Source::build_with("source", 4, |mut config| {
        config.takedown_denial = true;
        config
    })
    .await;
    source.store.latency_ms.store(0, Ordering::SeqCst);
    let initially_denied = source.pack;
    let (bytes, head, _) = tree_pack(3, 8, 1_000, vec![source.head], b"more");
    let latest_data = mkit_core::hash::hash(&bytes);
    let previous = source.packmap;
    let latest_map = source
        .push(bytes, head, Some(previous), &[latest_data])
        .await;
    source.head = head;
    source.packmap = latest_map;
    let destination = source.at("destination").repo;
    let spec = ForkSpec {
        source: source.repo.clone(),
        source_ref: "refs/heads/main".into(),
        expected_tip: source.head,
        dest: destination.clone(),
        dest_visibility: Visibility::Public,
    };
    let stop = StopAfterPreparation {
        store: source.store.clone(),
        capability: source.pipe.denial_capability().unwrap(),
        initially_denied,
        stopped: AtomicBool::new(false),
        cut_before: Mutex::new(None),
    };
    let environment = ForkEnv {
        publication_policy: None,
        store: &stop,
        shards: source.shards.as_ref(),
        clock: source.clock.as_ref(),
        takedown_denial: true,
        extract_min_bytes: None,
        limits: ForkLimits::default(),
    };
    mkit_server::fork::start(&environment, &spec, None)
        .await
        .unwrap();
    for _ in 0..20 {
        if mkit_server::fork::step(&environment, &destination, &SliceBudget::new(600))
            .await
            .is_err()
        {
            break;
        }
    }
    assert!(stop.stopped.load(Ordering::SeqCst));
    let prepared = mkit_server::fork::read_job(&source.store, source.shards.as_ref(), &destination)
        .await
        .unwrap()
        .unwrap()
        .0;
    assert_eq!(prepared.phase, Phase::Accept);
    assert_eq!(prepared.cursor, 0);
    let [first, second] = [prepared.packs[0].id, prepared.packs[1].id];
    // Give the first proof a whole allowance, then cut exactly before the
    // second proof. Its durable cursor must survive the exhausted slice.
    let proof_budget = SliceBudget::new(600);
    *stop.cut_before.lock().unwrap() = Some((
        keys::published_member(&source.repo.name, &second),
        proof_budget.clone(),
    ));
    let report = mkit_server::fork::step(&environment, &destination, &proof_budget)
        .await
        .unwrap();
    assert_eq!(
        report.job.phase,
        Phase::Accept,
        "first proof refused: {:?}; first={first:?}; second={second:?}; packmap={:?}",
        report.job.failure,
        prepared.packmap
    );
    assert_eq!(
        report.job.cursor, 1,
        "first proof checkpoint: {:?}",
        report.job
    );
    assert!(report.job.accepted.is_none());
    // The head packmap directly names its predecessor and newest data, so
    // the oldest data denial does not invalidate this first proof. Never
    // allow the complete chain simultaneously: stop the head before releasing
    // the oldest data. Pair/generation/visibility do not change.
    block(&source, &first).await;
    ContentIndex::new(source.store.inner.clone())
        .unblock(
            &initially_denied,
            u64::try_from(source.clock.now_ms()).unwrap(),
        )
        .await
        .unwrap();
    let _ = mkit_server::fork::step(&environment, &destination, &SliceBudget::new(600)).await;
    let finished = mkit_server::fork::read_job(&source.store, source.shards.as_ref(), &destination)
        .await
        .unwrap()
        .unwrap()
        .0;
    assert!(
        finished.accepted.is_none(),
        "accepted a source whose complete inherited set was never eligible after staging"
    );
}
