use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::memory::MemoryKv;
use crate::pipeline::{D34Shards, SinglePartition};
use crate::repo::{NamespaceKey, RepoName};
use crate::store::{Cursor, Key, PartitionStats, ScanPage, StoreCapabilities};

fn repo() -> RepoId {
    RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("registry").unwrap(),
    }
}
fn install(id: u8) -> FlagInstall {
    FlagInstall {
        id: [id; 32],
        reason: "review needed".into(),
        source: FlagSource {
            inspector: "scanner".into(),
            inspection_id: format!("inspection-{id}"),
            ref_name: "refs/heads/main".into(),
            sequence: 1,
        },
    }
}
fn record() -> FlagV1 {
    FlagV1::new(install(1)).unwrap()
}

#[test]
fn strict_versioned_codec_rejects_malformed_and_unknown_fields() {
    let record = record();
    let encoded = encode_flag(&record).unwrap();
    assert_eq!(encoded.as_bytes()[0], 1);
    assert_eq!(decode_flag(&encoded).unwrap(), record);
    let mut json = serde_json::to_value(&record).unwrap();
    for value in [
        Value::new(Vec::new()),
        Value::new(vec![2]),
        Value::new(vec![1, b'{']),
    ] {
        assert!(matches!(decode_flag(&value), Err(StoreError::Corrupt(_))));
    }
    let decode_json = |json: &serde_json::Value| {
        decode_flag(&Value::new(
            [vec![1], serde_json::to_vec(json).unwrap()].concat(),
        ))
    };
    json["extra"] = true.into();
    assert!(decode_json(&json).is_err());
    json.as_object_mut().unwrap().remove("extra");
    json["source"]["extra"] = true.into();
    assert!(decode_json(&json).is_err());
    json["source"].as_object_mut().unwrap().remove("extra");
    json["state"] = "unknown".into();
    assert!(decode_json(&json).is_err());
    json["state"] = "flagged".into();
    json["source"]["sequence"] = 0.into();
    assert!(decode_json(&json).is_err());
    json["source"]["sequence"] = 1.into();
    json["reason"] = "".into();
    assert!(decode_json(&json).is_err());
}

#[tokio::test]
async fn idempotent_install_release_and_new_inspection_on_single_and_d34() {
    let repo = repo();
    for shards in [
        &SinglePartition as &dyn ShardMap,
        &D34Shards as &dyn ShardMap,
    ] {
        let store = MemoryKv::default();
        let registry = InspectionFlags::new(&store, shards, &repo);
        assert_eq!(registry.version().await.unwrap(), 0);
        assert_eq!(
            registry
                .install_flags(&[install(1), install(2)])
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            registry
                .install_flags(&[install(1), install(2)])
                .await
                .unwrap(),
            2
        );
        let lookup = registry.lookup(&[[2; 32], [3; 32], [1; 32]]).await.unwrap();
        assert_eq!(lookup.version, 2);
        assert_eq!(
            lookup.flagged.iter().map(|f| f.id).collect::<Vec<_>>(),
            vec![[2; 32], [1; 32]]
        );
        assert_eq!(registry.release_flag(&[1; 32]).await.unwrap(), 3);
        assert_eq!(registry.release_flag(&[1; 32]).await.unwrap(), 3);
        assert_eq!(registry.release_flag(&[3; 32]).await.unwrap(), 3);
        assert_eq!(
            registry.install_flags(&[install(1)]).await.unwrap(),
            3,
            "released source replay cannot reinstall"
        );
        let mut fresh = install(1);
        fresh.source.inspection_id = "deliberate-reinspection".into();
        assert_eq!(registry.install_flags(&[fresh]).await.unwrap(), 4);
        let expected = shards.object_index(&repo, &[0; 32]);
        assert!(
            store
                .get(&expected, &keys::inspection_flag(&repo.name, &[1; 32]))
                .await
                .unwrap()
                .is_some()
        );
        if matches!(expected, Partition::RepoIndex { .. }) {
            let ordinary = shards.object_index(&repo, &[0x10; 32]);
            assert_ne!(ordinary, expected);
            assert!(
                store
                    .get(&ordinary, &keys::inspection_flag(&repo.name, &[1; 32]))
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }
}

#[tokio::test]
async fn bounds_op_count_and_invalid_requests_do_not_write() {
    let store = MemoryKv::default();
    let repo = repo();
    let registry = InspectionFlags::new(&store, &SinglePartition, &repo);
    let maximum: Vec<_> = (1..=u8::try_from(MAX_FLAG_IDS).unwrap())
        .map(install)
        .collect();
    assert_eq!(registry.install_flags(&maximum).await.unwrap(), 48);
    let ids: Vec<_> = maximum.iter().map(|r| r.id).collect();
    assert_eq!(registry.lookup(&ids).await.unwrap().flagged.len(), 48);
    assert_eq!(2 * MAX_FLAG_IDS + 2, 98);
    let mut too_many = maximum;
    too_many.push(install(49));
    assert!(matches!(
        registry.install_flags(&too_many).await,
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        registry.lookup(&vec![[0; 32]; 49]).await,
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        registry.install_flags(&[install(1), install(1)]).await,
        Err(StoreError::Invalid(_))
    ));
    let mut malformed = install(50);
    malformed.reason.clear();
    assert!(matches!(
        registry.install_flags(&[malformed]).await,
        Err(StoreError::Invalid(_))
    ));
    assert_eq!(registry.version().await.unwrap(), 48);
    assert!(registry.lookup(&[]).await.unwrap().flagged.is_empty());
}

#[tokio::test]
async fn corrupt_rows_and_counter_fail_closed() {
    let repo = repo();
    let store = MemoryKv::default();
    let partition = SinglePartition.object_index(&repo, &[0; 32]);
    let registry = InspectionFlags::new(&store, &SinglePartition, &repo);
    for version in [
        Value::new(vec![1]),
        codec::encode_u64(0),
        codec::encode_u64(u64::MAX),
    ] {
        store
            .apply(
                &partition,
                Batch::new().put(keys::inspection_version(&repo.name), version),
            )
            .await
            .unwrap();
        assert!(matches!(
            registry.install_flags(&[install(1)]).await,
            Err(StoreError::Corrupt(_))
        ));
    }
    store
        .apply(
            &partition,
            Batch::new()
                .put(keys::inspection_version(&repo.name), codec::encode_u64(1))
                .put(
                    keys::inspection_flag(&repo.name, &[2; 32]),
                    encode_flag(&record()).unwrap(),
                ),
        )
        .await
        .unwrap();
    assert!(matches!(
        registry.lookup(&[[2; 32]]).await,
        Err(StoreError::Corrupt(_))
    ));
    assert!(matches!(
        registry.release_flag(&[2; 32]).await,
        Err(StoreError::Corrupt(_))
    ));
    store
        .apply(
            &partition,
            Batch::new()
                .delete(keys::inspection_version(&repo.name))
                .delete(keys::inspection_flag(&repo.name, &[2; 32]))
                .put(
                    keys::inspection_flag(&repo.name, &[1; 32]),
                    encode_flag(&record()).unwrap(),
                ),
        )
        .await
        .unwrap();
    assert!(matches!(
        registry.lookup(&[[1; 32]]).await,
        Err(StoreError::Corrupt(_))
    ));
    assert!(matches!(
        registry.release_flag(&[1; 32]).await,
        Err(StoreError::Corrupt(_))
    ));
    assert!(
        store
            .get(&partition, &keys::inspection_version(&repo.name))
            .await
            .unwrap()
            .is_none()
    );
}

// A competing registry operation commits after the caller has read its
// snapshot, either during its apply or midway through default get_many.
// All rival writes use the production API on the same underlying store.
enum Rival {
    Install(u8),
    Release(u8),
}
struct RacingStore {
    inner: MemoryKv,
    rival: Mutex<Option<Rival>>,
    after_read: bool,
    failures: AtomicUsize,
}
impl RacingStore {
    fn new(after_read: bool) -> Self {
        Self {
            inner: MemoryKv::default(),
            rival: Mutex::new(None),
            after_read,
            failures: AtomicUsize::new(0),
        }
    }
    fn arm(&self, rival: Rival) {
        *self.rival.lock().unwrap() = Some(rival);
    }
    async fn race(&self) {
        let rival = self.rival.lock().unwrap().take();
        let repo = repo();
        let registry = InspectionFlags::new(&self.inner, &SinglePartition, &repo);
        match rival {
            Some(Rival::Install(id)) => {
                registry.install_flags(&[install(id)]).await.unwrap();
            }
            Some(Rival::Release(id)) => {
                registry.release_flag(&[id; 32]).await.unwrap();
            }
            None => {}
        }
    }
}
impl NamespaceStore for RacingStore {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        let result = self.inner.get(p, key).await?;
        if self.after_read && key.as_bytes().starts_with(b"if\0") {
            self.race().await;
        }
        Ok(result)
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.inner.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        if !self.after_read {
            self.race().await;
        }
        let result = self.inner.apply(p, batch).await?;
        if matches!(result, BatchOutcome::PreconditionFailed { .. }) {
            self.failures.fetch_add(1, Ordering::SeqCst);
        }
        Ok(result)
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

#[tokio::test]
async fn concurrent_install_and_release_cas_losers_retry() {
    let store = RacingStore::new(false);
    let repo = repo();
    let registry = InspectionFlags::new(&store, &SinglePartition, &repo);
    registry.install_flags(&[install(1)]).await.unwrap();
    store.arm(Rival::Release(1));
    assert_eq!(registry.install_flags(&[install(2)]).await.unwrap(), 3);
    assert_eq!(store.failures.load(Ordering::SeqCst), 1);
    let lookup = registry.lookup(&[[1; 32], [2; 32]]).await.unwrap();
    assert_eq!(lookup.flagged.len(), 1);
    assert_eq!(lookup.flagged[0].id, [2; 32]);
    store.arm(Rival::Install(3));
    assert_eq!(registry.release_flag(&[2; 32]).await.unwrap(), 5);
    assert_eq!(store.failures.load(Ordering::SeqCst), 2);
    assert_eq!(
        registry.lookup(&[[2; 32], [3; 32]]).await.unwrap().flagged[0].id,
        [3; 32]
    );
}

#[tokio::test]
async fn sequential_lookup_validates_version_and_retries_mixed_reads() {
    let store = RacingStore::new(true);
    let repo = repo();
    let registry = InspectionFlags::new(&store, &SinglePartition, &repo);
    registry
        .install_flags(&[install(1), install(2)])
        .await
        .unwrap();
    store.arm(Rival::Release(1));
    let result = registry.lookup(&[[1; 32], [2; 32]]).await.unwrap();
    assert_eq!(result.version, 3);
    assert_eq!(result.flagged.len(), 1);
    assert_eq!(result.flagged[0].id, [2; 32]);
    assert_eq!(store.failures.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn racing_first_install_retries_stale_absent_version() {
    let repo = repo();
    for mutate in [false, true] {
        let store = RacingStore::new(true);
        let registry = InspectionFlags::new(&store, &SinglePartition, &repo);
        store.arm(Rival::Install(2));
        if mutate {
            assert_eq!(
                registry
                    .install_flags(&[install(1), install(2)])
                    .await
                    .unwrap(),
                2
            );
        } else {
            let result = registry.lookup(&[[1; 32], [2; 32]]).await.unwrap();
            assert_eq!(result.version, 1);
            assert_eq!(result.flagged[0].id, [2; 32]);
        }
        assert_eq!(store.failures.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn unseen_verdict_while_flagged_is_remembered_across_release() {
    let repo = repo();
    for shards in [
        &SinglePartition as &dyn ShardMap,
        &D34Shards as &dyn ShardMap,
    ] {
        let store = MemoryKv::default();
        let registry = InspectionFlags::new(&store, shards, &repo);
        let a = install(1);
        let mut b = a.clone();
        b.source.inspection_id = "independent-b".into();
        assert_eq!(
            registry
                .install_flags(std::slice::from_ref(&a))
                .await
                .unwrap(),
            1
        );
        assert_eq!(registry.install_flags(&[b.clone()]).await.unwrap(), 2);
        let before = registry.lookup(&[a.id]).await.unwrap();
        assert_eq!(
            before.flagged[0].source, a.source,
            "preserve original active review source"
        );
        assert_eq!(before.flagged[0].seen_sources.len(), 2);
        assert_eq!(registry.release_flag(&a.id).await.unwrap(), 3);
        assert_eq!(registry.install_flags(&[b]).await.unwrap(), 3);
        assert!(registry.lookup(&[a.id]).await.unwrap().flagged.is_empty());
    }
}

#[tokio::test]
async fn old_verdict_cannot_reflag_after_two_released_inspections() {
    let store = MemoryKv::default();
    let repo = repo();
    let registry = InspectionFlags::new(&store, &SinglePartition, &repo);
    let a = install(1);
    let mut b = a.clone();
    b.source.inspection_id = "deliberate-b".into();
    assert_eq!(
        registry
            .install_flags(std::slice::from_ref(&a))
            .await
            .unwrap(),
        1
    );
    assert_eq!(registry.release_flag(&a.id).await.unwrap(), 2);
    assert_eq!(registry.install_flags(&[b.clone()]).await.unwrap(), 3);
    assert_eq!(registry.release_flag(&b.id).await.unwrap(), 4);
    assert_eq!(registry.install_flags(&[a]).await.unwrap(), 4);
    assert_eq!(registry.install_flags(&[b]).await.unwrap(), 4);
    assert!(
        registry
            .lookup(&[[1; 32]])
            .await
            .unwrap()
            .flagged
            .is_empty()
    );
}

#[tokio::test]
async fn source_history_is_strict_and_exhaustion_is_atomic() {
    let mut record = record();
    record.seen_sources = (0..MAX_FLAG_SOURCES)
        .map(|n| {
            let mut source = record.source.clone();
            source.inspection_id = format!("origin-{n}");
            source_id(&source)
        })
        .collect();
    record.seen_sources[0] = source_id(&record.source);
    record.seen_sources.sort_unstable();
    assert!(encode_flag(&record).is_ok());
    let store = MemoryKv::default();
    let repo = repo();
    let partition = SinglePartition.object_index(&repo, &[0; 32]);
    store
        .apply(
            &partition,
            Batch::new()
                .put(
                    keys::inspection_version(&repo.name),
                    codec::encode_u64(1024),
                )
                .put(
                    keys::inspection_flag(&repo.name, &record.id),
                    encode_flag(&record).unwrap(),
                ),
        )
        .await
        .unwrap();
    let registry = InspectionFlags::new(&store, &SinglePartition, &repo);
    let mut novel = install(1);
    novel.source.inspection_id = "unseen-overflow".into();
    assert!(matches!(
        registry.install_flags(&[install(2), novel]).await,
        Err(StoreError::Invalid(_))
    ));
    assert_eq!(registry.version().await.unwrap(), 1024);
    assert!(
        registry
            .lookup(&[[2; 32]])
            .await
            .unwrap()
            .flagged
            .is_empty()
    );
    assert_eq!(
        registry.install_flags(&[install(1)]).await.unwrap(),
        1024,
        "known source remains idempotent at capacity"
    );
    for invalid in [
        Vec::new(),
        vec![source_id(&record.source); 2],
        vec![[255; 32], [0; 32]],
        vec![[0; 32]],
    ] {
        record.seen_sources = invalid;
        let raw = Value::new([vec![1], serde_json::to_vec(&record).unwrap()].concat());
        assert!(matches!(decode_flag(&raw), Err(StoreError::Corrupt(_))));
    }
}
