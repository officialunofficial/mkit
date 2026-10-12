// Fixture setup must fail immediately; node ids are small test indexes.
#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]
//! Ordered, reserved dependency waves and independent directory reads.
use super::*;
use crate::store::{BatchOutcome, Cursor, Partition, PartitionStats, ScanPage, StoreCapabilities};
use crate::{Batch, MemoryKv, NamespaceKey, RepoName};
use futures_executor::block_on;
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[derive(Clone, Copy, Default)]
enum Reply {
    #[default]
    Missing,
    Blocked,
    Corrupt,
    Dead,
    Capped,
}
struct Probe {
    inner: MemoryKv,
    calls: Mutex<Vec<Hash>>,
    completed: Mutex<Vec<Hash>>,
    replies: BTreeMap<Hash, Reply>,
    active: AtomicUsize,
    peak: AtomicUsize,
    scan_error: bool,
    descriptor_bad: bool,
    charged: Option<SliceBudget>,
    dispatch_charges: Mutex<Vec<u32>>,
}
impl Probe {
    fn new() -> Self {
        Self {
            inner: MemoryKv::default(),
            calls: Mutex::default(),
            completed: Mutex::default(),
            replies: BTreeMap::new(),
            active: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            scan_error: false,
            descriptor_bad: false,
            charged: None,
            dispatch_charges: Mutex::default(),
        }
    }
    async fn hold(&self, ticks: usize) {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(active, Ordering::SeqCst);
        let mut left = ticks;
        futures::future::poll_fn(|cx| {
            if left == 0 {
                return std::task::Poll::Ready(());
            }
            left -= 1;
            cx.waker().wake_by_ref();
            std::task::Poll::Pending
        })
        .await;
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}
impl NamespaceStore for Probe {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    fn read_call_allowance(&self) -> Option<u32> {
        Some(u32::MAX)
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.inner.get(p, key).await
    }
    async fn get_many(
        &self,
        _p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        if keys[0].as_bytes().starts_with(INDEX_PREFIX) {
            if self.descriptor_bad {
                return Ok(vec![Some(Value::new(&b"malformed"[..])), None]);
            }
            return Ok(vec![None, None]);
        }
        let id: Hash = keys[0].as_bytes()[2..34].try_into().unwrap();
        assert_eq!(keys, &[crate::store::keys::block(&id), action_key(&id)]);
        let call = {
            let mut calls = self.calls.lock().unwrap();
            calls.push(id);
            calls.len()
        };
        if let Some(budget) = &self.charged {
            self.dispatch_charges.lock().unwrap().push(budget.used());
        }
        self.hold(12 - (call - 1) % 6).await;
        self.completed.lock().unwrap().push(id);
        match self.replies.get(&id).copied().unwrap_or_default() {
            Reply::Missing => Ok(vec![None, None]),
            Reply::Blocked => Ok(vec![
                Some(crate::store::codec::encode_block_entry(&BlockEntry::new(
                    "blocked", 1,
                ))),
                None,
            ]),
            Reply::Corrupt => Err(StoreError::Corrupt("first corrupt".into())),
            Reply::Dead => Err(StoreError::unavailable("later dead")),
            Reply::Capped => {
                SliceBudget::new(0).charge()?;
                unreachable!()
            }
        }
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.hold(20).await;
        if self.scan_error {
            return Err(StoreError::Corrupt("directory fault".into()));
        }
        self.inner.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.inner.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}
fn contexts() -> Vec<(Hash, ObjectContext)> {
    [vec![1, 3, 5, 7, 9, 11], vec![1, 2, 3, 4, 6, 8, 10, 12]]
        .into_iter()
        .enumerate()
        .map(|(n, ids)| {
            (
                [n as u8; 32],
                ObjectContext {
                    ids: ids.into_iter().map(|n| [n; 32]).collect(),
                    manifests: Vec::new(),
                },
            )
        })
        .collect()
}
#[test]
fn dependency_waves_dedupe_first_seen_reserve_exactly_and_refresh() {
    block_on(async {
        let inherited = SliceBudget::new(100);
        let calls = SliceBudget::new(100);
        let session = SliceBudget::new(100);
        let mut probe = Probe::new();
        probe.charged = Some(calls.clone());
        probe.replies.insert([3; 32], Reply::Blocked);
        let backend = Budgeted::new(&probe, &inherited);
        let io = crate::store::read_io::ReadIo::new();
        let store = Budgeted::new(&backend, &calls)
            .with_session(&session)
            .with_io(&io);
        let contexts = contexts();
        for phase in 1..=2 {
            assert_eq!(
                dependency_denials(&store, &contexts, true).await.unwrap(),
                BTreeSet::from([[3; 32]])
            );
            for budget in [&inherited, &calls, &session] {
                assert_eq!(budget.used(), phase * 12);
            }
        }
        let expected: Vec<_> = [1, 3, 5, 7, 9, 11, 2, 4, 6, 8, 10, 12]
            .into_iter()
            .map(|n| [n; 32])
            .collect();
        assert_eq!(*probe.calls.lock().unwrap(), expected.repeat(2));
        assert_eq!(
            *probe.dispatch_charges.lock().unwrap(),
            [vec![6; 6], vec![12; 6], vec![18; 6], vec![24; 6]].concat()
        );
        assert_eq!(probe.peak.load(Ordering::SeqCst), 6);
        assert_eq!(
            &probe.completed.lock().unwrap()[..6],
            &expected[..6].iter().rev().copied().collect::<Vec<_>>()
        );
    });
}
#[test]
fn dependency_wave_errors_follow_input_despite_reverse_completion() {
    block_on(async {
        let mut probe = Probe::new();
        probe.replies.insert([1; 32], Reply::Corrupt);
        probe.replies.insert([11; 32], Reply::Dead);
        let budget = SliceBudget::new(100);
        let store = Budgeted::new(&probe, &budget);
        let error = dependency_denials(&store, &contexts(), true)
            .await
            .unwrap_err();
        assert!(matches!(error, StoreError::Corrupt(message) if message == "first corrupt"));
        assert_eq!(budget.used(), 6);
        assert_eq!(probe.completed.lock().unwrap()[0], [11; 32]);
        assert_eq!(probe.calls.lock().unwrap().len(), 6);
    });
}
#[test]
fn tight_dependency_allowance_preserves_earlier_fault_before_later_budget() {
    block_on(async {
        for reply in [Reply::Corrupt, Reply::Dead] {
            let mut probe = Probe::new();
            probe.replies.insert([1; 32], reply);
            let calls = SliceBudget::new(1);
            let store = Budgeted::new(&probe, &calls);
            let error = dependency_denials(&store, &contexts(), true)
                .await
                .unwrap_err();
            assert!(!crate::indexed::budget::is_exhausted(&error));
            assert_eq!(*probe.calls.lock().unwrap(), vec![[1; 32]]);
            assert_eq!(calls.used(), 1);
            assert!(!calls.refused());
        }
        let probe = Probe::new();
        let calls = SliceBudget::new(1);
        let store = Budgeted::new(&probe, &calls);
        assert!(crate::indexed::budget::is_exhausted(
            &dependency_denials(&store, &contexts(), true)
                .await
                .unwrap_err()
        ));
        assert_eq!(*probe.calls.lock().unwrap(), vec![[1; 32]]);
        assert_eq!(calls.used(), 1);
    });
}
fn raw_request() -> (
    RepoId,
    Vec<(Hash, crate::store::index::LocatedObject)>,
    BTreeMap<Hash, super::super::inventory::Entry>,
) {
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("repo").unwrap(),
    };
    let mut facts = BTreeMap::new();
    let requested = (1..=4)
        .map(|n| {
            let id = [n; 32];
            facts.insert(
                id,
                super::super::inventory::Entry {
                    version: 1,
                    kind: 0,
                    canonical_len: 0,
                    logical_len: None,
                    base: None,
                    references: StoredAction {
                        action: BlockAction {
                            id,
                            takedown_id: [0; 32],
                            reason: String::new(),
                            blocked_at_ms: 0,
                            chunk_ids: vec![],
                        },
                        sorted_pages: false,
                        chunk_count: 0,
                        chunk_digest: [0; 32],
                        pages: vec![],
                        page_owner: [0; 32],
                        page_action: [0; 32],
                        pack_scope: None,
                        pack_digest: None,
                    },
                },
            );
            (
                id,
                crate::store::index::LocatedObject {
                    pack: [n + 10; 32],
                    value: crate::store::index::IndexValue {
                        frame_offset: 1,
                        frame_length: 1,
                        wire_type: 0,
                        decoded_size: 0,
                        chain_depth: 0,
                        delta_base: None,
                    },
                },
            )
        })
        .collect();
    (repo, requested, facts)
}
#[test]
fn directory_fault_precedes_quiet_dependency_cap_and_combined_io_is_six() {
    block_on(async {
        let (repo, requested, facts) = raw_request();
        for directory_fault in [true, false] {
            let mut probe = Probe::new();
            probe.scan_error = directory_fault;
            probe.replies.insert([1; 32], Reply::Capped);
            let calls = SliceBudget::new(100);
            let hit = AtomicBool::new(false);
            let io = crate::store::read_io::ReadIo::new();
            let store = Budgeted::new(&probe, &calls).flagging(&hit).with_io(&io);
            let quiet = store.unflagged();
            let error = object_denials_in(
                &store,
                &quiet,
                &crate::pipeline::D34Shards,
                &repo,
                &requested,
                &facts,
                &IndexedConfig::default(),
            )
            .await
            .unwrap_err();
            assert_eq!(
                error.code(),
                if directory_fault {
                    crate::Code::Unavailable
                } else {
                    crate::Code::ResourceExhausted
                }
            );
            assert!(
                !hit.load(Ordering::SeqCst),
                "quiet dependency cap must not reclassify directory fault"
            );
            assert_eq!(probe.peak.load(Ordering::SeqCst), 6);
        }
    });
}
#[test]
fn directory_and_dependency_reads_keep_mixed_denied_and_absent_results_fresh() {
    block_on(async {
        let (repo, requested, facts) = raw_request();
        let mut probe = Probe::new();
        probe.replies.insert([12; 32], Reply::Blocked);
        let calls = SliceBudget::new(100);
        let io = crate::store::read_io::ReadIo::new();
        let store = Budgeted::new(&probe, &calls).with_io(&io);
        let quiet = store.unflagged();
        for phase in 1..=2 {
            assert_eq!(
                object_denials_in(
                    &store,
                    &quiet,
                    &crate::pipeline::D34Shards,
                    &repo,
                    &requested,
                    &facts,
                    &IndexedConfig::default()
                )
                .await
                .unwrap(),
                BTreeSet::from([[2; 32]])
            );
            assert_eq!(probe.calls.lock().unwrap().len(), phase * 8);
        }
        assert_eq!(probe.peak.load(Ordering::SeqCst), 6);
    });
}

#[test]
fn descriptor_fault_precedes_independent_dependency_exhaustion() {
    block_on(async {
        let (repo, requested, facts) = raw_request();
        let mut probe = Probe::new();
        probe.descriptor_bad = true;
        probe.replies.insert([1; 32], Reply::Capped);
        let object = [32; 32];
        probe
            .inner
            .apply(
                &Partition::ContentShard(2),
                Batch::new().put(
                    Key::new([super::super::directory::PREFIX, &object].concat()),
                    Value::new([&[1][..], &object].concat()),
                ),
            )
            .await
            .unwrap();
        let calls = SliceBudget::new(100);
        let hit = AtomicBool::new(false);
        let io = crate::store::read_io::ReadIo::new();
        let store = Budgeted::new(&probe, &calls).flagging(&hit).with_io(&io);
        let quiet = store.unflagged();
        let error = object_denials_in(
            &store,
            &quiet,
            &crate::pipeline::D34Shards,
            &repo,
            &requested,
            &facts,
            &IndexedConfig::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), crate::Code::Unavailable);
        assert_eq!(error.public_message(), "object storage request failed");
        assert!(!hit.load(Ordering::SeqCst));
    });
}

#[test]
fn joined_dependencies_cannot_spend_directory_error_headroom() {
    block_on(async {
        let (repo, requested, facts) = raw_request();
        let mut probe = Probe::new();
        probe.descriptor_bad = true;
        let object = [32; 32];
        probe
            .inner
            .apply(
                &Partition::ContentShard(2),
                Batch::new().put(
                    Key::new([super::super::directory::PREFIX, &object].concat()),
                    Value::new([&[1][..], &object].concat()),
                ),
            )
            .await
            .unwrap();
        let mut observed = Vec::new();
        for joined in [false, true] {
            // Sixteen initial scans and eight dependency reads fit, but the
            // malformed descriptor must still win before dependency admission.
            let calls = SliceBudget::new(24);
            let hit = AtomicBool::new(false);
            let io = crate::store::read_io::ReadIo::new();
            let store = Budgeted::new(&probe, &calls).flagging(&hit).with_io(&io);
            let quiet = store.unflagged();
            let error = if joined {
                object_denials_in(
                    &store,
                    &quiet,
                    &crate::pipeline::D34Shards,
                    &repo,
                    &requested,
                    &facts,
                    &IndexedConfig::default(),
                )
                .await
            } else {
                object_denials(
                    &store,
                    &crate::pipeline::D34Shards,
                    &repo,
                    &requested,
                    &facts,
                    &IndexedConfig::default(),
                )
                .await
            }
            .unwrap_err();
            let code = if error.code() == crate::Code::Unavailable && hit.load(Ordering::SeqCst) {
                crate::Code::ResourceExhausted
            } else {
                error.code()
            };
            observed.push(code);
        }
        assert_eq!(observed[0], crate::Code::Unavailable);
        assert_eq!(
            observed[1], observed[0],
            "directory error precedence survives a shared tight budget"
        );
    });
}
