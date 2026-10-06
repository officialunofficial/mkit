//! Host backend contract: production DO client and an R2 bucket model share
//! the same dispatcher counter. `EnvBucket`'s wasm charge sites require wasm
//! validation; this model does not claim to execute the Workers JS runtime.
#![allow(clippy::unwrap_used)] // Invalid test fixtures must fail immediately.
mod common;

use std::collections::BTreeSet;
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use bytes::Bytes;
use futures::FutureExt as _;
use futures::channel::oneshot;
use futures::executor::block_on;
use mkit_core::hash::hash;
use mkit_core::protocol::PackKey;
use mkit_core::upload_parts::{MIN_PART_SIZE, PartPlan, part_subtree_cv};
use mkit_server::indexed::budget::SliceBudget;
use mkit_server::pipeline::{AuthMode, Hooks, Pipeline, PipelineConfig, RequestMeta};
use mkit_server::store::ReadReservation;
use mkit_server::{
    Addressing, BlobKey, BlobStore, ByteRange, MultipartBlobStore, NamespaceKey, NamespaceStore,
    NoopMetrics, PackSink, PartSink, Partition, Procedure, RepoId, RepoName, StoreError,
    SystemClock,
};
use mkit_server_worker::naming::DoTarget;
use mkit_server_worker::ns_client::{DoNamespaceStore, NsTransport, charge_request};
use mkit_server_worker::r2::{
    ObjectBucket, ObjectPage, ObjectStream, PACKS_KEYSPACE, PutBody, PutResult, R2BlobStore,
};
use mkit_server_worker::wire::{NsCall, NsReply, NsRequest};

#[derive(Clone, Default)]
struct EmptyTransport(Arc<AtomicU32>);
impl NsTransport for EmptyTransport {
    async fn call(
        &self,
        _: &DoTarget,
        _: &'static str,
        body: String,
    ) -> Result<String, StoreError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        let request: NsRequest = serde_json::from_str(&body).unwrap();
        let reply = match request.call {
            NsCall::Get { .. } => NsReply::Value { value: None },
            NsCall::GetMany { keys } => NsReply::Values {
                values: vec![None; keys.len()],
            },
            NsCall::Scan { .. } => NsReply::Page {
                entries: vec![],
                next: None,
            },
            _ => panic!("unexpected call"),
        };
        Ok(serde_json::to_string(&reply).unwrap())
    }
}

#[derive(Clone)]
struct CountedBucket {
    inner: common::SimBucket,
    budget: SliceBudget,
    alarm: Option<mkit_server::purge::SliceBudget>,
    dispatches: Arc<AtomicU32>,
    read_credits: Arc<mkit_server::store::ReadCredits>,
}
impl CountedBucket {
    fn dispatch(&self, prepaid_read: bool) -> Result<(), String> {
        if !prepaid_read || !self.read_credits.paid() {
            charge_request(Some(&self.budget)).map_err(|error| error.to_string())?;
            mkit_server_worker::ns_client::charge_alarm(self.alarm.as_ref())
                .map_err(|error| error.to_string())?;
        }
        self.dispatches.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
impl ObjectBucket for CountedBucket {
    fn reserve_read_calls(
        &self,
        calls: u32,
    ) -> Result<Option<mkit_server::store::ReadReservation>, StoreError> {
        self.budget.charge_many(calls)?;
        if self
            .alarm
            .as_ref()
            .is_some_and(|b| !b.charge_operations(calls))
        {
            return Err(StoreError::unavailable("alarm allowance exhausted"));
        }
        Ok(Some(self.read_credits.prepay(calls)))
    }
    fn spawn_put(&self, key: String, len: u64, body: PutBody) -> oneshot::Receiver<PutResult> {
        if let Err(error) = self.dispatch(false) {
            let (tx, rx) = oneshot::channel();
            let _ = tx.send(Err(error));
            return rx;
        }
        self.inner.spawn_put(key, len, body)
    }
    fn spawn_object_part(
        &self,
        key: String,
        upload: String,
        number: u16,
        len: u64,
        body: PutBody,
    ) -> oneshot::Receiver<Result<String, String>> {
        if let Err(error) = self.dispatch(false) {
            let (tx, rx) = oneshot::channel();
            let _ = tx.send(Err(error));
            return rx;
        }
        self.inner.spawn_object_part(key, upload, number, len, body)
    }
    async fn head(&self, key: &str) -> Result<Option<u64>, String> {
        self.dispatch(true)?;
        self.inner.head(key).await
    }
    async fn get(
        &self,
        key: &str,
        range: Option<Range<u64>>,
    ) -> Result<Option<(u64, ObjectStream)>, String> {
        self.dispatch(true)?;
        self.inner.get(key, range).await
    }
    async fn delete(&self, key: &str) -> Result<(), String> {
        self.dispatch(false)?;
        self.inner.delete(key).await
    }
    async fn list(&self, prefix: &str, cursor: Option<&str>) -> Result<ObjectPage, String> {
        self.dispatch(false)?;
        self.inner.list(prefix, cursor).await
    }
    async fn delete_many(&self, keys: Vec<String>) -> Result<(), String> {
        self.dispatch(false)?;
        self.inner.delete_many(keys).await
    }
    async fn probe(&self) -> Result<(), String> {
        self.dispatch(false)?;
        self.inner.probe().await
    }
}

fn repo() -> RepoId {
    RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("default").unwrap(),
    }
}

async fn clear(
    meta: &DoNamespaceStore<EmptyTransport>,
    budget: &SliceBudget,
) -> Result<(), mkit_server::ServerError> {
    mkit_server::takedown::denial::require_repo_clear_budgeted(
        meta,
        &mkit_server::pipeline::SinglePartition,
        &repo(),
        &BTreeSet::from([[6; 32]]),
        &[],
        budget,
    )
    .await
}

async fn metadata_probe(
    meta: &DoNamespaceStore<EmptyTransport>,
) -> Result<Option<mkit_server::Value>, StoreError> {
    meta.get(
        &Partition::Namespace(repo().namespace),
        &mkit_server::Key::new(b"b\0test".to_vec()),
    )
    .await
}

#[test]
fn request_budget_combines_do_r2_range_proofs_and_pipeline_serving() {
    block_on(async {
        let budget = SliceBudget::new(9000);
        let transport = EmptyTransport::default();
        let meta = DoNamespaceStore::new(transport.clone(), Partition::Namespace(repo().namespace))
            .with_budget(budget.clone());
        let bucket = common::SimBucket::default();
        let blobs = R2BlobStore::new(
            CountedBucket {
                inner: bucket.clone(),
                budget: budget.clone(),
                alarm: None,
                dispatches: Arc::default(),
                read_credits: Arc::default(),
            },
            PACKS_KEYSPACE,
        );
        let key = BlobKey::pack([5; 32]);
        bucket.replace_object(
            &blobs.object_key(&key).unwrap(),
            Bytes::from_static(b"test"),
        );
        metadata_probe(&meta).await.unwrap();
        assert!(
            blobs
                .get(
                    &key,
                    Some(ByteRange {
                        start: 0,
                        end_inclusive: 1
                    })
                )
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            budget.used(),
            2,
            "a bounded range is one GET: one probe and one GET"
        );
        let proof_budget = SliceBudget::new(9000);
        for _ in 0..2 {
            clear(&meta, &proof_budget).await.unwrap();
        }
        let config = PipelineConfig::new(
            Addressing::Single { repo: repo() },
            AuthMode::Open,
            mkit_server::upload::UploadLimits::new(1024, 16),
        );
        let pipe = Pipeline::new(
            blobs.clone(),
            meta.clone(),
            Hooks::new(),
            config,
            Arc::new(SystemClock),
            Arc::new(NoopMetrics),
        )
        .unwrap();
        let auth = pipe
            .authenticate(&RequestMeta {
                procedure: Procedure::PackExists,
                header: &|_| None,
                header_values: None,
                unary_body: None,
                transport_principal: None,
            })
            .unwrap();
        assert!(pipe.pack_exists(&auth, PackKey([5; 32])).await.unwrap());
        let fresh_proof = SliceBudget::new(9000);
        clear(&meta, &fresh_proof).await.unwrap();
        assert!(
            budget.used() < 200,
            "three directory proofs retain headroom"
        );
        // Spend the remaining physical allowance on actual metadata dispatches.
        // A new core proof ledger still cannot replenish the request's parent.
        while budget.remaining() > 1 {
            metadata_probe(&meta).await.unwrap();
        }
        assert!(clear(&meta, &SliceBudget::new(9000)).await.is_err());
        assert_eq!(budget.used(), 9000);
        let before = transport.0.load(Ordering::SeqCst)
            + u32::try_from(bucket.operations.load(Ordering::SeqCst)).unwrap();
        assert_eq!(before, 9000);
        assert!(pipe.pack_exists(&auth, PackKey([5; 32])).await.is_err());
        assert!(
            meta.get(
                &Partition::Namespace(repo().namespace),
                &mkit_server::Key::new(b"b\0test".to_vec())
            )
            .await
            .is_err()
        );
        assert_eq!(
            transport.0.load(Ordering::SeqCst)
                + u32::try_from(bucket.operations.load(Ordering::SeqCst)).unwrap(),
            before
        );
    });
}

#[test]
fn inventory_transport_peak_includes_base64_reply_and_nested_raw_pages() {
    use mkit_server_worker::wire::Blob;
    let rows = usize::try_from(mkit_server::takedown::inventory::SCAN_ROWS).unwrap();
    assert_eq!(rows, 8);
    let page = NsReply::Page {
        entries: (0..rows)
            .map(|_| {
                (
                    Blob(vec![0xff; 128]),
                    Blob(vec![0xff; mkit_server::MAX_VALUE_BYTES]),
                )
            })
            .collect(),
        next: Some(Blob(vec![0xff; 128])),
    };
    let json = serde_json::to_string(&page).unwrap();
    assert!(json.capacity() <= 12 << 20, "{}", json.capacity());
    let decoded: NsReply = serde_json::from_str(&json).unwrap();
    assert_eq!(page, decoded);
    let NsReply::Page { entries, .. } = &decoded else {
        unreachable!()
    };
    let raw_capacity: usize = entries
        .iter()
        .map(|(key, value)| key.0.capacity() + value.0.capacity())
        .sum();
    assert!(raw_capacity <= (4 << 20) + 4096, "{raw_capacity}");
    // Two retained visitor pages plus this response's JSON and decoded page;
    // one temporary base64 value; 4 MiB target context; 4 MiB header scratch;
    // and one 1 MiB chunk page. These phases precede canonical leaf decoding.
    let peak = raw_capacity * 3 + json.capacity() + (1 << 20) + (4 << 20) * 2 + (1 << 20);
    assert!(peak < 48 << 20, "{peak}");
}

#[test]
fn alarm_budget_counts_real_range_and_delete_calls_and_survives_clones() {
    block_on(async {
        let budget = mkit_server::purge::SliceBudget::new(4);
        let dispatches = Arc::new(AtomicU32::new(0));
        let transport = EmptyTransport::default();
        let meta = DoNamespaceStore::new(
            transport.clone(),
            Partition::Namespace(repo().namespace.clone()),
        )
        .with_alarm_budget(budget.clone());
        let bucket = common::SimBucket::default();
        let blobs = R2BlobStore::new(
            CountedBucket {
                inner: bucket.clone(),
                budget: SliceBudget::new(1000),
                alarm: Some(budget.clone()),
                dispatches: dispatches.clone(),
                read_credits: Arc::default(),
            },
            PACKS_KEYSPACE,
        );
        let key = BlobKey::pack([5; 32]);
        bucket.replace_object(
            &blobs.object_key(&key).unwrap(),
            Bytes::from_static(b"test"),
        );
        let partition = Partition::Namespace(repo().namespace);
        let metadata = mkit_server::Key::new(b"b\0test".to_vec());
        meta.get(&partition, &metadata).await.unwrap();
        assert!(
            blobs
                .clone()
                .get(
                    &key,
                    Some(ByteRange {
                        start: 0,
                        end_inclusive: 1
                    })
                )
                .await
                .unwrap()
                .is_some()
        );
        // One metadata read and one GET: a bounded range has no HEAD.
        assert_eq!(budget.used(), 2);
        assert!(blobs.delete(&key).await.unwrap());
        assert_eq!(budget.used(), 4);
        let actual = transport.0.load(Ordering::SeqCst) + dispatches.load(Ordering::SeqCst);
        assert_eq!(actual, 4);
        assert!(meta.clone().get(&partition, &metadata).await.is_err());
        assert!(blobs.head(&key).await.is_err());
        assert_eq!(
            transport.0.load(Ordering::SeqCst) + dispatches.load(Ordering::SeqCst),
            actual
        );
        budget.reset();
        meta.clone().get(&partition, &metadata).await.unwrap();
        assert_eq!(budget.used(), 1);
        assert_eq!(transport.0.load(Ordering::SeqCst), 2);
    });
}

#[test]
fn namespace_read_wave_reserves_inherited_allowance_before_transport() {
    block_on(async {
        for allowance in [5, 6] {
            let transport = EmptyTransport::default();
            let budget = SliceBudget::new(allowance);
            let store = Arc::new(
                DoNamespaceStore::new(transport.clone(), Partition::Namespace(repo().namespace))
                    .with_budget(budget.clone()),
            );
            let reservation = store.reserve_read_calls(6);
            if allowance == 5 {
                assert!(reservation.is_err());
                assert_eq!(transport.0.load(Ordering::SeqCst), 0);
            } else {
                let reservation = reservation.unwrap();
                let key = mkit_server::Key::new(b"key".to_vec());
                let partition = Partition::Namespace(repo().namespace);
                let reservations = [reservation];
                let replies = ReadReservation::scope(
                    &reservations,
                    futures::future::join_all((0..6).map(|_| store.get(&partition, &key))),
                )
                .await;
                assert!(replies.into_iter().all(|reply| reply.is_ok()));
                assert_eq!(budget.used(), 6);
                assert_eq!(transport.0.load(Ordering::SeqCst), 6);
                drop(reservations);
                assert!(store.get(&partition, &key).await.is_err());
                assert_eq!(transport.0.load(Ordering::SeqCst), 6);
            }
        }
    });
}

#[test]
fn blob_and_namespace_waves_preflight_the_same_invocation_ledger() {
    block_on(async {
        for allowance in [9, 10] {
            let budget = SliceBudget::new(allowance);
            let transport = EmptyTransport::default();
            let meta =
                DoNamespaceStore::new(transport.clone(), Partition::Namespace(repo().namespace))
                    .with_budget(budget.clone());
            let dispatches = Arc::<AtomicU32>::default();
            let bucket = common::SimBucket::default();
            let blobs = R2BlobStore::new(
                CountedBucket {
                    inner: bucket.clone(),
                    budget: budget.clone(),
                    alarm: None,
                    dispatches: dispatches.clone(),
                    read_credits: Arc::default(),
                },
                PACKS_KEYSPACE,
            );
            let key = BlobKey::pack([5; 32]);
            bucket.replace_object(
                &blobs.object_key(&key).unwrap(),
                Bytes::from_static(b"test"),
            );
            let namespace = meta.reserve_read_calls(6).unwrap();
            let blob = blobs.reserve_read_calls(4);
            if allowance == 9 {
                assert!(blob.is_err());
                assert_eq!(transport.0.load(Ordering::SeqCst), 0);
                assert_eq!(dispatches.load(Ordering::SeqCst), 0);
            } else {
                let blob = blob.unwrap();
                let p = Partition::Namespace(repo().namespace);
                let k = mkit_server::Key::new(b"key".to_vec());
                ReadReservation::scope(&[namespace, blob], async {
                    for _ in 0..6 {
                        meta.get(&p, &k).await.unwrap();
                    }
                    for _ in 0..2 {
                        let body = blobs
                            .get(
                                &key,
                                Some(ByteRange {
                                    start: 0,
                                    end_inclusive: 1,
                                }),
                            )
                            .await
                            .unwrap();
                        assert!(body.is_some());
                    }
                })
                .await;
                // Two single-call ranged reads; the four prepaid calls stay charged.
                assert_eq!(budget.used(), 10);
                assert_eq!(dispatches.load(Ordering::SeqCst), 2);
            }
        }
    });
}

#[test]
fn replacing_a_worker_budget_cannot_borrow_another_handles_wave_credit() {
    block_on(async {
        let transport = EmptyTransport::default();
        let store =
            DoNamespaceStore::new(transport.clone(), Partition::Namespace(repo().namespace))
                .with_budget(SliceBudget::new(6));
        let reservation = store.reserve_read_calls(6).unwrap();
        ReadReservation::scope(&[reservation], async {
            let other = store.clone().with_budget(SliceBudget::new(0));
            assert!(metadata_probe(&other).await.is_err());
            let alarm = store
                .clone()
                .with_alarm_budget(mkit_server::purge::SliceBudget::new(0));
            assert!(metadata_probe(&alarm).await.is_err());
            assert_eq!(transport.0.load(Ordering::SeqCst), 0);
            metadata_probe(&store).await.unwrap();
            assert_eq!(transport.0.load(Ordering::SeqCst), 1);
        })
        .await;
        assert!(metadata_probe(&store).await.is_err());
    });
}

#[test]
fn unrelated_calls_and_cancelled_waves_cannot_spend_read_credit() {
    block_on(async {
        let p = Partition::Namespace(repo().namespace);
        let k = mkit_server::Key::new(b"key".to_vec());
        let transport = EmptyTransport::default();
        let budget = SliceBudget::new(6);
        let store = DoNamespaceStore::new(transport.clone(), p.clone()).with_budget(budget.clone());
        let reservation = store.reserve_read_calls(6).unwrap();
        let other = store.clone();
        assert!(metadata_probe(&other).await.is_err());
        ReadReservation::scope(&[reservation], async {
            // Non-reader work stays charged even if called inside a read scope.
            assert!(
                other
                    .apply(
                        &p,
                        mkit_server::Batch::new().put(k, mkit_server::Value::default())
                    )
                    .await
                    .is_err()
            );
            assert!(other.export_page(&p, None, 1).await.is_err());
            assert_eq!(transport.0.load(Ordering::SeqCst), 0);
            for _ in 0..6 {
                metadata_probe(&store).await.unwrap();
            }
        })
        .await;
        assert_eq!(budget.used(), 6);
        assert_eq!(transport.0.load(Ordering::SeqCst), 6);

        let transport = EmptyTransport::default();
        let budget = SliceBudget::new(4);
        let store = DoNamespaceStore::new(transport.clone(), p).with_budget(budget.clone());
        let a = [store.reserve_read_calls(2).unwrap()];
        let b = [store.reserve_read_calls(2).unwrap()];
        let cancelled = ReadReservation::scope(&b, async {
            metadata_probe(&store).await.unwrap();
            futures::future::pending::<()>().await;
        });
        assert!(cancelled.now_or_never().is_none());
        drop(b);
        ReadReservation::scope(&a, async {
            for _ in 0..2 {
                metadata_probe(&store).await.unwrap();
            }
        })
        .await;
        assert_eq!(transport.0.load(Ordering::SeqCst), 3);
        assert_eq!(budget.used(), 4, "cancelled unused credit remains charged");
        assert!(metadata_probe(&store).await.is_err());
    });
}

#[test]
fn blob_read_credit_rejects_unrelated_deletes_even_inside_its_scope() {
    block_on(async {
        let budget = SliceBudget::new(4);
        let bucket = common::SimBucket::default();
        let dispatches = Arc::<AtomicU32>::default();
        let blobs = R2BlobStore::new(
            CountedBucket {
                inner: bucket.clone(),
                budget: budget.clone(),
                alarm: None,
                dispatches: dispatches.clone(),
                read_credits: Arc::default(),
            },
            PACKS_KEYSPACE,
        );
        let key = BlobKey::pack([5; 32]);
        bucket.replace_object(
            &blobs.object_key(&key).unwrap(),
            Bytes::from_static(b"test"),
        );
        let reservation = blobs.reserve_read_calls(4).unwrap();
        assert!(blobs.head(&key).await.is_err());
        ReadReservation::scope(&[reservation], async {
            assert!(blobs.delete(&key).await.is_err());
            assert_eq!(dispatches.load(Ordering::SeqCst), 0);
            for _ in 0..2 {
                assert!(
                    blobs
                        .get(
                            &key,
                            Some(ByteRange {
                                start: 0,
                                end_inclusive: 1
                            })
                        )
                        .await
                        .unwrap()
                        .is_some()
                );
            }
        })
        .await;
        assert_eq!(dispatches.load(Ordering::SeqCst), 2);
        assert_eq!(budget.used(), 4, "unused prepaid calls stay charged");
    });
}

struct MultipartCreditFixture {
    bucket: common::SimBucket,
    bytes: Vec<u8>,
    plan: PartPlan,
    cvs: Vec<[u8; 32]>,
    key: BlobKey,
    object: BlobKey,
    root: [u8; 32],
    ticket: Vec<u8>,
    token: Vec<u8>,
}

async fn multipart_credit_fixture() -> MultipartCreditFixture {
    let bucket = common::SimBucket::default();
    let unbudgeted = R2BlobStore::new(bucket.clone(), PACKS_KEYSPACE);
    let bytes = vec![7; usize::try_from(MIN_PART_SIZE).unwrap() + 4];
    let plan = PartPlan::new(bytes.len() as u64, MIN_PART_SIZE, 10_000).unwrap();
    let root = hash(&bytes);
    let cvs: Vec<_> = (0..plan.count())
        .map(|index| {
            let start = usize::try_from(plan.offset(index).unwrap()).unwrap();
            let end = start + usize::try_from(plan.expected_len(index).unwrap()).unwrap();
            part_subtree_cv(&plan, index, &bytes[start..end]).unwrap()
        })
        .collect();
    let key = BlobKey::pack(root);
    let object = BlobKey::object([9; 32]);
    bucket.replace_object(
        &unbudgeted.object_key(&key).unwrap(),
        Bytes::copy_from_slice(&bytes),
    );
    let ticket = unbudgeted
        .begin_multipart_for_ticket(key, plan.total(), plan.part_size(), [3; 32])
        .await
        .unwrap();
    let token = unbudgeted
        .begin_verified_object(object, &plan, root, &cvs, [4; 32])
        .await
        .unwrap();
    MultipartCreditFixture {
        bucket,
        bytes,
        plan,
        cvs,
        key,
        object,
        root,
        ticket,
        token,
    }
}

#[test]
fn multipart_mutation_reads_cannot_consume_the_reserved_reader_call() {
    block_on(async {
        let MultipartCreditFixture {
            bucket,
            plan,
            cvs,
            key,
            object,
            root,
            ticket,
            token,
            ..
        } = multipart_credit_fixture().await;
        let cv = cvs[0];
        let budget = SliceBudget::new(1);
        let dispatches = Arc::<AtomicU32>::default();
        let blobs = R2BlobStore::new(
            CountedBucket {
                inner: bucket.clone(),
                budget: budget.clone(),
                alarm: None,
                dispatches: dispatches.clone(),
                read_credits: Arc::default(),
            },
            PACKS_KEYSPACE,
        );
        let reservation = blobs.reserve_read_calls(1).unwrap();
        ReadReservation::scope(&[reservation], async {
            assert!(blobs.complete(key, &ticket, &plan, &[]).await.is_err());
            assert!(
                blobs
                    .complete_with_root(key, &ticket, &plan, &[], root)
                    .await
                    .is_err()
            );
            assert!(blobs.begin_part(key, &ticket, &plan, 0, cv).await.is_err());
            assert!(
                blobs
                    .begin_verified_object(object, &plan, root, &cvs, [4; 32])
                    .await
                    .is_err()
            );
            assert!(
                blobs
                    .begin_verified_object_part(object, &token, &plan, 0, cv)
                    .await
                    .is_err()
            );
            assert!(
                blobs
                    .complete_verified_object(object, &token, &plan, &[], root)
                    .await
                    .is_err()
            );
            assert!(
                blobs
                    .abort_verified_object(object, &token, &plan)
                    .await
                    .is_err()
            );
            assert_eq!(dispatches.load(Ordering::SeqCst), 0);
            assert!(blobs.head(&key).await.unwrap().is_some());
        })
        .await;
        assert_eq!(dispatches.load(Ordering::SeqCst), 1);
        assert_eq!(budget.used(), 1);
    });
}

async fn check_part<P: PartSink>(
    mut part: P,
    bytes: &[u8],
    blobs: &R2BlobStore<CountedBucket>,
    key: BlobKey,
    dispatches: &AtomicU32,
) {
    for chunk in bytes.chunks(256 * 1024) {
        part.write(Bytes::copy_from_slice(chunk)).await.unwrap();
    }
    let reservation = blobs.reserve_read_calls(1).unwrap();
    ReadReservation::scope(&[reservation], async {
        assert!(part.commit().await.is_err());
        assert_eq!(dispatches.load(Ordering::SeqCst), 2);
        assert!(blobs.head(&key).await.unwrap().is_some());
    })
    .await;
    assert_eq!(dispatches.load(Ordering::SeqCst), 3);
}
#[test]
fn multipart_part_commit_cannot_borrow_the_reserved_reader_call() {
    block_on(async {
        let MultipartCreditFixture {
            bucket,
            bytes,
            plan,
            cvs,
            key,
            object,
            ticket,
            token,
            ..
        } = multipart_credit_fixture().await;
        let cv = cvs[0];
        for verified in [false, true] {
            let budget = SliceBudget::new(3);
            let dispatches = Arc::<AtomicU32>::default();
            let blobs = R2BlobStore::new(
                CountedBucket {
                    inner: bucket.clone(),
                    budget: budget.clone(),
                    alarm: None,
                    dispatches: dispatches.clone(),
                    read_credits: Arc::default(),
                },
                PACKS_KEYSPACE,
            );
            let first = &bytes[..usize::try_from(plan.expected_len(0).unwrap()).unwrap()];
            if verified {
                let part = blobs
                    .begin_verified_object_part(object, &token, &plan, 0, cv)
                    .await
                    .unwrap();
                Box::pin(check_part(part, first, &blobs, key, &dispatches)).await;
            } else {
                let part = blobs.begin_part(key, &ticket, &plan, 0, cv).await.unwrap();
                Box::pin(check_part(part, first, &blobs, key, &dispatches)).await;
            }
            assert_eq!(budget.used(), 3);
        }
    });
}

#[test]
fn root_pinning_sink_cannot_borrow_credit_after_its_put_was_charged() {
    block_on(async {
        let budget = SliceBudget::new(2);
        let dispatches = Arc::<AtomicU32>::default();
        let bucket = common::SimBucket::default();
        let blobs = R2BlobStore::new(
            CountedBucket {
                inner: bucket.clone(),
                budget: budget.clone(),
                alarm: None,
                dispatches: dispatches.clone(),
                read_credits: Arc::default(),
            },
            PACKS_KEYSPACE,
        );
        let key = BlobKey::pack([5; 32]);
        bucket.replace_object(
            &blobs.object_key(&key).unwrap(),
            Bytes::from_static(b"test"),
        );
        let mut sink = blobs.begin(BlobKey::object([9; 32]), 1).await.unwrap();
        sink.write(Bytes::from_static(b"x")).await.unwrap();
        let reservation = blobs.reserve_read_calls(1).unwrap();
        ReadReservation::scope(&[reservation], async {
            assert!(sink.commit_with_root(hash(b"x")).await.is_err());
            assert_eq!(dispatches.load(Ordering::SeqCst), 1);
            assert!(blobs.head(&key).await.unwrap().is_some());
        })
        .await;
        assert_eq!(dispatches.load(Ordering::SeqCst), 2);
        assert_eq!(budget.used(), 2);
    });
}
