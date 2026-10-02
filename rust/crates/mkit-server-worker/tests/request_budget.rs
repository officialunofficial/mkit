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
use futures::channel::oneshot;
use futures::executor::block_on;
use mkit_core::protocol::PackKey;
use mkit_server::indexed::budget::SliceBudget;
use mkit_server::pipeline::{AuthMode, Hooks, Pipeline, PipelineConfig, RequestMeta};
use mkit_server::{
    Addressing, BlobKey, BlobStore, ByteRange, NamespaceKey, NamespaceStore, NoopMetrics,
    Partition, Procedure, RepoId, RepoName, StoreError, SystemClock,
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
}
impl CountedBucket {
    fn dispatch(&self) -> Result<(), String> {
        charge_request(Some(&self.budget)).map_err(|error| error.to_string())?;
        mkit_server_worker::ns_client::charge_alarm(self.alarm.as_ref())
            .map_err(|error| error.to_string())?;
        self.dispatches.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
impl ObjectBucket for CountedBucket {
    fn spawn_put(&self, key: String, len: u64, body: PutBody) -> oneshot::Receiver<PutResult> {
        if let Err(error) = self.dispatch() {
            let (tx, rx) = oneshot::channel();
            let _ = tx.send(Err(error));
            return rx;
        }
        self.inner.spawn_put(key, len, body)
    }
    async fn head(&self, key: &str) -> Result<Option<u64>, String> {
        self.dispatch()?;
        self.inner.head(key).await
    }
    async fn get(
        &self,
        key: &str,
        range: Option<Range<u64>>,
    ) -> Result<Option<(u64, ObjectStream)>, String> {
        self.dispatch()?;
        self.inner.get(key, range).await
    }
    async fn delete(&self, key: &str) -> Result<(), String> {
        self.dispatch()?;
        self.inner.delete(key).await
    }
    async fn list(&self, prefix: &str, cursor: Option<&str>) -> Result<ObjectPage, String> {
        self.dispatch()?;
        self.inner.list(prefix, cursor).await
    }
    async fn delete_many(&self, keys: Vec<String>) -> Result<(), String> {
        self.dispatch()?;
        self.inner.delete_many(keys).await
    }
    async fn probe(&self) -> Result<(), String> {
        self.dispatch()?;
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
            3,
            "range HEAD and GET share the metadata allowance"
        );
        let proof_budget = SliceBudget::new(9000);
        for _ in 0..2 {
            clear(&meta, &proof_budget).await.unwrap();
        }
        let config = PipelineConfig::new(
            Addressing::Single { repo: repo() },
            AuthMode::Open,
            mkit_server::upload::UploadLimits {
                max_total_bytes: 1024,
                max_chunks: 16,
            },
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
        let budget = mkit_server::purge::SliceBudget::new(5);
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
        assert_eq!(budget.used(), 3);
        assert!(blobs.delete(&key).await.unwrap());
        assert_eq!(budget.used(), 5);
        let actual = transport.0.load(Ordering::SeqCst) + dispatches.load(Ordering::SeqCst);
        assert_eq!(actual, 5);
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
