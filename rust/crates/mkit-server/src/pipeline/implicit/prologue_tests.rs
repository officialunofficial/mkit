use super::*;
use crate::store::{ReadCredits, ReadReservation};
use crate::{
    BlobMeta, BlobStore, ByteRange, ManualClock, MemoryBlobStore, MemoryKv, NamespaceKey,
    NoopMetrics, Principal, RepoId, RepoName, StoreError,
};
use futures::executor::block_on;
use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};

struct PrologueReads {
    bytes: Option<Vec<u8>>,
    head_failure: bool,
    head_absent: bool,
    remaining: AtomicU32,
    charged: AtomicU32,
    calls: AtomicU32,
    credits: ReadCredits,
    active: AtomicU32,
    maximum: AtomicU32,
}
impl PrologueReads {
    async fn dispatched(&self) {
        assert!(self.credits.paid(), "unreserved implicit prologue read");
        self.calls.fetch_add(1, Ordering::SeqCst);
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.maximum.fetch_max(active, Ordering::SeqCst);
        let mut yielded = false;
        futures::future::poll_fn(|cx| {
            if yielded {
                std::task::Poll::Ready(())
            } else {
                yielded = true;
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
        })
        .await;
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}
impl BlobStore for PrologueReads {
    type Sink = <MemoryBlobStore as BlobStore>::Sink;
    fn read_call_allowance(&self) -> Option<u32> {
        Some(self.remaining.load(Ordering::SeqCst))
    }
    fn reserve_read_calls(&self, calls: u32) -> Result<Option<ReadReservation>, StoreError> {
        // The tight-budget fallback must never attempt a speculative reservation.
        self.remaining
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(calls)
            })
            .expect("implicit prologue attempted an unaffordable reservation");
        self.charged.fetch_add(calls, Ordering::SeqCst);
        Ok(Some(self.credits.prepay(calls)))
    }
    async fn begin(&self, _: BlobKey, _: u64) -> Result<Self::Sink, StoreError> {
        unreachable!()
    }
    async fn get(&self, _: &BlobKey, _: Option<ByteRange>) -> Result<Option<BlobBody>, StoreError> {
        self.dispatched().await;
        Ok(self
            .bytes
            .clone()
            .map(|bytes| BlobBody::Bytes(bytes.into())))
    }
    async fn head(&self, _: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
        self.dispatched().await;
        if self.head_failure {
            return Err(StoreError::Invalid("known failure".into()));
        }
        Ok((!self.head_absent).then_some(BlobMeta { len: 32 }))
    }
    async fn delete(&self, _: &BlobKey) -> Result<bool, StoreError> {
        unreachable!()
    }
    async fn probe(&self) -> Result<(), StoreError> {
        unreachable!()
    }
}
impl MultipartBlobStore for PrologueReads {
    type PartSink = crate::store::UnsupportedPartSink;
    const MAX_PARTS: u32 = 10_000;
}

#[test]
fn joined_implicit_prologue_decode_absence_and_limit_precede_known_fault() {
    for budget in [1, 2] {
        let too_many = mkit_core::transfer::encode_packlist(
            None,
            &vec![[3; 32]; MAX_IMPLICIT_LISTED_PACKS + 1],
        )
        .unwrap();
        for bytes in [None, Some(b"bad".to_vec()), Some(too_many)] {
            run(bytes, true, false, budget, true, false);
        }
    }
}

#[test]
fn joined_implicit_prologue_known_refusal_and_fault_keep_order_and_accounting() {
    let bytes = Some(mkit_core::transfer::encode_packlist(None, &[]).unwrap());
    run(bytes.clone(), false, true, 2, true, false);
    run(bytes.clone(), true, false, 2, false, false);
    run(bytes, false, false, 2, false, false);
}

#[test]
fn joined_implicit_prologue_known_errors_precede_corrupt_current_ref() {
    let bytes = Some(mkit_core::transfer::encode_packlist(None, &[]).unwrap());
    run(bytes.clone(), false, true, 2, true, true);
    run(bytes.clone(), true, false, 2, false, true);
    run(bytes, false, false, 2, false, true);
}

#[allow(clippy::fn_params_excessive_bools)] // Compact scenario matrix.
fn run(
    bytes: Option<Vec<u8>>,
    head_failure: bool,
    head_absent: bool,
    budget: u32,
    refusal: bool,
    corrupt_current: bool,
) {
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("repo").unwrap(),
    };
    let pipe = Pipeline::new(
        PrologueReads {
            bytes,
            head_failure,
            head_absent,
            remaining: AtomicU32::new(budget),
            charged: AtomicU32::new(0),
            calls: AtomicU32::new(0),
            credits: ReadCredits::default(),
            active: AtomicU32::new(0),
            maximum: AtomicU32::new(0),
        },
        MemoryKv::default(),
        super::super::Hooks::new(),
        super::super::PipelineConfig::new(
            Addressing::Single { repo: repo.clone() },
            super::super::AuthMode::Open,
            crate::upload::UploadLimits::new(1024, 16),
        ),
        Arc::new(ManualClock::new(0)),
        Arc::new(NoopMetrics),
    )
    .unwrap();
    let mut upd = RefUpdate {
        name: "refs/mkit/packmap/main".into(),
        condition: if corrupt_current {
            RefWriteCondition::Any
        } else {
            RefWriteCondition::Missing
        },
        new: Some([99; 32]),
    };
    let op = Operation::new(
        repo,
        Principal::Anonymous,
        None,
        OpKind::UpdateRef(upd.clone()),
    );
    let mut ahead = Snapshot::default();
    let corrupt = crate::store::Value::new(b"bad".to_vec());
    if corrupt_current {
        ahead.insert(
            keys::ref_key(&op.repo.name, &upd.name),
            Some(corrupt.clone()),
        );
    }
    let result = block_on(pipe.check_implicit_packmap(&op, &[], Some(&ahead), &mut upd));
    if refusal {
        assert_eq!(result.unwrap_err().to_string(), refuse().to_string());
    } else if head_failure {
        assert_eq!(
            result.unwrap_err().to_string(),
            store_error(
                StorageOp::BlobHead,
                StoreError::Invalid("known failure".into())
            )
            .to_string()
        );
    } else if corrupt_current {
        assert_eq!(
            result.unwrap_err().to_string(),
            meta_error(codec::decode_ref_id(&corrupt).unwrap_err()).to_string()
        );
    } else {
        result.unwrap();
    }
    assert_eq!(pipe.blobs.calls.load(Ordering::SeqCst), budget);
    assert_eq!(pipe.blobs.charged.load(Ordering::SeqCst), budget);
    assert_eq!(pipe.blobs.maximum.load(Ordering::SeqCst), budget);
    assert_eq!(pipe.blobs.active.load(Ordering::SeqCst), 0);
}
