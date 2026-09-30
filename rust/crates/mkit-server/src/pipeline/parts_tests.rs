//! Multipart pipeline regression tests. `NoMeta` panics on every operation:
//! the upload and completion paths must remain stateless.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use ed25519_dalek::{Signer, SigningKey};
use futures_executor::block_on;
use mkit_core::hash::{hash, to_hex, to_hex_bytes};
use mkit_core::upload_parts::{MIN_PART_SIZE, PartHasher, PartPlan, part_subtree_cv};
use mkit_core::write_auth::{Context, Operation as SignedOp};

use super::*;
use crate::auth_v2::AuthV2Config;
use crate::error::Code;
use crate::memory::MemoryBlobStore;
use crate::pipeline::{Hooks, PipelineConfig, RequestMeta};
use crate::repo::{Addressing, NamespaceKey, RepoId, RepoName};
use crate::rt::ManualClock;
use crate::store::{
    Batch, BatchOutcome, BlobBody, BlobMeta, BlobStore, ByteRange, CommitOutcome, Cursor, Key,
    PackSink, Partition, PartitionStats, ScanPage, StoreCapabilities, Value,
};
use crate::telemetry::{METRIC_REQUESTS, METRIC_UPLOAD_BYTES, Metrics, NoopMetrics};
use crate::upload::UploadLimits;
use crate::upload::marker::upload_marker;
use crate::upload::token::{TicketClaims, TicketKeys};

const AUDIENCE: &str = "https://api.example.test";
const REPO: &str = "room-a";
const T0: i64 = 1_700_000_000_000;

struct NoMeta;

impl NamespaceStore for NoMeta {
    fn capabilities(&self) -> StoreCapabilities {
        StoreCapabilities::full()
    }
    async fn get(&self, _: &Partition, _: &Key) -> Result<Option<Value>, StoreError> {
        panic!("metadata get")
    }
    async fn scan(
        &self,
        _: &Partition,
        _: &Key,
        _: &Key,
        _: Option<&Cursor>,
        _: u32,
    ) -> Result<ScanPage, StoreError> {
        panic!("metadata scan")
    }
    async fn apply(&self, _: &Partition, _: Batch) -> Result<BatchOutcome, StoreError> {
        panic!("metadata apply")
    }
    async fn stats(&self, _: &Partition) -> Result<PartitionStats, StoreError> {
        panic!("metadata stats")
    }
    async fn probe(&self) -> Result<(), StoreError> {
        panic!("metadata probe")
    }
}

type TestPipe = Pipeline<MemoryBlobStore, NoMeta>;

fn keys() -> TicketKeys {
    TicketKeys::new(vec![("active".into(), [7; 32])]).unwrap()
}

fn signer() -> SigningKey {
    SigningKey::from_bytes(&[4; 32])
}

fn pipe_with<B: MultipartBlobStore>(
    blobs: B,
    keys: TicketKeys,
    clock: Arc<ManualClock>,
) -> Pipeline<B, NoMeta> {
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new(REPO).unwrap(),
    };
    let mut cfg = PipelineConfig::new(
        Addressing::Single { repo },
        AuthMode::AuthV2(AuthV2Config::new(AUDIENCE, REPO).unwrap()),
        UploadLimits {
            max_total_bytes: 64 * MIN_PART_SIZE,
            max_chunks: 1024,
        },
    );
    cfg.ticket_keys = Some(keys);
    Pipeline::new(
        blobs,
        NoMeta,
        Hooks::new(),
        cfg,
        clock,
        Arc::new(NoopMetrics),
    )
    .unwrap()
}

fn pipe(blobs: MemoryBlobStore, keys: TicketKeys, clock: Arc<ManualClock>) -> TestPipe {
    pipe_with(blobs, keys, clock)
}

fn signed<B: MultipartBlobStore>(
    pipe: &Pipeline<B, NoMeta>,
    signer: &SigningKey,
    procedure: Procedure,
    commitment: &str,
    nonce: u32,
) -> Authenticated {
    let nonce = format!("{nonce:064x}");
    let operation = SignedOp {
        context: Context {
            audience: AUDIENCE,
            repository: REPO,
        },
        procedure: procedure.connect_path(),
        commitment,
        created_at: T0,
        expires_at: T0 + 300_000,
        nonce: &nonce,
    };
    let signature = signer.sign(&operation.digest().unwrap());
    let headers = [
        ("x-envelope-version", "2".to_owned()),
        ("x-audience", AUDIENCE.to_owned()),
        ("x-repository", REPO.to_owned()),
        ("x-public-key", to_hex(signer.verifying_key().as_bytes())),
        ("x-signature", to_hex_bytes(&signature.to_bytes())),
        ("x-content-commitment", commitment.to_owned()),
        ("x-created-at", T0.to_string()),
        ("x-expires-at", (T0 + 300_000).to_string()),
        ("idempotency-key", nonce),
        ("x-digest", to_hex(&hash(b"complete"))),
    ];
    let header = |name: &str| {
        headers
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.clone())
    };
    pipe.authenticate(&RequestMeta {
        procedure,
        header: &header,
        header_values: None,
        unary_body: if procedure.is_streaming() {
            None
        } else {
            Some(b"complete")
        },
        transport_principal: None,
    })
    .unwrap()
}

fn claims(blobs: &MemoryBlobStore, data: &[u8], signer: &SigningKey) -> TicketClaims {
    let pack_id = hash(data);
    let session =
        block_on(blobs.begin_multipart(BlobKey::pack(pack_id), data.len() as u64, MIN_PART_SIZE))
            .unwrap();
    TicketClaims {
        authority_generation: None,
        ticket_id: [0x11; 32],
        audience: AUDIENCE.into(),
        repository: REPO.into(),
        signer: *signer.verifying_key().as_bytes(),
        pack_id,
        bytes: data.len() as u64,
        part_size: MIN_PART_SIZE,
        expires_at_ms: T0 as u64 + 86_400_000,
        upload_session: session,
    }
}

fn data(parts: usize, tail: usize) -> Vec<u8> {
    (0..=250_u8)
        .cycle()
        .take((parts - 1) * usize::try_from(MIN_PART_SIZE).unwrap() + tail)
        .collect()
}

fn part<'a>(plan: &PartPlan, data: &'a [u8], index: u32) -> &'a [u8] {
    let start = usize::try_from(plan.offset(index).unwrap()).unwrap();
    let len = usize::try_from(plan.expected_len(index).unwrap()).unwrap();
    &data[start..start + len]
}

fn part_auth<B: MultipartBlobStore>(
    pipe: &Pipeline<B, NoMeta>,
    signer: &SigningKey,
    claims: &TicketClaims,
    index: u32,
    cv: &[u8; 32],
    len: u64,
    nonce: u32,
) -> Authenticated {
    let commitment = format!(
        "part:{}:{index}:{}:{len}",
        to_hex(&claims.ticket_id),
        to_hex(cv)
    );
    signed(pipe, signer, Procedure::UploadPart, &commitment, nonce)
}

fn complete_auth<B: MultipartBlobStore>(
    pipe: &Pipeline<B, NoMeta>,
    signer: &SigningKey,
    nonce: u32,
) -> Authenticated {
    signed(
        pipe,
        signer,
        Procedure::CompleteUpload,
        &format!("body:{}", to_hex(&hash(b"complete"))),
        nonce,
    )
}

fn upload(
    pipe: &TestPipe,
    signer: &SigningKey,
    claims: &TicketClaims,
    token: &[u8],
    plan: &PartPlan,
    data: &[u8],
    index: u32,
    nonce: u32,
) -> Vec<u8> {
    let bytes = part(plan, data, index);
    let cv = part_subtree_cv(plan, index, bytes).unwrap();
    let a = part_auth(pipe, signer, claims, index, &cv, bytes.len() as u64, nonce);
    block_on(async {
        let mut session = pipe.open_part(&a, token, index).await.unwrap();
        for chunk in bytes.chunks(64 * 1024) {
            session.push(Bytes::copy_from_slice(chunk)).await.unwrap();
        }
        session.finish().await.unwrap()
    })
}

fn code<T: core::fmt::Debug>(result: Result<T, ServerError>) -> Code {
    result.unwrap_err().code()
}

#[test]
fn out_of_order_duplicate_complete_twice_and_marker_without_metadata() {
    let blobs = MemoryBlobStore::default();
    let keys = keys();
    let pipe = pipe(blobs.clone(), keys.clone(), Arc::new(ManualClock::new(T0)));
    let signer = signer();
    let data = data(2, 5);
    let claims = claims(&blobs, &data, &signer);
    let token = keys.mint(&claims);
    let plan = PartPlan::new(claims.bytes, claims.part_size, 10_000).unwrap();
    let last = upload(&pipe, &signer, &claims, &token, &plan, &data, 1, 1);
    let first = upload(&pipe, &signer, &claims, &token, &plan, &data, 0, 2);
    assert_eq!(
        first,
        upload(&pipe, &signer, &claims, &token, &plan, &data, 0, 3)
    );
    let receipts = vec![first, last];
    let a = complete_auth(&pipe, &signer, 4);
    block_on(pipe.complete_upload(&a, &token, &receipts)).unwrap();
    block_on(pipe.complete_upload(&a, &token, &receipts)).unwrap();
    assert_eq!(
        block_on(blobs.head(&BlobKey::pack(claims.pack_id)))
            .unwrap()
            .unwrap()
            .len,
        claims.bytes
    );
    let (marker, _) = upload_marker(&claims.ticket_id, &claims.pack_id);
    assert!(block_on(blobs.head(&marker)).unwrap().is_some());
}

#[test]
fn upload_part_rejects_binding_geometry_stream_and_token_errors() {
    let blobs = MemoryBlobStore::default();
    let keys = keys();
    let pipe = pipe(blobs.clone(), keys.clone(), Arc::new(ManualClock::new(T0)));
    let signer = signer();
    let data = data(2, 5);
    let claims = claims(&blobs, &data, &signer);
    let token = keys.mint(&claims);
    let plan = PartPlan::new(claims.bytes, claims.part_size, 10_000).unwrap();
    let first = part(&plan, &data, 0);
    let cv = part_subtree_cv(&plan, 0, first).unwrap();
    let a = part_auth(&pipe, &signer, &claims, 0, &cv, first.len() as u64, 1);
    assert_eq!(
        code(block_on(pipe.open_part(&a, &token, 1))),
        Code::PermissionDenied
    );
    let mut other_ticket = claims.clone();
    other_ticket.ticket_id = [0x22; 32];
    assert_eq!(
        code(block_on(pipe.open_part(&a, &keys.mint(&other_ticket), 0))),
        Code::PermissionDenied
    );
    for (index, len) in [(0, MIN_PART_SIZE - 1), (0, MIN_PART_SIZE + 1), (2, 5)] {
        let a = part_auth(&pipe, &signer, &claims, index, &cv, len, index + 10);
        assert_eq!(
            code(block_on(pipe.open_part(&a, &token, index))),
            Code::InvalidArgument
        );
    }
    let a = part_auth(&pipe, &signer, &claims, 0, &[0x55; 32], MIN_PART_SIZE, 20);
    let mut session = block_on(pipe.open_part(&a, &token, 0)).unwrap();
    block_on(session.push(Bytes::copy_from_slice(first))).unwrap();
    assert_eq!(code(block_on(session.finish())), Code::InvalidArgument);
    let mut session = block_on(pipe.open_part(
        &part_auth(&pipe, &signer, &claims, 0, &cv, MIN_PART_SIZE, 21),
        &token,
        0,
    ))
    .unwrap();
    assert_eq!(
        code(block_on(session.push(Bytes::new()))),
        Code::InvalidArgument
    );
    assert_eq!(
        code(block_on(session.push(Bytes::from(vec![
            1;
            usize::try_from(MIN_PART_SIZE).unwrap()
                + 1
        ])))),
        Code::InvalidArgument
    );
    assert_eq!(code(block_on(session.finish())), Code::InvalidArgument);
    let mut foreign_signer = claims.clone();
    foreign_signer.signer = [9; 32];
    assert_eq!(
        code(block_on(pipe.open_part(&a, &keys.mint(&foreign_signer), 0))),
        Code::PermissionDenied
    );
    let mut foreign_repo = claims.clone();
    foreign_repo.repository = "other".into();
    assert_eq!(
        code(block_on(pipe.open_part(&a, &keys.mint(&foreign_repo), 0))),
        Code::PermissionDenied
    );
    let mut expired = claims.clone();
    expired.expires_at_ms = T0 as u64;
    assert_eq!(
        code(block_on(pipe.open_part(&a, &keys.mint(&expired), 0))),
        Code::FailedPrecondition
    );
    assert_eq!(
        code(block_on(pipe.open_part(&a, b"garbage", 0))),
        Code::FailedPrecondition
    );
    let mut no_session = claims.clone();
    no_session.upload_session.clear();
    assert_eq!(
        code(block_on(pipe.open_part(&a, &keys.mint(&no_session), 0))),
        Code::FailedPrecondition
    );
}

#[test]
fn completion_rejects_receipts_and_wrong_root_before_store() {
    let blobs = MemoryBlobStore::default();
    let keys = keys();
    let pipe = pipe(blobs.clone(), keys.clone(), Arc::new(ManualClock::new(T0)));
    let signer = signer();
    let data = data(2, 5);
    let claims = claims(&blobs, &data, &signer);
    let token = keys.mint(&claims);
    let plan = PartPlan::new(claims.bytes, claims.part_size, 10_000).unwrap();
    let receipts = vec![
        upload(&pipe, &signer, &claims, &token, &plan, &data, 0, 1),
        upload(&pipe, &signer, &claims, &token, &plan, &data, 1, 2),
    ];
    let a = complete_auth(&pipe, &signer, 3);
    assert_eq!(
        code(block_on(pipe.complete_upload(&a, &token, &receipts[..1]))),
        Code::InvalidArgument
    );
    assert_eq!(
        code(block_on(pipe.complete_upload(
            &a,
            &token,
            &[receipts[1].clone(), receipts[0].clone()]
        ))),
        Code::InvalidArgument
    );
    let mut forged = receipts.clone();
    *forged[0].last_mut().unwrap() ^= 1;
    assert_eq!(
        code(block_on(pipe.complete_upload(&a, &token, &forged))),
        Code::InvalidArgument
    );
    let mut foreign = receipts.clone();
    let cv = part_subtree_cv(&plan, 0, part(&plan, &data, 0)).unwrap();
    foreign[0] = receipt::mint(&keys, &[0x99; 32], 0, &cv, MIN_PART_SIZE, &cv).unwrap();
    assert_eq!(
        code(block_on(pipe.complete_upload(&a, &token, &foreign))),
        Code::InvalidArgument
    );
    let mut wrong_len = receipts.clone();
    wrong_len[0] = receipt::mint(&keys, &claims.ticket_id, 0, &cv, MIN_PART_SIZE - 1, &cv).unwrap();
    assert_eq!(
        code(block_on(pipe.complete_upload(&a, &token, &wrong_len))),
        Code::InvalidArgument
    );
    let mut wrong_root = claims.clone();
    wrong_root.pack_id = [0x55; 32];
    assert_eq!(
        code(block_on(pipe.complete_upload(
            &a,
            &keys.mint(&wrong_root),
            &receipts
        ))),
        Code::InvalidArgument
    );
    let mut wrong_total = claims.clone();
    wrong_total.bytes += 1;
    assert_eq!(
        code(block_on(pipe.complete_upload(
            &a,
            &keys.mint(&wrong_total),
            &receipts
        ))),
        Code::InvalidArgument
    );
    assert!(
        block_on(blobs.head(&BlobKey::pack(claims.pack_id)))
            .unwrap()
            .is_none()
    );
}

#[test]
fn already_present_pack_aborts_session_and_writes_marker() {
    let blobs = MemoryBlobStore::default();
    let keys = keys();
    let pipe = pipe(blobs.clone(), keys.clone(), Arc::new(ManualClock::new(T0)));
    let signer = signer();
    let data = data(2, 5);
    let claims = claims(&blobs, &data, &signer);
    let token = keys.mint(&claims);
    let plan = PartPlan::new(claims.bytes, claims.part_size, 10_000).unwrap();
    let receipts = vec![
        upload(&pipe, &signer, &claims, &token, &plan, &data, 0, 1),
        upload(&pipe, &signer, &claims, &token, &plan, &data, 1, 2),
    ];
    let mut sink = block_on(blobs.begin(BlobKey::pack(claims.pack_id), claims.bytes)).unwrap();
    for chunk in data.chunks(64 * 1024) {
        block_on(sink.write(Bytes::copy_from_slice(chunk))).unwrap();
    }
    block_on(sink.commit()).unwrap();
    assert_eq!(blobs.multipart_session_count(), 1);
    block_on(pipe.complete_upload(&complete_auth(&pipe, &signer, 3), &token, &receipts)).unwrap();
    assert_eq!(blobs.multipart_session_count(), 0);
    let (marker, _) = upload_marker(&claims.ticket_id, &claims.pack_id);
    assert!(block_on(blobs.head(&marker)).unwrap().is_some());
}

#[test]
fn gone_session_without_pack_is_failed_precondition() {
    let blobs = MemoryBlobStore::default();
    let keys = keys();
    let signer = signer();
    let data = data(2, 5);
    let claims = claims(&blobs, &data, &signer);
    let token = keys.mint(&claims);
    let plan = PartPlan::new(claims.bytes, claims.part_size, 10_000).unwrap();
    let pipe = pipe(blobs.clone(), keys, Arc::new(ManualClock::new(T0)));
    let receipts = vec![
        upload(&pipe, &signer, &claims, &token, &plan, &data, 0, 1),
        upload(&pipe, &signer, &claims, &token, &plan, &data, 1, 2),
    ];
    block_on(blobs.abort(BlobKey::pack(claims.pack_id), &claims.upload_session)).unwrap();
    let err = block_on(pipe.complete_upload(&complete_auth(&pipe, &signer, 3), &token, &receipts))
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(err.public_message(), "invalid or expired upload ticket");
    assert!(
        block_on(blobs.head(&BlobKey::pack(claims.pack_id)))
            .unwrap()
            .is_none()
    );
    let (marker, _) = upload_marker(&claims.ticket_id, &claims.pack_id);
    assert!(block_on(blobs.head(&marker)).unwrap().is_none());
}

#[test]
fn resume_after_dropping_pipeline_state_with_held_receipts() {
    let blobs = MemoryBlobStore::default();
    let keys = keys();
    let clock = Arc::new(ManualClock::new(T0));
    let signer = signer();
    let data = data(3, 1);
    let claims = claims(&blobs, &data, &signer);
    let token = keys.mint(&claims);
    let plan = PartPlan::new(claims.bytes, claims.part_size, 10_000).unwrap();
    let first = {
        let pipe = pipe(blobs.clone(), keys.clone(), clock.clone());
        [
            upload(&pipe, &signer, &claims, &token, &plan, &data, 0, 1),
            upload(&pipe, &signer, &claims, &token, &plan, &data, 1, 2),
        ]
    };
    let pipe = pipe(blobs.clone(), keys, clock);
    let receipts = vec![
        first[0].clone(),
        first[1].clone(),
        upload(&pipe, &signer, &claims, &token, &plan, &data, 2, 3),
    ];
    block_on(pipe.complete_upload(&complete_auth(&pipe, &signer, 4), &token, &receipts)).unwrap();
    assert!(
        block_on(blobs.head(&BlobKey::pack(claims.pack_id)))
            .unwrap()
            .is_some()
    );
}

#[test]
fn verified_reupload_replaces_part_and_old_receipt_cannot_complete() {
    let blobs = MemoryBlobStore::default();
    let keys = keys();
    let pipe = pipe(blobs.clone(), keys.clone(), Arc::new(ManualClock::new(T0)));
    let signer = signer();
    let data = data(2, 5);
    let claims = claims(&blobs, &data, &signer);
    let token = keys.mint(&claims);
    let plan = PartPlan::new(claims.bytes, claims.part_size, 10_000).unwrap();
    let first = upload(&pipe, &signer, &claims, &token, &plan, &data, 0, 1);
    let mut wrong = part(&plan, &data, 1).to_vec();
    wrong[0] ^= 1;
    let wrong_cv = part_subtree_cv(&plan, 1, &wrong).unwrap();
    let a = part_auth(&pipe, &signer, &claims, 1, &wrong_cv, wrong.len() as u64, 2);
    let mut session = block_on(pipe.open_part(&a, &token, 1)).unwrap();
    block_on(session.push(Bytes::from(wrong))).unwrap();
    let wrong_receipt = block_on(session.finish()).unwrap();
    let completion = complete_auth(&pipe, &signer, 3);
    assert_eq!(
        code(block_on(pipe.complete_upload(
            &completion,
            &token,
            &[first.clone(), wrong_receipt.clone()]
        ))),
        Code::InvalidArgument
    );
    assert!(
        block_on(blobs.head(&BlobKey::pack(claims.pack_id)))
            .unwrap()
            .is_none()
    );
    let correct = upload(&pipe, &signer, &claims, &token, &plan, &data, 1, 4);
    assert!(matches!(
        block_on(blobs.complete(
            BlobKey::pack(claims.pack_id),
            &claims.upload_session,
            &plan,
            &[
                PartRef {
                    index: 0,
                    len: MIN_PART_SIZE,
                    tag: receipt::verify(&keys, &first).unwrap().tag
                },
                PartRef {
                    index: 1,
                    len: 5,
                    tag: receipt::verify(&keys, &wrong_receipt).unwrap().tag
                }
            ]
        )),
        Err(StoreError::Invalid(_))
    ));
    block_on(pipe.complete_upload(&completion, &token, &[first, correct])).unwrap();
    assert!(
        block_on(blobs.head(&BlobKey::pack(claims.pack_id)))
            .unwrap()
            .is_some()
    );
}

/// Simulate another completion consuming the session after our first head.
struct ConcurrentComplete<const MAX: u32>(MemoryBlobStore);

impl<const MAX: u32> BlobStore for ConcurrentComplete<MAX> {
    type Sink = crate::memory::MemoryPackSink;
    async fn begin(&self, key: BlobKey, len: u64) -> Result<Self::Sink, StoreError> {
        self.0.begin(key, len).await
    }
    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobBody>, StoreError> {
        self.0.get(key, range).await
    }
    async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
        self.0.head(key).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.0.probe().await
    }
    async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
        self.0.delete(key).await
    }
}

impl<const MAX: u32> MultipartBlobStore for ConcurrentComplete<MAX> {
    type PartSink = crate::memory::MemoryPartSink;
    const MAX_PARTS: u32 = MAX;
    fn supports_multipart(&self) -> bool {
        true
    }
    async fn begin_multipart(
        &self,
        key: BlobKey,
        len: u64,
        part_size: u64,
    ) -> Result<Vec<u8>, StoreError> {
        self.0.begin_multipart(key, len, part_size).await
    }
    async fn begin_part(
        &self,
        key: BlobKey,
        session: &[u8],
        plan: &PartPlan,
        index: u32,
        expected_cv: [u8; 32],
    ) -> Result<Self::PartSink, StoreError> {
        self.0
            .begin_part(key, session, plan, index, expected_cv)
            .await
    }
    async fn complete(
        &self,
        key: BlobKey,
        session: &[u8],
        plan: &PartPlan,
        parts: &[PartRef],
    ) -> Result<CommitOutcome, StoreError> {
        self.0.complete(key, session, plan, parts).await?;
        Err(StoreError::SessionGone)
    }
    async fn abort(&self, key: BlobKey, session: &[u8]) -> Result<(), StoreError> {
        self.0.abort(key, session).await
    }
}

#[test]
fn concurrent_completion_consumes_session_but_retry_succeeds() {
    let blobs = MemoryBlobStore::default();
    let keys = keys();
    let signer = signer();
    let data = data(2, 5);
    let claims = claims(&blobs, &data, &signer);
    let token = keys.mint(&claims);
    let plan = PartPlan::new(claims.bytes, claims.part_size, 10_000).unwrap();
    let upload_pipe = pipe(blobs.clone(), keys.clone(), Arc::new(ManualClock::new(T0)));
    let receipts = vec![
        upload(&upload_pipe, &signer, &claims, &token, &plan, &data, 0, 1),
        upload(&upload_pipe, &signer, &claims, &token, &plan, &data, 1, 2),
    ];
    let concurrent = pipe_with(
        ConcurrentComplete::<{ u32::MAX }>(blobs.clone()),
        keys,
        Arc::new(ManualClock::new(T0)),
    );
    let a = complete_auth(&concurrent, &signer, 3);
    block_on(concurrent.complete_upload(&a, &token, &receipts)).unwrap();
    let (marker, _) = upload_marker(&claims.ticket_id, &claims.pack_id);
    assert!(block_on(blobs.head(&marker)).unwrap().is_some());
    assert!(
        block_on(blobs.head(&BlobKey::pack(claims.pack_id)))
            .unwrap()
            .is_some()
    );
}

#[test]
fn configured_part_limit_must_fit_backend_capacity() {
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new(REPO).unwrap(),
    };
    let mut cfg = PipelineConfig::new(
        Addressing::Single { repo },
        AuthMode::AuthV2(AuthV2Config::new(AUDIENCE, REPO).unwrap()),
        UploadLimits {
            max_total_bytes: 2 * MIN_PART_SIZE,
            max_chunks: 1024,
        },
    );
    cfg.max_parts = 2;
    let err = Pipeline::new(
        ConcurrentComplete::<1>(MemoryBlobStore::default()),
        NoMeta,
        Hooks::new(),
        cfg,
        Arc::new(ManualClock::new(T0)),
        Arc::new(NoopMetrics),
    )
    .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(
        err.public_message(),
        "max_parts exceeds storage backend capacity"
    );
}

#[test]
fn part_rpc_refusals_require_keys_and_auth_v2() {
    let blobs = MemoryBlobStore::default();
    let keys = keys();
    let clock = Arc::new(ManualClock::new(T0));
    let normal = pipe(blobs.clone(), keys.clone(), clock.clone());
    let signer = signer();
    let data = data(2, 1);
    let claims = claims(&blobs, &data, &signer);
    let token = keys.mint(&claims);
    let plan = PartPlan::new(claims.bytes, claims.part_size, 10_000).unwrap();
    let cv = part_subtree_cv(&plan, 0, part(&plan, &data, 0)).unwrap();
    let a_part = part_auth(&normal, &signer, &claims, 0, &cv, MIN_PART_SIZE, 1);
    let a_complete = complete_auth(&normal, &signer, 2);
    let mut no_keys_cfg = normal.cfg.clone();
    no_keys_cfg.ticket_keys = None;
    let no_keys = Pipeline::new(
        blobs.clone(),
        NoMeta,
        Hooks::new(),
        no_keys_cfg,
        clock.clone(),
        Arc::new(NoopMetrics),
    )
    .unwrap();
    let err = block_on(no_keys.open_part(&a_part, &token, 0)).unwrap_err();
    assert_eq!(
        (err.code(), err.public_message()),
        (Code::Unimplemented, "upload tickets are not configured")
    );
    let err = block_on(no_keys.complete_upload(&a_complete, &token, &[])).unwrap_err();
    assert_eq!(
        (err.code(), err.public_message()),
        (Code::Unimplemented, "upload tickets are not configured")
    );
    let mut open_cfg = normal.cfg.clone();
    open_cfg.auth = AuthMode::Open;
    let open = Pipeline::new(
        blobs,
        NoMeta,
        Hooks::new(),
        open_cfg,
        clock,
        Arc::new(NoopMetrics),
    )
    .unwrap();
    let err = block_on(open.open_part(&a_part, &token, 0)).unwrap_err();
    assert_eq!(
        (err.code(), err.public_message()),
        (Code::Unimplemented, "UploadPart requires auth v2")
    );
    let err = block_on(open.complete_upload(&a_complete, &token, &[])).unwrap_err();
    assert_eq!(
        (err.code(), err.public_message()),
        (Code::Unimplemented, "CompleteUpload requires auth v2")
    );
}

#[derive(Default)]
struct PartMetrics(Mutex<Vec<(&'static str, String, u64)>>);

impl Metrics for PartMetrics {
    fn incr(&self, name: &'static str, labels: &[(&'static str, &str)], by: u64) {
        let code = labels
            .iter()
            .find(|(key, _)| *key == "code")
            .map_or("", |(_, value)| value);
        self.0.lock().unwrap().push((name, code.to_owned(), by));
    }
    fn observe_ms(&self, _: &'static str, _: &[(&'static str, &str)], _: f64) {}
}

#[test]
fn part_outcome_records_each_request_once_and_counts_pushed_bytes() {
    let blobs = MemoryBlobStore::default();
    let keys = keys();
    let clock = Arc::new(ManualClock::new(T0));
    let config_pipe = pipe(blobs.clone(), keys.clone(), clock.clone());
    let metrics = Arc::new(PartMetrics::default());
    let pipe = Pipeline::new(
        blobs.clone(),
        NoMeta,
        Hooks::new(),
        config_pipe.cfg.clone(),
        clock,
        metrics.clone(),
    )
    .unwrap();
    let signer = signer();
    let data = data(2, 1);
    let claims = claims(&blobs, &data, &signer);
    let token = keys.mint(&claims);
    let plan = PartPlan::new(claims.bytes, claims.part_size, 10_000).unwrap();
    let bytes = part(&plan, &data, 1);
    let cv = part_subtree_cv(&plan, 1, bytes).unwrap();
    let a = part_auth(&pipe, &signer, &claims, 1, &cv, bytes.len() as u64, 1);
    assert_eq!(
        code(block_on(pipe.open_part(&a, &token, 0))),
        Code::PermissionDenied
    );
    assert_eq!(
        code(block_on(pipe.open_part(&a, b"garbage", 1))),
        Code::FailedPrecondition
    );
    let mut session = block_on(pipe.open_part(&a, &token, 1)).unwrap();
    block_on(session.push(Bytes::copy_from_slice(bytes))).unwrap();
    block_on(session.finish()).unwrap();
    let mut invalid = block_on(pipe.open_part(&a, &token, 1)).unwrap();
    assert_eq!(
        code(block_on(invalid.push(Bytes::new()))),
        Code::InvalidArgument
    );
    block_on(invalid.abort());
    let session = block_on(pipe.open_part(&a, &token, 1)).unwrap();
    drop(session);
    let entries = metrics.0.lock().unwrap();
    let requests: Vec<_> = entries
        .iter()
        .filter(|(name, _, _)| *name == METRIC_REQUESTS)
        .map(|(_, code, _)| code.as_str())
        .collect();
    assert_eq!(
        requests,
        [
            "permission_denied",
            "failed_precondition",
            "ok",
            "invalid_argument",
            "canceled"
        ]
    );
    assert_eq!(
        entries
            .iter()
            .filter(|(name, _, _)| *name == METRIC_UPLOAD_BYTES)
            .map(|(_, _, by)| by)
            .sum::<u64>(),
        bytes.len() as u64
    );
    assert_eq!(
        entries
            .iter()
            .filter(|(name, _, _)| *name == METRIC_UPLOAD_BYTES)
            .count(),
        1
    );
}

/// A sink with only the hasher and counters: it never retains part bytes.
struct CountingStore {
    inner: MemoryBlobStore,
    seen: Arc<Mutex<Vec<usize>>>,
}

struct CountingPart {
    hasher: PartHasher,
    expected: [u8; 32],
    seen: Arc<Mutex<Vec<usize>>>,
}

impl BlobStore for CountingStore {
    type Sink = crate::memory::MemoryPackSink;
    async fn begin(&self, key: BlobKey, len: u64) -> Result<Self::Sink, StoreError> {
        self.inner.begin(key, len).await
    }
    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobBody>, StoreError> {
        self.inner.get(key, range).await
    }
    async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
        self.inner.head(key).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
    async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
        self.inner.delete(key).await
    }
}

impl MultipartBlobStore for CountingStore {
    type PartSink = CountingPart;
    const MAX_PARTS: u32 = u32::MAX;
    fn supports_multipart(&self) -> bool {
        true
    }
    async fn begin_multipart(
        &self,
        key: BlobKey,
        len: u64,
        part_size: u64,
    ) -> Result<Vec<u8>, StoreError> {
        self.inner.begin_multipart(key, len, part_size).await
    }
    async fn begin_part(
        &self,
        _: BlobKey,
        _: &[u8],
        plan: &PartPlan,
        index: u32,
        expected_cv: [u8; 32],
    ) -> Result<Self::PartSink, StoreError> {
        Ok(CountingPart {
            hasher: PartHasher::new(plan, index)
                .map_err(|e| StoreError::Invalid(e.to_string().into()))?,
            expected: expected_cv,
            seen: self.seen.clone(),
        })
    }
    async fn complete(
        &self,
        _: BlobKey,
        _: &[u8],
        _: &PartPlan,
        _: &[PartRef],
    ) -> Result<CommitOutcome, StoreError> {
        unreachable!()
    }
    async fn abort(&self, key: BlobKey, session: &[u8]) -> Result<(), StoreError> {
        self.inner.abort(key, session).await
    }
}

impl PartSink for CountingPart {
    async fn write(&mut self, chunk: Bytes) -> Result<(), StoreError> {
        self.seen.lock().unwrap().push(chunk.len());
        self.hasher
            .update(&chunk)
            .map_err(|e| StoreError::Invalid(e.to_string().into()))
    }
    async fn commit(self) -> Result<Vec<u8>, StoreError> {
        let cv = self
            .hasher
            .finalize()
            .map_err(|e| StoreError::Invalid(e.to_string().into()))?;
        if cv != self.expected {
            return Err(StoreError::Invalid("bad CV".into()));
        }
        Ok(cv.to_vec())
    }
    async fn abort(self) {}
}

#[test]
fn part_pipeline_forwards_chunks_without_buffering_a_part() {
    let inner = MemoryBlobStore::default();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let pipe = pipe_with(
        CountingStore {
            inner: inner.clone(),
            seen: seen.clone(),
        },
        keys(),
        Arc::new(ManualClock::new(T0)),
    );
    let signer = signer();
    let data = data(2, 1);
    let claims = claims(&inner, &data, &signer);
    let plan = PartPlan::new(claims.bytes, claims.part_size, 10_000).unwrap();
    let cv = part_subtree_cv(&plan, 0, part(&plan, &data, 0)).unwrap();
    let auth = part_auth(&pipe, &signer, &claims, 0, &cv, MIN_PART_SIZE, 1);
    let mut session = block_on(pipe.open_part(&auth, &keys().mint(&claims), 0)).unwrap();
    for chunk in part(&plan, &data, 0).chunks(128 * 1024) {
        block_on(session.push(Bytes::copy_from_slice(chunk))).unwrap();
    }
    block_on(session.finish()).unwrap();
    let writes = seen.lock().unwrap();
    assert_eq!(
        writes.iter().sum::<usize>(),
        usize::try_from(MIN_PART_SIZE).unwrap()
    );
    assert!(writes.iter().all(|size| *size <= 128 * 1024));
    assert!(writes.len() > 1);
}

#[test]
fn unrelated_store_invalid_error_has_fixed_public_message() {
    let inner = MemoryBlobStore::default();
    let pipe = pipe_with(
        CountingStore {
            inner: inner.clone(),
            seen: Arc::new(Mutex::new(Vec::new())),
        },
        keys(),
        Arc::new(ManualClock::new(T0)),
    );
    let signer = signer();
    let data = data(2, 1);
    let claims = claims(&inner, &data, &signer);
    let plan = PartPlan::new(claims.bytes, claims.part_size, 10_000).unwrap();
    let bytes = part(&plan, &data, 1);
    let auth = part_auth(&pipe, &signer, &claims, 1, &[0; 32], bytes.len() as u64, 1);
    let mut session = block_on(pipe.open_part(&auth, &keys().mint(&claims), 1)).unwrap();
    block_on(session.push(Bytes::copy_from_slice(bytes))).unwrap();
    let err = block_on(session.finish()).unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(err.public_message(), "invalid multipart upload state");
}
