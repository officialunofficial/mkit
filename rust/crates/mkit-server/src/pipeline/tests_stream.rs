//! `UploadSession`, `DownloadStream` and the `test-faults` seam, over the
//! memory stores and a `ManualClock` (WP-M0-05b).

use core::future::poll_fn;

use bytes::Bytes;
use futures_core::Stream;

use super::*;
use crate::download::chunk_plan;
use crate::memory::MemoryPackSink;
use crate::replay::StoredRejection;
use crate::store::{BlobBody, BlobKey, BlobMeta, ByteRange, CommitOutcome, PackSink};
use crate::telemetry::{METRIC_UPLOAD_BYTES, NoopMetrics};
use crate::upload::UploadError;

// ---------------------------------------------------------------- helpers

fn pack(len: usize) -> Vec<u8> {
    (0..=250_u8).cycle().take(len).collect()
}

/// A signed `UploadPack` of `pack` with nonce `n`, created at `T0`.
fn signed_upload(k: &SigningKey, pack: &[u8], n: u32) -> Req {
    let commitment = format!("pack:{}:{}", to_hex(&hash(pack)), pack.len());
    Req::committed(k, Procedure::UploadPack, &commitment, &nonce(n), T0)
}

/// One whole `UploadPack`: header, `chunk`-byte chunks, finish.
fn upload<H: HookSet>(
    env: &Env<H>,
    req: &Req,
    pack: &[u8],
    chunk: usize,
) -> Result<UploadMode, ServerError> {
    let a = env.auth(req)?;
    let id = hash(pack);
    block_on(async {
        let len = Some(pack.len() as u64);
        let mut session = env.pipe.begin_upload(&a, Some(&id), len).await?;
        let mode = session.mode();
        for span in chunk_plan(pack.len() as u64, chunk) {
            let at = usize::try_from(span.offset).unwrap();
            let data = Bytes::copy_from_slice(&pack[at..at + span.len]);
            let complete = session
                .push(Some(&id), Some(span.offset), data, span.last)
                .await?;
            assert_eq!(complete, span.last);
        }
        session.finish().await?;
        Ok(mode)
    })
}

/// The signer's quota: `(ops, bytes)`.
fn quota<H: HookSet>(env: &Env<H>) -> (u32, u64) {
    let rows = env.rows();
    let (_, value) = rows
        .iter()
        .find(|(k, _)| k.as_bytes().starts_with(b"q\0"))
        .unwrap();
    let state = codec::decode_quota_state(value).unwrap();
    (state.ops, state.bytes)
}

fn replay_state<H: HookSet>(env: &Env<H>, req: &Req) -> Option<ReplayState> {
    let scope = env.auth(req).unwrap().auth.unwrap().replay_scope;
    let record = now(read::replay_lookup(
        &env.pipe.meta.inner,
        &ns(),
        &ReplayKey(scope),
    ));
    record.unwrap().map(|r| r.state)
}

fn blob_present<H: HookSet>(env: &Env<H>, pack: &[u8]) -> bool {
    let key = BlobKey::new(hash(pack));
    now(env.pipe.blobs.head(&key)).unwrap().is_some()
}

const IN_FLIGHT: ReplayState = ReplayState::InFlight { resumable: true };

fn committed() -> ReplayState {
    ReplayState::Committed(StoredResult::UploadPack)
}

fn store_blob(blobs: &MemoryBlobStore, bytes: &[u8]) -> PackKey {
    let key = PackKey::new(hash(bytes));
    now(async {
        let mut sink = blobs.begin(key, bytes.len() as u64).await.unwrap();
        sink.write(Bytes::copy_from_slice(bytes)).await.unwrap();
        sink.commit().await.unwrap();
    });
    key
}

fn collect(stream: &mut DownloadStream) -> Vec<Result<DownloadChunk, ServerError>> {
    let mut out = Vec::new();
    while let Some(item) = block_on(poll_fn(|cx| stream.chunks.as_mut().poll_next(cx))) {
        out.push(item);
    }
    out
}

// ------------------------------------------------------------- uploads

#[test]
fn upload_resume_after_fault_does_not_recharge_quota() {
    let env = env(authv2());
    let _armed = env.pipe.blobs.clone().with_fault(MemoryFault::BlobCommit);
    let data = pack(3_000);
    let req = signed_upload(&key(7), &data, 1);
    let err = upload(&env, &req, &data, 1_000).unwrap_err();
    assert_eq!(err.code(), Code::Internal);
    assert!(!blob_present(&env, &data));
    assert_eq!(replay_state(&env, &req), Some(IN_FLIGHT));
    assert_eq!(quota(&env), (1, 3_000));

    // The retry resumes: re-streamed and committed, charged once.
    assert_eq!(upload(&env, &req, &data, 700).unwrap(), UploadMode::Resume);
    assert!(blob_present(&env, &data));
    assert_eq!(replay_state(&env, &req), Some(committed()));
    assert_eq!(quota(&env), (1, 3_000));
    assert_eq!(env.metrics.count(METRIC_UPLOAD_BYTES), 1);
}

#[test]
fn upload_replay_of_committed_op_succeeds_without_apply() {
    let env = env(authv2());
    let data = pack(10);
    let req = signed_upload(&key(7), &data, 1);
    assert_eq!(upload(&env, &req, &data, 4).unwrap(), UploadMode::Fresh);
    // Reservation, then commit: two batches, the second with a fresh
    // deadline guarding the in-flight record it read.
    let batches = env.batches();
    assert_eq!(batches.len(), 2);
    let scope = env.auth(&req).unwrap().auth.unwrap().replay_scope;
    let record = keys::replay(&scope);
    let guards = |b: &Batch, want: &dyn Fn(&Precondition) -> bool| b.preconditions.iter().any(want);
    assert!(guards(&batches[0], &|p| *p == Precondition::Absent(record.clone())));
    assert!(guards(&batches[1], &|p| {
        matches!(p, Precondition::Equals(k, _) if *k == record)
    }));
    let calls = env.pipe.meta.calls();

    assert_eq!(upload(&env, &req, &data, 4).unwrap(), UploadMode::Replay);
    assert_eq!(env.batches().len(), 2, "a replay applies nothing");
    assert_eq!(env.pipe.meta.calls(), calls + 1, "one read-ahead only");
    assert_eq!(quota(&env), (1, 10));
    // The same nonce for other bytes is a different operation.
    let other = pack(11);
    let reuse = signed_upload(&key(7), &other, 1);
    let err = upload(&env, &reuse, &other, 4).unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[test]
fn upload_commitment_mismatch_is_unauthenticated_before_reservation() {
    let env = env(authv2());
    let data = pack(12);
    let a = env.auth(&signed_upload(&key(7), &data, 1)).unwrap();
    let id = hash(&data);
    for (pack_id, total) in [(hash(b"other"), 12), (id, 13)] {
        let err = block_on(env.pipe.begin_upload(&a, Some(&pack_id), Some(total))).unwrap_err();
        assert_eq!(err.code(), Code::Unauthenticated);
        assert_eq!(
            err.public_message(),
            "pack header differs from signed commitment"
        );
    }
    assert_eq!(env.pipe.meta.calls(), 0, "nothing read or reserved");
    // A stream signed over a body commitment never uploads.
    let body = Req::signed(&key(7), Procedure::UploadPack, b"x", &nonce(2), T0);
    assert_eq!(code(env.auth(&body)), Code::Unauthenticated);
    // Nor do credentials checked for another procedure.
    let read = env.auth(&Req::unsigned(Procedure::ReadRef)).unwrap();
    let err = block_on(env.pipe.begin_upload(&read, Some(&id), Some(12))).unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);
    assert!(env.rows().is_empty());
}

#[test]
fn upload_hash_mismatch_never_visible() {
    for auth in [authv2(), AuthMode::Open] {
        let env = env(auth);
        let data = pack(20);
        let req = match env.pipe.cfg.auth {
            AuthMode::Open => Req::unsigned(Procedure::UploadPack),
            _ => signed_upload(&key(7), &data, 1),
        };
        let a = env.auth(&req).unwrap();
        let id = hash(&data);
        let err = block_on(async {
            let mut s = env.pipe.begin_upload(&a, Some(&id), Some(20)).await?;
            s.push(Some(&id), Some(0), Bytes::from(vec![0; 20]), true)
                .await?;
            s.finish().await
        })
        .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(
            err.public_message(),
            UploadError::DigestMismatch.connect_message()
        );
        assert!(!blob_present(&env, &data));
        assert!(!blob_present(&env, &[0; 20]));
        if !req.headers.is_empty() {
            // Still resumable with the right bytes.
            assert_eq!(replay_state(&env, &req), Some(IN_FLIGHT));
            assert_eq!(upload(&env, &req, &data, 8).unwrap(), UploadMode::Resume);
        }
    }
}

#[test]
fn upload_framing_errors_map_codes() {
    let env = env(AuthMode::Open);
    let a = env.auth(&Req::unsigned(Procedure::UploadPack)).unwrap();
    let id = hash(b"abc");
    // A header without a pack id.
    let err = block_on(env.pipe.begin_upload(&a, None, Some(3))).unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(
        err.public_message(),
        UploadError::BadPackId {
            chunk: false,
            len: None
        }
        .connect_message()
    );
    block_on(async {
        // An offset gap kills the stream: later calls repeat the error.
        let mut s = env.pipe.begin_upload(&a, Some(&id), Some(3)).await.unwrap();
        s.push(Some(&id), Some(0), Bytes::from_static(b"a"), false)
            .await
            .unwrap();
        let gap = s.push(Some(&id), Some(2), Bytes::from_static(b"c"), true);
        let err = gap.await.unwrap_err();
        let expected = UploadError::OffsetGap {
            offset: 2,
            expected: 1,
        };
        assert_eq!(
            (err.code(), err.public_message()),
            (Code::InvalidArgument, &*expected.connect_message())
        );
        let same = |e: ServerError| (e.code(), e.public_message().to_owned());
        let again = s.push(Some(&id), Some(1), Bytes::from_static(b"bc"), true);
        assert_eq!(same(again.await.unwrap_err()), same(err.clone()));
        assert_eq!(same(s.finish().await.unwrap_err()), same(err));
        // A stream that ends without `last`.
        let mut s = env.pipe.begin_upload(&a, Some(&id), Some(3)).await.unwrap();
        s.push(Some(&id), Some(0), Bytes::from_static(b"ab"), false)
            .await
            .unwrap();
        let err = s.finish().await.unwrap_err();
        assert_eq!(err.public_message(), UploadError::NoLast.connect_message());
    });
    assert!(!blob_present(&env, b"abc"));
    assert!(
        env.rows().is_empty(),
        "an unsigned upload writes no metadata"
    );
}

#[test]
fn upload_oversize_declared_is_resource_exhausted() {
    let env = env(authv2());
    let big = 1_u64 << 21;
    let commitment = format!("pack:{}:{big}", to_hex(&[5; 32]));
    let req = Req::committed(&key(7), Procedure::UploadPack, &commitment, &nonce(1), T0);
    let a = env.auth(&req).unwrap();
    let err = block_on(env.pipe.begin_upload(&a, Some(&[5; 32]), Some(big))).unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted);
    assert!(env.rows().is_empty());
    assert_eq!(env.pipe.meta.calls(), 0);
}

/// Blobs whose sinks record every write's length.
#[derive(Default)]
struct Counting {
    inner: MemoryBlobStore,
    writes: Arc<Mutex<Vec<usize>>>,
}

struct CountingSink(MemoryPackSink, Arc<Mutex<Vec<usize>>>);

impl BlobStore for Counting {
    type Sink = CountingSink;
    async fn begin(&self, key: BlobKey, len: u64) -> Result<CountingSink, StoreError> {
        let sink = self.inner.begin(key, len).await?;
        Ok(CountingSink(sink, self.writes.clone()))
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
        Ok(())
    }
    async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
        self.inner.delete(key).await
    }
}

impl PackSink for CountingSink {
    async fn write(&mut self, chunk: Bytes) -> Result<(), StoreError> {
        self.1.lock().unwrap().push(chunk.len());
        self.0.write(chunk).await
    }
    async fn commit(self) -> Result<CommitOutcome, StoreError> {
        self.0.commit().await
    }
    async fn abort(self) {
        self.0.abort().await;
    }
}

#[test]
fn upload_memory_bounded_by_one_chunk() {
    let clock = clock();
    let blobs = Counting::default();
    let writes = blobs.writes.clone();
    let meta = store(&clock);
    let metrics = Arc::new(NoopMetrics);
    let pipe = Pipeline::new(
        blobs,
        meta,
        Hooks::new(),
        cfg(AuthMode::Open),
        clock,
        metrics,
    )
    .unwrap();
    let data = pack(10_000);
    let id = hash(&data);
    let lookup = |_: &str| None;
    let a = pipe
        .authenticate(&RequestMeta {
            procedure: Procedure::UploadPack,
            header: &lookup,
            unary_body: None,
            transport_principal: None,
        })
        .unwrap();
    block_on(async {
        let mut s = pipe
            .begin_upload(&a, Some(&id), Some(10_000))
            .await
            .unwrap();
        for (i, span) in chunk_plan(10_000, 1_024).enumerate() {
            let at = usize::try_from(span.offset).unwrap();
            let chunk = Bytes::copy_from_slice(&data[at..at + span.len]);
            let probe = chunk.clone();
            s.push(Some(&id), Some(span.offset), chunk, span.last)
                .await
                .unwrap();
            // Each chunk reached the sink during its own push, and the
            // session kept no reference to it.
            assert_eq!(writes.lock().unwrap().len(), i + 1);
            assert_eq!(writes.lock().unwrap()[i], span.len);
            assert!(probe.is_unique());
        }
        s.finish().await.unwrap();
    });
    assert!(writes.lock().unwrap().iter().all(|n| *n <= 1_024));
}

#[test]
fn upload_final_apply_deadline_is_computed_after_streaming() {
    let env = env(authv2());
    let data = pack(64);
    let req = signed_upload(&key(7), &data, 1);
    let a = env.auth(&req).unwrap();
    let id = hash(&data);
    let slow = 3 * i64::try_from(WINDOW).unwrap();
    block_on(async {
        let mut s = env
            .pipe
            .begin_upload(&a, Some(&id), Some(64))
            .await
            .unwrap();
        for span in chunk_plan(64, 16) {
            // A stream slower than the apply window in total.
            env.clock.advance(slow / 4);
            let at = usize::try_from(span.offset).unwrap();
            let chunk = Bytes::copy_from_slice(&data[at..at + span.len]);
            s.push(Some(&id), Some(span.offset), chunk, span.last)
                .await
                .unwrap();
        }
        s.finish().await.unwrap();
    });
    let batches = env.batches();
    let deadline = |b: &Batch| b.preconditions[0].clone();
    assert_eq!(
        deadline(&batches[0]),
        Precondition::NotAfter(ms(T0) + WINDOW)
    );
    assert_eq!(
        deadline(&batches[1]),
        Precondition::NotAfter(ms(T0 + slow) + WINDOW)
    );
    assert_eq!(replay_state(&env, &req), Some(committed()));
}

#[test]
fn authv2_signed_stream_verified() {
    let env = env(authv2());
    let data = pack(2_000);
    let req = signed_upload(&key(7), &data, 1);
    let a = env.auth(&req).unwrap();
    let auth = a.auth.clone().unwrap();
    assert_eq!(
        auth.commitment,
        crate::op::Commitment::Pack {
            id: hash(&data),
            len: 2_000
        }
    );
    assert_eq!(upload(&env, &req, &data, 512).unwrap(), UploadMode::Fresh);
    assert!(blob_present(&env, &data));
    assert_eq!(replay_state(&env, &req), Some(committed()));
    assert_eq!(quota(&env), (1, 2_000));
    // A signature over another procedure never authenticates an upload.
    let mut other = signed_upload(&key(7), &data, 2);
    other.procedure = Procedure::UpdateRef;
    assert_eq!(code(env.auth(&other)), Code::Unauthenticated);
    // Tampered commitment header.
    let tampered = req.header("x-content-commitment", &format!("pack:{}:1", to_hex(&A)));
    assert_eq!(code(env.auth(&tampered)), Code::Unauthenticated);
}

#[test]
fn upload_quota_exhaustion_reserves_nothing() {
    let clock = clock();
    let mut c = cfg(authv2());
    c.write_quota = Some(crate::quota::QuotaLimits {
        max_ops: 10,
        max_bytes: 100,
        window_ms: 10_000,
    });
    let env = build(c, Spy::new(store(&clock)), Hooks::new(), clock);
    let data = pack(101);
    let req = signed_upload(&key(7), &data, 1);
    assert_eq!(code(upload(&env, &req, &data, 50)), Code::ResourceExhausted);
    assert!(env.rows().is_empty());
    assert!(!blob_present(&env, &data));
}

#[test]
fn stream_entry_futures_are_send() {
    fn send<T: Send>(_: &T) {}
    let env = env(AuthMode::Open);
    let a = env.auth(&Req::unsigned(Procedure::UploadPack)).unwrap();
    send(&env.pipe.begin_upload(&a, Some(&[1; 32]), Some(1)));
    let d = env.auth(&Req::unsigned(Procedure::DownloadPack)).unwrap();
    send(&env.pipe.download(&d, PackKey::new([1; 32])));
    let mut s = block_on(env.pipe.begin_upload(&a, Some(&[1; 32]), Some(1))).unwrap();
    send(&s.push(Some(&[1; 32]), Some(0), Bytes::from_static(b"x"), true));
    send(&s.finish());
}

#[test]
fn upload_outliving_its_envelope_commits_the_blob_without_the_record() {
    let env = env(authv2());
    let data = pack(64);
    let req = signed_upload(&key(7), &data, 1);
    let a = env.auth(&req).unwrap();
    let id = hash(&data);
    block_on(async {
        let mut s = env
            .pipe
            .begin_upload(&a, Some(&id), Some(64))
            .await
            .unwrap();
        for span in chunk_plan(64, 16) {
            if span.offset == 16 {
                // Past `expires_at + MAX_CLOCK_LEAD_MS`: no batch of this
                // operation can commit any more.
                env.clock.advance(300_000 + 30_001);
            }
            let at = usize::try_from(span.offset).unwrap();
            let chunk = Bytes::copy_from_slice(&data[at..at + span.len]);
            s.push(Some(&id), Some(span.offset), chunk, span.last)
                .await
                .unwrap();
        }
        s.finish().await.unwrap();
    });
    env.clock.set(T0); // only so the helpers can re-authenticate `req`
    assert!(blob_present(&env, &data));
    assert_eq!(quota(&env), (1, 64), "charged exactly once");
    assert_eq!(
        replay_state(&env, &req),
        Some(IN_FLIGHT),
        "left to the pruner"
    );
    assert_eq!(env.batches().len(), 1, "no commit batch was even tried");
}

/// Refuses every pack with `code`.
struct Refuse(Code);

impl PreReceive for Refuse {
    async fn check(&self, _op: &Operation, _pack: Option<&BlobKey>) -> Result<(), ServerError> {
        Err(ServerError::new(self.0, "pack refused by policy"))
    }
}

fn refusing(code: Code) -> Env<Hooks<OpenAuthorizer, DefaultAdmission, Refuse>> {
    let clock = clock();
    let hooks = Hooks {
        authorizer: OpenAuthorizer,
        admission: DefaultAdmission,
        pre_receive: Refuse(code),
        receipts: NoReceipts,
        outcomes: NoOutcomes,
    };
    build(cfg(authv2()), Spy::new(store(&clock)), hooks, clock)
}

#[test]
fn upload_pre_receive_final_rejection_is_stored_and_answered_before_streaming() {
    let env = refusing(Code::PermissionDenied);
    let data = pack(40);
    let req = signed_upload(&key(7), &data, 1);
    let err = upload(&env, &req, &data, 16).unwrap_err();
    assert_eq!(
        (err.code(), err.public_message()),
        (Code::PermissionDenied, "pack refused by policy")
    );
    let stored = StoredRejection::new(Code::PermissionDenied, "pack refused by policy").unwrap();
    let rejected = ReplayState::Committed(StoredResult::Rejected(stored));
    assert_eq!(replay_state(&env, &req), Some(rejected));
    // `pre_receive` runs after the blob is visible; GC reclaims it.
    assert!(blob_present(&env, &data));
    assert_eq!(quota(&env), (1, 40));
    // The retry is answered at `begin_upload`: one read, no stream, no batch.
    let (calls, batches) = (env.pipe.meta.calls(), env.batches().len());
    let a = env.auth(&req).unwrap();
    let again = block_on(env.pipe.begin_upload(&a, Some(&hash(&data)), Some(40))).unwrap_err();
    assert_eq!(again.code(), Code::PermissionDenied);
    assert_eq!(env.pipe.meta.calls(), calls + 1);
    assert_eq!(env.batches().len(), batches);

    // A retryable refusal is not stored: the record stays resumable.
    let env = refusing(Code::Unavailable);
    let err = upload(&env, &req, &data, 16).unwrap_err();
    assert_eq!(err.code(), Code::Unavailable);
    assert_eq!(replay_state(&env, &req), Some(IN_FLIGHT));
    let a = env.auth(&req).unwrap();
    let session = block_on(env.pipe.begin_upload(&a, Some(&hash(&data)), Some(40))).unwrap();
    assert_eq!(session.mode(), UploadMode::Resume);
}

#[test]
fn upload_replay_never_recreates_a_deleted_blob() {
    let env = env(authv2());
    let data = pack(50);
    let req = signed_upload(&key(7), &data, 1);
    assert_eq!(upload(&env, &req, &data, 16).unwrap(), UploadMode::Fresh);
    // GC or a takedown removes the pack.
    assert!(now(env.pipe.blobs.delete(&PackKey::new(hash(&data)))).unwrap());
    assert_eq!(upload(&env, &req, &data, 16).unwrap(), UploadMode::Replay);
    assert!(!blob_present(&env, &data), "a replay writes no blob");
    // A replay still verifies the stream it is sent.
    let a = env.auth(&req).unwrap();
    let id = hash(&data);
    let err = block_on(async {
        let mut s = env.pipe.begin_upload(&a, Some(&id), Some(50)).await?;
        s.push(Some(&id), Some(0), Bytes::from(vec![0; 50]), true)
            .await?;
        s.finish().await
    })
    .unwrap_err();
    assert_eq!(
        err.public_message(),
        UploadError::DigestMismatch.connect_message()
    );
    assert_eq!(env.batches().len(), 2, "reserve and commit only");
}

/// The `code` label of every request metric for `procedure`, in order.
fn codes<H: HookSet>(env: &Env<H>, procedure: &str) -> Vec<String> {
    let label = |labels: &Labels, name: &str| {
        labels
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
            .unwrap()
    };
    let recorded = env.metrics.0.lock().unwrap();
    recorded
        .iter()
        .filter(|(n, l)| *n == METRIC_REQUESTS && label(l, "procedure") == procedure)
        .map(|(_, l)| label(l, "code"))
        .collect()
}

#[test]
fn upload_session_records_each_request_once_and_drop_as_canceled() {
    let env = env(AuthMode::Open);
    let a = env.auth(&Req::unsigned(Procedure::UploadPack)).unwrap();
    let data = pack(8);
    let id = hash(&data);
    let begin = || block_on(env.pipe.begin_upload(&a, Some(&id), Some(8))).unwrap();
    drop(begin());
    block_on(begin().abort());
    assert_eq!(codes(&env, "UploadPack"), ["canceled", "canceled"]);
    upload(&env, &Req::unsigned(Procedure::UploadPack), &data, 3).unwrap();
    // A failed push records once, however the session then ends.
    let mut s = begin();
    let gap = block_on(s.push(Some(&id), Some(1), Bytes::from_static(b"x"), false));
    assert_eq!(gap.unwrap_err().code(), Code::InvalidArgument);
    assert!(block_on(s.finish()).is_err());
    let mut s = begin();
    assert!(block_on(s.push(Some(&id), None, Bytes::new(), false)).is_err());
    drop(s);
    // `abort_with` records the binding's error; after a failed push the
    // first error stands.
    block_on(begin().abort_with(&ServerError::invalid_argument("second header")));
    let mut s = begin();
    assert!(block_on(s.push(Some(&id), None, Bytes::new(), false)).is_err());
    block_on(s.abort_with(&ServerError::unavailable("ignored")));
    assert_eq!(
        codes(&env, "UploadPack"),
        [
            "canceled",
            "canceled",
            "ok",
            "invalid_argument",
            "invalid_argument",
            "invalid_argument",
            "invalid_argument"
        ]
    );
}

#[test]
fn download_records_at_stream_end_or_drop() {
    let clock = clock();
    let mut c = cfg(AuthMode::Open);
    c.download_chunk_max = 4;
    let env = build(c, Spy::new(store(&clock)), Hooks::new(), clock);
    let key = store_blob(&env.pipe.blobs, &pack(10));
    let a = env.auth(&Req::unsigned(Procedure::DownloadPack)).unwrap();
    let mut stream = block_on(env.pipe.download(&a, key)).unwrap();
    assert!(codes(&env, "DownloadPack").is_empty(), "not at creation");
    assert_eq!(collect(&mut stream).len(), 3);
    assert_eq!(codes(&env, "DownloadPack"), ["ok"]);
    drop(stream);
    // Abandoned after one chunk.
    let mut stream = block_on(env.pipe.download(&a, key)).unwrap();
    let first = block_on(poll_fn(|cx| stream.chunks.as_mut().poll_next(cx)));
    assert!(first.unwrap().is_ok());
    drop(stream);
    let missing = block_on(env.pipe.download(&a, PackKey::new([9; 32])));
    assert_eq!(missing.unwrap_err().code(), Code::NotFound);
    assert_eq!(codes(&env, "DownloadPack"), ["ok", "canceled", "not_found"]);
    // Dropped right after the `last` chunk, never polled to its end: the
    // client has the whole pack, so it is `ok`, not `canceled`.
    let mut stream = block_on(env.pipe.download(&a, key)).unwrap();
    for _ in 0..3 {
        let chunk = block_on(poll_fn(|cx| stream.chunks.as_mut().poll_next(cx)));
        assert!(chunk.unwrap().is_ok());
    }
    drop(stream);
    assert_eq!(
        codes(&env, "DownloadPack"),
        ["ok", "canceled", "not_found", "ok"]
    );
}

// ----------------------------------------------------------- downloads

#[test]
fn download_missing_is_not_found_before_stream() {
    let env = env(AuthMode::Open);
    let a = env.auth(&Req::unsigned(Procedure::DownloadPack)).unwrap();
    let err = block_on(env.pipe.download(&a, PackKey::new([9; 32]))).unwrap_err();
    assert_eq!(err.code(), Code::NotFound);
    // Credentials for another procedure never download.
    let other = env.auth(&Req::unsigned(Procedure::PackExists)).unwrap();
    let err = block_on(env.pipe.download(&other, PackKey::new([9; 32]))).unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);
}

#[test]
fn download_chunks_contiguous_last() {
    let big = crate::store::MAX_BLOB_PIECE_BYTES * 2 + 5;
    for (len, max) in [(0, 4), (1, 4), (12, 4), (10, 4), (big, DOWNLOAD_CHUNK_MAX)] {
        let clock = clock();
        let mut c = cfg(AuthMode::Open);
        c.download_chunk_max = max;
        let env = build(c, Spy::new(store(&clock)), Hooks::new(), clock);
        let data = pack(len);
        let key = store_blob(&env.pipe.blobs, &data);
        let a = env.auth(&Req::unsigned(Procedure::DownloadPack)).unwrap();
        let mut stream = block_on(env.pipe.download(&a, key)).unwrap();
        assert_eq!(stream.total_bytes, len as u64);
        let chunks: Vec<DownloadChunk> = collect(&mut stream)
            .into_iter()
            .map(Result::unwrap)
            .collect();
        let spans: Vec<_> = chunks
            .iter()
            .map(|c| crate::download::ChunkSpan {
                offset: c.offset,
                len: c.data.len(),
                last: c.last,
            })
            .collect();
        let plan: Vec<_> = chunk_plan(len as u64, max).collect();
        assert_eq!(spans, plan, "len {len}");
        let joined: Vec<u8> = chunks.iter().flat_map(|c| c.data.to_vec()).collect();
        assert_eq!(joined, data);
    }
}

#[test]
fn download_short_body_is_internal() {
    let body = BlobBody::Stream {
        len: 10,
        stream: Box::pin(ShortBody(Some(Bytes::from_static(b"12345")))),
    };
    let mut stream = DownloadStream::new(body, 4, None);
    let items = collect(&mut stream);
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].as_ref().unwrap().data, "1234");
    assert_eq!(items[1].as_ref().unwrap_err().code(), Code::Internal);
}

/// One piece, then the end: shorter than its declared length.
struct ShortBody(Option<Bytes>);

impl Stream for ShortBody {
    type Item = Result<Bytes, StoreError>;
    fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.get_mut().0.take().map(Ok))
    }
}

// ------------------------------------------------------------ test faults

#[cfg(not(feature = "test-faults"))]
#[test]
fn test_directive_headers_are_ignored_without_the_feature() {
    let env = env(authv2());
    let u = upd(HEAD, Missing, A);
    let req = Req::update(&key(7), 1, &u, T0).header("x-mkit-test-clock-skew-ms", "5000");
    assert_eq!(env.auth(&req).unwrap().business_skew_ms, 0);
}

#[cfg(feature = "test-faults")]
mod faults {
    use std::sync::mpsc;

    use super::*;

    fn with_faults(env: Env, hooks: impl FaultHooks + 'static) -> Env {
        let Env {
            pipe,
            clock,
            metrics,
        } = env;
        Env {
            pipe: pipe.with_faults(hooks),
            clock,
            metrics,
        }
    }

    #[test]
    fn fault_after_reserve_then_retry_resumes() {
        let env = with_faults(env(authv2()), FailOnce::new());
        for (n, token) in [(1, "after-reserve"), (2, "after-put")] {
            let data = pack(100 + n as usize);
            let req = signed_upload(&key(7), &data, n).header(FAULT_HEADER, token);
            let err = upload(&env, &req, &data, 40).unwrap_err();
            assert_eq!(err.code(), Code::Internal, "{token}");
            assert_eq!(replay_state(&env, &req), Some(IN_FLIGHT));
            assert_eq!(blob_present(&env, &data), token == "after-put");
            assert_eq!(upload(&env, &req, &data, 40).unwrap(), UploadMode::Resume);
            assert_eq!(replay_state(&env, &req), Some(committed()));
            assert_eq!(upload(&env, &req, &data, 40).unwrap(), UploadMode::Replay);
            // One charge per operation, however often it resumed.
            assert_eq!(quota(&env).0, n);
        }
    }

    /// Pauses the first request at `point` until the test releases it.
    struct Gate {
        point: FaultPoint,
        paused: Mutex<Option<mpsc::Sender<()>>>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    impl FaultHooks for Gate {
        async fn at(
            &self,
            point: FaultPoint,
            _op: &Operation,
            _d: &TestDirectives,
        ) -> Result<(), ServerError> {
            if point == self.point {
                let first = self.paused.lock().unwrap().take();
                if let Some(paused) = first {
                    paused.send(()).unwrap();
                    self.release.lock().unwrap().recv().unwrap();
                }
            }
            Ok(())
        }
    }

    fn gate(point: FaultPoint) -> (Gate, mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (paused_tx, paused_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let gate = Gate {
            point,
            paused: Mutex::new(Some(paused_tx)),
            release: Mutex::new(release_rx),
        };
        (gate, paused_rx, release_tx)
    }

    #[test]
    fn fault_hook_can_block_between_authorize_and_apply() {
        let (gate, paused, release) = gate(FaultPoint::AfterAuthorize);
        let env = with_faults(env(authv2()), gate);
        let first = upd(HEAD, Missing, A);
        let racer = upd(HEAD, Missing, B);
        std::thread::scope(|s| {
            let blocked = s.spawn(|| env.update(&Req::update(&key(7), 1, &first, T0), &first));
            paused.recv().unwrap();
            // Another writer commits while the first is held after
            // authorization.
            let won = env.update(&Req::update(&key(8), 2, &racer, T0), &racer);
            assert_eq!(won.unwrap(), UpdateRefResult::Committed);
            release.send(()).unwrap();
            let lost = blocked.join().unwrap().unwrap();
            assert_eq!(lost, UpdateRefResult::Conflict { current: Some(B) });
        });
        assert_eq!(env.read(HEAD), Some(B));
    }

    /// Moves the clock past the apply window at `BeforeFinalApply`, the
    /// first `n` times.
    struct Stall {
        clock: Arc<ManualClock>,
        left: AtomicU32,
        points: Mutex<Vec<FaultPoint>>,
    }

    impl FaultHooks for Arc<Stall> {
        async fn at(
            &self,
            point: FaultPoint,
            _op: &Operation,
            _d: &TestDirectives,
        ) -> Result<(), ServerError> {
            self.points.lock().unwrap().push(point);
            let stall = point == FaultPoint::BeforeFinalApply
                && self
                    .left
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |l| l.checked_sub(1))
                    .is_ok();
            if stall {
                self.clock.advance(i64::try_from(WINDOW).unwrap() + 1);
            }
            Ok(())
        }
    }

    fn stalled(stalls: u32) -> (Env, Arc<Stall>) {
        let env = env(authv2());
        let stall = Arc::new(Stall {
            clock: env.clock.clone(),
            left: AtomicU32::new(stalls),
            points: Mutex::default(),
        });
        (with_faults(env, stall.clone()), stall)
    }

    #[test]
    fn fault_hook_before_final_apply_makes_a_late_batch() {
        // Unary: the paused batch misses its deadline and re-plans once.
        let (env, stall) = stalled(1);
        let u = upd(HEAD, Missing, A);
        let req = Req::update(&key(7), 1, &u, T0);
        assert_eq!(env.update(&req, &u).unwrap(), UpdateRefResult::Committed);
        let batches = env.batches();
        assert_eq!(batches.len(), 2);
        let late = ms(T0) + WINDOW + 1;
        assert_eq!(
            batches[1].preconditions[0],
            Precondition::NotAfter(late + WINDOW)
        );
        assert_eq!(
            *stall.points.lock().unwrap(),
            [
                FaultPoint::AfterAuthenticate,
                FaultPoint::AfterAuthorize,
                FaultPoint::BeforeFinalApply,
                FaultPoint::BeforeFinalApply,
            ]
        );
        // Paused past the window twice: `unavailable`, nothing written.
        let (env, _) = stalled(2);
        assert_eq!(code(env.update(&req, &u)), Code::Unavailable);
        assert!(env.rows().is_empty());

        // Upload: the pause hits the commit batch only, never the
        // reservation; the commit re-plans and lands.
        let (env, stall) = stalled(1);
        let data = pack(30);
        let req = signed_upload(&key(7), &data, 1);
        assert_eq!(upload(&env, &req, &data, 16).unwrap(), UploadMode::Fresh);
        assert_eq!(env.batches().len(), 3);
        assert_eq!(replay_state(&env, &req), Some(committed()));
        assert_eq!(
            *stall.points.lock().unwrap(),
            [
                FaultPoint::AfterAuthenticate,
                FaultPoint::AfterAuthorize,
                FaultPoint::AfterReserve,
                FaultPoint::AfterBlobCommit,
                FaultPoint::BeforeFinalApply,
                FaultPoint::BeforeFinalApply,
            ]
        );
    }

    #[test]
    fn upload_commit_late_after_expiry_still_answers_ok() {
        // Streamed to just before `expires_at`; the commit is then paused
        // past its deadline and past `expires_at` (but not the cap).
        let (env, _) = stalled(1);
        let data = pack(20);
        let req = signed_upload(&key(7), &data, 1);
        let a = env.auth(&req).unwrap();
        let id = hash(&data);
        block_on(async {
            let mut s = env.pipe.begin_upload(&a, Some(&id), Some(20)).await?;
            s.push(Some(&id), Some(0), Bytes::from(data.clone()), true)
                .await?;
            env.clock.set(T0 + 295_000);
            s.finish().await
        })
        .unwrap();
        env.clock.set(T0);
        assert!(blob_present(&env, &data));
        assert_eq!(quota(&env), (1, 20));
        assert_eq!(replay_state(&env, &req), Some(IN_FLIGHT));
        assert_eq!(env.batches().len(), 2, "reserve and one late commit");
    }

    #[test]
    fn clock_skew_directive_shifts_now_for_one_request_only() {
        let env = env(authv2());
        let hour = 3_600_000;
        let u = upd(HEAD, Missing, A);
        // Signed an hour ahead: in the future without the directive.
        let ahead = Req::update(&key(7), 1, &u, T0 + hour);
        assert_eq!(code(env.auth(&ahead)), Code::Unauthenticated);
        let skewed = ahead.header(CLOCK_SKEW_HEADER, &hour.to_string());
        let a = env.auth(&skewed).unwrap();
        assert_eq!(a.test_directives().clock_skew_ms, hour);
        assert_eq!(env.update(&skewed, &u).unwrap(), UpdateRefResult::Committed);
        // The next request runs on the real clock again.
        let next = Req::update(&key(7), 2, &upd(HEAD, Match(A), B), T0);
        let a = env.auth(&next).unwrap();
        assert_eq!(
            (a.business_skew_ms, a.test_directives()),
            (0, &TestDirectives::default())
        );
        let bad = next.header(CLOCK_SKEW_HEADER, "soon");
        assert_eq!(code(env.auth(&bad)), Code::InvalidArgument);
        let faulted = Req::unsigned(Procedure::ReadRef).header(FAULT_HEADER, "after-put");
        let a = env.auth(&faulted).unwrap();
        assert_eq!(a.test_directives().fault.as_deref(), Some("after-put"));
    }

    #[test]
    fn clock_skew_directive_never_moves_deadlines() {
        let env = env(authv2());
        let skew = "-120000";
        let u = upd(HEAD, Missing, A);
        let req = Req::update(&key(7), 1, &u, T0 - 120_000).header(CLOCK_SKEW_HEADER, skew);
        assert_eq!(env.update(&req, &u).unwrap(), UpdateRefResult::Committed);
        let data = pack(8);
        let up = signed_upload(&key(7), &data, 2).header(CLOCK_SKEW_HEADER, "1000");
        upload(&env, &up, &data, 8).unwrap();
        for batch in env.batches() {
            assert_eq!(
                batch.preconditions[0],
                Precondition::NotAfter(ms(T0) + WINDOW)
            );
        }
        assert_eq!(env.batches().len(), 3);
    }
}
