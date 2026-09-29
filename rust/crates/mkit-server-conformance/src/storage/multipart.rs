//! Shared multipart storage cases for memory, FS, R2 and S3 backends.

use bytes::Bytes;
use mkit_core::hash::hash;
use mkit_core::upload_parts::{MIN_PART_SIZE, PartPlan, part_subtree_cv};
use mkit_server::{
    BlobKey, BlobStore, CommitOutcome, MultipartBlobStore, PackSink, PartRef, PartSink, StoreError,
};

use super::CaseResult::Pass;
use super::Outcome;

/// A new, empty multipart store for each case.
pub trait MultipartHarness: Send + Sync + 'static {
    /// The store under test.
    type Store: MultipartBlobStore + 'static;

    /// Construct a new, empty store.
    fn store(&self) -> Self::Store;
}

impl<F, B> MultipartHarness for F
where
    F: Fn() -> B + Send + Sync + 'static,
    B: MultipartBlobStore + 'static,
{
    type Store = B;

    fn store(&self) -> B {
        self()
    }
}

const CHUNK: usize = 64 * 1024;

/// Allocator callbacks supplied by each backend test binary.
#[derive(Clone, Copy, Debug)]
pub struct HeapProbe {
    pub start: fn(),
    pub finish: fn() -> usize,
}

/// Counts the chunks actually accepted by a backend part sink.
struct CountingSink<S> {
    inner: S,
    chunks: usize,
    largest: usize,
}

impl<S: PartSink> CountingSink<S> {
    async fn write(&mut self, chunk: Bytes) -> Result<(), StoreError> {
        self.largest = self.largest.max(chunk.len());
        self.inner.write(chunk).await?;
        self.chunks += 1;
        Ok(())
    }
}

struct Fixture {
    data: Vec<u8>,
    key: BlobKey,
    plan: PartPlan,
}

impl Fixture {
    fn new() -> Self {
        let len = usize::try_from(MIN_PART_SIZE).expect("part size fits usize") * 2 + 11;
        let data: Vec<u8> = (0_u8..=250).cycle().take(len).collect();
        Self {
            key: BlobKey::pack(hash(&data)),
            plan: PartPlan::new(len as u64, MIN_PART_SIZE, u32::MAX)
                .expect("valid multipart fixture"),
            data,
        }
    }

    fn part(&self, index: u32) -> &[u8] {
        let start = usize::try_from(self.plan.offset(index).expect("fixture index"))
            .expect("offset fits usize");
        let len = usize::try_from(self.plan.expected_len(index).expect("fixture index"))
            .expect("part length fits usize");
        &self.data[start..start + len]
    }

    fn cv(&self, index: u32) -> [u8; 32] {
        part_subtree_cv(&self.plan, index, self.part(index)).expect("valid fixture part")
    }
}

async fn session<B: MultipartBlobStore>(s: &B, f: &Fixture) -> Result<Vec<u8>, String> {
    Ok(ok!(s
        .begin_multipart_for_ticket(
            f.key,
            f.plan.total(),
            f.plan.part_size(),
            hash(f.key.hash())
        )
        .await))
}

async fn upload<B: MultipartBlobStore>(
    s: &B,
    f: &Fixture,
    session: &[u8],
    index: u32,
    data: &[u8],
    cv: [u8; 32],
) -> Result<(PartRef, usize), String> {
    let mut sink = ok!(s.begin_part(f.key, session, &f.plan, index, cv).await);
    let mut chunks = 0;
    for piece in data.chunks(CHUNK) {
        ok!(sink.write(Bytes::copy_from_slice(piece)).await);
        chunks += 1;
    }
    let tag = ok!(sink.commit().await);
    Ok((
        PartRef {
            index,
            len: data.len() as u64,
            tag,
        },
        chunks,
    ))
}

async fn upload_all<B: MultipartBlobStore>(
    s: &B,
    f: &Fixture,
    session: &[u8],
) -> Result<Vec<PartRef>, String> {
    let mut parts = Vec::new();
    for index in 0..f.plan.count() {
        parts.push(
            upload(s, f, session, index, f.part(index), f.cv(index))
                .await?
                .0,
        );
    }
    Ok(parts)
}

async fn absent<B: BlobStore>(s: &B, key: &BlobKey) -> Result<(), String> {
    ensure_eq!(ok!(s.head(key).await), None);
    ensure!(
        ok!(s.get(key, None).await).is_none(),
        "uncommitted pack is readable"
    );
    Ok(())
}

/// Parts may arrive in any order; completion reads them by index.
pub async fn multipart_out_of_order<H: MultipartHarness>(h: H) -> Outcome {
    let s = h.store();
    let f = Fixture::new();
    let id = session(&s, &f).await?;
    let mut parts: Vec<Option<PartRef>> = vec![None; 3];
    for index in [2, 0, 1] {
        let (part, _) = upload(&s, &f, &id, index, f.part(index), f.cv(index)).await?;
        parts[index as usize] = Some(part);
        absent(&s, &f.key).await?;
    }
    let parts: Vec<_> = parts.into_iter().map(Option::unwrap).collect();
    ensure_eq!(
        ok!(s.complete(f.key, &id, &f.plan, &parts).await),
        CommitOutcome::Created
    );
    ensure_eq!(
        ok!(s.head(&f.key).await).map(|meta| meta.len),
        Some(f.plan.total())
    );
    Ok(Pass)
}

/// Repeating identical verified bytes returns the same tag.
pub async fn multipart_duplicate_part<H: MultipartHarness>(h: H) -> Outcome {
    let s = h.store();
    let f = Fixture::new();
    let id = session(&s, &f).await?;
    let first = upload(&s, &f, &id, 0, f.part(0), f.cv(0)).await?.0;
    let second = upload(&s, &f, &id, 0, f.part(0), f.cv(0)).await?.0;
    ensure_eq!(first, second);
    absent(&s, &f.key).await?;
    Ok(Pass)
}

/// A different valid CV replaces the index and invalidates the old tag.
pub async fn multipart_replace_verified_part<H: MultipartHarness>(h: H) -> Outcome {
    let s = h.store();
    let f = Fixture::new();
    let id = session(&s, &f).await?;
    let mut parts = upload_all(&s, &f, &id).await?;
    let changed = vec![0x91; f.part(0).len()];
    let new_cv = part_subtree_cv(&f.plan, 0, &changed).map_err(|e| e.to_string())?;
    let replacement = upload(&s, &f, &id, 0, &changed, new_cv).await?.0;
    ensure!(
        replacement.tag != parts[0].tag,
        "replacement retained the old tag"
    );
    ensure_err!(
        s.complete(f.key, &id, &f.plan, &parts).await,
        StoreError::Invalid(_)
    );
    absent(&s, &f.key).await?;
    parts[0] = upload(&s, &f, &id, 0, f.part(0), f.cv(0)).await?.0;
    ensure_eq!(
        ok!(s.complete(f.key, &id, &f.plan, &parts).await),
        CommitOutcome::Created
    );
    Ok(Pass)
}

/// An object key (an object id, not a content hash) completes only through
/// `complete_with_root`: plain `complete` and a wrong root leave nothing
/// visible, and the right root publishes the parts' bytes (WP-4.10).
pub async fn multipart_object_completes_only_against_its_root<H: MultipartHarness>(
    h: H,
) -> Outcome {
    let s = h.store();
    let mut f = Fixture::new();
    let root = *f.key.hash();
    f.key = BlobKey::object(hash(b"an object id, not the content hash"));
    let id = session(&s, &f).await?;
    let parts = upload_all(&s, &f, &id).await?;
    ensure_err!(
        s.complete(f.key, &id, &f.plan, &parts).await,
        StoreError::Invalid(_)
    );
    let wrong = hash(b"wrong root");
    ensure_err!(
        s.complete_with_root(f.key, &id, &f.plan, &parts, wrong)
            .await,
        StoreError::Invalid(_)
    );
    absent(&s, &f.key).await?;
    ensure_eq!(
        ok!(s
            .complete_with_root(f.key, &id, &f.plan, &parts, root)
            .await),
        CommitOutcome::Created
    );
    ensure_eq!(
        ok!(s.head(&f.key).await).map(|meta| meta.len),
        Some(f.plan.total())
    );
    // A pack key refuses a content root, so no caller can bypass the key.
    let pack = Fixture::new();
    let id = session(&s, &pack).await?;
    let parts = upload_all(&s, &pack, &id).await?;
    ensure_err!(
        s.complete_with_root(pack.key, &id, &pack.plan, &parts, root)
            .await,
        StoreError::Invalid(_)
    );
    absent(&s, &pack.key).await?;
    Ok(Pass)
}

/// A failed CV check leaves the old verified part available.
pub async fn multipart_cv_mismatch_keeps_old<H: MultipartHarness>(h: H) -> Outcome {
    let s = h.store();
    let f = Fixture::new();
    let id = session(&s, &f).await?;
    let parts = upload_all(&s, &f, &id).await?;
    let mut sink = ok!(s.begin_part(f.key, &id, &f.plan, 0, f.cv(0)).await);
    let changed = vec![0x91; f.part(0).len()];
    for piece in changed.chunks(CHUNK) {
        ok!(sink.write(Bytes::copy_from_slice(piece)).await);
    }
    ensure_err!(sink.commit().await, StoreError::PartSubtreeMismatch);
    ensure_eq!(
        ok!(s.complete(f.key, &id, &f.plan, &parts).await),
        CommitOutcome::Created
    );
    Ok(Pass)
}

/// A short part fails at commit; a long part fails before it counts.
pub async fn multipart_short_or_long_part<H: MultipartHarness>(h: H) -> Outcome {
    let s = h.store();
    let f = Fixture::new();
    let id = session(&s, &f).await?;
    let mut short = ok!(s.begin_part(f.key, &id, &f.plan, 0, f.cv(0)).await);
    ok!(short
        .write(Bytes::copy_from_slice(&f.part(0)[..CHUNK]))
        .await);
    ensure_err!(short.commit().await, StoreError::Invalid(_));
    let mut long = ok!(s.begin_part(f.key, &id, &f.plan, 2, f.cv(2)).await);
    ensure_err!(
        long.write(Bytes::from(vec![0; f.part(2).len() + 1])).await,
        StoreError::Invalid(_)
    );
    long.abort().await;
    absent(&s, &f.key).await?;
    Ok(Pass)
}

/// Incorrect root or total never publishes a pack.
pub async fn multipart_root_or_total_mismatch<H: MultipartHarness>(h: H) -> Outcome {
    let s = h.store();
    let f = Fixture::new();
    let wrong_key = BlobKey::pack(hash(b"wrong pack"));
    let id = ok!(s
        .begin_multipart_for_ticket(
            wrong_key,
            f.plan.total(),
            f.plan.part_size(),
            hash(wrong_key.hash())
        )
        .await);
    let mut parts = Vec::new();
    for index in 0..f.plan.count() {
        let mut sink = ok!(s
            .begin_part(wrong_key, &id, &f.plan, index, f.cv(index))
            .await);
        for piece in f.part(index).chunks(CHUNK) {
            ok!(sink.write(Bytes::copy_from_slice(piece)).await);
        }
        parts.push(PartRef {
            index,
            len: f.part(index).len() as u64,
            tag: ok!(sink.commit().await),
        });
    }
    ensure_err!(
        s.complete(wrong_key, &id, &f.plan, &parts).await,
        StoreError::Invalid(_)
    );
    absent(&s, &wrong_key).await?;
    let correct_id = session(&s, &f).await?;
    let mut wrong_total = upload_all(&s, &f, &correct_id).await?;
    wrong_total
        .last_mut()
        .ok_or("missing final fixture part")?
        .len += 1;
    ensure_err!(
        s.complete(f.key, &correct_id, &f.plan, &wrong_total).await,
        StoreError::Invalid(_)
    );
    absent(&s, &f.key).await?;
    absent(&s, &wrong_key).await?;
    Ok(Pass)
}

/// A completed session is gone; the committed pack remains unchanged.
pub async fn multipart_complete_twice<H: MultipartHarness>(h: H) -> Outcome {
    let s = h.store();
    let f = Fixture::new();
    let id = session(&s, &f).await?;
    let parts = upload_all(&s, &f, &id).await?;
    ensure_eq!(
        ok!(s.complete(f.key, &id, &f.plan, &parts).await),
        CommitOutcome::Created
    );
    ensure!(
        matches!(
            s.complete(f.key, &id, &f.plan, &parts).await,
            Err(StoreError::SessionGone) | Ok(CommitOutcome::AlreadyPresent)
        ),
        "repeated completion returned neither SessionGone nor AlreadyPresent"
    );
    ensure_eq!(
        ok!(s.head(&f.key).await).map(|meta| meta.len),
        Some(f.plan.total())
    );
    Ok(Pass)
}

/// Racing completions cannot report Invalid after either publishes the pack.
pub async fn multipart_concurrent_complete<H: MultipartHarness>(h: H) -> Outcome {
    let s = std::sync::Arc::new(h.store());
    let f = Fixture::new();
    let id = session(s.as_ref(), &f).await?;
    let parts = upload_all(s.as_ref(), &f, &id).await?;
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));
    let run = |s: std::sync::Arc<H::Store>| {
        let barrier = barrier.clone();
        let id = id.clone();
        let parts = parts.clone();
        let plan = f.plan;
        let key = f.key;
        tokio::spawn(async move {
            barrier.wait().await;
            s.complete(key, &id, &plan, &parts).await
        })
    };
    let first = run(s.clone());
    let second = run(s.clone());
    barrier.wait().await;
    let first = first.await.map_err(|e| e.to_string())?;
    let second = second.await.map_err(|e| e.to_string())?;
    for result in [first, second] {
        ensure!(
            matches!(result, Ok(_) | Err(StoreError::SessionGone)),
            "concurrent completion returned {result:?}"
        );
    }
    ensure_eq!(
        ok!(s.head(&f.key).await).map(|meta| meta.len),
        Some(f.plan.total())
    );
    Ok(Pass)
}

/// Completion of a second session for an existing pack is harmless.
pub async fn multipart_pack_already_present<H: MultipartHarness>(h: H) -> Outcome {
    let s = h.store();
    let f = Fixture::new();
    let mut sink = ok!(s.begin(f.key, f.plan.total()).await);
    for chunk in f.data.chunks(CHUNK) {
        ok!(sink.write(Bytes::copy_from_slice(chunk)).await);
    }
    ensure_eq!(ok!(sink.commit().await), CommitOutcome::Created);
    let id = session(&s, &f).await?;
    let parts = upload_all(&s, &f, &id).await?;
    ensure!(
        matches!(
            s.complete(f.key, &id, &f.plan, &parts).await,
            Ok(CommitOutcome::Created | CommitOutcome::AlreadyPresent)
        ),
        "completion of existing pack failed"
    );
    Ok(Pass)
}

/// Abort is idempotent and revokes the session.
pub async fn multipart_abort_then_session_gone<H: MultipartHarness>(h: H) -> Outcome {
    let s = h.store();
    let f = Fixture::new();
    let id = session(&s, &f).await?;
    ok!(s.abort(f.key, &id).await);
    ok!(s.abort(f.key, &id).await);
    ensure!(
        matches!(
            s.begin_part(f.key, &id, &f.plan, 0, f.cv(0)).await,
            Err(StoreError::SessionGone)
        ),
        "aborted session accepted a part"
    );
    ensure_err!(
        s.complete(f.key, &id, &f.plan, &[]).await,
        StoreError::SessionGone
    );
    absent(&s, &f.key).await?;
    Ok(Pass)
}

/// The harness sends fixed 64 KiB chunks and counts each sink write.
pub async fn multipart_chunked_writes<H: MultipartHarness>(h: H) -> Outcome {
    let s = h.store();
    let f = Fixture::new();
    let id = session(&s, &f).await?;
    let inner = ok!(s.begin_part(f.key, &id, &f.plan, 0, f.cv(0)).await);
    let mut sink = CountingSink {
        inner,
        chunks: 0,
        largest: 0,
    };
    for chunk in f.part(0).chunks(CHUNK) {
        ok!(sink.write(Bytes::copy_from_slice(chunk)).await);
    }
    ensure_eq!(
        sink.chunks,
        usize::try_from(MIN_PART_SIZE).map_err(|e| e.to_string())? / CHUNK
    );
    ensure!(sink.largest <= CHUNK, "a whole part reached the sink");
    ok!(sink.inner.commit().await);
    absent(&s, &f.key).await?;
    Ok(Pass)
}

async fn measured_heap<H: MultipartHarness>(h: H, probe: HeapProbe, buffered: bool) -> Outcome {
    let s = h.store();
    let f = Fixture::new();
    let id = session(&s, &f).await?;
    (probe.start)();
    let first = upload(&s, &f, &id, 0, f.part(0), f.cv(0)).await;
    let upload_peak = (probe.finish)();
    let first = first?.0;
    let mut parts = vec![first];
    for index in 1..f.plan.count() {
        parts.push(
            upload(&s, &f, &id, index, f.part(index), f.cv(index))
                .await?
                .0,
        );
    }
    (probe.start)();
    let completed = s.complete(f.key, &id, &f.plan, &parts).await;
    let complete_peak = (probe.finish)();
    ensure_eq!(ok!(completed), CommitOutcome::Created);
    let limit = usize::try_from(MIN_PART_SIZE / 4).map_err(|e| e.to_string())?;
    if buffered {
        ensure!(
            upload_peak > limit && complete_peak > limit,
            "memory store should expose buffering: upload={upload_peak}, complete={complete_peak}, limit={limit}"
        );
    } else {
        ensure!(
            upload_peak <= limit && complete_peak <= limit,
            "multipart backend buffered too much: upload={upload_peak}, complete={complete_peak}, limit={limit}"
        );
    }
    Ok(Pass)
}

/// The FS and future remote backends must stay below a quarter part of heap.
pub async fn multipart_bounded_heap<H: MultipartHarness>(h: H, probe: HeapProbe) -> Outcome {
    measured_heap(h, probe, false).await
}

/// The reference memory backend intentionally keeps complete parts in RAM.
pub async fn multipart_buffered_heap<H: MultipartHarness>(h: H, probe: HeapProbe) -> Outcome {
    measured_heap(h, probe, true).await
}

/// Dropped attempt and verified but uncompleted parts are never blobs.
pub async fn multipart_crash_leftovers_invisible<H: MultipartHarness>(h: H) -> Outcome {
    let s = h.store();
    let f = Fixture::new();
    let id = session(&s, &f).await?;
    let mut sink = ok!(s.begin_part(f.key, &id, &f.plan, 0, f.cv(0)).await);
    ok!(sink
        .write(Bytes::copy_from_slice(&f.part(0)[..CHUNK]))
        .await);
    drop(sink);
    absent(&s, &f.key).await?;
    upload(&s, &f, &id, 0, f.part(0), f.cv(0)).await?;
    absent(&s, &f.key).await?;
    Ok(Pass)
}
