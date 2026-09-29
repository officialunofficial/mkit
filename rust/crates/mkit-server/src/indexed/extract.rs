//! Extraction of file content into the deployment-wide object store
//! (SPEC-SERVER §9.6, WP-4.10, R-163). Runtime-agnostic: the native inline
//! verifier drives it per pack, and a Worker driver (WP-4.10b) will reuse the
//! selection, the per-object step and the sidecar codec.
//!
//! Every `ChunkedBlob` and every Blob of at least `extract_min_bytes` that is
//! not merely a chunk of a staged manifest is stored once under its object id
//! (`BlobKey::object`), as raw content (a `ChunkedBlob` as its reassembled
//! chunks), with a chunk-offset sidecar for manifests (`BlobKey::object_offsets`).
//!
//! **Protocol per object** (the order is the invariant: at no instant is a
//! present object without a hold or a holder):
//! 1. take the hold (durable before any byte is reused, §13.4);
//! 2. `head` the object: if it is there with the expected length, skip the
//!    upload (deduplication; `AlreadyPresent` is never used for accounting);
//! 3. otherwise stream the content into a root-verified sink, verifying each
//!    chunk against the verified manifest on the way, then the sidecar;
//! 4. record the holder and release the hold in one `ContentIndex` batch.
//!
//! Nothing here reaches a response except the fixed errors below: chunks come
//! only from this push or this repository's membership (never from the object
//! store), and dedup or storage outcomes map to `pending` or to the generic
//! storage error, so no outcome reveals what the deployment already holds.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use bytes::Bytes;
use mkit_core::hash::{Hash, Hasher, hash};
use mkit_core::object::{ChunkedBlob, Object};
use mkit_core::ops::graph::{ClosureMode, children};
use mkit_core::upload_parts::{MIN_PART_SIZE, PartPlan, part_subtree_cv};

use super::{IndexedConfig, resolve};
use crate::pipeline::{MAX_APPLY_WINDOW, ShardMap};
use crate::repo::RepoId;
use crate::store::{
    BlobKey, BorrowedStore, ContentIndex, HoldOutcome, Holder, MAX_BLOB_PIECE_BYTES,
    MAX_HOLD_TTL_MS, MultipartBlobStore, PackSink, PartRef, PartSink, StoreError,
    index::MAX_LOOKUP_IDS,
};
use crate::telemetry::Metrics;
use crate::{BoxFuture, Clock, MaybeSend, NamespaceStore, ServerError};

/// The staged objects of one advance: canonical bytes, decoded object and
/// the creating ticket's time.
pub(super) type Staged = BTreeMap<Hash, (Vec<u8>, Object, u64)>;

/// Magic of the chunk-offset sidecar.
const OFFSETS_MAGIC: &[u8; 4] = b"MKOF";
/// Least hold lifetime: it must outlive the extraction and the relay.
const MIN_HOLD_TTL_MS: u64 = 60 * 60 * 1000;
/// Slack on top of the apply window and the relay lag bound.
const HOLD_MARGIN_MS: u64 = 10 * 60 * 1000;

/// How an object is extracted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    /// A plain Blob: its data.
    Blob,
    /// A `ChunkedBlob`: its reassembled chunks, plus the offsets sidecar.
    Chunked,
}

/// A pure function of the staged set: every `ChunkedBlob`, and every Blob of
/// at least `min_bytes` except one referenced only as a chunk by a staged
/// manifest (D-3). A Blob that is also referenced by a staged tree is file
/// content and is extracted. A Blob first seen only as a chunk and referenced
/// by a tree in a later push stays unextracted (carry-forward to WP-4.12).
pub(super) fn select(staged: &Staged, min_bytes: u64) -> BTreeMap<Hash, Kind> {
    let (mut chunk_refs, mut tree_refs) = (BTreeSet::new(), BTreeSet::new());
    for (_, object, _) in staged.values() {
        match object {
            Object::ChunkedBlob(cb) => chunk_refs.extend(cb.chunks.iter().copied()),
            Object::Tree(_) => tree_refs.extend(children(object, ClosureMode::History)),
            _ => {}
        }
    }
    staged
        .iter()
        .filter_map(|(id, (_, object, _))| match object {
            Object::ChunkedBlob(_) => Some((*id, Kind::Chunked)),
            Object::Blob(blob)
                if blob.data.len() as u64 >= min_bytes
                    && (!chunk_refs.contains(id) || tree_refs.contains(id)) =>
            {
                Some((*id, Kind::Blob))
            }
            _ => None,
        })
        .collect()
}

/// The content length of a selected object, in bytes.
fn content_len(object: &Object) -> u64 {
    match object {
        Object::Blob(blob) => blob.data.len() as u64,
        Object::ChunkedBlob(cb) => cb.total_size,
        _ => 0,
    }
}

/// The bytes the selection will reassemble, charged against
/// `max_extract_bytes` before anything is written.
pub(super) fn selected_bytes(staged: &Staged, selected: &BTreeMap<Hash, Kind>) -> u64 {
    selected
        .keys()
        .map(|id| content_len(&staged[id].1))
        .fold(0, u64::saturating_add)
}

/// The sidecar of a `ChunkedBlob`: `"MKOF"`, `u32` LE chunk count, then the
/// `chunk_count + 1` prefix offsets as `u64` LE (0 first, `total_size` last),
/// the `boundaries` of `build_range_proof_from`.
pub(super) fn encode_offsets(boundaries: &[u64]) -> Vec<u8> {
    let count = u32::try_from(boundaries.len().saturating_sub(1)).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(8 + boundaries.len() * 8);
    out.extend_from_slice(OFFSETS_MAGIC);
    out.extend_from_slice(&count.to_le_bytes());
    for offset in boundaries {
        out.extend_from_slice(&offset.to_le_bytes());
    }
    out
}

/// The sidecar length of a manifest of `chunks` chunks.
fn offsets_len(chunks: usize) -> u64 {
    8 + (chunks as u64 + 1) * 8
}

/// The deterministic id of the hold `ticket` takes on `object` for `repo`.
pub(super) fn hold_id(repo: &RepoId, ticket: &Hash, object: &Hash) -> Hash {
    let mut hasher = Hasher::new();
    hasher.update(b"mkit-extract-hold:v1");
    for part in [repo.namespace.as_str(), repo.name.as_str()] {
        hasher.update(&u32::try_from(part.len()).unwrap_or(u32::MAX).to_le_bytes());
        hasher.update(part.as_bytes());
    }
    hasher.update(ticket);
    hasher.update(object);
    hasher.finalize()
}

/// `min(MAX_HOLD_TTL_MS, max(1 h, apply window + relay lag bound + margin))`
/// (D-9).
pub(super) fn hold_ttl_ms(relay_lag_bound_ms: u64) -> u64 {
    let window = u64::try_from(MAX_APPLY_WINDOW.as_millis()).unwrap_or(u64::MAX);
    window
        .saturating_add(relay_lag_bound_ms)
        .saturating_add(HOLD_MARGIN_MS)
        .clamp(MIN_HOLD_TTL_MS, MAX_HOLD_TTL_MS)
}

fn inconsistent() -> ServerError {
    tracing::error!("extraction found verified pack content inconsistent");
    ServerError::unavailable("verified pack content inconsistency")
}

fn blocked() -> ServerError {
    ServerError::permission_denied("object blocked")
}

/// A store error on the blob side: a full spool or disk is retryable
/// `pending`, a failed check is an inconsistency, the rest a storage error.
fn blob_error(error: &StoreError) -> ServerError {
    match error {
        StoreError::Full => super::pending(1_000),
        StoreError::Invalid(_) => inconsistent(),
        _ => ServerError::unavailable("object storage request failed"),
    }
}

/// A `ContentIndex` error: contention, a GC delete in progress and a missed
/// deadline are all retryable (`pending`).
fn index_error(error: &StoreError) -> ServerError {
    match error {
        StoreError::Unavailable(_) | StoreError::Full => super::pending(1_000),
        _ => ServerError::unavailable("object storage request failed"),
    }
}

/// Renews the caller's verification lease. The extractor calls it between
/// pieces and before each commit, so a long extraction keeps the lease.
pub(super) trait Renew: MaybeSend {
    fn renew(&mut self) -> BoxFuture<'_, Result<(), ServerError>>;
}

/// [`Renew`] that also keeps the extraction's `ContentIndex` hold alive: past
/// half its lifetime, the hold is taken again (which extends it), so a long
/// stream never outlives the protection GC honors (SPEC-SERVER §13.4, D-9).
struct Held<'a, R, S: NamespaceStore> {
    inner: &'a mut R,
    content: &'a ContentIndex<BorrowedStore<'a, S>>,
    clock: &'a dyn Clock,
    id: Hash,
    hold: Hash,
    ttl_ms: u64,
    renew_at_ms: u64,
}

impl<R: Renew, S: NamespaceStore> Renew for Held<'_, R, S> {
    fn renew(&mut self) -> BoxFuture<'_, Result<(), ServerError>> {
        Box::pin(async move {
            self.inner.renew().await?;
            let now = u64::try_from(self.clock.now_ms()).unwrap_or(0);
            if now >= self.renew_at_ms {
                let until = now.saturating_add(self.ttl_ms);
                match self
                    .content
                    .add_hold(&self.id, &self.hold, until, now)
                    .await
                {
                    Ok(HoldOutcome::Held) => {}
                    Ok(_) => return Err(blocked()),
                    Err(e) => return Err(index_error(&e)),
                }
                self.renew_at_ms = now.saturating_add(self.ttl_ms / 2);
            }
            Ok(())
        })
    }
}

/// Largest part an extraction upload uses (the protocol's 32 MiB bound).
const MAX_PART_SIZE: u64 = 32 * 1024 * 1024;

/// Where a [`Writer`]'s bytes go.
enum Target<B: MultipartBlobStore> {
    /// One `begin` upload.
    Single(B::Sink),
    /// An object beyond the backend's `single_put_limit`: parts, buffered one
    /// at a time, with server-computed part CVs (D-4).
    Parts {
        session: Vec<u8>,
        plan: PartPlan,
        buffer: Vec<u8>,
        parts: Vec<PartRef>,
    },
}

/// A root-verified upload of one object-store key.
struct Writer<'a, B: MultipartBlobStore> {
    blobs: &'a B,
    key: BlobKey,
    target: Target<B>,
    expected: u64,
    written: u64,
    hasher: Hasher,
}

impl<B: MultipartBlobStore> Writer<'_, B> {
    /// Append `data` in pieces of at most [`MAX_BLOB_PIECE_BYTES`].
    async fn push<R: Renew>(&mut self, data: &[u8], renew: &mut R) -> Result<(), ServerError> {
        for piece in data.chunks(MAX_BLOB_PIECE_BYTES) {
            renew.renew().await?;
            let total = self.written.checked_add(piece.len() as u64);
            if total.is_none_or(|total| total > self.expected) {
                return Err(inconsistent());
            }
            self.hasher.update(piece);
            self.put(piece).await.map_err(|e| blob_error(&e))?;
            self.written += piece.len() as u64;
        }
        Ok(())
    }

    async fn put(&mut self, mut piece: &[u8]) -> Result<(), StoreError> {
        if let Target::Single(sink) = &mut self.target {
            return sink.write(Bytes::copy_from_slice(piece)).await;
        }
        while !piece.is_empty() {
            let Target::Parts { plan, buffer, .. } = &mut self.target else {
                return Ok(());
            };
            let part = usize::try_from(plan.part_size()).unwrap_or(usize::MAX);
            let take = (part - buffer.len()).min(piece.len());
            buffer.extend_from_slice(&piece[..take]);
            piece = &piece[take..];
            if buffer.len() == part {
                self.flush_part().await?;
            }
        }
        Ok(())
    }

    /// Upload the buffered part: its CV is computed here, and the store
    /// verifies the bytes it receives against it.
    async fn flush_part(&mut self) -> Result<(), StoreError> {
        let Target::Parts {
            session,
            plan,
            buffer,
            parts,
        } = &mut self.target
        else {
            return Ok(());
        };
        let index = u32::try_from(parts.len()).map_err(|_| StoreError::Invalid("parts".into()))?;
        let cv = part_subtree_cv(plan, index, buffer)
            .map_err(|e| StoreError::Invalid(e.to_string().into()))?;
        let mut sink = self
            .blobs
            .begin_part(self.key, session, plan, index, cv)
            .await?;
        for piece in buffer.chunks(MAX_BLOB_PIECE_BYTES) {
            sink.write(Bytes::copy_from_slice(piece)).await?;
        }
        let tag = sink.commit().await?;
        parts.push(PartRef {
            index,
            len: buffer.len() as u64,
            tag,
        });
        buffer.clear();
        Ok(())
    }

    /// Commit against the running content hash: the store checks that the
    /// bytes it holds are the bytes that were verified here. A failure
    /// aborts a multipart session, except a lost lease (`renew` fails):
    /// the verifier that took over shares the session, so it is left to it.
    async fn finish<R: Renew>(mut self, renew: &mut R) -> Result<(), ServerError> {
        if self.written != self.expected {
            self.abort().await;
            return Err(inconsistent());
        }
        renew.renew().await?;
        let root = self.hasher.finalize();
        if matches!(&self.target, Target::Parts { buffer, .. } if !buffer.is_empty())
            && let Err(e) = self.flush_part().await
        {
            self.abort().await;
            return Err(blob_error(&e));
        }
        let stored = match self.target {
            Target::Single(sink) => sink.commit_with_root(root).await,
            Target::Parts {
                session,
                plan,
                parts,
                ..
            } => {
                let done = self
                    .blobs
                    .complete_with_root(self.key, &session, &plan, &parts, root)
                    .await;
                if done.is_err() {
                    let _ = self.blobs.abort(self.key, &session).await;
                }
                done
            }
        };
        stored.map(drop).map_err(|e| blob_error(&e))
    }

    /// Discard the upload; nothing is visible.
    async fn abort(self) {
        match self.target {
            Target::Single(sink) => sink.abort().await,
            Target::Parts { session, .. } => {
                let _ = self.blobs.abort(self.key, &session).await;
            }
        }
    }
}

/// Everything the per-object step needs, borrowed from the verifier.
pub(super) struct Extractor<'a, B, S> {
    pub blobs: &'a B,
    pub store: &'a S,
    pub shards: &'a dyn ShardMap,
    pub repo: &'a RepoId,
    pub cfg: IndexedConfig,
    pub clock: &'a dyn Clock,
    pub metrics: &'a dyn Metrics,
    pub staged: &'a Staged,
    /// Bytes the staged set already holds of `cfg.decode_budget`.
    pub staged_bytes: u64,
}

impl<B: MultipartBlobStore, S: NamespaceStore> Extractor<'_, B, S> {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.clock.now_ms()).unwrap_or(0)
    }

    /// Extract one selected object under `ticket`'s hold, and record the
    /// repository as its holder.
    ///
    /// # Errors
    /// `permission_denied` `object blocked`; `pending` for a GC delete in
    /// progress, contention or a lost lease; `unavailable` for a storage
    /// failure or an inconsistency in verified content.
    pub(super) async fn extract<R: Renew>(
        &self,
        id: Hash,
        kind: Kind,
        ticket: &Hash,
        renew: &mut R,
    ) -> Result<(), ServerError> {
        let object = &self.staged[&id].1;
        let content = ContentIndex::new(BorrowedStore(self.store));
        let hold = hold_id(self.repo, ticket, &id);
        let ttl_ms = hold_ttl_ms(self.cfg.relay_lag_bound_ms);
        let now = self.now_ms();
        match content
            .add_hold(&id, &hold, now.saturating_add(ttl_ms), now)
            .await
        {
            Ok(HoldOutcome::Held) => {}
            Ok(_) => return Err(blocked()),
            Err(e) => return Err(index_error(&e)),
        }
        let mut keeper = Held {
            inner: renew,
            content: &content,
            clock: self.clock,
            id,
            hold,
            ttl_ms,
            renew_at_ms: now.saturating_add(ttl_ms / 2),
        };
        let renew = &mut keeper;
        renew.renew().await?;
        let (key, len) = (BlobKey::object(id), content_len(object));
        // Reserve the upload before the `head`: a full spool then answers the
        // same whether or not the object is already stored, so that answer
        // reveals nothing about the deployment's contents (§9.6).
        let mut reserved = if self.beyond_single_put(len) {
            None
        } else {
            Some(self.writer(key, len, &hold).await?)
        };
        if self.already_stored(&id, object, kind).await? {
            if let Some(w) = reserved.take() {
                w.abort().await;
            }
        } else {
            match object {
                Object::Blob(blob) => {
                    // A plain Blob rehashes against its id on its canonical bytes.
                    if hash(&self.staged[&id].0) != id {
                        return Err(inconsistent());
                    }
                    let mut w = match reserved.take() {
                        Some(w) => w,
                        None => self.writer(key, len, &hold).await?,
                    };
                    let filled = w.push(&blob.data, renew).await;
                    self.close(w, filled, renew).await?;
                }
                Object::ChunkedBlob(cb) => {
                    self.reassemble(id, cb, &hold, reserved.take(), renew)
                        .await?;
                }
                _ => return Err(inconsistent()),
            }
        }
        renew.renew().await?;
        let holder = Holder::new(self.repo.namespace.clone(), self.repo.name.clone());
        let recorded = content
            .add_holder(&id, &holder, ticket, Some(&hold), self.now_ms())
            .await
            .map_err(|e| index_error(&e))?;
        if recorded.blocked.is_some() {
            return Err(blocked());
        }
        Ok(())
    }

    /// Whether `len` bytes need a multipart upload on this backend.
    fn beyond_single_put(&self, len: u64) -> bool {
        matches!(self.blobs.single_put_limit(), Some(limit) if len > limit)
    }

    /// The object (and a manifest's sidecar) is there with its expected
    /// length: deduplicate. A different length is a corrupt store.
    async fn already_stored(
        &self,
        id: &Hash,
        object: &Object,
        kind: Kind,
    ) -> Result<bool, ServerError> {
        let mut wanted = vec![(BlobKey::object(*id), content_len(object))];
        if let (Kind::Chunked, Object::ChunkedBlob(cb)) = (kind, object) {
            wanted.push((BlobKey::object_offsets(*id), offsets_len(cb.chunks.len())));
        }
        for (key, len) in wanted {
            match self.blobs.head(&key).await {
                Ok(Some(meta)) if meta.len == len => {}
                Ok(Some(_)) => return Err(inconsistent()),
                Ok(None) => return Ok(false),
                Err(e) => return Err(blob_error(&e)),
            }
        }
        Ok(true)
    }

    /// Open the upload of `key`: one put, or parts when `len` exceeds what the
    /// backend's single put carries. `hold` names the multipart session, so a
    /// verifier retrying the same ticket reuses its id (a failed upload
    /// aborts it, so the retry starts over).
    async fn writer(
        &self,
        key: BlobKey,
        len: u64,
        hold: &Hash,
    ) -> Result<Writer<'_, B>, ServerError> {
        let target = if self.beyond_single_put(len) {
            let mut part_size = MIN_PART_SIZE;
            while len.div_ceil(part_size) > u64::from(B::MAX_PARTS) && part_size < MAX_PART_SIZE {
                part_size *= 2;
            }
            let plan = PartPlan::new(len, part_size, B::MAX_PARTS).map_err(|_| inconsistent())?;
            let seed = [b"mkit-extract-session:v1".as_slice(), hold, key.hash()].concat();
            let session = self
                .blobs
                .begin_multipart_for_ticket(key, len, part_size, hash(&seed))
                .await
                .map_err(|e| blob_error(&e))?;
            Target::Parts {
                session,
                plan,
                buffer: Vec::new(),
                parts: Vec::new(),
            }
        } else {
            Target::Single(
                self.blobs
                    .begin(key, len)
                    .await
                    .map_err(|e| blob_error(&e))?,
            )
        };
        Ok(Writer {
            blobs: self.blobs,
            key,
            target,
            expected: len,
            written: 0,
            hasher: Hasher::new(),
        })
    }

    /// Commit `w` if `filled` succeeded, else abort it (nothing is visible).
    async fn close<R: Renew>(
        &self,
        w: Writer<'_, B>,
        filled: Result<(), ServerError>,
        renew: &mut R,
    ) -> Result<(), ServerError> {
        match filled {
            Ok(()) => w.finish(renew).await,
            Err(error) => {
                w.abort().await;
                Err(error)
            }
        }
    }

    /// Stream a manifest's chunks into `Object(id)`, verifying each against
    /// the manifest, then write the offsets sidecar.
    async fn reassemble<R: Renew>(
        &self,
        id: Hash,
        cb: &ChunkedBlob,
        hold: &Hash,
        reserved: Option<Writer<'_, B>>,
        renew: &mut R,
    ) -> Result<(), ServerError> {
        let mut w = match reserved {
            Some(w) => w,
            None => {
                self.writer(BlobKey::object(id), cb.total_size, hold)
                    .await?
            }
        };
        let mut boundaries = Vec::with_capacity(cb.chunks.len() + 1);
        boundaries.push(0);
        let filled = self.stream_chunks(cb, &mut w, &mut boundaries, renew).await;
        self.close(w, filled, renew).await?;
        let sidecar = encode_offsets(&boundaries);
        let mut w = self
            .writer(BlobKey::object_offsets(id), sidecar.len() as u64, hold)
            .await?;
        let filled = w.push(&sidecar, renew).await;
        self.close(w, filled, renew).await
    }

    async fn stream_chunks<R: Renew>(
        &self,
        cb: &ChunkedBlob,
        w: &mut Writer<'_, B>,
        boundaries: &mut Vec<u64>,
        renew: &mut R,
    ) -> Result<(), ServerError> {
        // Member bytes resolved so far, bases included: a manifest may list one
        // member chunk many times, so the resolution work is bounded by the
        // same budget as the reassembled output.
        let mut resolved = 0_u64;
        for window in cb.chunks.chunks(MAX_LOOKUP_IDS) {
            let unstaged: BTreeSet<Hash> = window
                .iter()
                .filter(|id| !self.staged.contains_key(*id))
                .copied()
                .collect();
            let unstaged: Vec<Hash> = unstaged.into_iter().collect();
            let located = if unstaged.is_empty() {
                BTreeMap::new()
            } else {
                resolve::locate_split(self.store, self.shards, self.repo, &unstaged, self.metrics)
                    .await?
            };
            for chunk in window {
                let data = self.chunk_data(chunk, &located, &mut resolved).await?;
                let end = boundaries
                    .last()
                    .and_then(|at| at.checked_add(data.len() as u64))
                    .filter(|end| *end <= cb.total_size)
                    .ok_or_else(inconsistent)?;
                w.push(&data, renew).await?;
                boundaries.push(end);
            }
        }
        if boundaries.last() != Some(&cb.total_size) {
            return Err(inconsistent());
        }
        Ok(())
    }

    /// One chunk's content: from this push, else this repository's
    /// membership (never the object store or another repository). Its
    /// canonical bytes must hash to the manifest's id and be a Blob.
    async fn chunk_data(
        &self,
        id: &Hash,
        located: &BTreeMap<Hash, crate::store::index::ObjectLookup>,
        resolved: &mut u64,
    ) -> Result<Cow<'_, [u8]>, ServerError> {
        if let Some((canonical, object, _)) = self.staged.get(id) {
            // Borrowed: a staged chunk is never copied a second time.
            return match object {
                Object::Blob(blob) if hash(canonical) == *id => Ok(Cow::Borrowed(&blob.data)),
                _ => Err(inconsistent()),
            };
        }
        let Some(Ok(Some(location))) = located.get(id) else {
            return Err(inconsistent());
        };
        // A fresh cache per chunk: the chunk is dropped once written.
        let mut cache = resolve::MemberCache::default();
        let (canonical, _) = resolve::member_object(
            self.blobs,
            self.store,
            self.shards,
            self.repo,
            *id,
            *location,
            self.cfg.max_delta_chain_depth,
            self.cfg.decode_budget.saturating_sub(self.staged_bytes),
            &mut cache,
            &mut BTreeSet::new(),
            self.metrics,
        )
        .await
        .map_err(|failure| match failure {
            resolve::ResolveFailure::Other(error) => error,
            _ => inconsistent(),
        })?;
        *resolved = resolved.saturating_add(cache.retained_bytes());
        if *resolved > self.cfg.max_extract_bytes {
            return Err(ServerError::invalid_argument(
                "pack exceeds indexed decode budget",
            ));
        }
        if hash(&canonical) != *id {
            return Err(inconsistent());
        }
        match mkit_core::serialize::deserialize(&canonical) {
            Ok(Object::Blob(blob)) => Ok(Cow::Owned(blob.data)),
            _ => Err(inconsistent()),
        }
    }
}
