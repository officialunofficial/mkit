use super::read_limits::ReaderSession;
use super::{HookSet, OpKind, Operation, Pipeline, Principal, RequestMeta, ms};
use crate::http_objects::{
    Fail, TakedownVerdict, Target, reach,
    resolve::{self, Budget, Env},
};
use crate::indexed::budget::Budgeted;
use crate::indexed::budget::SliceBudget;
use crate::indexed::resolve::Caps;
use crate::store::{MultipartBlobStore, NamespaceStore, view::ViewStore};
use crate::takedown::{
    denial::{denied, object_denials},
    inventory,
};
use crate::url_token::UrlTarget;
use crate::{Code, RepoId, ServerError};
use std::sync::atomic::{AtomicBool, Ordering};
/// A signed token and expiry; its credential is redacted from Debug.
pub type IssuedUrl = crate::url_token::MintedToken;
use mkit_core::{hash::Hash, object::ObjectType};
use std::collections::{BTreeMap, BTreeSet};
type Prefetched = (BTreeMap<Hash, Vec<u8>>, BTreeMap<Hash, ObjectMetadata>);
/// Verified lengths describe canonical objects separately from logical files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectMetadata {
    /// Reconstructed canonical object kind.
    pub kind: ObjectType,
    /// Length of the complete canonical serialization.
    pub canonical_len: u64,
    /// `Blob` payload or `ChunkedBlob::total_size`; absent for non-file objects.
    pub logical_len: Option<u64>,
}
fn exhausted() -> ServerError {
    super::repo_storage::exhausted()
}
fn resolution_failure(miss: resolve::Miss) -> ServerError {
    if miss == resolve::Miss::Capped {
        exhausted()
    } else {
        failure(miss)
    }
}
/// Stable public message for exhausted object-reader allowances.
pub const OBJECT_READER_LIMIT_MESSAGE: &str = super::repo_storage::OWNER_READ_LIMIT_MESSAGE;
/// Maximum IDs per call; duplicates preserve input order and share proof work.
pub const OBJECT_READER_BATCH: usize = 16;
/// Core call cap inside the Worker invocation allowance.
pub const OBJECT_READER_CALLS: u32 = crate::limits::OBJECT_READER_CALLS;
/// Repository view, with envelope-verified owner authority.
#[derive(Debug)]
pub enum ReaderView<'a> {
    /// Anonymous public-repository reads through published membership and refs.
    Public,
    /// Signed `ListRefs` envelope; authority and epoch are rechecked per batch.
    Owner(&'a RequestMeta<'a>),
}
/// Repository prefetch for `mkit_core::store::MemorySource` and core builders.
#[derive(Debug)]
pub struct ObjectReader<'a, B, N, H> {
    identity: std::sync::Arc<()>,
    pipe: &'a Pipeline<B, N, H>,
    repo: RepoId,
    view: ReaderView<'a>,
    cfg: &'a crate::http_objects::HttpObjectsConfig,
    indexed: &'a crate::indexed::IndexedConfig,
    seams: &'a crate::http_objects::HttpSeams,
}
fn failure<E>(_: E) -> ServerError {
    ServerError::unavailable("object reader unavailable")
}
// A cap converted to absence is consumed: a later, unrelated failure must not
// inherit it.
fn absorb(capped: &AtomicBool) -> bool {
    capped.swap(false, Ordering::SeqCst)
}
// Backend errors redact the spent allowance; an `Unavailable` result while a
// cap is recorded is that cap. Any other typed error passes through.
fn settle<T>(result: Result<T, ServerError>, capped: &AtomicBool) -> Result<T, ServerError> {
    match result {
        Err(error) if error.code() == Code::Unavailable && capped.load(Ordering::SeqCst) => {
            Err(exhausted())
        }
        other => other,
    }
}
fn http_failure(fail: &Fail) -> ServerError {
    ServerError::new(fail.code(), "object reader unavailable")
}
impl<B: MultipartBlobStore, N: NamespaceStore + Clone + 'static, H: HookSet> Pipeline<B, N, H> {
    /// Construct a repository reader using verified owner authority.
    /// # Errors
    /// Missing indexed/HTTP configuration, or invalid/non-owner credentials.
    pub async fn object_reader<'a>(
        &'a self,
        repo: RepoId,
        view: ReaderView<'a>,
    ) -> Result<ObjectReader<'a, B, N, H>, ServerError> {
        let (Some(cfg), Some(indexed), Some(seams)) =
            (&self.cfg.http_objects, &self.cfg.indexed, &self.http_seams)
        else {
            return Err(ServerError::new(Code::Unimplemented, "indexed HTTP config"));
        };
        let reader = ObjectReader {
            identity: std::sync::Arc::new(()),
            pipe: self,
            repo,
            view,
            cfg,
            indexed,
            seams,
        };
        if matches!(reader.view, ReaderView::Owner(_)) {
            let calls = SliceBudget::new(OBJECT_READER_CALLS);
            reader.authorize(&calls).await?;
        }
        Ok(reader)
    }
}
impl<B: MultipartBlobStore, N: NamespaceStore + Clone + 'static, H: HookSet>
    ObjectReader<'_, B, N, H>
{
    async fn authorize(
        &self,
        budget: &SliceBudget,
    ) -> Result<Option<super::Authenticated>, ServerError> {
        for _ in 0..2 {
            budget.charge().map_err(|_| exhausted())?;
        }
        match &self.view {
            ReaderView::Public => {
                let op = Operation::new(
                    self.repo.clone(),
                    Principal::Anonymous,
                    None,
                    OpKind::HttpGet { ref_name: None },
                );
                let capped = AtomicBool::new(false);
                let meta = Budgeted::capture(&self.pipe.meta, &capped);
                self.pipe
                    .authorize_http_read_with_meta(
                        &op,
                        &Target::Object([0; 32]),
                        self.seams,
                        None,
                        &meta,
                    )
                    .await
                    .map_err(|e| {
                        if capped.load(Ordering::SeqCst) {
                            exhausted()
                        } else {
                            http_failure(&e)
                        }
                    })?;
                Ok(None)
            }
            ReaderView::Owner(meta) => self.pipe.authorize_owner(&self.repo, meta).await.map(Some),
        }
    }
    /// Prefetch canonical bytes; inaccessible IDs are uniformly absent.
    /// # Errors
    /// Oversized batches, invalid authority, exhausted budgets or store failures.
    pub async fn read_canonical(&self, ids: &[Hash]) -> Result<Vec<Option<Vec<u8>>>, ServerError> {
        self.read_canonical_with_limit(ids, self.cfg.http_decode_budget)
            .await
    }
    /// Bound canonical decode work (including ancestors/bases) and output bytes
    /// for this call. Duplicate outputs count individually. Inaccessible ids
    /// remain absent. Length checks precede requested-object allocation.
    /// # Errors
    /// `ResourceExhausted` for the caller cap; other errors as `read_canonical`.
    pub async fn read_canonical_with_limit(
        &self,
        ids: &[Hash],
        max_bytes: u64,
    ) -> Result<Vec<Option<Vec<u8>>>, ServerError> {
        let (bytes, _) = self.batch_limited(ids, false, Some(max_bytes)).await?;
        Ok(ids.iter().map(|id| bytes.get(id).cloned()).collect())
    }
    /// Prefetch canonical bytes using an aggregate session allowance and
    /// request-local graph proofs. Keep this reader and session across levels;
    /// use a new session for new commits. See [`ReaderSession`] for root capture,
    /// fixed expiry and live authorization semantics.
    /// # Errors
    /// As [`Self::read_canonical`]; cap hits use `ResourceExhausted` except
    /// unprovable public IDs, which remain uniformly absent.
    pub async fn read_canonical_in(
        &self,
        session: &mut ReaderSession,
        ids: &[Hash],
    ) -> Result<Vec<Option<Vec<u8>>>, ServerError> {
        let (bytes, _) = self
            .batch_limited_in(ids, false, None, Some(session))
            .await?;
        Ok(ids.iter().map(|id| bytes.get(id).cloned()).collect())
    }
    /// Read verified metadata while charging proof work to a shared session.
    /// Metadata emits no canonical output bytes.
    /// # Errors
    /// As [`Self::object_metadata`], with typed exhaustion for authorized writers.
    pub async fn object_metadata_in(
        &self,
        session: &mut ReaderSession,
        ids: &[Hash],
    ) -> Result<Vec<Option<ObjectMetadata>>, ServerError> {
        let (_, metadata) = self
            .batch_limited_in(ids, true, None, Some(session))
            .await?;
        Ok(ids.iter().map(|id| metadata.get(id).copied()).collect())
    }
    /// Verified object metadata without fetching requested canonical bytes.
    /// # Errors
    /// Invalid authority, incomplete proof, corrupt facts or storage failure.
    pub async fn object_metadata(
        &self,
        ids: &[Hash],
    ) -> Result<Vec<Option<ObjectMetadata>>, ServerError> {
        let (_, metadata) = self.batch(ids, true).await?;
        Ok(ids.iter().map(|id| metadata.get(id).copied()).collect())
    }
    /// Issue at most 16 URL tokens, preserving order and duplicates.
    /// Requires configured URL-token keys. Inaccessible targets are uniformly
    /// absent. Tokens bind unresolved targets exactly as `IssueObjectUrl` does,
    /// after a bounded reachability preflight, including for Owner readers.
    /// # Errors
    /// As [`Self::read_canonical`], plus `unimplemented` without URL-token keys.
    /// Targets whose reachability cannot be proved within decode/walk limits are absent.
    #[allow(clippy::too_many_lines)] // One shared-budget preflight and credential issuance pass.
    pub async fn issue_urls(
        &self,
        targets: &[UrlTarget],
        ttl_s: u32,
    ) -> Result<Vec<Option<IssuedUrl>>, ServerError> {
        if targets.len() > OBJECT_READER_BATCH {
            return Err(ServerError::invalid_argument("batch exceeds 16 targets"));
        }
        if self.pipe.cfg.url_tokens.is_none() {
            return Err(ServerError::unimplemented("URL tokens not configured"));
        }
        let calls = SliceBudget::new(OBJECT_READER_CALLS);
        let capped = AtomicBool::new(false);
        let result = self
            .issue_urls_with_budget(targets, ttl_s, &calls, &capped)
            .await;
        settle(result, &capped)
    }
    #[allow(clippy::too_many_lines)] // Credential issuance and one published proof share a budget.
    async fn issue_urls_with_budget(
        &self,
        targets: &[UrlTarget],
        ttl_s: u32,
        calls: &SliceBudget,
        capped: &AtomicBool,
    ) -> Result<Vec<Option<IssuedUrl>>, ServerError> {
        match self.authorize(calls).await {
            Err(e) if e.code() == Code::NotFound && matches!(self.view, ReaderView::Public) => {
                return Ok(vec![None; targets.len()]);
            }
            other => {
                other?;
            }
        }
        let mut op = match &self.view {
            ReaderView::Owner(meta) => {
                let a = self.pipe.authenticate(meta)?;
                self.pipe.identify(
                    &a,
                    OpKind::ListRefs {
                        prefix: "refs/".into(),
                    },
                )?
            }
            ReaderView::Public => Operation::new(
                self.repo.clone(),
                Principal::Anonymous,
                None,
                OpKind::ListRefs {
                    prefix: "refs/".into(),
                },
            ),
        };
        let repository = if self.repo.namespace == crate::NamespaceKey::deployment_default() {
            self.repo.name.as_str().to_owned()
        } else {
            format!(
                "{}/{}",
                self.repo.namespace.as_str(),
                self.repo.name.as_str()
            )
        };
        let now = self.pipe.clock.now_ms();
        let mut issued = Vec::with_capacity(targets.len());
        let capture = Budgeted::capture(&self.pipe.meta, capped);
        for target in targets {
            calls.charge().map_err(|_| exhausted())?;
            calls.charge().map_err(|_| exhausted())?;
            op.kind = OpKind::IssueObjectUrl {
                target: target.clone(),
                ttl_seconds: ttl_s,
            };
            issued.push(
                match settle(
                    self.pipe
                        .issue_url_with_meta(
                            &op,
                            &repository,
                            target,
                            ttl_s,
                            now,
                            &capture,
                            Some(OBJECT_READER_LIMIT_MESSAGE),
                        )
                        .await,
                    capped,
                ) {
                    Ok(token) => Some(token),
                    Err(e)
                        if matches!(
                            e.code(),
                            Code::NotFound | Code::PermissionDenied | Code::Unauthenticated
                        ) =>
                    {
                        None
                    }
                    Err(e) => return Err(e),
                },
            );
        }
        let meta = Budgeted::new(&self.pipe.meta, calls).flagging(capped);
        let blobs = Budgeted::new(&self.pipe.blobs, calls).flagging(capped);
        let view = ViewStore {
            store: &meta,
            repo: &self.repo,
            writer: false,
            policy: self.pipe.publication_policy.as_deref(),
        };
        let env = Env {
            no_reads: &BTreeSet::new(),
            blobs: &blobs,
            meta: &view,
            shards: self.pipe.shards.as_ref(),
            repo: &self.repo,
            indexed: self.indexed,
            cfg: self.cfg,
            metrics: self.pipe.metrics.as_ref(),
            caps: Caps::Reader,
        };
        let mut decode = Budget(self.cfg.http_decode_budget);
        let mut ids = Vec::with_capacity(targets.len());
        for (target, token) in targets.iter().zip(&issued) {
            if token.is_none() {
                ids.push(None);
                continue;
            }
            let id = match target {
                UrlTarget::Object(id) => Some(*id),
                UrlTarget::Path { reference, path } => {
                    let shard = self.pipe.shards.ref_shard(&self.repo, reference);
                    let tip = match crate::store::read::read_ref(
                        &view,
                        &shard,
                        &self.repo.name,
                        reference,
                    )
                    .await
                    {
                        Err(_) if absorb(capped) => {
                            ids.push(None);
                            continue;
                        }
                        other => other.map_err(failure)?,
                    };
                    if let Some(tip) = tip {
                        let path = if path.is_empty() {
                            Vec::new()
                        } else {
                            path.split('/').map(|p| p.as_bytes().to_vec()).collect()
                        };
                        match resolve::resolve_ref(&env, tip, &path, &mut decode).await {
                            Ok(resolved) => Some(resolved.leaf),
                            Err(resolve::Miss::NotFound | resolve::Miss::Capped) => None,
                            Err(_) if absorb(capped) => None,
                            Err(miss) => return Err(failure(miss)),
                        }
                    } else {
                        None
                    }
                }
            };
            ids.push(id);
        }
        let leaves = ids.iter().flatten().copied().collect::<Vec<_>>();
        let (_, sizes) = self
            .batch_with_budget(
                &leaves,
                true,
                calls,
                false,
                &BTreeSet::new(),
                &mut decode,
                true,
                None,
                None,
                None,
                capped,
            )
            .await?;
        Ok(ids
            .into_iter()
            .zip(issued)
            .map(|(id, token)| id.filter(|id| sizes.contains_key(id)).and(token))
            .collect())
    }
    async fn batch(&self, ids: &[Hash], sizes_only: bool) -> Result<Prefetched, ServerError> {
        self.batch_limited(ids, sizes_only, None).await
    }
    async fn batch_limited(
        &self,
        ids: &[Hash],
        sizes_only: bool,
        max_bytes: Option<u64>,
    ) -> Result<Prefetched, ServerError> {
        self.batch_limited_in(ids, sizes_only, max_bytes, None)
            .await
    }
    async fn batch_limited_in(
        &self,
        ids: &[Hash],
        sizes_only: bool,
        max_bytes: Option<u64>,
        mut session: Option<&mut ReaderSession>,
    ) -> Result<Prefetched, ServerError> {
        if ids.len() > OBJECT_READER_BATCH {
            return Err(ServerError::invalid_argument("batch exceeds 16 ids"));
        }
        let started = ms(self.pipe.clock.now_ms());
        let calls = SliceBudget::new(OBJECT_READER_CALLS);
        if let Some(session) = &session {
            session.io.calls.charge_many(2).map_err(|_| exhausted())?;
        }
        let authority = match self.authorize(&calls).await {
            Err(e) if e.code() == Code::NotFound && matches!(self.view, ReaderView::Public) => {
                return Ok((BTreeMap::new(), BTreeMap::new()));
            }
            other => other?,
        };
        let writer = authority.is_some();
        if let Some(session) = &mut session {
            session
                .proofs
                .bind(&self.identity, authority, started, self.cfg)?;
        }
        let capped = AtomicBool::new(false);
        let allowance = max_bytes
            .unwrap_or(self.cfg.http_decode_budget)
            .min(self.cfg.http_decode_budget);
        let mut decode = Budget(allowance);
        let result = if let Some(session) = session.as_mut() {
            let (io, mut charge, output, proofs) = session.split_with_proofs(allowance);
            self.batch_with_budget(
                ids,
                sizes_only,
                &calls,
                writer,
                &if sizes_only {
                    ids.iter().copied().collect()
                } else {
                    BTreeSet::new()
                },
                &mut charge.budget,
                !writer,
                max_bytes,
                Some((io, output)),
                Some(proofs),
                &capped,
            )
            .await
        } else {
            self.batch_with_budget(
                ids,
                sizes_only,
                &calls,
                writer,
                &if sizes_only {
                    ids.iter().copied().collect()
                } else {
                    BTreeSet::new()
                },
                &mut decode,
                !writer,
                max_bytes,
                None,
                None,
                &capped,
            )
            .await
        };
        settle(result, &capped)
    }

    #[allow(clippy::too_many_lines, clippy::too_many_arguments)] // One shared-budget authorization/resolution pass, in precedence order.
    async fn batch_with_budget(
        &self,
        ids: &[Hash],
        sizes_only: bool,
        calls: &SliceBudget,
        writer: bool,
        forbidden: &BTreeSet<Hash>,
        decode: &mut Budget,
        capped_as_absent: bool,
        max_bytes: Option<u64>,
        mut session: Option<(
            &super::read_limits::IoLedger,
            &mut super::read_limits::OutputBudget,
        )>,
        mut proofs: Option<&mut super::read_proofs::ReadProofs>,
        capped: &AtomicBool,
    ) -> Result<Prefetched, ServerError> {
        let mut output_left = max_bytes
            .unwrap_or(self.cfg.http_decode_budget)
            .min(self.cfg.http_decode_budget);
        if let Some((_, output)) = &session {
            output_left = output_left.min(output.remaining());
        }
        let pipe = self.pipe;
        let (cfg, indexed, seams) = (self.cfg, self.indexed, self.seams);
        let mut meta = Budgeted::new(&pipe.meta, calls).flagging(capped);
        let mut blobs = Budgeted::new(&pipe.blobs, calls).flagging(capped);
        if let Some((io, _)) = &session {
            meta = meta.with_session(&io.calls);
            blobs = blobs.with_session(&io.calls).with_encoded(&io.encoded);
        }
        let view = ViewStore {
            store: &meta,
            repo: &self.repo,
            writer,
            policy: pipe.publication_policy.as_deref(),
        };
        let env = Env {
            no_reads: forbidden,
            blobs: &blobs,
            meta: &view,
            shards: pipe.shards.as_ref(),
            repo: &self.repo,
            indexed,
            cfg,
            metrics: pipe.metrics.as_ref(),
            caps: Caps::Reader,
        };
        let mut located = if capped_as_absent {
            Vec::new()
        } else {
            resolve::locate_ids(&env, ids, resolve::OnCap::Fail)
                .await
                .map_err(resolution_failure)?
                .0
        };
        // Directly denied members are absent even when their reachability
        // cannot be proved within the caller's byte or walk budget.
        let mut clear = Vec::with_capacity(located.len());
        for (id, location) in located {
            if !denied(&meta, &id).await.map_err(failure)?
                && !denied(&meta, &location.pack).await.map_err(failure)?
            {
                clear.push((id, location));
            }
        }
        located = clear;
        // Issuance proves missing IDs too: proof cost must not expose membership.
        let mut targets = if capped_as_absent {
            ids.iter().copied().collect::<BTreeSet<_>>()
        } else {
            located.iter().map(|(id, _)| *id).collect::<BTreeSet<_>>()
        };
        let mut reached = BTreeSet::new();
        let mut fresh = BTreeSet::new();
        if proofs.is_none() && !writer && !pipe.cfg.takedown_denial {
            for id in &targets {
                if meta.charge().is_err() {
                    if capped_as_absent {
                        absorb(capped);
                        break;
                    }
                    return Err(exhausted());
                }
                if seams
                    .reachability
                    .known_reachable(&self.repo, id, ms(pipe.clock.now_ms()))
                    .await?
                {
                    reached.insert(*id);
                }
            }
        }
        if let Some(memo) = &mut proofs {
            match memo
                .revalidate(&meta, &self.repo, seams.takedown.as_ref(), &targets)
                .await
            {
                Err(_) if capped_as_absent && absorb(capped) => {
                    return Ok((BTreeMap::new(), BTreeMap::new()));
                }
                other => other?,
            }
            if !memo.current(ms(pipe.clock.now_ms())) {
                return if capped_as_absent {
                    Ok((BTreeMap::new(), BTreeMap::new()))
                } else {
                    Err(exhausted())
                };
            }
            reached.extend(targets.iter().filter(|id| memo.contains(id)).copied());
        }
        targets.retain(|id| !reached.contains(id));
        if !targets.is_empty() {
            let tips = if let Some(tips) = proofs.as_ref().and_then(|memo| memo.tips.as_ref()) {
                Ok((tips.clone(), false))
            } else {
                pipe.reader_tips(&meta, &self.repo, cfg.max_walk_objects, writer)
                    .await
            };
            // A spent call budget is an unprovable proof, not a store fault.
            let (tips, truncated) = match tips {
                Err(_) if capped_as_absent && absorb(capped) => (Vec::new(), true),
                other => other.map_err(|e| http_failure(&e))?,
            };
            if truncated && !capped_as_absent {
                return Err(exhausted());
            }
            if !truncated {
                if let Some(memo) = &mut proofs
                    && memo.tips.is_none()
                {
                    memo.capture(tips.clone());
                }
                let walked = reach::walk_many_memo(
                    &env,
                    seams.takedown.as_ref(),
                    &tips,
                    &targets,
                    decode,
                    proofs.as_deref_mut(),
                )
                .await;
                let (found, incomplete) = match walked {
                    Err(resolve::Miss::Capped) if capped_as_absent => {
                        (BTreeSet::new(), Some(resolve::Miss::Capped))
                    }
                    Err(_) if capped_as_absent && absorb(capped) => {
                        (BTreeSet::new(), Some(resolve::Miss::Capped))
                    }
                    other => other.map_err(resolution_failure)?,
                };
                if !capped_as_absent && incomplete == Some(resolve::Miss::Capped) {
                    return Err(exhausted());
                }
                fresh.extend(found.iter().copied());
                reached.extend(found);
            }
        }
        if capped_as_absent {
            // Do not locate inaccessible targets: membership-dependent work can
            // distinguish a stored orphan from a missing ID near the call cap.
            let mut accessible = Vec::new();
            for id in &reached {
                if !denied(&meta, id).await.map_err(failure)? {
                    accessible.push(*id);
                }
            }
            located = resolve::locate_ids(&env, &accessible, resolve::OnCap::Skip)
                .await
                .map_err(resolution_failure)?
                .0;
            reached = located.iter().map(|(id, _)| *id).collect();
        }
        let blocked = if pipe.cfg.takedown_denial && !reached.is_empty() {
            object_denials(&view, pipe.shards.as_ref(), &self.repo, &reached, indexed).await?
        } else {
            BTreeSet::new()
        };
        let (mut bytes, mut sizes) = (BTreeMap::new(), BTreeMap::new());
        for (id, located) in located {
            if !reached.contains(&id) || blocked.contains(&id) {
                continue;
            }
            if denied(&meta, &id).await.map_err(failure)?
                || denied(&meta, &located.pack).await.map_err(failure)?
            {
                continue;
            }
            meta.charge().map_err(|_| exhausted())?;
            if !matches!(
                seams.takedown.check(&self.repo, &id).await?,
                TakedownVerdict::Clear
            ) {
                continue;
            }
            if proofs.is_none() && !writer && fresh.contains(&id) {
                seams
                    .reachability
                    .record(&self.repo, &id, ms(pipe.clock.now_ms()));
            }
            if sizes_only {
                if !crate::indexed::resolve::member_dependencies_clear(
                    &view,
                    pipe.shards.as_ref(),
                    &self.repo,
                    id,
                    located,
                    indexed.max_delta_chain_depth,
                    pipe.metrics.as_ref(),
                    Caps::Reader,
                )
                .await?
                {
                    continue;
                }
                let row = inventory::entry(&meta, &located.pack, &id)
                    .await
                    .map_err(failure)?
                    .ok_or_else(|| failure(resolve::Miss::Unavailable))?;
                if row.kind == ObjectType::Delta as u8 {
                    continue;
                }
                let kind = match row.kind {
                    1 => ObjectType::Blob,
                    2 => ObjectType::Tree,
                    3 => ObjectType::Commit,
                    4 => ObjectType::Remix,
                    5 => ObjectType::ChunkedBlob,
                    7 => ObjectType::Tag,
                    _ => return Err(failure(resolve::Miss::Unavailable)),
                };
                if row.canonical_len != located.value.decoded_size {
                    return Err(failure(resolve::Miss::Unavailable));
                }
                sizes.insert(
                    id,
                    ObjectMetadata {
                        kind,
                        canonical_len: row.canonical_len,
                        logical_len: row.logical_len,
                    },
                );
            } else {
                let output = located
                    .value
                    .decoded_size
                    .checked_mul(ids.iter().filter(|requested| **requested == id).count() as u64)
                    .filter(|n| *n <= output_left)
                    .ok_or_else(exhausted)?;
                match resolve::load(&env, id, located, decode).await {
                    Ok(canonical) if resolve::type_of(&canonical) != Some(ObjectType::Delta) => {
                        if canonical.len() as u64 != located.value.decoded_size {
                            return Err(failure(resolve::Miss::Unavailable));
                        }
                        output_left -= output;
                        if let Some((_, budget)) = &mut session {
                            budget.used = budget.used.saturating_add(output);
                        }
                        if let Some(memo) = &mut proofs
                            && memo.can_decode(&id, &canonical)
                            && !seams.takedown.stops_descent(&self.repo, &id)
                        {
                            let object =
                                mkit_core::serialize::deserialize(&canonical).map_err(failure)?;
                            memo.expand(id, located.pack, &object);
                        }
                        bytes.insert(id, canonical.to_vec());
                    }
                    Ok(_) | Err(resolve::Miss::NotFound) => {}
                    Err(miss) => return Err(resolution_failure(miss)),
                }
            }
        }
        if proofs
            .as_ref()
            .is_some_and(|memo| !memo.current(ms(pipe.clock.now_ms())))
        {
            return if capped_as_absent && bytes.is_empty() && sizes.is_empty() {
                Ok((BTreeMap::new(), BTreeMap::new()))
            } else {
                Err(exhausted())
            };
        }
        Ok((bytes, sizes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absorbed_cap_does_not_reclassify_a_later_storage_failure() {
        let capped = AtomicBool::new(true);
        let failed: Result<(), ServerError> = Err(failure(()));
        assert_eq!(
            settle(failed, &capped).unwrap_err().code(),
            Code::ResourceExhausted
        );
        // The cap was converted to absence, so a genuine fault stays one.
        assert!(absorb(&capped));
        let failed: Result<(), ServerError> = Err(failure(()));
        let error = settle(failed, &capped).unwrap_err();
        assert_eq!(error.code(), Code::Unavailable);
        assert!(!absorb(&capped));
    }

    #[test]
    fn settle_leaves_typed_errors_alone() {
        let capped = AtomicBool::new(true);
        let error = settle::<()>(Err(ServerError::permission_denied("x")), &capped).unwrap_err();
        assert_eq!(error.code(), Code::PermissionDenied);
    }
    struct TargetError(Code);
    impl super::super::Authorizer for TargetError {
        async fn authorize(&self, op: &Operation) -> Result<crate::AuthzFacts, ServerError> {
            if op.procedure() == crate::Procedure::IssueObjectUrl {
                Err(ServerError::new(self.0, "target refused"))
            } else {
                Ok(crate::AuthzFacts::default())
            }
        }
    }
    #[test]
    #[allow(clippy::unwrap_used)]
    fn issue_urls_target_authorization_settles_only_unavailable() {
        use super::super::{AuthMode, Hooks, PipelineConfig};
        use crate::repo::{Addressing, NamespaceKey, RepoName};
        use std::sync::Arc;
        for code in [
            Code::Internal,
            Code::InvalidArgument,
            Code::ResourceExhausted,
            Code::Unavailable,
        ] {
            let repo = RepoId {
                namespace: NamespaceKey::deployment_default(),
                name: RepoName::new("reader").unwrap(),
            };
            let mut cfg = PipelineConfig::new(
                Addressing::Multi(crate::repo::MultiAddressing::new()),
                AuthMode::AuthV2(
                    crate::auth_v2::AuthV2Config::new("https://reader.test", "reader").unwrap(),
                ),
                crate::upload::UploadLimits::new(1 << 20, 64),
            );
            cfg.ticket_keys = Some(
                crate::upload::token::TicketKeys::new(vec![("test".into(), [7; 32])]).unwrap(),
            );
            cfg.http_objects = Some(crate::http_objects::HttpObjectsConfig::default());
            cfg.indexed = Some(crate::indexed::IndexedConfig::default());
            cfg.url_tokens = Some(crate::url_token::UrlTokenConfig::new(
                crate::url_token::UrlTokenKeys::new(zeroize::Zeroizing::new([13; 32]), vec![])
                    .unwrap(),
            ));
            let defaults = Hooks::new();
            let hooks = Hooks {
                authorizer: TargetError(code),
                admission: defaults.admission,
                pre_receive: defaults.pre_receive,
                receipts: defaults.receipts,
                outcomes: defaults.outcomes,
            };
            let pipe = Pipeline::new(
                crate::MemoryBlobStore::default(),
                Arc::new(crate::MemoryKv::default()),
                hooks,
                cfg,
                Arc::new(crate::rt::ManualClock::new(0)),
                Arc::new(crate::telemetry::NoopMetrics),
            )
            .unwrap();
            futures_executor::block_on(pipe.meta.apply(
                &pipe.shards.coordinator(&repo.namespace),
                crate::Batch::new().put(
                    crate::store::keys::repo_record(&repo.name),
                    crate::store::codec::encode_repo_record(&crate::store::codec::RepoRecord {
                        created_at_ms: 0,
                    }),
                ),
            ))
            .unwrap();
            let reader =
                futures_executor::block_on(pipe.object_reader(repo, ReaderView::Public)).unwrap();
            let capped = AtomicBool::new(true);
            let error = futures_executor::block_on(reader.issue_urls_with_budget(
                &[UrlTarget::Object([1; 32])],
                0,
                &SliceBudget::new(OBJECT_READER_CALLS),
                &capped,
            ))
            .unwrap_err();
            if code == Code::Unavailable {
                assert_eq!(error.code(), Code::ResourceExhausted);
                assert_eq!(error.public_message(), OBJECT_READER_LIMIT_MESSAGE);
            } else {
                assert_eq!(error.code(), code);
                assert_eq!(error.public_message(), "target refused");
            }
        }
    }
}
