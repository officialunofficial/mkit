use super::{
    AuthMode, CallerView, HookSet, OpKind, Operation, Pipeline, Principal, RequestMeta, ms,
    read_policy,
};
use crate::http_objects::{
    Fail, TakedownVerdict, Target, reach,
    resolve::{self, Budget, Env},
};
use crate::indexed::budget::{Budgeted, SliceBudget};
use crate::store::{MultipartBlobStore, NamespaceStore, view::ViewStore};
use crate::takedown::{
    denial::{denied, object_denials},
    inventory,
};
use crate::url_token::UrlTarget;
use crate::{Code, RepoId, ServerError};
/// A signed token and expiry; its credential is redacted from Debug.
pub type IssuedUrl = crate::url_token::MintedToken;
use mkit_core::{hash::Hash, object::ObjectType, repo_identity::Namespace};
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
    ServerError::resource_exhausted("object reader byte limit exceeded")
}
fn resolution_failure(miss: resolve::Miss, limited: bool) -> ServerError {
    if limited && miss == resolve::Miss::Capped {
        exhausted()
    } else {
        failure(miss)
    }
}
/// Maximum IDs per call; duplicates preserve input order and share proof work.
pub const OBJECT_READER_BATCH: usize = 16;
/// Core call cap inside the Worker invocation allowance.
pub const OBJECT_READER_CALLS: u32 = 8_500;
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
    async fn authorize(&self, budget: &SliceBudget) -> Result<bool, ServerError> {
        for _ in 0..2 {
            budget.charge().map_err(failure)?;
        }
        match &self.view {
            ReaderView::Public => {
                let op = Operation::new(
                    self.repo.clone(),
                    Principal::Anonymous,
                    None,
                    OpKind::HttpGet { ref_name: None },
                );
                self.pipe
                    .authorize_http_read(&op, &Target::Object([0; 32]), self.seams, None)
                    .await
                    .map_err(|e| http_failure(&e))?;
                Ok(false)
            }
            ReaderView::Owner(meta) => {
                if !matches!(self.pipe.cfg.auth, AuthMode::AuthV2(_)) {
                    return Err(ServerError::unauthenticated("auth v2 required"));
                }
                let a = self.pipe.authenticate(meta)?;
                if a.auth.is_none() || a.repo().repo != self.repo {
                    return Err(ServerError::unauthenticated("envelope mismatch"));
                }
                let op = self.pipe.identify(
                    &a,
                    OpKind::ListRefs {
                        prefix: "refs/".into(),
                    },
                )?;
                let auth = self.pipe.authorize_read(&op).await?;
                let owner = Namespace::parse(self.repo.namespace.as_str()).is_ok_and(
                    |n| matches!(n, Namespace::Ed25519(key) if a.principal.ed25519() == Some(&key)),
                );
                let grant = self.pipe.visibility_gates_reads()
                    && auth.facts.grant.is_some()
                    && op
                        .write_grant
                        .as_ref()
                        .zip(self.pipe.cfg.grants.as_ref())
                        .and_then(|(h, c)| read_policy::check_grant(c, h.expose(), &op))
                        .is_some_and(|g| g.write);
                if auth.facts.caller_view != CallerView::Writer || !(owner || grant) {
                    return Err(ServerError::permission_denied("writer authority required"));
                }
                Ok(true)
            }
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
    /// Historical mixed sizes: `Blob` payload, other kinds' canonical length.
    /// # Errors
    /// As `object_metadata`; incomplete proofs remain unavailable.
    #[deprecated(note = "use object_metadata for kind, canonical_len and logical_len")]
    pub async fn object_sizes(&self, ids: &[Hash]) -> Result<Vec<Option<u64>>, ServerError> {
        Ok(self
            .object_metadata(ids)
            .await?
            .into_iter()
            .map(|row| {
                row.map(|m| {
                    if m.kind == ObjectType::Blob {
                        m.logical_len.unwrap_or(0)
                    } else {
                        m.canonical_len
                    }
                })
            })
            .collect())
    }
    /// Issue at most 16 URL tokens, preserving order and duplicates.
    /// Requires configured URL-token keys. Inaccessible targets are uniformly
    /// absent. Tokens bind unresolved targets exactly as `IssueObjectUrl` does,
    /// after a bounded published-view preflight, including for Owner readers.
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
        match self.authorize(&calls).await {
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
        for target in targets {
            calls.charge().map_err(failure)?;
            calls.charge().map_err(failure)?;
            op.kind = OpKind::IssueObjectUrl {
                target: target.clone(),
                ttl_seconds: ttl_s,
            };
            issued.push(
                match self
                    .pipe
                    .issue_url(&op, &repository, target, ttl_s, now)
                    .await
                {
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
        let meta = Budgeted::new(&self.pipe.meta, &calls);
        let blobs = Budgeted::new(&self.pipe.blobs, &calls);
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
                    let tip =
                        crate::store::read::read_ref(&view, &shard, &self.repo.name, reference)
                            .await
                            .map_err(failure)?;
                    if let Some(tip) = tip {
                        let path = if path.is_empty() {
                            Vec::new()
                        } else {
                            path.split('/').map(|p| p.as_bytes().to_vec()).collect()
                        };
                        match resolve::resolve_ref(&env, tip, &path, &mut decode).await {
                            Ok(resolved) => Some(resolved.leaf),
                            Err(resolve::Miss::NotFound | resolve::Miss::Capped) => None,
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
                &calls,
                false,
                &BTreeSet::new(),
                &mut decode,
                true,
                None,
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
        if ids.len() > OBJECT_READER_BATCH {
            return Err(ServerError::invalid_argument("batch exceeds 16 ids"));
        }
        let calls = SliceBudget::new(OBJECT_READER_CALLS);
        let writer = match self.authorize(&calls).await {
            Err(e) if e.code() == Code::NotFound && matches!(self.view, ReaderView::Public) => {
                return Ok((BTreeMap::new(), BTreeMap::new()));
            }
            other => other?,
        };
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
            &mut Budget(
                max_bytes
                    .unwrap_or(self.cfg.http_decode_budget)
                    .min(self.cfg.http_decode_budget),
            ),
            false,
            max_bytes,
        )
        .await
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
    ) -> Result<Prefetched, ServerError> {
        let mut output_left = max_bytes
            .unwrap_or(self.cfg.http_decode_budget)
            .min(self.cfg.http_decode_budget);
        let limited = max_bytes.is_some();
        let pipe = self.pipe;
        let (cfg, indexed, seams) = (self.cfg, self.indexed, self.seams);
        let meta = Budgeted::new(&pipe.meta, calls);
        let blobs = Budgeted::new(&pipe.blobs, calls);
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
        };
        let mut located = if capped_as_absent {
            Vec::new()
        } else {
            resolve::locate_many(&env, ids).await.map_err(failure)?
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
        if !writer && !pipe.cfg.takedown_denial {
            for id in &targets {
                calls.charge().map_err(failure)?;
                if seams
                    .reachability
                    .known_reachable(&self.repo, id, ms(pipe.clock.now_ms()))
                    .await?
                {
                    reached.insert(*id);
                }
            }
        }
        targets.retain(|id| !reached.contains(id));
        if !targets.is_empty() {
            let (tips, truncated) = pipe
                .reader_tips(&meta, &self.repo, cfg.max_walk_objects, writer)
                .await
                .map_err(|e| http_failure(&e))?;
            if truncated && sizes_only && !capped_as_absent {
                return Err(failure(resolve::Miss::Capped));
            }
            if !truncated {
                let (found, incomplete) =
                    reach::walk_many(&env, seams.takedown.as_ref(), &tips, &targets, decode)
                        .await
                        .map_err(|e| resolution_failure(e, limited))?;
                if limited && incomplete == Some(resolve::Miss::Capped) {
                    return Err(exhausted());
                }
                if sizes_only && !capped_as_absent && incomplete == Some(resolve::Miss::Capped) {
                    return Err(failure(resolve::Miss::Capped));
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
            reached = accessible.iter().copied().collect();
            located = resolve::locate_many(&env, &accessible)
                .await
                .map_err(failure)?;
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
            calls.charge().map_err(failure)?;
            if !matches!(
                seams.takedown.check(&self.repo, &id).await?,
                TakedownVerdict::Clear
            ) {
                continue;
            }
            if !writer && fresh.contains(&id) {
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
                        bytes.insert(id, canonical.to_vec());
                    }
                    Ok(_) | Err(resolve::Miss::NotFound) => {}
                    Err(miss) => return Err(resolution_failure(miss, limited)),
                }
            }
        }
        Ok((bytes, sizes))
    }
}
