//! Verify the complete resulting pair, independently of inspector verdicts.
pub mod resume;
use super::{IndexedConfig, resolve};
use crate::ServerError;
use crate::pipeline::{ShardMap, clearance::PublicationPolicy};
use crate::repo::RepoId;
use crate::store::publication::{Advance, MAX_ADVANCE_ITEMS, Pair};
use crate::store::{
    self, Batch, BatchOutcome, BlobBody, BlobKey, BlobStore, Cursor, Key, NamespaceStore,
    Partition, PartitionStats, RangeScan, ScanPage, StoreCapabilities, StoreError, Value, keys,
};
use crate::telemetry::Metrics;
use futures::StreamExt as _;
use mkit_core::hash::{Hash, hash};
use mkit_core::ops::graph::{ClosureMode, children};
use mkit_primitives::closure::pair::{
    ClearedSet, ObjectFact, PackmapNode as PairNode, PairCheck, PairLimits, PairRequest,
    PairResponse, PairStep, PairWalker, ResultingPair,
};
use mkit_primitives::evidence::{ProfileId, RepositoryId, Revision, RulesetBinding, RulesetId};
use mkit_primitives::pack_verify::Acquisition;
use std::collections::BTreeSet;

fn closed() -> ServerError {
    ServerError::invalid_argument("open closure")
}
fn capped() -> ServerError {
    ServerError::invalid_argument("object index limit exceeded")
}
/// The retained-evidence item bound (4,096) is an implementation capacity, not
/// a statement about the content.
pub(super) fn item_capacity() -> ServerError {
    crate::pipeline::publication_budget::PublicationBudget::capacity_error()
}
fn unavailable() -> ServerError {
    ServerError::unavailable("object storage request failed")
}

/// The consuming request's clock context for repository-membership lag.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Lag {
    /// Server time, Unix ms.
    pub now: u64,
    /// When the consuming ticket was created.
    pub created: u64,
    /// The configured membership visibility bound.
    pub bound: u64,
}
impl Lag {
    /// The one answer for an absent closure object (`base: false`) or delta
    /// base (`base: true`) on both pair-coverage paths: retryable inside the
    /// lag window, and only after it an open closure or an unavailable base.
    pub(super) fn miss(self, base: bool) -> ServerError {
        if base {
            resolve::missing_base(self.now, self.created, self.bound)
        } else {
            super::verify::closure_error(self.now, self.created, self.bound)
        }
    }
}

// Restrict closure lookup to the exact packmap chain. Newly consumed packs
// qualify before live membership commits; this facade never grants bytes on a
// serving path and still applies the hold gate before accepting any membership.
struct PairStore<'a, S> {
    store: &'a S,
    repo: &'a RepoId,
    additions: &'a [Hash],
    /// Sorted unique chain-listed packs; membership outside them is hidden.
    packs: Option<&'a [Hash]>,
    policy: &'a dyn PublicationPolicy,
}
impl<S: NamespaceStore> PairStore<'_, S> {
    fn member(&self, key: &Key, value: Option<Value>) -> Option<Value> {
        if let Some(keys::ParsedKey::Membership { repo, pack_id }) = keys::parse(key) {
            if repo != self.repo.name
                || !self.policy.pack_available(self.repo, &pack_id)
                || self
                    .packs
                    .is_some_and(|packs| packs.binary_search(&pack_id).is_err())
            {
                return None;
            }
            if self.additions.contains(&pack_id) {
                return Some(Value::default());
            }
            return value.filter(|v| store::publication::Witness::decode(v).is_ok_and(|w| !w.held));
        }
        value
    }
}
impl<S: NamespaceStore> NamespaceStore for PairStore<'_, S> {
    fn capabilities(&self) -> StoreCapabilities {
        self.store.capabilities()
    }
    async fn get(&self, p: &Partition, k: &Key) -> Result<Option<Value>, StoreError> {
        let row = self.store.get(p, k).await?;
        if matches!(keys::parse(k), Some(keys::ParsedKey::Membership { .. }))
            && let Some(raw) = &row
        {
            store::publication::Witness::decode(raw)?;
        }
        Ok(self.member(k, row))
    }
    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        let rows = self.store.get_many(p, keys).await?;
        if rows.len() != keys.len() {
            return Err(StoreError::MalformedReply(
                "short pair membership read".into(),
            ));
        }
        // Do not hide malformed witnesses as ordinary absence.
        for (key, row) in keys.iter().zip(&rows) {
            if matches!(
                store::keys::parse(key),
                Some(store::keys::ParsedKey::Membership { .. })
            ) && let Some(raw) = row
            {
                store::publication::Witness::decode(raw)?;
            }
        }
        Ok(keys
            .iter()
            .zip(rows)
            .map(|(k, v)| self.member(k, v))
            .collect())
    }
    async fn scan(
        &self,
        partition: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.store.scan(partition, start, end, after, limit).await
    }
    async fn scan_many(&self, p: &Partition, r: &[RangeScan]) -> Result<Vec<ScanPage>, StoreError> {
        self.store.scan_many(p, r).await
    }
    async fn apply(&self, _: &Partition, _: Batch) -> Result<BatchOutcome, StoreError> {
        Err(StoreError::Invalid("pair verifier is read-only".into()))
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.store.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.store.probe().await
    }
}

#[allow(clippy::too_many_arguments)]
async fn packlist<B: BlobStore, S: NamespaceStore>(
    blobs: &B,
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    id: Hash,
    additions: &[Hash],
    remaining: &mut u64,
    lag: Lag,
) -> Result<(mkit_core::transfer::PackListNode, bool), ServerError> {
    let mut boundary = false;
    if !additions.contains(&id) {
        // The membership witness is the one read `is_member` makes; a
        // completed fork flags its inherited packmap head in it.
        let row = store
            .get(
                &shards.membership(repo, &BlobKey::pack(id)),
                &keys::membership(&repo.name, &id),
            )
            .await
            .map_err(|_| unavailable())?;
        match row {
            None => return Err(lag.miss(false)),
            Some(raw) => {
                boundary = store::publication::Witness::decode(&raw)
                    .map_err(|_| unavailable())?
                    .boundary;
            }
        }
    }
    let info = blobs
        .head(&BlobKey::pack(id))
        .await
        .map_err(|_| unavailable())?
        .ok_or_else(closed)?;
    let length = info.len;
    if length > *remaining {
        return Err(capped());
    }
    *remaining -= length;
    let body = blobs
        .get(&BlobKey::pack(id), None)
        .await
        .map_err(|_| unavailable())?
        .ok_or_else(closed)?;
    let mut bytes = Vec::new();
    match body {
        BlobBody::Bytes(b) => {
            if b.len() as u64 != length {
                return Err(unavailable());
            }
            bytes.extend_from_slice(&b);
        }
        BlobBody::Stream { len, mut stream } => {
            if len != length {
                return Err(unavailable());
            }
            while let Some(b) = stream.next().await {
                let b = b.map_err(|_| unavailable())?;
                if (bytes.len() as u64).saturating_add(b.len() as u64) > length {
                    return Err(unavailable());
                }
                bytes.extend_from_slice(&b);
            }
        }
    }
    if bytes.len() as u64 != length || hash(&bytes) != id {
        return Err(closed());
    }
    let node = mkit_core::transfer::decode_packlist(&bytes).map_err(|_| closed())?;
    Ok((node, boundary))
}

/// The server fills dependencies from verified content; policy-supplied lists
/// cannot omit a packmap node, reachable object pack or external delta source.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn verify_inner<B: BlobStore, S: NamespaceStore>(
    blobs: &B,
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    value: &Pair,
    branch: bool,
    advance: &mut Advance,
    policy: &dyn PublicationPolicy,
    cfg: IndexedConfig,
    metrics: &dyn Metrics,
    honor_cleared: bool,
    lag: Lag,
) -> Result<(), ServerError> {
    // The primitive owns resulting-pair graph semantics; this host owns
    // storage reads, byte accounting, item caps, and refusal mapping.
    let pair = ResultingPair {
        head: value.head,
        packmap: value.packmap,
        branch,
    };
    // Local identities bind machine state to this repository view only;
    // they never leave the process.
    let limits = PairLimits {
        chain: u32::try_from(MAX_ADVANCE_ITEMS).unwrap_or(u32::MAX),
        packs: u32::try_from(MAX_ADVANCE_ITEMS).unwrap_or(u32::MAX),
        // The inline host bounds the frontier by its visited cap and the
        // decode budget instead of a discovery count.
        discovered: u32::MAX,
        dependencies: u32::try_from(MAX_ADVANCE_ITEMS).unwrap_or(u32::MAX),
        suppliers: u32::try_from(MAX_ADVANCE_ITEMS).unwrap_or(u32::MAX),
        cleared: u32::try_from(crate::fork::MAX_SET_IDS).unwrap_or(u32::MAX),
        max_delta_depth: cfg.max_delta_chain_depth,
        // Reference work is bounded by the call and byte ledgers, not the
        // machine's abstract work counter.
        work: u64::MAX,
    };
    let mut walker = PairWalker::new(
        pair,
        &advance.additions,
        pair_identity(repo),
        Revision(hash(&advance.generation.to_be_bytes())),
        PAIR_RULESET,
        limits,
        honor_cleared,
        advance.generation,
    )
    .map_err(|_| item_capacity())?;
    let live = PairStore {
        store,
        repo,
        additions: &advance.additions,
        packs: None,
        policy,
    };
    let mut remaining = cfg.decode_budget;
    loop {
        // Reference order: the combined chain/pack cap is checked before the
        // repeat check that step() performs.
        if walker.pending_packmap().is_some() {
            let counts = walker.counts();
            if counts.chain + counts.packs >= MAX_ADVANCE_ITEMS as u64 {
                return Err(item_capacity());
            }
        }
        match walker.step() {
            Err(error) => return Err(pair_failure(&error, walker.failure_context(), lag)),
            Ok(PairStep::Progress) => {}
            Ok(PairStep::Covered(coverage)) => {
                advance.dependencies = coverage.dependencies().to_vec();
                advance.external_bases = coverage.external_suppliers().to_vec();
                return Ok(());
            }
            Ok(PairStep::Request(request)) => {
                let request = request.clone();
                match request {
                    PairRequest::PackmapNode { request, pack, .. } => {
                        let (node, flagged) = packlist(
                            blobs,
                            &live,
                            shards,
                            repo,
                            pack,
                            &advance.additions,
                            &mut remaining,
                            lag,
                        )
                        .await?;
                        walker
                            .answer(PairResponse::PackmapNode {
                                request,
                                pack,
                                value: Acquisition::Present(PairNode {
                                    prev: node.prev,
                                    packs: &node.packs,
                                    boundary: flagged,
                                }),
                            })
                            .map_err(|error| pair_failure(&error, walker.failure_context(), lag))?;
                        let counts = walker.counts();
                        if counts.chain + counts.packs > MAX_ADVANCE_ITEMS as u64 {
                            return Err(item_capacity());
                        }
                    }
                    PairRequest::Boundary { request } => {
                        // The machine asks exactly when a flagged chain node
                        // makes the cleared set reachable and honored.
                        let cleared = crate::fork::boundary::load(store, shards, repo)
                            .await
                            .map_err(|_| unavailable())?;
                        let objects: Vec<Hash> = cleared.ids.iter().copied().collect();
                        let suppliers: Vec<Hash> = cleared.bases.iter().copied().collect();
                        walker
                            .answer(PairResponse::Boundary {
                                request,
                                value: Acquisition::Present(ClearedSet {
                                    objects: &objects,
                                    suppliers: &suppliers,
                                }),
                            })
                            .map_err(|error| pair_failure(&error, walker.failure_context(), lag))?;
                    }
                    PairRequest::Object {
                        request,
                        object,
                        restricted,
                        ..
                    } => {
                        // Cleared skips happen inside the machine; the cap is
                        // checked only on real object requests, as before.
                        if walker.counts().visited > MAX_ADVANCE_ITEMS as u64 {
                            return Err(item_capacity());
                        }
                        let closure = PairStore {
                            store,
                            repo,
                            additions: &advance.additions,
                            packs: restricted.then_some(walker.chain_packs()),
                            policy,
                        };
                        let located =
                            resolve::locate_split(&closure, shards, repo, &[object], metrics)
                                .await?
                                .remove(&object)
                                .ok_or_else(|| lag.miss(false))?
                                .map_err(|_| capped())?
                                .ok_or_else(|| lag.miss(false))?;
                        let mut memo = resolve::MemberCache::with_work_budget(256);
                        let mut visiting = BTreeSet::new();
                        let (bytes, _) = resolve::member_object(
                            blobs,
                            &live,
                            shards,
                            repo,
                            object,
                            located,
                            cfg.max_delta_chain_depth,
                            remaining,
                            &mut memo,
                            &mut visiting,
                            metrics,
                        )
                        .await
                        .map_err(|e| match e {
                            resolve::ResolveFailure::Other(e)
                                if e.public_message() == "object blocked" =>
                            {
                                e
                            }
                            resolve::ResolveFailure::Missing => lag.miss(false),
                            resolve::ResolveFailure::Capped => capped(),
                            resolve::ResolveFailure::Store(_) => {
                                ServerError::unavailable("object storage request failed")
                            }
                            resolve::ResolveFailure::Corrupt(_) => {
                                ServerError::unavailable(resolve::MEMBER_UNAVAILABLE)
                            }
                            resolve::ResolveFailure::Other(e) => e,
                        })?;
                        remaining = remaining
                            .checked_sub(memo.retained_bytes())
                            .ok_or_else(capped)?;
                        let suppliers: Vec<Hash> = memo
                            .rows()
                            .filter(|((_, pack, _), _)| *pack != located.pack)
                            .map(|((_, pack, _), _)| *pack)
                            .collect();
                        let object_data =
                            mkit_core::serialize::deserialize(&bytes).map_err(|_| closed())?;
                        let children = children(&object_data, ClosureMode::History);
                        walker
                            .answer(PairResponse::Object {
                                request,
                                object,
                                value: Acquisition::Present(ObjectFact {
                                    pack: located.pack,
                                    kind: object_data.object_type(),
                                    children: &children,
                                    suppliers: &suppliers,
                                    base: None,
                                }),
                            })
                            .map_err(|error| pair_failure(&error, walker.failure_context(), lag))?;
                        let counts = walker.counts();
                        if counts.dependencies > MAX_ADVANCE_ITEMS as u64
                            || sorted_union_len(walker.suppliers(), walker.cleared_suppliers())
                                > MAX_ADVANCE_ITEMS as u64
                        {
                            return Err(item_capacity());
                        }
                    }
                    // Inline facts carry no base; this request never arises.
                    _ => return Err(unavailable()),
                }
            }
            _ => return Err(unavailable()),
        }
    }
}

/// Map a machine refusal to the reference error surface. Semantic checks keep
/// their classification; host-side protocol violations are unavailability.
/// Pair-coverage identities are process-local: they bind a walker's state
/// (and its checkpoints) to this repository name and never leave the server.
pub(super) fn pair_identity(repo: &RepoId) -> RepositoryId {
    RepositoryId(hash(repo.name.as_str().as_bytes()))
}
/// The fixed ruleset the reference server verifies against.
pub(super) const PAIR_RULESET: RulesetBinding = RulesetBinding {
    ruleset: RulesetId(1),
    profile: ProfileId::Indexed,
};

/// Sorted-union size of two strictly-ascending id lists, without allocation.
fn sorted_union_len(left: &[Hash], right: &[Hash]) -> u64 {
    let (mut a, mut b, mut n) = (0usize, 0usize, 0u64);
    while a < left.len() && b < right.len() {
        match left[a].cmp(&right[b]) {
            std::cmp::Ordering::Less => a += 1,
            std::cmp::Ordering::Greater => b += 1,
            std::cmp::Ordering::Equal => {
                a += 1;
                b += 1;
            }
        }
        n += 1;
    }
    n + (left.len() - a + right.len() - b) as u64
}

fn pair_failure(
    error: &mkit_primitives::error::Failure,
    context: Option<PairCheck>,
    lag: Lag,
) -> ServerError {
    use mkit_primitives::error::FailureCode;
    match error.code {
        FailureCode::MissingClosure => lag.miss(false),
        FailureCode::WrongKind => closed(),
        FailureCode::PackmapCycle => capped(),
        FailureCode::ResourceLimit => item_capacity(),
        _ => {
            debug_assert!(
                matches!(context, None | Some(PairCheck::Bound(_))),
                "host must not feed the machine invalid facts"
            );
            unavailable()
        }
    }
}

/// Verify the resulting pair within a caller's slice, a child of the request's
/// publication ledger. Exhaustion is read from the budget itself and is
/// execution capacity (`unavailable`), never a closed-closure verdict.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn verify_within<B: BlobStore, S: NamespaceStore>(
    blobs: &B,
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    value: &Pair,
    branch: bool,
    advance: &mut Advance,
    policy: &dyn PublicationPolicy,
    cfg: IndexedConfig,
    metrics: &dyn Metrics,
    honor_cleared: bool,
    lag: Lag,
    slice: &super::budget::SliceBudget,
) -> Result<(), ServerError> {
    let blobs = super::budget::Budgeted::new(blobs, slice);
    let store = super::budget::Budgeted::new(store, slice);
    let result = verify_inner(
        &blobs,
        &store,
        shards,
        repo,
        value,
        branch,
        advance,
        policy,
        cfg,
        metrics,
        honor_cleared,
        lag,
    )
    .await;
    crate::pipeline::publication_budget::PublicationBudget::settle(slice, result)
}

/// Verify the resulting pair, then collect only the added-pack inspection
/// metadata, both sharing one caller slice. Inspection does not alter the
/// publication closure walk or its classification.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn verify_inspected_within<B: BlobStore, S: NamespaceStore>(
    blobs: &B,
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    value: &Pair,
    branch: bool,
    advance: &mut Advance,
    policy: &dyn PublicationPolicy,
    cfg: IndexedConfig,
    metrics: &dyn Metrics,
    honor_cleared: bool,
    inspection: &mut super::inspection::InspectionSet,
    lag: Lag,
    slice: &super::budget::SliceBudget,
) -> Result<(), ServerError> {
    let blobs = super::budget::Budgeted::new(blobs, slice);
    let store = super::budget::Budgeted::new(store, slice);
    let result = async {
        verify_inner(
            &blobs,
            &store,
            shards,
            repo,
            value,
            branch,
            advance,
            policy,
            cfg,
            metrics,
            honor_cleared,
            lag,
        )
        .await?;
        inspection.complete_added(&store, repo).await
    }
    .await;
    crate::pipeline::publication_budget::PublicationBudget::settle(slice, result)
}
