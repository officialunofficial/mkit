//! Immutable evidence and bounded continuations for publication preparation.
use super::{PairStore, closed, resume, unavailable};
use crate::indexed::{
    IndexedConfig,
    budget::{Budgeted, SliceBudget},
    resolve, state,
};
use crate::pipeline::{
    ShardMap,
    clearance::{Immediate, PublicationPolicy},
};
use crate::store::{
    keys,
    publication::{Advance, Evidence, Pair, Publication},
    publication_certificate as cert,
};
use crate::takedown::{denial, inventory};
use crate::{
    Batch, BatchOutcome, NamespaceStore, Partition, Precondition, RepoId, ServerError, StoreError,
    Value,
};
use mkit_core::hash::{Hash, hash};
use serde::{Deserialize, Serialize};

mod cache;

#[derive(Clone, Debug)]
pub(crate) struct Proof {
    pub evidence: Evidence,
    pub prior: Option<Value>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Progress {
    binding: Hash,
    value: Pair,
    generation: u64,
    additions: Vec<Hash>,
    depth: u32,
    prior: Option<Vec<u8>>,
    seed_pair: Pair,
    seed_root: Option<Hash>,
    seed_support: Option<Hash>,
    inherited: bool,
    root: Option<Hash>,
    support: Option<Hash>,
    frontier: Option<Hash>,
    tasks: Vec<cert::Task>,
    active: Active,
    complete: Option<Hash>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pages: Vec<cache::Page>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum Active {
    Probe {
        next: Option<Hash>,
        count: u32,
    },
    Map {
        next: Option<Hash>,
    },
    MapPacks {
        next: Option<Hash>,
        packs: Vec<Hash>,
        ordinal: usize,
    },
    Idle,
    Resolve {
        id: Hash,
        after: Option<Vec<u8>>,
        pages: u32,
        purpose: Resolution,
    },
    Insert {
        id: Hash,
        flags: u8,
        main: Option<Hash>,
        next: Box<Active>,
    },
    References {
        row: Box<denial::StoredAction>,
        page: usize,
        ordinal: usize,
        kind: u8,
        next: Box<Active>,
    },
    Inventory {
        pack: Hash,
        cursor: inventory::InventoryCursor,
    },
    Base {
        origin: Hash,
        next: Hash,
        depth: u32,
        finish: Box<Active>,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum Resolution {
    Closure,
    Base {
        origin: Hash,
        depth: u32,
        finish: Box<Active>,
    },
}
impl Active {
    fn insert(id: Hash, flags: u8, next: Self) -> Self {
        Self::Insert {
            id,
            flags,
            main: None,
            next: Box::new(next),
        }
    }
    fn references(row: denial::StoredAction, kind: u8, next: Self) -> Self {
        Self::References {
            row: Box::new(row),
            page: 0,
            ordinal: 0,
            kind,
            next: Box::new(next),
        }
    }
    fn base(origin: Hash, base: Option<Hash>, finish: Self) -> Self {
        base.map_or(finish.clone(), |next| Self::Base {
            origin,
            next,
            depth: 0,
            finish: Box::new(finish),
        })
    }
}
impl Progress {
    pub(super) fn validate(&self) -> Result<(), StoreError> {
        cache::validate(&self.pages)?;
        if self.tasks.len() > cert::FRONTIER_TASKS
            || self.additions.len() > crate::store::outbox::MAX_TICKETS_PER_ADVANCE
            || self.complete.is_some()
                && (!matches!(self.active, Active::Idle)
                    || !self.tasks.is_empty()
                    || self.frontier.is_some())
            || self.binding
                != binding(
                    &self.value,
                    self.generation,
                    &self.additions,
                    self.depth,
                    self.prior.as_deref(),
                )?
        {
            return Err(StoreError::Corrupt(
                "invalid incremental publication progress".into(),
            ));
        }
        Ok(())
    }
    async fn packlist<S: NamespaceStore>(
        &self,
        store: &S,
        id: Hash,
    ) -> Result<(Option<Hash>, Vec<Hash>), ServerError> {
        let (length, prev, packs) = inventory::packlist_facts(store, &id)
            .await
            .map_err(mapped)?;
        packlist_binding(id, prev, &packs, length)?;
        Ok((prev, packs))
    }
    async fn push<S: NamespaceStore>(
        &mut self,
        store: &S,
        tasks: Vec<cert::Task>,
        now: u64,
    ) -> Result<(), StoreError> {
        for task in tasks {
            if self.tasks.len() == cert::FRONTIER_TASKS {
                let page = cert::Frontier {
                    tasks: self.tasks.clone(),
                    next: self.frontier,
                };
                self.frontier = Some(page.write(store, now).await?);
                self.tasks.clear();
            }
            self.tasks.push(task);
        }
        Ok(())
    }
}
fn packlist_binding(
    id: Hash,
    prev: Option<Hash>,
    packs: &[Hash],
    length: u64,
) -> Result<(), ServerError> {
    let bytes = mkit_core::transfer::encode_packlist(prev, packs).map_err(|_| unavailable())?;
    if hash(&bytes) != id || length != bytes.len() as u64 {
        return Err(unavailable());
    }
    Ok(())
}

fn binding(
    value: &Pair,
    generation: u64,
    additions: &[Hash],
    depth: u32,
    prior: Option<&[u8]>,
) -> Result<Hash, StoreError> {
    serde_json::to_vec(&(value, generation, additions, depth, prior))
        .map(|v| hash(&v))
        .map_err(|_| StoreError::Corrupt("bad certificate binding".into()))
}
fn mapped(error: StoreError) -> ServerError {
    match error {
        StoreError::Unavailable(reason) if reason.to_string().contains("subrequest budget") => {
            exhausted()
        }
        _ => unavailable(),
    }
}

fn exhausted() -> ServerError {
    ServerError::resource_exhausted("publication verification budget exhausted")
}
fn task(kind: u8, id: Hash) -> Result<cert::Task, ServerError> {
    cert::Task::new(kind, id).map_err(mapped)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn prepare<S: NamespaceStore>(
    store: &S,
    source: &Partition,
    shards: &dyn ShardMap,
    repo: &RepoId,
    advance: &mut Advance,
    prior: Option<&Value>,
    cfg: IndexedConfig,
    now: u64,
    denial: bool,
    custom_policy: bool,
    metrics: &dyn crate::Metrics,
) -> Result<Proof, ServerError> {
    let budget = SliceBudget::new(resume::SLICE_CALLS);
    let counted = Budgeted::new(store, &budget);
    let (published, anchor) = (
        Publication::decode(prior).map_err(mapped)?,
        prior
            .map(crate::store::publication::stored)
            .transpose()
            .map_err(mapped)?
            .and_then(|(_, e)| e),
    );
    let checkpoint = checkpoint_pack(&counted, shards, repo, advance, metrics)
        .await
        .map_err(|error| {
            if budget.remaining() == 0 {
                exhausted()
            } else {
                error
            }
        })?;
    let wanted = binding(
        &advance.value,
        advance.generation,
        &advance.additions,
        cfg.max_delta_chain_depth,
        prior.map(Value::as_bytes),
    )
    .map_err(mapped)?;
    let mut verified = state::read(store, source, &repo.name, &checkpoint)
        .await
        .map_err(mapped)?;
    let mut state = if let Some((value, _)) = &verified {
        value.clone()
    } else {
        state::VerificationV1::Verified {
            pack_len: inventory::sealed_length(&counted, &checkpoint)
                .await
                .map_err(mapped)?,
            verified_at_ms: now,
            publication: None,
        }
    };
    if !matches!(state, state::VerificationV1::Verified { .. }) {
        return Err(crate::indexed::pending(1_000));
    }
    let restart = resume::certificate_progress(&mut state).is_none_or(|p| p.binding != wanted);
    if restart {
        let p = initial_progress(&counted, repo, advance, prior, published, anchor, cfg).await?;
        let container = resume::container(advance, cfg, p)?;
        if let state::VerificationV1::Verified { publication, .. } = &mut state {
            *publication = Some(Box::new(container));
        }
    }
    let progress = resume::certificate_progress(&mut state).ok_or_else(unavailable)?;
    let slice_result = slice(store, shards, repo, progress, now, metrics, None, &budget).await;
    let complete = progress.complete;
    let encoded = state::encode(&state);
    if encoded.as_bytes().len() > resume::MAX_STATE_BYTES {
        return Err(exhausted());
    }
    let key = keys::verification(&repo.name, &checkpoint);
    let old = verified.take().map(|(_, raw)| raw);
    checkpoint_state(
        store,
        source,
        key,
        wanted,
        (encoded, complete),
        old.as_ref(),
        now,
    )
    .await?;
    slice_result?;
    let certificate = complete.ok_or_else(|| crate::indexed::pending(1_000))?;
    advance.dependencies.clear();
    advance.external_bases.clear();
    Ok(Proof {
        evidence: Evidence {
            certificate,
            denial,
            custom_policy,
        },
        prior: prior.cloned(),
    })
}

async fn checkpoint_pack<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    advance: &Advance,
    metrics: &dyn crate::Metrics,
) -> Result<Hash, ServerError> {
    let checkpoint = if let Some(id) = advance
        .value
        .packmap
        .or_else(|| advance.additions.first().copied())
    {
        id
    } else if let Some(id) = advance.value.head {
        let live = PairStore {
            store,
            repo,
            additions: &advance.additions,
            packs: None,
            policy: &Immediate,
            certificate: None,
        };
        resolve::locate_split(&live, shards, repo, &[id], metrics)
            .await?
            .remove(&id)
            .ok_or_else(closed)?
            .map_err(|_| exhausted())?
            .ok_or_else(closed)?
            .pack
    } else {
        return Err(closed());
    };
    Ok(checkpoint)
}

async fn checkpoint_state<S: NamespaceStore>(
    store: &S,
    source: &Partition,
    key: crate::Key,
    wanted: Hash,
    (encoded, complete): (Value, Option<Hash>),
    prior: Option<&Value>,
    now: u64,
) -> Result<(), ServerError> {
    let mut batch = Batch::new()
        .require(Precondition::NotAfter(now.saturating_add(10_000)))
        .require(crate::store::outbox::guard(key.clone(), prior))
        .put(key.clone(), encoded);
    if complete.is_none() {
        let timer = keys::timer(now.saturating_add(1_000), 12, key.as_bytes());
        let previous_timer = store.get(source, &timer).await.map_err(mapped)?;
        batch = batch
            .require(crate::store::outbox::guard(
                timer.clone(),
                previous_timer.as_ref(),
            ))
            .put(timer, Value::new(wanted.to_vec()));
    }
    if store.apply(source, batch).await.map_err(mapped)? != BatchOutcome::Committed {
        return Err(crate::indexed::pending(1_000));
    }
    Ok(())
}

async fn initial_progress<S: NamespaceStore>(
    store: &S,
    repo: &RepoId,
    advance: &Advance,
    prior: Option<&Value>,
    published: Publication,
    anchor: Option<Evidence>,
    cfg: IndexedConfig,
) -> Result<Progress, ServerError> {
    let wanted = binding(
        &advance.value,
        advance.generation,
        &advance.additions,
        cfg.max_delta_chain_depth,
        prior.map(Value::as_bytes),
    )
    .map_err(mapped)?;
    let seed = if let Some(anchor) = anchor {
        let header = cert::Header::read(store, &anchor.certificate)
            .await
            .map_err(mapped)?;
        if !header.matches(
            repo,
            published.generation,
            &published.value,
            cfg.max_delta_chain_depth,
        ) {
            return Err(unavailable());
        }
        Some(header)
    } else {
        None
    };
    let seed = seed.filter(|h| h.support_root().is_some());
    let mut p = Progress {
        binding: wanted,
        value: advance.value.clone(),
        generation: advance.generation,
        additions: advance.additions.clone(),
        depth: cfg.max_delta_chain_depth,
        prior: prior.map(|v| v.as_bytes().to_vec()),
        seed_pair: published.value,
        seed_root: seed.as_ref().and_then(cert::Header::root),
        seed_support: seed.as_ref().and_then(cert::Header::support_root),
        inherited: false,
        root: None,
        support: None,
        frontier: None,
        tasks: Vec::new(),
        active: Active::Probe {
            next: advance.value.packmap,
            count: 0,
        },
        complete: None,
        pages: Vec::new(),
    };
    p.tasks = advance
        .additions
        .iter()
        .copied()
        .map(|id| task(2, id))
        .collect::<Result<_, _>>()?;
    // Ticket count is already bounded below the frontier page capacity.
    if let Some(head) = advance.value.head {
        p.tasks.push(task(0, head)?);
    }
    Ok(p)
}

#[allow(clippy::too_many_lines)]
async fn one<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    p: &mut Progress,
    now: u64,
    _metrics: &dyn crate::Metrics,
) -> Result<(), ServerError> {
    let live = PairStore {
        store,
        repo,
        additions: &p.additions,
        packs: None,
        policy: &Immediate,
        certificate: None,
    };
    match p.active.clone() {
        Active::Probe { next, count } => {
            if next.is_some() && next == p.seed_pair.packmap && p.seed_support.is_some()
                || next.is_none() && p.value.packmap.is_none() && p.seed_pair.packmap.is_none()
            {
                p.inherited = true;
                p.root = p.seed_root;
                p.support = p.seed_support;
                p.active = Active::Map {
                    next: p
                        .value
                        .packmap
                        .filter(|id| Some(*id) != p.seed_pair.packmap),
                };
            } else if let Some(id) = next {
                if !p.additions.contains(&id)
                    && !crate::store::read::is_member(&live, shards, repo, &id, None)
                        .await
                        .map_err(mapped)?
                {
                    return Err(closed());
                }
                let (prev, _) = p.packlist(store, id).await?;
                p.active = Active::Probe {
                    next: prev,
                    count: count.saturating_add(1),
                };
            } else {
                p.active = Active::Map {
                    next: p.value.packmap,
                };
            }
        }
        Active::Map { next: Some(id) } => {
            let (prev, packs) = p.packlist(store, id).await?;
            let next = if p.inherited && prev == p.seed_pair.packmap {
                None
            } else {
                prev
            };
            p.active = Active::insert(
                id,
                cert::SUPPORT | cert::DENIAL,
                Active::MapPacks {
                    next,
                    packs,
                    ordinal: 0,
                },
            );
        }
        Active::Map { next: None } => p.active = Active::Idle,
        Active::MapPacks {
            next,
            packs,
            ordinal,
        } => {
            if let Some(id) = packs.get(ordinal).copied() {
                p.push(store, vec![task(2, id)?], now)
                    .await
                    .map_err(mapped)?;
                p.active = Active::insert(
                    id,
                    cert::SUPPORT,
                    Active::MapPacks {
                        next,
                        packs,
                        ordinal: ordinal + 1,
                    },
                );
            } else {
                p.active = Active::Map { next };
            }
        }
        Active::Insert {
            id,
            flags,
            main,
            next,
        } => {
            if let Some(main) = main {
                let support = cert::insert(
                    store,
                    p.support,
                    id,
                    flags & (cert::SUPPORT | cert::EXTERNAL),
                    now,
                )
                .await
                .map_err(mapped)?;
                p.root = Some(main);
                p.support = Some(support);
                p.active = *next;
            } else {
                let root = cert::insert(store, p.root, id, flags, now)
                    .await
                    .map_err(mapped)?;
                if flags & (cert::SUPPORT | cert::EXTERNAL) == 0 {
                    p.root = Some(root);
                    p.active = *next;
                } else {
                    p.active = Active::Insert {
                        id,
                        flags,
                        main: Some(root),
                        next,
                    };
                }
            }
        }
        Active::References {
            row,
            page,
            ordinal,
            kind,
            next,
        } => {
            if page == row.pages.len() {
                p.active = *next;
            } else {
                let ids = denial::page(store, &row, page).await?;
                if ordinal > ids.len() {
                    return Err(unavailable());
                }
                let end = (ordinal + cert::FRONTIER_TASKS).min(ids.len());
                p.push(
                    store,
                    ids[ordinal..end]
                        .iter()
                        .copied()
                        .map(|id| task(kind, id))
                        .collect::<Result<_, _>>()?,
                    now,
                )
                .await
                .map_err(mapped)?;
                p.active = Active::References {
                    row,
                    page: page + usize::from(end == ids.len()),
                    ordinal: if end == ids.len() { 0 } else { end },
                    kind,
                    next,
                };
            }
        }
        Active::Inventory { pack, cursor } => {
            let (cursor, rows, done) = inventory::next_one(store, &pack, cursor)
                .await
                .map_err(mapped)?;
            let finish = if done {
                Active::insert(pack, cert::DENIAL, Active::Idle)
            } else {
                Active::Inventory { pack, cursor }
            };
            if let Some((id, row)) = rows.into_iter().next() {
                let finish = Active::base(pack, row.base, finish);
                let finish = if row.kind == 5 {
                    Active::references(row.references, 1, finish)
                } else {
                    finish
                };
                p.active = Active::insert(id, cert::DENIAL, finish);
            } else {
                p.active = finish;
            }
        }
        Active::Base {
            origin,
            next,
            depth,
            finish,
        } => {
            if depth >= p.depth {
                return Err(ServerError::invalid_argument("delta chain too deep"));
            }
            p.active = Active::Resolve {
                id: next,
                after: None,
                pages: 0,
                purpose: Resolution::Base {
                    origin,
                    depth,
                    finish,
                },
            };
        }
        Active::Resolve {
            id,
            after,
            pages,
            purpose,
        } => {
            let (start, end) = keys::object_index_range(&repo.name, &id);
            let cursor = after
                .as_ref()
                .map(|bytes| crate::Cursor::new(bytes.clone()));
            let page = store
                .scan(
                    &shards.object_index(repo, &id),
                    &start,
                    &end,
                    cursor.as_ref(),
                    1,
                )
                .await
                .map_err(mapped)?;
            if page.entries.len() > 1 {
                return Err(unavailable());
            }
            if let Some((key, raw)) = page.entries.into_iter().next() {
                let Some(keys::ParsedKey::ObjectIndex {
                    repo: found,
                    object,
                    pack_id,
                }) = keys::parse(&key)
                else {
                    return Err(unavailable());
                };
                if found != repo.name || object != id || key < start || key >= end {
                    return Err(unavailable());
                }
                let selected = PairStore {
                    store,
                    repo,
                    additions: &p.additions,
                    packs: None,
                    policy: &Immediate,
                    certificate: matches!(purpose, Resolution::Closure)
                        .then(|| p.value.packmap.map(|_| cert::Root { root: p.root }))
                        .flatten(),
                };
                if crate::store::read::is_member(&selected, shards, repo, &pack_id, None)
                    .await
                    .map_err(mapped)?
                {
                    crate::store::codec::decode_object_index(&id, &raw).map_err(mapped)?;
                    let row = facts(store, pack_id, id).await?;
                    p.active = resolved(store, p, id, pack_id, row, purpose, now).await?;
                    return Ok(());
                }
            }
            let next = page.next.ok_or_else(closed)?.as_bytes().to_vec();
            if after.as_ref() == Some(&next) {
                return Err(unavailable());
            }
            if pages as usize + 1 >= crate::store::index::MAX_LOOKUP_PAGES {
                return Err(exhausted());
            }
            p.active = Active::Resolve {
                id,
                after: Some(next),
                pages: pages + 1,
                purpose,
            };
        }
        Active::Idle => {
            if p.tasks.is_empty()
                && let Some(frontier) = p.frontier
            {
                let page = cert::Frontier::read(store, &frontier)
                    .await
                    .map_err(mapped)?;
                p.frontier = page.next;
                p.tasks = page.tasks;
            }
            let Some(work) = p.tasks.last().copied() else {
                let header =
                    cert::Header::new(repo, p.generation, p.value.clone(), p.depth, p.root)
                        .with_support(p.support);
                p.complete = Some(header.write(store, now).await.map_err(mapped)?);
                return Ok(());
            };
            p.tasks.pop();
            match work.kind() {
                0 => {
                    if cert::get(store, p.root, &work.id()).await.map_err(mapped)? & cert::REACHABLE
                        == 0
                    {
                        p.active = Active::Resolve {
                            id: work.id(),
                            after: None,
                            pages: 0,
                            purpose: Resolution::Closure,
                        };
                    }
                }
                1 => p.active = Active::insert(work.id(), cert::DENIAL, Active::Idle),
                2 | 3 => {
                    if cert::get(store, p.root, &work.id()).await.map_err(mapped)? & cert::DENIAL
                        == 0
                    {
                        if !p.additions.contains(&work.id())
                            && !crate::store::read::is_member(&live, shards, repo, &work.id(), None)
                                .await
                                .map_err(mapped)?
                        {
                            return Err(closed());
                        }
                        p.active = Active::Inventory {
                            pack: work.id(),
                            cursor: inventory::InventoryCursor::default(),
                        };
                    }
                }
                _ => return Err(unavailable()),
            }
        }
    }
    Ok(())
}
async fn resolved<S: NamespaceStore>(
    store: &S,
    p: &mut Progress,
    id: Hash,
    pack: Hash,
    row: inventory::Entry,
    purpose: Resolution,
    now: u64,
) -> Result<Active, ServerError> {
    match purpose {
        Resolution::Closure => {
            if Some(id) == p.value.head && !matches!(row.kind, 3 | 4 | 7) {
                return Err(closed());
            }
            let finish = Active::base(pack, row.base, Active::Idle);
            let finish = Active::insert(id, cert::REACHABLE | cert::DENIAL, finish);
            let finish = Active::references(row.references, 0, finish);
            if p.value.packmap.is_none() {
                p.push(store, vec![task(2, pack)?], now)
                    .await
                    .map_err(mapped)?;
                Ok(Active::insert(pack, cert::SUPPORT, finish))
            } else {
                Ok(finish)
            }
        }
        Resolution::Base {
            origin,
            depth,
            finish,
        } => {
            let finish = if let Some(next) = row.base {
                Active::Base {
                    origin,
                    next,
                    depth: depth + 1,
                    finish,
                }
            } else {
                *finish
            };
            let finish = if pack == origin {
                finish
            } else {
                p.push(store, vec![task(2, pack)?], now)
                    .await
                    .map_err(mapped)?;
                Active::insert(pack, cert::EXTERNAL, finish)
            };
            Ok(Active::insert(id, cert::DENIAL, finish))
        }
    }
}
async fn facts<S: NamespaceStore>(
    store: &S,
    pack: Hash,
    id: Hash,
) -> Result<inventory::Entry, ServerError> {
    inventory::seal(store, &pack).await.map_err(mapped)?;
    let row = inventory::entry(store, &pack, &id)
        .await
        .map_err(mapped)?
        .ok_or_else(closed)?;
    if row.kind == 0 || row.kind == 6 {
        return Err(closed());
    }
    Ok(row)
}

async fn slice<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    p: &mut Progress,
    now: u64,
    metrics: &dyn crate::Metrics,
    alarm: Option<&crate::purge::SliceBudget>,
    budget: &SliceBudget,
) -> Result<(), ServerError> {
    let charged = Charged {
        inner: Budgeted::new(store, budget),
        alarm,
        stopped: std::sync::atomic::AtomicBool::new(false),
    };
    let cached = cache::Cached::new(charged, std::mem::take(&mut p.pages));
    let result = async {
        while p.complete.is_none() {
            let before = p.clone();
            let start = budget.used();
            if let Err(error) = one(&cached, shards, repo, p, now, metrics).await {
                *p = before;
                if budget.remaining() == 0
                    || cached
                        .inner
                        .stopped
                        .load(std::sync::atomic::Ordering::Relaxed)
                {
                    return if start == 0 { Err(exhausted()) } else { Ok(()) };
                }
                // Membership is mutable. A refused search restarts on a later
                // request so newly available earlier providers remain visible.
                if let Active::Resolve { after, pages, .. } = &mut p.active {
                    *after = None;
                    *pages = 0;
                }
                return Err(error);
            }
            cached.pages.lock().map_err(|_| unavailable())?.clear();
            if budget.remaining() < 16 {
                break;
            }
        }
        Ok(())
    }
    .await;
    p.pages = cached.pages.into_inner().map_err(|_| unavailable())?;
    result
}
pub(crate) struct Charged<'a, S> {
    inner: Budgeted<'a, S>,
    alarm: Option<&'a crate::purge::SliceBudget>,
    stopped: std::sync::atomic::AtomicBool,
}
impl<S: NamespaceStore> NamespaceStore for Charged<'_, S> {
    fn capabilities(&self) -> crate::store::StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, p: &Partition, k: &crate::Key) -> Result<Option<Value>, StoreError> {
        self.charge()?;
        self.inner.get(p, k).await
    }
    async fn get_many(
        &self,
        p: &Partition,
        k: &[crate::Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        self.charge()?;
        self.inner.get_many(p, k).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &crate::Key,
        end: &crate::Key,
        after: Option<&crate::Cursor>,
        limit: u32,
    ) -> Result<crate::ScanPage, StoreError> {
        self.charge()?;
        self.inner.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, b: Batch) -> Result<BatchOutcome, StoreError> {
        self.charge()?;
        self.inner.apply(p, b).await
    }
    async fn stats(&self, p: &Partition) -> Result<crate::PartitionStats, StoreError> {
        self.charge()?;
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.charge()?;
        self.inner.probe().await
    }
}
impl<S> Charged<'_, S> {
    fn charge(&self) -> Result<(), StoreError> {
        if self.alarm.is_some_and(|b| !b.charge(1)) {
            self.stopped
                .store(true, std::sync::atomic::Ordering::Relaxed);
            return Err(StoreError::unavailable(
                "publication alarm budget exhausted",
            ));
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn fire<S: NamespaceStore, T: NamespaceStore>(
    ctx: &crate::timers::TimerCtx<'_, S>,
    target: &T,
    timer: &crate::timers::DueTimer,
    alarm: Option<&crate::purge::SliceBudget>,
    raw: Value,
    mut state: state::VerificationV1,
    repo: crate::RepoName,
    ns: crate::NamespaceKey,
    shards: &dyn ShardMap,
) -> Result<crate::timers::Fired, StoreError> {
    let p = resume::certificate_progress(&mut state)
        .ok_or_else(|| StoreError::Corrupt("missing certificate progress".into()))?;
    if timer.value.as_bytes() != p.binding || p.complete.is_some() {
        return Ok(crate::timers::Fired::Done(Batch::new()));
    }
    let result = slice(
        target,
        shards,
        &RepoId {
            namespace: ns,
            name: repo,
        },
        p,
        ctx.now_ms,
        &crate::telemetry::NoopMetrics,
        alarm,
        &SliceBudget::new(resume::SLICE_CALLS),
    )
    .await;
    let complete = p.complete.is_some();
    let key = crate::Key::new(timer.reference.clone());
    let encoded = state::encode(&state);
    if encoded.as_bytes().len() > resume::MAX_STATE_BYTES {
        return Err(StoreError::unavailable(
            "publication checkpoint exceeds budget",
        ));
    }
    let batch = Batch::new()
        .require(Precondition::Equals(key.clone(), raw))
        .require(Precondition::NotAfter(ctx.now_ms.saturating_add(10_000)))
        .put(key, encoded);
    if complete {
        Ok(crate::timers::Fired::Done(batch))
    } else {
        Ok(crate::timers::Fired::Reschedule {
            due_at_ms: ctx.now_ms.saturating_add(if result.is_err() {
                crate::timers::RETRY_BACKOFF_MS
            } else {
                1_000
            }),
            value: timer.value.clone(),
            batch,
        })
    }
}

/// Mutable support is checked fresh; certificate coverage never grants availability.
pub(crate) async fn support_clear<S: NamespaceStore>(
    store: &S,
    source: &Partition,
    shards: &dyn ShardMap,
    repo: &RepoId,
    advance: &Advance,
    header: &cert::Header,
    policy: &dyn PublicationPolicy,
) -> Result<bool, StoreError> {
    if header.support_root().is_none() {
        return Err(StoreError::Corrupt(
            "missing support certificate projection".into(),
        ));
    }
    for pack in &advance.external_bases {
        if cert::get(store, header.support_root(), pack).await? & cert::EXTERNAL == 0 {
            return Err(StoreError::Corrupt(
                "external support missing from certificate".into(),
            ));
        }
    }
    let mut after = None;
    while let Some((pack, flags)) = cert::next(store, header.support_root(), after).await? {
        if flags & !(cert::SUPPORT | cert::EXTERNAL) != 0 {
            return Err(StoreError::Corrupt("invalid support certificate".into()));
        }
        if !policy.pack_available(repo, &pack) {
            return Ok(false);
        }
        if flags & cert::EXTERNAL == 0 && advance.additions.contains(&pack) {
            after = Some(pack);
            continue;
        }
        let partition = shards.membership(repo, &crate::BlobKey::pack(pack));
        let key = if partition == *source {
            keys::membership(&repo.name, &pack)
        } else {
            keys::published_member(&repo.name, &pack)
        };
        let row = store.get(&partition, &key).await?;
        if row
            .as_ref()
            .map(crate::store::publication::Witness::decode)
            .transpose()?
            .is_none_or(|w| !w.visible(false, advance.generation))
        {
            return Ok(false);
        }
        after = Some(pack);
    }
    for pack in &advance.additions {
        if !policy.pack_available(repo, pack) {
            return Ok(false);
        }
        let partition = shards.membership(repo, &crate::BlobKey::pack(*pack));
        if let Some(raw) = store
            .get(&partition, &keys::membership(&repo.name, pack))
            .await?
        {
            let witness = crate::store::publication::Witness::decode(&raw)?;
            if witness.generation == advance.generation && witness.held {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

pub(crate) fn charged<'a, S>(
    store: &'a S,
    budget: &'a SliceBudget,
    alarm: Option<&'a crate::purge::SliceBudget>,
) -> Charged<'a, S> {
    Charged {
        inner: Budgeted::new(store, budget),
        alarm,
        stopped: std::sync::atomic::AtomicBool::new(false),
    }
}
