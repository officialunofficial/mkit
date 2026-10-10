//! Registration, the index-row copy and the one-time storage count.

use super::{
    COPY_PUTS, ForkEnv, ForkError, ForkJobV1, MAX_SCANNED_ROWS, SCAN_PAGE_ROWS, set, sets,
};
use crate::budget::SliceBudget;
use crate::indexed::budget::Budgeted;
use crate::store::outbox::OutboxBuilder;
use crate::store::{
    Batch, BorrowedStore, CONTENT_APPLY_WINDOW_MS, ContentIndex, Cursor, Holder, NamespaceStore,
    Partition, Precondition, Write, codec, keys, repo_storage,
};
use mkit_core::hash::Hash;
use std::collections::BTreeMap;

/// The authority the request was authorized under must still hold, as it must
/// for any write that registers a repository. Returns the guards that keep it
/// holding until the registration batch applies.
fn fence_guards(
    fence: &super::FenceV1,
    (ag, authority): (crate::store::Key, Option<&crate::store::Value>),
    (ge, epoch): (crate::store::Key, Option<&crate::store::Value>),
) -> Result<Vec<Precondition>, ForkError> {
    let current = |row: Option<&crate::store::Value>| {
        row.map(codec::decode_u64)
            .transpose()
            .map(|v| v.unwrap_or(0))
    };
    let mut guards = Vec::new();
    // A persisted authority fence needs a request authorized under one, as in
    // an ordinary write.
    if authority.is_some() && fence.authority_generation.is_none() {
        return Err(ForkError::Unavailable("fork requires authority fence"));
    }
    if let Some(generation) = fence.authority_generation {
        if current(authority)? != generation {
            return Err(ForkError::Moved("authority"));
        }
        // A namespace the authority has not registered is not ours to create.
        if authority.is_none() && !fence.create_namespace {
            return Err(ForkError::Denied);
        }
        guards.push(crate::store::outbox::guard(ag, authority));
    } else {
        // No generation was seen, so none may appear before the batch applies.
        guards.push(crate::store::outbox::guard(ag, None));
    }
    if let Some(seen) = fence.grant_epoch {
        if current(epoch)? != seen {
            return Err(ForkError::Moved("epoch"));
        }
        guards.push(crate::store::outbox::guard(ge, epoch));
    }
    Ok(guards)
}

/// The coordinator rows that make the destination a registered, empty
/// repository, first so a takedown sweep enumerating the registry finds it.
pub(crate) async fn register<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    job: &ForkJobV1,
) -> Result<Batch, ForkError> {
    let dest = job.dest()?;
    let p = env.shards.coordinator(&dest.namespace);
    let (nr, rr, rv) = (
        keys::namespace_record(),
        keys::repo_record(&dest.name),
        keys::repo_visibility(&dest.name),
    );
    let (ag, ge) = (keys::authority_generation(), keys::grant_epoch());
    let rows = env
        .store
        .get_many(
            &p,
            &[nr.clone(), rr.clone(), rv.clone(), ag.clone(), ge.clone()],
        )
        .await?;
    let [namespace, repo, visibility, authority, epoch]: [_; 5] = rows
        .try_into()
        .map_err(|_| ForkError::Unavailable("fork registration read"))?;
    // The Register phase commits atomically with its own advance, so there is
    // no legitimate second entry: a repository registered since the check at
    // the start of the phase is someone else's.
    if repo.is_some() {
        return Err(ForkError::NotEmpty);
    }
    let now = env.now();
    let mut batch = Batch::new();
    let fence = job.fence.clone().unwrap_or(super::FenceV1 {
        authority_generation: None,
        grant_epoch: None,
        create_namespace: false,
    });
    batch.preconditions.extend(fence_guards(
        &fence,
        (ag, authority.as_ref()),
        (ge, epoch.as_ref()),
    )?);
    if namespace.is_none() {
        // Where an authority registers namespaces, its generation row is the
        // registration: the first repository creates the namespace record, as
        // an ordinary write does. Without one, only a fence that allows it.
        if !(fence.create_namespace || authority.is_some()) {
            return Err(ForkError::Denied);
        }
        batch = batch.require(Precondition::Absent(nr.clone())).put(
            nr,
            codec::encode_namespace_record(&codec::NamespaceRecord {
                created_at_ms: now,
                config_version: 1,
            }),
        );
    }
    if repo.is_none() {
        let requested = if job.visibility == "private" {
            codec::StoredVisibility::Private
        } else {
            codec::StoredVisibility::Public
        };
        // An owner may have declared the name's visibility before it exists.
        // That declaration stands: a fork never replaces it, and a request
        // for another visibility is refused.
        let stored = match &visibility {
            Some(existing) => {
                if codec::decode_repo_visibility(existing)?.visibility != requested {
                    return Err(ForkError::NotEmpty);
                }
                existing.clone()
            }
            None => codec::encode_repo_visibility(&codec::RepoVisibilityV1 {
                visibility: requested,
                last_created_ms: 0,
                last_statement_id: None,
                changed_ms: now,
            }),
        };
        batch = batch
            .require(Precondition::Absent(rr.clone()))
            .require(crate::store::outbox::guard(rv.clone(), visibility.as_ref()))
            .put(
                rr,
                codec::encode_repo_record(&codec::RepoRecord { created_at_ms: now }),
            )
            .put(
                keys::repo_storage(&dest.name),
                repo_storage::initial_counter(),
            );
        if visibility.is_none() {
            batch = batch.put(rv, stored.clone());
        }
        crate::pipeline::list_repos_index_writes(&mut batch, &dest.name, true, Some(&stored))
            .map_err(ForkError::from)?;
    }
    Ok(batch)
}

/// Refuse a source whose index is too large to scan, before the destination is
/// registered: the partitions' key counts bound the rows the copy would read.
/// A store that does not know its counts cheaply leaves the check to the copy.
pub(crate) async fn require_scannable<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    job: &ForkJobV1,
    budget: &SliceBudget,
) -> Result<(), ForkError> {
    let store = Budgeted::new(env.store, budget);
    let mut total = 0_u64;
    for partition in env.shards.object_index_partitions(&job.source()?) {
        // A partition shared with other repositories says nothing about this one.
        if !matches!(partition, Partition::RepoIndex { .. }) {
            continue;
        }
        if let Some(keys) = store.stats(&partition).await?.keys {
            total = total.saturating_add(keys);
        }
    }
    if total > MAX_SCANNED_ROWS {
        return Err(ForkError::TooLarge);
    }
    Ok(())
}

/// What a copy page needs, fixed for the whole copy.
struct Page<'a> {
    source: crate::repo::RepoId,
    dest: crate::repo::RepoId,
    packs: std::collections::BTreeSet<Hash>,
    manifests: std::collections::BTreeSet<Hash>,
    holders: Option<u64>,
    rows: u32,
    per_batch: usize,
    range: (crate::store::Key, crate::store::Key),
    partitions: &'a [Partition],
}

/// Scan the source's index rows and copy those of the pack set. One scan page
/// per unit; every index write is a put of the same row.
pub(crate) async fn copy<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    job: &mut ForkJobV1,
    budget: &SliceBudget,
) -> Result<bool, ForkError> {
    let source = job.source()?;
    let dest = job.dest()?;
    let store = Budgeted::new(env.store, budget);
    let partitions = env.shards.object_index_partitions(&source);
    let holders = env.extract_min_bytes;
    let manifests = if holders.is_some() {
        let coordinator = env.shards.coordinator(&dest.namespace);
        let [m] = sets::read(&store, &coordinator, &dest.name, [set::MANIFESTS]).await?;
        m.ids
    } else {
        std::collections::BTreeSet::new()
    };
    // The apply reserve of a store (Workers) comes off the batch, with the
    // deadline guard.
    let per_batch = COPY_PUTS.min(
        crate::store::MAX_BATCH_OPS
            .saturating_sub(env.store.capabilities().reserved_batch_ops)
            .saturating_sub(2)
            .max(1),
    );
    let page = Page {
        range: keys::object_index_repo_range(&source.name),
        packs: job.pack_ids(),
        rows: if holders.is_some() {
            64
        } else {
            SCAN_PAGE_ROWS
        },
        per_batch,
        holders,
        manifests,
        partitions: &partitions,
        source,
        dest,
    };
    let reserve = if holders.is_some() { 64 * 6 + 40 } else { 60 };
    let expected = job.object_total();
    let fresh = super::fresh(budget);
    let mut progressed = false;
    while (job.part as usize) < partitions.len() {
        if budget.remaining() < reserve {
            return Ok(false);
        }
        let before = (job.part, job.after.clone(), job.scanned, job.copied);
        match copy_page(env, &store, job, &page, expected).await {
            Ok(()) => progressed = true,
            Err(error) if super::spent(&error, budget) => {
                (job.part, job.after, job.scanned, job.copied) = before;
                return if progressed || !fresh {
                    Ok(false)
                } else {
                    Err(ForkError::TooLarge)
                };
            }
            Err(error) => return Err(error),
        }
    }
    // Every entry of every inherited pack must have been copied, or the
    // inventory and the index disagree: refuse rather than publish a gap.
    if job.copied != expected {
        return Err(ForkError::NotFound);
    }
    Ok(true)
}

async fn copy_page<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    store: &Budgeted<'_, S>,
    job: &mut ForkJobV1,
    page: &Page<'_>,
    expected: u64,
) -> Result<(), ForkError> {
    let partition = &page.partitions[job.part as usize];
    let after = job.after.clone().map(Cursor::new);
    let scanned = store
        .scan(
            partition,
            &page.range.0,
            &page.range.1,
            after.as_ref(),
            page.rows,
        )
        .await?;
    job.scanned += scanned.entries.len() as u64;
    if job.scanned > MAX_SCANNED_ROWS {
        return Err(ForkError::TooLarge);
    }
    let mut grouped: BTreeMap<Partition, Vec<(crate::store::Key, crate::store::Value)>> =
        BTreeMap::new();
    let mut candidates: Vec<Hash> = Vec::new();
    for (key, value) in scanned.entries {
        let Some(keys::ParsedKey::ObjectIndex {
            repo,
            object,
            pack_id,
        }) = keys::parse(&key)
        else {
            return Err(ForkError::NotFound);
        };
        if repo != page.source.name || !page.packs.contains(&pack_id) {
            continue;
        }
        let located = codec::decode_object_index(&object, &value)?;
        if page.holders.is_some_and(|min| located.decoded_size >= min)
            || page.manifests.contains(&object)
        {
            candidates.push(object);
        }
        grouped
            .entry(env.shards.object_index(&page.dest, &object))
            .or_default()
            .push((
                keys::object_index(&page.dest.name, &object, &pack_id),
                value,
            ));
        job.copied += 1;
    }
    if job.copied > expected {
        // More rows than the sealed inventories hold: the index and the
        // inventories disagree.
        return Err(ForkError::NotFound);
    }
    if job.copied > env.limits.max_objects {
        return Err(ForkError::TooLarge);
    }
    for (target, puts) in grouped {
        for chunk in puts.chunks(page.per_batch) {
            // A slice outlives one apply window: stamp each write when it is made.
            let mut batch = Batch::new().require(Precondition::NotAfter(
                env.now().saturating_add(CONTENT_APPLY_WINDOW_MS),
            ));
            for (key, value) in chunk {
                batch = batch.put(key.clone(), value.clone());
            }
            match store.apply(&target, batch).await? {
                crate::store::BatchOutcome::Committed => {}
                _ => return Err(ForkError::Unavailable("fork copy contended")),
            }
        }
    }
    if !candidates.is_empty() {
        copy_holders(env, store, job, &page.source, &page.dest, &candidates).await?;
    }
    if let Some(next) = scanned.next {
        job.after = Some(next.as_bytes().to_vec());
    } else {
        job.part += 1;
        job.after = None;
    }
    Ok(())
}

/// The destination becomes a holder of each extracted object the source holds.
async fn copy_holders<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    store: &Budgeted<'_, S>,
    job: &ForkJobV1,
    source: &crate::repo::RepoId,
    dest: &crate::repo::RepoId,
    objects: &[Hash],
) -> Result<(), ForkError> {
    let index = ContentIndex::new(BorrowedStore(store));
    let from = Holder::new(source.namespace.clone(), source.name.clone());
    let to = Holder::new(dest.namespace.clone(), dest.name.clone());
    for object in objects {
        if index.holder_record(object, &from).await?.is_none() {
            continue;
        }
        let outcome = index
            .add_holder_unless_blocked(object, &to, &job.binding, None, env.now())
            .await?;
        if outcome.blocked.is_some() {
            return Err(ForkError::NotFound);
        }
    }
    Ok(())
}

/// Count the next batch of packs once against the destination. The batch is
/// the effects only; the driver adds the job row.
pub(crate) async fn count<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    job: &mut ForkJobV1,
    budget: &SliceBudget,
) -> Result<Batch, ForkError> {
    let dest = job.dest()?;
    let store = Budgeted::new(env.store, budget);
    let p = env.shards.coordinator(&dest.namespace);
    let start = job.cursor as usize;
    let end = (start + super::COUNT_BATCH_PACKS).min(job.packs.len());
    let packs: Vec<(Hash, u64)> = job.packs[start..end]
        .iter()
        .map(|r| (r.id, r.len))
        .collect();
    let mut wanted = repo_storage::read_keys(&dest.name, &packs);
    wanted.push(keys::outbox_sequence());
    wanted.push(keys::outcome_backlog());
    let rows = store.get_many(&p, &wanted).await?;
    let lookup = |key: &crate::store::Key| {
        wanted
            .iter()
            .position(|k| k == key)
            .and_then(|i| rows.get(i))
            .and_then(Option::as_ref)
    };
    let mut outbox = OutboxBuilder::new(
        lookup(&keys::outbox_sequence()),
        lookup(&keys::outcome_backlog()),
    )?;
    let (mut pre, mut writes) = (Vec::new(), Vec::new());
    let now = env.now();
    repo_storage::plan_count(
        &dest,
        &packs,
        &p,
        env.shards,
        lookup,
        |_| false,
        now,
        &mut outbox,
        &mut pre,
        &mut writes,
    )?;
    outbox.relay_at(now);
    outbox.try_finish(&mut pre, &mut writes)?;
    job.cursor = u32::try_from(end).map_err(|_| ForkError::TooLarge)?;
    let mut batch = Batch::new();
    batch.preconditions = pre;
    for write in writes {
        batch = match write {
            Write::Put(k, v) => batch.put(k, v),
            Write::Delete(k) => batch.delete(k),
        };
    }
    Ok(batch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fork::{FenceV1, ForkLimits, Phase};
    use crate::pipeline::{D34Shards, ShardMap as _};
    use crate::{ManualClock, MemoryKv};

    fn job(fence: Option<FenceV1>) -> ForkJobV1 {
        ForkJobV1 {
            binding: [1; 32],
            dest_ns: "0x1111111111111111111111111111111111111111".into(),
            dest_repo: "forked".into(),
            source_ns: "0x1111111111111111111111111111111111111111".into(),
            source_repo: "source".into(),
            source_ref: "refs/heads/main".into(),
            tip: [2; 32],
            packmap: [3; 32],
            source_sequence: 1,
            source_generation: 0,
            visibility: "public".into(),
            created_ms: 0,
            expires_ms: 1,
            phase: Phase::Register,
            packs: Vec::new(),
            cursor: 0,
            deps: Vec::new(),
            part: 0,
            after: None,
            scanned: 0,
            copied: 0,
            failure: None,
            settle: None,
            fence,
            result: None,
        }
    }

    fn open() -> FenceV1 {
        FenceV1 {
            authority_generation: None,
            grant_epoch: None,
            create_namespace: true,
        }
    }

    async fn registered(kv: &MemoryKv, job: &ForkJobV1, put: &[(crate::Key, crate::Value)]) {
        let mut batch = Batch::new();
        for (key, value) in put {
            batch = batch.put(key.clone(), value.clone());
        }
        kv.apply(
            &D34Shards.coordinator(&job.dest().unwrap().namespace),
            batch,
        )
        .await
        .unwrap();
    }

    fn env<'a>(kv: &'a MemoryKv, clock: &'a ManualClock) -> ForkEnv<'a, MemoryKv> {
        ForkEnv {
            store: kv,
            shards: &D34Shards,
            clock,
            takedown_denial: true,
            extract_min_bytes: None,
            limits: ForkLimits::default(),
        }
    }

    #[tokio::test]
    async fn a_repository_registered_since_the_check_is_never_adopted() {
        let (kv, clock) = (MemoryKv::default(), ManualClock::new(0));
        let job = job(Some(open()));
        let dest = job.dest().unwrap();
        registered(
            &kv,
            &job,
            &[(
                keys::repo_record(&dest.name),
                codec::encode_repo_record(&codec::RepoRecord { created_at_ms: 1 }),
            )],
        )
        .await;
        assert_eq!(
            register(&env(&kv, &clock), &job).await.unwrap_err(),
            ForkError::NotEmpty
        );
    }

    #[tokio::test]
    async fn a_persisted_authority_fence_needs_a_fork_authorized_under_one() {
        let (kv, clock) = (MemoryKv::default(), ManualClock::new(0));
        for fence in [None, Some(open())] {
            let job = job(fence);
            registered(
                &kv,
                &job,
                &[(keys::authority_generation(), codec::encode_u64(4))],
            )
            .await;
            assert_eq!(
                register(&env(&kv, &clock), &job).await.unwrap_err(),
                ForkError::Unavailable("fork requires authority fence")
            );
        }
        // With the generation it was authorized under, registration proceeds.
        let job = job(Some(FenceV1 {
            authority_generation: Some(4),
            ..open()
        }));
        assert!(register(&env(&kv, &clock), &job).await.is_ok());
    }

    #[tokio::test]
    async fn the_first_repository_of_a_registered_authority_namespace_creates_its_record() {
        let (kv, clock) = (MemoryKv::default(), ManualClock::new(0));
        let job = job(Some(FenceV1 {
            authority_generation: Some(3),
            grant_epoch: None,
            create_namespace: false,
        }));
        registered(
            &kv,
            &job,
            &[(keys::authority_generation(), codec::encode_u64(3))],
        )
        .await;
        let batch = register(&env(&kv, &clock), &job).await.unwrap();
        assert!(batch.writes.iter().any(
            |w| matches!(w, crate::store::Write::Put(k, _) if *k == keys::namespace_record())
        ));
    }

    #[tokio::test]
    async fn an_authority_row_without_a_namespace_is_not_ours_to_create() {
        let (kv, clock) = (MemoryKv::default(), ManualClock::new(0));
        let job = job(Some(FenceV1 {
            authority_generation: Some(0),
            grant_epoch: None,
            create_namespace: false,
        }));
        assert_eq!(
            register(&env(&kv, &clock), &job).await.unwrap_err(),
            ForkError::Denied
        );
    }
}
