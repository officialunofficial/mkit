//! Registration, the index-row copy and the one-time storage count.

use super::{
    COPY_PUTS, CopyLane, ForkEnv, ForkError, ForkJobV1, MAX_SCANNED_ROWS, SCAN_PAGE_ROWS, set, sets,
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
pub(super) fn fence_guards(
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
    let mut batch = Batch::new()
        .require(Precondition::Absent(keys::fork_barrier(&dest.name)))
        .put(
            keys::fork_barrier(&dest.name),
            crate::Value::new(job.binding.to_vec()),
        );
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
    let partitions: Vec<_> = env
        .shards
        .object_index_partitions(&job.source()?)
        .into_iter()
        .filter(|p| matches!(p, Partition::RepoIndex { .. }))
        .collect();
    let mut total = 0_u64;
    let mut pending = partitions.as_slice();
    while !pending.is_empty() {
        // Stats cannot use read credits, but a zero-call reservation exposes
        // inherited accounting layers without spending or dispatching calls.
        // Include the local debit and an opaque leaf: shared ancestors must
        // cover the whole wave before a later call can mask an earlier error.
        let cap = match (
            env.store.read_call_allowance(),
            env.store.reserve_read_calls(0),
        ) {
            (Some(allowance), Ok(reservation)) => {
                let layers = reservation
                    .as_ref()
                    .map_or(0, crate::store::ReadReservation::accounting_layers);
                let debits = layers.saturating_mul(2).saturating_add(2);
                usize::try_from(allowance.min(budget.remaining()) / debits)
                    .unwrap_or(6)
                    .clamp(1, super::WAVE_WIDTH)
            }
            _ => 1,
        };
        let width = pending.len().min(cap);
        let (wave, rest) = pending.split_at(width);
        pending = rest;
        // Stats do not consume read credits. Charge the slice once before
        // dispatch, then use the underlying store (including its own ledger).
        budget.charge_many(u32::try_from(wave.len()).unwrap_or(u32::MAX))?;
        let replies = crate::store::ReadReservation::scope(
            &[],
            futures::future::join_all(wave.iter().map(|p| env.store.stats(p))),
        )
        .await;
        for reply in replies {
            if let Some(keys) = reply?.keys {
                total = total.saturating_add(keys);
            }
        }
    }
    if total > MAX_SCANNED_ROWS {
        return Err(ForkError::TooLarge);
    }
    Ok(())
}

/// Source partitions one copy wave reads together. Six is the number of
/// simultaneous subrequests a Worker keeps open.
const COPY_WAVE: usize = 6;
/// Rows per source index scan when holders are copied. A page whose holder
/// candidates exceed what one wave may copy resumes inside the page (see
/// [`CopyLane::held`]), so the page size does not bound the holder work.
const HOLDER_PAGE_ROWS: u32 = 256;
/// Holder candidates one wave copies, at most.
const HOLDERS_PER_WAVE: usize = 64;
/// Calls budgeted to one holder candidate: the source read and a mutation.
const HOLDER_CALLS: u32 = 6;

/// What a copy wave needs, fixed for the whole copy.
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
    budget: &'a SliceBudget,
}

impl Page<'_> {
    /// Calls one lane of a wave needs besides holders: its scan and its
    /// writes, with one spare.
    fn lane_reserve(&self) -> u32 {
        let writes = (self.rows as usize).div_ceil(self.per_batch);
        2 + u32::try_from(writes).unwrap_or(u32::MAX)
    }
    /// Remaining calls below which no wave starts.
    fn wave_reserve(&self) -> u32 {
        self.lane_reserve()
            + if self.holders.is_some() {
                2 * HOLDER_CALLS
            } else {
                0
            }
    }
}

/// What one lane of a wave read from its partition and decided to copy.
struct Fetched {
    lane: usize,
    /// Rows the scan returned.
    scanned: u64,
    /// Rows of the pack set: the page's rows to write and count.
    copied: u64,
    next: Option<Cursor>,
    /// Destination writes by target partition.
    writes: BTreeMap<Partition, Vec<(crate::store::Key, crate::store::Value)>>,
    /// Source key and object of each holder candidate, in key order.
    candidates: Vec<(crate::store::Key, Hash)>,
}

/// Scan the source's index rows and copy those of the pack set, up to
/// [`COPY_WAVE`] partitions at a time. Every index write is a put of the same
/// row.
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
            HOLDER_PAGE_ROWS
        } else {
            SCAN_PAGE_ROWS
        },
        per_batch,
        holders,
        manifests,
        partitions: &partitions,
        budget,
        source,
        dest,
    };
    if job.lanes.is_empty() {
        job.lanes = vec![CopyLane::default(); partitions.len()];
    } else if job.lanes.len() != partitions.len() {
        return Err(ForkError::Unavailable("fork shard map"));
    }
    let expected = job.object_total();
    let fresh = super::fresh(budget);
    let mut progressed = false;
    loop {
        let open: Vec<usize> = (0..job.lanes.len())
            .filter(|&lane| !job.lanes[lane].done)
            .collect();
        if open.is_empty() {
            break;
        }
        if budget.remaining() < page.wave_reserve() {
            return Ok(false);
        }
        let before = (job.lanes.clone(), job.scanned, job.copied);
        match copy_wave(env, &store, job, &page, expected, &open).await {
            Ok(true) => progressed = true,
            // No lane could move: the slice cannot pay for one more step.
            Ok(false) => {
                return if progressed || !fresh {
                    Ok(false)
                } else {
                    Err(ForkError::TooLarge)
                };
            }
            // A wave that spends the slice keeps nothing; its writes are
            // puts of the same rows and holders that only raise a sequence.
            Err(error) if super::spent(&error, budget) => {
                (job.lanes, job.scanned, job.copied) = before;
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

/// One wave: a page of each of the first partitions that are still open.
/// Reads, then writes, then holders, each stage completing for the whole wave
/// and consuming its replies in partition order, so the wave answers as the
/// same lanes taken one after another would: the first failing lane's error,
/// and no lane after it counted. Returns whether any lane moved.
async fn copy_wave<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    store: &Budgeted<'_, S>,
    job: &mut ForkJobV1,
    page: &Page<'_>,
    expected: u64,
    open: &[usize],
) -> Result<bool, ForkError> {
    let (wave, replies) = scan_wave(store, job, page, open).await?;

    // Fold the replies in lane order. The totals run across the wave, pages
    // that wait for holders included, so a bound can trip a wave before the
    // serial walk would reach it; the outcome is the same failure.
    let (mut scanned, mut copied) = (job.scanned, job.copied);
    let mut ready: Vec<Fetched> = Vec::new();
    let mut failure = None;
    for (&lane, reply) in wave.iter().zip(replies) {
        match fetched(
            env,
            page,
            lane,
            reply,
            (&mut scanned, &mut copied),
            expected,
        ) {
            Ok(lane) => ready.push(lane),
            Err(error) => {
                failure = Some(error);
                break;
            }
        }
    }

    // Keep the lanes whose writes the slice can still pay for (the first
    // always stays: a wave of one is the serial walk). The rest wait for the
    // next wave, and so does a failure that belonged to one of them.
    let mut room = page
        .budget
        .remaining()
        .saturating_sub(if page.holders.is_some() {
            2 * HOLDER_CALLS
        } else {
            0
        });
    let mut keep = 0;
    for lane in &ready {
        let calls = if job.lanes[lane.lane].held.is_some() {
            0
        } else {
            let chunks: usize = lane
                .writes
                .values()
                .map(|puts| puts.len().div_ceil(page.per_batch))
                .sum();
            u32::try_from(chunks).unwrap_or(u32::MAX)
        };
        if keep > 0 && calls > room {
            break;
        }
        room = room.saturating_sub(calls);
        keep += 1;
    }
    if keep < ready.len() {
        ready.truncate(keep);
        failure = None;
    }

    if let Some((index, error)) = write_wave(env, store, job, page, &ready).await {
        // The failing lane and every lane after it end here.
        ready.truncate(index);
        failure = Some(error);
    }

    // Holders of the lanes that reached here, within what the slice can pay
    // for. Candidates the wave cannot take wait for the next one.
    let (objects, steps) = holder_steps(job, page, &ready);
    if !objects.is_empty() {
        copy_holders(
            env,
            store,
            page.budget,
            job,
            &page.source,
            &page.dest,
            &objects,
        )
        .await?;
    }
    if let Some(error) = failure {
        return Err(error);
    }

    let mut moved = false;
    for (lane, step) in ready.iter().zip(steps) {
        let cursor = &mut job.lanes[lane.lane];
        if step.take == step.waiting {
            if let Some(next) = &lane.next {
                cursor.after = Some(next.as_bytes().to_vec());
            } else {
                cursor.done = true;
                cursor.after = None;
            }
            cursor.held = None;
            job.scanned += lane.scanned;
            job.copied += lane.copied;
            moved = true;
        } else if step.take > 0 {
            cursor.held = step.last;
            moved = true;
        } else if cursor.held.is_none() {
            // The wave had no room for this lane's holders, but its rows are
            // written: an empty mark keeps the next wave from writing them again.
            cursor.held = Some(Vec::new());
        }
    }
    Ok(moved)
}

/// Scan one page in each lane of the wave: as many of `open` as the known
/// allowance and the slice's calls cover.
async fn scan_wave<'a, S: NamespaceStore>(
    store: &Budgeted<'_, S>,
    job: &ForkJobV1,
    page: &Page<'_>,
    open: &'a [usize],
) -> Result<
    (
        &'a [usize],
        Vec<Result<crate::store::ScanPage, crate::store::StoreError>>,
    ),
    ForkError,
> {
    // Reserve the first read before choosing the width: its reservation shows
    // the accounting depth, and a wave narrows where the remaining calls
    // cannot cover shared ancestors. An unknown allowance stays serial.
    let first = store.reserve_read_calls(1)?;
    let layers = first
        .as_ref()
        .map_or(0, crate::store::ReadReservation::accounting_layers);
    let debits = layers.saturating_mul(2).saturating_add(1);
    let by_allowance = usize::try_from(store.read_call_allowance().unwrap_or(0) / debits)
        .unwrap_or(COPY_WAVE)
        .clamp(1, COPY_WAVE);
    let by_budget = usize::try_from(page.budget.remaining() / page.lane_reserve()).unwrap_or(1);
    let wave = &open[..open.len().min(by_allowance).min(by_budget).max(1)];

    let mut first = Some(first);
    let replies = futures::future::join_all(wave.iter().map(|&lane| {
        let reservation = if let Some(first) = first.take() {
            Ok(first)
        } else {
            store.reserve_read_calls(1)
        };
        let after = job.lanes[lane].after.clone().map(Cursor::new);
        let partition = &page.partitions[lane];
        async move {
            let reservation = reservation?;
            crate::store::ReadReservation::scope(
                &[reservation],
                store.scan(
                    partition,
                    &page.range.0,
                    &page.range.1,
                    after.as_ref(),
                    page.rows,
                ),
            )
            .await
        }
    }))
    .await;
    Ok((wave, replies))
}

/// Write the rows of `ready`, at most six batches at a time. A lane that
/// already copied some of its page's holders wrote its rows in an earlier
/// wave. Returns the first failing batch's lane (an index into `ready`) and
/// its error.
async fn write_wave<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    store: &Budgeted<'_, S>,
    job: &ForkJobV1,
    page: &Page<'_>,
    ready: &[Fetched],
) -> Option<(usize, ForkError)> {
    let mut units = Vec::new();
    for (index, lane) in ready.iter().enumerate() {
        if job.lanes[lane.lane].held.is_some() {
            continue;
        }
        for (target, puts) in &lane.writes {
            for chunk in puts.chunks(page.per_batch) {
                units.push((index, target, chunk));
            }
        }
    }
    for group in units.chunks(COPY_WAVE) {
        let replies =
            futures::future::join_all(group.iter().map(|&(_, target, chunk)| async move {
                // A slice outlives one apply window: stamp each write when it is made.
                let mut batch = Batch::new().require(Precondition::NotAfter(
                    env.now().saturating_add(CONTENT_APPLY_WINDOW_MS),
                ));
                for (key, value) in chunk {
                    batch = batch.put(key.clone(), value.clone());
                }
                store.apply(target, batch).await
            }))
            .await;
        for (&(index, _, _), reply) in group.iter().zip(replies) {
            match reply {
                Ok(crate::store::BatchOutcome::Committed) => {}
                Ok(_) => return Some((index, ForkError::Unavailable("fork copy deadline"))),
                Err(error) => return Some((index, error.into())),
            }
        }
    }
    None
}

/// How far one lane's holders get in a wave.
struct HolderStep {
    /// Candidates copied now.
    take: usize,
    /// Candidates still to copy at the wave's start.
    waiting: usize,
    /// The source key of the last one copied.
    last: Option<Vec<u8>>,
}

/// The holders each lane of the wave copies, in lane and key order, and the
/// objects they name. The wave copies at most [`HOLDERS_PER_WAVE`], and no more
/// than the slice's remaining calls pay for.
fn holder_steps(
    job: &ForkJobV1,
    page: &Page<'_>,
    ready: &[Fetched],
) -> (Vec<Hash>, Vec<HolderStep>) {
    let mut room = HOLDERS_PER_WAVE.min(
        usize::try_from(page.budget.remaining().saturating_sub(4) / HOLDER_CALLS)
            .unwrap_or(HOLDERS_PER_WAVE),
    );
    let mut objects = Vec::new();
    let mut steps = Vec::new();
    for lane in ready {
        let held = job.lanes[lane.lane].held.as_deref();
        let waiting: Vec<&(crate::store::Key, Hash)> = lane
            .candidates
            .iter()
            // Scan order is key byte order, so "after the mark" is a prefix cut.
            .filter(|(key, _)| held.is_none_or(|held| key.as_bytes() > held))
            .collect();
        let take = waiting.len().min(room);
        room -= take;
        objects.extend(waiting[..take].iter().map(|(_, object)| *object));
        steps.push(HolderStep {
            take,
            waiting: waiting.len(),
            last: waiting[..take]
                .last()
                .map(|(key, _)| key.as_bytes().to_vec()),
        });
    }
    (objects, steps)
}

/// Read one lane's page: the rows of the pack set to write and the holder
/// candidates among them. `totals` are the wave's running scanned and copied
/// counts, which the bounds are checked against.
fn fetched<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    page: &Page<'_>,
    lane: usize,
    reply: Result<crate::store::ScanPage, crate::store::StoreError>,
    totals: (&mut u64, &mut u64),
    expected: u64,
) -> Result<Fetched, ForkError> {
    let (scanned_total, copied_total) = totals;
    let scanned = reply?;
    let rows = scanned.entries.len() as u64;
    *scanned_total += rows;
    if *scanned_total > MAX_SCANNED_ROWS {
        return Err(ForkError::TooLarge);
    }
    let mut writes: BTreeMap<Partition, Vec<(crate::store::Key, crate::store::Value)>> =
        BTreeMap::new();
    let mut candidates = Vec::new();
    let mut copied = 0;
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
            candidates.push((key, object));
        }
        writes
            .entry(env.shards.object_index(&page.dest, &object))
            .or_default()
            .push((
                keys::object_index(&page.dest.name, &object, &pack_id),
                value,
            ));
        copied += 1;
    }
    *copied_total += copied;
    if *copied_total > expected {
        // More rows than the sealed inventories hold: the index and the
        // inventories disagree.
        return Err(ForkError::NotFound);
    }
    if *copied_total > env.limits.max_objects {
        return Err(ForkError::TooLarge);
    }
    Ok(Fetched {
        lane,
        scanned: rows,
        copied,
        next: scanned.next,
        writes,
        candidates,
    })
}

/// The destination becomes a holder of each extracted object the source holds.
pub(super) async fn copy_holders<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    store: &Budgeted<'_, S>,
    budget: &SliceBudget,
    job: &ForkJobV1,
    source: &crate::repo::RepoId,
    dest: &crate::repo::RepoId,
    objects: &[Hash],
) -> Result<(), ForkError> {
    let denial_reads = crate::store::DenialReads::new(store, env.takedown_denial);
    let index = ContentIndex::new(BorrowedStore(&denial_reads));
    let from = Holder::new(source.namespace.clone(), source.name.clone());
    let to = Holder::new(dest.namespace.clone(), dest.name.clone());
    // Four mutations retain fewer rows than the existing 500-row copy scan.
    // The page reserve still covers the same calls; retries charge on dispatch.
    let mut pending = objects;
    while !pending.is_empty() {
        // An object may occur in several packs. Keep its repeated writes
        // serial, preserving call counts without introducing CAS races.
        // One holder read plus up to eight three-call mutation attempts.
        // With less headroom, retain serial error precedence.
        // Reserve the first existing read before inspecting its accounting
        // layers. Each layer can charge two ledgers, whose ancestors may alias;
        // leave one more debit for an opaque leaf. Unknown caps stay serial.
        let first_reservation = store.reserve_read_calls(1)?;
        let layers = first_reservation
            .as_ref()
            .map_or(0, crate::store::ReadReservation::accounting_layers);
        let debits = layers.saturating_mul(2).saturating_add(1);
        let allowance = store
            .read_call_allowance()
            .unwrap_or(0)
            .min(budget.remaining());
        let cap = usize::try_from(allowance / 25_u32.saturating_mul(debits))
            .unwrap_or(4)
            .clamp(1, 4);
        let mut width = 0;
        while width < pending.len().min(cap) && !pending[..width].contains(&pending[width]) {
            width += 1;
        }
        let (wave, rest) = pending.split_at(width);
        pending = rest;
        let mut first_reservation = Some(first_reservation);
        let replies = futures::future::join_all(wave.iter().map(|object| {
            let reservation = if let Some(first) = first_reservation.take() {
                Ok(first)
            } else {
                store.reserve_read_calls(1)
            };
            let (index, from, to) = (&index, &from, &to);
            async move {
                let reservation = reservation?;
                let held = crate::store::ReadReservation::scope(
                    &[reservation],
                    index.holder_record(object, from),
                )
                .await?;
                if held.is_none() {
                    return Ok(());
                }
                let outcome = index
                    .add_holder_unless_blocked(object, to, &job.binding, None, env.now())
                    .await?;
                if outcome.blocked.is_some() {
                    return Err(ForkError::NotFound);
                }
                Ok(())
            }
        }))
        .await;
        for reply in replies {
            reply?;
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
            lanes: Vec::new(),
            after: None,
            scanned: 0,
            copied: 0,
            failure: None,
            settle: None,
            fence,
            fence_rows: crate::fork::FenceRowsV1::default(),
            source_access: crate::fork::SourceAccessV1::default(),
            accepted: None,
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
