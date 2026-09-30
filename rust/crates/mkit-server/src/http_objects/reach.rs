//! Reachability for id URLs (SPEC-HTTP-OBJECTS §4, D2): a member id is
//! served only when a published ref reaches it. The default is a bounded
//! breadth-first walk from the published refs with a positive-result cache;
//! [`Reachability`] is the seam a maintained reachable set (WP-5.3a) will
//! replace it behind.
//!
//! The walk follows commit and remix parents and trees, tree entries,
//! manifest chunks and tag targets. It never follows remix `sources` or
//! delta bases (the same edges as `mkit_core::ops::graph::children` in
//! history mode), and it stops at a tombstoned or blocked object
//! ([`TakedownGate::stops_descent`]). A cap never aborts the walk: the
//! object or subtree it hides is skipped and the walk reports
//! `Capped` only if the target was not found anywhere else.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Mutex;

use mkit_core::hash::Hash;
use mkit_core::object::{EntryMode, Object, ObjectType};

use super::TakedownGate;
use super::resolve::{self, Budget, Env, Miss};
use crate::repo::RepoId;
use crate::{BlobStore, BoxFuture, MaybeSend, MaybeSync, NamespaceStore, ServerError};

/// Ids located per index lookup (`store::index::MAX_LOOKUP_IDS`).
const BATCH: usize = 256;
/// Canonical manifest bytes without chunk hashes: prologue 6, `total_size`
/// 8, `chunk_size` 4, `chunk_count` 4.
const MANIFEST_FIXED: u64 = 22;
/// The decode-side chunk-count cap of `mkit-core`'s deserializer
/// (`MAX_CHUNKS`, `serialize.rs`): a larger manifest cannot exist.
const MAX_MANIFEST_CHUNKS: u64 = 1_000_000;
/// Least time between sweeps of a full [`TtlReachability`] table.
const SWEEP_MS: u64 = 1_000;

/// A source of positive reachability answers, consulted before the walk.
pub trait Reachability: MaybeSend + MaybeSync {
    /// Whether `id` is already known to be reachable from a published ref of
    /// `repo` as of `now_ms`. `false` means unknown, never unreachable. A
    /// positive answer skips the walk, so it also skips the walk's takedown
    /// stop predicate: [`TakedownGate::check`] must therefore refuse a leaf
    /// that only a blocked or tombstoned manifest reaches.
    fn known_reachable<'a>(
        &'a self,
        repo: &'a RepoId,
        id: &'a Hash,
        now_ms: u64,
    ) -> BoxFuture<'a, Result<bool, ServerError>>;

    /// Record a proof: a walk found `id`, or a ref-path serve resolved it.
    fn record(&self, repo: &RepoId, id: &Hash, now_ms: u64);

    /// Forget every proof of `repo`: a takedown, suspension or visibility
    /// change (WP-5.9a) that cannot wait out the lag calls it.
    fn invalidate(&self, repo: &RepoId);
}

/// The default: proofs live for `lag_ms`, in a table of at most
/// `max_entries` rows. A rewind or ref deletion is therefore visible within
/// the configured `reachability_lag`; only [`Reachability::invalidate`]
/// forgets one sooner.
#[derive(Debug)]
pub struct TtlReachability {
    lag_ms: u64,
    max_entries: usize,
    table: Mutex<Table>,
}

#[derive(Debug, Default)]
struct Table {
    rows: BTreeMap<(RepoId, Hash), u64>,
    /// When expired rows were last swept: a full table of live rows is not
    /// re-scanned on every record.
    swept_ms: u64,
}

impl TtlReachability {
    /// A cache whose rows expire `lag_ms` after they are recorded.
    #[must_use]
    pub fn new(lag_ms: u64, max_entries: usize) -> Self {
        Self {
            lag_ms,
            max_entries,
            table: Mutex::default(),
        }
    }

    fn table(&self) -> std::sync::MutexGuard<'_, Table> {
        self.table
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Reachability for TtlReachability {
    fn known_reachable<'a>(
        &'a self,
        repo: &'a RepoId,
        id: &'a Hash,
        now_ms: u64,
    ) -> BoxFuture<'a, Result<bool, ServerError>> {
        Box::pin(async move {
            Ok(self
                .table()
                .rows
                .get(&(repo.clone(), *id))
                .is_some_and(|expires| *expires > now_ms))
        })
    }

    fn record(&self, repo: &RepoId, id: &Hash, now_ms: u64) {
        let mut table = self.table();
        if table.rows.len() >= self.max_entries && now_ms >= table.swept_ms.saturating_add(SWEEP_MS)
        {
            table.rows.retain(|_, expires| *expires > now_ms);
            table.swept_ms = now_ms;
        }
        // A full table of live rows drops the new proof: the next request
        // walks again. Memory stays bounded.
        if table.rows.len() < self.max_entries {
            table
                .rows
                .insert((repo.clone(), *id), now_ms.saturating_add(self.lag_ms));
        }
    }

    fn invalidate(&self, repo: &RepoId) {
        self.table()
            .rows
            .retain(|(row_repo, _), _| row_repo != repo);
    }
}

/// The walk's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reach {
    Reachable,
    Unreachable,
    /// A cap hid part of the graph and the target was not found elsewhere:
    /// the uniform 404 and a metric.
    Capped,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// A commit, remix, tag or ref tip: type unknown until decoded.
    Node,
    Tree,
    /// A tree entry that is a Blob or a `ChunkedBlob`.
    File,
}

/// Whether a `File` of `size` canonical bytes can be a manifest: an exact
/// necessary condition (`22 + 32n`, `n` at most the decode cap), so a plain
/// Blob is decoded only about one time in 32, and never when it is too big
/// to be one.
fn manifest_sized(size: u64) -> bool {
    (MANIFEST_FIXED..=MANIFEST_FIXED + 32 * MAX_MANIFEST_CHUNKS).contains(&size)
        && (size - MANIFEST_FIXED).is_multiple_of(32)
}

/// The queues one walk drains, bounded by `cap` distinct objects so a wide
/// tree cannot grow them without limit.
struct Frontier {
    cap: usize,
    seen: BTreeSet<Hash>,
    /// Commits, remixes and tags: history, walked after the trees.
    nodes: VecDeque<Hash>,
    /// Trees and files: tip trees are the likeliest targets.
    work: VecDeque<(Hash, Kind)>,
    /// A reference was not queued because of `cap`, or an object was skipped
    /// because of the decode budget: the walk is incomplete.
    incomplete: bool,
}

impl Frontier {
    fn push(&mut self, id: Hash, kind: Kind) {
        if self.seen.contains(&id) {
            return;
        }
        if self.seen.len() >= self.cap {
            self.incomplete = true;
            return;
        }
        self.seen.insert(id);
        match kind {
            Kind::Node => self.nodes.push_back(id),
            Kind::Tree | Kind::File => self.work.push_back((id, kind)),
        }
    }

    /// The next batch: trees and files first, then history.
    fn batch(&mut self) -> Vec<(Hash, Kind)> {
        let mut batch = Vec::new();
        if self.work.is_empty() {
            while batch.len() < BATCH {
                let Some(id) = self.nodes.pop_front() else {
                    break;
                };
                batch.push((id, Kind::Node));
            }
        } else {
            while batch.len() < BATCH {
                let Some(item) = self.work.pop_front() else {
                    break;
                };
                batch.push(item);
            }
        }
        batch
    }
}

/// Queue the references of `object`; whether `target` is among them. The
/// comparison happens for every reference, queued or not.
fn expand(object: &Object, frontier: &mut Frontier, mut reached: impl FnMut(Hash)) {
    let mut visit = |child: Hash, kind: Option<Kind>| {
        reached(child);
        if let Some(kind) = kind {
            frontier.push(child, kind);
        }
    };
    match object {
        Object::Commit(c) => {
            visit(c.tree_hash, Some(Kind::Tree));
            c.parents.iter().for_each(|p| visit(*p, Some(Kind::Node)));
        }
        Object::Remix(r) => {
            visit(r.tree_hash, Some(Kind::Tree));
            r.parents.iter().for_each(|p| visit(*p, Some(Kind::Node)));
        }
        Object::Tree(t) => {
            for entry in &t.entries {
                let kind = if entry.mode == EntryMode::Tree {
                    Kind::Tree
                } else {
                    Kind::File
                };
                visit(entry.object_hash, Some(kind));
            }
        }
        Object::ChunkedBlob(cb) => cb.chunks.iter().for_each(|c| visit(*c, None)),
        Object::Tag(t) => visit(
            t.target,
            match t.target_type {
                ObjectType::Tree => Some(Kind::Tree),
                ObjectType::Blob | ObjectType::ChunkedBlob => Some(Kind::File),
                ObjectType::Delta => None,
                _ => Some(Kind::Node),
            },
        ),
        Object::Blob(_) | Object::Delta(_) => {}
    }
}

/// Search the published `tips` for `target`, queueing at most
/// `max_walk_objects` objects and charging every decode to `budget`.
pub(crate) async fn walk<B: BlobStore, N: NamespaceStore>(
    env: &Env<'_, B, N>,
    takedown: &dyn TakedownGate,
    tips: &[Hash],
    target: Hash,
    budget: &mut Budget,
) -> Result<Reach, Miss> {
    let targets = BTreeSet::from([target]);
    let (reached, capped) = walk_many(env, takedown, tips, &targets, budget).await?;
    Ok(if reached.contains(&target) {
        Reach::Reachable
    } else if capped {
        Reach::Capped
    } else {
        Reach::Unreachable
    })
}

/// One walk for a batch. `Env::no_reads` forbids loading selected objects, including
/// as ancestors; unresolved descendants then report an incomplete proof.
pub(crate) async fn walk_many<B: BlobStore, N: NamespaceStore>(
    env: &Env<'_, B, N>,
    takedown: &dyn TakedownGate,
    tips: &[Hash],
    targets: &BTreeSet<Hash>,
    budget: &mut Budget,
) -> Result<(BTreeSet<Hash>, bool), Miss> {
    let mut reached = BTreeSet::new();
    let mut frontier = Frontier {
        cap: env.cfg.max_walk_objects,
        seen: BTreeSet::new(),
        nodes: VecDeque::new(),
        work: VecDeque::new(),
        incomplete: false,
    };
    let mut record = |id| {
        if targets.contains(&id) {
            reached.insert(id);
        }
    };
    for tip in tips {
        record(*tip);
        frontier.push(*tip, Kind::Node);
    }
    loop {
        if reached.len() == targets.len() {
            return Ok((reached, false));
        }
        let batch = frontier.batch();
        if batch.is_empty() {
            return Ok((reached, frontier.incomplete));
        }
        let ids: Vec<Hash> = batch.iter().map(|(id, _)| *id).collect();
        let kinds: BTreeMap<Hash, Kind> = batch.into_iter().collect();
        for (id, located) in resolve::locate_many(env, &ids).await? {
            if crate::takedown::denial::denied(env.meta, &id)
                .await
                .map_err(|_| Miss::Unavailable)?
                || takedown.stops_descent(env.repo, &id)
            {
                continue;
            }
            if kinds[&id] == Kind::File && !manifest_sized(located.value.decoded_size) {
                continue;
            }
            if env.no_reads.contains(&id) {
                frontier.incomplete = true;
                continue;
            }
            let bytes = match resolve::load(env, id, located, budget).await {
                Ok(bytes) => bytes,
                Err(Miss::Capped) => {
                    frontier.incomplete = true;
                    continue;
                }
                Err(other) => return Err(other),
            };
            let object =
                mkit_core::serialize::deserialize(&bytes).map_err(|_| Miss::Unavailable)?;
            expand(&object, &mut frontier, |child| {
                if targets.contains(&child) {
                    reached.insert(child);
                }
            });
            if reached.len() == targets.len() {
                return Ok((reached, false));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use futures_executor::block_on;

    use super::*;
    use crate::repo::{NamespaceKey, RepoName};

    fn repo(name: &str) -> RepoId {
        RepoId {
            namespace: NamespaceKey::deployment_default(),
            name: RepoName::new(name).unwrap(),
        }
    }

    fn known(cache: &TtlReachability, repo: &RepoId, id: u8, now: u64) -> bool {
        block_on(cache.known_reachable(repo, &[id; 32], now)).unwrap()
    }

    #[test]
    fn a_proof_expires_after_the_lag_and_is_per_repository() {
        let cache = TtlReachability::new(60_000, 8);
        let (a, b) = (repo("a"), repo("b"));
        cache.record(&a, &[1; 32], 1_000);
        assert!(known(&cache, &a, 1, 60_999));
        assert!(!known(&cache, &a, 1, 61_000));
        assert!(!known(&cache, &b, 1, 1_000), "another repository's proof");
        assert!(!known(&cache, &a, 2, 1_000));
        cache.record(&a, &[2; 32], 1_000);
        cache.record(&b, &[2; 32], 1_000);
        cache.invalidate(&a);
        assert!(!known(&cache, &a, 2, 1_001) && known(&cache, &b, 2, 1_001));
    }

    #[test]
    fn a_full_table_is_bounded_and_sweeps_at_most_once_a_second() {
        let cache = TtlReachability::new(10_000, 2);
        let a = repo("a");
        cache.record(&a, &[1; 32], 5_000);
        cache.record(&a, &[2; 32], 5_000);
        // Full of live rows: the new proof is dropped, never stored.
        cache.record(&a, &[3; 32], 6_000);
        assert!(!known(&cache, &a, 3, 6_000));
        // Once the rows expire, the next record sweeps and stores.
        cache.record(&a, &[3; 32], 16_000);
        assert!(known(&cache, &a, 3, 16_000));
        assert!(!known(&cache, &a, 1, 16_000));
    }

    #[test]
    fn only_a_manifest_shaped_file_is_ever_decoded() {
        for (size, want) in [
            (0, false),
            (21, false),
            (22, true),
            (23, false),
            (54, true),
            (22 + 32 * 1_000_000, true),
            (22 + 32 * 1_000_001, false),
            (10 + 300 * 1024 * 1024, false),
        ] {
            assert_eq!(manifest_sized(size), want, "{size}");
        }
    }
}
