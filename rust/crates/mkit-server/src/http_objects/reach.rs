//! Reachability for id URLs (SPEC-HTTP-OBJECTS §4, D2): a member id is
//! served only when a published ref reaches it. The default is a bounded
//! breadth-first walk from the published refs with a positive-result cache;
//! [`Reachability`] is the seam a maintained reachable set (WP-5.3a) will
//! replace it behind.
//!
//! The walk follows commit and remix parents and trees, tree entries,
//! manifest chunks and tag targets. It never follows remix `sources` or
//! delta bases (`mkit_core::ops::graph::children` skips both), and it stops
//! at a tombstoned or blocked object ([`TakedownGate::stops_descent`]).

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

/// A source of positive reachability answers, consulted before the walk.
pub trait Reachability: MaybeSend + MaybeSync {
    /// Whether `id` is already known to be reachable from a published ref of
    /// `repo` as of `now_ms`. `false` means unknown, never unreachable.
    fn known_reachable<'a>(
        &'a self,
        repo: &'a RepoId,
        id: &'a Hash,
        now_ms: u64,
    ) -> BoxFuture<'a, Result<bool, ServerError>>;

    /// Record a proof: a walk found `id`, or a ref-path serve resolved it.
    fn record(&self, repo: &RepoId, id: &Hash, now_ms: u64);
}

/// The default: proofs live for `lag_ms`, in a table of at most
/// `max_entries` rows. A rewind or ref deletion is therefore visible within
/// the configured `reachability_lag`; nothing else invalidates a row.
#[derive(Debug)]
pub struct TtlReachability {
    lag_ms: u64,
    max_entries: usize,
    rows: Mutex<BTreeMap<(RepoId, Hash), u64>>,
}

impl TtlReachability {
    /// A cache whose rows expire `lag_ms` after they are recorded.
    #[must_use]
    pub fn new(lag_ms: u64, max_entries: usize) -> Self {
        Self {
            lag_ms,
            max_entries,
            rows: Mutex::default(),
        }
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
            let rows = self
                .rows
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Ok(rows
                .get(&(repo.clone(), *id))
                .is_some_and(|expires| *expires > now_ms))
        })
    }

    fn record(&self, repo: &RepoId, id: &Hash, now_ms: u64) {
        let mut rows = self
            .rows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if rows.len() >= self.max_entries {
            rows.retain(|_, expires| *expires > now_ms);
        }
        // A full table of live rows drops the new proof: the next request
        // walks again. Memory stays bounded.
        if rows.len() < self.max_entries {
            rows.insert((repo.clone(), *id), now_ms.saturating_add(self.lag_ms));
        }
    }
}

/// The walk's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reach {
    Reachable,
    Unreachable,
    /// The walk or decode budget ran out: the uniform 404 and a metric.
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
/// necessary condition, so a plain Blob is almost never decoded.
fn manifest_sized(size: u64) -> bool {
    size >= MANIFEST_FIXED && (size - MANIFEST_FIXED).is_multiple_of(32)
}

/// Queue the references of `object`; whether `target` is among them.
fn expand(
    object: &Object,
    target: Hash,
    seen: &mut BTreeSet<Hash>,
    nodes: &mut VecDeque<Hash>,
    work: &mut VecDeque<(Hash, Kind)>,
) -> bool {
    let mut found = false;
    let mut visit = |child: Hash, kind: Option<Kind>| {
        found |= child == target;
        if let Some(kind) = kind
            && seen.insert(child)
        {
            match kind {
                Kind::Node => nodes.push_back(child),
                _ => work.push_back((child, kind)),
            }
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
    found
}

/// Search the published `tips` for `target`, deciding at most
/// `max_walk_objects` objects and charging every decode to `budget`.
pub(crate) async fn walk<B: BlobStore, N: NamespaceStore>(
    env: &Env<'_, B, N>,
    takedown: &dyn TakedownGate,
    tips: &[Hash],
    target: Hash,
    budget: &mut Budget,
) -> Result<Reach, Miss> {
    let mut seen = BTreeSet::new();
    let mut nodes: VecDeque<Hash> = VecDeque::new();
    let mut work: VecDeque<(Hash, Kind)> = VecDeque::new();
    for tip in tips {
        if *tip == target {
            return Ok(Reach::Reachable);
        }
        if seen.insert(*tip) {
            nodes.push_back(*tip);
        }
    }
    let mut decided = 0_usize;
    loop {
        // Tip trees and everything below them first, then history.
        let mut batch: Vec<(Hash, Kind)> = Vec::new();
        if work.is_empty() {
            while batch.len() < BATCH {
                let Some(id) = nodes.pop_front() else { break };
                batch.push((id, Kind::Node));
            }
        } else {
            while batch.len() < BATCH {
                let Some(item) = work.pop_front() else { break };
                batch.push(item);
            }
        }
        if batch.is_empty() {
            return Ok(Reach::Unreachable);
        }
        decided += batch.len();
        if decided > env.cfg.max_walk_objects {
            return Ok(Reach::Capped);
        }
        let ids: Vec<Hash> = batch.iter().map(|(id, _)| *id).collect();
        let kinds: BTreeMap<Hash, Kind> = batch.into_iter().collect();
        for (id, located) in resolve::locate_many(env, &ids).await? {
            if takedown.stops_descent(env.repo, &id) {
                continue;
            }
            let kind = kinds[&id];
            if kind == Kind::File && !manifest_sized(located.value.decoded_size) {
                continue;
            }
            let bytes = match resolve::load(env, id, located, budget).await {
                Ok(bytes) => bytes,
                Err(Miss::Capped) => return Ok(Reach::Capped),
                Err(other) => return Err(other),
            };
            let Ok(object) = mkit_core::serialize::deserialize(&bytes) else {
                tracing::warn!("member object failed to decode during a reachability walk");
                return Err(Miss::Unavailable);
            };
            let found = expand(&object, target, &mut seen, &mut nodes, &mut work);
            if found {
                return Ok(Reach::Reachable);
            }
        }
    }
}
