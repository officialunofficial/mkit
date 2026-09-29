//! Splitting an oversized ticketed push along first-parent history (WP-1.17b,
//! R-164).
//!
//! A Connect advance may consume at most seven tickets, one of them for the
//! packmap node, so a push whose new data needs more than six packs cannot land
//! in one advance. This module chooses intermediate first-parent commits
//! ("cuts") so that each advance carries a closure that fits, and the caller
//! (`push_branch_steps`) publishes them one after another.
//!
//! The cuts are a pure function of (store, tip, remote head, limits): a
//! resumed push recomputes them from the new remote head and regenerates
//! identical packs for the interrupted step.
//!
//! * [`walk_chain`] walks the tip's first parents back to the first commit the
//!   remote already holds.
//! * [`cumulative_weights`] makes one forward pass that sizes what each chain
//!   commit adds, in serialized bytes (raw size plus one frame per object).
//! * [`select_steps`] cuts the chain: a guaranteed floor of `3 * cap` per step
//!   (under next-fit any two consecutive packs together exceed the cap, so
//!   three caps of weight never need more than six packs), extended greedily to
//!   the furthest commit whose real plan still fits, found by binary search.
//!   A single commit heavier than the floor is verified with the real plan and,
//!   if its estimate is over budget, an exact local dry seal.

use std::collections::HashSet;

use mkit_core::hash::{Hash, to_hex};
use mkit_core::object::{Object, ObjectType};
use mkit_core::ops::graph::{ClosureMode, MAX_REACHABLE, children, reachable_closure_checked};
use mkit_core::ops::merge::is_ancestor;
use mkit_core::pack;
use mkit_core::protocol::UploadLimits;
use mkit_core::refs::RefWriteCondition;
use mkit_core::store::{ObjectStore, StoreError};
use mkit_core::transfer::{self, PackPlan};

use super::{
    DispatchError, PackSink, build_and_upload_packs, effective_payload_cap,
    encode_delta_candidates_batch, estimate_pack_sizes,
};

/// Most advances one push may be split into (B2).
pub const MAX_SPLIT_STEPS: usize = 1_000;

/// Most first-parent commits the chain walk visits before it gives up.
pub const MAX_CHAIN_COMMITS: usize = 1_000_000;

/// Grants a caller can check for every advance of a split push before
/// anything is uploaded (B5).
pub trait StepAuthority: Send + Sync {
    /// Refuse the push unless the caller may perform the first advance under
    /// `first` and, when `later_steps` is set, every following advance, each
    /// of which is a `Match` on the previous step's commit.
    ///
    /// # Errors
    /// The reason authority is missing, phrased for the user.
    fn authorize(
        &self,
        branch: &str,
        first: RefWriteCondition,
        later_steps: bool,
    ) -> Result<(), String>;
}

/// The knobs and hooks of one branch push. The default is the production one.
pub struct PushControl<'a> {
    /// Checked before the first upload of a split push. `None` skips it.
    pub authority: Option<&'a dyn StepAuthority>,
    /// Refuse a split into more advances than this.
    pub max_steps: usize,
    /// Refuse a first-parent walk longer than this.
    pub max_chain: usize,
    /// Commits whose parents are not part of this repository (the shallow
    /// boundary): the chain walk stops at them.
    pub shallow: HashSet<Hash>,
}

impl std::fmt::Debug for PushControl<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushControl")
            .field("checks_grants", &self.authority.is_some())
            .field("max_steps", &self.max_steps)
            .field("max_chain", &self.max_chain)
            .field("shallow", &self.shallow.len())
            .finish()
    }
}

impl Default for PushControl<'_> {
    fn default() -> Self {
        Self {
            authority: None,
            max_steps: MAX_SPLIT_STEPS,
            max_chain: MAX_CHAIN_COMMITS,
            shallow: HashSet::new(),
        }
    }
}

/// Data packs one advance may carry: the ticket allowance minus the packmap
/// node's ticket (R-142). Six unless the transport advertises less.
pub(super) fn data_pack_budget(limits: UploadLimits) -> usize {
    limits
        .tickets_per_advance
        .map_or(6, |tickets| tickets.min(7).saturating_sub(1))
}

/// The first-parent commits between the remote's history and the tip.
struct Chain {
    /// Oldest first; the last is the tip.
    commits: Vec<Hash>,
    /// Objects the remote already holds among the chain's ancestors: the
    /// closure of the newest chain ancestor the remote has (none for a new
    /// branch, or one with no shared history).
    seed: HashSet<Hash>,
}

fn first_parent(obj: &Object) -> Option<Hash> {
    match obj {
        Object::Commit(c) => c.parents.first().copied(),
        Object::Remix(r) => r.parents.first().copied(),
        _ => None,
    }
}

/// The closure of `root`, or nothing when the store lacks part of it (the
/// same degradation as `plan_pack_with`). A closure too large to enumerate
/// is refused: a truncated one would send the walk past commits the remote
/// holds and rewind its branch.
fn held_closure(store: &ObjectStore, root: Option<Hash>) -> Result<HashSet<Hash>, DispatchError> {
    let Some(root) = root.filter(|root| store.contains(root)) else {
        return Ok(HashSet::new());
    };
    match reachable_closure_checked(store, [&root]) {
        Ok((set, false)) => Ok(set.into_iter().collect()),
        Ok((_, true)) => Err(too_large_to_split()),
        Err(StoreError::ObjectNotFound(_)) => Ok(HashSet::new()),
        Err(e) => Err(e.into()),
    }
}

fn too_large_to_split() -> DispatchError {
    DispatchError::PushSplitLimit(format!(
        "the history is too large to split ({MAX_REACHABLE} objects or more); no advance of this branch was published"
    ))
}

/// Walk `tip`'s first parents down to the first commit `remote_tip`'s closure
/// contains. Never enters a second-parent side: a merge is one chain commit.
fn walk_chain(
    store: &ObjectStore,
    tip: Hash,
    remote_tip: Option<Hash>,
    ctl: &PushControl<'_>,
) -> Result<Chain, DispatchError> {
    let held = held_closure(store, remote_tip)?;
    let mut commits = Vec::new();
    let mut base = None;
    let mut cursor = tip;
    loop {
        if held.contains(&cursor) {
            base = Some(cursor);
            break;
        }
        if commits.len() >= ctl.max_chain {
            return Err(DispatchError::PushSplitLimit(format!(
                "the first-parent history between the remote and the local tip is longer than {} commits, too long to split; no advance of this branch was published",
                ctl.max_chain
            )));
        }
        if crate::signal::is_shutdown() {
            return Err(DispatchError::Interrupted);
        }
        commits.push(cursor);
        if ctl.shallow.contains(&cursor) {
            break;
        }
        match first_parent(&store.read_object(&cursor)?) {
            Some(parent) => cursor = parent,
            None => break,
        }
    }
    commits.reverse();
    let seed = match base {
        Some(base) if Some(base) == remote_tip => held,
        base => held_closure(store, base)?,
    };
    Ok(Chain { commits, seed })
}

/// Serialized bytes each chain prefix adds: `weights[j]` is what the first `j`
/// chain commits contribute beyond `chain.seed`. One pass, each object visited
/// once; a walk from a chain commit stops at anything already seen, since a
/// closure is closed under its children.
fn cumulative_weights(
    store: &ObjectStore,
    chain: &Chain,
    ctl: &PushControl<'_>,
) -> Result<Vec<u64>, DispatchError> {
    let mut seen = chain.seed.clone();
    let mut cumulative = Vec::with_capacity(chain.commits.len() + 1);
    let mut total = 0_u64;
    cumulative.push(0);
    for commit in &chain.commits {
        if crate::signal::is_shutdown() {
            return Err(DispatchError::Interrupted);
        }
        let mut stack = vec![*commit];
        while let Some(hash) = stack.pop() {
            if !seen.insert(hash) {
                continue;
            }
            if seen.len() > MAX_REACHABLE {
                return Err(too_large_to_split());
            }
            total = total
                .saturating_add(store.object_metadata(&hash)?.len())
                .saturating_add(pack::ENTRY_FRAME_LEN as u64);
            if matches!(
                store.object_type(&hash)?,
                ObjectType::Blob | ObjectType::Delta
            ) {
                continue;
            }
            // A shallow-boundary commit's parents are not in this repository.
            let mode = if ctl.shallow.contains(&hash) {
                ClosureMode::Snapshot
            } else {
                ClosureMode::History
            };
            stack.extend(children(&store.read_object(&hash)?, mode));
        }
        cumulative.push(total);
    }
    Ok(cumulative)
}

/// The largest total weight (payload plus frames) after which a pack must
/// seal: either the payload cap, or the serialized limit net of header and
/// trailer. Two consecutive packs always weigh more than this together.
fn pack_weight_cap(payload_cap: u64, max_pack_bytes: Option<u64>) -> u64 {
    let serialized = max_pack_bytes.map_or(u64::MAX, |limit| {
        limit.saturating_sub((pack::HEADER_LEN + pack::TRAILER_LEN) as u64)
    });
    payload_cap.min(serialized).max(1)
}

struct Cutter<'a> {
    store: &'a ObjectStore,
    chain: &'a Chain,
    weights: &'a [u64],
    remote_tip: Option<Hash>,
    limits: UploadLimits,
    cap: u64,
    budget: usize,
    /// Chain positions the first advance must reach (0: no constraint).
    must_reach: usize,
}

impl Cutter<'_> {
    /// The real plan for advancing from chain position `from` to `to`, with
    /// its estimated pack count. `from == 0` diffs against the remote head.
    fn probe(&self, from: usize, to: usize) -> Result<(PackPlan, usize), DispatchError> {
        if crate::signal::is_shutdown() {
            return Err(DispatchError::Interrupted);
        }
        let base = match from {
            0 => self.remote_tip,
            from => Some(self.chain.commits[from - 1]),
        };
        let plan = transfer::plan_pack_with(
            self.store,
            self.chain.commits[to - 1],
            base,
            encode_delta_candidates_batch,
        )?;
        let packs =
            estimate_pack_sizes(self.store, &plan, self.cap, self.limits.max_pack_bytes)?.len();
        Ok((plan, packs))
    }

    /// The furthest position after `from` whose cumulative weight stays within
    /// `limit`, at least `from + 1`.
    fn furthest(&self, from: usize, limit: u64) -> usize {
        let bound = self.weights[from].saturating_add(limit);
        let count = self.weights.partition_point(|&weight| weight <= bound);
        count
            .saturating_sub(1)
            .max(from + 1)
            .min(self.weights.len() - 1)
    }

    /// The end position of the step that starts at `from`.
    fn cut(&self, from: usize) -> Result<usize, DispatchError> {
        let wcap = pack_weight_cap(self.cap, self.limits.max_pack_bytes);
        // Two consecutive packs weigh more than one cap, so `budget / 2` caps
        // of weight never need more than `budget` packs.
        let floor_weight = wcap.saturating_mul((self.budget / 2) as u64);
        let natural = self.furthest(from, floor_weight);
        // The first advance must already contain the remote head, or the
        // published branch would leave commits the remote holds (a merge of
        // the remote head reaches it through a second parent).
        let floor = if from == 0 {
            natural.max(self.must_reach)
        } else {
            natural
        };
        let ceiling = self
            .furthest(from, wcap.saturating_mul(self.budget as u64))
            .max(floor);
        let (mut fits, mut over) = (floor, ceiling);
        while fits < over {
            let mid = fits + (over - fits).div_ceil(2);
            if self.probe(from, mid)?.1 <= self.budget {
                fits = mid;
            } else {
                over = mid - 1;
            }
        }
        // Within the natural floor a step always fits; anything past it that
        // was forced (a lone heavy commit, or reaching the remote head) has
        // not been verified yet.
        let heavy = self.weights[fits] - self.weights[from] > floor_weight;
        if fits == floor && heavy {
            self.verify_forced(from, fits, from == 0 && floor > natural)?;
        }
        Ok(fits)
    }

    /// A step that cannot be split further must fit in the budget once
    /// compressed: run the exact seal without uploading.
    /// `holds_remote_head`: the step was forced to reach the remote head, which
    /// the refusal then says.
    fn verify_forced(
        &self,
        from: usize,
        to: usize,
        holds_remote_head: bool,
    ) -> Result<(), DispatchError> {
        let (plan, packs) = self.probe(from, to)?;
        if packs <= self.budget {
            return Ok(());
        }
        build_and_upload_packs(PackSink::Count, self.store, plan, self.cap, self.limits)
            .map(drop)
            .map_err(|error| match error {
                DispatchError::PushTooLarge { packs, limit, .. } => DispatchError::PushTooLarge {
                    packs,
                    limit,
                    commit: Some(self.describe(self.chain.commits[to - 1])),
                    holds_remote_head,
                },
                other => other,
            })
    }

    fn describe(&self, commit: Hash) -> String {
        match self.store.read_object(&commit) {
            Ok(Object::Commit(c)) if c.parents.len() > 1 => format!(
                "merge commit {} (second parent {})",
                to_hex(&commit),
                to_hex(&c.parents[1])
            ),
            _ => format!("commit {}", to_hex(&commit)),
        }
    }
}

/// The fewest chain commits after which the branch descends from the remote
/// head, or 0 when the remote head is not an ancestor of the tip (a forced
/// overwrite, which has nothing to preserve). Descent is monotonic along the
/// chain, so a binary search finds it.
fn positions_to_reach(
    store: &ObjectStore,
    chain: &Chain,
    remote_tip: Option<Hash>,
) -> Result<usize, DispatchError> {
    let Some(remote) = remote_tip.filter(|remote| store.contains(remote)) else {
        return Ok(0);
    };
    let (mut low, mut high) = (1, chain.commits.len());
    if !is_ancestor(store, remote, chain.commits[high - 1])? {
        return Ok(0);
    }
    while low < high {
        let mid = low + (high - low) / 2;
        if is_ancestor(store, remote, chain.commits[mid - 1])? {
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    Ok(low)
}

/// The commits to advance the remote head through, oldest first, ending at
/// `tip`. One entry means the push is not split.
///
/// Refuses, before anything is uploaded, a push that would need more than
/// `ctl.max_steps` advances, one whose grants do not cover every advance, and
/// one containing a single commit that cannot fit in an advance.
///
/// # Errors
/// [`DispatchError::PushSplitLimit`], [`DispatchError::PushNotAuthorized`],
/// [`DispatchError::PushTooLarge`], or a store or planning failure.
#[allow(clippy::too_many_arguments)]
pub fn plan_push_steps(
    store: &ObjectStore,
    tip: Hash,
    remote_tip: Option<Hash>,
    limits: UploadLimits,
    pack_payload_cap: u64,
    ctl: &PushControl<'_>,
    condition: RefWriteCondition,
    branch: &str,
) -> Result<Vec<Hash>, DispatchError> {
    let cap = effective_payload_cap(pack_payload_cap, limits.max_pack_bytes)?;
    let chain = walk_chain(store, tip, remote_tip, ctl)?;
    if chain.commits.is_empty() {
        return Ok(vec![tip]);
    }
    if let Some(authority) = ctl.authority {
        authority
            .authorize(branch, condition, chain.commits.len() > 1)
            .map_err(DispatchError::PushNotAuthorized)?;
    }
    let weights = cumulative_weights(store, &chain, ctl)?;
    let cutter = Cutter {
        store,
        chain: &chain,
        weights: &weights,
        remote_tip,
        limits,
        cap,
        budget: data_pack_budget(limits),
        must_reach: positions_to_reach(store, &chain, remote_tip)?,
    };
    let mut steps = Vec::new();
    let mut from = 0;
    while from < chain.commits.len() {
        if steps.len() >= ctl.max_steps {
            return Err(DispatchError::PushSplitLimit(format!(
                "this push would need more than {} advances; no advance of this branch was published. Ask the operator to raise max_pack_bytes, or push an ancestor commit first",
                ctl.max_steps
            )));
        }
        from = cutter.cut(from)?;
        steps.push(chain.commits[from - 1]);
    }
    Ok(steps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_core::layout::RepoLayout;
    use mkit_core::object::{Blob, Commit, EntryMode, Identity, Tree, TreeEntry};
    use mkit_core::ops::graph::reachable_objects;
    use mkit_core::serialize;
    use proptest::prelude::*;
    use tempfile::TempDir;

    fn store() -> (TempDir, ObjectStore) {
        let dir = TempDir::new().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
        (dir, store)
    }

    fn put(store: &ObjectStore, obj: &Object) -> Hash {
        store.write(&serialize::serialize(obj).unwrap()).unwrap()
    }

    /// Deterministic bytes: incompressible, or one repeated byte.
    fn bytes(seed: u64, len: usize, compressible: bool) -> Vec<u8> {
        if compressible {
            return vec![seed.to_le_bytes()[0]; len];
        }
        let mut out = vec![0; len];
        let mut state = seed | 1;
        for chunk in out.chunks_mut(8) {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
        }
        out
    }

    /// A commit whose tree holds every blob in `files`.
    fn commit(store: &ObjectStore, files: &[Hash], parents: Vec<Hash>, seed: u8) -> Hash {
        let mut entries: Vec<TreeEntry> = files
            .iter()
            .enumerate()
            .map(|(i, hash)| TreeEntry {
                name: format!("f{i:04}").into_bytes(),
                mode: EntryMode::Blob,
                object_hash: *hash,
            })
            .collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let tree = put(store, &Object::Tree(Tree { entries }));
        put(
            store,
            &Object::Commit(Commit::new_unannotated(
                tree,
                parents,
                Identity::ed25519([7; 32]),
                [0; 32],
                vec![seed],
                u64::from(seed),
                [0; 64],
            )),
        )
    }

    fn blob(store: &ObjectStore, seed: u64, len: usize) -> Hash {
        put(
            store,
            &Object::Blob(Blob {
                data: bytes(seed, len, false),
            }),
        )
    }

    /// A linear history of `n` commits, each adding one 100-byte file.
    fn line(store: &ObjectStore, n: u8) -> Vec<Hash> {
        let mut files = Vec::new();
        let mut commits: Vec<Hash> = Vec::new();
        for i in 0..n {
            files.push(blob(store, u64::from(i) + 1, 100));
            let parents = commits.last().copied().into_iter().collect();
            commits.push(commit(store, &files, parents, i));
        }
        commits
    }

    #[test]
    fn the_walk_stops_at_the_commit_the_remote_holds() {
        let (_dir, store) = store();
        let c = line(&store, 6);
        let chain = walk_chain(&store, c[5], Some(c[2]), &PushControl::default()).unwrap();
        assert_eq!(chain.commits, [c[3], c[4], c[5]]);
        assert_eq!(chain.seed, held_closure(&store, Some(c[2])).unwrap());

        // A new branch walks to the root.
        let chain = walk_chain(&store, c[5], None, &PushControl::default()).unwrap();
        assert_eq!(chain.commits, c);
        assert!(chain.seed.is_empty());
    }

    #[test]
    fn a_diverged_remote_seeds_the_shared_ancestor_not_its_own_tip() {
        let (_dir, store) = store();
        let c = line(&store, 6);
        let other = blob(&store, 900, 100);
        let theirs = commit(&store, &[other], vec![c[1]], 90);
        let chain = walk_chain(&store, c[5], Some(theirs), &PushControl::default()).unwrap();
        assert_eq!(chain.commits, [c[2], c[3], c[4], c[5]]);
        assert_eq!(chain.seed, held_closure(&store, Some(c[1])).unwrap());
    }

    #[test]
    fn the_walk_never_enters_a_second_parent_side() {
        let (_dir, store) = store();
        let c = line(&store, 4);
        let side_file = blob(&store, 500, 100);
        let side = commit(&store, &[side_file], vec![c[0]], 50);
        let merge = commit(&store, &[side_file], vec![c[3], side], 60);
        let chain = walk_chain(&store, merge, None, &PushControl::default()).unwrap();
        assert_eq!(chain.commits, [c[0], c[1], c[2], c[3], merge]);
        // The side branch's objects are weighed with the merge that brings them.
        let weights = cumulative_weights(&store, &chain, &PushControl::default()).unwrap();
        let brought = weights[5] - weights[4];
        let lone = weights[4] - weights[3];
        assert!(brought > lone, "{weights:?}");
    }

    #[test]
    fn a_shallow_boundary_ends_the_walk_and_its_parents_are_not_followed() {
        let (_dir, store) = store();
        let c = line(&store, 6);
        let control = PushControl {
            shallow: std::iter::once(c[3]).collect(),
            ..PushControl::default()
        };
        let chain = walk_chain(&store, c[5], None, &control).unwrap();
        assert_eq!(chain.commits, [c[3], c[4], c[5]]);
        // The boundary commit weighs its own tree closure only.
        let weights = cumulative_weights(&store, &chain, &control).unwrap();
        let everything = cumulative_weights(&store, &chain, &PushControl::default()).unwrap();
        assert!(weights[1] < everything[1]);
    }

    #[test]
    fn a_too_long_walk_is_refused() {
        let (_dir, store) = store();
        let c = line(&store, 6);
        let control = PushControl {
            max_chain: 4,
            ..PushControl::default()
        };
        let error = walk_chain(&store, c[5], None, &control).err().unwrap();
        assert!(
            matches!(error, DispatchError::PushSplitLimit(_)),
            "{error:?}"
        );
    }

    #[test]
    fn cumulative_weights_add_up_to_the_new_objects() {
        let (_dir, store) = store();
        let c = line(&store, 6);
        let chain = walk_chain(&store, c[5], Some(c[1]), &PushControl::default()).unwrap();
        let weights = cumulative_weights(&store, &chain, &PushControl::default()).unwrap();
        assert_eq!(weights.len(), chain.commits.len() + 1);
        assert!(weights.windows(2).all(|w| w[0] < w[1]));
        let held = reachable_objects(&store, &c[1]).unwrap();
        let expected: u64 = reachable_objects(&store, &c[5])
            .unwrap()
            .difference(&held)
            .map(|h| store.object_metadata(h).unwrap().len() + pack::ENTRY_FRAME_LEN as u64)
            .sum();
        assert_eq!(*weights.last().unwrap(), expected);
    }

    /// The refusal of a lone commit that only fits by containing the remote
    /// head carries the rebase-or-merge-earlier advice.
    #[test]
    fn a_step_forced_to_reach_the_remote_head_says_how_to_avoid_it() {
        let (_dir, store) = store();
        let a = line(&store, 4);
        let their_file = blob(&store, 900, 100);
        let theirs = commit(&store, &[their_file], Vec::new(), 90);
        let big: Vec<Hash> = (0..20).map(|i| blob(&store, 300 + i, 2048)).collect();
        let merge = commit(&store, &big, vec![a[3], theirs], 91);
        let limits = UploadLimits {
            max_pack_bytes: Some(8192),
            tickets_per_advance: Some(7),
            ticket_threshold_bytes: Some(0),
        };
        let error = plan_push_steps(
            &store,
            merge,
            Some(theirs),
            limits,
            4096,
            &PushControl::default(),
            RefWriteCondition::Match(theirs),
            "main",
        )
        .unwrap_err();
        assert!(
            matches!(
                &error,
                DispatchError::PushTooLarge {
                    holds_remote_head: true,
                    ..
                }
            ),
            "{error:?}"
        );
        assert!(
            error.to_string().contains("rebase onto the remote head"),
            "{error}"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// The real sealed pack count never exceeds the conservative estimate,
        /// and a push whose weight is within three pack caps always fits the
        /// budget: the two facts the cut selection rests on. Entries stay below
        /// the server's pack limit, and half the cases send deltas against a
        /// base the remote holds.
        #[test]
        fn estimate_bounds_the_real_pack_count_and_three_caps_always_fit(
            sizes in prop::collection::vec((16_usize..1500, any::<bool>()), 1..12),
            payload_cap in 512_u64..16_384,
            max_pack in prop::option::of(2048_u64..12_000),
            with_deltas in any::<bool>(),
        ) {
            let (_dir, store) = store();
            let files: Vec<Hash> = sizes
                .iter()
                .enumerate()
                .map(|(i, (len, compressible))| {
                    put(&store, &Object::Blob(Blob { data: bytes(i as u64 + 1, *len, *compressible) }))
                })
                .collect();
            let (tip, base, seed) = if with_deltas {
                // The tip edits every file a little, so each is sent as a delta.
                let base = commit(&store, &files, Vec::new(), 1);
                let edited: Vec<Hash> = sizes
                    .iter()
                    .enumerate()
                    .map(|(i, (len, compressible))| {
                        let mut data = bytes(i as u64 + 1, *len, *compressible);
                        let middle = data.len() / 2;
                        data[middle] ^= 0xff;
                        put(&store, &Object::Blob(Blob { data }))
                    })
                    .collect();
                let tip = commit(&store, &edited, vec![base], 2);
                (tip, Some(base), held_closure(&store, Some(base)).unwrap())
            } else {
                (commit(&store, &files, Vec::new(), 1), None, HashSet::new())
            };
            let plan = if with_deltas {
                transfer::plan_pack_with(&store, tip, base, encode_delta_candidates_batch).unwrap()
            } else {
                transfer::plan_pack_with(&store, tip, None, |_, candidates| {
                    Ok(vec![None; candidates.len()])
                })
                .unwrap()
            };
            // No ticket gate: count every pack the seal produces.
            let limits = UploadLimits {
                max_pack_bytes: max_pack,
                tickets_per_advance: None,
                ticket_threshold_bytes: None,
            };
            let cap = effective_payload_cap(payload_cap, max_pack).unwrap();
            let estimate = estimate_pack_sizes(&store, &plan, cap, max_pack).unwrap().len();
            let keys = build_and_upload_packs(PackSink::Count, &store, plan, cap, limits)
                .map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
            prop_assert!(keys.len() <= estimate, "{} > {estimate}", keys.len());
            let chain = Chain { commits: vec![tip], seed };
            let weight = *cumulative_weights(&store, &chain, &PushControl::default())
                .unwrap()
                .last()
                .unwrap();
            if weight <= 3 * pack_weight_cap(cap, max_pack) {
                prop_assert!(estimate <= 6, "{estimate} packs for weight {weight}");
            }
        }
    }
}
