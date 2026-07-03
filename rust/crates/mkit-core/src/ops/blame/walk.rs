//! Merge-aware blame walk: build the file's ancestor subgraph, order it
//! topologically (parents before children), and resolve each commit's line
//! attributions from its parents' already-resolved ones. `super::blame_file_with`
//! drives this; the single-parent path reproduces the old linear replay.

use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use super::{
    Attribution, BlameError, BlameOptions, BlameOutcome, CopyDetection, find_blob_in_tree,
    ignore_fallthrough, is_trivial_key, line_key, load_blob_lines, match_lines_with_options,
    move_copy,
};
use crate::hash::Hash;
use crate::object::{Identity, Object};
use crate::store::ObjectStore;

/// A commit in the file's ancestor subgraph: the blob the path resolves to
/// there, the author/timestamp for the output, and the **relevant** parents
/// — the parents that still contain the file. Following all parents makes
/// blame merge-aware; with `--first-parent` only the first parent is kept,
/// so every node has at most one relevant parent and the walk degenerates to
/// the old linear first-parent replay.
pub(super) struct DagNode {
    pub(super) blob_hash: Hash,
    author: Identity,
    timestamp: u64,
    pub(super) parents: Vec<Hash>,
}

impl DagNode {
    /// This commit as the origin for one of its own lines.
    fn own_attribution(&self, commit_hash: Hash) -> Attribution {
        Attribution {
            commit_hash,
            author: self.author.clone(),
            timestamp: self.timestamp,
        }
    }
}

/// The file's blob at `commit` (cached). Reads the commit only when the
/// blob is not already known, so a parent probed for relevance and later
/// processed costs one tree walk, not two.
fn file_blob_at(
    store: &ObjectStore,
    blob_of: &mut HashMap<Hash, Option<Hash>>,
    commit: Hash,
    file_path: &str,
) -> BlameOutcome<Option<Hash>> {
    if let Some(&blob) = blob_of.get(&commit) {
        return Ok(blob);
    }
    let Object::Commit(c) = store.read_object(&commit)? else {
        return Err(BlameError::NotACommit);
    };
    let blob = find_blob_in_tree(store, c.tree_hash, file_path)?;
    blob_of.insert(commit, blob);
    Ok(blob)
}

/// Build the file's ancestor subgraph from `head_hash`: every commit at which
/// `file_path` resolves to a blob, reachable through parents that also still
/// contain the file. All parents are followed (merge-aware) unless
/// `first_parent`. Returns the node map and, for each commit, its number of
/// subgraph children, so the caller can release a node's attribution memo
/// once all of its children have been processed.
///
/// The child→parent edges recorded here — including the non-first-parent
/// edges of a merge — are exactly the merge-DAG edges the blame walk visits;
/// a future provable-blame ancestry accumulator (#495) can be built from this
/// same traversal instead of a second ancestor-set pass. They are not
/// surfaced as public API, since #458 has no consumer for them yet.
pub(super) fn build_file_dag(
    store: &ObjectStore,
    head_hash: Hash,
    file_path: &str,
    first_parent: bool,
) -> BlameOutcome<(HashMap<Hash, DagNode>, HashMap<Hash, usize>)> {
    let mut nodes: HashMap<Hash, DagNode> = HashMap::new();
    let mut children: HashMap<Hash, usize> = HashMap::new();
    let mut blob_of: HashMap<Hash, Option<Hash>> = HashMap::new();

    let mut stack = vec![head_hash];
    while let Some(commit_hash) = stack.pop() {
        if nodes.contains_key(&commit_hash) {
            continue;
        }
        let Object::Commit(commit) = store.read_object(&commit_hash)? else {
            return Err(BlameError::NotACommit);
        };
        let Some(blob_hash) = find_blob_in_tree(store, commit.tree_hash, file_path)? else {
            // Reachable only for `head_hash` (parents are probed before being
            // pushed); the caller has already rejected a fileless head.
            continue;
        };
        blob_of.entry(commit_hash).or_insert(Some(blob_hash));
        let raw_parents: &[Hash] = if first_parent {
            commit.parents.get(..1).unwrap_or(&[])
        } else {
            &commit.parents
        };
        let mut relevant = Vec::new();
        for &parent in raw_parents {
            if file_blob_at(store, &mut blob_of, parent, file_path)?.is_some() {
                relevant.push(parent);
                *children.entry(parent).or_insert(0) += 1;
                if !nodes.contains_key(&parent) {
                    stack.push(parent);
                }
            }
        }
        nodes.insert(
            commit_hash,
            DagNode {
                blob_hash,
                author: commit.author.clone(),
                timestamp: commit.timestamp,
                parents: relevant,
            },
        );
    }
    Ok((nodes, children))
}

/// Topologically order `nodes` so every commit appears after all of its
/// relevant parents (DFS post-order from `head`). Parents-before-children
/// lets the forward replay read a parent's resolved attribution before the
/// child needs it.
pub(super) fn topo_order(nodes: &HashMap<Hash, DagNode>, head: Hash) -> Vec<Hash> {
    let mut order = Vec::with_capacity(nodes.len());
    let mut visited: HashSet<Hash> = HashSet::new();
    let mut stack: Vec<(Hash, bool)> = vec![(head, false)];
    while let Some((commit, emit)) = stack.pop() {
        if emit {
            order.push(commit);
            continue;
        }
        if !visited.insert(commit) {
            continue;
        }
        stack.push((commit, true));
        for &parent in &nodes[&commit].parents {
            if !visited.contains(&parent) {
                stack.push((parent, false));
            }
        }
    }
    order
}

/// A relevant parent's loaded lines and its line mapping (`mapping[ni]` = the
/// parent line child line `ni` is unchanged from, or `None`). Loaded once in
/// [`attribute_commit`] and reused by the fall-through / detector passes.
type ParentData<'a> = (Cow<'a, [Vec<u8>]>, Vec<Option<usize>>);

/// Read-mostly context threaded into [`attribute_commit`].
pub(super) struct WalkCtx<'a> {
    pub(super) store: &'a ObjectStore,
    pub(super) opts: &'a BlameOptions,
    pub(super) nodes: &'a HashMap<Hash, DagNode>,
    pub(super) file_path: &'a str,
}

/// The per-commit working set shared by the merge passes: the commit and its
/// node, the commit's own lines, and the first parent's lines (loaded once and
/// reused). Bundling these keeps the fall-through and detector helpers to a
/// handful of arguments instead of a positional pile-up.
struct CommitPass<'a> {
    node: &'a DagNode,
    commit: Hash,
    lines: &'a [Vec<u8>],
    first_parent_lines: &'a [Vec<u8>],
}

impl<'a> CommitPass<'a> {
    /// The `k`th parent's lines: the first parent is already loaded and simply
    /// borrowed; the rest (only reached at a merge) are loaded on demand. The
    /// `Cow` lets both cases share one binding without the borrow-or-own dance.
    fn parent_lines(
        &self,
        ctx: &WalkCtx,
        k: usize,
        parent: Hash,
    ) -> BlameOutcome<Cow<'a, [Vec<u8>]>> {
        Ok(if k == 0 {
            Cow::Borrowed(self.first_parent_lines)
        } else {
            Cow::Owned(load_blob_lines(ctx.store, ctx.nodes[&parent].blob_hash)?)
        })
    }
}

/// Resolve the attribution of every line of `commit`'s blob from its parents'
/// already-resolved attributions in `memo`.
///
/// With one relevant parent this is exactly the old single-parent step
/// (match → inherit, unmatched → this commit or `--ignore-rev` fall-through,
/// then the `-M`/`-C` detector). At a **merge**, each line is explained by
/// the first parent — in parent order — that still contains it (so a line on
/// both sides is credited to the first parent, matching git); lines no parent
/// explains are introduced here, then offered to ignore-rev fall-through
/// (against every relevant parent, first-parent-wins) and the `-M`/`-C`
/// detector against every REAL parent under porigin rules — see
/// [`apply_detection`].
pub(super) fn attribute_commit(
    ctx: &WalkCtx,
    memo: &HashMap<Hash, Rc<[Attribution]>>,
    detector: &mut move_copy::Detector,
    commit: Hash,
) -> BlameOutcome<Rc<[Attribution]>> {
    let node = &ctx.nodes[&commit];

    // Fast path: a single parent with the identical blob contributes every
    // line unchanged (the old `newer.blob == older.blob` skip). Checked
    // before loading the blob, so a passthrough commit reads nothing and just
    // refcount-bumps the parent memo — this matters on the merge-aware walk,
    // which visits every file-touching ancestor, not only first parents.
    if node.parents.len() == 1 && ctx.nodes[&node.parents[0]].blob_hash == node.blob_hash {
        return Ok(Rc::clone(&memo[&node.parents[0]]));
    }

    let lines = load_blob_lines(ctx.store, node.blob_hash)?;
    let own = node.own_attribution(commit);

    // Root/boundary: the file first appears here (no *relevant* parent still
    // has it), so every line is introduced — but a block may have been
    // copied from another file in a real parent (`-C`). The same
    // real-parent detection pass as the interior case applies; with no
    // porigin anywhere, `-C -C` searches every real parent's whole tree,
    // first included, in order, first-found-wins (pinned against git
    // 2.50.1 — see the `blame_c_merge_boundary_*` tests in `mod.rs`).
    if node.parents.is_empty() {
        let mut attrs = vec![own; lines.len()];
        if matches!(ctx.opts.copies, CopyDetection::On { .. }) {
            let pass = CommitPass {
                node,
                commit,
                lines: &lines,
                first_parent_lines: &[],
            };
            let mut claimed = vec![false; lines.len()];
            apply_detection(ctx, memo, detector, &pass, &[], &mut attrs, &mut claimed)?;
        }
        return Ok(attrs.into());
    }

    let first_parent = node.parents[0];
    let mut attrs = vec![own; lines.len()];
    let mut matched = vec![false; lines.len()];
    let first_parent_lines = load_blob_lines(ctx.store, ctx.nodes[&first_parent].blob_hash)?;
    let pass = CommitPass {
        node,
        commit,
        lines: &lines,
        first_parent_lines: &first_parent_lines,
    };

    // Load each relevant parent's lines and its line mapping exactly once,
    // here, and reuse them in the fall-through / detector passes below —
    // otherwise a merge under `--ignore-rev` (or `-M`/`-C`) would reload the
    // blob and rerun the diff per parent. `parents_data[k]` corresponds to
    // `node.parents[k]`; `mapping[ni]` = the parent line this commit's line
    // `ni` is unchanged from, or `None` if changed/introduced.
    let mut parents_data: Vec<ParentData> = Vec::with_capacity(node.parents.len());
    for (k, &parent) in node.parents.iter().enumerate() {
        let parent_lines = pass.parent_lines(ctx, k, parent)?;
        let mapping = match_lines_with_options(&parent_lines, &lines, ctx.opts)?;
        // Each line is explained by the first parent — in parent order — that
        // still contains it (a line on both sides sticks to the first parent).
        let parent_attrs = &memo[&parent];
        for (ni, m) in mapping.iter().enumerate() {
            if matched[ni] {
                continue; // already explained by an earlier parent
            }
            let Some(oi) = *m else { continue };
            if oi < parent_attrs.len() {
                attrs[ni] = parent_attrs[oi].clone();
                matched[ni] = true;
            }
        }
        parents_data.push((parent_lines, mapping));
    }

    if ctx.opts.is_ignored(&commit) {
        apply_ignore_fallthrough(ctx, memo, &pass, &parents_data, &mut attrs, &mut matched);
    }

    if ctx.opts.detection_enabled() {
        apply_detection(
            ctx,
            memo,
            detector,
            &pass,
            &parents_data,
            &mut attrs,
            &mut matched,
        )?;
    }

    Ok(attrs.into())
}

/// `--ignore-rev` fall-through across `node`'s parents (first-parent-wins).
///
/// A line this (ignored) commit would keep falls through to a parent's
/// corresponding line. At a merge the fall-through is offered to each parent
/// in turn: a line the first parent has a positional counterpart for is
/// credited there, but a line the first parent dropped (no counterpart in its
/// conflicted hunk) falls through across to the next parent that does pair it
/// — matching `git blame --ignore-rev` at a merge. A resolved line is marked
/// `matched` so the detector does not overwrite it (`--ignore-rev` takes
/// precedence over `-M`/`-C`). With one parent this is exactly the old
/// single-parent fall-through.
///
/// When [`BlameOptions::ignore_rev_precise`] is set, [`precise_overrides`]
/// refines each parent's positional `fall` result with content matching
/// before it is applied here — the credit loop below, the first-parent-wins
/// per-parent ordering, and the `matched` marking are all unchanged either
/// way.
fn apply_ignore_fallthrough(
    ctx: &WalkCtx,
    memo: &HashMap<Hash, Rc<[Attribution]>>,
    pass: &CommitPass,
    parents_data: &[ParentData],
    attrs: &mut [Attribution],
    matched: &mut [bool],
) {
    for (k, &parent) in pass.node.parents.iter().enumerate() {
        // Reuse the lines + mapping loaded once in `attribute_commit`.
        let (parent_lines, mapping) = &parents_data[k];
        let fall = ignore_fallthrough(mapping, parent_lines.len());
        let fall = if ctx.opts.ignore_rev_precise {
            precise_overrides(&PreciseRequest {
                mapping,
                fall: &fall,
                new_lines: pass.lines,
                parent_lines,
                matched,
                ignore_whitespace: ctx.opts.ignore_whitespace,
            })
        } else {
            fall
        };
        let parent_attrs = &memo[&parent];
        for (ni, &paired) in fall.iter().enumerate() {
            if matched[ni] {
                continue;
            }
            let Some(oi) = paired else { continue };
            if oi < parent_attrs.len() {
                attrs[ni] = parent_attrs[oi].clone();
                matched[ni] = true;
            }
        }
    }
}

/// `-M`/`-C` reassignment across the commit's **real** parents, in commit
/// order, first-found-wins — mirroring git 2.50.1's `pass_blame` move/copy
/// passes (`blame.c`).
///
/// Each real parent gets one `reassign` call. What that call may search is
/// keyed on the parent's **porigin** (its version of the blamed file):
///
/// * The parent has a porigin when it contains the file (it appears in the
///   filtered `node.parents`) AND no earlier real parent brought the
///   identical file blob — git dedups same-blob porigins, and the deduped
///   parent is treated as porigin-less from then on.
/// * With a porigin, `-M` searches the parent's file and `-C` candidates
///   are limited to files modified between that parent and this commit.
/// * Without one (parent lacks the file / deduped / boundary), `-M` is off
///   and `-C -C` widens to the parent's whole tree — so a parent that
///   deleted the file still surfaces its copy sources, and at a boundary
///   every real parent (first included) is searched.
///
/// Everything previously modeled as a first-parent carve-out or an
/// interior-vs-boundary tie-break falls out of these rules; the
/// `blame_c_merge_*` tests in `mod.rs` pin each shape against a real git
/// 2.50.1 run. `--first-parent` truncates the real parent list to one,
/// exactly like git's `first_scapegoat`. `matched` doubles as the
/// "already explained" mask threaded through `reassign`, so a line an
/// earlier parent claimed is never reassigned twice. With one real parent
/// that has the file this is exactly the old single pass, so the linear
/// path is unchanged.
fn apply_detection(
    ctx: &WalkCtx,
    memo: &HashMap<Hash, Rc<[Attribution]>>,
    detector: &mut move_copy::Detector,
    pass: &CommitPass,
    parents_data: &[ParentData],
    attrs: &mut [Attribution],
    matched: &mut [bool],
) -> BlameOutcome<()> {
    let mut real_parents = move_copy::commit_parents(ctx.store, pass.commit)?;
    if ctx.opts.first_parent {
        real_parents.truncate(1);
    }
    let copies_on = matches!(ctx.opts.copies, CopyDetection::On { .. });
    // File blobs already offered as a porigin; a later parent with an
    // identical blob is deduped to porigin-less (git parity).
    let mut seen_blobs: HashSet<Hash> = HashSet::new();
    for &parent in &real_parents {
        if matched.iter().all(|&m| m) {
            break; // every line explained — later parents have no work
        }
        // The parent's porigin: its index in the file-bearing (filtered)
        // parent list, unless its file blob was already offered by an
        // earlier parent (dedup).
        let porigin = match pass.node.parents.iter().position(|&p| p == parent) {
            Some(k) if seen_blobs.insert(ctx.nodes[&parent].blob_hash) => Some(k),
            _ => None,
        };
        // A porigin-less parent contributes nothing without `-C` (there is
        // no within-file `-M` source), and `reassign` would silently
        // no-op — skip the call outright.
        if porigin.is_none() && !copies_on {
            continue;
        }
        detector.reassign(
            &move_copy::ReassignRequest {
                file_path: ctx.file_path,
                source_commit: parent,
                attributed_commit: pass.commit,
                new_lines: pass.lines,
                within_file: porigin.map(|k| {
                    (
                        &*parents_data[k].0,
                        &*memo[&pass.node.parents[k]] as &[Attribution],
                    )
                }),
            },
            attrs,
            matched,
        )?;
    }
    Ok(())
}

/// Cap on how many content candidates a single new line's key may have
/// before that line is deemed too ambiguous to refine cheaply and simply
/// keeps its positional guess. Bounds the per-line fan-out, mirroring
/// [`move_copy::MAX_DETECT_RUN`]'s role as a per-step blow-up guard.
const PRECISE_MAX_CANDIDATES_PER_KEY: usize = 256;

/// Total forward-run comparison budget for one [`precise_overrides`] call.
/// Many identical ≥3-byte lines (generated/log-like files) make candidate
/// ranking degenerate toward `O(n³)`; once the cumulative run-extension work
/// crosses this bound the whole refinement is abandoned and the plain
/// positional `fall` is returned unchanged — a graceful fallback that can
/// never hang, the same "cap the blow-up rather than fail" stance as
/// [`super::BLAME_MAX_LINES`].
const PRECISE_MAX_RUN_WORK: usize = 1 << 22; // ~4.2M key comparisons

/// Inputs for [`precise_overrides`], bundled so the two adjacent
/// `&[Option<usize>]` (`mapping`, `fall`) and two adjacent `&[Vec<u8>]`
/// (`new_lines`, `parent_lines`) can't be silently transposed at the call
/// site — the same positional-argument hazard [`move_copy::ReassignRequest`]
/// bundles away.
pub(super) struct PreciseRequest<'r> {
    /// LCS mapping: `mapping[ni]` = the parent line this commit's line `ni`
    /// is unchanged from, or `None` (changed/introduced).
    pub(super) mapping: &'r [Option<usize>],
    /// git's positional [`ignore_fallthrough`] guess — the base this refines.
    pub(super) fall: &'r [Option<usize>],
    /// This commit's blob lines.
    pub(super) new_lines: &'r [Vec<u8>],
    /// The parent's blob lines.
    pub(super) parent_lines: &'r [Vec<u8>],
    /// Lines already explained by an earlier parent at a merge. Excluded
    /// from refinement so they neither reserve nor steal a content candidate
    /// a genuinely-unresolved line needs (their override would be discarded
    /// by the credit loop's `matched` check anyway).
    pub(super) matched: &'r [bool],
    /// `-w`: content keys are whitespace-stripped for matching.
    pub(super) ignore_whitespace: bool,
}

/// `--ignore-rev-precise` (#496): refine one parent's positional
/// [`ignore_fallthrough`] result (`fall`) with content matching, so a line
/// a reformat/reorder moved can be attributed to its true surviving origin
/// instead of whatever line happens to sit at the same offset in the hunk.
///
/// **Never worse than git's positional `--ignore-rev`, by construction.**
/// git's positional guess is the base; this only *overrides* a slot when
/// the content evidence is strong enough that the result cannot be worse:
///
/// * `fall[ni] == Some(j)` (positional already found a parent line): the
///   slot is re-pointed **only** by a genuine *moved block* — a run of ≥ 2
///   file-adjacent lines whose keys match the candidate contiguously. An
///   isolated single-line key coincidence never displaces a filled
///   positional guess: that is exactly how the old code could land an
///   edited line (`foo`→`bar`, whose positional predecessor `foo` is its
///   true history) onto an unrelated duplicate `bar` deleted elsewhere —
///   strictly worse than positional. Content that agrees with the guess, or
///   a trivial key, is likewise kept.
/// * `fall[ni] == None` (positional left the line on the ignored commit —
///   a genuine insertion): may be filled from a single exact-content match
///   anywhere in the parent's **whole file** (not just the enclosing hunk —
///   the point is finding lines a reformat moved across hunk boundaries).
///   Any exact origin only improves on "credited to the noise commit", so
///   even a single-line match is safe here.
/// * A trivial key ([`is_trivial_key`] — blank lines, `}`-only lines,
///   sub-3-byte tokens, measured whitespace-stripped even without `-w`) is
///   never content-reattributed, so trivial lines don't "teleport".
///
/// Resolution is three phases:
///
/// * **Pass 1** reserves, for every keeper (trivial key or content already
///   agrees with `fall[ni]`), its positional old index, so no override can
///   steal a line its positional owner is keeping.
/// * **Pass 2a** proposes at most one override per remaining line — its best
///   content candidate (longest file-contiguous run; ties toward the
///   positional guess, then lowest old index) — subject to the never-worse
///   rule above and the ambiguity/work caps
///   ([`PRECISE_MAX_CANDIDATES_PER_KEY`], [`PRECISE_MAX_RUN_WORK`]).
/// * **Pass 2b** applies proposals longest-run-first, so a genuine moved
///   block wins any old line a weaker single-line match also wanted; a
///   proposal that loses the contest keeps its positional target (still
///   ≥ positional). This global ranking replaces the old ascending-index
///   greedy claim, which let an early weak single-candidate match starve a
///   later longer-run block head.
///
/// Does not touch `ignore_fallthrough` itself or its shape: callers see the
/// same `Vec<Option<usize>>` domain (only unmatched new lines are ever
/// `Some`/reattributed), so the credit loop in [`apply_ignore_fallthrough`]
/// is unchanged either way.
///
/// `pub(super)`: exercised directly by `blame::tests` unit tests (mirroring
/// how `ignore_fallthrough_pairs_per_hunk` unit-tests `ignore_fallthrough`),
/// alongside the full `blame_file_with` integration tests.
/// One candidate override in [`precise_overrides`]' Pass 2: reattribute new
/// line `ni` to old line `real_old`, backed by a file-contiguous run of
/// `run_len` matching lines (the priority for contested-claim resolution).
struct Proposal {
    ni: usize,
    real_old: usize,
    run_len: usize,
}

pub(super) fn precise_overrides(req: &PreciseRequest) -> Vec<Option<usize>> {
    let &PreciseRequest {
        mapping,
        fall,
        new_lines,
        parent_lines,
        matched,
        ignore_whitespace: iw,
    } = req;

    // `fall` is only ever defined over the LCS-unmatched new lines (the
    // domain `ignore_fallthrough` pairs); further exclude lines an earlier
    // merge parent already explained (finding #3) — they must not compete
    // for candidates a still-unresolved line needs.
    let unmatched_new: Vec<usize> = (0..mapping.len())
        .filter(|&ni| mapping[ni].is_none() && !matched[ni])
        .collect();
    if unmatched_new.is_empty() {
        return fall.to_vec();
    }

    // The parent's unmatched-old lines, across the WHOLE file — a reformat
    // can move a line across hunk boundaries, which per-hunk pairing alone
    // can never see.
    let matched_old: HashSet<usize> = mapping.iter().filter_map(|&m| m).collect();
    let unmatched_old: Vec<usize> = (0..parent_lines.len())
        .filter(|oi| !matched_old.contains(oi))
        .collect();
    if unmatched_old.is_empty() {
        return fall.to_vec();
    }

    let old_keys: Vec<Vec<u8>> = unmatched_old
        .iter()
        .map(|&oi| line_key(&parent_lines[oi], iw))
        .collect();
    let old_index = move_copy::build_index(&old_keys);
    let new_keys: Vec<Vec<u8>> = unmatched_new
        .iter()
        .map(|&ni| line_key(&new_lines[ni], iw))
        .collect();

    // Pass 1: reserve each keeper's positional old index (trivial key, or
    // content already agrees) so no override elsewhere can steal it.
    let mut keeps: HashSet<usize> = HashSet::new(); // ni values that keep `fall[ni]` as-is
    let mut claimed: HashSet<usize> = HashSet::new(); // old indices reserved / taken
    for (pos, &ni) in unmatched_new.iter().enumerate() {
        let Some(j) = fall[ni] else { continue };
        let key = &new_keys[pos];
        if is_trivial_key(key) || *line_key(&parent_lines[j], iw) == **key {
            keeps.insert(ni);
            claimed.insert(j);
        }
    }

    // Pass 2a: propose one best override per non-keeper, enforcing the
    // never-worse rule (a filled `Some` guess is only re-pointed by a real
    // moved block, run ≥ 2).
    let mut proposals: Vec<Proposal> = Vec::new();
    let mut work = 0usize;
    for (pos, &ni) in unmatched_new.iter().enumerate() {
        let key = &new_keys[pos];
        if keeps.contains(&ni) || is_trivial_key(key) {
            continue; // kept as-is, or a trivial key that never teleports
        }
        let Some(offsets) = old_index.get(key) else {
            continue; // no content candidate anywhere in the parent
        };
        if offsets.len() > PRECISE_MAX_CANDIDATES_PER_KEY {
            continue; // too ambiguous to refine cheaply — keep positional
        }
        let Some((d, run_len)) = best_content_candidate(
            pos,
            offsets,
            &unmatched_new,
            &new_keys,
            &old_keys,
            &unmatched_old,
            fall[ni],
            &mut work,
        ) else {
            continue;
        };
        if work > PRECISE_MAX_RUN_WORK {
            return fall.to_vec(); // graceful global fallback — never hang
        }
        // Never-worse: only a genuine moved block (≥ 2 file-adjacent lines)
        // may displace a positional `Some`; a `None` guess (positional gave
        // nothing) may take even a single exact-content line.
        if fall[ni].is_some() && run_len < 2 {
            continue;
        }
        proposals.push(Proposal {
            ni,
            real_old: unmatched_old[d],
            run_len,
        });
    }

    // Pass 2b: apply longest-run-first so a real moved block wins a contested
    // old line; a loser simply keeps its positional target (still ≥ positional).
    proposals.sort_by(|a, b| b.run_len.cmp(&a.run_len).then(a.ni.cmp(&b.ni)));
    let mut out = fall.to_vec();
    for p in proposals {
        if claimed.insert(p.real_old) {
            out[p.ni] = Some(p.real_old);
        }
    }
    out
}

/// The best content candidate for the unmatched new line at dense `pos`:
/// the dense old offset (into `old_keys`/`unmatched_old`) with the longest
/// forward **file-contiguous** matching run, plus that run length. Returns
/// `None` only if `offsets` is empty.
///
/// The run extends while the new and old lines stay adjacent *in their
/// respective files* (consecutive `unmatched_new` / `unmatched_old` indices)
/// AND their keys match — so a run of length ≥ 2 is a genuine moved block,
/// not lines that merely share keys across LCS anchors. This is the
/// forward-extension *idea* of [`move_copy::longest_match`], but that helper
/// runs over file-contiguous lines directly; here the arrays are dense
/// (unmatched-only), so the file-adjacency check is added explicitly (the
/// old dense run overstated the parallel — a fragmented decoy could tie a
/// genuinely contiguous block; #523 finding #7).
///
/// Longer run wins; a length tie breaks toward git's positional guess
/// (`positional`), if any, then by lowest old-line index. `work` accumulates
/// the run-extension budget the caller bounds against
/// [`PRECISE_MAX_RUN_WORK`].
#[allow(clippy::too_many_arguments)]
fn best_content_candidate(
    pos: usize,
    offsets: &[usize],
    unmatched_new: &[usize],
    new_keys: &[Vec<u8>],
    old_keys: &[Vec<u8>],
    unmatched_old: &[usize],
    positional: Option<usize>,
    work: &mut usize,
) -> Option<(usize, usize)> {
    let mut run_len = |d: usize| -> usize {
        let mut k = 0usize;
        while pos + k < new_keys.len()
            && d + k < old_keys.len()
            && new_keys[pos + k] == old_keys[d + k]
            && (k == 0
                || (unmatched_new[pos + k] == unmatched_new[pos + k - 1] + 1
                    && unmatched_old[d + k] == unmatched_old[d + k - 1] + 1))
        {
            k += 1;
            *work += 1;
        }
        k
    };
    let mut best: Option<(usize, usize)> = None; // (dense old offset, run length)
    for &d in offsets {
        let len = run_len(d);
        let better = match best {
            None => true,
            Some((bd, bl)) => match len.cmp(&bl) {
                Ordering::Greater => true,
                Ordering::Less => false,
                Ordering::Equal => match positional {
                    Some(expected) => {
                        let cur = unmatched_old[d].abs_diff(expected);
                        let prev = unmatched_old[bd].abs_diff(expected);
                        cur < prev || (cur == prev && unmatched_old[d] < unmatched_old[bd])
                    }
                    None => unmatched_old[d] < unmatched_old[bd],
                },
            },
        };
        if better {
            best = Some((d, len));
        }
    }
    best
}
