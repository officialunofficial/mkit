//! Merge-aware blame walk: build the file's ancestor subgraph, order it
//! topologically (parents before children), and resolve each commit's line
//! attributions from its parents' already-resolved ones. `super::blame_file_with`
//! drives this; the single-parent path reproduces the old linear replay.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use super::{
    Attribution, BlameError, BlameOptions, BlameOutcome, CopyDetection, find_blob_in_tree,
    ignore_fallthrough, load_blob_lines, match_lines_with_options, move_copy,
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
/// explains are introduced here, then offered to ignore-rev fall-through and
/// the `-M`/`-C` detector against every relevant parent (first-parent-wins).
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
    // copied from another file in a real parent (`-C`). Unlike the interior
    // merge case in `apply_detection`, git's boundary `-C` search covers
    // EVERY real parent of this commit, INCLUDING the first, in order,
    // first-found-wins (pinned against git 2.50.1 — see the
    // `blame_c_merge_boundary_*` tests in `mod.rs`). `node.parents` cannot be
    // used here: it is filtered to parents that still contain the file, which
    // is exactly empty in this branch, so the real parent list is read
    // straight from the commit object via `commit_parents`.
    if node.parents.is_empty() {
        let mut attrs = vec![own; lines.len()];
        if matches!(ctx.opts.copies, CopyDetection::On { .. }) {
            let mut boundary_parents = move_copy::commit_parents(ctx.store, commit)?;
            if ctx.opts.first_parent {
                boundary_parents.truncate(1);
            }
            let mut claimed = vec![false; lines.len()];
            for parent in boundary_parents {
                let unmatched: Vec<bool> = claimed.iter().map(|&c| !c).collect();
                detector.reassign(
                    &move_copy::ReassignRequest {
                        file_path: ctx.file_path,
                        source_commit: parent,
                        attributed_commit: commit,
                        new_lines: &lines,
                        unmatched: &unmatched,
                        within_file: None,
                        allow_copy: true,
                    },
                    &mut attrs,
                    &mut claimed,
                )?;
            }
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
        apply_ignore_fallthrough(memo, &pass, &parents_data, &mut attrs, &mut matched);
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
fn apply_ignore_fallthrough(
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

/// `-M`/`-C` reassignment across `node`'s parents (first-parent-wins, with one
/// `-C`-specific carve-out below).
///
/// At a merge the unexplained lines are offered to each relevant parent in
/// turn, each searching that parent's own tree, so a block moved (`-M`) or
/// copied (`-C -C`) in from a non-first-parent side is credited to that side's
/// origin — matching `git blame -M`/`-C`, which credits the merge parent whose
/// tree holds the source. `matched` doubles as the "already explained" mask
/// threaded into `reassign`, so a line an earlier parent claimed is excluded
/// from the next parent's candidates and never reassigned twice; it is not
/// read after this pass. With one parent this is exactly the old single pass,
/// so the linear path is unchanged.
///
/// **`-C`'s first-parent carve-out.** At a true (multi-parent) merge, real
/// git's cross-file `-C` search never considers the FIRST parent's own tree —
/// only parents `[1..]`, in order, first-found-wins with no override on a
/// length tie. A block that is a duplicate ONLY on the first parent therefore
/// stays on the merge, even though the first parent has a perfectly valid,
/// uncontested candidate (pinned against git 2.50.1: see
/// `blame_c_merge_copy_tie_prefers_last_parent` and
/// `blame_c_merge_copy_tie_octopus_prefers_first_non_first_parent` in
/// `mod.rs`). `-M` (within-file move) is NOT subject to this carve-out — it
/// stays offered to every parent including the first, so a same-length `-M`
/// candidate on the first parent still wins over any parent's `-C` (both
/// mechanisms share one `reassign` call per parent, and the first parent's
/// call, processed first, can still claim the block via `-M`).
fn apply_detection(
    ctx: &WalkCtx,
    memo: &HashMap<Hash, Rc<[Attribution]>>,
    detector: &mut move_copy::Detector,
    pass: &CommitPass,
    parents_data: &[ParentData],
    attrs: &mut [Attribution],
    matched: &mut [bool],
) -> BlameOutcome<()> {
    let is_merge = pass.node.parents.len() > 1;
    for (k, &parent) in pass.node.parents.iter().enumerate() {
        let parent_lines = &parents_data[k].0;
        let unmatched: Vec<bool> = matched.iter().map(|&m| !m).collect();
        detector.reassign(
            &move_copy::ReassignRequest {
                file_path: ctx.file_path,
                source_commit: parent,
                attributed_commit: pass.commit,
                new_lines: pass.lines,
                unmatched: &unmatched,
                within_file: Some((parent_lines, &memo[&parent])),
                allow_copy: !(is_merge && k == 0),
            },
            attrs,
            matched,
        )?;
    }
    Ok(())
}
