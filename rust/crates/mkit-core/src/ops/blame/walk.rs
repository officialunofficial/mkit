//! Merge-aware blame walk: build the file's ancestor subgraph, order it
//! topologically (parents before children), and resolve each commit's line
//! attributions from its parents' already-resolved ones. `super::blame_file_with`
//! drives this; the single-parent path reproduces the old linear replay.

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

/// Read-mostly context threaded into [`attribute_commit`].
pub(super) struct WalkCtx<'a> {
    pub(super) store: &'a ObjectStore,
    pub(super) opts: &'a BlameOptions,
    pub(super) nodes: &'a HashMap<Hash, DagNode>,
    pub(super) file_path: &'a str,
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
/// the detector against the first parent.
pub(super) fn attribute_commit(
    ctx: &WalkCtx,
    memo: &HashMap<Hash, Rc<[Attribution]>>,
    detector: &mut move_copy::Detector,
    commit: Hash,
) -> BlameOutcome<Rc<[Attribution]>> {
    let node = &ctx.nodes[&commit];
    let lines = load_blob_lines(ctx.store, node.blob_hash)?;
    let own = node.own_attribution(commit);

    // Root: the file first appears here, so every line is introduced — but a
    // block may have been copied from other files in the real parent (`-C`).
    if node.parents.is_empty() {
        let mut attrs = vec![own; lines.len()];
        let boundary_parent = if matches!(ctx.opts.copies, CopyDetection::On { .. }) {
            move_copy::commit_parent(ctx.store, commit)?
        } else {
            None
        };
        if let Some(parent) = boundary_parent {
            detector.reassign(
                &move_copy::ReassignRequest {
                    file_path: ctx.file_path,
                    source_commit: parent,
                    attributed_commit: commit,
                    new_lines: &lines,
                    unmatched: &vec![true; lines.len()],
                    within_file: None,
                },
                &mut attrs,
            )?;
        }
        return Ok(attrs.into());
    }

    let first_parent = node.parents[0];
    // Fast path: a single parent with the identical blob contributes every
    // line unchanged (the old `newer.blob == older.blob` skip). The memo is
    // `Rc`-shared, so this is an O(1) refcount bump, not a full-vector clone.
    if node.parents.len() == 1 && ctx.nodes[&first_parent].blob_hash == node.blob_hash {
        return Ok(Rc::clone(&memo[&first_parent]));
    }

    let mut attrs = vec![own; lines.len()];
    let mut matched = vec![false; lines.len()];
    let first_parent_lines = load_blob_lines(ctx.store, ctx.nodes[&first_parent].blob_hash)?;
    let mut first_parent_mapping: Vec<Option<usize>> = Vec::new();

    for (k, &parent) in node.parents.iter().enumerate() {
        let parent_lines = if k == 0 {
            first_parent_lines.clone()
        } else {
            load_blob_lines(ctx.store, ctx.nodes[&parent].blob_hash)?
        };
        // `mapping[ni]` = the parent index that this commit's line `ni` is
        // unchanged from, or `None` if changed/introduced.
        let mapping = match_lines_with_options(&parent_lines, &lines, ctx.opts)?;
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
        if k == 0 {
            first_parent_mapping = mapping;
        }
    }

    // `--ignore-rev`: a line this (ignored) commit would keep falls through to
    // the first parent's corresponding line. A line the fall-through resolves
    // is marked `matched` so the detector below does not overwrite it —
    // `--ignore-rev` takes precedence over `-M`/`-C` on the lines it resolves.
    if ctx.opts.is_ignored(&commit) {
        let fall = ignore_fallthrough(&first_parent_mapping, first_parent_lines.len());
        let parent_attrs = &memo[&first_parent];
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

    // `-M`/`-C`: reassign blocks no parent explained, against the first parent
    // (its lines and resolved origins are the move/copy source).
    if ctx.opts.detection_enabled() {
        let unmatched: Vec<bool> = matched.iter().map(|&m| !m).collect();
        detector.reassign(
            &move_copy::ReassignRequest {
                file_path: ctx.file_path,
                source_commit: first_parent,
                attributed_commit: commit,
                new_lines: &lines,
                unmatched: &unmatched,
                within_file: Some((&first_parent_lines, &memo[&first_parent])),
            },
            &mut attrs,
        )?;
    }

    Ok(attrs.into())
}
