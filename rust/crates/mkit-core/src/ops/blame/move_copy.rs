//! Move (`-M`) and copy (`-C`) detection for blame.
//!
//! The main blame pass ([`super::blame_file_with`]) attributes each line
//! by replaying the line matcher: a line the matcher calls "new" is
//! provisionally credited to the editing commit. This module reassigns
//! those provisional lines when they are actually a **block moved within
//! the file** (`-M`) or **copied from another file** (`-C`), crediting the
//! block to its true origin — matching `git blame -M`/`-C`.
//!
//! Detection works over **normalized keys** (whitespace-stripped under
//! `-w`, raw otherwise), so it agrees with the matcher and so `-w -C`
//! detects a block copied with a whitespace change. Within a run of
//! unmatched lines it finds, at each start position, the longest
//! contiguous block that appears verbatim in a source and clears git's
//! alphanumeric-character threshold, credits the longest such block in the
//! run, and repeats on the lines before and after it — so a moved block
//! adjacent to genuinely-new lines is still split out (git parity).
//!
//! Attribution is **positional**: a matched block at source offset `oi`
//! credits child line `s + k` to the source's own per-line origin at
//! `oi + k`. That keeps `-w` copies correct even when the copied bytes
//! differ only in whitespace.
//!
//! Cost: a per-source index from a line's key to its offsets turns block
//! search into ~`O(run · matches)` (an unmatched line absent from every
//! source is an `O(1)` miss — the common "added a new block" case). A run
//! longer than [`MAX_DETECT_RUN`] is searched only as a single whole block
//! (a documented bound; the matcher already caps inputs at
//! [`super::BLAME_MAX_LINES`]).
//!
//! **Merges.** At a merge both the within-file `-M` move source and the
//! cross-file `-C` copy source are offered to **every relevant parent** (see
//! [`super::walk::attribute_commit`]), each search enumerating that parent's
//! own tree. So a block moved or copied in from a non-first-parent side is
//! credited to that side — matching `git blame -M`/`-C -C`, which credits the
//! merge parent whose tree holds the source (verified against git 2.50.1). A
//! block whose source lives only in the merge's *own* tree (introduced by the
//! merge) stays on the merge, as in git.
//!
//! Two narrow `-C` residuals remain (issue #499 follow-up); `-M` and
//! `--ignore-rev` are fully merge-aware:
//!
//! 1. **Multi-parent copy tie.** When the *same* block is newly added on two
//!    or more merge sides, mkit's first-parent-wins `claimed` mask credits the
//!    first such parent, whereas git credits the last (its copy-source scoring
//!    is effectively last-parent-wins across the parent queue). Only a block
//!    duplicated across sides is affected.
//! 2. **Boundary / newly-added file.** When the blamed file is *added by the
//!    merge* (no parent contains it) and its sole copy source lives on a
//!    non-first parent, the root search walks the first parent's tree only
//!    ([`commit_parent`] returns a single parent, and [`super::walk::build_file_dag`]
//!    drops parents that lack the file), so mkit credits the merge where git
//!    would credit that parent.

use std::collections::HashMap;
use std::ops::Range;

use super::{
    Attribution, BlameError, BlameOptions, BlameOutcome, CopyDetection, MoveDetection,
    blame_file_with, line_key, load_blob_lines,
};
use crate::hash::Hash;
use crate::object::{EntryMode, Object};
use crate::ops::diff::diff_trees;
use crate::store::ObjectStore;

/// Past this many unmatched lines in one run, only the whole run is tried
/// as a single block (no sub-block search). Bounds the worst case; the
/// matcher already rejects inputs over [`super::BLAME_MAX_LINES`].
const MAX_DETECT_RUN: usize = 10_000;

/// Line-key → the offsets at which it occurs in a source, for `O(1)`
/// "where could a block starting with this line be?" lookups.
type KeyIndex = HashMap<Vec<u8>, Vec<usize>>;

/// Inputs for one [`Detector::reassign`] call. Bundled to keep the entry
/// point off the positional-argument hazard and to make the "what does
/// this step see" surface explicit.
pub(super) struct ReassignRequest<'r> {
    /// Path being blamed (excluded from its own copy candidates).
    pub file_path: &'r str,
    /// Parent revision: supplies `-C` candidate trees and their origins,
    /// and is the commit the within-file `-M` source is taken from.
    pub source_commit: Hash,
    /// Child commit: scopes `-C` level 1 to files changed in it.
    pub attributed_commit: Hash,
    /// The child blob's lines (origins are written for these).
    pub new_lines: &'r [Vec<u8>],
    /// `unmatched[i]` = the matcher left line `i` "new" (a detection
    /// candidate). All-`true` at a file's boundary commit.
    pub unmatched: &'r [bool],
    /// Parent version of *this* file as a `(lines, origins)` `-M` source —
    /// `None` at the boundary, where there is no earlier version.
    pub within_file: Option<(&'r [Vec<u8>], &'r [Attribution])>,
}

/// Stateful move/copy detector. Holds the per-blame caches so a source
/// blob's keys/index are built at most once and a source file is blamed
/// at most once, across every step and the boundary.
pub(super) struct Detector<'a> {
    store: &'a ObjectStore,
    opts: &'a BlameOptions,
    /// Source blob → its normalized line keys + key index (cheap).
    keys_cache: HashMap<Hash, (Vec<Vec<u8>>, KeyIndex)>,
    /// (commit, path) → that file's per-line origins, from blaming it
    /// (expensive; built only once a candidate actually matches a block).
    attrs_cache: HashMap<(Hash, String), Vec<Attribution>>,
}

/// Where a matched block came from.
enum BlockSource {
    /// Same file, parent revision; offset into the within-file source.
    WithinFile { offset: usize },
    /// Another file at `source_commit`; offset into that file's lines.
    Copy { path: String, offset: usize },
}

/// Per-`reassign` context, computed once. Borrows the caller's child lines
/// and the within-file source; owns the per-call derived data. Never
/// borrows the [`Detector`].
struct Ctx<'c> {
    source_commit: Hash,
    new_keys: Vec<Vec<u8>>,
    /// `alnum_prefix[i]` = alphanumeric byte count over `new_lines[..i]`,
    /// so a block's count is `alnum_prefix[e] - alnum_prefix[s]` in `O(1)`.
    alnum_prefix: Vec<usize>,
    within_keys: Option<Vec<Vec<u8>>>,
    within_index: Option<KeyIndex>,
    within_attrs: Option<&'c [Attribution]>,
    move_threshold: Option<usize>,
    candidates: Vec<(String, Hash)>,
    copy_threshold: Option<usize>,
}

impl Ctx<'_> {
    /// Alphanumeric byte count of `new_lines[s..e]`, in `O(1)`.
    fn alnum(&self, s: usize, e: usize) -> usize {
        self.alnum_prefix[e] - self.alnum_prefix[s]
    }
}

impl<'a> Detector<'a> {
    pub(super) fn new(store: &'a ObjectStore, opts: &'a BlameOptions) -> Self {
        Self {
            store,
            opts,
            keys_cache: HashMap::new(),
            attrs_cache: HashMap::new(),
        }
    }

    /// Reassign moved/copied blocks among the unmatched lines of the
    /// request, writing origins into `out` and marking each reassigned line
    /// `true` in `claimed`. A no-op when detection is off or nothing
    /// qualifies.
    ///
    /// `claimed` lets a merge run the detector against each parent in turn
    /// (first-parent-wins): a line a higher-priority parent already explained
    /// is excluded from the next parent's `unmatched` mask, so it is never
    /// reassigned twice. The single-parent path passes a throwaway buffer.
    pub(super) fn reassign(
        &mut self,
        req: &ReassignRequest,
        out: &mut [Attribution],
        claimed: &mut [bool],
    ) -> BlameOutcome<()> {
        let iw = self.opts.ignore_whitespace;
        let move_threshold = match self.opts.effective_move() {
            MoveDetection::On { threshold } => req.within_file.map(|_| threshold),
            MoveDetection::Off => None,
        };
        let (copy_level, copy_threshold) = match self.opts.copies {
            CopyDetection::On { level, threshold } => (level, Some(threshold)),
            CopyDetection::Off => (0, None),
        };
        if move_threshold.is_none() && copy_threshold.is_none() {
            return Ok(());
        }

        let candidates = if copy_level > 0 {
            copy_candidates(
                self.store,
                req.source_commit,
                req.attributed_commit,
                req.file_path,
                copy_level,
            )?
        } else {
            Vec::new()
        };
        let (within_keys, within_index) = match req.within_file {
            Some((lines, _)) => {
                let keys: Vec<Vec<u8>> = lines.iter().map(|l| line_key(l, iw)).collect();
                let index = build_index(&keys);
                (Some(keys), Some(index))
            }
            None => (None, None),
        };
        let ctx = Ctx {
            source_commit: req.source_commit,
            new_keys: req.new_lines.iter().map(|l| line_key(l, iw)).collect(),
            alnum_prefix: alnum_prefix(req.new_lines),
            within_keys,
            within_index,
            within_attrs: req.within_file.map(|(_, attrs)| attrs),
            move_threshold,
            candidates,
            copy_threshold,
        };

        // Process each maximal run of unmatched lines with an explicit
        // work-stack (no recursion → no stack-overflow on a run of many
        // independent single-line moves).
        let mut stack: Vec<Range<usize>> = unmatched_runs(req.unmatched);
        while let Some(region) = stack.pop() {
            if region.is_empty() {
                continue;
            }
            let Some((s, e, source)) = self.find_best_block(&region, &ctx)? else {
                continue;
            };
            self.credit(s, e, &source, &ctx, out)?;
            claimed[s..e].fill(true);
            stack.push(region.start..s);
            stack.push(e..region.end);
        }
        Ok(())
    }

    /// Write the origins for a matched block `[s, e)` into `out`.
    fn credit(
        &mut self,
        s: usize,
        e: usize,
        source: &BlockSource,
        ctx: &Ctx,
        out: &mut [Attribution],
    ) -> BlameOutcome<()> {
        match source {
            BlockSource::WithinFile { offset } => {
                let attrs = ctx.within_attrs.expect("within-file source present");
                copy_origins(out, s, e - s, attrs, *offset);
            }
            BlockSource::Copy { path, offset } => {
                // Blame the winning source file once to get its origins.
                // The cached slice and `out` never alias, so borrow it
                // directly rather than cloning the whole vector per block.
                let attrs = self.candidate_attrs(ctx.source_commit, path)?;
                copy_origins(out, s, e - s, attrs, *offset);
            }
        }
        Ok(())
    }

    /// The longest qualifying block in `region` (longest wins; earliest
    /// start breaks length ties; within-file `-M` beats `-C` at the same
    /// start and length). Returns `(start, end, source)`.
    fn find_best_block(
        &mut self,
        region: &Range<usize>,
        ctx: &Ctx,
    ) -> BlameOutcome<Option<(usize, usize, BlockSource)>> {
        // Cost bound: only try the whole run as one block past the limit.
        if region.len() > MAX_DETECT_RUN {
            return Ok(self
                .longest_block_at(region.start, region.end, ctx)?
                .filter(|(len, _)| region.start + len == region.end)
                .map(|(len, src)| (region.start, region.start + len, src)));
        }
        let mut best: Option<(usize, usize, BlockSource)> = None;
        for s in region.start..region.end {
            if let Some((len, source)) = self.longest_block_at(s, region.end, ctx)? {
                let longer = best.as_ref().is_none_or(|(bs, be, _)| be - bs < len);
                if longer {
                    best = Some((s, s + len, source));
                }
            }
        }
        Ok(best)
    }

    /// The longest contiguous block starting at `s` (bounded by `end`) that
    /// appears in a source and clears that source's threshold, with its
    /// source. `-M` is preferred over an equal-length `-C` match.
    fn longest_block_at(
        &mut self,
        s: usize,
        end: usize,
        ctx: &Ctx,
    ) -> BlameOutcome<Option<(usize, BlockSource)>> {
        let needle = &ctx.new_keys[s..end];
        let mut best: Option<(usize, BlockSource)> = None;

        // -M: same file, parent revision.
        let moved = match (ctx.move_threshold, &ctx.within_keys, &ctx.within_index) {
            (Some(threshold), Some(keys), Some(index)) => longest_match(needle, keys, index)
                .filter(|&(len, _)| ctx.alnum(s, s + len) >= threshold),
            _ => None,
        };
        if let Some((len, offset)) = moved {
            best = Some((len, BlockSource::WithinFile { offset }));
        }

        // -C: other files at the parent commit. A strictly-longer copy
        // match wins; an equal-length one does not (keeps `-M` preferred).
        if let Some(threshold) = ctx.copy_threshold {
            for ci in 0..ctx.candidates.len() {
                let blob = ctx.candidates[ci].1;
                self.ensure_candidate(blob)?;
                let (keys, index) = &self.keys_cache[&blob];
                let Some((len, offset)) = longest_match(needle, keys, index) else {
                    continue;
                };
                let wins = best.as_ref().is_none_or(|(bl, _)| len > *bl);
                if wins && ctx.alnum(s, s + len) >= threshold {
                    best = Some((
                        len,
                        BlockSource::Copy {
                            path: ctx.candidates[ci].0.clone(),
                            offset,
                        },
                    ));
                }
            }
        }
        Ok(best)
    }

    /// Ensure a source blob's keys + key index are cached.
    fn ensure_candidate(&mut self, blob: Hash) -> BlameOutcome<()> {
        if !self.keys_cache.contains_key(&blob) {
            let iw = self.opts.ignore_whitespace;
            let lines = load_blob_lines(self.store, blob)?;
            let keys: Vec<Vec<u8>> = lines.iter().map(|l| line_key(l, iw)).collect();
            let index = build_index(&keys);
            self.keys_cache.insert(blob, (keys, index));
        }
        Ok(())
    }

    /// Per-line origins for a source file, by blaming it at `commit`
    /// (cached; expensive).
    ///
    /// The source blame keeps the *active* `-w`, (effective) `-M`,
    /// `--ignore-rev` set, and first-parent mode so a copied block is credited
    /// through a prior whitespace-only edit, same-file move, ignored noise
    /// commit, or merge in the source — matching git. Only `-C` is dropped,
    /// which both prevents unbounded recursion and matches git (a copy source
    /// is blamed without further cross-file copy detection).
    fn candidate_attrs(&mut self, commit: Hash, path: &str) -> BlameOutcome<&[Attribution]> {
        let key = (commit, path.to_string());
        if !self.attrs_cache.contains_key(&key) {
            let source_opts = BlameOptions {
                ignore_whitespace: self.opts.ignore_whitespace,
                moves: self.opts.effective_move(),
                copies: CopyDetection::Off,
                ignore_revs: self.opts.ignore_revs.clone(),
                first_parent: self.opts.first_parent,
            };
            let res = blame_file_with(self.store, commit, path, &source_opts)?;
            let attrs = res.lines.into_iter().map(Attribution::from).collect();
            self.attrs_cache.insert(key.clone(), attrs);
        }
        Ok(&self.attrs_cache[&key])
    }
}

/// Copy `len` source origins starting at `src_off` into `out` at `dst`.
fn copy_origins(
    out: &mut [Attribution],
    dst: usize,
    len: usize,
    src: &[Attribution],
    src_off: usize,
) {
    for k in 0..len {
        if let Some(a) = src.get(src_off + k) {
            out[dst + k] = a.clone();
        }
    }
}

/// Longest prefix of `needle` that occurs contiguously in `hay`, using
/// `index` (key → offsets) to find candidate starts, plus the offset.
///
/// Divergence: when an identical block occurs at several offsets in the
/// same source, the **earliest** offset wins the length tie (`build_index`
/// records offsets ascending and this keeps the first maximal match). git
/// tracks line identity through its diff and may land on a different copy;
/// for block-based detection the earliest deterministic offset is the
/// documented choice (see the cross-file tie-break note in CHANGELOG).
fn longest_match(needle: &[Vec<u8>], hay: &[Vec<u8>], index: &KeyIndex) -> Option<(usize, usize)> {
    let first = needle.first()?;
    let offsets = index.get(first)?;
    let mut best: Option<(usize, usize)> = None;
    for &oi in offsets {
        let len = needle
            .iter()
            .zip(&hay[oi..])
            .take_while(|(a, b)| a == b)
            .count();
        if best.is_none_or(|(bl, _)| len > bl) {
            best = Some((len, oi));
        }
    }
    best
}

/// Build a line-key → offsets index over `keys`.
fn build_index(keys: &[Vec<u8>]) -> KeyIndex {
    let mut index: KeyIndex = HashMap::with_capacity(keys.len());
    for (i, k) in keys.iter().enumerate() {
        index.entry(k.clone()).or_default().push(i);
    }
    index
}

/// Alphanumeric-byte prefix sums over `lines` (`len + 1` entries).
fn alnum_prefix(lines: &[Vec<u8>]) -> Vec<usize> {
    let mut prefix = Vec::with_capacity(lines.len() + 1);
    let mut acc = 0;
    prefix.push(0);
    for l in lines {
        acc += l.iter().filter(|b| b.is_ascii_alphanumeric()).count();
        prefix.push(acc);
    }
    prefix
}

/// Maximal runs of `true` in `mask`, as `[start, end)` ranges.
fn unmatched_runs(mask: &[bool]) -> Vec<Range<usize>> {
    let mut runs = Vec::new();
    let mut i = 0;
    while i < mask.len() {
        if !mask[i] {
            i += 1;
            continue;
        }
        let start = i;
        while i < mask.len() && mask[i] {
            i += 1;
        }
        runs.push(start..i);
    }
    runs
}

/// Source files to search for copies, per git's `-C` level: level 1 =
/// files whose blob differs between the parent (`older`) and child
/// (`newer`) commit (the files "changed in the commit"); level >= 2 =
/// every file in the parent commit. The blamed path is always excluded.
///
/// Built on the canonical [`diff_trees`] differ, so it inherits the shared
/// `MAX_TREE_DEPTH` guard and the hash-equal-subtree pruning (it does not
/// re-flatten the whole tree on every ancestor step). Level >= 2 diffs the
/// parent tree against the empty tree, enumerating every parent blob as a
/// `Removed` entry that carries its hash.
fn copy_candidates(
    store: &ObjectStore,
    older: Hash,
    newer: Hash,
    target_path: &str,
    level: u8,
) -> BlameOutcome<Vec<(String, Hash)>> {
    let older_tree = commit_tree(store, older)?;
    let entries = if level >= 2 {
        diff_trees(store, Some(older_tree), None)?.entries
    } else {
        let newer_tree = commit_tree(store, newer)?;
        diff_trees(store, Some(older_tree), Some(newer_tree))?.entries
    };
    Ok(entries
        .into_iter()
        .filter_map(|e| {
            // The copy source is the *parent* version: its content must be
            // present in `older` and actually differ in the child (so a
            // mode-only change is not a copy source). `diff_trees` doesn't
            // emit renames, so `path` is the parent path.
            let hash = e.old_hash?;
            if e.new_hash == Some(hash) {
                return None;
            }
            // Only real file content is blamable (skip symlinks/submodules).
            if !matches!(e.old_mode, Some(EntryMode::Blob | EntryMode::Executable)) {
                return None;
            }
            // A non-UTF-8 name comes back lossy-converted (`�`) and can't
            // round-trip through `find_blob_in_tree`; such a file is neither
            // the blamed target nor a usable copy source, so drop it (and
            // keep self-exclusion exact).
            if e.path.contains('\u{FFFD}') || e.path == target_path {
                return None;
            }
            Some((e.path, hash))
        })
        .collect())
}

/// First-parent of a commit, or `None` for a root commit.
pub(super) fn commit_parent(store: &ObjectStore, commit: Hash) -> BlameOutcome<Option<Hash>> {
    let Object::Commit(c) = store.read_object(&commit)? else {
        return Err(BlameError::NotACommit);
    };
    Ok(c.parents.first().copied())
}

/// The tree a commit points at.
fn commit_tree(store: &ObjectStore, commit: Hash) -> BlameOutcome<Hash> {
    let Object::Commit(c) = store.read_object(&commit)? else {
        return Err(BlameError::NotACommit);
    };
    Ok(c.tree_hash)
}
