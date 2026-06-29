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
//! unmatched lines it finds the **longest contiguous sub-block** that
//! appears verbatim in a source and clears git's alphanumeric-character
//! threshold, credits it, and recurses on the remainder — so a moved block
//! adjacent to genuinely-new lines is still split out (git parity).
//!
//! Attribution is **positional**: a matched block at source offset `oi`
//! credits child line `s + k` to the source's own per-line origin at
//! `oi + k`. That keeps `-w` copies correct even when the copied bytes
//! differ only in whitespace.

use std::collections::HashMap;
use std::ops::Range;

use super::{
    Attribution, BlameOptions, BlameOutcome, CopyDetection, MoveDetection, blame_file_with,
    line_key, load_blob_lines,
};
use crate::hash::Hash;
use crate::object::{EntryMode, Object};
use crate::store::ObjectStore;

/// Stateful move/copy detector. Holds the per-blame caches so a source
/// blob's keys are stripped at most once and a source file is blamed at
/// most once, across every step and the boundary.
pub(super) struct Detector<'a> {
    store: &'a ObjectStore,
    opts: BlameOptions,
    /// Source blob → its normalized line keys (cheap: load + strip).
    keys_cache: HashMap<Hash, Vec<Vec<u8>>>,
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

/// Per-`reassign` context shared down the recursion. Borrows the caller's
/// child lines and the optional within-file source; owns the candidate
/// list. Never borrows the [`Detector`] itself.
struct Ctx<'c> {
    source_commit: Hash,
    new_lines: &'c [Vec<u8>],
    new_keys: Vec<Vec<u8>>,
    within_keys: Option<Vec<Vec<u8>>>,
    within_attrs: Option<&'c [Attribution]>,
    candidates: Vec<(String, Hash)>,
    move_threshold: Option<usize>,
    copy_threshold: Option<usize>,
}

impl<'a> Detector<'a> {
    pub(super) fn new(store: &'a ObjectStore, opts: BlameOptions) -> Self {
        Self {
            store,
            opts,
            keys_cache: HashMap::new(),
            attrs_cache: HashMap::new(),
        }
    }

    /// Reassign moved/copied blocks among the lines of `new_lines` for
    /// which `is_unmatched` holds, writing origins into `out`.
    ///
    /// `source_commit` is the parent revision: its tree supplies `-C`
    /// candidates and its blame supplies their origins. `attributed_commit`
    /// is the child commit (used to scope `-C` level 1 to files changed in
    /// it). `within_file` is the parent version of *this* file as a
    /// `(lines, origins)` `-M` source — `None` at a file's boundary commit,
    /// where there is no earlier version.
    pub(super) fn reassign(
        &mut self,
        file_path: &str,
        source_commit: Hash,
        attributed_commit: Hash,
        new_lines: &[Vec<u8>],
        is_unmatched: &dyn Fn(usize) -> bool,
        within_file: Option<(&[Vec<u8>], &[Attribution])>,
        out: &mut [Attribution],
    ) -> BlameOutcome<()> {
        let iw = self.opts.ignore_whitespace;
        let move_threshold = match self.opts.effective_move() {
            MoveDetection::On { threshold } => within_file.map(|_| threshold),
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
                source_commit,
                attributed_commit,
                file_path,
                copy_level,
            )?
        } else {
            Vec::new()
        };

        let ctx = Ctx {
            source_commit,
            new_lines,
            new_keys: new_lines.iter().map(|l| line_key(l, iw)).collect(),
            within_keys: within_file
                .map(|(lines, _)| lines.iter().map(|l| line_key(l, iw)).collect()),
            within_attrs: within_file.map(|(_, attrs)| attrs),
            candidates,
            move_threshold,
            copy_threshold,
        };

        // Walk maximal runs of unmatched lines.
        let mut ni = 0;
        while ni < new_lines.len() {
            if !is_unmatched(ni) {
                ni += 1;
                continue;
            }
            let start = ni;
            while ni < new_lines.len() && is_unmatched(ni) {
                ni += 1;
            }
            self.reassign_region(start..ni, &ctx, out)?;
        }
        Ok(())
    }

    /// Greedily credit the longest qualifying sub-block in `region`, then
    /// recurse on the lines before and after it.
    fn reassign_region(
        &mut self,
        region: Range<usize>,
        ctx: &Ctx,
        out: &mut [Attribution],
    ) -> BlameOutcome<()> {
        if region.is_empty() {
            return Ok(());
        }
        let Some((s, e, source)) = self.find_best_block(&region, ctx)? else {
            return Ok(());
        };
        match source {
            BlockSource::WithinFile { offset } => {
                let attrs = ctx.within_attrs.expect("within-file source present");
                for k in 0..(e - s) {
                    if let Some(a) = attrs.get(offset + k) {
                        out[s + k] = a.clone();
                    }
                }
            }
            BlockSource::Copy { path, offset } => {
                // Blame the (winning) source file once to get its origins.
                let attrs = self.candidate_attrs(ctx.source_commit, &path)?.to_vec();
                for k in 0..(e - s) {
                    if let Some(a) = attrs.get(offset + k) {
                        out[s + k] = a.clone();
                    }
                }
            }
        }
        self.reassign_region(region.start..s, ctx, out)?;
        self.reassign_region(e..region.end, ctx, out)?;
        Ok(())
    }

    /// Find the longest contiguous sub-block of `region` (longest first,
    /// earliest on ties) that appears verbatim in a source and clears that
    /// source's threshold. `-M` (within-file) is preferred over `-C`.
    fn find_best_block(
        &mut self,
        region: &Range<usize>,
        ctx: &Ctx,
    ) -> BlameOutcome<Option<(usize, usize, BlockSource)>> {
        for len in (1..=region.len()).rev() {
            for s in region.start..=(region.end - len) {
                let e = s + len;
                let needle = &ctx.new_keys[s..e];
                let alnum = block_alnum(ctx.new_lines, s..e);

                // -M: same file, parent revision.
                let moved = ctx
                    .move_threshold
                    .filter(|&t| alnum >= t)
                    .and(ctx.within_keys.as_deref())
                    .and_then(|keys| find_block(keys, needle));
                if let Some(offset) = moved {
                    return Ok(Some((s, e, BlockSource::WithinFile { offset })));
                }

                // -C: other files at the parent commit.
                if ctx.copy_threshold.is_some_and(|t| alnum >= t) {
                    for (path, blob) in &ctx.candidates {
                        if let Some(offset) = find_block(self.candidate_keys(*blob)?, needle) {
                            return Ok(Some((
                                s,
                                e,
                                BlockSource::Copy {
                                    path: path.clone(),
                                    offset,
                                },
                            )));
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    /// Normalized keys for a source blob (cached; cheap).
    fn candidate_keys(&mut self, blob: Hash) -> BlameOutcome<&[Vec<u8>]> {
        if !self.keys_cache.contains_key(&blob) {
            let iw = self.opts.ignore_whitespace;
            let lines = load_blob_lines(self.store, blob)?;
            let keys = lines.iter().map(|l| line_key(l, iw)).collect();
            self.keys_cache.insert(blob, keys);
        }
        Ok(&self.keys_cache[&blob])
    }

    /// Per-line origins for a source file, by blaming it at `commit`
    /// (cached; expensive).
    ///
    /// The source blame keeps the *active* `-w` and (effective) `-M` so a
    /// copied block is credited through a prior whitespace-only edit or
    /// same-file move in the source — matching git. Only `-C` is dropped,
    /// which both prevents unbounded recursion and matches git (a copy
    /// source is blamed without further cross-file copy detection).
    fn candidate_attrs(&mut self, commit: Hash, path: &str) -> BlameOutcome<&[Attribution]> {
        let key = (commit, path.to_string());
        if !self.attrs_cache.contains_key(&key) {
            let source_opts = BlameOptions {
                ignore_whitespace: self.opts.ignore_whitespace,
                moves: self.opts.effective_move(),
                copies: CopyDetection::Off,
            };
            let res = blame_file_with(self.store, commit, path, &source_opts)?;
            let attrs = res
                .lines
                .into_iter()
                .map(|l| Attribution {
                    commit_hash: l.commit_hash,
                    author: l.author,
                    timestamp: l.timestamp,
                })
                .collect();
            self.attrs_cache.insert(key.clone(), attrs);
        }
        Ok(&self.attrs_cache[&key])
    }
}

/// First start index in `hay` where `needle` occurs as a contiguous run.
fn find_block(hay: &[Vec<u8>], needle: &[Vec<u8>]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|&i| hay[i..i + needle.len()] == needle[..])
}

/// Count ASCII-alphanumeric bytes across `lines[range]` — git's unit for
/// the `-M`/`-C` detection threshold.
fn block_alnum(lines: &[Vec<u8>], range: Range<usize>) -> usize {
    lines[range]
        .iter()
        .flat_map(|l| l.iter())
        .filter(|b| b.is_ascii_alphanumeric())
        .count()
}

/// Source files to search for copies, per git's `-C` level: level 1 =
/// files whose blob differs between the parent (`older`) and child
/// (`newer`) commit (the files "changed in the commit"); level >= 2 =
/// every file in the parent commit. The blamed path is always excluded.
fn copy_candidates(
    store: &ObjectStore,
    older: Hash,
    newer: Hash,
    target_path: &str,
    level: u8,
) -> BlameOutcome<Vec<(String, Hash)>> {
    let older_blobs = commit_blobs(store, older)?;
    if level >= 2 {
        return Ok(older_blobs
            .into_iter()
            .filter(|(p, _)| p != target_path)
            .collect());
    }
    let newer_blobs = commit_blobs(store, newer)?;
    let newer_map: HashMap<&str, Hash> =
        newer_blobs.iter().map(|(p, h)| (p.as_str(), *h)).collect();
    Ok(older_blobs
        .into_iter()
        .filter(|(p, h)| p != target_path && newer_map.get(p.as_str()) != Some(h))
        .collect())
}

/// First-parent of a commit, or `None` for a root commit.
pub(super) fn commit_parent(store: &ObjectStore, commit: Hash) -> BlameOutcome<Option<Hash>> {
    let Object::Commit(c) = store.read_object(&commit)? else {
        return Err(super::BlameError::NotACommit);
    };
    Ok(c.parents.first().copied())
}

/// Every `(path, blob_hash)` reachable from a commit's tree.
fn commit_blobs(store: &ObjectStore, commit: Hash) -> BlameOutcome<Vec<(String, Hash)>> {
    let Object::Commit(c) = store.read_object(&commit)? else {
        return Err(super::BlameError::NotACommit);
    };
    let mut out = Vec::new();
    collect_tree_blobs(store, c.tree_hash, "", &mut out)?;
    Ok(out)
}

/// Recursively collect `(path, blob_hash)` for every blob under a tree.
/// Symlinks are skipped (not blamable content).
fn collect_tree_blobs(
    store: &ObjectStore,
    tree_hash: Hash,
    prefix: &str,
    out: &mut Vec<(String, Hash)>,
) -> BlameOutcome<()> {
    let Object::Tree(tree) = store.read_object(&tree_hash)? else {
        return Ok(());
    };
    for entry in tree.entries {
        let name = String::from_utf8_lossy(&entry.name);
        match entry.mode {
            EntryMode::Blob | EntryMode::Executable => {
                out.push((format!("{prefix}{name}"), entry.object_hash));
            }
            EntryMode::Tree => {
                let child_prefix = format!("{prefix}{name}/");
                collect_tree_blobs(store, entry.object_hash, &child_prefix, out)?;
            }
            EntryMode::Symlink => {}
        }
    }
    Ok(())
}
