//! `mkit status` — show working-tree changes relative to HEAD.
//!
//! ## Default (human) output
//!
//! ```text
//! on branch <name>           # to stderr  (or "detached HEAD at <hash>" / "no HEAD yet")
//!                            #
//! Changes to be committed:   # to stderr
//!   A  added.txt             # to stderr
//!   D  deleted.txt           # to stderr
//!
//! Changes not staged for commit:    # to stderr
//!   M  modified.txt                 # to stderr
//! ```
//!
//! Banners and section headers go to stderr; per-file lines also go to
//! stderr in default mode because they are formatted for humans.
//! Scripts should use `--porcelain` (see below) for stdout output
//! that is safe to parse.
//!
//! ## `--porcelain[=v1]` / `-s` (`--short`) output
//!
//! `-s`/`--short` is an alias for `--porcelain=v1`; both select the
//! same renderer. Compatible with `git status --porcelain` — one entry
//! per line,
//! two-character XY status code, space, path:
//!
//! ```text
//! M  modified-staged.txt
//!  M unstaged-edit.txt
//! A  newly-staged.txt
//! ?? untracked.txt
//! ```
//!
//! `X` is the staged-vs-HEAD state; `Y` is the worktree-vs-index
//! state. mkit's `DiffKind::ModeChanged` renders as `T` (a non-git
//! extension). `??` is the conventional code for untracked files.
//!
//! Paths containing special bytes are C-style quoted (matching git's
//! default `core.quotePath`). With `-z`, records are NUL-terminated and
//! paths are emitted raw (unquoted) — the round-trip-safe form for paths
//! with newlines or other special bytes; `-z` implies porcelain.
//!
//! Empty stdout means "nothing to commit, working tree clean."
//!
//! ## `--porcelain=v2` output
//!
//! Selects git's richer per-path format. Each changed tracked path is a
//! `1` record:
//!
//! ```text
//! 1 <XY> <sub> <mH> <mI> <mW> <hH> <hI> <path>
//! ```
//!
//! where `XY` uses `.` (not space) for an unchanged column, `<sub>` is
//! always `N...` (mkit is never a submodule), `<mH>/<mI>/<mW>` are the
//! octal file modes in HEAD / index / worktree, and `<hH>/<hI>` are the
//! HEAD and index object ids (full 64-hex BLAKE3; git's are 40-hex
//! SHA-1, so the differential harness masks length). Untracked paths are
//! `? <path>` records, and a rename emits a `2` record (`R100`, exact
//! content). There are no `--branch` header lines. Path quoting and `-z`
//! semantics match the v1 renderer.

use std::io::Write;

use std::path::Path;

use clap::{Parser, ValueEnum};
use mkit_core::Hash;
use mkit_core::index::{self, EntryStatus, Index};
use mkit_core::layout::RepoLayout;
use mkit_core::ops::{
    DiffEntry, DiffKind, StatusEntry, StatusStaging, detect_exact_renames, status_diff_observed,
};
use mkit_core::refs;
use mkit_core::store::ObjectStore;

use crate::clap_shim;
use crate::exit;
use crate::format;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum PorcelainVersion {
    V1,
    V2,
}

#[derive(Debug, Parser)]
#[command(
    name = "mkit status",
    about = "Show working-tree changes relative to HEAD."
)]
struct StatusOpts {
    /// Emit machine-readable XY-code-plus-path on stdout. Default
    /// `v1` matches `git status --porcelain=v1`.
    #[arg(long, value_name = "VERSION", num_args = 0..=1, default_missing_value = "v1")]
    porcelain: Option<PorcelainVersion>,

    /// Short format. Alias for `--porcelain=v1`: emits the same
    /// XY-code-plus-path lines on stdout.
    #[arg(short = 's', long = "short")]
    short: bool,

    /// NUL-terminate entries instead of newline, and emit raw (unquoted)
    /// paths — like `git status -z`. Implies porcelain output. Without
    /// `-z`, paths with special bytes are C-style quoted.
    #[arg(short = 'z')]
    z: bool,

    /// Turn off rename detection (on by default, like git). A move then
    /// reports as a separate deletion and addition.
    #[arg(long = "no-renames")]
    no_renames: bool,

    /// Detect renames, optionally with a similarity threshold. Accepted
    /// for git familiarity; mkit pairs by identical content (exact, 100%),
    /// so any threshold ≤ 100 selects the same exact matches.
    #[arg(long = "find-renames", value_name = "N", num_args = 0..=1, require_equals = true)]
    find_renames: Option<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<StatusOpts>("mkit status", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    // `-s`/`--short` is an alias for `--porcelain=v1`; `-z` also implies
    // porcelain output. All select the line-oriented XY renderer on stdout.
    let porcelain = opts.porcelain.is_some() || opts.short || opts.z;

    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let layout = match super::resolve_layout(&cwd) {
        Ok(layout) => layout,
        Err(code) => return code,
    };
    let store = match ObjectStore::open(&layout) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };

    // Resolve HEAD tree hash (None on a HEAD-less repo). Use the shared
    // helper so a `Remix` HEAD is compared against its tree like every
    // other command, not treated as "no HEAD".
    let head_tree: Option<mkit_core::Hash> = match super::current_head_tree(&layout, &store) {
        Ok(t) => t,
        Err(e) => return emit_err(&format!("status: {e}"), exit::GENERAL_ERROR),
    };

    // Load the index, falling back to None only when absent/empty.
    // Corrupt or invalid persisted state must surface instead of
    // silently reverting to the HEAD<->worktree comparison.
    let idx = match index::read_index(&layout) {
        Ok(idx) if idx.entries.is_empty() => None,
        Ok(idx) => Some(idx),
        Err(e) => return emit_err(&format!("read index: {e}"), exit::GENERAL_ERROR),
    };

    // A provided `--find-renames` threshold must be a number (`50`, `50%`)
    // — reject garbage like git does, even though the exact matcher then
    // ignores the magnitude.
    if let Some(t) = &opts.find_renames {
        let n = t.trim_end_matches('%');
        if !n.is_empty() && n.parse::<u8>().is_err() {
            return emit_err(&format!("invalid --find-renames value: {t}"), exit::USAGE);
        }
    }

    let (mut entries, observations) =
        match status_diff_observed(&store, head_tree.as_ref(), &cwd, idx.as_ref()) {
            Ok(v) => v,
            Err(e) => return emit_err(&format!("status: {e}"), exit::GENERAL_ERROR),
        };

    // Opportunistic stat-cache refresh, like `git status`: entries the
    // racy-clean rule forced us to re-hash and whose re-hash matched
    // the staged hash get their cache re-recorded from the HASH-TIME
    // stat (never a later one — see StatObservation). Purely an
    // optimisation — skipped on lock contention or any error.
    if idx.is_some() {
        refresh_stat_cache(&layout, &observations);
    }

    // Rename detection (on by default, like git): pair identical-content
    // staged deletes and adds into a single `R` entry.
    if !opts.no_renames {
        entries = detect_status_renames(entries);
    }

    if porcelain {
        if opts.porcelain == Some(PorcelainVersion::V2) {
            render_porcelain_v2(&store, head_tree.as_ref(), &layout, &entries, opts.z)
        } else {
            render_porcelain(&entries, opts.z)
        }
    } else {
        render_human(&layout, &entries)
    }
}

/// Re-record the stat cache from the worktree walk's hash-time
/// [`StatObservation`]s. Sound by construction:
///
/// - each observation pairs a hash with the stat captured from the
///   opened fd BEFORE its content was read — a modification after that
///   stat lands a newer mtime/ctime, so the recorded pair can only
///   under-claim, never hide an edit;
/// - the rewrite happens under the worktree lock against a freshly
///   re-read index, matching path AND hash, so a concurrent `add` is
///   never clobbered;
/// - a v1 on-disk index is left untouched: `status` is a query and must
///   not one-way-upgrade the format under an older binary's feet (the
///   first mutating command performs the upgrade instead).
///
/// Lock contention or any error skips the refresh — it is an
/// optimisation.
fn refresh_stat_cache(layout: &RepoLayout, observations: &[mkit_core::worktree::StatObservation]) {
    if observations.is_empty() {
        return;
    }
    // Version sniff: never auto-upgrade a v1 index from a query command.
    match std::fs::File::open(mkit_core::index::index_path(layout)) {
        Ok(mut f) => {
            use std::io::Read as _;
            let mut header = [0u8; 5];
            if f.read_exact(&mut header).is_err() || header[4] != mkit_core::index::FORMAT_VERSION {
                return;
            }
        }
        Err(_) => return,
    }
    // Try-take the worktree lock with a near-zero timeout and no error
    // output; a concurrent mutator wins and we silently skip.
    let Ok(_lock) = mkit_core::repo_lock::acquire(
        layout.worktree_state_dir(),
        super::WORKTREE_LOCK,
        std::time::Duration::from_millis(10),
    ) else {
        return;
    };
    let Ok(mut fresh) = index::read_index(layout) else {
        return;
    };
    let by_path: std::collections::HashMap<&str, &mkit_core::worktree::StatObservation> =
        observations.iter().map(|o| (o.path.as_str(), o)).collect();
    let mut updated = false;
    for e in &mut fresh.entries {
        let Some(obs) = by_path.get(e.path.as_str()) else {
            continue;
        };
        // Heal any clean-but-stale stat cache, not just the zero-mtime
        // first-observation case: a metadata-only touch (chmod, link
        // count, atime-bump that moved ctime) leaves nonzero-but-stale
        // fields whose content still hashes to the cached object. Those
        // would re-hash on EVERY future `status` until refreshed. When
        // the hash still matches, write back whichever stat fields drifted.
        if e.object_hash == obs.object_hash
            && (e.mtime_ns != obs.mtime_ns
                || e.size != obs.size
                || e.ino != obs.ino
                || e.ctime_ns != obs.ctime_ns)
        {
            e.mtime_ns = obs.mtime_ns;
            e.size = obs.size;
            e.ino = obs.ino;
            e.ctime_ns = obs.ctime_ns;
            updated = true;
        }
    }
    if updated {
        let _ = index::write_index(layout, &fresh);
    }
}

/// `--porcelain[=v1]` output — XY-code-plus-path, one entry per record.
/// Empty stdout means clean. Matches `git status --porcelain` for the
/// codes mkit and git share; `T ` (`ModeChanged`) is the only non-git
/// extension.
///
/// With `z = false` (default), records are newline-terminated and a path
/// containing special bytes is C-style quoted (matching git's default
/// `core.quotePath`). With `z = true` (`-z`), records are NUL-terminated
/// and paths are emitted **raw** (unquoted) — the round-trip-safe form
/// for paths that contain newlines or other special bytes.
fn render_porcelain(entries: &[StatusEntry], z: bool) -> u8 {
    let disp = |p: &str| super::c_quote_path(p).unwrap_or_else(|| p.to_string());
    let mut stdout = std::io::stdout().lock();
    for (xy, path, old_path) in combine_porcelain(entries) {
        // `xy` is two ASCII status columns by construction.
        let code = std::str::from_utf8(&xy).unwrap_or("??");
        match old_path {
            // Rename: git renders `old -> new` by default, and `new\0old\0`
            // under `-z` (destination first — verified against git).
            Some(old) if z => {
                let _ = write!(stdout, "{code} {path}\0{old}\0");
            }
            Some(old) => {
                let _ = writeln!(stdout, "{code} {} -> {}", disp(old), disp(path));
            }
            None if z => {
                let _ = write!(stdout, "{code} {path}\0");
            }
            None => {
                let _ = writeln!(stdout, "{code} {}", disp(path));
            }
        }
    }
    exit::OK
}

/// `--porcelain=v2` output — git's richer per-path format. Each changed
/// tracked path is a `1 <XY> <sub> <mH> <mI> <mW> <hH> <hI> <path>` line, a
/// rename is a `2 … <Xscore> <new>\t<old>` line (mkit pairs exact-content
/// moves, so the score is always `R100`), and (mkit having no submodules)
/// `<sub>` is always `N...`; untracked paths are `? <path>`.
///
/// `<XY>` uses `.` for an unchanged column (vs v1's space). `<mH>`/`<mI>` are
/// the HEAD/index octal modes, `<mW>` the worktree mode (`000000` when the
/// side is absent); `<hH>`/`<hI>` are the HEAD/index object ids (full 64-hex
/// BLAKE3 — longer than git's SHA-1, the documented hash-length divergence).
/// Without `--branch` there are no header lines, matching git.
fn render_porcelain_v2(
    store: &ObjectStore,
    head_tree: Option<&Hash>,
    layout: &RepoLayout,
    entries: &[StatusEntry],
    z: bool,
) -> u8 {
    // HEAD paths (mode+id) via a flattened tree; the effective staging index
    // (seeded from HEAD when no index file exists) for the index columns.
    let head_index = match head_tree {
        Some(h) => match index::from_tree(store, *h) {
            Ok(i) => i,
            Err(e) => return emit_err(&format!("read HEAD tree: {e}"), exit::GENERAL_ERROR),
        },
        None => Index::new(),
    };
    let work_index = match super::read_or_seed_index_from_head(layout, store) {
        Ok(i) => i,
        Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
    };

    let mut stdout = std::io::stdout().lock();
    for (xy, path, old_path) in combine_porcelain(entries) {
        if xy == [b'?', b'?'] {
            emit_v2_record(&mut stdout, "? ", path, z);
            continue;
        }
        // v2 uses `.` for an unchanged column, not a space.
        let x = if xy[0] == b' ' { '.' } else { xy[0] as char };
        let y = if xy[1] == b' ' { '.' } else { xy[1] as char };
        if let Some(old) = old_path {
            // `2` rename record. The HEAD side (mH/hH) describes the SOURCE
            // path; the index side (mI/hI) the DESTINATION. Exact content
            // means hH == hI and the score is `R100`. Verified vs git.
            let (m_head, h_head) = v2_mode_and_id(&head_index, old);
            let (m_index, h_index) = v2_mode_and_id(&work_index, path);
            let m_work = worktree_mode(layout.worktree_root(), path);
            let prefix =
                format!("2 {x}{y} N... {m_head} {m_index} {m_work} {h_head} {h_index} R100 ");
            emit_v2_rename_record(&mut stdout, &prefix, path, old, z);
            continue;
        }
        let (m_head, h_head) = v2_mode_and_id(&head_index, path);
        let (m_index, h_index) = v2_mode_and_id(&work_index, path);
        let m_work = worktree_mode(layout.worktree_root(), path);
        let prefix = format!("1 {x}{y} N... {m_head} {m_index} {m_work} {h_head} {h_index} ");
        emit_v2_record(&mut stdout, &prefix, path, z);
    }
    exit::OK
}

/// Write a v2 `2` rename record: `<prefix><dest><sep><src>` where `<sep>`
/// is a TAB by default and NUL under `-z` (destination first, then the
/// source — matching git). Paths are C-quoted when not in `-z` mode.
fn emit_v2_rename_record(out: &mut impl Write, prefix: &str, new: &str, old: &str, z: bool) {
    if z {
        let _ = write!(out, "{prefix}{new}\0{old}\0");
    } else {
        let nq = super::c_quote_path(new).unwrap_or_else(|| new.to_string());
        let oq = super::c_quote_path(old).unwrap_or_else(|| old.to_string());
        let _ = writeln!(out, "{prefix}{nq}\t{oq}");
    }
}

/// Write one v2 record: `<prefix><path>` with git's quoting/termination —
/// raw + NUL under `-z`, else C-style quoted + newline.
fn emit_v2_record(out: &mut impl Write, prefix: &str, path: &str, z: bool) {
    if z {
        let _ = write!(out, "{prefix}{path}\0");
    } else if let Some(quoted) = super::c_quote_path(path) {
        let _ = writeln!(out, "{prefix}{quoted}");
    } else {
        let _ = writeln!(out, "{prefix}{path}");
    }
}

/// The octal mode and full object id for `path` in `index` (a real index or a
/// flattened HEAD tree). Absent / removed → `000000` and the all-zero id.
fn v2_mode_and_id(index: &Index, path: &str) -> (&'static str, String) {
    match index.find_entry(path) {
        Some(i) if index.entries[i].status != EntryStatus::Removed => {
            let e = &index.entries[i];
            (git_mode(e.status), format::hex_hash(&e.object_hash))
        }
        _ => ("000000", format::hex_hash(&mkit_core::hash::ZERO)),
    }
}

/// git octal mode for an index entry's status.
fn git_mode(status: EntryStatus) -> &'static str {
    match status {
        EntryStatus::Executable => "100755",
        EntryStatus::Symlink => "120000",
        _ => "100644",
    }
}

/// The worktree octal mode for `path`. `000000` unless the path is a
/// *stageable* worktree object — a regular file or a symlink. A directory
/// (or any other non-file type) at a tracked file path is **not** a valid
/// worktree side for that path: status reports the tracked file as deleted
/// (`mW = 000000`) and surfaces anything inside as a separate `?` record,
/// so reporting `040000` here would misrepresent it as still present.
fn worktree_mode(root: &Path, path: &str) -> &'static str {
    let Ok(meta) = std::fs::symlink_metadata(root.join(path)) else {
        return "000000";
    };
    if meta.is_symlink() {
        "120000"
    } else if meta.is_file() {
        if is_executable(&meta) {
            "100755"
        } else {
            "100644"
        }
    } else {
        "000000"
    }
}

#[cfg(unix)]
fn is_executable(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_meta: &std::fs::Metadata) -> bool {
    false
}

/// Collapse `status_diff`'s per-(staging) entries into porcelain records,
/// matching `git status --porcelain`.
///
/// A path that is staged **and** further changed in the worktree produces
/// a single combined code (e.g. `MM`, `AM`) rather than two records: `X`
/// is the staged (index-vs-HEAD) side, `Y` the unstaged (worktree-vs-index)
/// side, and `porcelain_code` already returns each side in its column, so
/// we OR the non-space columns together.
///
/// **Untracked entries are the exception** — git treats them as a separate
/// category, never folded into a tracked path's `XY`. A path can be both
/// staged-for-deletion *and* present as untracked on disk (`mkit rm
/// --cached <f>` with the file still there): git emits **two** records,
/// `D  <f>` then `?? <f>`. So an untracked entry (`Unstaged` + `Added`)
/// always becomes its own `??` record and is never merged — otherwise the
/// `??` would clobber the staged `D `, hiding a deletion `commit` records.
///
/// Output order matches git: all tracked-change records first (first-seen
/// order), then all untracked records.
fn combine_porcelain(entries: &[StatusEntry]) -> Vec<([u8; 2], &str, Option<&str>)> {
    let mut tracked_order: Vec<&str> = Vec::new();
    // value = (XY columns, source path for a rename).
    let mut tracked: std::collections::HashMap<&str, ([u8; 2], Option<&str>)> =
        std::collections::HashMap::new();
    let mut untracked: Vec<&str> = Vec::new();
    for e in entries {
        // Untracked: a worktree path the index doesn't know about. Never
        // merged — it is always its own `??` record (see doc comment).
        if e.staging == StatusStaging::Unstaged && e.diff.kind == DiffKind::Added {
            untracked.push(&e.diff.path);
            continue;
        }
        let c = porcelain_code(e.staging, e.diff.kind).as_bytes();
        let slot = tracked.entry(&e.diff.path).or_insert_with(|| {
            tracked_order.push(&e.diff.path);
            ([b' ', b' '], None)
        });
        // Fill each column from whichever entry sets it (non-space wins).
        if c[0] != b' ' {
            slot.0[0] = c[0];
        }
        if c[1] != b' ' {
            slot.0[1] = c[1];
        }
        // A rename keyed by its destination path carries the source path
        // (e.g. an `RM` entry: renamed in index, modified in worktree).
        if e.diff.kind == DiffKind::Renamed {
            slot.1 = e.diff.old_path.as_deref();
        }
    }
    let mut out: Vec<([u8; 2], &str, Option<&str>)> = tracked_order
        .into_iter()
        .map(|p| {
            let s = tracked[p];
            (s.0, p, s.1)
        })
        .collect();
    out.extend(untracked.into_iter().map(|p| ([b'?', b'?'], p, None)));
    out
}

/// Map (staging, kind) → two-char XY code per the porcelain format.
fn porcelain_code(staging: StatusStaging, kind: DiffKind) -> &'static str {
    match (staging, kind) {
        (StatusStaging::Staged, DiffKind::Added) => "A ",
        (StatusStaging::Staged, DiffKind::Removed) => "D ",
        (StatusStaging::Staged, DiffKind::Modified) => "M ",
        (StatusStaging::Staged, DiffKind::ModeChanged) => "T ",
        // Unstaged Added with an index present means the worktree has
        // a path the index doesn't know about — i.e. untracked. With
        // no index, every worktree-only entry is also untracked.
        (StatusStaging::Unstaged, DiffKind::Added) => "??",
        (StatusStaging::Unstaged, DiffKind::Removed) => " D",
        (StatusStaging::Unstaged, DiffKind::Modified) => " M",
        (StatusStaging::Unstaged, DiffKind::ModeChanged) => " T",
        // PartiallyStaged is documented as retained-for-back-compat
        // and no longer produced by status_diff post-#102, but render
        // defensively in case it ever resurfaces. `MM` matches git's
        // double-mod indicator.
        (StatusStaging::PartiallyStaged, DiffKind::Added) => "AM",
        (StatusStaging::PartiallyStaged, DiffKind::Removed) => "MD",
        (StatusStaging::PartiallyStaged, DiffKind::Modified) => "MM",
        (StatusStaging::PartiallyStaged, DiffKind::ModeChanged) => "MT",
        // Renames are detected per staging leg, so they only ever appear
        // as a clean staged (`R `) or unstaged (` R`) move; PartiallyStaged
        // can't be produced for a rename but is rendered defensively.
        (StatusStaging::Staged | StatusStaging::PartiallyStaged, DiffKind::Renamed) => "R ",
        (StatusStaging::Unstaged, DiffKind::Renamed) => " R",
    }
}

/// Default human output, git-shaped. All lines go to stderr — stdout is
/// reserved for porcelain/data callers (an mkit convention; documented in
/// docs/CLI.md). A consumer that wants the human format in a pipeline can
/// `mkit status 2>&1` explicitly; the default pipeline behaviour stays
/// empty-on-clean. The (use "mkit …") hints name mkit commands, not git.
fn render_human(layout: &RepoLayout, entries: &[StatusEntry]) -> u8 {
    let mut stderr = std::io::stderr().lock();

    // Branch / HEAD line, matching git's banners.
    match refs::read_head(layout) {
        Ok(refs::Head::Branch(name)) => {
            let _ = writeln!(stderr, "On branch {name}");
            if refs::resolve_head(layout).ok().flatten().is_none() {
                let _ = writeln!(stderr, "\nNo commits yet");
            }
        }
        Ok(refs::Head::Detached(h)) => {
            let _ = writeln!(
                stderr,
                "HEAD detached at {}",
                crate::format::short_hash(&h, crate::format::SUMMARY_ABBREV)
            );
        }
        Err(_) => {
            let _ = writeln!(stderr, "On branch main\n\nNo commits yet");
        }
    }

    if entries.is_empty() {
        let _ = writeln!(stderr, "\nnothing to commit, working tree clean");
        return exit::OK;
    }

    // An untracked path is an unstaged addition (porcelain `??`); git lists
    // those in their own section, separate from tracked-but-unstaged edits.
    let staged: Vec<_> = entries
        .iter()
        .filter(|e| e.staging == StatusStaging::Staged)
        .collect();
    let partial: Vec<_> = entries
        .iter()
        .filter(|e| e.staging == StatusStaging::PartiallyStaged)
        .collect();
    let unstaged: Vec<_> = entries
        .iter()
        .filter(|e| e.staging == StatusStaging::Unstaged && e.diff.kind != DiffKind::Added)
        .collect();
    let untracked: Vec<_> = entries
        .iter()
        .filter(|e| e.staging == StatusStaging::Unstaged && e.diff.kind == DiffKind::Added)
        .collect();

    if !staged.is_empty() {
        let _ = writeln!(stderr, "\nChanges to be committed:");
        let _ = writeln!(
            stderr,
            "  (use \"mkit restore --staged <file>...\" to unstage)"
        );
        for e in &staged {
            let _ = writeln!(stderr, "	{:<12}{}", human_label(e.diff.kind), human_path(e));
        }
    }
    if !partial.is_empty() {
        let _ = writeln!(stderr, "\nChanges both staged and not staged:");
        for e in &partial {
            let _ = writeln!(stderr, "	{:<12}{}", human_label(e.diff.kind), human_path(e));
        }
    }
    if !unstaged.is_empty() {
        let _ = writeln!(stderr, "\nChanges not staged for commit:");
        let _ = writeln!(
            stderr,
            "  (use \"mkit add <file>...\" to update what will be committed)"
        );
        let _ = writeln!(
            stderr,
            "  (use \"mkit restore <file>...\" to discard changes in working directory)"
        );
        for e in &unstaged {
            let _ = writeln!(stderr, "	{:<12}{}", human_label(e.diff.kind), human_path(e));
        }
    }
    if !untracked.is_empty() {
        let _ = writeln!(stderr, "\nUntracked files:");
        let _ = writeln!(
            stderr,
            "  (use \"mkit add <file>...\" to include in what will be committed)"
        );
        for e in &untracked {
            let _ = writeln!(stderr, "\t{}", e.diff.path);
        }
    }

    // Footer guidance, like git's.
    if staged.is_empty() && partial.is_empty() {
        if !unstaged.is_empty() {
            let _ = writeln!(
                stderr,
                "\nno changes added to commit (use \"mkit add\" and/or \"mkit commit -a\")"
            );
        } else if !untracked.is_empty() {
            let _ = writeln!(
                stderr,
                "\nnothing added to commit but untracked files present (use \"mkit add\" to track)"
            );
        }
    }

    exit::OK
}

/// git's word label for a change kind.
fn human_label(kind: DiffKind) -> &'static str {
    match kind {
        DiffKind::Added => "new file:",
        DiffKind::Removed => "deleted:",
        DiffKind::Modified => "modified:",
        DiffKind::ModeChanged => "typechange:",
        DiffKind::Renamed => "renamed:",
    }
}

/// The path column for the human listing. A rename renders `old -> new`
/// (git's form); every other kind is just its path.
fn human_path(e: &StatusEntry) -> String {
    match (e.diff.kind, &e.diff.old_path) {
        (DiffKind::Renamed, Some(old)) => format!("{old} -> {}", e.diff.path),
        _ => e.diff.path.clone(),
    }
}

/// Pair identical-content staged deletes and adds into single `Renamed`
/// entries, matching git's rename detection in `status`.
///
/// Scoped to the staged leg: `git mv` (and `mkit mv`) stage both sides, so
/// they share a staging state and — because mkit is content-addressed — an
/// object id. An *unstaged* move leaves the destination untracked (`??`),
/// which git never folds into a rename, so the worktree leg is left alone.
fn detect_status_renames(entries: Vec<StatusEntry>) -> Vec<StatusEntry> {
    let (staged, others): (Vec<StatusEntry>, Vec<StatusEntry>) = entries
        .into_iter()
        .partition(|e| e.staging == StatusStaging::Staged);
    let mut staged_diffs: Vec<DiffEntry> = staged.into_iter().map(|e| e.diff).collect();
    detect_exact_renames(&mut staged_diffs);
    let mut out: Vec<StatusEntry> = staged_diffs
        .into_iter()
        .map(|d| StatusEntry {
            diff: d,
            staging: StatusStaging::Staged,
        })
        .chain(others)
        .collect();
    // Restore status's canonical order: by path, staged before unstaged.
    out.sort_by(|a, b| {
        a.diff
            .path
            .cmp(&b.diff.path)
            .then_with(|| staging_rank(a.staging).cmp(&staging_rank(b.staging)))
    });
    out
}

fn staging_rank(s: StatusStaging) -> u8 {
    match s {
        StatusStaging::Staged => 0,
        StatusStaging::PartiallyStaged => 1,
        StatusStaging::Unstaged => 2,
    }
}

use super::error as emit_err;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn porcelain_code_matrix() {
        // Spot-check the matrix corners.
        assert_eq!(porcelain_code(StatusStaging::Staged, DiffKind::Added), "A ",);
        assert_eq!(
            porcelain_code(StatusStaging::Staged, DiffKind::Removed),
            "D ",
        );
        assert_eq!(
            porcelain_code(StatusStaging::Staged, DiffKind::Modified),
            "M ",
        );
        assert_eq!(
            porcelain_code(StatusStaging::Unstaged, DiffKind::Added),
            "??",
        );
        assert_eq!(
            porcelain_code(StatusStaging::Unstaged, DiffKind::Modified),
            " M",
        );
        assert_eq!(
            porcelain_code(StatusStaging::Unstaged, DiffKind::Removed),
            " D",
        );
    }

    fn entry(path: &str, staging: StatusStaging, kind: DiffKind) -> StatusEntry {
        StatusEntry {
            diff: mkit_core::ops::DiffEntry {
                path: path.to_string(),
                kind,
                old_hash: None,
                new_hash: None,
                old_mode: None,
                new_mode: None,
                old_path: None,
            },
            staging,
        }
    }

    fn combined(entries: &[StatusEntry]) -> Vec<(String, String)> {
        combine_porcelain(entries)
            .into_iter()
            .map(|(xy, p, _)| (std::str::from_utf8(&xy).unwrap().to_string(), p.to_string()))
            .collect()
    }

    #[test]
    fn combine_merges_staged_and_unstaged_same_path_into_one_record() {
        use DiffKind::Modified;
        use StatusStaging::{Staged, Unstaged};
        // Staged modify + further worktree modify on the same path → one
        // `MM a.txt` record, not two (git porcelain semantics).
        let entries = [
            entry("a.txt", Staged, Modified),
            entry("a.txt", Unstaged, Modified),
        ];
        assert_eq!(combined(&entries), vec![("MM".into(), "a.txt".into())]);
    }

    #[test]
    fn combine_staged_add_plus_worktree_modify_is_am() {
        let entries = [
            entry("n.txt", StatusStaging::Staged, DiffKind::Added),
            entry("n.txt", StatusStaging::Unstaged, DiffKind::Modified),
        ];
        assert_eq!(combined(&entries), vec![("AM".into(), "n.txt".into())]);
    }

    #[test]
    fn combine_preserves_lone_records_and_untracked() {
        let entries = [
            entry("staged.txt", StatusStaging::Staged, DiffKind::Added),
            entry("dirty.txt", StatusStaging::Unstaged, DiffKind::Modified),
            entry("new.txt", StatusStaging::Unstaged, DiffKind::Added), // untracked → ??
        ];
        assert_eq!(
            combined(&entries),
            vec![
                ("A ".into(), "staged.txt".into()),
                (" M".into(), "dirty.txt".into()),
                ("??".into(), "new.txt".into()),
            ]
        );
    }

    #[test]
    fn combine_keeps_staged_delete_and_untracked_at_same_path_separate() {
        use DiffKind::{Added, Removed};
        use StatusStaging::{Staged, Unstaged};
        // `mkit rm --cached a.txt` with the file still on disk: the index
        // dropped a.txt (staged delete vs HEAD → `D `) but the worktree
        // still has it, unknown to the index (untracked → `??`). Git emits
        // BOTH records — the staged deletion must not be clobbered by `??`.
        let entries = [
            entry("a.txt", Staged, Removed),
            entry("a.txt", Unstaged, Added),
        ];
        assert_eq!(
            combined(&entries),
            vec![("D ".into(), "a.txt".into()), ("??".into(), "a.txt".into())]
        );
    }

    #[test]
    fn combine_orders_all_tracked_before_untracked_like_git() {
        use DiffKind::{Added, Modified, Removed};
        use StatusStaging::{Staged, Unstaged};
        // Mixed: staged-delete-with-untracked (a.txt), a tracked unstaged
        // modify (m.txt), and a pure untracked file (b.txt). Git groups all
        // tracked changes first, then all `??` records.
        let entries = [
            entry("a.txt", Staged, Removed),
            entry("a.txt", Unstaged, Added),
            entry("m.txt", Unstaged, Modified),
            entry("b.txt", Unstaged, Added),
        ];
        assert_eq!(
            combined(&entries),
            vec![
                ("D ".into(), "a.txt".into()),
                (" M".into(), "m.txt".into()),
                ("??".into(), "a.txt".into()),
                ("??".into(), "b.txt".into()),
            ]
        );
    }

    #[test]
    fn porcelain_codes_are_two_chars() {
        use DiffKind::{Added, ModeChanged, Modified, Removed};
        use StatusStaging::{PartiallyStaged, Staged, Unstaged};
        for s in [Staged, Unstaged, PartiallyStaged] {
            for k in [Added, Removed, Modified, ModeChanged] {
                assert_eq!(porcelain_code(s, k).len(), 2, "{s:?} + {k:?}");
            }
        }
    }
}
