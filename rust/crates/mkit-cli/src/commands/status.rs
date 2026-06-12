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
//! `? <path>` records. mkit emits no rename (`2`) records — it has no
//! rename detection — and no `--branch` header lines. Path quoting and
//! `-z` semantics match the v1 renderer.

use std::io::Write;

use std::path::Path;

use clap::{Parser, ValueEnum};
use mkit_core::Hash;
use mkit_core::index::{self, EntryStatus, Index};
use mkit_core::ops::{DiffKind, StatusEntry, StatusStaging, status_diff_observed};
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
    let store = match ObjectStore::open(&cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);

    // Resolve HEAD tree hash (None on a HEAD-less repo). Use the shared
    // helper so a `Remix` HEAD is compared against its tree like every
    // other command, not treated as "no HEAD".
    let head_tree: Option<mkit_core::Hash> = match super::current_head_tree(&cwd, &store) {
        Ok(t) => t,
        Err(e) => return emit_err(&format!("status: {e}"), exit::GENERAL_ERROR),
    };

    // Load the index, falling back to None only when absent/empty.
    // Corrupt or invalid persisted state must surface instead of
    // silently reverting to the HEAD<->worktree comparison.
    let idx = match index::read_index(&cwd) {
        Ok(idx) if idx.entries.is_empty() => None,
        Ok(idx) => Some(idx),
        Err(e) => return emit_err(&format!("read index: {e}"), exit::GENERAL_ERROR),
    };

    let (entries, observations) =
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
        refresh_stat_cache(&cwd, &observations);
    }

    if porcelain {
        if opts.porcelain == Some(PorcelainVersion::V2) {
            render_porcelain_v2(&store, head_tree.as_ref(), &cwd, &entries, opts.z)
        } else {
            render_porcelain(&entries, opts.z)
        }
    } else {
        render_human(&mkit_dir, &entries)
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
fn refresh_stat_cache(root: &Path, observations: &[mkit_core::worktree::StatObservation]) {
    if observations.is_empty() {
        return;
    }
    // Version sniff: never auto-upgrade a v1 index from a query command.
    match std::fs::File::open(mkit_core::index::index_path(root)) {
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
        &root.join(mkit_core::MKIT_DIR),
        super::WORKTREE_LOCK,
        std::time::Duration::from_millis(10),
    ) else {
        return;
    };
    let Ok(mut fresh) = index::read_index(root) else {
        return;
    };
    let by_path: std::collections::HashMap<&str, &mkit_core::worktree::StatObservation> =
        observations.iter().map(|o| (o.path.as_str(), o)).collect();
    let mut updated = false;
    for e in &mut fresh.entries {
        let Some(obs) = by_path.get(e.path.as_str()) else {
            continue;
        };
        if e.mtime_ns == 0 && e.object_hash == obs.object_hash {
            e.mtime_ns = obs.mtime_ns;
            e.size = obs.size;
            e.ino = obs.ino;
            e.ctime_ns = obs.ctime_ns;
            updated = true;
        }
    }
    if updated {
        let _ = index::write_index(root, &fresh);
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
    let mut stdout = std::io::stdout().lock();
    for (xy, path) in combine_porcelain(entries) {
        // `xy` is two ASCII status columns by construction.
        let code = std::str::from_utf8(&xy).unwrap_or("??");
        if z {
            let _ = write!(stdout, "{code} {path}\0");
        } else if let Some(quoted) = super::c_quote_path(path) {
            let _ = writeln!(stdout, "{code} {quoted}");
        } else {
            let _ = writeln!(stdout, "{code} {path}");
        }
    }
    exit::OK
}

/// `--porcelain=v2` output — git's richer per-path format. Each changed
/// tracked path is a `1 <XY> <sub> <mH> <mI> <mW> <hH> <hI> <path>` line
/// (mkit emits no rename `2` lines — it has no rename detection — and no
/// submodules, so `<sub>` is always `N...`); untracked paths are `? <path>`.
///
/// `<XY>` uses `.` for an unchanged column (vs v1's space). `<mH>`/`<mI>` are
/// the HEAD/index octal modes, `<mW>` the worktree mode (`000000` when the
/// side is absent); `<hH>`/`<hI>` are the HEAD/index object ids (full 64-hex
/// BLAKE3 — longer than git's SHA-1, the documented hash-length divergence).
/// Without `--branch` there are no header lines, matching git.
fn render_porcelain_v2(
    store: &ObjectStore,
    head_tree: Option<&Hash>,
    root: &Path,
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
    let work_index = match super::read_or_seed_index_from_head(root, store) {
        Ok(i) => i,
        Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
    };

    let mut stdout = std::io::stdout().lock();
    for (xy, path) in combine_porcelain(entries) {
        if xy == [b'?', b'?'] {
            emit_v2_record(&mut stdout, "? ", path, z);
            continue;
        }
        // v2 uses `.` for an unchanged column, not a space.
        let x = if xy[0] == b' ' { '.' } else { xy[0] as char };
        let y = if xy[1] == b' ' { '.' } else { xy[1] as char };
        let (m_head, h_head) = v2_mode_and_id(&head_index, path);
        let (m_index, h_index) = v2_mode_and_id(&work_index, path);
        let m_work = worktree_mode(root, path);
        let prefix = format!("1 {x}{y} N... {m_head} {m_index} {m_work} {h_head} {h_index} ");
        emit_v2_record(&mut stdout, &prefix, path, z);
    }
    exit::OK
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
fn combine_porcelain(entries: &[StatusEntry]) -> Vec<([u8; 2], &str)> {
    let mut tracked_order: Vec<&str> = Vec::new();
    let mut tracked: std::collections::HashMap<&str, [u8; 2]> = std::collections::HashMap::new();
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
            [b' ', b' ']
        });
        // Fill each column from whichever entry sets it (non-space wins).
        if c[0] != b' ' {
            slot[0] = c[0];
        }
        if c[1] != b' ' {
            slot[1] = c[1];
        }
    }
    let mut out: Vec<([u8; 2], &str)> =
        tracked_order.into_iter().map(|p| (tracked[p], p)).collect();
    out.extend(untracked.into_iter().map(|p| ([b'?', b'?'], p)));
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
    }
}

/// Default human output. All lines go to stderr — stdout is reserved
/// for porcelain/data callers. A consumer that wants the human format
/// in a pipeline can `mkit status 2>&1` explicitly; the default
/// pipeline behaviour stays empty-on-clean.
fn render_human(mkit_dir: &std::path::Path, entries: &[StatusEntry]) -> u8 {
    let mut stderr = std::io::stderr().lock();

    // Branch / HEAD line.
    match refs::read_head(mkit_dir) {
        Ok(refs::Head::Branch(name)) => {
            let _ = writeln!(stderr, "on branch {name}");
        }
        Ok(refs::Head::Detached(h)) => {
            let _ = writeln!(stderr, "detached HEAD at {}", mkit_core::hash::to_hex(&h));
        }
        Err(_) => {
            let _ = writeln!(stderr, "no HEAD yet");
        }
    }

    if entries.is_empty() {
        let _ = writeln!(stderr, "nothing to commit, working tree clean");
        return exit::OK;
    }

    let staged: Vec<_> = entries
        .iter()
        .filter(|e| e.staging == StatusStaging::Staged)
        .collect();
    let unstaged: Vec<_> = entries
        .iter()
        .filter(|e| e.staging == StatusStaging::Unstaged)
        .collect();
    let partial: Vec<_> = entries
        .iter()
        .filter(|e| e.staging == StatusStaging::PartiallyStaged)
        .collect();

    if !staged.is_empty() {
        let _ = writeln!(stderr, "\nChanges to be committed:");
        for e in &staged {
            let tag = diff_tag(e.diff.kind);
            let _ = writeln!(stderr, "  {tag}  {}", e.diff.path);
        }
    }
    if !unstaged.is_empty() {
        let _ = writeln!(stderr, "\nChanges not staged for commit:");
        for e in &unstaged {
            let tag = diff_tag(e.diff.kind);
            let _ = writeln!(stderr, "  {tag}  {}", e.diff.path);
        }
    }
    if !partial.is_empty() {
        let _ = writeln!(stderr, "\nChanges partially staged:");
        for e in &partial {
            let tag = diff_tag(e.diff.kind);
            let _ = writeln!(stderr, "  {tag}  {}", e.diff.path);
        }
    }

    exit::OK
}

fn diff_tag(kind: DiffKind) -> &'static str {
    match kind {
        DiffKind::Added => "A",
        DiffKind::Removed => "D",
        DiffKind::Modified => "M",
        DiffKind::ModeChanged => "T",
    }
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}

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
            },
            staging,
        }
    }

    fn combined(entries: &[StatusEntry]) -> Vec<(String, String)> {
        combine_porcelain(entries)
            .into_iter()
            .map(|(xy, p)| (std::str::from_utf8(&xy).unwrap().to_string(), p.to_string()))
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
