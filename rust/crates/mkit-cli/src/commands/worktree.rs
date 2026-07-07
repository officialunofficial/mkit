//! `mkit worktree` — manage linked working trees (#493 Phase 2).
//!
//! `add <path> [<commit-ish>]`, `list [--porcelain]`,
//! `remove [--force] <path>`, `prune [--dry-run]`, with git's
//! semantics: every linked tree shares the one object store and the
//! shared refs; each tree has its own HEAD, index, and in-progress-op
//! state (see `mkit_core::layout` for the split). Registry mutations
//! serialise on the common-dir `worktrees.lock`.
//!
//! Crash-ordering in `add`: the per-tree state dir (commondir,
//! back-pointer, HEAD) is fully written BEFORE the tree's pointer
//! file, so a crash in between leaves only a prunable registry orphan,
//! never a tree that points at half-built state. Materialization runs
//! last, into a fresh directory — a crash mid-restore leaves a valid
//! worktree with missing files that `checkout --force` heals.

use std::io::Write;
use std::path::{Path, PathBuf};

use mkit_core::hash::Hash;
use mkit_core::layout::{self, RepoLayout};
use mkit_core::object::Object;
use mkit_core::refs::{self, RefWriteCondition};
use mkit_core::store::ObjectStore;

use crate::clap_shim;
use crate::exit;
use crate::format;
use clap::Parser;
use clap::Subcommand;

#[derive(Debug, Parser)]
#[command(name = "mkit worktree", about = "Manage linked working trees.")]
struct WorktreeOpts {
    #[command(subcommand)]
    sub: WorktreeCmd,
}

#[derive(Debug, Subcommand)]
enum WorktreeCmd {
    /// Create a linked working tree at <path>.
    ///
    /// With no <commit-ish>, creates a new branch named after the
    /// path's basename (refusing if it exists). A branch <commit-ish>
    /// is checked out (refusing if some other tree already has it);
    /// any other revision yields a detached HEAD.
    Add {
        path: String,
        commit_ish: Option<String>,
    },
    /// List the main and every linked working tree.
    List {
        /// Stable, script-friendly block output (like git's).
        #[arg(long)]
        porcelain: bool,
    },
    /// Remove a linked working tree and its state dir.
    Remove {
        /// Remove even if the tree has local changes or an operation
        /// in progress.
        #[arg(long, short)]
        force: bool,
        path: String,
    },
    /// Delete registry entries whose linked tree is gone.
    Prune {
        /// Report what would be pruned without deleting anything.
        #[arg(long)]
        dry_run: bool,
    },
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<WorktreeOpts>("mkit worktree", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(c) => c,
        Err(e) => return super::error(&format!("cwd: {e}"), exit::CONFIG_ERROR),
    };
    let layout = match super::resolve_layout(&cwd) {
        Ok(layout) => layout,
        Err(code) => return code,
    };

    match opts.sub {
        WorktreeCmd::Add { path, commit_ish } => add(&layout, &cwd, &path, commit_ish.as_deref()),
        WorktreeCmd::List { porcelain } => list(&layout, porcelain),
        WorktreeCmd::Remove { force, path } => remove(&layout, &cwd, &path, force),
        WorktreeCmd::Prune { dry_run } => prune(&layout, dry_run),
    }
}

// ─── add ────────────────────────────────────────────────────────────

/// What `add` will point the new tree's HEAD at.
enum HeadPlan {
    /// Create `branch` at `start` (condition Missing), HEAD symbolic.
    NewBranch { branch: String, start: Hash },
    /// HEAD symbolic to an existing branch at `tip`.
    ExistingBranch { branch: String, tip: Hash },
    /// Detached HEAD at the commit.
    Detached(Hash),
}

fn add(layout: &RepoLayout, cwd: &Path, path: &str, commit_ish: Option<&str>) -> u8 {
    let store = match super::open_store_configured(layout) {
        Ok(s) => s,
        Err(e) => return super::error(&format!("open store: {e}"), exit::UNAVAILABLE),
    };

    // Absolutize the target (canonicalizing through the deepest
    // existing ancestor — it does not fully exist yet).
    let target = canonical_or_lexical(&absolutize(cwd, Path::new(path)));
    if let Err(code) = check_add_target(layout, &target) {
        return code;
    }
    let plan = match plan_head(layout, &store, &target, commit_ish) {
        Ok(p) => p,
        Err(code) => return code,
    };

    let commit_hash = match &plan {
        HeadPlan::NewBranch { start, .. } => *start,
        HeadPlan::ExistingBranch { tip, .. } => *tip,
        HeadPlan::Detached(h) => *h,
    };
    let tree_hash = match store.read_object(&commit_hash) {
        Ok(Object::Commit(c)) => c.tree_hash,
        Ok(Object::Remix(r)) => r.tree_hash,
        Ok(_) => {
            return super::error(
                &format!(
                    "{} does not resolve to a commit or remix",
                    format::short_hash(&commit_hash, 8)
                ),
                exit::DATAERR,
            );
        }
        Err(e) => return super::error(&format!("read commit: {e}"), exit::GENERAL_ERROR),
    };
    if let Err(code) = create_worktree(layout, &store, &plan, &target, tree_hash) {
        return code;
    }

    let mut stdout = std::io::stdout().lock();
    match &plan {
        HeadPlan::NewBranch { branch, .. } => {
            let _ = writeln!(stdout, "Preparing worktree (new branch '{branch}')");
        }
        HeadPlan::ExistingBranch { branch, .. } => {
            let _ = writeln!(stdout, "Preparing worktree (checking out '{branch}')");
        }
        HeadPlan::Detached(h) => {
            let _ = writeln!(
                stdout,
                "Preparing worktree (detached HEAD {})",
                format::short_hash(h, 8)
            );
        }
    }
    let _ = writeln!(
        stdout,
        "HEAD is now at {} {}",
        format::short_hash(&commit_hash, 8),
        super::commit_subject(&store, &commit_hash)
    );
    exit::OK
}

/// Refuse targets nested in an existing worktree, or non-empty ones.
fn check_add_target(layout: &RepoLayout, target: &Path) -> Result<(), u8> {
    // Containment: never nest a linked tree inside an existing
    // worktree of this repository — the tree walkers treat a nested
    // `.mkit` as a foreign-repo boundary, which would make the outer
    // tree silently skip the inner one.
    let siblings =
        super::all_worktree_layouts(layout).map_err(|e| super::error(&e, exit::DATAERR))?;
    for (tree_root, _) in &siblings {
        let root = canonical_or_lexical(tree_root);
        if target.starts_with(&root) {
            return Err(super::error(
                &format!(
                    "'{}' is inside the worktree at '{}'; choose a path outside every \
                     existing worktree",
                    target.display(),
                    tree_root.display()
                ),
                exit::USAGE,
            ));
        }
    }
    match std::fs::read_dir(target) {
        Ok(mut entries) => {
            if entries.next().is_some() {
                return Err(super::error(
                    &format!("'{}' already exists and is not empty", target.display()),
                    exit::CANTCREAT,
                ));
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) if target.exists() => Err(super::error(
            &format!(
                "'{}' already exists and is not a directory",
                target.display()
            ),
            exit::CANTCREAT,
        )),
        Err(e) => Err(super::error(
            &format!("inspect '{}': {e}", target.display()),
            exit::GENERAL_ERROR,
        )),
    }
}

/// Decide the new tree's HEAD and enforce single-writer-per-branch.
fn plan_head(
    layout: &RepoLayout,
    store: &ObjectStore,
    target: &Path,
    commit_ish: Option<&str>,
) -> Result<HeadPlan, u8> {
    let plan = match commit_ish {
        None => {
            let Some(branch) = branch_name_from_path(target) else {
                return Err(super::error(
                    &format!(
                        "cannot derive a branch name from '{}'; pass a commit-ish",
                        target.display()
                    ),
                    exit::USAGE,
                ));
            };
            if matches!(refs::read_ref(layout, &branch), Ok(Some(_))) {
                return Err(super::error(
                    &format!(
                        "branch '{branch}' already exists; pass it explicitly to check it out"
                    ),
                    exit::CANTCREAT,
                ));
            }
            let start = match refs::resolve_head(layout) {
                Ok(Some(h)) => h,
                Ok(None) => {
                    return Err(super::error(
                        "cannot add a worktree: the repository has no commits yet",
                        exit::DATAERR,
                    ));
                }
                Err(e) => return Err(super::error(&format!("resolve HEAD: {e}"), exit::DATAERR)),
            };
            HeadPlan::NewBranch { branch, start }
        }
        Some(spec) => match refs::read_ref(layout, spec) {
            Ok(Some(tip)) => HeadPlan::ExistingBranch {
                branch: spec.to_string(),
                tip,
            },
            _ => match super::revspec::resolve_revision(store, layout, spec) {
                Ok(h) => HeadPlan::Detached(h),
                Err(e) => {
                    return Err(super::error(
                        &format!("no such branch, tag, or commit: {spec} ({e})"),
                        exit::GENERAL_ERROR,
                    ));
                }
            },
        },
    };

    // Single-writer-per-branch: a branch may be checked out in at most
    // one tree (the history-MMR ref-write path assumes it).
    if let HeadPlan::ExistingBranch { branch, .. } | HeadPlan::NewBranch { branch, .. } = &plan {
        match super::branch_checked_out_elsewhere(layout, branch) {
            Ok(Some(at)) => {
                return Err(super::error(
                    &format!(
                        "branch '{branch}' is already checked out at '{}'",
                        at.display()
                    ),
                    exit::DATAERR,
                ));
            }
            Ok(None) => {}
            Err(e) => return Err(super::error(&e, exit::DATAERR)),
        }
        // The invoking tree too: the helper deliberately skips self.
        if matches!(refs::read_head(layout), Ok(refs::Head::Branch(ref cur)) if cur == branch) {
            return Err(super::error(
                &format!("branch '{branch}' is already checked out in this worktree"),
                exit::DATAERR,
            ));
        }
    }
    Ok(plan)
}

/// Registry + state dir + refs + pointer + materialization, in the
/// crash-safe order documented in the module header.
fn create_worktree(
    layout: &RepoLayout,
    store: &ObjectStore,
    plan: &HeadPlan,
    target: &Path,
    tree_hash: Hash,
) -> Result<(), u8> {
    // Registry mutation begins: serialise against sibling add/remove/
    // prune, and against `checkout` (which holds this lock across its
    // own guard + HEAD write). (Ref creation below additionally
    // serialises on the refs-history lock, as every branch write does.)
    let _lock = super::acquire_worktrees_registry_lock(layout)?;

    // Re-verify single-writer-per-branch now that the registry is
    // frozen: the pre-lock check in `plan_head` raced sibling
    // checkouts/adds; this one cannot.
    if let HeadPlan::ExistingBranch { branch, .. } | HeadPlan::NewBranch { branch, .. } = plan {
        match super::branch_checked_out_elsewhere(layout, branch) {
            Ok(None) => {}
            Ok(Some(at)) => {
                return Err(super::error(
                    &format!(
                        "branch '{branch}' is already checked out at '{}'",
                        at.display()
                    ),
                    exit::DATAERR,
                ));
            }
            Err(e) => return Err(super::error(&e, exit::DATAERR)),
        }
    }

    let Some(id) = free_worktree_id(layout, target) else {
        return Err(super::error(
            &format!("cannot derive a worktree id from '{}'", target.display()),
            exit::USAGE,
        ));
    };
    let state_dir = layout.worktree_state_dir_for(&id);
    let linked = RepoLayout::linked(target, &state_dir, layout.common_dir());

    // 1. Per-tree state dir, fully populated before the pointer file
    //    exists anywhere (crash ⇒ prunable orphan, never a live tree
    //    pointing at half-built state).
    if let Err(e) = std::fs::create_dir_all(&state_dir) {
        return Err(super::error(
            &format!("create state dir: {e}"),
            exit::CANTCREAT,
        ));
    }
    let steps: [(&str, std::io::Result<()>); 2] = [
        (
            "commondir",
            std::fs::write(state_dir.join(layout::COMMONDIR_FILE_NAME), b"../..\n"),
        ),
        (
            "back-pointer",
            std::fs::write(
                state_dir.join(layout::BACKPOINTER_FILE_NAME),
                format!("{}\n", target.join(mkit_core::MKIT_DIR).display()),
            ),
        ),
    ];
    for (what, res) in steps {
        if let Err(e) = res {
            return Err(super::error(&format!("write {what}: {e}"), exit::CANTCREAT));
        }
    }
    let head_write = match plan {
        HeadPlan::NewBranch { branch, .. } | HeadPlan::ExistingBranch { branch, .. } => {
            refs::write_head_branch(&linked, branch)
        }
        HeadPlan::Detached(h) => refs::write_head_detached(&linked, h),
    };
    if let Err(e) = head_write {
        return Err(super::error(&format!("write HEAD: {e}"), exit::CANTCREAT));
    }

    // 2. The branch ref (new-branch form) — before the tree goes live.
    if let HeadPlan::NewBranch { branch, start } = plan
        && let Err(e) =
            super::write_ref_recording_history(layout, branch, RefWriteCondition::Missing, start)
    {
        return Err(super::error(
            &format!("create branch '{branch}': {e}"),
            exit::CANTCREAT,
        ));
    }

    // 3. The tree itself: pointer file, then materialization.
    if let Err(e) = std::fs::create_dir_all(target) {
        return Err(super::error(
            &format!("create '{}': {e}", target.display()),
            exit::CANTCREAT,
        ));
    }
    if let Err(e) = layout::write_pointer_file(target, &state_dir) {
        return Err(super::error(
            &format!("write worktree pointer: {e}"),
            exit::CANTCREAT,
        ));
    }
    if let Err(e) = super::restore_worktree_and_index(&linked, store, tree_hash) {
        return Err(super::error(&e, exit::GENERAL_ERROR));
    }
    Ok(())
}

// ─── list ───────────────────────────────────────────────────────────

/// One `worktree list` row: path, resolved HEAD, checked-out branch,
/// and the prunable reason for broken registry entries.
type ListRow = (PathBuf, Option<Hash>, Option<String>, Option<String>);

fn list(layout: &RepoLayout, porcelain: bool) -> u8 {
    let store = match super::open_store_configured(layout) {
        Ok(s) => s,
        Err(e) => return super::error(&format!("open store: {e}"), exit::UNAVAILABLE),
    };
    let _ = store; // hashes come from refs; store presence validates the repo

    let mut rows: Vec<ListRow> = Vec::new();
    let siblings = match super::all_worktree_layouts(layout) {
        Ok(s) => s,
        Err(e) => return super::error(&e, exit::DATAERR),
    };
    for (tree_root, candidate) in &siblings {
        let head = refs::resolve_head(candidate).ok().flatten();
        let branch = match refs::read_head(candidate) {
            Ok(refs::Head::Branch(name)) => Some(name),
            _ => None,
        };
        rows.push((tree_root.clone(), head, branch, None));
    }
    // Broken registry entries: visible, marked prunable.
    match layout::worktrees(layout) {
        Ok(entries) => {
            for wt in entries {
                if let Some(reason) = wt.prunable {
                    let shown = wt.tree_root.unwrap_or_else(|| wt.state_dir.clone());
                    rows.push((shown, None, None, Some(reason)));
                }
            }
        }
        Err(e) => return super::error(&format!("worktree registry: {e}"), exit::DATAERR),
    }

    let mut stdout = std::io::stdout().lock();
    for (path, head, branch, prunable) in rows {
        if porcelain {
            let _ = writeln!(stdout, "worktree {}", path.display());
            if let Some(h) = head {
                let _ = writeln!(stdout, "HEAD {}", mkit_core::hash::to_hex(&h));
            }
            match (&branch, &prunable) {
                (_, Some(reason)) => {
                    let _ = writeln!(stdout, "prunable {reason}");
                }
                (Some(b), None) => {
                    let _ = writeln!(stdout, "branch refs/heads/{b}");
                }
                (None, None) => {
                    let _ = writeln!(stdout, "detached");
                }
            }
            let _ = writeln!(stdout);
        } else {
            let hash_col = head.map_or_else(|| "-".repeat(8), |h| format::short_hash(&h, 8));
            let desc = match (&branch, &prunable) {
                (_, Some(reason)) => format!("(prunable: {reason})"),
                (Some(b), None) => format!("[{b}]"),
                (None, None) => "(detached HEAD)".to_owned(),
            };
            let _ = writeln!(stdout, "{}  {hash_col} {desc}", path.display());
        }
    }
    exit::OK
}

// ─── remove ─────────────────────────────────────────────────────────

fn remove(layout: &RepoLayout, cwd: &Path, path: &str, force: bool) -> u8 {
    let target = canonical_or_lexical(&absolutize(cwd, Path::new(path)));

    let main_root = layout.common_dir().parent().map(canonical_or_lexical);
    if main_root.as_deref() == Some(target.as_path()) {
        return super::error("the main working tree cannot be removed", exit::USAGE);
    }
    if canonical_or_lexical(cwd).starts_with(&target) {
        return super::error(
            "cannot remove the worktree you are currently inside",
            exit::USAGE,
        );
    }

    let entries = match layout::worktrees(layout) {
        Ok(e) => e,
        Err(e) => return super::error(&format!("worktree registry: {e}"), exit::DATAERR),
    };
    let Some(wt) = entries.into_iter().find(|wt| {
        wt.tree_root
            .as_deref()
            .is_some_and(|root| canonical_or_lexical(root) == target)
    }) else {
        return super::error(
            &format!(
                "'{}' is not a linked worktree of this repository",
                target.display()
            ),
            exit::USAGE,
        );
    };

    // Refuse to destroy local work unless forced: any in-progress op,
    // staged, or unstaged change counts (untracked files too — they
    // exist only in that tree).
    if !force && wt.prunable.is_none() {
        let linked = RepoLayout::linked(&target, &wt.state_dir, layout.common_dir());
        if let Some(op) = mkit_core::ops::conflict_state::in_progress_op_name(&linked) {
            return super::error(
                &format!("worktree has a {op} in progress; resolve it or pass --force"),
                exit::DATAERR,
            );
        }
        match worktree_is_dirty(&linked) {
            Ok(Some(why)) => {
                return super::error(
                    &format!("worktree contains {why}; commit, stash, or pass --force"),
                    exit::DATAERR,
                );
            }
            Ok(None) => {}
            Err(e) => return super::error(&e, exit::DATAERR),
        }
    }

    let _lock = match super::acquire_worktrees_registry_lock(layout) {
        Ok(l) => l,
        Err(code) => return code,
    };
    // Hold the CONDEMNED tree's own worktree lock too (registry lock
    // first — global order): another process cwd'ed inside it could be
    // mid-commit; deleting its state dir under it would corrupt the
    // shared refs-history step or strand half-written state.
    let _target_lock = if wt.state_dir.is_dir() {
        let target_layout = RepoLayout::linked(&target, &wt.state_dir, layout.common_dir());
        match super::acquire_worktree_lock(&target_layout) {
            Ok(l) => Some(l),
            Err(code) => return code,
        }
    } else {
        None
    };
    // Tree first, then registry: a crash in between leaves a prunable
    // orphaned state dir, never a live tree without state.
    if target.exists()
        && let Err(e) = std::fs::remove_dir_all(&target)
    {
        return super::error(
            &format!("remove '{}': {e}", target.display()),
            exit::GENERAL_ERROR,
        );
    }
    if let Err(e) = std::fs::remove_dir_all(&wt.state_dir) {
        return super::error(
            &format!("remove state dir '{}': {e}", wt.state_dir.display()),
            exit::GENERAL_ERROR,
        );
    }
    exit::OK
}

/// `Some(description)` when the tree has staged or unstaged changes or
/// untracked files, relative to its own HEAD.
fn worktree_is_dirty(linked: &RepoLayout) -> Result<Option<String>, String> {
    let store = super::open_store_configured(linked).map_err(|e| format!("open store: {e}"))?;
    let head_tree = super::current_head_tree(linked, &store)?;
    let Some(head_tree) = head_tree else {
        return Ok(None); // unborn HEAD: nothing to lose
    };
    // Untracked files first, for the precise diagnostic (the gate
    // below would also catch them, but with restore-flavored wording).
    let idx = super::read_or_seed_index_from_head(linked, &store)?;
    let mut paths = Vec::new();
    super::collect_worktree_paths(
        linked.worktree_root(),
        linked.worktree_root(),
        "",
        &mut paths,
    )
    .map_err(|e| format!("scan worktree: {e}"))?;
    for p in paths {
        let abs = linked.worktree_root().join(&p);
        if abs.is_dir() {
            continue;
        }
        if !super::index_tracks_path_or_descendant(&idx, &p) {
            return Ok(Some(format!("untracked file '{p}'")));
        }
    }
    // Staged/unstaged changes, via the shared destructive-op gate. Its
    // dirty-tree refusals all start with "restore would"; anything
    // else is an infrastructure failure and must propagate — an
    // unreadable tree must not read as "clean".
    match super::ensure_restore_safe(linked, &store, head_tree) {
        Ok(()) => Ok(None),
        Err(why) if why.starts_with("restore would") => Ok(Some("local changes".to_owned())),
        Err(why) => Err(why),
    }
}

// ─── prune ──────────────────────────────────────────────────────────

fn prune(layout: &RepoLayout, dry_run: bool) -> u8 {
    // Lock FIRST (non-dry-run), snapshot second: a registry scan taken
    // before the lock can classify a mid-`add` entry (state dir
    // written, pointer file not yet) as "linked tree is gone", then
    // delete the fully live tree's state after `add` releases the
    // lock. Dry runs stay lock-free — they only report.
    let _lock = if dry_run {
        None
    } else {
        match super::acquire_worktrees_registry_lock(layout) {
            Ok(l) => Some(l),
            Err(code) => return code,
        }
    };
    let entries = match layout::worktrees(layout) {
        Ok(e) => e,
        Err(e) => return super::error(&format!("worktree registry: {e}"), exit::DATAERR),
    };
    let mut stdout = std::io::stdout().lock();
    for wt in entries {
        let Some(reason) = wt.prunable else { continue };
        if dry_run {
            let _ = writeln!(stdout, "would prune worktrees/{}: {reason}", wt.id);
            continue;
        }
        if let Err(e) = std::fs::remove_dir_all(&wt.state_dir) {
            return super::error(
                &format!("prune worktrees/{}: {e}", wt.id),
                exit::GENERAL_ERROR,
            );
        }
        let _ = writeln!(stdout, "pruned worktrees/{}: {reason}", wt.id);
    }
    exit::OK
}

// ─── shared bits ────────────────────────────────────────────────────

/// Lexical absolutization against `cwd` — the target of `add` does not
/// exist yet, so `canonicalize` is not an option.
fn absolutize(cwd: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }
}

/// Canonicalize when possible (resolves `..` and symlinks for the
/// containment / identity checks). For a not-yet-existing path,
/// canonicalize the deepest EXISTING ancestor and re-append the
/// remainder — macOS tempdirs live behind the `/var → /private/var`
/// symlink, so a purely lexical fallback would defeat every
/// containment comparison against canonicalized roots.
fn canonical_or_lexical(p: &Path) -> PathBuf {
    if let Ok(c) = p.canonicalize() {
        return c;
    }
    let mut missing = Vec::new();
    let mut cur = p;
    while let Some(parent) = cur.parent() {
        if let Some(name) = cur.file_name() {
            missing.push(name.to_owned());
        }
        if let Ok(c) = parent.canonicalize() {
            let mut out = c;
            for name in missing.iter().rev() {
                out.push(name);
            }
            return out;
        }
        cur = parent;
    }
    p.to_path_buf()
}

/// Branch name derived from the target basename, sanitized into the
/// ref grammar (invalid bytes become `-`).
fn branch_name_from_path(target: &Path) -> Option<String> {
    let base = target.file_name()?.to_string_lossy();
    let candidate: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let candidate = candidate.trim_matches(['-', '.']).to_string();
    refs::validate_ref_name(&candidate).then_some(candidate)
}

/// First free registry id derived from the target basename:
/// `<basename>`, then `<basename>-1`, `-2`, … (git-style uniquify).
fn free_worktree_id(layout: &RepoLayout, target: &Path) -> Option<String> {
    let base = target.file_name()?.to_string_lossy();
    let sanitized: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let sanitized = sanitized.trim_matches('-').to_string();
    if !layout::validate_worktree_id(&sanitized) {
        return None;
    }
    if !layout.worktree_state_dir_for(&sanitized).exists() {
        return Some(sanitized);
    }
    (1..10_000).find_map(|n| {
        let candidate = format!("{sanitized}-{n}");
        (layout::validate_worktree_id(&candidate)
            && !layout.worktree_state_dir_for(&candidate).exists())
        .then_some(candidate)
    })
}
