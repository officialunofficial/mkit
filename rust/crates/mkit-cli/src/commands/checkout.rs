//! `mkit checkout <branch>` — switch HEAD to a branch and materialise
//! the branch tip's tree into the working directory.
//!
//! The file-restoration half was previously a Phase 10 follow-up; this
//! wire-up calls `mkit_core::ops::restore::restore_tree_to_worktree`
//! which respects `.mkitignore` and rejects symlinks that would escape
//! the repo root.

use std::io::Write;

use clap::Parser;
use mkit_core::hash::Hash;
use mkit_core::object::Object;
use mkit_core::ops::restore::{RestoreOptions, restore_tree_to_worktree};
use mkit_core::refs;
use mkit_core::store::ObjectStore;

use crate::clap_shim;
use crate::exit;
use crate::format;

#[derive(Debug, Parser)]
#[command(
    name = "mkit checkout",
    about = "Switch HEAD to a branch (or tag / commit hash) and restore files."
)]
struct CheckoutOpts {
    /// One or more path-prefix patterns selecting a subset of the
    /// commit's tree. Each pattern is interpreted the same way the
    /// `mkit sparse-checkout` config patterns are — a leading `/` is
    /// stripped, a trailing `/` marks a directory-only match, and `!`
    /// negates. Repeat the flag to add more patterns.
    ///
    /// When supplied, `mkit checkout` builds a verifiable sparse
    /// manifest from the commit's top-level tree (via
    /// `mkit_core::sparse::build_sparse`), re-runs the verifier on the
    /// delivered subset, caches the bitmap under
    /// `.mkit/sparse/<tree-hex>.bitmap`, and materialises only the
    /// matching files. The patterns are NOT persisted to
    /// `.mkit/sparse-checkout` — use `mkit sparse-checkout set` for
    /// that.
    #[cfg(feature = "sparse-checkout")]
    #[arg(long = "sparse", value_name = "PATTERN", num_args = 1..)]
    sparse: Vec<String>,
    /// Branch name, tag, or 64-char commit hash.
    target: String,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<CheckoutOpts>("mkit checkout", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let name = &opts.target;
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);
    let store = match ObjectStore::open(&cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };

    // Resolve <name> — try ref first (branch / tag), then fall back to
    // a raw 64-char commit hash.
    let commit_hash: Hash = match refs::read_ref(&mkit_dir, name) {
        Ok(Some(h)) => h,
        Ok(None) => match refs::read_tag(&mkit_dir, name) {
            Ok(Some(h)) => h,
            Ok(None) => match mkit_core::hash::from_hex(name) {
                Ok(h) if store.contains(&h) => h,
                _ => {
                    return emit_err(
                        &format!("no such branch, tag, or commit: {name}"),
                        exit::GENERAL_ERROR,
                    );
                }
            },
            Err(e) => return emit_err(&format!("read tag: {e}"), exit::GENERAL_ERROR),
        },
        Err(e) => return emit_err(&format!("read ref: {e}"), exit::GENERAL_ERROR),
    };

    // Resolve the commit's tree so we can materialise it.
    let tree_hash = match store.read_object(&commit_hash) {
        Ok(Object::Commit(c)) => c.tree_hash,
        Ok(Object::Remix(r)) => r.tree_hash,
        Ok(_) => {
            return emit_err(
                &format!(
                    "{} does not resolve to a commit or remix",
                    format::short_hash(&commit_hash, 8)
                ),
                exit::GENERAL_ERROR,
            );
        }
        Err(e) => return emit_err(&format!("read commit: {e}"), exit::GENERAL_ERROR),
    };

    // If `--sparse` was supplied, drive a verifiable sparse-checkout:
    // build a manifest from the commit's tree, re-verify the
    // delivered subset, cache the bitmap, then materialise with the
    // restore-side sparse patterns set. Empty `opts.sparse` falls
    // through to the full-tree restore below.
    #[cfg(feature = "sparse-checkout")]
    let sparse_opts: RestoreOptions = if opts.sparse.is_empty() {
        RestoreOptions::default()
    } else {
        match prepare_sparse_restore(&cwd, &store, tree_hash, &opts.sparse) {
            Ok(o) => o,
            Err((msg, code)) => return emit_err(&msg, code),
        }
    };
    #[cfg(not(feature = "sparse-checkout"))]
    let sparse_opts: RestoreOptions = RestoreOptions::default();

    // Materialise the tree. `clean=true` is the default — `checkout`
    // reshapes the worktree to the branch tip. `.mkitignore` is
    // honoured inside the helper so locally-ignored files (editor
    // swapfiles, build artefacts) survive the transition.
    if let Err(e) = super::ensure_restore_safe_with_options(&cwd, &store, tree_hash, &sparse_opts) {
        return emit_err(&e, exit::GENERAL_ERROR);
    }
    let report = match restore_tree_to_worktree(&store, &tree_hash, &cwd, &sparse_opts) {
        Ok(r) => r,
        Err(e) => return emit_err(&format!("restore: {e}"), exit::CANTCREAT),
    };
    if let Err(e) = super::sync_index_to_tree(&cwd, &store, tree_hash) {
        return emit_err(&e, exit::CANTCREAT);
    }

    // Update HEAD last. If the input was a ref name we know we saw a
    // branch/tag above; for tags + bare commit hashes we go detached.
    let is_branch = matches!(refs::read_ref(&mkit_dir, name), Ok(Some(_)));
    let head_err = if is_branch {
        refs::write_head_branch(&mkit_dir, name)
    } else {
        refs::write_head_detached(&mkit_dir, &commit_hash)
    };
    if let Err(e) = head_err {
        return emit_err(&format!("update HEAD: {e}"), exit::CANTCREAT);
    }

    let mut stderr = std::io::stderr().lock();
    if is_branch {
        let _ = writeln!(stderr, "switched to branch {name}");
    } else {
        let _ = writeln!(
            stderr,
            "switched to detached {}",
            format::short_hash(&commit_hash, 8)
        );
    }
    let _ = writeln!(
        stderr,
        "  {} file(s), {} dir(s), {} symlink(s) restored ({} ignored)",
        report.files_written,
        report.directories_created,
        report.symlinks_written,
        report.skipped_by_ignore
    );
    exit::OK
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}

/// Drive the verifiable sparse-checkout pipeline for `tree_hash`
/// against the supplied path-prefix patterns:
///
/// 1. Read the top-level tree from `store`.
/// 2. Translate the CLI `--sparse <pattern>...` argv into both
///    (a) a flat `Vec<PathBuf>` filter the sparse module understands,
///    and
///    (b) a `Vec<SparsePattern>` the restore code understands.
/// 3. Call `build_sparse` → `verify_sparse` (the round-trip catches a
///    self-inconsistency at the seam).
/// 4. Persist the bitmap under `.mkit/sparse/<tree-hex>.bitmap`.
/// 5. Return the `RestoreOptions` the caller hands to
///    `restore_tree_to_worktree`.
///
/// On any failure, returns `(message, exit_code)` so the caller can
/// thread it back through the existing `emit_err` plumbing.
#[cfg(feature = "sparse-checkout")]
fn prepare_sparse_restore(
    cwd: &std::path::Path,
    store: &ObjectStore,
    tree_hash: Hash,
    patterns: &[String],
) -> Result<RestoreOptions, (String, u8)> {
    use mkit_core::object::Object as CoreObject;
    use mkit_core::ops::restore::parse_sparse_patterns;
    use mkit_core::sparse::{build_sparse, verify_sparse};
    use std::path::PathBuf;

    let tree = match store.read_object(&tree_hash) {
        Ok(CoreObject::Tree(t)) => t,
        Ok(_) => {
            return Err((
                "checkout: HEAD does not resolve to a tree".to_string(),
                exit::DATAERR,
            ));
        }
        Err(e) => return Err((format!("read tree: {e}"), exit::GENERAL_ERROR)),
    };

    // The sparse module's filter is a flat list of `PathBuf` prefixes.
    // The restore code's pattern grammar additionally supports `!`
    // negation and `/`-anchored matches; we translate the CLI argv
    // into both representations so the manifest's filter binding sees
    // a stable canonical form while the restore code keeps its
    // existing semantics. Negated patterns are excluded from the
    // sparse-module filter (they're a worktree-side exclusion, not a
    // server-side inclusion), but still flow through to the restore
    // step so the user's intent survives.
    let mut filter: Vec<PathBuf> = Vec::with_capacity(patterns.len());
    for raw in patterns {
        let trimmed = raw.trim_start_matches('/');
        let trimmed = trimmed.trim_end_matches('/');
        if trimmed.is_empty() || trimmed.starts_with('!') {
            continue;
        }
        filter.push(PathBuf::from(trimmed));
    }

    // Self-consistency round-trip: build the manifest, then verify
    // the delivered subset against it. This is the local equivalent
    // of "server delivers manifest, client checks it" — it catches a
    // regression in either side without standing up a transport.
    let (delivered, manifest, proof) = build_sparse(&tree, &filter)
        .map_err(|e| (format!("sparse build: {e}"), exit::GENERAL_ERROR))?;
    if !verify_sparse(&manifest, &delivered, &filter, &proof) {
        return Err((
            "sparse build produced a manifest that fails verify".to_string(),
            exit::GENERAL_ERROR,
        ));
    }

    // Persist to the on-disk cache. Errors are non-fatal — a missing
    // cache just means the next checkout re-runs the verifier — but
    // we surface them on stderr so the user knows the persistent
    // optimisation is broken.
    if let Err(e) = crate::sparse_cache::store(cwd, &manifest.tree_hash, &manifest, &proof) {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "warning: sparse cache write failed: {e}");
    }

    // Translate the CLI patterns into the restore-side pattern grammar.
    let joined = patterns.join("\n");
    let parsed = parse_sparse_patterns(&joined);
    Ok(RestoreOptions {
        clean: true,
        sparse_patterns: Some(parsed),
    })
}
