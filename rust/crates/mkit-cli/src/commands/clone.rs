//! `mkit clone <url> [<dir>]` — initialise a new repo and pull from
//! the URL. The destination defaults to the final path segment of the
//! URL when `<dir>` is omitted.
//!
//! Dispatches to the same transport-open path used by `mkit pull` —
//! `file://`, `https://`, `s3://`, and `ssh://` are all wired via
//! `remote_dispatch::open`. `--sparse` is implemented (behind the
//! `sparse-checkout` feature): the patterns are persisted to
//! `.mkit/sparse-checkout` and a verifiable sparse checkout is performed
//! after the pull. `--depth` (shallow clone) is still deferred and is
//! rejected with a clear message rather than silently ignored.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use clap::Parser;
use mkit_core::refs;
use mkit_core::store::{ObjectStore, StoreError};

use crate::clap_shim;
use crate::config::{self, Config};
use crate::exit;
use crate::remote_dispatch;

#[derive(Debug, Parser)]
#[command(
    name = "mkit clone",
    about = "Initialise a new repo and pull from a remote URL."
)]
struct CloneOpts {
    /// Shallow clone depth (not yet wired).
    #[arg(long, value_name = "N")]
    depth: Option<u32>,
    /// One or more sparse-checkout patterns (issue #158).
    /// Pulls the full ref set + reachable pack, then runs the
    /// verifiable sparse pipeline on the new working tree's HEAD,
    /// caching the bitmap and materialising only the matching files.
    /// Repeat the flag to add more patterns.
    #[cfg(feature = "sparse-checkout")]
    #[arg(long = "sparse", value_name = "PATTERN", num_args = 1..)]
    sparse: Vec<String>,
    /// Remote URL (e.g. `mkit+file:///abs/path`).
    url: String,
    /// Destination directory. Defaults to the final URL segment.
    dir: Option<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<CloneOpts>("mkit clone", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    if opts.depth.is_some() {
        return super::usage_error("mkit clone: --depth is not yet wired");
    }
    // `--sparse` no longer rejects — the patterns are persisted to
    // `.mkit/sparse-checkout` after the pack pull lands, and the next
    // `mkit checkout` honours them. Sparse fetch over the wire is
    // wired through `mkit checkout --sparse` itself.
    let url = opts.url.as_str();
    // Reject control characters (newline et al.) before the URL is
    // persisted to `.mkit/config` via `config::write` (which emits values
    // raw) — a newline would inject extra `key = value` lines into the
    // config (config injection). Mirrors the `mkit remote add` check.
    if config::validate_value(url).is_err() {
        return emit_err(
            &format!("invalid remote URL '{url}': contains control characters"),
            exit::PROTOCOL_ERROR,
        );
    }
    let target: PathBuf = match opts.dir.as_deref() {
        Some(d) => PathBuf::from(d),
        None => PathBuf::from(derive_dir_from_url(url)),
    };
    if target.exists() {
        return emit_err(
            &format!("destination '{}' already exists", target.display()),
            exit::CANTCREAT,
        );
    }
    // git prints this before doing any work; match the shape (mkit's
    // honest object-transfer summary follows at the end — the pack/delta
    // progress lines are a separate follow-up).
    {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "Cloning into '{}'...", target.display());
    }
    if let Err(e) = fs::create_dir_all(&target) {
        return emit_err(
            &format!("create {}: {e}", target.display()),
            exit::CANTCREAT,
        );
    }
    match ObjectStore::init(&target) {
        Ok(_) => {}
        Err(StoreError::AlreadyInitialized) => {
            return emit_err("already a mkit repository", exit::GENERAL_ERROR);
        }
        Err(e) => return emit_err(&format!("init: {e}"), exit::CANTCREAT),
    }
    if let Err(e) = refs::init(&target.join(mkit_core::MKIT_DIR)) {
        return emit_err(&format!("refs init: {e}"), exit::CANTCREAT);
    }
    let mut cfg = Config::with_defaults();
    url.clone_into(&mut cfg.remote_endpoint);
    cfg.remote_type = scheme_of(url).unwrap_or_default().to_string();
    if let Err(e) = config::write(&target, &cfg) {
        return emit_err(&format!("write config: {e}"), exit::CANTCREAT);
    }

    // Issue #389: clone establishes trust for a brand-new endpoint, so it
    // bypasses `open_trusted`'s credential gate — but it must still thread
    // the per-repo `ssh.*` trust-pinning keys into the spawned `ssh(1)`.
    // Routing through `open_with_config` keeps that resolution in the one
    // shared chokepoint instead of re-deriving it here. The keys are
    // user-scoped (REPO_FORBIDDEN_KEYS), so `read_or_default` against the
    // freshly-initialised destination still picks them up.
    let merged = match config::read_or_default(&target) {
        Ok(merged) => merged,
        Err(e) => return emit_err(&format!("read config: {e}"), exit::CONFIG_ERROR),
    };
    let pull_outcome = match remote_dispatch::open_with_config(url, &merged) {
        Ok(tx) => remote_dispatch::pull_all(&target, tx.as_ref(), "default"),
        Err(e) => return emit_err(&format!("open remote: {e}"), exit::PROTOCOL_ERROR),
    };
    let n = match pull_outcome {
        Ok(n) => n,
        Err(remote_dispatch::DispatchError::Interrupted) => {
            return emit_err("clone: interrupted", exit::TEMPFAIL);
        }
        Err(e) => return emit_err(&format!("pull: {e}"), exit::GENERAL_ERROR),
    };

    // If `--sparse` was supplied, persist the patterns to
    // `.mkit/sparse-checkout` so the next checkout honours them, and
    // run a verifiable sparse checkout against HEAD right now.
    #[cfg(feature = "sparse-checkout")]
    if !opts.sparse.is_empty()
        && let Err((msg, code)) = apply_sparse_after_clone(&target, &opts.sparse)
    {
        return emit_err(&msg, code);
    }

    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "cloned {n} ref(s) from {url} into {}",
        target.display()
    );
    exit::OK
}

/// Persist the supplied sparse patterns to `.mkit/sparse-checkout` and
/// drive a verifiable sparse re-materialise against the freshly-cloned
/// HEAD. Mirrors the inline sparse path used by `mkit checkout
/// --sparse`, but the entry point is "we just landed a full clone".
#[cfg(feature = "sparse-checkout")]
fn apply_sparse_after_clone(
    target: &std::path::Path,
    patterns: &[String],
) -> Result<(), (String, u8)> {
    use crate::sparse_cache::{SparseBuildError, SparseOutcome, load_or_build};
    use mkit_core::object::Object as CoreObject;
    use mkit_core::ops::restore::{
        RestoreOptions, parse_sparse_patterns, restore_tree_to_worktree, write_sparse_checkout,
    };
    use mkit_core::store::ObjectStore;
    use std::path::PathBuf as StdPathBuf;

    // Persist patterns to .mkit/sparse-checkout for follow-up commands.
    let pat_refs: Vec<&str> = patterns.iter().map(String::as_str).collect();
    write_sparse_checkout(target, &pat_refs)
        .map_err(|e| (format!("write sparse-checkout: {e}"), exit::CANTCREAT))?;

    // Open store, resolve HEAD → tree.
    let store =
        ObjectStore::open(target).map_err(|e| (format!("open store: {e}"), exit::GENERAL_ERROR))?;
    let mkit_dir = target.join(mkit_core::MKIT_DIR);
    let head = match mkit_core::refs::resolve_head(&mkit_dir) {
        Ok(Some(h)) => h,
        Ok(None) => return Ok(()), // fresh, no HEAD → nothing to materialise
        Err(e) => return Err((format!("resolve HEAD: {e}"), exit::GENERAL_ERROR)),
    };
    let tree_hash = match store.read_object(&head) {
        Ok(CoreObject::Commit(c)) => c.tree_hash,
        Ok(CoreObject::Remix(r)) => r.tree_hash,
        Ok(_) => return Err(("HEAD is not a commit".into(), exit::DATAERR)),
        Err(e) => return Err((format!("read HEAD: {e}"), exit::GENERAL_ERROR)),
    };

    let tree = match store.read_object(&tree_hash) {
        Ok(CoreObject::Tree(t)) => t,
        Ok(_) => return Err(("HEAD tree not a tree".into(), exit::DATAERR)),
        Err(e) => return Err((format!("read tree: {e}"), exit::GENERAL_ERROR)),
    };

    // Build + verify against the same filter the manifest binds to.
    let mut filter: Vec<StdPathBuf> = Vec::with_capacity(patterns.len());
    for raw in patterns {
        let trimmed = raw.trim_start_matches('/').trim_end_matches('/');
        if trimmed.is_empty() || trimmed.starts_with('!') {
            continue;
        }
        filter.push(StdPathBuf::from(trimmed));
    }
    // Cache-aware: a hit for this exact (tree, filter) skips the
    // expensive build_sparse + verify_sparse Merkle-bitmap
    // reconstruction entirely (SPEC-SPARSE-CHECKOUT §8). A miss
    // (including a stale filter or a corrupt cache entry) falls
    // through to a fresh build and rewrites the cache.
    match load_or_build(target, &tree, &filter) {
        Ok(SparseOutcome::CacheHit) => {}
        Ok(SparseOutcome::Built { store_error }) => {
            if let Some(e) = store_error {
                let mut stderr = std::io::stderr().lock();
                let _ = writeln!(stderr, "warning: sparse cache write failed: {e}");
            }
        }
        Err(SparseBuildError::Build(e)) => {
            return Err((format!("sparse build: {e}"), exit::GENERAL_ERROR));
        }
        Err(SparseBuildError::VerifyFailed) => {
            return Err((
                "sparse build produced a manifest that fails verify".into(),
                exit::GENERAL_ERROR,
            ));
        }
    }

    let joined = patterns.join("\n");
    let restore_opts = RestoreOptions {
        clean: true,
        sparse_patterns: Some(parse_sparse_patterns(&joined)),
    };
    restore_tree_to_worktree(&store, &tree_hash, target, &restore_opts)
        .map_err(|e| (format!("restore: {e}"), exit::CANTCREAT))?;
    Ok(())
}

fn derive_dir_from_url(url: &str) -> String {
    let trimmed = url.trim_end_matches('/');
    let last = trimmed.rsplit('/').next().unwrap_or(trimmed);
    let stripped = last.strip_suffix(".mkit").unwrap_or(last);
    if stripped.is_empty() {
        "repo".to_string()
    } else {
        stripped.to_string()
    }
}

fn scheme_of(url: &str) -> Option<&'static str> {
    for (prefix, kind) in [
        ("mkit+file://", "file"),
        ("mkit+https://", "http"),
        ("mkit+s3://", "s3"),
        ("mkit+ssh://", "ssh"),
        ("mkit+memory://", "memory"),
    ] {
        if url.starts_with(prefix) {
            return Some(kind);
        }
    }
    None
}

use super::error as emit_err;
