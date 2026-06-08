//! `mkit update-ref [-d] <ref> [<newvalue> [<oldvalue>]]` — low-level guarded
//! ref write/delete, like `git update-ref`.
//!
//! Supports `refs/heads/<branch>` and `refs/tags/<name>` (the namespaces mkit
//! manages); other namespaces (`HEAD`, `refs/remotes/…`) are rejected.
//! `<newvalue>` / `<oldvalue>` resolve through the shared revspec grammar
//! (ref, full/short hash, `HEAD~n`). Without `<oldvalue>` the write is
//! unconditional; with one it is a compare-and-swap that fails unless the ref
//! currently holds that value. In **update** mode an all-zero `<oldvalue>`
//! means "the ref must not already exist" (git's create-only convention); in
//! `-d` (delete) mode `<oldvalue>`, if given, must be a concrete value the
//! ref currently holds (an all-zero value is rejected — you cannot delete a
//! ref asserted to be absent).
//!
//! Safety divergence: `-d` on a branch uses the same guard as `branch -d` —
//! it refuses to delete the currently checked-out branch (git's plumbing
//! would, leaving HEAD dangling).

use std::io::Write;

use clap::Parser;
use mkit_core::hash::Hash;
use mkit_core::refs::{self, RefWriteCondition};
use mkit_core::store::ObjectStore;

use super::revspec;
use crate::clap_shim;
use crate::exit;

#[derive(Debug, Parser)]
#[command(
    name = "mkit update-ref",
    about = "Create, update, or delete a ref (guarded)."
)]
struct UpdateRefOpts {
    /// Delete the ref instead of updating it.
    #[arg(short = 'd', long)]
    delete: bool,
    /// The ref to write: `refs/heads/<branch>` or `refs/tags/<name>`.
    name: String,
    /// New value as a revision (required unless `-d`); for `-d` this slot is
    /// the optional expected old value.
    value: Option<String>,
    /// Expected current value for a compare-and-swap (update mode only).
    old_value: Option<String>,
}

/// Which ref namespace a `refs/…` path addresses.
enum Namespace {
    Head,
    Tag,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<UpdateRefOpts>("mkit update-ref", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let store = match ObjectStore::open(&cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);

    let Some((ns, name)) = parse_ref(&opts.name) else {
        return emit_err(
            &format!(
                "unsupported ref '{}': update-ref handles refs/heads/<branch> and refs/tags/<name>",
                opts.name
            ),
            exit::USAGE,
        );
    };

    // update-ref publishes a gc root (refs/heads/* or refs/tags/*) at an
    // arbitrary object, so hold the repo lock across resolve + publish: a
    // concurrent `gc --grace-secs 0` then can't prune a (possibly
    // unreachable) target between resolving it and writing the ref (#267).
    // Acquired after repo validation (store open) so a non-repo reported
    // cleanly above; covers the delete path too for consistency.
    let _lock = match super::acquire_worktree_lock(&cwd) {
        Ok(l) => l,
        Err(code) => return code,
    };

    if opts.delete {
        if opts.old_value.is_some() {
            return super::usage_error("usage: mkit update-ref -d <ref> [<oldvalue>]");
        }
        return run_delete(&store, &mkit_dir, &ns, name, opts.value.as_deref());
    }

    let Some(newspec) = opts.value.as_deref() else {
        return super::usage_error("usage: mkit update-ref <ref> <newvalue> [<oldvalue>]");
    };
    let newhash = match resolve(&store, &mkit_dir, newspec) {
        Ok(h) => h,
        Err(msg) => return emit_err(&msg, exit::DATAERR),
    };
    // Refuse to publish a ref pointing at an object that is not present
    // (resolved under the lock, so this also closes the resolve→publish race).
    if !store.contains(&newhash) {
        return emit_err(
            &format!("object '{newspec}' does not exist in the store"),
            exit::DATAERR,
        );
    }
    let condition = match opts.old_value.as_deref() {
        None => RefWriteCondition::Any,
        Some(s) if is_zero(s) => RefWriteCondition::Missing,
        Some(s) => match resolve(&store, &mkit_dir, s) {
            Ok(h) => RefWriteCondition::Match(h),
            Err(msg) => return emit_err(&msg, exit::DATAERR),
        },
    };
    let res = match ns {
        // Branch moves MUST funnel through the history-recording helper so a
        // `--features history-mmr` build advances the ref and its journal
        // together under lock (the CLI ref-write invariant). Tags are not
        // history-tracked (the journal is keyed per branch).
        Namespace::Head => super::write_ref_recording_history(&mkit_dir, name, condition, &newhash),
        Namespace::Tag => refs::update_tag(&mkit_dir, name, condition, &newhash),
    };
    match res {
        Ok(()) => exit::OK,
        Err(e) => emit_err(
            &format!("update-ref {}: {e}", opts.name),
            exit::GENERAL_ERROR,
        ),
    }
}

/// `-d`: delete the ref, optionally verifying its current value first.
fn run_delete(
    store: &ObjectStore,
    mkit_dir: &std::path::Path,
    ns: &Namespace,
    name: &str,
    old_value: Option<&str>,
) -> u8 {
    if let Some(spec) = old_value {
        if is_zero(spec) {
            return emit_err(
                "cannot delete a ref whose expected old value is all-zero (absent)",
                exit::USAGE,
            );
        }
        let expected = match resolve(store, mkit_dir, spec) {
            Ok(h) => h,
            Err(msg) => return emit_err(&msg, exit::DATAERR),
        };
        let current = match ns {
            Namespace::Head => refs::read_ref(mkit_dir, name),
            Namespace::Tag => refs::read_tag(mkit_dir, name),
        };
        match current {
            Ok(Some(h)) if h == expected => {}
            Ok(_) => {
                return emit_err(
                    "ref does not have the expected old value; not deleting",
                    exit::GENERAL_ERROR,
                );
            }
            Err(e) => return emit_err(&format!("read ref: {e}"), exit::GENERAL_ERROR),
        }
    }
    let res = match ns {
        // Branch delete uses the safe path — refuses the current branch.
        Namespace::Head => refs::delete_ref_safe(mkit_dir, name),
        Namespace::Tag => refs::delete_tag(mkit_dir, name),
    };
    match res {
        Ok(()) => exit::OK,
        Err(e) => emit_err(&format!("delete ref: {e}"), exit::GENERAL_ERROR),
    }
}

/// Map a `refs/heads/<branch>` / `refs/tags/<name>` path to its namespace and
/// short name. Returns `None` for any other ref.
fn parse_ref(full: &str) -> Option<(Namespace, &str)> {
    if let Some(b) = full.strip_prefix("refs/heads/") {
        Some((Namespace::Head, b))
    } else if let Some(t) = full.strip_prefix("refs/tags/") {
        Some((Namespace::Tag, t))
    } else {
        None
    }
}

/// Resolve a revision spec to a concrete object hash.
fn resolve(store: &ObjectStore, mkit_dir: &std::path::Path, spec: &str) -> Result<Hash, String> {
    revspec::resolve_revision(store, mkit_dir, spec)
        .map_err(|e| format!("bad revision '{spec}': {e}"))
}

/// Is `s` git's all-zero object id (mkit's is 64 hex zeros)?
fn is_zero(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b == b'0')
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
