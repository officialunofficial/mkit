//! `mkit commit` — build a signed commit object from the staging
//! index.
//!
//! Scope:
//! 1. Accept `-m <msg>` OR spawn `$EDITOR` on a tempfile pre-filled
//! with `editor::COMMIT_EDITMSG_TEMPLATE`. An empty message
//! aborts.
//! 2. Read `.mkit/index` and build a tree via
//! [`worktree::build_tree_from_index`]. An empty / missing index is
//! an error — `mkit add <path>` (or `mkit add .`) must come first.
//! 3. Resolve the author identity in this order:
//! a. `--author <spec>` CLI flag (overrides everything).
//! b. `config.user_identity` in `.mkit/config`.
//! c. Derived from the signing key's public key (default).
//! 4. Sign the commit, write the `Commit` object, advance
//! `refs/heads/<current>` and `HEAD`.
//!
//! Pre-issue-#102 `mkit commit` walked the worktree directly via
//! `worktree::build_tree`, ignoring the index entirely. That made
//! `mkit add` write-only state with no reader and surprised any user
//! reasoning by analogy from git. Post-#102, the staging area is
//! load-bearing: only paths in the index land in the commit's tree.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, ValueEnum};
use mkit_core::index;
use mkit_core::layout::RepoLayout;
use mkit_core::object::{Commit, Identity, IdentityKind, Object, Tag};
use mkit_core::ops::conflict_state;
use mkit_core::refs::{self, Head};
use mkit_core::serialize;
use mkit_core::sign::{self, KeyPair};
use mkit_core::store::ObjectStore;
use mkit_core::worktree;
use mkit_keystore::{KeyRef, KeySelector, open_backend};

use crate::clap_shim;
use crate::config::Config;
use crate::editor::{COMMIT_EDITMSG_TEMPLATE, spawn_editor};
use crate::exit;
use crate::format::{self, JsonObject};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CommitFormat {
    Default,
    Json,
}

#[derive(Debug, Parser)]
#[command(
    name = "mkit commit",
    about = "Create a signed commit from the staging index."
)]
#[allow(clippy::struct_excessive_bools)] // clap option flags, not a state machine
struct CommitOptions {
    /// Commit message. If omitted, `$EDITOR` is launched.
    #[arg(short, long)]
    message: Option<String>,
    /// Read the commit message from `<file>` (like `git commit -F`). Use
    /// `-` to read from stdin. Mutually exclusive with `-m`.
    #[arg(
        short = 'F',
        long = "file",
        value_name = "FILE",
        conflicts_with = "message"
    )]
    file: Option<String>,
    /// Override the author Identity for this commit.
    #[arg(long = "author", value_name = "SPEC")]
    author_spec: Option<String>,
    /// Stage every tracked-and-modified file before committing
    /// (mirrors `git commit -a`).
    #[arg(short = 'a', long)]
    all: bool,
    /// Replace the current commit (HEAD) instead of adding a new one.
    ///
    /// The new commit re-uses HEAD's parent(s) as its own parent(s)
    /// (so it supersedes HEAD rather than building on it), takes its
    /// tree from the staging index, and is re-signed. The branch is
    /// moved to the new commit; the superseded commit becomes
    /// unreachable. If `-m` is omitted, the previous commit's message
    /// is reused (no `$EDITOR` is launched).
    ///
    /// NOTE: the superseded commit is not deleted — it stays on disk as
    /// an unreachable object until `mkit gc` ships (see issue #233).
    #[arg(long)]
    amend: bool,
    /// Suppress the commit summary line (git `-q`).
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,
    /// Accepted for git compatibility; mkit ALWAYS signs commits with its
    /// own key, so `-S`/`--gpg-sign[=<keyid>]` is a no-op (the optional
    /// `<keyid>` is ignored).
    #[arg(
        short = 'S',
        long = "gpg-sign",
        value_name = "KEYID",
        num_args = 0..=1,
        default_missing_value = ""
    )]
    gpg_sign: Option<String>,
    /// Accepted for git compatibility; mkit has no hooks, so `--no-verify`
    /// is a no-op.
    #[arg(long = "no-verify")]
    no_verify: bool,
    /// With `--amend`, keep the existing message. mkit already reuses
    /// HEAD's message when `-m` is omitted, so this is effectively the
    /// default; accepted for compatibility.
    #[arg(long = "no-edit")]
    no_edit: bool,
    /// Emit a machine-readable JSON result object to stdout on success:
    /// `{"ok":true,"hash":"<64-hex>","branch":"<name>|null",
    /// "parents":["<64-hex>",...],"tree":"<64-hex>","subject":"...",
    /// "is_merge":<bool>,"is_root":<bool>}`.
    #[arg(long, value_enum, default_value = "default")]
    format: CommitFormat,
}

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn run(args: &[String]) -> u8 {
    // Split fused `-am<msg>` / `-am <msg>` shortcuts into the
    // equivalent `-a -m <msg>` so clap sees only canonical forms.
    let normalised = expand_dash_am(args);
    let opts = match clap_shim::parse::<CommitOptions>("mkit commit", &normalised) {
        Ok(o) => o,
        Err(code) => return code,
    };
    // Accepted-for-compatibility no-ops: mkit always signs (`-S`) and has
    // no hooks (`--no-verify`); `--no-edit` matches mkit's default amend.
    let _ = (&opts.gpg_sign, opts.no_verify, opts.no_edit);
    let json = matches!(opts.format, CommitFormat::Json);

    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let layout = match super::resolve_layout(&cwd) {
        Ok(layout) => layout,
        Err(code) => return code,
    };
    let store = match super::open_store_configured(&layout) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };

    let cfg = match crate::config::read_or_default(&layout) {
        Ok(c) => c,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };

    // ---- Everything up to the lock acquisition below is read-only and/or
    // interactive (#641): it composes the commit message — possibly
    // spawning `$EDITOR`, which can block for an arbitrary, user-paced
    // amount of time — and loads the signer/key. None of it mutates the
    // repo, so none of it needs `worktree.lock`. The lock is acquired
    // just before the actual index/ref write, below, and every read here
    // whose result is still load-bearing at write time (`merge_state` for
    // `--amend` compat and for the merge-conclusion path; `pre_lock_head`
    // for `--amend`) is re-validated immediately after the lock is taken,
    // so a concurrent write landing during message composition is
    // detected rather than silently clobbered. See the re-validation
    // block below for the reasoning on each case, including why a plain
    // (non-amend, non-merge) commit needs none of this.
    //
    // ---- A merge left in progress turns this into a merge commit. --
    // Either a clean `merge --no-commit`, or a conflicted merge the user
    // has since resolved and staged. `mkit commit` then records a
    // two-parent commit and clears the merge state, mirroring how
    // `git commit` concludes a merge.
    let merge_state = if conflict_state::is_merge_in_progress(&layout) {
        match conflict_state::read_merge_state(&layout) {
            Ok(s) => s,
            Err(e) => return emit_err(&format!("read merge state: {e}"), exit::GENERAL_ERROR),
        }
    } else {
        None
    };
    if merge_state.is_some() && opts.amend {
        return emit_err(
            "cannot --amend while a merge is in progress; finish it with `mkit commit` \
             or abandon it with `mkit merge --abort`",
            exit::USAGE,
        );
    }

    // ---- When amending, load the commit being replaced. ------------
    // `--amend` re-creates HEAD: the new commit inherits HEAD's parents
    // (so it supersedes HEAD rather than stacking on it) and, when no
    // `-m` is given, reuses HEAD's message verbatim.
    let amend_target = if opts.amend {
        match resolve_amend_target(&layout, &store) {
            Ok(commit) => Some(commit),
            Err((m, c)) => return emit_err(&m, c),
        }
    } else {
        None
    };
    // Snapshot of HEAD at the same moment `amend_target` was resolved.
    // `--amend` reuses that commit's parents (and, absent `-m`, its
    // message) below, both computed from THIS snapshot rather than a
    // fresh read at write time — unlike a plain commit's parent, which
    // is always read fresh under the lock (see `parents` further down).
    // Message composition + signer loading can now take arbitrarily long
    // before the lock is acquired, so re-validate after the lock that
    // HEAD hasn't moved out from under this snapshot; see the
    // re-validation block right after `acquire_worktree_lock`.
    let pre_lock_head = if opts.amend {
        match refs::resolve_head(&layout) {
            Ok(h) => h,
            Err(e) => return emit_err(&format!("read HEAD: {e}"), exit::DATAERR),
        }
    } else {
        None
    };

    // ---- Resolve / prompt for message. -----------------------------
    // `--amend` without `-m` reuses the superseded commit's message and
    // never launches `$EDITOR`.
    // Message precedence: `-m` → `-F <file>` → amend-reuse → merge message
    // (`MERGE_MSG`) → `$EDITOR`. `-F`/merge defaults never launch the editor
    // so they stay usable in non-interactive contexts.
    let msg = match opts.message {
        Some(m) => m,
        None => match &opts.file {
            Some(path) => match read_message_file(path) {
                Ok(m) if !m.trim().is_empty() => m,
                Ok(_) => return emit_err("empty commit message — aborting", exit::USAGE),
                Err(e) => return emit_err(&format!("read message file: {e}"), exit::NOINPUT),
            },
            None => match &amend_target {
                Some(prev) => String::from_utf8_lossy(&prev.message).into_owned(),
                None => match &merge_state {
                    Some(state) => String::from_utf8_lossy(&state.message).into_owned(),
                    None => match spawn_editor(COMMIT_EDITMSG_TEMPLATE) {
                        Ok(m) if !m.is_empty() => m,
                        Ok(_) => {
                            return emit_err("empty commit message — aborting", exit::USAGE);
                        }
                        Err(e) => return emit_err(&format!("editor: {e}"), exit::GENERAL_ERROR),
                    },
                },
            },
        },
    };

    // ---- Load signer. ----------------------------------------------
    let mut signer = match load_commit_signer(&layout, &cfg) {
        Ok(signer) => signer,
        Err((msg, code)) => return emit_err(&msg, code),
    };
    let signer_public = match signer.public_key() {
        Ok(public) => public,
        Err((msg, code)) => return emit_err(&msg, code),
    };

    // ---- Resolve author. -------------------------------------------
    // Precedence: --author flag → config.user_identity → pubkey-derived.
    let author = match resolve_author(
        opts.author_spec.as_deref(),
        &cfg.user_identity,
        &signer_public,
    ) {
        Ok(id) => id,
        Err(e) => return emit_err(&format!("author: {e}"), exit::CONFIG_ERROR),
    };

    // ---- Acquire the write lock. ------------------------------------
    // Everything above this point (message composition — including any
    // `$EDITOR` spawn — and signer/key loading) is done. Everything
    // below mutates the repo (or reads state that must not shift under a
    // mutation), so it all happens under the lock, right up to the ref
    // advance.
    let _lock = match super::acquire_worktree_lock(&layout) {
        Ok(l) => l,
        Err(code) => return code,
    };

    // ---- Re-validate preconditions captured before the lock. --------
    // `merge_state` and (when `--amend`) `pre_lock_head` were read before
    // the lock so message composition could use them; re-read them now
    // and compare, since a concurrent mutator could have run to
    // completion in the (potentially long, interactive) window between
    // that read and this lock acquisition.
    //
    // `merge_state` unconditionally: it gates the merge-conclusion
    // checks and the two-parent merge commit below regardless of
    // `--amend`, so ANY change to it (a merge started, finished, or was
    // aborted concurrently) must abort rather than act on stale sidecar
    // state.
    let fresh_merge_state = if conflict_state::is_merge_in_progress(&layout) {
        match conflict_state::read_merge_state(&layout) {
            Ok(s) => s,
            Err(e) => return emit_err(&format!("read merge state: {e}"), exit::GENERAL_ERROR),
        }
    } else {
        None
    };
    if fresh_merge_state != merge_state {
        return emit_err(
            "commit aborted: the in-progress merge changed while the commit message was \
             being composed (concluded or aborted concurrently) — re-run `mkit commit`",
            exit::TEMPFAIL,
        );
    }
    // `--amend` only: the message-reuse (above) and the parent list
    // (below) both derive from `amend_target`, which was resolved from
    // `pre_lock_head`. If HEAD has since moved, that snapshot no longer
    // describes "the commit being amended" and re-using it would amend
    // against stale state (and silently orphan whatever now-superseded
    // commit actually landed).
    //
    // A plain (non-amend, non-merge) commit needs NO staleness check: its
    // parent is read fresh from HEAD below (`refs::resolve_head`, inside
    // this same lock hold), and its tree is built fresh from the index
    // read below — both entirely inside the critical section, so there is
    // no pre-lock snapshot that could go stale. A concurrent commit
    // landing during message composition just becomes this commit's
    // parent, exactly as if the two `mkit commit` invocations had run
    // sequentially.
    if opts.amend {
        let fresh_head = match refs::resolve_head(&layout) {
            Ok(h) => h,
            Err(e) => return emit_err(&format!("read HEAD: {e}"), exit::DATAERR),
        };
        if fresh_head != pre_lock_head {
            return emit_err(
                "commit aborted: HEAD changed while the commit message was being composed \
                 (a concurrent commit landed) — re-run `mkit commit --amend`",
                exit::TEMPFAIL,
            );
        }
    }

    if opts.all
        && let Err(e) = super::add::stage_tracked_changes(&layout, &store)
    {
        return emit_err(&format!("stage tracked changes: {e}"), exit::GENERAL_ERROR);
    }

    // Finishing a merge: refuse while conflict markers remain and make sure
    // every conflicted path is staged, exactly like `mkit merge --continue`
    // (and `git commit` after a merge). For a clean `merge --no-commit`
    // the record set is empty, so both checks are no-ops.
    if merge_state.is_some() {
        let records = match conflict_state::read_conflicts(layout.worktree_state_dir()) {
            Ok(r) => r,
            Err(e) => return emit_err(&format!("read conflicts: {e}"), exit::GENERAL_ERROR),
        };
        match super::conflict::first_unresolved_marker(&cwd, &records) {
            Ok(Some(path)) => {
                return emit_err(
                    &format!(
                        "committing is not possible because '{path}' still has unresolved \
                         conflict markers; resolve it and `mkit add` it"
                    ),
                    exit::GENERAL_ERROR,
                );
            }
            Ok(None) => {}
            Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
        }
        if let Err(e) = super::conflict::ensure_conflict_paths_staged(&layout, &store, &records) {
            return emit_err(&e, exit::GENERAL_ERROR);
        }
    }

    // Read the staging index. An absent file OR a totally empty
    // entries vector is a hard error — see module docs and issue
    // #102. An all-Removed index, by contrast, is a meaningful
    // changeset (the user is committing deletions) and produces an
    // empty-tree commit, so we DON'T gate on `staged_count()` (which
    // excludes Removed entries by design).
    let idx = match index::read_index(&layout) {
        Ok(idx) => idx,
        Err(e) => return emit_err(&format!("read index: {e}"), exit::GENERAL_ERROR),
    };
    // A merge being concluded may legitimately produce an empty tree (both
    // sides deleted everything), so the empty-index gate is skipped while a
    // merge is in progress — the two-parent merge commit is still meaningful.
    // (A merge that made NO net change vs HEAD is caught below, after the tree
    // is built, matching git's "nothing to commit".)
    if idx.entries.is_empty() && merge_state.is_none() {
        return emit_err(
            "nothing staged: index is empty; run `mkit add <path>` (or `mkit add .`) before commit",
            exit::USAGE,
        );
    }
    // One durability batch spans every tree object plus the commit
    // object; committed below, BEFORE the ref advance that makes the
    // commit reachable.
    let batch = store.batch();
    // Publishing a durable commit — verify staged objects before the tree
    // references them.
    let tree_hash = match worktree::build_tree_from_index_with(&store, &batch, &idx, true) {
        Ok(h) => h,
        Err(e) => return emit_err(&format!("build tree: {e}"), exit::GENERAL_ERROR),
    };
    // Refuse a no-op merge commit produced by discarding the staged merge
    // (e.g. `reset` between `merge --no-commit` and `commit`), matching git's
    // "nothing to commit". The staged tree equaling `ORIG_HEAD` is necessary
    // but NOT sufficient — a legitimate merge of divergent branches can
    // produce HEAD's tree (e.g. both sides deleted the same file). So only
    // refuse when the recorded merge RESULT differs from HEAD yet the staged
    // tree matches it: that means the merge changed something the user then
    // reverted. (Absent result tree → don't refuse, preserving old behavior.)
    if let Some(state) = &merge_state
        && let Ok(Object::Commit(orig)) = store.read_object(&state.orig_head)
        && orig.tree_hash == tree_hash
        && conflict_state::read_result_tree(layout.worktree_state_dir())
            .ok()
            .flatten()
            .is_some_and(|result| result != orig.tree_hash)
    {
        return emit_err(
            "nothing to commit: the staged merge was discarded (its result \
             differs from HEAD but the index matches HEAD); re-stage it or run \
             `mkit merge --abort`",
            exit::USAGE,
        );
    }
    // Parent selection. A normal commit builds on HEAD. An `--amend`
    // replaces HEAD, so it adopts HEAD's *parents* — the superseded
    // commit drops out of the chain entirely.
    let parents = if let Some(prev) = &amend_target {
        prev.parents.clone()
    } else if let Some(state) = &merge_state {
        // Two-parent merge commit. Use the merge's recorded base
        // (`ORIG_HEAD`) as the first parent — NOT the live HEAD — so the
        // result matches `mkit merge --continue` even if HEAD moved (e.g. a
        // `reset` between `merge --no-commit` and `commit`), and so we never
        // depend on a HEAD read that could silently drop a parent.
        vec![state.orig_head, state.merge_head]
    } else {
        match refs::resolve_head(&layout) {
            Ok(Some(h)) => vec![h],
            _ => vec![],
        }
    };
    // Capture parent shape before `parents` is moved into the commit, for
    // the git-shaped summary (root = no parents, merge = >=2 parents) and
    // the `--format=json` payload.
    let is_root = parents.is_empty();
    let is_merge = parents.len() >= 2;
    let first_parent = parents.first().copied();
    let parents_for_json = parents.clone();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut unsigned = Commit::new_unannotated(
        tree_hash,
        parents,
        author,
        signer_public,
        msg.as_bytes().to_vec(),
        timestamp,
        [0u8; 64],
    );
    let sig = match signer.sign_commit(&unsigned) {
        Ok(s) => s,
        Err((msg, code)) => return emit_err(&msg, code),
    };
    unsigned.signature = sig;
    let bytes = match serialize::serialize(&Object::Commit(unsigned)) {
        Ok(b) => b,
        Err(e) => return emit_err(&format!("serialize commit: {e}"), exit::DATAERR),
    };
    let commit_hash = match batch.write(&bytes) {
        Ok(h) => h,
        Err(e) => return emit_err(&format!("store commit: {e}"), exit::CANTCREAT),
    };
    // Make the tree + commit objects durable before anything (recovery
    // log, HEAD/branch ref, index) references them.
    if let Err(e) = batch.commit() {
        return emit_err(&format!("store commit: {e}"), exit::CANTCREAT);
    }
    // Amend supersedes the old HEAD. Record it BEFORE moving the branch
    // (under the worktree lock) so the superseded commit stays
    // recoverable; abort if the recovery log can't be written.
    if amend_target.is_some() {
        match refs::resolve_head(&layout) {
            Ok(Some(old_head)) => {
                let branch = super::head_branch_name(&layout);
                if let Err((m, c)) = super::record_superseded(&layout, "amend", &branch, old_head) {
                    return emit_err(&m, c);
                }
            }
            Ok(None) => {}
            Err(e) => return emit_err(&format!("read HEAD: {e}"), exit::DATAERR),
        }
    }
    // The tip this commit was actually built on, enforced as advance_head's
    // CAS precondition (issue #658, Fix B) — which value counts as "the
    // tip" depends on the mode:
    //
    // - `--amend`: NOT `parents` (that's the superseded commit's OWN
    //   parents, one generation further back) — it's `pre_lock_head`,
    //   already re-validated fresh against HEAD above (the staleness
    //   check a few dozen lines up), i.e. the commit actually being
    //   replaced.
    // - merge-conclusion: NOT `first_parent` (`state.orig_head`) — that's
    //   deliberately decoupled from live HEAD (see the parent-selection
    //   comment above), so using it here would let this CAS silently pass
    //   even when HEAD has moved. Read HEAD fresh, right here, at the
    //   actual moment of the ref advance.
    // - plain commit: `first_parent`, which IS a fresh HEAD read (done
    //   above, inside this same lock hold) — nothing has mutated HEAD
    //   between that read and here, so no re-read is needed.
    let expected_tip = if amend_target.is_some() {
        pre_lock_head
    } else if merge_state.is_some() {
        match refs::resolve_head(&layout) {
            Ok(h) => h,
            Err(e) => return emit_err(&format!("read HEAD: {e}"), exit::DATAERR),
        }
    } else {
        first_parent
    };
    if let Err((m, c)) = advance_head(&layout, &commit_hash, expected_tip) {
        return emit_err(&m, c);
    }
    if let Err(e) = super::sync_index_to_tree(&layout, &store, tree_hash) {
        return emit_err(&e, exit::CANTCREAT);
    }
    // The merge is now recorded; clear MERGE_HEAD/MERGE_MSG/conflicts so the
    // repo is no longer "merging".
    if merge_state.is_some()
        && let Err(e) = conflict_state::clear_merge_state(&layout)
    {
        return emit_err(&format!("clear merge state: {e}"), exit::GENERAL_ERROR);
    }
    // git-shaped post-commit summary: `[<branch> <hash>] <subject>` plus
    // a diffstat and create/delete-mode trailers. Merge commits (>=2
    // parents) show no diffstat, like git.
    let old_tree = if is_merge {
        Some(tree_hash) // suppress the diffstat (empty diff) for merges
    } else {
        first_parent.and_then(|p| commit_tree(&store, &p))
    };
    let branch_name = match refs::read_head(&layout) {
        Ok(Head::Branch(b)) => Some(b),
        _ => None,
    };
    let head_ref = match &branch_name {
        Some(b) => super::summary::HeadRef::Branch(b),
        None => super::summary::HeadRef::Detached,
    };
    if !opts.quiet {
        let mut stderr = std::io::stderr().lock();
        super::summary::print_commit_summary(
            &mut stderr,
            &store,
            &head_ref,
            &commit_hash,
            msg.lines().next().unwrap_or(""),
            is_root,
            old_tree,
            Some(tree_hash),
        );
    }
    if json {
        let mut obj = JsonObject::new();
        obj.field_bool("ok", true)
            .field_hash("hash", &commit_hash)
            .field_opt_str("branch", branch_name.as_deref())
            .field_raw(
                "parents",
                &format::json_string_array(
                    &parents_for_json
                        .iter()
                        .map(format::hex_hash)
                        .collect::<Vec<_>>(),
                ),
            )
            .field_hash("tree", &tree_hash)
            .field_str("subject", msg.lines().next().unwrap_or(""))
            .field_bool("is_merge", is_merge)
            .field_bool("is_root", is_root);
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "{}", obj.finish());
    }
    exit::OK
}

/// Resolve a commit/remix hash to its tree hash (None on any error or a
/// non-commit object) — used to bound the post-commit diffstat.
fn commit_tree(
    store: &ObjectStore,
    commit: &mkit_core::hash::Hash,
) -> Option<mkit_core::hash::Hash> {
    match store.read_object(commit).ok()? {
        Object::Commit(c) => Some(c.tree_hash),
        Object::Remix(r) => Some(r.tree_hash),
        _ => None,
    }
}

/// Pre-process `args` to canonicalize the legacy `-am<msg>` /
/// `-am <msg>` shortcut into `-a -m <msg>`. Everything else passes
/// through unchanged. Clap then sees only canonical forms.
fn expand_dash_am(args: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(args.len() + 2);
    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        match a.as_str() {
            "-am" => {
                out.push("-a".to_owned());
                out.push("-m".to_owned());
                if let Some(next) = iter.next() {
                    out.push(next.clone());
                }
            }
            s if s.starts_with("-am") && s.len() > 3 => {
                out.push("-a".to_owned());
                out.push("-m".to_owned());
                out.push(s[3..].to_owned());
            }
            _ => out.push(a.clone()),
        }
    }
    out
}

#[cfg(test)]
mod expand_dash_am_tests {
    use super::expand_dash_am;

    fn to_strs(args: &[String]) -> Vec<&str> {
        args.iter().map(String::as_str).collect()
    }

    #[test]
    fn fused_dash_am_with_inline_message() {
        let out = expand_dash_am(&["-amhello".to_owned()]);
        assert_eq!(to_strs(&out), &["-a", "-m", "hello"]);
    }

    #[test]
    fn spaced_dash_am_with_following_message() {
        let out = expand_dash_am(&["-am".to_owned(), "hello".to_owned()]);
        assert_eq!(to_strs(&out), &["-a", "-m", "hello"]);
    }

    #[test]
    fn unrelated_args_pass_through() {
        let out = expand_dash_am(&[
            "-m".to_owned(),
            "msg".to_owned(),
            "--author".to_owned(),
            "id".to_owned(),
        ]);
        assert_eq!(to_strs(&out), &["-m", "msg", "--author", "id"]);
    }
}

/// Load the Ed25519 signing key. Returns a mapped (message,
/// exit-code) pair on failure so the caller can route the error
/// through its usual `emit_err` path.
///
/// Auto-generation was removed: combined with a non-atomic `save_key`,
/// an interrupted keygen could silently rotate the user's identity
/// (subsequent commits no longer share a signer with prior ones). The
/// save path is now atomic, but auto-keygen also masks genuine
/// path-misconfigurations and tooling errors. Users run `mkit keygen`
/// once, explicitly, and a missing key on `mkit commit` is now an error.
fn load_signing_key(
    layout: &RepoLayout,
    rel_signing_key_path: &str,
) -> Result<KeyPair, (String, u8)> {
    let key_path = match crate::config::resolve_key_path(layout, rel_signing_key_path) {
        Ok(p) => p,
        Err(e) => return Err((format!("{e}"), exit::CONFIG_ERROR)),
    };
    if !key_path.exists() {
        return Err((
            format!(
                "no signing key at {} — run `mkit keygen` to create one",
                key_path.display()
            ),
            exit::NOINPUT,
        ));
    }
    sign::load_key(&key_path).map_err(|e| (format!("load key: {e}"), exit::NOPERM))
}

pub(super) enum CommitSigner {
    Legacy(KeyPair),
    Keystore(Box<dyn mkit_keystore::KeySigner>),
}

impl CommitSigner {
    pub(super) fn public_key(&self) -> Result<[u8; 32], (String, u8)> {
        match self {
            Self::Legacy(kp) => Ok(kp.public.0),
            Self::Keystore(signer) => {
                let public = signer
                    .public_key()
                    .map_err(|error| (format!("keystore public key: {error}"), exit::DATAERR))?;
                public.as_bytes().try_into().map_err(|_| {
                    (
                        format!(
                            "keystore Ed25519 public key must be 32 bytes, got {}",
                            public.len()
                        ),
                        exit::DATAERR,
                    )
                })
            }
        }
    }

    /// Sign a [`Tag`] under the distinct tag domain. Mirrors
    /// [`Self::sign_commit`]: legacy keypairs sign directly, keystore
    /// signers sign the pre-computed tag signing hash.
    pub(super) fn sign_tag(&mut self, tag: &Tag) -> Result<[u8; 64], (String, u8)> {
        match self {
            Self::Legacy(kp) => sign::sign_tag(tag, kp)
                .map(|signature| signature.0)
                .map_err(|error| (format!("sign: {error}"), exit::GENERAL_ERROR)),
            Self::Keystore(signer) => {
                let digest = sign::tag_signing_hash(tag)
                    .map_err(|error| (format!("tag signing hash: {error}"), exit::DATAERR))?;
                let signature = signer
                    .sign(&digest)
                    .map_err(|error| (format!("keystore sign: {error}"), exit::DATAERR))?;
                signature.try_into().map_err(|signature: Vec<u8>| {
                    (
                        format!(
                            "keystore Ed25519 signature must be 64 bytes, got {}",
                            signature.len()
                        ),
                        exit::DATAERR,
                    )
                })
            }
        }
    }

    pub(super) fn sign_commit(&mut self, commit: &Commit) -> Result<[u8; 64], (String, u8)> {
        match self {
            Self::Legacy(kp) => sign::sign_commit(commit, kp)
                .map(|signature| signature.0)
                .map_err(|error| (format!("sign: {error}"), exit::GENERAL_ERROR)),
            Self::Keystore(signer) => {
                let digest = sign::commit_signing_hash(commit)
                    .map_err(|error| (format!("commit signing hash: {error}"), exit::DATAERR))?;
                let signature = signer
                    .sign(&digest)
                    .map_err(|error| (format!("keystore sign: {error}"), exit::DATAERR))?;
                signature.try_into().map_err(|signature: Vec<u8>| {
                    (
                        format!(
                            "keystore Ed25519 signature must be 64 bytes, got {}",
                            signature.len()
                        ),
                        exit::DATAERR,
                    )
                })
            }
        }
    }
}

pub(super) fn load_commit_signer(
    layout: &RepoLayout,
    cfg: &Config,
) -> Result<CommitSigner, (String, u8)> {
    match cfg.signer.as_str() {
        "" | "legacy" => load_signing_key(layout, &cfg.signing_key).map(CommitSigner::Legacy),
        "keystore" => load_keystore_commit_signer(cfg),
        other => Err((
            format!("unknown signer `{other}` — expected `legacy` or `keystore`"),
            exit::CONFIG_ERROR,
        )),
    }
}

fn load_keystore_commit_signer(cfg: &Config) -> Result<CommitSigner, (String, u8)> {
    let key_ref = cfg
        .key
        .ed25519_ref_or_fallback()
        .parse::<KeyRef>()
        .map_err(|error| (format!("key.ed25519_ref: {error}"), exit::CONFIG_ERROR))?;
    let store = open_backend(key_ref.backend())
        .map_err(|error| (format!("keystore backend: {error}"), exit::UNAVAILABLE))?;
    let selector = KeySelector::new(
        key_ref.label().to_owned(),
        Some(mkit_keystore::Algorithm::Ed25519),
    )
    .map_err(|error| (format!("key.ed25519_ref: {error}"), exit::CONFIG_ERROR))?;
    let opener = store.opener().ok_or_else(|| {
        (
            format!(
                "keystore backend `{}` does not support opening keys",
                key_ref.backend()
            ),
            exit::DATAERR,
        )
    })?;
    let signer = opener.open(&selector).map_err(|error| match error {
        mkit_keystore::Error::KeyNotFound(_) => (
            format!(
                "missing keystore signing key for algorithm ed25519 — run `mkit key generate --backend {} --algorithm ed25519 --label <label>` first, or set `signer = legacy` and use `mkit keygen`: {error}",
                key_ref.backend()
            ),
            exit::NOINPUT,
        ),
        other => (
            format!("keystore signing key for algorithm ed25519: {other}"),
            exit::DATAERR,
        ),
    })?;
    Ok(CommitSigner::Keystore(signer))
}

/// Resolve the commit that `--amend` will replace.
///
/// Returns the decoded HEAD [`Commit`]. The new amended commit reuses
/// this commit's parents and (absent `-m`) its message. Errors when
/// HEAD has no commit yet (nothing to amend) or when HEAD does not
/// resolve to a `Commit` object.
fn resolve_amend_target(layout: &RepoLayout, store: &ObjectStore) -> Result<Commit, (String, u8)> {
    let head = refs::resolve_head(layout)
        .map_err(|e| (format!("read HEAD: {e}"), exit::DATAERR))?
        .ok_or_else(|| {
            (
                "nothing to amend: HEAD has no commit yet".to_owned(),
                exit::USAGE,
            )
        })?;
    match store.read_object(&head) {
        Ok(Object::Commit(c)) => Ok(c),
        Ok(_) => Err((
            format!(
                "cannot amend: HEAD {} is not a commit",
                format::hex_hash(&head)
            ),
            exit::DATAERR,
        )),
        Err(e) => Err((
            format!("read HEAD commit {}: {e}", format::hex_hash(&head)),
            exit::DATAERR,
        )),
    }
}

/// Advance the branch pointed to by HEAD (or HEAD itself, if detached)
/// to `commit_hash`.
///
/// Routes through [`super::write_ref_recording_history`] so a build
/// with `--features history-mmr` records every advance in the branch's
/// journaled MMR under the repo's `refs-history.lock`. Detached HEAD
/// advances bypass the journal: per-branch history is keyed on a
/// branch name and a detached HEAD has none.
///
/// `expected` is the tip this commit was actually built on top of —
/// `Some(parent)` for a normal advance, `None` for a root commit or an
/// unborn branch's first commit — and is enforced as a CAS precondition
/// (issue #658, Fix B): `Some(t)` becomes `RefWriteCondition::Match(t)`,
/// `None` becomes `RefWriteCondition::Missing`. Before this, the
/// branch-ref advance used `RefWriteCondition::Any`, an unconditional
/// clobber: a concurrent writer (e.g. `branch -m` publishing a stale
/// pre-commit tip under a new name, or another `commit`) could land
/// between this commit composing its parent and this call executing,
/// and `Any` would still "succeed" — silently discarding whichever
/// commit didn't win, with no error to either side. See `run`'s
/// call site for how `expected` is derived per commit mode (plain,
/// `--amend`, merge-conclusion).
fn advance_head(
    layout: &RepoLayout,
    commit_hash: &mkit_core::hash::Hash,
    expected: Option<mkit_core::hash::Hash>,
) -> Result<(), (String, u8)> {
    let head = refs::read_head(layout).map_err(|e| (format!("read HEAD: {e}"), exit::DATAERR))?;
    match head {
        Head::Branch(name) => {
            let condition = match expected {
                Some(h) => refs::RefWriteCondition::Match(h),
                None => refs::RefWriteCondition::Missing,
            };
            super::write_ref_recording_history(layout, &name, condition, commit_hash).map_err(|e| {
                match e {
                    refs::RefError::Conflict(_) => (
                        format!(
                            "commit aborted: branch '{name}' moved underneath this commit \
                             (a concurrent commit landed) — the commit object {} is durable \
                             but currently unreferenced (GC-recoverable), nothing is corrupted; \
                             re-run `mkit commit`",
                            format::hex_hash(commit_hash)
                        ),
                        exit::TEMPFAIL,
                    ),
                    other => (format!("write ref: {other}"), exit::CANTCREAT),
                }
            })
        }
        Head::Detached(_) => refs::write_head_detached(layout, commit_hash)
            .map_err(|e| (format!("update HEAD: {e}"), exit::CANTCREAT)),
    }
}

/// Issue #658, Fix B — direct, deterministic tests of `advance_head`'s
/// CAS enforcement. These exercise the mechanism itself (does it
/// translate `expected` into the right [`refs::RefWriteCondition`], and
/// does a mismatch surface as `TEMPFAIL` rather than a silent clobber)
/// without depending on timing to reproduce a live cross-process race —
/// `branch_rename_commit_race.rs` (a `mkit-cli` integration test) covers
/// the genuine racing scenario end-to-end.
#[cfg(test)]
mod advance_head_tests {
    use super::*;
    use mkit_core::hash::hash;
    use mkit_core::layout::RepoLayout;
    use tempfile::TempDir;

    fn fresh_repo() -> (TempDir, RepoLayout) {
        let dir = TempDir::new().unwrap();
        let layout = RepoLayout::single(dir.path());
        // On `--features history-mmr` builds, `advance_head` routes
        // through `write_ref_recording_history`, which opens the object
        // store (for the empty-journal backfill's `parent_of` walker)
        // even though these tests never actually need a commit object
        // read. `ObjectStore::init` (which also creates the common dir
        // — it errors if the dir already exists) must run BEFORE
        // `refs::init` for exactly that reason.
        mkit_core::store::ObjectStore::init(&layout).unwrap();
        refs::init(&layout).unwrap();
        (dir, layout)
    }

    /// The core Fix B regression: if the branch moved to a value other
    /// than `expected` since the caller captured it (a concurrent
    /// writer landed in the window between `run`'s parent read and this
    /// call), the advance must refuse — `TEMPFAIL`, matching the
    /// existing amend-staleness error's tone — and the concurrently
    /// landed value must survive completely untouched.
    #[test]
    fn advance_head_conflicts_when_branch_moved_since_expected_was_captured() {
        let (_dir, layout) = fresh_repo();
        let t0 = hash(b"t0");
        // Seeded via the same `write_ref_recording_history` helper
        // `advance_head` itself uses (not a raw `refs::write_ref`): on
        // `--features history-mmr` builds a bare ref write with no
        // journal entry makes the NEXT history-aware write try to
        // backfill from `t0` as a real commit object, which it isn't
        // here. `Missing` establishes a proper from-empty journal
        // instead, matching how a real first commit would seed it.
        super::super::write_ref_recording_history(
            &layout,
            "main",
            refs::RefWriteCondition::Missing,
            &t0,
        )
        .unwrap();

        // A concurrent writer (e.g. another commit, or `update-ref`)
        // advances "main" past what this commit's `expected` snapshot
        // (`t0`) describes.
        let moved = hash(b"moved-concurrently");
        super::super::write_ref_recording_history(
            &layout,
            "main",
            refs::RefWriteCondition::Match(t0),
            &moved,
        )
        .unwrap();

        let new_commit = hash(b"new-commit");
        let (msg, code) = advance_head(&layout, &new_commit, Some(t0)).unwrap_err();
        assert_eq!(code, exit::TEMPFAIL);
        assert!(
            msg.contains("moved") && msg.contains("commit aborted"),
            "expected a clear conflict message, got: {msg}"
        );
        assert_eq!(
            refs::read_ref(&layout, "main").unwrap(),
            Some(moved),
            "the concurrently-landed value must survive a refused advance untouched"
        );
    }

    /// Normal case: `expected` matches the ref's current value, so the
    /// `Match` CAS succeeds and the branch advances.
    #[test]
    fn advance_head_succeeds_when_expected_matches_current_value() {
        let (_dir, layout) = fresh_repo();
        let t0 = hash(b"t0");
        super::super::write_ref_recording_history(
            &layout,
            "main",
            refs::RefWriteCondition::Missing,
            &t0,
        )
        .unwrap();

        let c1 = hash(b"c1");
        advance_head(&layout, &c1, Some(t0)).unwrap();
        assert_eq!(refs::read_ref(&layout, "main").unwrap(), Some(c1));
    }

    /// Root commit / unborn-branch case: `expected = None` becomes
    /// `RefWriteCondition::Missing`, which succeeds when the branch has
    /// no ref yet.
    #[test]
    fn advance_head_missing_condition_succeeds_for_a_fresh_branch() {
        let (_dir, layout) = fresh_repo();
        let c1 = hash(b"root-commit");
        advance_head(&layout, &c1, None).unwrap();
        assert_eq!(refs::read_ref(&layout, "main").unwrap(), Some(c1));
    }

    /// If a concurrent writer raced to create the branch first (e.g.
    /// another root commit landed), `Missing` must refuse rather than
    /// silently overwrite it.
    #[test]
    fn advance_head_missing_condition_conflicts_when_branch_already_exists() {
        let (_dir, layout) = fresh_repo();
        let raced_in = hash(b"raced-in-first");
        super::super::write_ref_recording_history(
            &layout,
            "main",
            refs::RefWriteCondition::Missing,
            &raced_in,
        )
        .unwrap();

        let c1 = hash(b"root-commit");
        let (_, code) = advance_head(&layout, &c1, None).unwrap_err();
        assert_eq!(code, exit::TEMPFAIL);
        assert_eq!(refs::read_ref(&layout, "main").unwrap(), Some(raced_in));
    }
}

/// Resolve the commit author. See [`run`] for precedence order.
///
/// Exposed to sibling commands (`cherry_pick`, `merge`) so they apply
/// the same precedence as `commit`: `--author` flag (if any) → user-
/// scoped `user.identity` config → signer pubkey fallback. They pass
/// `None` for `author_flag` because they don't accept that flag.
pub(super) fn resolve_author(
    author_flag: Option<&str>,
    cfg_user_identity: &str,
    signer_public: &[u8; 32],
) -> Result<Identity, String> {
    if let Some(spec) = author_flag {
        return parse_author_spec(spec);
    }
    if !cfg_user_identity.is_empty() {
        return decode_user_identity_hex(cfg_user_identity);
    }
    Ok(Identity::ed25519(*signer_public))
}

/// Parse a `--author` flag value.
///
/// Accepted forms:
/// * `ed25519:<64-char hex>` — 32-byte Ed25519 public key.
/// * `did:key:<multibase>` — a `did:key` whose multibase payload (the part
///   after `did:key:`, e.g. `z6Mk…`) is stored verbatim as the DID payload.
///   It must be a non-empty printable-ASCII multibase string (validated via
///   `Identity::is_valid`), matching the on-disk `DidKey` invariant.
/// * `opaque:<bytes>` — raw UTF-8 bytes, stored as-is.
fn parse_author_spec(spec: &str) -> Result<Identity, String> {
    if let Some(hex) = spec.strip_prefix("ed25519:") {
        let bytes = hex_decode(hex).ok_or_else(|| "ed25519:<hex> invalid hex".to_string())?;
        if bytes.len() != 32 {
            return Err("ed25519:<hex> must decode to 32 bytes".to_string());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        return Ok(Identity::ed25519(arr));
    }
    if let Some(payload) = spec.strip_prefix("did:key:") {
        // Store the multibase payload verbatim (the `did:key:` scheme prefix
        // is stripped). A real did:key is base58btc (`z…`); the on-disk
        // invariant only requires a non-empty printable-ASCII multibase
        // string, so validate through `is_valid` rather than hex-decoding.
        let id = Identity {
            kind: IdentityKind::DidKey,
            bytes: payload.as_bytes().to_vec(),
        };
        if !id.is_valid() {
            return Err(
                "did:key:<multibase> must be a non-empty printable-ASCII multibase string \
                 (e.g. did:key:z6Mk…)"
                    .to_string(),
            );
        }
        return Ok(id);
    }
    if let Some(raw) = spec.strip_prefix("opaque:") {
        if raw.is_empty() {
            return Err("opaque:<bytes> must not be empty".to_string());
        }
        return Ok(Identity::opaque(raw.as_bytes().to_vec()));
    }
    Err(format!(
        "unknown identity spec '{spec}' — expected ed25519:<hex>, did:key:<multibase>, or opaque:<bytes>"
    ))
}

/// Decode a `user.identity` config string into an [`Identity`]. The
/// config file stores the canonical `[kind:u8][len:u16 LE][bytes]`
/// form (see `config::expand_user_identity`), so we invert that here.
fn decode_user_identity_hex(hex: &str) -> Result<Identity, String> {
    let bytes =
        hex_decode(hex).ok_or_else(|| "user.identity: not a lowercase hex string".to_string())?;
    if bytes.len() < 3 {
        return Err("user.identity: too short (kind + len prefix missing)".to_string());
    }
    let kind_byte = bytes[0];
    let declared_len = u16::from(bytes[1]) | (u16::from(bytes[2]) << 8);
    if bytes.len() != usize::from(declared_len) + 3 {
        return Err("user.identity: declared length does not match payload".to_string());
    }
    let payload = bytes[3..].to_vec();
    let kind = match kind_byte {
        0x01 => IdentityKind::Ed25519,
        0x02 => IdentityKind::DidKey,
        // 0x03 (mid) shares the Opaque variant — upstream compat.
        0x03 | 0x04 => IdentityKind::Opaque,
        other => return Err(format!("user.identity: unknown kind byte {other:#04x}")),
    };
    if kind == IdentityKind::Ed25519 && payload.len() != 32 {
        return Err("user.identity: ed25519 payload must be exactly 32 bytes".to_string());
    }
    Ok(Identity {
        kind,
        bytes: payload,
    })
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hi = nibble(b[i])?;
        let lo = nibble(b[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn nibble(c: u8) -> Option<u8> {
    Some(match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => 10 + c - b'a',
        b'A'..=b'F' => 10 + c - b'A',
        _ => return None,
    })
}

/// Read a `-F`/`--file` commit message. `-` reads stdin; otherwise the
/// named file. Trailing whitespace is trimmed (git's default `-F` cleanup
/// drops trailing blank lines).
fn read_message_file(path: &str) -> std::io::Result<String> {
    use std::io::Read as _;
    let raw = if path == "-" {
        let mut s = String::new();
        std::io::stdin().lock().read_to_string(&mut s)?;
        s
    } else {
        std::fs::read_to_string(path)?
    };
    Ok(raw.trim_end().to_string())
}

use super::error as emit_err;

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_keystore::Keystore;

    #[test]
    fn parse_author_ed25519_roundtrips() {
        let hex = "11".repeat(32);
        let spec = format!("ed25519:{hex}");
        let id = parse_author_spec(&spec).unwrap();
        assert_eq!(id.kind, IdentityKind::Ed25519);
        assert_eq!(id.bytes.len(), 32);
        assert!(id.bytes.iter().all(|&b| b == 0x11));
    }

    #[test]
    fn parse_author_rejects_bad_ed25519() {
        assert!(parse_author_spec("ed25519:short").is_err());
        assert!(parse_author_spec("ed25519:zzzzz").is_err());
    }

    #[test]
    fn parse_author_did_key_stores_multibase_payload() {
        // The multibase payload after `did:key:` is stored verbatim as ASCII.
        let id = parse_author_spec("did:key:z6MkExample").unwrap();
        assert_eq!(id.kind, IdentityKind::DidKey);
        assert_eq!(id.bytes, b"z6MkExample");
        assert!(id.is_valid());
    }

    #[test]
    fn parse_author_did_key_rejects_non_multibase() {
        // Empty payload and non-printable/whitespace payloads are rejected
        // (consistent with the on-disk DidKey invariant).
        assert!(parse_author_spec("did:key:").is_err());
        assert!(parse_author_spec("did:key:has space").is_err());
    }

    #[test]
    fn parse_author_opaque_takes_raw_bytes() {
        let id = parse_author_spec("opaque:hello world").unwrap();
        assert_eq!(id.kind, IdentityKind::Opaque);
        assert_eq!(id.bytes, b"hello world");
    }

    #[test]
    fn parse_author_rejects_unknown_prefix() {
        assert!(parse_author_spec("foo:bar").is_err());
        assert!(parse_author_spec("").is_err());
    }

    #[test]
    fn decode_user_identity_ed25519_roundtrip() {
        // Mirror expand_user_identity("ed25519:<hex>") output.
        // 0x01 + len(32=0x20,0x00) + 32 bytes of 0xAB.
        let mut hex = String::from("012000");
        hex.push_str(&"ab".repeat(32));
        let id = decode_user_identity_hex(&hex).unwrap();
        assert_eq!(id.kind, IdentityKind::Ed25519);
        assert_eq!(id.bytes.len(), 32);
    }

    #[test]
    fn decode_user_identity_rejects_length_mismatch() {
        let hex = "011000aabbcc"; // declares 16 bytes, provides 3
        assert!(decode_user_identity_hex(hex).is_err());
    }

    #[test]
    fn resolve_author_prefers_flag_over_config() {
        let kp = KeyPair::generate().unwrap();
        let hex = "22".repeat(32);
        let spec = format!("ed25519:{hex}");
        // Populate config with a DIFFERENT identity to verify flag wins.
        let cfg_hex = {
            let mut s = String::from("012000");
            s.push_str(&"33".repeat(32));
            s
        };
        let id = resolve_author(Some(&spec), &cfg_hex, &kp.public.0).unwrap();
        assert!(id.bytes.iter().all(|&b| b == 0x22));
    }

    #[test]
    fn resolve_author_uses_config_when_no_flag() {
        let kp = KeyPair::generate().unwrap();
        let mut cfg_hex = String::from("012000");
        cfg_hex.push_str(&"44".repeat(32));
        let id = resolve_author(None, &cfg_hex, &kp.public.0).unwrap();
        assert_eq!(id.kind, IdentityKind::Ed25519);
        assert!(id.bytes.iter().all(|&b| b == 0x44));
    }

    #[test]
    fn resolve_author_falls_back_to_pubkey() {
        let kp = KeyPair::generate().unwrap();
        let id = resolve_author(None, "", &kp.public.0).unwrap();
        assert_eq!(id.kind, IdentityKind::Ed25519);
        assert_eq!(id.bytes, kp.public.0.to_vec());
    }

    #[test]
    fn keystore_commit_signature_matches_legacy_keypair_signature() {
        let seed = [0x5a; 32];
        let kp = KeyPair::from_seed(seed);
        let store_root = tempfile::tempdir().unwrap();
        let store = mkit_keystore::SoftwareRawKeystore::with_root(store_root.path().join("keys"));
        store
            .importer()
            .unwrap()
            .import(
                &mkit_keystore::KeyLabel::new("committer").unwrap(),
                mkit_keystore::SecretKey::new(mkit_keystore::Algorithm::Ed25519, seed),
                mkit_keystore::KeyAttrs::default(),
                mkit_keystore::ImportOptions::default(),
            )
            .unwrap();
        let selector =
            mkit_keystore::KeySelector::new("committer", Some(mkit_keystore::Algorithm::Ed25519))
                .unwrap();
        let mut signer = CommitSigner::Keystore(store.opener().unwrap().open(&selector).unwrap());
        let signer_public = signer.public_key().unwrap();
        let commit = Commit::new_unannotated(
            [1; 32],
            vec![[2; 32]],
            Identity::ed25519(signer_public),
            signer_public,
            b"same commit".to_vec(),
            123,
            [0; 64],
        );

        let keystore_sig = signer.sign_commit(&commit).unwrap();
        let legacy_sig = sign::sign_commit(&commit, &kp).unwrap().0;
        assert_eq!(keystore_sig, legacy_sig);
    }
}
