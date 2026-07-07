//! `mkit git import` / `mkit git fetch` / `mkit git pull` — the
//! importer-signed git→mkit direction (SPEC-GIT-IMPORT; feature
//! `git-bridge`).
//!
//! Import clones a `--mirror` staging repo under
//! `.mkit/git/<remote>/repo.git`, translates through the
//! mkit-git-bridge engine under a DEDICATED import key (pinned in the
//! state dir), lands branches in `refs/remotes/<remote>/*` (plus
//! `refs/heads/<default>` + worktree checkout in the fresh-clone
//! form), retains raw commit/tag bytes, and mints git-import/v1
//! attestations per head. Fetch updates tracking refs only; pull adds
//! the native fast-forward of the current branch. Integration with
//! local work is NATIVE (`mkit merge <remote>/<branch>`).

use clap::Parser;
use mkit_attest::Signer as _;
use mkit_attest::{Envelope, PAYLOAD_TYPE_IN_TOTO, Sig, statement, store as attest_store};
use mkit_core::layout::RepoLayout;
use mkit_core::object::{Object, ObjectType};
use mkit_core::sign::{KeyPair, sign_commit, sign_tag};
use mkit_core::store::BulkWriter;
use mkit_core::{Hash, ObjectStore, refs};
use mkit_git_bridge::error::BridgeError;
use mkit_git_bridge::gitobj::{Sha1Id, bytes_hex, sha1_hex};
use mkit_git_bridge::gitsrc::{self, CatFileBatch};
use mkit_git_bridge::import::{
    DepthMemo, IMPORT_SPEC_VERSION, ImportOptions, ImportSigner, Importer, ObjectSink,
};
use mkit_git_bridge::map::{self, Direction};
use mkit_git_bridge::remoteid::remote_identity;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::exit;
use crate::format;

/// SPEC-GIT-IMPORT §5 predicate type.
const PREDICATE_TYPE: &str =
    "https://github.com/officialunofficial/mkit/spec/predicate/git-import/v1";

/// Default dedicated import key path (SPEC-GIT-IMPORT §4).
const IMPORT_KEY_FILE: &str = "keys/git-import.key";

/// Crash marker: present while a bulk import session is open; found
/// at start ⇒ the previous session crashed ⇒ discard the map cache
/// (objects may be torn; the map must not vouch for them).
const IMPORTING_MARKER: &str = "importing";

#[derive(Debug, Parser)]
pub struct ImportArgs {
    /// Upstream git URL or local path.
    pub url: String,
    /// Directory for the fresh-clone form (omit to import into the
    /// current mkit repository as tracking refs only).
    pub dir: Option<String>,
    /// Bridge state name under `.mkit/git/<name>/`.
    #[arg(long = "remote-name", value_name = "NAME", default_value = "upstream")]
    pub remote_name: String,
    /// Path to the import signing key (32-byte seed file). Default:
    /// `.mkit/keys/git-import.key`, generated on first use.
    #[arg(long = "key", value_name = "PATH")]
    pub key: Option<String>,
    /// Machine-readable JSON on stdout.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Parser)]
pub struct FetchArgs {
    /// Bridge state name under `.mkit/git/<name>/`.
    #[arg(long = "remote-name", value_name = "NAME", default_value = "upstream")]
    pub remote_name: String,
    /// Path to the import signing key (default: the pinned key file).
    #[arg(long = "key", value_name = "PATH")]
    pub key: Option<String>,
    /// Machine-readable JSON on stdout.
    #[arg(long)]
    pub json: bool,
}

type CmdResult<T> = Result<T, (String, u8)>;

// ─── entry points ───────────────────────────────────────────────────

#[must_use]
pub fn run_import(opts: &ImportArgs) -> u8 {
    let outcome = match opts.dir.as_deref() {
        Some(dir) => fresh_clone(opts, dir),
        None => std::env::current_dir()
            .map_err(|e| (format!("cwd: {e}"), exit::CONFIG_ERROR))
            .and_then(|cwd| import_into(&super::resolve_layout(&cwd), opts, true)),
    };
    finish(outcome, opts.json)
}

#[must_use]
pub fn run_fetch(opts: &FetchArgs, pull: bool) -> u8 {
    let outcome = std::env::current_dir()
        .map_err(|e| (format!("cwd: {e}"), exit::CONFIG_ERROR))
        .and_then(|cwd| fetch_and_maybe_pull(&super::resolve_layout(&cwd), opts, pull));
    finish(outcome, opts.json)
}

fn finish(outcome: CmdResult<Summary>, json: bool) -> u8 {
    match outcome {
        Ok(summary) => {
            summary.print(json);
            if summary.imported.is_empty() && !summary.skipped.is_empty() {
                emit_err(
                    &format!(
                        "every requested ref was skipped ({} refusals)",
                        summary.skipped.len()
                    ),
                    exit::GENERAL_ERROR,
                )
            } else {
                exit::OK
            }
        }
        Err((msg, code)) => emit_err(&msg, code),
    }
}

// ─── the forms ──────────────────────────────────────────────────────

/// `mkit git import <url> <dir>`: init a fresh repo, import, check
/// out the upstream default branch.
/// An option-shaped "url" must never reach a git argv (argument
/// injection: `--upload-pack=...` etc.), and an empty one would make
/// git operate on whatever directory it happens to be in. Checked
/// FIRST — before any directory is created or stamped.
fn validate_url(url: &str) -> CmdResult<()> {
    if url.trim().is_empty() {
        return Err(("empty git URL or path".into(), exit::USAGE));
    }
    if url.starts_with('-') {
        return Err((
            format!("{url:?} is not a valid git URL or path"),
            exit::USAGE,
        ));
    }
    Ok(())
}

fn fresh_clone(opts: &ImportArgs, dir: &str) -> CmdResult<Summary> {
    validate_url(&opts.url)?;
    let target = PathBuf::from(dir);
    if target.exists() && std::fs::read_dir(&target).map_or(true, |mut d| d.next().is_some()) {
        return Err((
            format!("destination '{dir}' already exists"),
            exit::CANTCREAT,
        ));
    }
    let created = !target.exists();
    std::fs::create_dir_all(&target).map_err(|e| (format!("mkdir: {e}"), exit::CANTCREAT))?;
    let layout = super::resolve_layout(&target);
    ObjectStore::init(&layout).map_err(|e| (format!("init: {e}"), exit::CANTCREAT))?;
    refs::init(&layout).map_err(|e| (format!("refs init: {e}"), exit::CANTCREAT))?;
    let mut summary = match import_into(&layout, opts, false) {
        Ok(s) => s,
        Err(e) => {
            // Undo this run's work so a corrected retry is not refused
            // with "destination already exists" — but only remove the
            // DIRECTORY itself if this run created it (a pre-existing
            // empty dir may carry meaning: ownership, mode, mountpoint).
            if created {
                let _ = std::fs::remove_dir_all(&target);
            } else if let Ok(rd) = std::fs::read_dir(&target) {
                for entry in rd.flatten() {
                    let p = entry.path();
                    let _ = if p.is_dir() {
                        std::fs::remove_dir_all(&p)
                    } else {
                        std::fs::remove_file(&p)
                    };
                }
            }
            return Err(e);
        }
    };

    // Check out the upstream default branch.
    let staging = map::state_dir(&layout, &opts.remote_name)
        .map_err(|e| (e.to_string(), exit::USAGE))?
        .join("repo.git");
    let default = gitsrc::default_branch(&staging)
        .map_err(|e| (format!("default branch: {e}"), exit::GENERAL_ERROR))?
        .and_then(|r| r.strip_prefix("refs/heads/").map(str::to_owned));
    if let Some(branch) = default
        && let Some(head) = refs::read_remote_ref(&layout, &opts.remote_name, &branch)
            .map_err(|e| (format!("read tracking ref: {e}"), exit::GENERAL_ERROR))?
    {
        checkout_initial(&layout, &branch, &head)?;
        summary.checked_out = Some(branch);
    }
    Ok(summary)
}

fn checkout_initial(layout: &RepoLayout, branch: &str, head: &Hash) -> CmdResult<()> {
    let store =
        ObjectStore::open(layout).map_err(|e| (format!("open store: {e}"), exit::GENERAL_ERROR))?;
    let tree = match store.read_object(head) {
        Ok(Object::Commit(c)) => c.tree_hash,
        Ok(Object::Tag(_) | _) | Err(_) => {
            return Err(("imported head is not a commit".into(), exit::DATAERR));
        }
    };
    super::write_ref_recording_history(
        layout,
        branch,
        mkit_core::refs::RefWriteCondition::Missing,
        head,
    )
    .map_err(|e| (format!("write branch: {e}"), exit::CANTCREAT))?;
    refs::write_head_branch(layout, branch)
        .map_err(|e| (format!("write HEAD: {e}"), exit::CANTCREAT))?;
    super::restore_worktree_and_index(layout, &store, tree)
        .map_err(|e| (format!("checkout: {e}"), exit::GENERAL_ERROR))?;
    Ok(())
}

/// Import/refresh into an existing repo: tracking refs + tags only.
fn import_into(layout: &RepoLayout, opts: &ImportArgs, require_repo: bool) -> CmdResult<Summary> {
    if require_repo {
        ObjectStore::open(layout)
            .map_err(|e| (format!("open repository: {e}"), exit::GENERAL_ERROR))?;
    }
    super::git::git_version().map_err(|e| (e, exit::UNAVAILABLE))?;

    validate_url(&opts.url)?;

    let state =
        map::state_dir(layout, &opts.remote_name).map_err(|e| (e.to_string(), exit::USAGE))?;
    // One bridge operation per state dir at a time: concurrent runs
    // would race the crash marker / map discard / bulk session.
    let _state_lock = mkit_core::repo_lock::acquire_default(
        layout.common_dir(),
        &format!("git-{}.lock", opts.remote_name),
    )
    .map_err(|e| {
        (
            format!(
                "bridge state '{}' is busy (another mkit git operation?): {e}",
                opts.remote_name
            ),
            exit::TEMPFAIL,
        )
    })?;
    // VALIDATE existing bindings before any network/disk work, but
    // RECORD new ones only after the clone + sha256 check succeed: a
    // typo'd URL must not permanently burn the state name (there is
    // no CLI command to unbind it).
    validate_import_bindings(layout, &state, &opts.url)?;
    let kp = load_or_create_import_key(layout, opts.key.as_deref())?;
    if let Some(pinned) =
        map::read_signer(&state).map_err(|e| (e.to_string(), exit::CONFIG_ERROR))?
        && pinned != kp.public.0
    {
        // Surface the §4 designated-importer refusal before the clone.
        // Deliberately NOT an unconditional bind_signer call: that
        // would WRITE a fresh pin pre-clone, violating the
        // validate-then-bind contract (the pin is recorded with the
        // other bindings only after the clone succeeds).
        map::bind_signer(&state, &kp.public.0).map_err(|e| (e.to_string(), exit::CONFIG_ERROR))?;
    }

    // Staging mirror: clone once, fetch thereafter. Local paths must
    // be absolutized — the clone runs `git -C <state>`, which would
    // resolve a relative path against the state dir.
    let clone_url = absolutize_clone_url(&opts.url);
    let staging = state.join("repo.git");
    // The state dir itself is just a directory (bindings come after a
    // successful clone); `git -C <state>` needs it to exist.
    std::fs::create_dir_all(&state)
        .map_err(|e| (format!("create state dir: {e}"), exit::CANTCREAT))?;
    if staging.join("objects").is_dir() {
        // Explicit refspecs (not the mirror's +refs/*:refs/*) so
        // --prune is scoped to upstream namespaces: fork-mode export
        // state living in this repo (refs/mkit-export/*, the
        // attestation chain ref) must survive an upstream fetch.
        super::git::git_in(
            &staging,
            &[
                "fetch",
                "--quiet",
                "--prune",
                "origin",
                "+refs/heads/*:refs/heads/*",
                "+refs/tags/*:refs/tags/*",
            ],
        )
        .map_err(|e| (format!("fetch upstream: {e}"), exit::UNAVAILABLE))?;
    } else {
        super::git::git_in(
            state.as_path(),
            &["clone", "--mirror", "--quiet", &clone_url, "repo.git"],
        )
        .map_err(|e| (format!("clone upstream: {e}"), exit::UNAVAILABLE))?;
    }
    if gitsrc::is_sha256_repo(&staging).map_err(|e| (e.to_string(), exit::GENERAL_ERROR))? {
        return Err((
            "SHA-256 repositories are out of scope for git-import v1 (SPEC-GIT-IMPORT §2)".into(),
            exit::DATAERR,
        ));
    }
    // Clone validated — NOW record the bindings.
    bind_import_state(layout, &state, &opts.url)?;
    map::bind_signer(&state, &kp.public.0).map_err(|e| (e.to_string(), exit::CONFIG_ERROR))?;
    translate_upstream(layout, &state, &staging, opts, &kp)
}

/// Read-only twin of [`bind_import_state`]: refuse direction/source
/// mismatches without writing anything.
fn validate_import_bindings(layout: &RepoLayout, state: &Path, url: &str) -> CmdResult<()> {
    match map::read_direction(state).map_err(|e| (e.to_string(), exit::GENERAL_ERROR))? {
        None | Some(Direction::Import | Direction::Fork) => {}
        Some(other) => {
            return Err((
                format!(
                    "state dir is bound to direction '{}' (one direction per state dir)",
                    other.as_str()
                ),
                exit::USAGE,
            ));
        }
    }
    let identity = remote_identity(url);
    match std::fs::read_to_string(state.join("source")) {
        Ok(recorded) if recorded.trim() != identity => Err((
            format!(
                "state '{}' is bound to {}; use a different --remote-name for {url}",
                state.file_name().unwrap_or_default().to_string_lossy(),
                recorded.trim(),
            ),
            exit::USAGE,
        )),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(other) = other_state_with_source(layout, state, &identity) {
                return Err((
                    format!(
                        "{url} is already imported as state '{other}'; use \
                         `--remote-name {other}` instead of creating a duplicate \
                         import (SPEC-GIT-IMPORT §6.1)"
                    ),
                    exit::USAGE,
                ));
            }
            Ok(())
        }
        Err(e) => Err((format!("read source binding: {e}"), exit::GENERAL_ERROR)),
    }
}

/// `mkit git fetch` / `pull`.
fn fetch_and_maybe_pull(layout: &RepoLayout, opts: &FetchArgs, pull: bool) -> CmdResult<Summary> {
    let import_opts = ImportArgs {
        url: String::new(), // resolved from the recorded source below
        dir: None,
        remote_name: opts.remote_name.clone(),
        key: opts.key.clone(),
        json: opts.json,
    };
    let state =
        map::state_dir(layout, &opts.remote_name).map_err(|e| (e.to_string(), exit::USAGE))?;
    if read_source(&state)?.is_none() {
        return Err((
            format!(
                "no import state for '{}' — run `mkit git import <url>` first",
                opts.remote_name
            ),
            exit::CONFIG_ERROR,
        ));
    }
    // Re-fetch through the staging mirror's own recorded origin (the
    // canonical identity strips `.git`, so it is NOT a fetch URL).
    let origin = super::git::git_in(
        &state.join("repo.git"),
        &["config", "--get", "remote.origin.url"],
    )
    .map(|s| s.trim().to_owned())
    .map_err(|e| (format!("staging origin: {e}"), exit::GENERAL_ERROR))?;
    let import_opts = ImportArgs {
        url: origin,
        ..import_opts
    };
    let mut summary = import_into(layout, &import_opts, true)?;

    if pull {
        summary.pulled = fast_forward_current(layout, &opts.remote_name)?;
    }
    Ok(summary)
}

/// FF the current branch from its tracking ref (native machinery).
fn fast_forward_current(layout: &RepoLayout, remote: &str) -> CmdResult<Option<String>> {
    let store =
        ObjectStore::open(layout).map_err(|e| (format!("open store: {e}"), exit::GENERAL_ERROR))?;
    let Ok(refs::Head::Branch(branch)) = refs::read_head(layout) else {
        return Ok(None); // detached/unborn: fetch-only semantics
    };
    let Some(target) = refs::read_remote_ref(layout, remote, &branch)
        .map_err(|e| (format!("read tracking ref: {e}"), exit::GENERAL_ERROR))?
    else {
        return Ok(None);
    };
    let Some(current) = refs::read_ref(layout, &branch)
        .map_err(|e| (format!("read branch: {e}"), exit::GENERAL_ERROR))?
    else {
        return Ok(None);
    };
    if current == target {
        return Ok(None);
    }
    let ancestor = mkit_core::ops::merge::is_ancestor(&store, current, target)
        .map_err(|e| (format!("ancestry: {e}"), exit::GENERAL_ERROR))?;
    if !ancestor {
        return Err((
            format!(
                "pull would not fast-forward branch '{branch}'; integrate with \
                 `mkit merge {remote}/{branch}` (or `mkit rebase {remote}/{branch}`)"
            ),
            exit::GENERAL_ERROR,
        ));
    }
    let tree = match store.read_object(&target) {
        Ok(Object::Commit(c)) => c.tree_hash,
        _ => return Err(("tracking ref is not a commit".into(), exit::DATAERR)),
    };
    // Same discipline as native pull (remote_dispatch::pull_all): the
    // worktree lock spans safety check → ref write → restore, so a
    // concurrent commit/checkout cannot interleave after the safety
    // check; a failed restore rolls the branch ref back instead of
    // leaving it advanced over a stale worktree.
    let _wt_lock = super::acquire_worktree_lock(layout)
        .map_err(|code| ("worktree is busy (another mkit command?)".to_owned(), code))?;
    super::ensure_restore_safe(layout, &store, tree).map_err(|e| (e, exit::GENERAL_ERROR))?;
    super::write_ref_recording_history(
        layout,
        &branch,
        mkit_core::refs::RefWriteCondition::Match(current),
        &target,
    )
    .map_err(|e| (format!("advance branch: {e}"), exit::CANTCREAT))?;
    if let Err(e) = super::restore_worktree_and_index(layout, &store, tree) {
        let rollback = super::write_ref_recording_history(
            layout,
            &branch,
            mkit_core::refs::RefWriteCondition::Match(target),
            &current,
        );
        let extra = match rollback {
            Ok(()) => String::new(),
            Err(rb) => format!("; additionally failed to roll back the branch ref: {rb}"),
        };
        return Err((format!("{e}{extra}"), exit::GENERAL_ERROR));
    }
    Ok(Some(branch))
}

// ─── translation core wiring ────────────────────────────────────────

struct Summary {
    imported: Vec<(String, Sha1Id, Hash)>,
    skipped: Vec<(String, String)>,
    normalized: bool,
    checked_out: Option<String>,
    pulled: Option<String>,
}

impl Summary {
    fn print(&self, json: bool) {
        if json {
            // ok mirrors the exit code: an all-skipped run exits
            // non-zero and must not claim success on stdout.
            let ok = !self.imported.is_empty() || self.skipped.is_empty();
            let mut out = format!("{{\"ok\":{ok},\"imported\":[");
            for (i, (r, s1, b3)) in self.imported.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                let _ = write!(
                    out,
                    "{{\"ref\":\"{}\",\"git\":\"{}\",\"mkit\":\"{}\"}}",
                    format::json_escape(r),
                    sha1_hex(s1),
                    mkit_core::to_hex(b3)
                );
            }
            out.push_str("],\"skipped\":[");
            for (i, (r, why)) in self.skipped.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                let _ = write!(
                    out,
                    "{{\"ref\":\"{}\",\"reason\":\"{}\"}}",
                    format::json_escape(r),
                    format::json_escape(why)
                );
            }
            out.push(']');
            if let Some(b) = &self.checked_out {
                let _ = write!(out, ",\"checkedOut\":\"{}\"", format::json_escape(b));
            }
            if let Some(b) = &self.pulled {
                let _ = write!(out, ",\"fastForwarded\":\"{}\"", format::json_escape(b));
            }
            out.push('}');
            println!("{out}");
            return;
        }
        for (r, s1, b3) in &self.imported {
            println!(
                "imported {r} {} -> {}",
                &sha1_hex(s1)[..8],
                &mkit_core::to_hex(b3)[..8]
            );
        }
        if self.normalized {
            eprintln!(
                "warning: historic tree modes were normalized (declared-lossy; \
                 originals retained in the staging mirror)"
            );
        }
        if let Some(b) = &self.checked_out {
            eprintln!("checked out '{b}'");
        }
        if let Some(b) = &self.pulled {
            eprintln!("fast-forwarded '{b}'");
        }
    }
}

/// Bulk sink: deferred-fsync writes + the kind probe the tag path
/// needs (review finding: without `kind_of`, chunked tag targets
/// misclassify and fork hashes between sink choices).
struct BulkSink<'a> {
    bw: BulkWriter<'a>,
    store: &'a ObjectStore,
}

impl ObjectSink for BulkSink<'_> {
    fn write_object(&mut self, bytes: &[u8]) -> Result<Hash, BridgeError> {
        self.bw
            .write(bytes)
            .map_err(|e| BridgeError::Source(format!("bulk write: {e}")))
    }

    fn kind_of(&self, h: &Hash) -> Option<ObjectType> {
        self.store.read_object(h).ok().map(|o| o.object_type())
    }
}

#[allow(clippy::too_many_lines)] // linear pipeline; stages are commented
fn translate_upstream(
    layout: &RepoLayout,
    state: &Path,
    staging: &Path,
    opts: &ImportArgs,
    kp: &KeyPair,
) -> CmdResult<Summary> {
    let store =
        ObjectStore::open(layout).map_err(|e| (format!("open store: {e}"), exit::GENERAL_ERROR))?;

    // Crash marker: a leftover marker means torn objects may exist
    // that the (durably-fsynced) map still vouches for — discard the
    // map and re-translate EVERY ref from scratch (per-key determinism
    // reproduces the exact same hashes, SPEC-GIT-IMPORT §1.2).
    // refs-import is KEPT: its hashes are reproducible (it cannot
    // vouch for torn objects) and it carries memory the surrounding
    // logic needs — tag ownership for the clobber guard and the prune
    // baseline for upstream deletions. The recovery pass instead
    // bypasses its unchanged-ref short-circuit and rev-list
    // exclusions below, so the map is fully rebuilt.
    let marker = state.join(IMPORTING_MARKER);
    let mut recovering = marker.exists();
    if recovering {
        let _ = std::fs::remove_file(state.join("map"));
        eprintln!("note: previous import was interrupted; rebuilding the map cache");
    }

    let mut sha_map = map::load_map_inverse(state)
        .map_err(|e| (format!("load map: {e}"), exit::GENERAL_ERROR))?;
    let prior_state = map::load_import_ref_state(state)
        .map_err(|e| (format!("load ref state: {e}"), exit::GENERAL_ERROR))?;
    // The map is a DISPOSABLE cache (§12.3): refs recorded with a
    // missing OR partially-corrupt map behind them (no crash marker)
    // must trigger the full rebuild — surviving lines of a corrupt
    // file are not evidence the rest exists, and the unchanged-ref
    // short-circuit would otherwise leave holes a later passthrough
    // export turns into re-translated history.
    let map_intact = map::map_is_intact(state).map_err(|e| (e.to_string(), exit::GENERAL_ERROR))?;
    // Tip-presence check: every recorded ref tip is appended to the
    // map BEFORE the ref state persists, so a recorded tip with no
    // map entry means the map tail was lost (truncation at a clean
    // line boundary parses as intact).
    let tips_mapped = prior_state
        .iter()
        .all(|st| sha_map.contains_key(&st.git_id));
    if !recovering
        && (!map_intact || !tips_mapped || (sha_map.is_empty() && !prior_state.is_empty()))
    {
        recovering = true;
        let _ = std::fs::remove_file(state.join("map"));
        sha_map.clear();
        eprintln!("note: map cache missing or corrupt; rebuilding from the staging mirror");
    }

    let upstream_refs =
        gitsrc::list_refs(staging).map_err(|e| (e.to_string(), exit::GENERAL_ERROR))?;

    // In-store divergence probe (SPEC-GIT-IMPORT §6.1, content side):
    // bounded walk-back digests vs existing commits under other keys.
    // Only on FIRST contact (empty map = fresh import or post-crash
    // rebuild): afterwards the pinned key + bound source already
    // guarantee consistency, and the probe scans the whole store —
    // too heavy for every routine fetch.
    if sha_map.is_empty() {
        divergence_probe(&store, staging, &upstream_refs, &kp.public.0)?;
    }

    // Written only now, after the read-only probe: the marker brackets
    // exactly the window where torn objects can exist (store writes
    // until the map/ref-state commit below).
    write_durable(&marker, b"").map_err(|e| (format!("marker: {e}"), exit::CANTCREAT))?;

    let direction = map::read_direction(state)
        .map_err(|e| (e.to_string(), exit::GENERAL_ERROR))?
        .unwrap_or(Direction::Import);
    let fork_mode = direction == Direction::Fork;

    let mut batch = CatFileBatch::open(staging).map_err(|e| (e.to_string(), exit::UNAVAILABLE))?;
    let mut sink = BulkSink {
        bw: store.bulk_writer(),
        store: &store,
    };
    let raw_dir = state.join("raw");
    let mut raw_dirs: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    let mut retain = |id: &Sha1Id, raw: &[u8]| -> Result<(), BridgeError> {
        let hex = sha1_hex(id);
        let dir = raw_dir.join(&hex[..2]);
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(&hex[2..]);
        // Temp + content-fsync + rename: a torn final file would be
        // permanent (the exists() short-circuit is what makes re-runs
        // cheap, so the final path must never hold partial bytes).
        if !path.exists() {
            let tmp = dir.join(format!(".{}.tmp", &hex[2..]));
            {
                use std::io::Write as _;
                let mut f = std::fs::File::create(&tmp)?;
                f.write_all(raw)?;
                f.sync_all()?;
            }
            std::fs::rename(&tmp, &path)?;
        }
        // Collect the dir even when the file already existed: a
        // previous crashed run may have renamed it without ever
        // reaching the batch dir-fsync.
        raw_dirs.insert(dir);
        Ok(())
    };
    let public = kp.public.0;
    let mut sc = |c: &mkit_core::object::Commit| {
        Ok(sign_commit(c, kp)
            .map_err(|e| BridgeError::Source(e.to_string()))?
            .0)
    };
    let mut st = |t: &mkit_core::object::Tag| {
        Ok(sign_tag(t, kp)
            .map_err(|e| BridgeError::Source(e.to_string()))?
            .0)
    };

    let prior_by_ref: HashMap<&str, &map::RefState> = prior_state
        .iter()
        .map(|s| (s.ref_name.as_str(), s))
        .collect();
    // Exclusions must still exist in the mirror: after an upstream
    // force-push plus gc, a pruned old tip would make `rev-list ^tip`
    // abort every future fetch ("fatal: bad object"). A recovery pass
    // excludes nothing — the discarded map must be rebuilt over the
    // FULL history (and the empty exclusion set keeps rev-list's
    // parents-first order covering every commit, recursion depth 1).
    let exclude: Vec<Sha1Id> = if recovering {
        Vec::new()
    } else {
        prior_state
            .iter()
            .map(|s| s.git_id)
            .filter(|id| gitsrc::object_exists(staging, id).unwrap_or(false))
            .collect()
    };

    let mut imported: Vec<(String, Sha1Id, Hash)> = Vec::new();
    let mut skipped: Vec<(String, String)> = Vec::new();
    let mut all_pairs: Vec<(Sha1Id, Hash)> = Vec::new();
    let mut normalized = false;

    for uref in &upstream_refs {
        // Ref-name legality on the mkit side (grammar + tags).
        let mkit_legal = if let Some(b) = uref.name.strip_prefix("refs/heads/") {
            refs::validate_ref_name(b)
        } else if let Some(t) = uref.name.strip_prefix("refs/tags/") {
            refs::validate_ref_name(t)
        } else {
            false
        };
        if !mkit_legal {
            let why = format!("ref name {:?} is outside the mkit ref grammar", uref.name);
            eprintln!("warning: skipping {}: {why}", uref.name);
            skipped.push((uref.name.clone(), why));
            continue;
        }
        // Unchanged since last import? (Never during recovery: the
        // recorded tip is fine but the discarded map must be rebuilt
        // by actually re-translating the ref's closure.)
        if !recovering
            && let Some(prev) = prior_by_ref.get(uref.name.as_str())
            && prev.git_id == uref.id
        {
            imported.push((uref.name.clone(), uref.id, prev.mkit_hash));
            continue;
        }
        // Translate: commits in topo order (no deep recursion), then
        // the tip object itself (tag objects ride on top).
        let commit_tip = uref.peeled.unwrap_or(uref.id);
        let order = gitsrc::rev_list(staging, &[commit_tip], &exclude)
            .map_err(|e| (e.to_string(), exit::GENERAL_ERROR))?;
        let mut imp = Importer {
            source: &mut batch,
            sink: &mut sink,
            signer: ImportSigner {
                public,
                sign_commit: &mut sc,
                sign_tag: &mut st,
            },
            map: &mut sha_map,
            retain_raw: &mut retain,
            options: ImportOptions { fork_mode },
            depth_memo: DepthMemo::default(),
        };
        // Pairs are caller-owned and persisted EVEN when the ref
        // refuses: the sink already wrote those objects, and a later
        // ref sharing the history memo-hits without re-emitting them.
        let mut ref_pairs: Vec<(Sha1Id, Hash)> = Vec::new();
        let result = imp.import_commits(&order, &uref.id, &mut ref_pairs, &mut normalized);
        all_pairs.extend_from_slice(&ref_pairs);
        match result {
            Ok(head) => {
                imported.push((uref.name.clone(), uref.id, head));
            }
            Err(BridgeError::Refused(r)) => {
                eprintln!("warning: skipping {}: {r}", uref.name);
                skipped.push((uref.name.clone(), r.to_string()));
            }
            Err(e) => return Err((format!("import {}: {e}", uref.name), exit::GENERAL_ERROR)),
        }
    }
    drop(batch);

    // Durability order: objects (dir fsync) → map (file fsync) →
    // tracking refs → marker removal.
    sink.bw
        .commit()
        .map_err(|e| (format!("commit bulk writes: {e}"), exit::CANTCREAT))?;
    for dir in &raw_dirs {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    map::append_map_import(state, &all_pairs)
        .map_err(|e| (format!("persist map: {e}"), exit::GENERAL_ERROR))?;

    let mut new_state: Vec<map::RefState> = Vec::new();
    for (name, git_id, mkit_hash) in &imported {
        if let Some(branch) = name.strip_prefix("refs/heads/") {
            // Force-push detection: tracking refs move with a warning
            // when the old tip is no longer an ancestor of the new.
            if let Some(prev) = prior_by_ref.get(name.as_str())
                && prev.git_id != *git_id
                && !gitsrc::is_ancestor(staging, &prev.git_id, git_id).unwrap_or(true)
            {
                eprintln!(
                    "warning: upstream force-pushed {name}; tracking ref rewound \
                     (rebase local branches that built on the old history)"
                );
            }
            refs::write_remote_ref(layout, &opts.remote_name, branch, mkit_hash)
                .map_err(|e| (format!("tracking ref {name}: {e}"), exit::CANTCREAT))?;
        } else if let Some(tag) = name.strip_prefix("refs/tags/") {
            // Never clobber a locally-moved tag: only write when the
            // tag is absent or still where THIS import last put it
            // (mirrors git fetch's would-clobber refusal).
            let existing = refs::read_tag(layout, tag)
                .map_err(|e| (format!("tag ref {name}: {e}"), exit::GENERAL_ERROR))?;
            let ours_before = prior_by_ref.get(name.as_str()).map(|p| p.mkit_hash);
            match existing {
                Some(cur) if cur != *mkit_hash && Some(cur) != ours_before => {
                    eprintln!(
                        "warning: not updating tag '{tag}': it was moved locally \
                         (delete it with `mkit tag -d {tag}` to track the upstream tag)"
                    );
                }
                Some(cur) if cur == *mkit_hash => {}
                _ => {
                    refs::update_tag(
                        layout,
                        tag,
                        mkit_core::refs::RefWriteCondition::Any,
                        mkit_hash,
                    )
                    .map_err(|e| (format!("tag ref {name}: {e}"), exit::CANTCREAT))?;
                }
            }
        }
        new_state.push(map::RefState {
            ref_name: name.clone(),
            mkit_hash: *mkit_hash,
            git_id: *git_id,
        });
    }
    // Upstream deletions propagate to the tracking refs (like
    // `git fetch --prune` for refs/remotes); local TAGS are kept,
    // matching git's default (no --prune-tags).
    let current: std::collections::HashSet<&str> =
        upstream_refs.iter().map(|u| u.name.as_str()).collect();
    for prev in &prior_state {
        if let Some(branch) = prev.ref_name.strip_prefix("refs/heads/")
            && !current.contains(prev.ref_name.as_str())
        {
            match refs::delete_remote_ref(layout, &opts.remote_name, branch) {
                Ok(()) => eprintln!(
                    "warning: upstream deleted {}; tracking ref {}/{branch} removed",
                    prev.ref_name, opts.remote_name
                ),
                Err(mkit_core::refs::RefError::NotFound(_)) => {}
                Err(e) => {
                    return Err((format!("prune tracking ref {branch}: {e}"), exit::CANTCREAT));
                }
            }
        }
    }

    if normalized {
        // Sticky, and recorded BEFORE the marker can be removed: a
        // crash here re-runs the (idempotent) stamp; losing it would
        // permanently unblock a fork upgrade §3.3 forbids.
        map::mark_normalized(state).map_err(|e| (e.to_string(), exit::CANTCREAT))?;
    }

    // Attestations BEFORE the ref-state persist: minting is
    // idempotent (content-addressed envelopes), but the
    // "claim already exists" skip keys on recorded-state equality —
    // a crash between persist and mint would skip those heads
    // forever on re-run.
    mint_attestations(
        layout,
        &opts.url,
        &opts.remote_name,
        &imported,
        &prior_by_ref,
        kp,
    )?;

    map::store_import_ref_state(state, &new_state)
        .map_err(|e| (format!("persist ref state: {e}"), exit::GENERAL_ERROR))?;
    std::fs::remove_file(&marker).map_err(|e| (format!("marker: {e}"), exit::GENERAL_ERROR))?;

    Ok(Summary {
        imported,
        skipped,
        normalized,
        checked_out: None,
        pulled: None,
    })
}

/// `std::fs::write` + content fsync + parent-dir fsync — for tiny
/// state files whose EXISTENCE is the signal (the crash marker).
fn write_durable(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    {
        use std::io::Write as _;
        let mut f = std::fs::File::create(path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    if let Some(parent) = path.parent()
        && let Ok(d) = std::fs::File::open(parent)
    {
        let _ = d.sync_all();
    }
    Ok(())
}

/// SPEC-GIT-IMPORT §5: subject = mkit head, predicate carries the git
/// locator + canonical remote identity, signed with the import key.
fn mint_attestations(
    layout: &RepoLayout,
    url: &str,
    remote_name: &str,
    imported: &[(String, Sha1Id, Hash)],
    prior: &HashMap<&str, &map::RefState>,
    kp: &KeyPair,
) -> CmdResult<()> {
    let remote_url = remote_identity(url);
    for (name, git_id, mkit_hash) in imported {
        if let Some(prev) = prior.get(name.as_str())
            && prev.mkit_hash == *mkit_hash
        {
            continue; // unchanged head: claim already exists
        }
        // §5: subject/refName carry the FULL MKIT ref — imported
        // branches live under refs/remotes/<name>/, not refs/heads/.
        let mkit_ref = name.strip_prefix("refs/heads/").map_or_else(
            || name.clone(),
            |branch| format!("refs/remotes/{remote_name}/{branch}"),
        );
        let predicate = format!(
            "{{\"gitCommit\":\"{}\",\"refName\":\"{}\",\"remoteUrl\":\"{}\",\"schemaVersion\":1,\"specVersion\":1}}",
            sha1_hex(git_id),
            format::json_escape(&mkit_ref),
            format::json_escape(&remote_url)
        );
        let stmt = statement::encode(&statement::Statement {
            subjects: vec![statement::Subject {
                name: Some(mkit_ref),
                digest_blake3_hex: mkit_core::to_hex(mkit_hash),
            }],
            predicate_type: PREDICATE_TYPE.to_owned(),
            predicate_jcs: predicate.as_bytes(),
        })
        .map_err(|e| (format!("encode statement: {e}"), exit::GENERAL_ERROR))?;
        let pae = mkit_attest::pae_of(PAYLOAD_TYPE_IN_TOTO, stmt.as_bytes());
        let mut signer = mkit_attest::RepoKeySigner::new(KeyPair {
            public: kp.public,
            secret: mkit_core::sign::SecretSeed(kp.secret.0),
        });
        let sig = signer
            .sign(&pae)
            .map_err(|e| (format!("sign attestation: {e}"), exit::GENERAL_ERROR))?;
        let keyid = signer
            .keyid()
            .map_err(|e| (format!("attestation keyid: {e}"), exit::GENERAL_ERROR))?;
        let envelope = Envelope {
            payload_type: PAYLOAD_TYPE_IN_TOTO.to_owned(),
            payload: stmt.into_bytes(),
            signatures: vec![Sig { keyid, sig }],
        };
        let encoded = envelope
            .encode()
            .map_err(|e| (format!("encode envelope: {e}"), exit::GENERAL_ERROR))?;
        attest_store::save(layout, mkit_hash, encoded.as_bytes())
            .map_err(|e| (format!("save attestation: {e}"), exit::CANTCREAT))?;
    }
    Ok(())
}

// ─── state, keys, probes ────────────────────────────────────────────

/// Bind direction=import (or accept fork) + record the canonical
/// source identity; refuse a different source for this state name.
fn bind_import_state(layout: &RepoLayout, state: &Path, url: &str) -> CmdResult<()> {
    map::bind_direction(state, Direction::Import)
        .or_else(|_| {
            // fork is the allowed superset (import + passthrough).
            match map::read_direction(state) {
                Ok(Some(Direction::Fork)) => Ok(()),
                _ => Err(BridgeError::Source(
                    "state dir direction conflict (one direction per state dir)".into(),
                )),
            }
        })
        .map_err(|e| (e.to_string(), exit::USAGE))?;
    let identity = remote_identity(url);
    let src_file = state.join("source");
    match std::fs::read_to_string(&src_file) {
        Ok(recorded) if recorded.trim() != identity => Err((
            format!(
                "state '{}' is bound to {}; use a different --remote-name for {}",
                state.file_name().unwrap_or_default().to_string_lossy(),
                recorded.trim(),
                url
            ),
            exit::USAGE,
        )),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // SPEC-GIT-IMPORT §6.1 check 1: one upstream, one state
            // dir. A second state for the same canonical source would
            // duplicate the whole history under (possibly) another
            // key — almost always a mistake.
            if let Some(other) = other_state_with_source(layout, state, &identity) {
                return Err((
                    format!(
                        "{url} is already imported as state '{other}'; use \
                         `--remote-name {other}` instead of creating a duplicate \
                         import (SPEC-GIT-IMPORT §6.1)"
                    ),
                    exit::USAGE,
                ));
            }
            map::write_binding(state, "source", &identity)
                .map_err(|e| (format!("record source: {e}"), exit::CANTCREAT))
        }
        Err(e) => Err((format!("read source binding: {e}"), exit::GENERAL_ERROR)),
    }?;
    map::bind_import_spec(state, IMPORT_SPEC_VERSION).map_err(|e| (e.to_string(), exit::USAGE))
}

/// Absolutize a local-path clone URL verbatim (no `.git` stripping —
/// that is identity normalization, not path resolution).
fn absolutize_clone_url(url: &str) -> String {
    let looks_like_url = url.contains("://")
        || url
            .split('/')
            .next()
            .is_some_and(|first| first.contains(':'));
    if looks_like_url {
        return url.to_owned();
    }
    let p = Path::new(url);
    p.canonicalize()
        .map_or_else(|_| url.to_owned(), |c| c.to_string_lossy().into_owned())
}

fn read_source(state: &Path) -> CmdResult<Option<String>> {
    match std::fs::read_to_string(state.join("source")) {
        Ok(s) => Ok(Some(s.trim().to_owned())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err((format!("read source: {e}"), exit::GENERAL_ERROR)),
    }
}

/// The name of another state dir already bound to `identity`, if any.
fn other_state_with_source(
    layout: &RepoLayout,
    this_state: &Path,
    identity: &str,
) -> Option<String> {
    for entry in std::fs::read_dir(layout.git_state_dir()).ok()?.flatten() {
        if entry.path() == this_state {
            continue;
        }
        if let Ok(src) = std::fs::read_to_string(entry.path().join("source"))
            && src.trim() == identity
        {
            return Some(entry.file_name().to_string_lossy().into_owned());
        }
    }
    None
}

/// SPEC-GIT-IMPORT §4: a dedicated import key by default, generated
/// on first use with a loud notice.
fn load_or_create_import_key(layout: &RepoLayout, flag: Option<&str>) -> CmdResult<KeyPair> {
    let path = flag.map_or_else(|| layout.common_dir().join(IMPORT_KEY_FILE), PathBuf::from);
    match mkit_core::sign::load_key(&path) {
        Ok(kp) => {
            // §4: say which key signs this import (operators juggling
            // several imports need to see a key mixup immediately).
            eprintln!(
                "note: signing imported history with key {}… ({})",
                &mkit_core::to_hex(&{
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&kp.public.0);
                    h
                })[..16],
                path.display()
            );
            Ok(kp)
        }
        // Generate ONLY when the file is truly absent: any other load
        // failure (symlink, truncation, transient IO) must surface —
        // overwriting an existing-but-unreadable key would destroy
        // the seed the pinned state depends on, irreversibly.
        Err(_) if flag.is_none() && !path.exists() => {
            // The default key file is shared by every remote-name, but
            // the bridge locks are per-state — two concurrent
            // first-time imports would each generate a key and the
            // rename-replacing save would orphan one pinned signer
            // forever. Serialize generation and re-check under the
            // lock.
            let _key_lock =
                mkit_core::repo_lock::acquire_default(layout.common_dir(), "git-import-key.lock")
                    .map_err(|e| (format!("import key generation busy: {e}"), exit::TEMPFAIL))?;
            if let Ok(kp) = mkit_core::sign::load_key(&path) {
                return Ok(kp);
            }
            let kp = KeyPair::generate()
                .map_err(|e| (format!("generate import key: {e}"), exit::GENERAL_ERROR))?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| (format!("mkdir keys: {e}"), exit::CANTCREAT))?;
            }
            mkit_core::sign::save_key(&path, &kp)
                .map_err(|e| (format!("save import key: {e}"), exit::CANTCREAT))?;
            eprintln!(
                "note: generated a DEDICATED import key at {} — collaborative \
                 tracking of one upstream requires sharing this key (org/bot \
                 key); a different key produces an unrelated fork \
                 (SPEC-GIT-IMPORT §4)",
                path.display()
            );
            Ok(kp)
        }
        Err(e) => Err((
            format!("load import key {}: {e}", path.display()),
            exit::NOINPUT,
        )),
    }
}

/// SPEC-GIT-IMPORT §6.1 content probe: walk back from each upstream
/// head (bounded) and refuse when a commit with the same framed-bytes
/// digest exists locally under a DIFFERENT signer key.
fn divergence_probe(
    store: &ObjectStore,
    staging: &Path,
    upstream_refs: &[gitsrc::UpstreamRef],
    our_key: &[u8; 32],
) -> CmdResult<()> {
    // Collect candidate digests: heads + up to 32 first-parents back.
    let mut batch = CatFileBatch::open(staging).map_err(|e| (e.to_string(), exit::UNAVAILABLE))?;
    let mut digests: HashMap<Hash, Sha1Id> = HashMap::new();
    for uref in upstream_refs {
        let mut cur = uref.peeled.unwrap_or(uref.id);
        for _ in 0..32 {
            let Ok((kind, body)) = batch.read(&cur) else {
                break;
            };
            if kind != gitsrc::GitObjKind::Commit {
                break;
            }
            let mut framed = format!("commit {}\0", body.len()).into_bytes();
            framed.extend_from_slice(&body);
            digests.insert(mkit_core::hash::hash(&framed), cur);
            let Ok(parsed) = mkit_git_bridge::gitparse::parse_commit(&body) else {
                break;
            };
            match parsed.parents.first() {
                Some(p) => cur = *p,
                None => break,
            }
        }
    }
    if digests.is_empty() {
        return Ok(());
    }
    // Linear scan (imports are rare interactive operations).
    let hashes = store
        .iter_object_hashes()
        .map_err(|e| (format!("scan store: {e}"), exit::GENERAL_ERROR))?;
    for h in hashes {
        let Ok(Object::Commit(c)) = store.read_object(&h) else {
            continue;
        };
        if digests.contains_key(&c.content_digest) && c.signer != *our_key {
            return Err((
                format!(
                    "this upstream is already imported here under key {}…; pull from \
                     the designated importer over mkit transport, or install that key \
                     (SPEC-GIT-IMPORT §4/§6.1)",
                    &bytes_hex(&c.signer)[..16]
                ),
                exit::CONFIG_ERROR,
            ));
        }
    }
    Ok(())
}

use super::error as emit_err;
