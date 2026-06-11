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
use mkit_core::object::{Object, ObjectType};
use mkit_core::sign::{KeyPair, sign_commit, sign_tag};
use mkit_core::store::BulkWriter;
use mkit_core::{Hash, ObjectStore, refs};
use mkit_git_bridge::error::BridgeError;
use mkit_git_bridge::gitobj::{Sha1Id, bytes_hex, sha1_hex};
use mkit_git_bridge::gitsrc::{self, CatFileBatch};
use mkit_git_bridge::import::{
    IMPORT_SPEC_VERSION, ImportOptions, ImportSigner, Importer, ObjectSink,
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
            .and_then(|cwd| import_into(&cwd, opts, true)),
    };
    finish(outcome, opts.json)
}

#[must_use]
pub fn run_fetch(opts: &FetchArgs, pull: bool) -> u8 {
    let outcome = std::env::current_dir()
        .map_err(|e| (format!("cwd: {e}"), exit::CONFIG_ERROR))
        .and_then(|cwd| fetch_and_maybe_pull(&cwd, opts, pull));
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
fn fresh_clone(opts: &ImportArgs, dir: &str) -> CmdResult<Summary> {
    let target = PathBuf::from(dir);
    if target.exists() && std::fs::read_dir(&target).map_or(true, |mut d| d.next().is_some()) {
        return Err((
            format!("destination '{dir}' already exists"),
            exit::CANTCREAT,
        ));
    }
    std::fs::create_dir_all(&target).map_err(|e| (format!("mkdir: {e}"), exit::CANTCREAT))?;
    ObjectStore::init(&target).map_err(|e| (format!("init: {e}"), exit::CANTCREAT))?;
    refs::init(&target.join(mkit_core::MKIT_DIR))
        .map_err(|e| (format!("refs init: {e}"), exit::CANTCREAT))?;
    let mut summary = import_into(&target, opts, false)?;

    // Check out the upstream default branch.
    let mkit_dir = target.join(mkit_core::MKIT_DIR);
    let staging = map::state_dir(&mkit_dir, &opts.remote_name)
        .map_err(|e| (e.to_string(), exit::USAGE))?
        .join("repo.git");
    let default = gitsrc::default_branch(&staging)
        .map_err(|e| (format!("default branch: {e}"), exit::GENERAL_ERROR))?
        .and_then(|r| r.strip_prefix("refs/heads/").map(str::to_owned));
    if let Some(branch) = default
        && let Some(head) = refs::read_remote_ref(&mkit_dir, &opts.remote_name, &branch)
            .map_err(|e| (format!("read tracking ref: {e}"), exit::GENERAL_ERROR))?
    {
        checkout_initial(&target, &mkit_dir, &branch, &head)?;
        summary.checked_out = Some(branch);
    }
    Ok(summary)
}

fn checkout_initial(root: &Path, mkit_dir: &Path, branch: &str, head: &Hash) -> CmdResult<()> {
    let store =
        ObjectStore::open(root).map_err(|e| (format!("open store: {e}"), exit::GENERAL_ERROR))?;
    let tree = match store.read_object(head) {
        Ok(Object::Commit(c)) => c.tree_hash,
        Ok(Object::Tag(_) | _) | Err(_) => {
            return Err(("imported head is not a commit".into(), exit::DATAERR));
        }
    };
    super::write_ref_recording_history(
        mkit_dir,
        branch,
        mkit_core::refs::RefWriteCondition::Missing,
        head,
    )
    .map_err(|e| (format!("write branch: {e}"), exit::CANTCREAT))?;
    refs::write_head_branch(mkit_dir, branch)
        .map_err(|e| (format!("write HEAD: {e}"), exit::CANTCREAT))?;
    super::restore_worktree_and_index(root, &store, tree)
        .map_err(|e| (format!("checkout: {e}"), exit::GENERAL_ERROR))?;
    Ok(())
}

/// Import/refresh into an existing repo: tracking refs + tags only.
fn import_into(root: &Path, opts: &ImportArgs, require_repo: bool) -> CmdResult<Summary> {
    if require_repo {
        ObjectStore::open(root)
            .map_err(|e| (format!("open repository: {e}"), exit::GENERAL_ERROR))?;
    }
    let mkit_dir = root.join(mkit_core::MKIT_DIR);
    super::git::git_version().map_err(|e| (e, exit::UNAVAILABLE))?;

    let state =
        map::state_dir(&mkit_dir, &opts.remote_name).map_err(|e| (e.to_string(), exit::USAGE))?;
    bind_import_state(&state, &opts.url)?;
    let kp = load_or_create_import_key(&mkit_dir, opts.key.as_deref())?;
    map::bind_signer(&state, &kp.public.0).map_err(|e| (e.to_string(), exit::CONFIG_ERROR))?;

    // Staging mirror: clone once, fetch thereafter. Local paths must
    // be absolutized — the clone runs `git -C <state>`, which would
    // resolve a relative path against the state dir.
    let clone_url = absolutize_clone_url(&opts.url);
    let staging = state.join("repo.git");
    if staging.join("objects").is_dir() {
        super::git::git_in(&staging, &["fetch", "--quiet", "--prune"])
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
    translate_upstream(root, &mkit_dir, &state, &staging, opts, &kp)
}

/// `mkit git fetch` / `pull`.
fn fetch_and_maybe_pull(cwd: &Path, opts: &FetchArgs, pull: bool) -> CmdResult<Summary> {
    let import_opts = ImportArgs {
        url: String::new(), // resolved from the recorded source below
        dir: None,
        remote_name: opts.remote_name.clone(),
        key: opts.key.clone(),
        json: opts.json,
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);
    let state =
        map::state_dir(&mkit_dir, &opts.remote_name).map_err(|e| (e.to_string(), exit::USAGE))?;
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
    let mut summary = import_into(cwd, &import_opts, true)?;

    if pull {
        summary.pulled = fast_forward_current(cwd, &mkit_dir, &opts.remote_name)?;
    }
    Ok(summary)
}

/// FF the current branch from its tracking ref (native machinery).
fn fast_forward_current(root: &Path, mkit_dir: &Path, remote: &str) -> CmdResult<Option<String>> {
    let store =
        ObjectStore::open(root).map_err(|e| (format!("open store: {e}"), exit::GENERAL_ERROR))?;
    let Ok(refs::Head::Branch(branch)) = refs::read_head(mkit_dir) else {
        return Ok(None); // detached/unborn: fetch-only semantics
    };
    let Some(target) = refs::read_remote_ref(mkit_dir, remote, &branch)
        .map_err(|e| (format!("read tracking ref: {e}"), exit::GENERAL_ERROR))?
    else {
        return Ok(None);
    };
    let Some(current) = refs::read_ref(mkit_dir, &branch)
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
    super::ensure_restore_safe(root, &store, tree).map_err(|e| (e, exit::GENERAL_ERROR))?;
    super::write_ref_recording_history(
        mkit_dir,
        &branch,
        mkit_core::refs::RefWriteCondition::Match(current),
        &target,
    )
    .map_err(|e| (format!("advance branch: {e}"), exit::CANTCREAT))?;
    super::restore_worktree_and_index(root, &store, tree).map_err(|e| (e, exit::GENERAL_ERROR))?;
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
            let mut out = String::from("{\"ok\":true,\"imported\":[");
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
            out.push_str("]}");
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
    root: &Path,
    mkit_dir: &Path,
    state: &Path,
    staging: &Path,
    opts: &ImportArgs,
    kp: &KeyPair,
) -> CmdResult<Summary> {
    let store =
        ObjectStore::open(root).map_err(|e| (format!("open store: {e}"), exit::GENERAL_ERROR))?;

    // Crash marker: a leftover marker means torn objects may exist
    // that the (durably-fsynced) map still vouches for — discard the
    // map; determinism makes the rebuild exact (SPEC-GIT-IMPORT §1.2).
    let marker = state.join(IMPORTING_MARKER);
    if marker.exists() {
        let _ = std::fs::remove_file(state.join("map"));
        eprintln!("note: previous import was interrupted; rebuilding the map cache");
    }
    std::fs::write(&marker, b"").map_err(|e| (format!("marker: {e}"), exit::CANTCREAT))?;

    let mut sha_map = map::load_map_inverse(state)
        .map_err(|e| (format!("load map: {e}"), exit::GENERAL_ERROR))?;
    let prior_state = map::load_ref_state(state)
        .map_err(|e| (format!("load ref state: {e}"), exit::GENERAL_ERROR))?;

    let upstream_refs =
        gitsrc::list_refs(staging).map_err(|e| (e.to_string(), exit::GENERAL_ERROR))?;

    // In-store divergence probe (SPEC-GIT-IMPORT §6.1, content side):
    // bounded walk-back digests vs existing commits under other keys.
    divergence_probe(&store, staging, &upstream_refs, &kp.public.0)?;

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
    let mut retain = |id: &Sha1Id, raw: &[u8]| -> Result<(), BridgeError> {
        let hex = sha1_hex(id);
        let dir = raw_dir.join(&hex[..2]);
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(&hex[2..]);
        if !path.exists() {
            std::fs::write(path, raw)?;
        }
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
    let exclude: Vec<Sha1Id> = prior_state.iter().map(|s| s.git_id).collect();

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
        // Unchanged since last import?
        if let Some(prev) = prior_by_ref.get(uref.name.as_str())
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
        };
        match imp.import_commits(&order, &uref.id) {
            Ok(outcome) => {
                normalized |= outcome.normalized_modes;
                all_pairs.extend_from_slice(&outcome.new_pairs);
                imported.push((uref.name.clone(), uref.id, outcome.head));
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
            refs::write_remote_ref(mkit_dir, &opts.remote_name, branch, mkit_hash)
                .map_err(|e| (format!("tracking ref {name}: {e}"), exit::CANTCREAT))?;
        } else if let Some(tag) = name.strip_prefix("refs/tags/") {
            refs::update_tag(
                mkit_dir,
                tag,
                mkit_core::refs::RefWriteCondition::Any,
                mkit_hash,
            )
            .map_err(|e| (format!("tag ref {name}: {e}"), exit::CANTCREAT))?;
        }
        new_state.push(map::RefState {
            ref_name: name.clone(),
            mkit_hash: *mkit_hash,
            git_id: sha1_to_id(git_id),
        });
    }
    map::store_ref_state(state, &new_state)
        .map_err(|e| (format!("persist ref state: {e}"), exit::GENERAL_ERROR))?;
    std::fs::remove_file(&marker).map_err(|e| (format!("marker: {e}"), exit::GENERAL_ERROR))?;

    // git-import/v1 attestations for new/moved heads (skip unchanged).
    mint_attestations(mkit_dir, &opts.url, &imported, &prior_by_ref, kp)?;

    Ok(Summary {
        imported,
        skipped,
        normalized,
        checked_out: None,
        pulled: None,
    })
}

fn sha1_to_id(s: &Sha1Id) -> Sha1Id {
    *s
}

/// SPEC-GIT-IMPORT §5: subject = mkit head, predicate carries the git
/// locator + canonical remote identity, signed with the import key.
fn mint_attestations(
    mkit_dir: &Path,
    url: &str,
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
        let predicate = format!(
            "{{\"gitCommit\":\"{}\",\"refName\":\"{}\",\"remoteUrl\":\"{}\",\"schemaVersion\":1,\"specVersion\":1}}",
            sha1_hex(git_id),
            format::json_escape(name),
            format::json_escape(&remote_url)
        );
        let stmt = statement::encode(&statement::Statement {
            subjects: vec![statement::Subject {
                name: Some(name.clone()),
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
        attest_store::save(mkit_dir, mkit_hash, encoded.as_bytes())
            .map_err(|e| (format!("save attestation: {e}"), exit::CANTCREAT))?;
    }
    Ok(())
}

// ─── state, keys, probes ────────────────────────────────────────────

/// Bind direction=import (or accept fork) + record the canonical
/// source identity; refuse a different source for this state name.
fn bind_import_state(state: &Path, url: &str) -> CmdResult<()> {
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
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::create_dir_all(state)
            .and_then(|()| std::fs::write(&src_file, format!("{identity}\n")))
            .map_err(|e| (format!("record source: {e}"), exit::CANTCREAT)),
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

/// SPEC-GIT-IMPORT §4: a dedicated import key by default, generated
/// on first use with a loud notice.
fn load_or_create_import_key(mkit_dir: &Path, flag: Option<&str>) -> CmdResult<KeyPair> {
    let path = flag.map_or_else(|| mkit_dir.join(IMPORT_KEY_FILE), PathBuf::from);
    match mkit_core::sign::load_key(&path) {
        Ok(kp) => Ok(kp),
        Err(_) if flag.is_none() => {
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

fn emit_err(msg: &str, code: u8) -> u8 {
    eprintln!("error: {msg}");
    code
}
