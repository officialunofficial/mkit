//! `mkit git` — the git bridge subcommands (feature `git-bridge`):
//! deterministic export to git mirrors (SPEC-GIT-BRIDGE) and, as the
//! phases land, importer-signed import (SPEC-GIT-IMPORT).
//!
//! Translation happens into a local bare staging repo under
//! `.mkit/git/<remote>/repo.git`, then a single `git push` with
//! per-ref `--force-with-lease` moves the mirror. Per-ref refusals
//! (remix ancestry, git-illegal ref names, non-canonical chunking)
//! skip that ref with an actionable warning and export the rest
//! (SPEC-GIT-BRIDGE §8, §12).

use clap::Parser;
use mkit_attest::{Envelope, PAYLOAD_TYPE_IN_TOTO, Sig, statement, store as attest_store};
use mkit_core::object::Object;
use mkit_core::{Hash, ObjectStore, refs};
use mkit_git_bridge::gitobj::{GitObject, GitType, Sha1Id, sha1_from_hex, sha1_hex};
use mkit_git_bridge::translate::translate_closure;
use mkit_git_bridge::{BridgeError, map, refname};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::clap_shim;
use crate::commands::attest_factory;
use crate::exit;
use crate::format;

/// SPEC-GIT-BRIDGE §11 predicate type.
const PREDICATE_TYPE: &str =
    "https://github.com/officialunofficial/mkit/spec/predicate/git-bridge/v1";

/// Mirror-side ref carrying published bridge attestations (§11).
const ATTESTATIONS_REF: &str = "refs/mkit/attestations";

#[derive(Debug, Parser)]
#[command(name = "mkit git", about = "Git-bridge subcommands (SPEC-GIT-BRIDGE).")]
enum Cmd {
    /// Export refs to a git mirror (one-way, deterministic).
    Export(ExportArgs),
    /// Import a git upstream as an importer-signed downstream fork.
    Import(super::git_import::ImportArgs),
    /// Fetch new upstream commits into refs/remotes/<name>/* only.
    Fetch(super::git_import::FetchArgs),
    /// Fetch, then fast-forward the current branch from its tracking ref.
    Pull(super::git_import::FetchArgs),
    /// Verify bridge state: shallow-verify translated objects, check
    /// imported objects against the pinned importer key (--fork-audit
    /// re-derives the referenced content too).
    Verify(super::git_tools::VerifyArgs),
    /// Show every bridge state dir: direction, endpoints, key, refs.
    Status(super::git_tools::StatusArgs),
    /// Render native commits as `git am`-able patches.
    FormatPatch(super::git_tools::FormatPatchArgs),
}

#[derive(Debug, Parser)]
struct ExportArgs {
    /// Destination: a git URL or a local path (a missing local path
    /// is initialized as a bare repository).
    dest: String,
    /// Name for the per-remote bridge state under `.mkit/git/<name>/`.
    #[arg(long = "remote-name", value_name = "NAME", default_value = "mirror")]
    remote_name: String,
    /// Export only these refs (full names, e.g. `refs/heads/main`).
    /// Default: every local branch and tag.
    #[arg(long = "ref", value_name = "REF")]
    refs: Vec<String>,
    /// Skip minting/publishing git-bridge provenance attestations.
    #[arg(long = "no-attest")]
    no_attest: bool,
    /// Attestation algorithm: `ed25519`, `secp256k1`, or `p256`
    /// (default: `attest.default_algorithm` from config, else ed25519).
    #[arg(long, value_name = "ALG")]
    algorithm: Option<String>,
    /// Attestation signer kind: `repo-key`, `external`, or `keystore`
    /// (default: the configured attest signer, like `mkit attest`).
    #[arg(long, value_name = "KIND")]
    signer: Option<String>,
    /// Fork mode (SPEC-GIT-BRIDGE §14): re-emit imported history as
    /// the ORIGINAL git objects (shared SHAs with the upstream) and
    /// bridge-translate only native commits on top. Requires this
    /// remote-name's import state; upgrades its direction to `fork`.
    #[arg(long)]
    passthrough: bool,
    /// Machine-readable JSON on stdout.
    #[arg(long)]
    json: bool,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let cmd = match clap_shim::parse::<Cmd>("mkit git", args) {
        Ok(c) => c,
        Err(code) => return code,
    };
    match cmd {
        Cmd::Export(opts) => {
            let cwd = match std::env::current_dir() {
                Ok(c) => c,
                Err(e) => return emit_err(&format!("cwd: {e}"), exit::CONFIG_ERROR),
            };
            match export(&cwd, &opts) {
                Ok(code) => code,
                Err((msg, code)) => emit_err(&msg, code),
            }
        }
        Cmd::Import(opts) => super::git_import::run_import(&opts),
        Cmd::Fetch(opts) => super::git_import::run_fetch(&opts, false),
        Cmd::Pull(opts) => super::git_import::run_fetch(&opts, true),
        Cmd::Verify(opts) => run_simple(|| super::git_tools::verify(&opts)),
        Cmd::Status(opts) => run_simple(|| super::git_tools::status(&opts)),
        Cmd::FormatPatch(opts) => run_simple(|| super::git_tools::format_patch(&opts)),
    }
}

fn gitsrc_is_ancestor(staging: &Path, old: &Sha1Id, new: &Sha1Id) -> CmdResult<bool> {
    mkit_git_bridge::gitsrc::is_ancestor(staging, old, new)
        .map_err(|e| (e.to_string(), exit::GENERAL_ERROR))
}

fn json_report(ok: bool, exported: &[Exported], skipped: &[(String, String)]) -> String {
    let mut out = format!("{{\"ok\":{ok},\"exported\":[");
    for (i, e) in exported.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"ref\":\"{}\",\"mkit\":\"{}\",\"git\":\"{}\"}}",
            format::json_escape(&e.ref_name),
            mkit_core::to_hex(&e.mkit_hash),
            sha1_hex(&e.git_id)
        );
    }
    out.push_str("],\"skipped\":[");
    for (i, (r, why)) in skipped.iter().enumerate() {
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
    out
}

fn run_simple(f: impl FnOnce() -> Result<(), (String, u8)>) -> u8 {
    match f() {
        Ok(()) => exit::OK,
        Err((msg, code)) => emit_err(&msg, code),
    }
}

struct Exported {
    ref_name: String,
    mkit_hash: Hash,
    git_id: Sha1Id,
}

type CmdResult<T> = Result<T, (String, u8)>;

#[allow(clippy::too_many_lines)] // linear pipeline; stages are commented
fn export(cwd: &Path, opts: &ExportArgs) -> CmdResult<u8> {
    let store = ObjectStore::open(cwd)
        .map_err(|e| (format!("open repository: {e}"), exit::GENERAL_ERROR))?;
    let mkit_dir = cwd.join(mkit_core::store::MKIT_DIR);
    git_version().map_err(|e| (e, exit::UNAVAILABLE))?;

    // An option-shaped dest must never reach a git argv, and an empty
    // one would `git init --bare` the caller's working directory.
    if opts.dest.trim().is_empty() {
        return Err(("empty git URL or path".into(), exit::USAGE));
    }
    if opts.dest.starts_with('-') {
        return Err((
            format!("{:?} is not a valid git URL or path", opts.dest),
            exit::USAGE,
        ));
    }

    // ── per-remote bridge state + bare staging repo ────────────────
    let state =
        map::state_dir(&mkit_dir, &opts.remote_name).map_err(|e| (e.to_string(), exit::USAGE))?;
    // One bridge operation per state dir at a time (shared with the
    // import side: fetch + passthrough export on a fork dir race the
    // staging mirror and the map).
    let _state_lock =
        mkit_core::repo_lock::acquire_default(&mkit_dir, &format!("git-{}.lock", opts.remote_name))
            .map_err(|e| {
                (
                    format!(
                        "bridge state '{}' is busy (another mkit git operation?): {e}",
                        opts.remote_name
                    ),
                    exit::TEMPFAIL,
                )
            })?;

    // ORIGIN GUARD (SPEC-GIT-BRIDGE §14.2), FIRST — before any state
    // is stamped or the dest is initialized, so a refusal has no side
    // effects. Export toward a recorded git-import source would pass
    // its ls-remote-seeded lease and force-replace upstream history
    // with a disconnected re-translation. The only supported path is
    // passthrough export through the SAME state that imported it
    // (whose map re-emits the upstream's own objects) — passthrough
    // through a DIFFERENT state is just as disconnected as a plain
    // export.
    let dest_identity = mkit_git_bridge::remoteid::remote_identity(&opts.dest);
    if let Some(import_state) = recorded_import_source(&mkit_dir, &dest_identity)
        && !(opts.passthrough && import_state == opts.remote_name)
    {
        return Err((
            format!(
                "{} is a recorded git-import source (state '{import_state}'); \
                 export toward an imported-from upstream would replace its \
                 history with a disconnected re-translation. Passthrough export \
                 through that state (`--passthrough --remote-name {import_state}`) \
                 is the supported path (SPEC-GIT-BRIDGE §14.2)",
                opts.dest
            ),
            exit::USAGE,
        ));
    }

    // Direction binding (SPEC-GIT-IMPORT §6): plain export owns its
    // state dir; --passthrough upgrades an IMPORT state dir to fork.
    if opts.passthrough {
        if mkit_git_bridge::map::read_direction(&state)
            .ok()
            .flatten()
            .is_none()
        {
            return Err((
                format!(
                    "--passthrough requires import state for '{}' — run \
                     `mkit git import <url>` first (SPEC-GIT-BRIDGE §14.1)",
                    opts.remote_name
                ),
                exit::USAGE,
            ));
        }
        // §3.3 stickiness: history imported with historic-mode
        // normalization cannot reproduce its original sha1s — a fork
        // built on it would fail every fork audit as false tampering.
        if mkit_git_bridge::map::read_normalized(&state)
            .map_err(|e| (e.to_string(), exit::GENERAL_ERROR))?
        {
            return Err((
                format!(
                    "state '{}' contains historic-mode-normalized trees; fork mode \
                     cannot reproduce their original sha1s (SPEC-GIT-IMPORT §3.3). \
                     Re-import under a new --remote-name to get fork-strict refusals",
                    opts.remote_name
                ),
                exit::USAGE,
            ));
        }
        mkit_git_bridge::map::bind_direction(&state, mkit_git_bridge::map::Direction::Fork)
            .map_err(|e| (e.to_string(), exit::USAGE))?;
    } else {
        // Validate the direction early (mismatch refusals must fire
        // before any work) but WRITE a fresh stamp only after the
        // push succeeds — a typo'd remote dest must not burn the
        // state name (mirrors the import side's validate-then-bind).
        match mkit_git_bridge::map::read_direction(&state)
            .map_err(|e| (e.to_string(), exit::GENERAL_ERROR))?
        {
            None | Some(mkit_git_bridge::map::Direction::Export) => {}
            Some(other) => {
                return Err((
                    format!(
                        "state dir is bound to direction '{}'; 'export' is not allowed \
                         here (one direction per state dir — use a different \
                         --remote-name)",
                        other.as_str()
                    ),
                    exit::USAGE,
                ));
            }
        }
    }

    let staging = state.join("repo.git");
    if !staging.join("objects").is_dir() {
        if opts.passthrough {
            return Err((
                "fork-mode staging mirror missing — re-run `mkit git import` to restore it".into(),
                exit::CONFIG_ERROR,
            ));
        }
        // (Re)initializing staging invalidates the map cache: cached
        // sha1s would point at objects the fresh staging repo does not
        // have, wedging update-ref/push (§12.3: cache is disposable).
        let _ = std::fs::remove_file(state.join("map"));
        std::fs::create_dir_all(&staging)
            .map_err(|e| (format!("create staging dir: {e}"), exit::CANTCREAT))?;
        git_in(&staging, &["init", "--bare", "--quiet", "."])
            .map_err(|e| (format!("init staging repo: {e}"), exit::CANTCREAT))?;
    }
    let mut known =
        map::load_map(&state).map_err(|e| (format!("load map cache: {e}"), exit::GENERAL_ERROR))?;
    let prior_state = map::load_ref_state(&state)
        .map_err(|e| (format!("load ref state: {e}"), exit::GENERAL_ERROR))?;

    // Validate/prepare the destination up front (before any signing or
    // state mutation). PLAIN export binds this state dir to one dest
    // by canonical identity (SPEC-GIT-IMPORT §8): recorded leases are
    // statements about one mirror and are wrong for another. FORK
    // mode does NOT bind — its leases come from a fresh per-push
    // observation guarded by the explicit fast-forward check, so the
    // triangular workflow (import upstream U, push fork F, later
    // contribute to U) stays possible; the last dest is recorded for
    // `mkit git status` only.
    let push_dest = ensure_dest(&opts.dest)?;
    // A state dir is FRESH when nothing has ever bound it: if the
    // remote contact below fails, the whole dir (staging, map cache)
    // is removed so the name is not burned and a later import cannot
    // land on mixed leftovers.
    let fresh_state = !opts.passthrough && !state.join("dest").exists();

    // Recompute AFTER ensure_dest: a fresh local mirror did not exist
    // when the origin-guard identity above was taken, so its lexical
    // fallback differs from the canonicalized spelling every later
    // run produces — binding the early value would wedge the state on
    // the second export. (The guard itself is unaffected: recorded
    // import sources always exist.)
    let bound_identity = mkit_git_bridge::remoteid::remote_identity(&opts.dest);

    let dest_file = state.join("dest");
    if opts.passthrough {
        mkit_git_bridge::map::write_binding(&state, "dest", &bound_identity)
            .map_err(|e| (format!("record dest: {e}"), exit::CANTCREAT))?;
    } else {
        match std::fs::read_to_string(&dest_file) {
            Ok(recorded) if recorded.trim() != bound_identity => {
                return Err((
                    format!(
                        "state '{}' is bound to {}; use a different --remote-name for {}",
                        opts.remote_name,
                        recorded.trim(),
                        opts.dest
                    ),
                    exit::USAGE,
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Recorded after the push succeeds (see below).
            }
            Err(e) => return Err((format!("read dest binding: {e}"), exit::GENERAL_ERROR)),
        }
    }

    // ── ref selection (§12.1) ──────────────────────────────────────
    let requested = collect_refs(&mkit_dir, &opts.refs)?;
    if requested.is_empty() {
        return Err(("nothing to export: no branches or tags".into(), exit::USAGE));
    }

    let mut exported: Vec<Exported> = Vec::new();
    let mut skipped: Vec<(String, String)> = Vec::new();
    let mut new_pairs: Vec<(Hash, Sha1Id)> = Vec::new();

    for (ref_name, head) in requested {
        if let Err(refusal) = refname::check_git_legal(&ref_name) {
            warn_skip(&mut skipped, &ref_name, &refusal.to_string());
            continue;
        }
        let result = translate_closure(&store, &head, &mut known, &mut |h, g| {
            let id = g.write_loose(&staging)?;
            new_pairs.push((*h, id));
            Ok(())
        });
        match result {
            Ok(batch) => {
                // Fork mode writes under a private namespace so the
                // import mirror's own refs (upstream state) stay
                // untouched; the push refspec maps it back.
                let local_ref = if opts.passthrough {
                    format!("refs/mkit-export/{ref_name}")
                } else {
                    ref_name.clone()
                };
                git_in(
                    &staging,
                    &["update-ref", &local_ref, &sha1_hex(&batch.root)],
                )
                .map_err(|e| (format!("update-ref {ref_name}: {e}"), exit::GENERAL_ERROR))?;
                exported.push(Exported {
                    ref_name,
                    mkit_hash: head,
                    git_id: batch.root,
                });
            }
            Err(BridgeError::Refused(r)) => {
                // Objects already written are harmless content-addressed
                // orphans; the map pairs stay valid (determinism).
                warn_skip(&mut skipped, &ref_name, &r.to_string());
            }
            Err(e) => return Err((format!("translate {ref_name}: {e}"), exit::GENERAL_ERROR)),
        }
    }

    map::append_map(&state, &new_pairs)
        .map_err(|e| (format!("persist map cache: {e}"), exit::GENERAL_ERROR))?;

    if exported.is_empty() {
        if opts.json {
            // Same shape as the success report, ok:false — a JSON
            // consumer gets per-ref skip reasons here just like the
            // import side does.
            println!("{}", json_report(false, &exported, &skipped));
        }
        return Err((
            format!(
                "every requested ref was skipped ({} refusals)",
                skipped.len()
            ),
            exit::GENERAL_ERROR,
        ));
    }

    // ── provenance attestations (§11) ──────────────────────────────
    // §11 scoping: fork-mode heads whose tip passed through (came
    // from the import map) carry no translation claim — their
    // provenance is git-import/v1.
    let attestable: Vec<Exported> = exported
        .iter()
        .filter(|e| {
            if !opts.passthrough {
                return true;
            }
            // An imported tip's raw git bytes are retained under
            // state/raw/ — that head passed through and its
            // provenance is git-import/v1, not a translation claim.
            let hex = sha1_hex(&e.git_id);
            !state.join("raw").join(&hex[..2]).join(&hex[2..]).exists()
        })
        .map(|e| Exported {
            ref_name: e.ref_name.clone(),
            mkit_hash: e.mkit_hash,
            git_id: e.git_id,
        })
        .collect();
    let attest_head: Option<Sha1Id> = if opts.no_attest || attestable.is_empty() {
        None
    } else {
        Some(publish_attestations(
            cwd,
            &mkit_dir,
            &store,
            &staging,
            &opts.dest,
            &attestable,
            opts,
            &prior_state,
        )?)
    };

    // ── push with per-ref CAS leases (§12.2) ───────────────────────
    // Lease expectation per ref: recorded state, else (state lost or
    // never recorded) the mirror's CURRENT value via ls-remote — a
    // fresh observation is still a CAS, and it is what makes wiped
    // bridge state rebuildable against an existing mirror (§12.3).
    let prior: HashMap<&str, &map::RefState> = prior_state
        .iter()
        .map(|s| (s.ref_name.as_str(), s))
        .collect();
    let mut to_push: Vec<(&str, Sha1Id)> = exported
        .iter()
        .map(|e| (e.ref_name.as_str(), e.git_id))
        .collect();
    if let Some(head) = attest_head {
        to_push.push((ATTESTATIONS_REF, head));
    }
    // Fork mode ALWAYS observes: it pushes to a repository mkit does
    // not own, so the remote moving between exports is the normal
    // case — a recorded lease from our last push would go stale the
    // moment a third-party commit lands, and `mkit git fetch` only
    // updates the import side. The fresh observation is safe to lease
    // against because the explicit fast-forward guard below refuses
    // anything we have not integrated. Plain export keeps recorded
    // leases (the mirror is owned by this repo; the lease IS the
    // tamper check) and observes only refs it has no lease for.
    let needs_observation =
        opts.passthrough || to_push.iter().any(|(name, _)| !prior.contains_key(*name));
    let observed: HashMap<String, Sha1Id> = if needs_observation {
        match ls_remote(&staging, &push_dest) {
            Ok(o) => o,
            Err(e) => {
                if fresh_state {
                    let _ = std::fs::remove_dir_all(&state);
                }
                return Err(e);
            }
        }
    } else {
        HashMap::new()
    };
    // One expectation rule shared by the FF guard and the push lease.
    // Passthrough: the observation is AUTHORITATIVE — fork mode is
    // not dest-bound, so a lease recorded against one destination is
    // meaningless for another (absent on the remote means "must not
    // exist", never "fall back to what we pushed elsewhere").
    let expectation = |name: &str| -> Option<Sha1Id> {
        if opts.passthrough {
            observed.get(name).copied()
        } else {
            prior
                .get(name)
                .map(|s| s.git_id)
                .or_else(|| observed.get(name).copied())
        }
    };
    // Fork mode pushes to repositories mkit does NOT own (the
    // upstream itself, or a real fork): a lease seeded from a fresh
    // ls-remote observation passes unconditionally, so require
    // fast-forward explicitly — the expected value must be an
    // ancestor of what we push, and tags must not move. Plain export
    // keeps Phase-1 semantics (the mirror is owned by this repo).
    if opts.passthrough {
        for (name, new_id) in &to_push {
            if *name == ATTESTATIONS_REF {
                continue;
            }
            let Some(expect) = expectation(name) else {
                continue;
            };
            if expect == *new_id {
                continue;
            }
            if name.starts_with("refs/tags/") {
                return Err((
                    format!(
                        "{name} already exists on {} at a different object; fork-mode \
                         export never moves an existing tag",
                        opts.dest
                    ),
                    exit::USAGE,
                ));
            }
            let ff = mkit_git_bridge::gitsrc::object_exists(&staging, &expect)
                .map_err(|e| (e.to_string(), exit::GENERAL_ERROR))?
                && gitsrc_is_ancestor(&staging, &expect, new_id)?;
            if !ff {
                return Err((
                    format!(
                        "{name} on {} has commits this repo has not integrated; \
                         run `mkit git fetch` and `mkit merge {}/{}` first \
                         (fork-mode export refuses non-fast-forward pushes)",
                        opts.dest,
                        opts.remote_name,
                        name.strip_prefix("refs/heads/").unwrap_or(name)
                    ),
                    exit::DATAERR,
                ));
            }
        }
    }

    // --atomic: either every ref (incl. attestations) lands or none
    // does, so recorded state can never go stale per-ref.
    let mut push_args: Vec<String> = vec!["push".into(), "--quiet".into(), "--atomic".into()];
    for (name, _) in &to_push {
        let expect = expectation(name)
            .map(|id| sha1_hex(&id))
            .unwrap_or_default();
        push_args.push(format!("--force-with-lease={name}:{expect}"));
    }
    push_args.push(push_dest.clone());
    for (name, _) in &to_push {
        if opts.passthrough && *name != ATTESTATIONS_REF {
            push_args.push(format!("refs/mkit-export/{name}:{name}"));
        } else {
            push_args.push(format!("{name}:{name}"));
        }
    }
    let push_arg_refs: Vec<&str> = push_args.iter().map(String::as_str).collect();
    git_in(&staging, &push_arg_refs).map_err(|e| {
        if fresh_state {
            let _ = std::fs::remove_dir_all(&state);
        }
        let hint = if e.contains("stale info") {
            "\nhint: the mirror moved since the last export; if that \
             change is yours/expected, remove .mkit/git/<name>/refs to \
             reseed leases from the mirror and re-run"
        } else {
            ""
        };
        (
            format!("push to {}: {e}{hint}", opts.dest),
            exit::GENERAL_ERROR,
        )
    })?;

    // Push succeeded: record the fresh plain-export bindings the
    // validation above deferred (idempotent for already-bound dirs).
    if !opts.passthrough {
        mkit_git_bridge::map::bind_direction(&state, mkit_git_bridge::map::Direction::Export)
            .map_err(|e| (e.to_string(), exit::CANTCREAT))?;
        if !dest_file.exists() {
            mkit_git_bridge::map::write_binding(&state, "dest", &bound_identity)
                .map_err(|e| (format!("record dest: {e}"), exit::CANTCREAT))?;
        }
    }

    // ── record the new lease expectations ──────────────────────────
    // Merge over prior state: refs not in this export keep their
    // recorded leases (a --ref subset or a skip must not wipe them).
    let mut merged: Vec<map::RefState> = prior_state
        .iter()
        .filter(|s| !to_push.iter().any(|(n, _)| *n == s.ref_name))
        .cloned()
        .collect();
    merged.extend(exported.iter().map(|e| map::RefState {
        ref_name: e.ref_name.clone(),
        mkit_hash: e.mkit_hash,
        git_id: e.git_id,
    }));
    if let Some(head) = attest_head {
        merged.push(map::RefState {
            ref_name: ATTESTATIONS_REF.to_owned(),
            mkit_hash: mkit_core::hash::ZERO,
            git_id: head,
        });
    }
    merged.sort_by(|a, b| a.ref_name.cmp(&b.ref_name));
    map::store_ref_state(&state, &merged)
        .map_err(|e| (format!("persist ref state: {e}"), exit::GENERAL_ERROR))?;

    // ── report ─────────────────────────────────────────────────────
    if opts.json {
        println!("{}", json_report(true, &exported, &skipped));
    } else {
        for e in &exported {
            println!(
                "exported {} {} -> {}",
                e.ref_name,
                mkit_core::to_hex(&e.mkit_hash),
                sha1_hex(&e.git_id)
            );
        }
    }
    Ok(exit::OK)
}

/// Default export set: every branch and tag, as full ref names.
fn collect_refs(mkit_dir: &Path, explicit: &[String]) -> CmdResult<Vec<(String, Hash)>> {
    if !explicit.is_empty() {
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for name in explicit {
            if !seen.insert(name.as_str()) {
                continue; // duplicate --ref would duplicate the refspec
            }
            let short = name
                .strip_prefix("refs/heads/")
                .or_else(|| name.strip_prefix("refs/tags/"));
            let Some(short) = short else {
                return Err((
                    format!("--ref {name}: expected refs/heads/... or refs/tags/..."),
                    exit::USAGE,
                ));
            };
            // read_ref/read_tag take namespace-relative short names.
            let hash = if name.starts_with("refs/heads/") {
                refs::read_ref(mkit_dir, short)
            } else {
                refs::read_tag(mkit_dir, short)
            }
            .map_err(|e| (format!("read {name}: {e}"), exit::GENERAL_ERROR))?
            .ok_or_else(|| (format!("--ref {name}: not found"), exit::DATAERR))?;
            out.push((name.clone(), hash));
        }
        return Ok(out);
    }
    let mut out = Vec::new();
    let branches = refs::list_refs(mkit_dir)
        .map_err(|e| (format!("list branches: {e}"), exit::GENERAL_ERROR))?;
    for r in branches {
        if let Some(h) = r.hash {
            out.push((format!("refs/heads/{}", r.name), h));
        }
    }
    let tags =
        refs::list_tags(mkit_dir).map_err(|e| (format!("list tags: {e}"), exit::GENERAL_ERROR))?;
    for r in tags {
        if let Some(h) = r.hash {
            out.push((format!("refs/tags/{}", r.name), h));
        }
    }
    Ok(out)
}

/// Mint one DSSE attestation per exported head (subject = mkit hash,
/// predicate carries the git locator), save it locally like `mkit
/// attest` does, and publish the set on the staging repo's
/// `refs/mkit/attestations` flat tree. Returns the staging ref's
/// resulting head — unchanged trees return the existing commit, so a
/// previously failed push retries with the same refspec instead of
/// silently dropping the attestations ref.
#[allow(clippy::too_many_lines)] // mint loop + tree/commit assembly; splitting would scatter §11
fn publish_attestations(
    cwd: &Path,
    mkit_dir: &Path,
    store: &ObjectStore,
    staging: &Path,
    dest: &str,
    exported: &[Exported],
    opts: &ExportArgs,
    prior_state: &[map::RefState],
) -> CmdResult<Sha1Id> {
    // Same signer resolution as `mkit attest` (SPEC-GIT-BRIDGE §11:
    // "the exporter's configured signer"): flag, else config default.
    let cfg = crate::config::read_or_default(cwd)
        .map_err(|e| (format!("read config: {e}"), exit::CONFIG_ERROR))?;
    let alg_str = opts
        .algorithm
        .clone()
        .unwrap_or_else(|| cfg.attest.default_algorithm_or_fallback().to_owned());
    let algorithm =
        attest_factory::parse_algorithm(&alg_str).map_err(|e| (format!("{e}"), exit::USAGE))?;
    let signer_kind = opts
        .signer
        .clone()
        .unwrap_or_else(|| cfg.attest.signer_or_fallback().to_owned());
    let mut signer =
        attest_factory::build_signer(cwd, algorithm, &signer_kind, &cfg).map_err(|e| {
            (
                format!("build bridge signer: {e}"),
                crate::commands::attest::factory_error_code(&e),
            )
        })?;

    // Existing published entries (name → blob id) so re-exports merge.
    let mut entries: Vec<(String, Sha1Id)> = Vec::new();
    let old_commit = read_ref_in(staging, ATTESTATIONS_REF)?;
    if let Some(old) = &old_commit {
        for (name, id) in ls_tree(staging, old)? {
            entries.push((name, id));
        }
    }

    // Mint only for new/moved heads: a head whose recorded state is
    // unchanged AND whose claim is already on the published ref needs
    // no fresh envelope. This keeps no-op re-exports no-op even with
    // nondeterministic signers (e.g. P-256), instead of growing the
    // tree and local store every run.
    let already_published = |e: &Exported| -> bool {
        old_commit.is_some()
            && prior_state.iter().any(|s| {
                s.ref_name == e.ref_name && s.mkit_hash == e.mkit_hash && s.git_id == e.git_id
            })
    };
    let mut max_ts = 0u64;
    for e in exported {
        if already_published(e) {
            max_ts = max_ts.max(head_timestamp(store, &e.mkit_hash));
            continue;
        }
        // Deterministic synthetic-commit timestamp: newest exported head.
        max_ts = max_ts.max(head_timestamp(store, &e.mkit_hash));
        let predicate = format!(
            "{{\"gitCommit\":\"{}\",\"mirror\":\"{}\",\"refName\":\"{}\",\"schemaVersion\":1,\"specVersion\":1}}",
            sha1_hex(&e.git_id),
            format::json_escape(dest),
            format::json_escape(&e.ref_name)
        );
        let stmt = statement::encode(&statement::Statement {
            subjects: vec![statement::Subject {
                name: Some(e.ref_name.clone()),
                digest_blake3_hex: mkit_core::to_hex(&e.mkit_hash),
            }],
            predicate_type: PREDICATE_TYPE.to_owned(),
            predicate_jcs: predicate.as_bytes(),
        })
        .map_err(|e| (format!("encode statement: {e}"), exit::GENERAL_ERROR))?;
        let pae = mkit_attest::pae_of(PAYLOAD_TYPE_IN_TOTO, stmt.as_bytes());
        let sig = signer
            .sign(&pae)
            .map_err(|e| (format!("sign bridge attestation: {e}"), exit::GENERAL_ERROR))?;
        let keyid = signer
            .keyid()
            .map_err(|e| (format!("bridge signer keyid: {e}"), exit::GENERAL_ERROR))?;
        let envelope = Envelope {
            payload_type: PAYLOAD_TYPE_IN_TOTO.to_owned(),
            payload: stmt.into_bytes(),
            signatures: vec![Sig { keyid, sig }],
        };
        let encoded = envelope
            .encode()
            .map_err(|e| (format!("encode envelope: {e}"), exit::GENERAL_ERROR))?;
        attest_store::save(mkit_dir, &e.mkit_hash, encoded.as_bytes())
            .map_err(|e| (format!("save attestation: {e}"), exit::CANTCREAT))?;

        let blob = GitObject {
            gtype: GitType::Blob,
            body: encoded.into_bytes(),
        };
        let blob_id = blob
            .write_loose(staging)
            .map_err(|e| (format!("write attestation blob: {e}"), exit::CANTCREAT))?;
        // Entry name = attestation id (BLAKE3 of the envelope bytes,
        // matching the local store's naming). Naming by git sha would
        // collide when two refs share a head — each ref still gets
        // its own envelope (distinct refName in the predicate).
        let att_id = mkit_attest::attestation_id(blob.body.as_slice());
        let name = format!("{}.dsse", mkit_core::to_hex(&att_id));
        entries.retain(|(n, _)| n != &name);
        entries.push((name, blob_id));
    }

    // Flat tree, git sort order (all blobs, so plain byte-lex).
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut tree_body = Vec::new();
    for (name, id) in &entries {
        tree_body.extend_from_slice(b"100644 ");
        tree_body.extend_from_slice(name.as_bytes());
        tree_body.push(0);
        tree_body.extend_from_slice(id);
    }
    let tree = GitObject {
        gtype: GitType::Tree,
        body: tree_body,
    };
    let tree_id = tree
        .write_loose(staging)
        .map_err(|e| (format!("write attestation tree: {e}"), exit::CANTCREAT))?;

    // Unchanged tree ⇒ keep the existing commit (no new history; the
    // caller still pushes the ref so an earlier failed push retries).
    if let Some(old) = &old_commit
        && commit_tree_id(staging, old)? == Some(tree_id)
    {
        return Ok(*old);
    }

    let person = format!("mkit-git-bridge <bridge@mkit.invalid> {max_ts} +0000");
    let mut body = Vec::new();
    body.extend_from_slice(format!("tree {}\n", sha1_hex(&tree_id)).as_bytes());
    if let Some(old) = &old_commit {
        body.extend_from_slice(format!("parent {}\n", sha1_hex(old)).as_bytes());
    }
    body.extend_from_slice(format!("author {person}\ncommitter {person}\n").as_bytes());
    body.extend_from_slice(b"\nmkit git-bridge attestations\n");
    let commit = GitObject {
        gtype: GitType::Commit,
        body,
    };
    let commit_id = commit
        .write_loose(staging)
        .map_err(|e| (format!("write attestation commit: {e}"), exit::CANTCREAT))?;
    git_in(
        staging,
        &["update-ref", ATTESTATIONS_REF, &sha1_hex(&commit_id)],
    )
    .map_err(|e| {
        (
            format!("update-ref {ATTESTATIONS_REF}: {e}"),
            exit::GENERAL_ERROR,
        )
    })?;
    Ok(commit_id)
}

fn head_timestamp(store: &ObjectStore, h: &Hash) -> u64 {
    match store.read_object(h) {
        Ok(Object::Commit(c)) => c.timestamp,
        Ok(Object::Tag(t)) => t.timestamp,
        _ => 0,
    }
}

fn warn_skip(skipped: &mut Vec<(String, String)>, ref_name: &str, why: &str) {
    eprintln!("warning: skipping {ref_name}: {why}");
    skipped.push((ref_name.to_owned(), why.to_owned()));
}

// ─── git subprocess helpers ─────────────────────────────────────────

pub(crate) fn git_version() -> Result<(), String> {
    match Command::new("git")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(format!("`git --version` exited with {s}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err("`git` not found on PATH; mkit git export shells out to it".into())
        }
        Err(e) => Err(format!("spawn git: {e}")),
    }
}

pub(crate) fn git_in(dir: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .map_err(|e| format!("spawn git: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!(
            "git {} failed: {}",
            args.first().copied().unwrap_or(""),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// A missing or empty *local path* destination is initialized as a
/// bare repo; URLs pass through untouched. Local paths come back
/// absolutized because the push runs `git -C <staging>`, which would
/// otherwise resolve them against the staging directory.
fn ensure_dest(dest: &str) -> CmdResult<String> {
    if dest.starts_with('-') {
        // Would be parsed as a git option in the push argv.
        return Err((format!("invalid destination {dest:?}"), exit::USAGE));
    }
    // git's own rule: "://" means a URL, and otherwise a colon BEFORE
    // the first slash means an scp-style remote (user@ is optional) —
    // except a DOS drive prefix (`C:\` / `C:/`), which is a path.
    let dos_drive = dest.len() >= 2
        && dest.as_bytes()[0].is_ascii_alphabetic()
        && dest.as_bytes()[1] == b':'
        && matches!(dest.as_bytes().get(2), None | Some(b'/' | b'\\'));
    let looks_like_url = !dos_drive
        && (dest.contains("://")
            || dest
                .split('/')
                .next()
                .is_some_and(|first| first.contains(':')));
    if looks_like_url {
        return Ok(dest.to_owned());
    }
    let path = PathBuf::from(dest);
    let needs_init = if path.exists() {
        let is_repo = Command::new("git")
            .arg("-C")
            .arg(&path)
            .args(["rev-parse", "--git-dir"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if is_repo {
            false
        } else {
            let empty = std::fs::read_dir(&path)
                .map_err(|e| (format!("read {dest}: {e}"), exit::CONFIG_ERROR))?
                .next()
                .is_none();
            if !empty {
                return Err((
                    format!("{dest} exists and is neither a git repository nor empty"),
                    exit::CANTCREAT,
                ));
            }
            true
        }
    } else {
        std::fs::create_dir_all(&path)
            .map_err(|e| (format!("create {dest}: {e}"), exit::CANTCREAT))?;
        true
    };
    if needs_init {
        git_in(&path, &["init", "--bare", "--quiet", "."])
            .map_err(|e| (format!("init {dest}: {e}"), exit::CANTCREAT))?;
    }
    let abs = path
        .canonicalize()
        .map_err(|e| (format!("resolve {dest}: {e}"), exit::CONFIG_ERROR))?;
    Ok(abs.to_string_lossy().into_owned())
}

fn read_ref_in(repo: &Path, name: &str) -> CmdResult<Option<Sha1Id>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "--verify", "--quiet", name])
        .output()
        .map_err(|e| (format!("spawn git: {e}"), exit::GENERAL_ERROR))?;
    if !out.status.success() {
        return Ok(None);
    }
    let hex = String::from_utf8_lossy(&out.stdout);
    Ok(sha1_from_hex(hex.trim()))
}

fn ls_tree(repo: &Path, commit: &Sha1Id) -> CmdResult<Vec<(String, Sha1Id)>> {
    let spec = format!("{}^{{tree}}", sha1_hex(commit));
    let out = git_in(repo, &["ls-tree", &spec])
        .map_err(|e| (format!("ls-tree: {e}"), exit::GENERAL_ERROR))?;
    let mut entries = Vec::new();
    for line in out.lines() {
        // "<mode> blob <id>\t<name>"
        let Some((meta, name)) = line.split_once('\t') else {
            continue;
        };
        let Some(id_hex) = meta.split(' ').nth(2) else {
            continue;
        };
        if let Some(id) = sha1_from_hex(id_hex) {
            entries.push((name.to_owned(), id));
        }
    }
    Ok(entries)
}

fn commit_tree_id(repo: &Path, commit: &Sha1Id) -> CmdResult<Option<Sha1Id>> {
    let spec = format!("{}^{{tree}}", sha1_hex(commit));
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "--verify", "--quiet", &spec])
        .output()
        .map_err(|e| (format!("spawn git: {e}"), exit::GENERAL_ERROR))?;
    if !out.status.success() {
        return Ok(None);
    }
    let hex = String::from_utf8_lossy(&out.stdout);
    Ok(sha1_from_hex(hex.trim()))
}

/// Read the destination's current refs (one round-trip). Used to seed
/// lease expectations when recorded state is missing (§12.3).
fn ls_remote(staging: &Path, dest: &str) -> CmdResult<HashMap<String, Sha1Id>> {
    let out = git_in(staging, &["ls-remote", "--quiet", dest, "refs/*"])
        .map_err(|e| (format!("ls-remote {dest}: {e}"), exit::GENERAL_ERROR))?;
    let mut refs = HashMap::new();
    for line in out.lines() {
        let Some((hex, name)) = line.split_once('\t') else {
            continue;
        };
        if let Some(id) = sha1_from_hex(hex.trim()) {
            refs.insert(name.trim().to_owned(), id);
        }
    }
    Ok(refs)
}

/// The state-dir name whose recorded import `source` matches the
/// given canonical identity, if any.
fn recorded_import_source(mkit_dir: &Path, identity: &str) -> Option<String> {
    let git_dir = mkit_dir.join("git");
    let entries = std::fs::read_dir(git_dir).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let src = entry.path().join("source");
        if let Ok(recorded) = std::fs::read_to_string(src)
            && recorded.trim() == identity
        {
            return Some(name);
        }
    }
    None
}

fn emit_err(msg: &str, code: u8) -> u8 {
    eprintln!("error: {msg}");
    code
}
