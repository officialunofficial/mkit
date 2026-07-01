//! `mkit self` — self-management of an installer-managed mkit binary.
//!
//! ```text
//! mkit self update [--version <tag>] [--check] [--allow-downgrade]
//!                  [--format human|json]
//! ```
//!
//! Updates the running binary in place from GitHub Releases,
//! verifying the **mkit-native release attestation** (a DSSE/in-toto
//! envelope over the BLAKE3 digests of the release tarballs — see
//! `docs/RELEASE.md`) against the release-attestation public keys
//! embedded in this binary at build time. Verification is fully
//! in-process: no `cosign`, no GitHub attestation API.
//!
//! Management contract (shared with `install.sh`):
//!
//! * The binary is "installer-managed" iff `<bin_dir>/.mkit-installed-tag`
//!   exists next to the (canonicalized) executable. Homebrew, cargo,
//!   and other package-manager installs don't have it — for those we
//!   refuse with channel-specific guidance instead of fighting the
//!   package manager.
//! * Receipts: `<bin_dir>/.mkit-installed-tag` plus the global
//!   `$MKIT_STATE_DIR/installed-tag` (default `~/.local/state/mkit`).
//!   Both are re-written after a successful swap, in the installer's
//!   exact format (`vX.Y.Z\n`, atomic `.new` + rename), so installer
//!   and updater stay interchangeable.
//! * Downgrade policy mirrors the installer: `latest` never
//!   downgrades; an explicit `--version` may only with
//!   `--allow-downgrade`, loudly.
//!
//! There is deliberately **no background update check** — this command
//! only ever runs when invoked. Network egress: `api.github.com` and
//! the release-asset host, HTTPS only, with an https→http redirect
//! downgrade refused (mirrors `mkit-transport-http`, #223).
//!
//! Environment:
//! * `GH_TOKEN` / `GITHUB_TOKEN` — bearer for the GitHub API. Optional
//!   for public repos; required while the repo is private.
//! * `MKIT_STATE_DIR` — receipt state dir override (installer parity).
//! * `MKIT_SELF_UPDATE_API_BASE` — override the API base URL
//!   (`https://api.github.com/repos/officialunofficial/mkit`). For
//!   tests and mirrors.
//!
//! Windows: not yet supported (there are no Windows release binaries);
//! exits `UNAVAILABLE` with a clear message. The swap step needs the
//! rename-old-then-move dance on Windows — revisit when a
//! `windows-msvc` target ships.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Parser;
use mkit_attest::{Registry, TrustRoot};
use mkit_core::hash;
use sha2::Digest as _;

use crate::clap_shim;
use crate::cli::CLI_VERSION;
use crate::exit;
use crate::format::json_escape;

/// Embedded release-attestation public keys (rotation set). This is a
/// crate-local copy of `docs/keys/release-attest.pub` so `cargo publish`
/// can package it; the `embedded_keys_match_docs_copy` test keeps the
/// two in sync.
const RELEASE_ATTEST_PUB: &str = include_str!("../../keys/release-attest.pub");

/// Predicate type URI the release attestation must carry
/// (SPEC-ATTESTATIONS §6.4; emitted by `mkit-release-attest sign`).
const PREDICATE_TYPE_RELEASE_V1: &str =
    "https://github.com/officialunofficial/mkit/spec/predicate/release/v1";

/// Target triple this binary was built for — release archives are
/// named `mkit-<version>-<triple>.tar.gz`. Emitted by `build.rs`.
const TARGET_TRIPLE: &str = env!("MKIT_TARGET_TRIPLE");

/// Default GitHub API base for release resolution.
const DEFAULT_API_BASE: &str = "https://api.github.com/repos/officialunofficial/mkit";

/// Read caps, defense-in-depth against a hostile or broken origin.
const MAX_JSON_BYTES: u64 = 4 * 1024 * 1024;
const MAX_DSSE_BYTES: u64 = 1024 * 1024;
const MAX_SHA256_BYTES: u64 = 4 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;
/// Cap on the extracted binary (the archive is ~4 MB compressed today;
/// 512 MB leaves room without letting a gzip bomb fill the disk).
const MAX_BINARY_BYTES: u64 = 512 * 1024 * 1024;

/// Maximum redirects; https→http downgrades are refused outright
/// (mirrors mkit-transport-http #223).
const MAX_REDIRECTS: usize = 5;

/// Per-request timeout. The archive is a few MB; 120 s tolerates slow
/// links without letting a stalled connection wedge the command.
const REQUEST_TIMEOUT: Duration = Duration::from_mins(2);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Parser)]
#[command(
    name = "mkit self update",
    about = "Update the mkit binary in place from a signed release."
)]
pub struct Opts {
    /// Pin to a specific release tag (e.g. v0.4.0). Default: latest.
    #[arg(long, value_name = "TAG")]
    pub version: Option<String>,
    /// Only report whether an update is available; change nothing.
    #[arg(long)]
    pub check: bool,
    /// Allow an explicit `--version` pin to downgrade. Never applies
    /// to `latest`.
    #[arg(long = "allow-downgrade")]
    pub allow_downgrade: bool,
    /// Output format: `human` (default) or `json`.
    #[arg(long, value_name = "FMT", default_value = "human")]
    pub format: String,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    match args.first().map(String::as_str) {
        Some("update") => run_update_cli(&args[1..]),
        Some("-h" | "--help") | None => {
            let mut stdout = std::io::stdout().lock();
            let _ = writeln!(
                stdout,
                "usage: mkit self update [--version <tag>] [--check] [--allow-downgrade] [--format human|json]"
            );
            exit::OK
        }
        Some(other) => super::error(
            &format!("unknown self subcommand '{other}' (expected: update)"),
            exit::USAGE,
        ),
    }
}

fn run_update_cli(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<Opts>("mkit self update", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    if !matches!(opts.format.as_str(), "human" | "json") {
        return super::error(
            &format!("unknown --format '{}' (expected: human, json)", opts.format),
            exit::USAGE,
        );
    }
    if opts.allow_downgrade && opts.version.is_none() {
        return super::error(
            "--allow-downgrade requires an explicit --version pin",
            exit::USAGE,
        );
    }

    if cfg!(windows) {
        return super::error(
            "self update is not yet supported on Windows (there are no Windows \
             release binaries yet); reinstall manually when a new release ships",
            exit::UNAVAILABLE,
        );
    }

    let env = match UpdateEnv::production() {
        Ok(e) => e,
        Err((msg, code)) => return super::error(&msg, code),
    };
    match run_update(&opts, &env) {
        Ok(outcome) => {
            emit_outcome(&outcome, &opts.format);
            exit::OK
        }
        Err((msg, code)) => super::error(&msg, code),
    }
}

/// Everything `run_update` touches outside pure computation, so the
/// integration tests can point the whole flow at a mock server, a
/// temp install dir, and a test trust root. Production wiring is
/// [`UpdateEnv::production`].
#[derive(Debug)]
pub struct UpdateEnv {
    /// Release-API base, no trailing slash.
    pub api_base: String,
    /// Bearer token for the API + asset downloads.
    pub token: Option<String>,
    /// Release-attestation trust roots (Ed25519 public keys).
    pub trust_keys: Vec<[u8; 32]>,
    /// Canonicalized path of the binary to replace.
    pub exe_path: PathBuf,
    /// Receipt state dir (`installed-tag` lives here).
    pub state_dir: PathBuf,
    /// Version currently running (bare, e.g. `0.3.0`).
    pub current_version: String,
    /// Archive-name target triple.
    pub target: String,
}

impl UpdateEnv {
    fn production() -> Result<Self, (String, u8)> {
        let exe_path = std::env::current_exe()
            .and_then(|p| p.canonicalize())
            .map_err(|e| (format!("resolve current executable: {e}"), exit::NOINPUT))?;
        let state_dir =
            match std::env::var_os("MKIT_STATE_DIR") {
                Some(d) => PathBuf::from(d),
                None => match std::env::var_os("HOME") {
                    Some(h) => Path::new(&h).join(".local/state/mkit"),
                    None => return Err((
                        "HOME is not set; cannot locate the receipt state dir (set MKIT_STATE_DIR)"
                            .to_owned(),
                        exit::CONFIG_ERROR,
                    )),
                },
            };
        let api_base = std::env::var("MKIT_SELF_UPDATE_API_BASE")
            .unwrap_or_else(|_| DEFAULT_API_BASE.to_owned());
        let token = std::env::var("GH_TOKEN")
            .or_else(|_| std::env::var("GITHUB_TOKEN"))
            .ok()
            .filter(|t| !t.is_empty());
        Ok(Self {
            api_base: api_base.trim_end_matches('/').to_owned(),
            token,
            trust_keys: parse_pubkeys(RELEASE_ATTEST_PUB)
                .map_err(|e| (format!("embedded release keys: {e}"), exit::CONFIG_ERROR))?,
            exe_path,
            state_dir,
            current_version: CLI_VERSION.to_owned(),
            target: TARGET_TRIPLE.to_owned(),
        })
    }
}

/// What happened, for output rendering.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    UpToDate {
        current: String,
    },
    UpdateAvailable {
        current: String,
        latest: String,
    },
    Updated {
        from: String,
        to: String,
        exe: PathBuf,
    },
}

fn emit_outcome(outcome: &Outcome, format: &str) {
    let mut stdout = std::io::stdout().lock();
    match (outcome, format) {
        (Outcome::UpToDate { current }, "json") => {
            let _ = writeln!(
                stdout,
                "{{\"status\":\"up-to-date\",\"current\":\"{}\"}}",
                json_escape(current)
            );
        }
        (Outcome::UpToDate { current }, _) => {
            let _ = writeln!(stdout, "mkit {current} is up to date");
        }
        (Outcome::UpdateAvailable { current, latest }, "json") => {
            let _ = writeln!(
                stdout,
                "{{\"status\":\"update-available\",\"current\":\"{}\",\"latest\":\"{}\"}}",
                json_escape(current),
                json_escape(latest)
            );
        }
        (Outcome::UpdateAvailable { current, latest }, _) => {
            let _ = writeln!(
                stdout,
                "update available: mkit {current} → {latest} (run `mkit self update`)"
            );
        }
        (Outcome::Updated { from, to, exe }, "json") => {
            let _ = writeln!(
                stdout,
                "{{\"status\":\"updated\",\"from\":\"{}\",\"to\":\"{}\",\"exe\":\"{}\"}}",
                json_escape(from),
                json_escape(to),
                json_escape(&exe.display().to_string())
            );
        }
        (Outcome::Updated { from, to, .. }, _) => {
            let _ = writeln!(stdout, "updated mkit {from} → {to}");
        }
    }
}

/// The full update flow. Everything before the swap is read-only.
///
/// # Errors
/// `(message, exit_code)` for every failure mode; the caller renders it.
#[allow(clippy::too_many_lines)] // linear resolve→verify→swap pipeline; splitting would obscure the ordering invariants
pub fn run_update(opts: &Opts, env: &UpdateEnv) -> Result<Outcome, (String, u8)> {
    if let Some(tag) = opts.version.as_deref() {
        validate_tag(tag).map_err(|e| (e, exit::USAGE))?;
    }

    let client = http_client(env)?;

    // --- Resolve the target release tag. -----------------------------
    let resolved_from_latest = opts.version.is_none();
    let target_tag = match opts.version.clone() {
        Some(t) => t,
        None => resolve_latest_tag(&client, env)?,
    };
    let target_bare = target_tag.trim_start_matches('v').to_owned();

    // --- `--check` is receipt-independent: compare against the running
    // binary's own version so it is useful under any install method. --
    if opts.check {
        return Ok(
            match cmp_versions(&env.current_version, &target_bare)
                .map_err(|e| (e, exit::DATAERR))?
            {
                std::cmp::Ordering::Less => Outcome::UpdateAvailable {
                    current: format!("v{}", env.current_version),
                    latest: target_tag,
                },
                _ => Outcome::UpToDate {
                    current: format!("v{}", env.current_version),
                },
            },
        );
    }

    // --- Management + receipts. --------------------------------------
    let bin_dir = env
        .exe_path
        .parent()
        .ok_or_else(|| {
            (
                "executable has no parent directory".to_owned(),
                exit::NOINPUT,
            )
        })?
        .to_path_buf();
    let local_receipt = bin_dir.join(".mkit-installed-tag");
    let global_receipt = env.state_dir.join("installed-tag");

    let local_tag = read_receipt(&local_receipt);
    let Some(local_tag) = local_tag else {
        return Err((unmanaged_guidance(&env.exe_path), exit::UNAVAILABLE));
    };
    let global_tag = read_receipt(&global_receipt);

    // Both receipts must agree when both exist (installer parity).
    if let Some(g) = &global_tag
        && g != &local_tag
    {
        return Err((
            format!(
                "installed-tag mismatch: {} says '{g}' but {} says '{local_tag}'. \
                 Refusing to update. Resolve manually.",
                global_receipt.display(),
                local_receipt.display()
            ),
            exit::DATAERR,
        ));
    }

    let installed_tag = local_tag;
    let installed_bare = installed_tag.trim_start_matches('v').to_owned();
    if installed_bare != env.current_version {
        eprintln!(
            "warning: receipt says {installed_tag} but this binary reports v{} — \
             receipts may have been edited; using the receipt for downgrade checks",
            env.current_version
        );
    }

    // --- Downgrade / no-op policy (installer parity). -----------------
    match cmp_versions(&target_bare, &installed_bare).map_err(|e| (e, exit::DATAERR))? {
        std::cmp::Ordering::Equal => {
            return Ok(Outcome::UpToDate {
                current: installed_tag,
            });
        }
        std::cmp::Ordering::Less if resolved_from_latest => {
            return Err((
                format!(
                    "refusing to silently downgrade from {installed_tag} to {target_tag} via \
                     'latest'. Pin --version {installed_tag} or newer, or delete {} and {}.",
                    global_receipt.display(),
                    local_receipt.display()
                ),
                exit::DATAERR,
            ));
        }
        std::cmp::Ordering::Less if !opts.allow_downgrade => {
            return Err((
                format!(
                    "{target_tag} is a DOWNGRADE from {installed_tag}; pass --allow-downgrade \
                     to proceed anyway"
                ),
                exit::USAGE,
            ));
        }
        std::cmp::Ordering::Less => {
            eprintln!(
                "warning: downgrading from {installed_tag} to {target_tag} (--allow-downgrade)"
            );
        }
        std::cmp::Ordering::Greater => {}
    }

    // --- Install-dir hardening (installer parity): a group- or world-
    // writable bin dir lets a local attacker race a replacement binary
    // into place between rename and first execution. ------------------
    refuse_lax_dir_perms(&bin_dir)?;

    // --- Fetch release metadata + assets. ----------------------------
    let release = fetch_release_by_tag(&client, env, &target_tag)?;
    let archive_name = format!("mkit-{target_bare}-{}.tar.gz", env.target);
    let dsse_name = format!("mkit-{target_bare}.release.dsse");

    let archive_url = asset_url(&release, &archive_name).ok_or_else(|| {
        (
            format!("release {target_tag} has no prebuilt binary for {} ({archive_name} not among its assets)", env.target),
            exit::UNAVAILABLE,
        )
    })?;
    let dsse_url = asset_url(&release, &dsse_name).ok_or_else(|| {
        (
            format!(
                "release {target_tag} predates the mkit-native release attestation \
                 ({dsse_name} not among its assets); it cannot be verified by self update — \
                 use install.sh (cosign path) instead"
            ),
            exit::UNAVAILABLE,
        )
    })?;

    eprintln!("downloading mkit {target_tag} ({})...", env.target);
    let archive_bytes = download(&client, env, &archive_url, MAX_ARCHIVE_BYTES)?;
    let dsse_bytes = download(&client, env, &dsse_url, MAX_DSSE_BYTES)?;

    // --- Verify. ------------------------------------------------------
    // (a) sha256 sidecar — pure defense-in-depth (same origin as the
    // archive); absence is tolerated, mismatch is not.
    if let Some(sha_url) = asset_url(&release, &format!("{archive_name}.sha256")) {
        let sha_body = download(&client, env, &sha_url, MAX_SHA256_BYTES)?;
        verify_sha256_sidecar(&archive_bytes, &sha_body, &archive_name)
            .map_err(|e| (e, exit::DATAERR))?;
    }
    // (b) the mkit-native attestation — REQUIRED.
    let keyid = verify_release_attestation(
        &dsse_bytes,
        &env.trust_keys,
        &target_tag,
        &archive_name,
        &archive_bytes,
    )
    .map_err(|e| (format!("release attestation: {e}"), exit::DATAERR))?;
    eprintln!("verified release attestation (keyid {keyid})");

    // --- Extract + pre-swap validation. -------------------------------
    let binary = extract_binary(
        &archive_bytes,
        &format!("mkit-{target_bare}-{}", env.target),
    )
    .map_err(|e| (e, exit::DATAERR))?;

    let staged = stage_binary(&bin_dir, &binary)?;
    if let Err(e) = check_staged_version(&staged, &target_bare) {
        let _ = std::fs::remove_file(&staged);
        return Err((e, exit::DATAERR));
    }

    // --- Swap + receipts. ----------------------------------------------
    std::fs::rename(&staged, &env.exe_path).map_err(|e| {
        let _ = std::fs::remove_file(&staged);
        (
            format!("replace {}: {e}", env.exe_path.display()),
            exit::CANTCREAT,
        )
    })?;

    // Receipt failures after a successful swap are warnings, not
    // errors: the binary IS updated, and failing the command here
    // would misreport that. The downgrade guard degrades gracefully.
    for receipt in [&local_receipt, &global_receipt] {
        if let Err(e) = write_receipt(receipt, &target_tag) {
            eprintln!(
                "warning: binary updated, but writing receipt {} failed: {e} — \
                 the silent-downgrade guard is weakened until it is restored",
                receipt.display()
            );
        }
    }

    Ok(Outcome::Updated {
        from: installed_tag,
        to: target_tag,
        exe: env.exe_path.clone(),
    })
}

// ------------------------------------------------------------ receipts

fn read_receipt(path: &Path) -> Option<String> {
    let s = std::fs::read_to_string(path).ok()?;
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_owned())
    }
}

fn write_receipt(path: &Path, tag: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("new");
    std::fs::write(&tmp, format!("{tag}\n"))?;
    std::fs::rename(&tmp, path)
}

fn unmanaged_guidance(exe: &Path) -> String {
    let p = exe.to_string_lossy();
    let hint = if p.contains("/Cellar/") || p.contains("/homebrew/") || p.contains("/linuxbrew/") {
        "this looks like a Homebrew install — run `brew upgrade mkit` instead"
    } else if p.contains("/.cargo/bin/") {
        "this looks like a cargo install — run `cargo install --locked mkit-cli` \
         (or `cargo binstall mkit-cli`) instead"
    } else {
        "reinstall via `curl mkit.sh | sh` to adopt it (the installer writes the receipt)"
    };
    format!(
        "this mkit binary ({p}) is not installer-managed (no .mkit-installed-tag receipt \
         next to it); {hint}"
    )
}

// ------------------------------------------------------------- versions

/// Strict-semver release tag, mirroring release.yml's regex.
fn validate_tag(tag: &str) -> Result<(), String> {
    let err = || format!("tag '{tag}' is not strict semver (vMAJOR.MINOR.PATCH[-suffix])");
    let rest = tag.strip_prefix('v').ok_or_else(err)?;
    parse_version(rest).map(|_| ()).map_err(|_| err())
}

type Parsed = (u64, u64, u64, Option<Vec<PreSeg>>);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum PreSeg {
    /// Numeric segments order before and below alphanumeric ones
    /// (semver §11.4).
    Num(u64),
    Alpha(String),
}

fn parse_version(bare: &str) -> Result<Parsed, String> {
    let (core, pre) = match bare.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (bare, None),
    };
    let mut nums = core.split('.');
    let mut next_num = |what: &str| -> Result<u64, String> {
        nums.next()
            .filter(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|p| p.parse().ok())
            .ok_or_else(|| format!("bad {what} in version '{bare}'"))
    };
    let (major, minor, patch) = (next_num("major")?, next_num("minor")?, next_num("patch")?);
    if nums.next().is_some() {
        return Err(format!("version '{bare}' has more than three components"));
    }
    let pre = match pre {
        None => None,
        Some(p) => {
            if p.is_empty() {
                return Err(format!("version '{bare}' has an empty prerelease"));
            }
            let mut segs = Vec::new();
            for s in p.split('.') {
                if s.is_empty() || !s.bytes().all(|b| b.is_ascii_alphanumeric()) {
                    return Err(format!("bad prerelease segment '{s}' in '{bare}'"));
                }
                segs.push(if s.bytes().all(|b| b.is_ascii_digit()) {
                    PreSeg::Num(
                        s.parse()
                            .map_err(|_| format!("prerelease number overflow in '{bare}'"))?,
                    )
                } else {
                    PreSeg::Alpha(s.to_owned())
                });
            }
            Some(segs)
        }
    };
    Ok((major, minor, patch, pre))
}

/// Semver ordering on bare versions (`0.3.0`, `1.0.0-rc.1`). A
/// prerelease orders below its release (semver §11.3).
fn cmp_versions(a: &str, b: &str) -> Result<std::cmp::Ordering, String> {
    let (amaj, amin, apat, apre) = parse_version(a)?;
    let (bmaj, bmin, bpat, bpre) = parse_version(b)?;
    Ok((amaj, amin, apat)
        .cmp(&(bmaj, bmin, bpat))
        .then_with(|| match (apre, bpre) {
            (None, None) => std::cmp::Ordering::Equal,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (Some(_), None) => std::cmp::Ordering::Less,
            (Some(x), Some(y)) => x.cmp(&y),
        }))
}

// ----------------------------------------------------------------- HTTP

fn http_client(env: &UpdateEnv) -> Result<reqwest::blocking::Client, (String, u8)> {
    // Refuse https→http redirect downgrades: a downgrade would move
    // the bearer token onto a plaintext channel (mirrors
    // mkit-transport-http #223).
    let policy = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            return attempt.error("too many redirects");
        }
        if let Some(prev) = attempt.previous().last()
            && prev.scheme() == "https"
            && attempt.url().scheme() != "https"
        {
            return attempt.error("refusing redirect that downgrades https to a weaker scheme");
        }
        attempt.follow()
    });
    reqwest::blocking::Client::builder()
        .user_agent(format!("mkit/{} (self-update)", env.current_version))
        .redirect(policy)
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .build()
        .map_err(|e| (format!("build http client: {e}"), exit::GENERAL_ERROR))
}

fn get(
    client: &reqwest::blocking::Client,
    env: &UpdateEnv,
    url: &str,
    accept: &str,
    cap: u64,
) -> Result<Vec<u8>, (String, u8)> {
    let mut req = client.get(url).header("Accept", accept);
    // GitHub's API version header is harmless on non-GitHub mirrors.
    req = req.header("X-GitHub-Api-Version", "2022-11-28");
    if let Some(t) = &env.token {
        req = req.header("Authorization", format!("Bearer {t}"));
    }
    let resp = req
        .send()
        .map_err(|e| (format!("GET {url}: {}", error_chain(&e)), exit::TEMPFAIL))?;
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err((
            format!(
                "GET {url}: 404 — release or asset not found (for a private repo, set \
                 GH_TOKEN)"
            ),
            exit::UNAVAILABLE,
        ));
    }
    if !status.is_success() {
        return Err((format!("GET {url}: HTTP {status}"), exit::TEMPFAIL));
    }
    let mut body = Vec::new();
    resp.take(cap + 1)
        .read_to_end(&mut body)
        .map_err(|e| (format!("read {url}: {e}"), exit::TEMPFAIL))?;
    if body.len() as u64 > cap {
        return Err((
            format!("response from {url} exceeds the {cap}-byte cap"),
            exit::DATAERR,
        ));
    }
    Ok(body)
}

/// Render an error with its full `source()` chain — reqwest's Display
/// alone says only "error sending request", hiding the DNS/TLS/socket
/// cause the user actually needs.
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut cur = e.source();
    while let Some(src) = cur {
        out.push_str(": ");
        out.push_str(&src.to_string());
        cur = src.source();
    }
    out
}

fn get_json(
    client: &reqwest::blocking::Client,
    env: &UpdateEnv,
    url: &str,
) -> Result<serde_json::Value, (String, u8)> {
    let body = get(
        client,
        env,
        url,
        "application/vnd.github+json",
        MAX_JSON_BYTES,
    )?;
    serde_json::from_slice(&body).map_err(|e| (format!("parse {url}: {e}"), exit::PROTOCOL_ERROR))
}

fn resolve_latest_tag(
    client: &reqwest::blocking::Client,
    env: &UpdateEnv,
) -> Result<String, (String, u8)> {
    let v = get_json(client, env, &format!("{}/releases/latest", env.api_base))?;
    let tag = v["tag_name"]
        .as_str()
        .ok_or_else(|| {
            (
                "releases/latest has no tag_name".to_owned(),
                exit::PROTOCOL_ERROR,
            )
        })?
        .to_owned();
    validate_tag(&tag).map_err(|e| (format!("latest release: {e}"), exit::PROTOCOL_ERROR))?;
    Ok(tag)
}

fn fetch_release_by_tag(
    client: &reqwest::blocking::Client,
    env: &UpdateEnv,
    tag: &str,
) -> Result<serde_json::Value, (String, u8)> {
    get_json(
        client,
        env,
        &format!("{}/releases/tags/{tag}", env.api_base),
    )
}

/// The API `url` of the named asset (NOT `browser_download_url`): with
/// `Accept: application/octet-stream` it serves the bytes for public
/// AND token-authenticated private repos alike.
fn asset_url(release: &serde_json::Value, name: &str) -> Option<String> {
    release["assets"].as_array()?.iter().find_map(|a| {
        (a["name"].as_str() == Some(name)).then(|| a["url"].as_str().map(str::to_owned))?
    })
}

fn download(
    client: &reqwest::blocking::Client,
    env: &UpdateEnv,
    url: &str,
    cap: u64,
) -> Result<Vec<u8>, (String, u8)> {
    get(client, env, url, "application/octet-stream", cap)
}

// --------------------------------------------------------- verification

fn verify_sha256_sidecar(archive: &[u8], sidecar: &[u8], archive_name: &str) -> Result<(), String> {
    let text =
        core::str::from_utf8(sidecar).map_err(|_| format!("{archive_name}.sha256 is not UTF-8"))?;
    let expected = text
        .split_whitespace()
        .next()
        .ok_or_else(|| format!("{archive_name}.sha256 is empty"))?
        .to_ascii_lowercase();
    let actual = hash::to_hex_bytes(&sha2::Sha256::digest(archive));
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "sha256 mismatch for {archive_name}: sidecar says {expected}, archive is {actual}"
        ))
    }
}

/// Parse the `ed25519:<64-hex>` rotation-set file (crate-embedded copy
/// of `docs/keys/release-attest.pub`).
fn parse_pubkeys(text: &str) -> Result<Vec<[u8; 32]>, String> {
    let mut keys = Vec::new();
    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let hex = line
            .strip_prefix("ed25519:")
            .ok_or_else(|| format!("line {}: expected `ed25519:<64-hex>`", lineno + 1))?;
        keys.push(hash::from_hex(hex).map_err(|_| format!("line {}: bad hex", lineno + 1))?);
    }
    if keys.is_empty() {
        return Err("no keys found".to_owned());
    }
    Ok(keys)
}

/// keyid convention from SPEC-ATTESTATIONS §6.3.
fn keyid_for_pubkey(pubkey: &[u8; 32]) -> String {
    format!(
        "{}{}",
        mkit_attest::KEYID_PREFIX,
        hash::to_hex(&hash::hash(pubkey))
    )
}

/// Verify the release DSSE for ONE downloaded archive: envelope
/// signature against the trust set, release predicate type, predicate
/// tag, and a subject whose name is `archive_name` with the archive's
/// BLAKE3 digest. (A *subset* check — the attestation covers every
/// target's archive; we hold one of them.) Returns the verifying keyid.
pub fn verify_release_attestation(
    dsse_bytes: &[u8],
    trust_keys: &[[u8; 32]],
    tag: &str,
    archive_name: &str,
    archive_bytes: &[u8],
) -> Result<String, String> {
    let mut registry = Registry::new();
    for pk in trust_keys {
        registry.add(keyid_for_pubkey(pk), TrustRoot::Ed25519PubKey(*pk));
    }
    let result = mkit_attest::verify_envelope(dsse_bytes, &registry)
        .map_err(|e| format!("envelope: {e}"))?;
    let Some(verified) = result.signatures.iter().find(|s| s.verified) else {
        return Err(
            "no signature verified against the release-attestation keys embedded in this \
             binary — the release may be signed with a newer (rotated) key; reinstall via \
             install.sh"
                .to_owned(),
        );
    };

    let env = mkit_attest::envelope::decode(dsse_bytes).map_err(|e| format!("envelope: {e}"))?;
    let stmt: serde_json::Value =
        serde_json::from_slice(&env.payload).map_err(|e| format!("statement: {e}"))?;

    if stmt["predicateType"] != PREDICATE_TYPE_RELEASE_V1 {
        return Err(format!(
            "predicateType is {}, expected {PREDICATE_TYPE_RELEASE_V1}",
            stmt["predicateType"]
        ));
    }
    if stmt["predicate"]["tag"] != tag {
        return Err(format!(
            "predicate tag is {}, expected \"{tag}\" — the attestation belongs to a \
             different release",
            stmt["predicate"]["tag"]
        ));
    }

    let digest = hash::to_hex(&hash::hash(archive_bytes));
    let subjects = stmt["subject"]
        .as_array()
        .ok_or_else(|| "statement has no subject array".to_owned())?;
    let matched = subjects.iter().any(|s| {
        s["name"].as_str() == Some(archive_name)
            && s["digest"]["blake3"].as_str() == Some(digest.as_str())
    });
    if !matched {
        return Err(format!(
            "downloaded {archive_name} (blake3 {digest}) does not match any attested subject"
        ));
    }
    Ok(verified.keyid.clone())
}

// ------------------------------------------------------ extract + swap

/// Pull `<stage_dir>/mkit` out of the tar.gz. Only that one entry is
/// ever extracted — no full unpack, so hostile archive members
/// (traversal paths, symlinks, device nodes) are never materialized.
fn extract_binary(archive: &[u8], stage_dir: &str) -> Result<Vec<u8>, String> {
    let want = format!("{stage_dir}/mkit");
    let gz = flate2::read::GzDecoder::new(archive);
    let mut tar = tar::Archive::new(gz);
    let entries = tar.entries().map_err(|e| format!("read archive: {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read archive entry: {e}"))?;
        let path = entry
            .path()
            .map_err(|e| format!("archive entry path: {e}"))?;
        if path.as_os_str() != want.as_str() {
            continue;
        }
        if !entry.header().entry_type().is_file() {
            return Err(format!("archive member {want} is not a regular file"));
        }
        let mut buf = Vec::new();
        entry
            .take(MAX_BINARY_BYTES + 1)
            .read_to_end(&mut buf)
            .map_err(|e| format!("extract {want}: {e}"))?;
        if buf.len() as u64 > MAX_BINARY_BYTES {
            return Err(format!("{want} exceeds the {MAX_BINARY_BYTES}-byte cap"));
        }
        return Ok(buf);
    }
    Err(format!("archive has no {want} member"))
}

/// Refuse group- or world-writable bin dirs (installer parity — see
/// install.sh's rationale: a lax dir lets a local attacker race a
/// replacement binary in between rename and first execution).
#[cfg(unix)]
fn refuse_lax_dir_perms(dir: &Path) -> Result<(), (String, u8)> {
    use std::os::unix::fs::MetadataExt as _;
    let meta = std::fs::metadata(dir)
        .map_err(|e| (format!("stat {}: {e}", dir.display()), exit::NOINPUT))?;
    let mode = meta.mode() & 0o777;
    if mode & 0o020 != 0 {
        return Err((
            format!(
                "install dir {} is group-writable (mode {mode:o}); refusing to update — \
                 tighten permissions: chmod g-w {}",
                dir.display(),
                dir.display()
            ),
            exit::NOPERM,
        ));
    }
    if mode & 0o002 != 0 {
        return Err((
            format!(
                "install dir {} is world-writable (mode {mode:o}); refusing to update — \
                 tighten permissions: chmod o-w {}",
                dir.display(),
                dir.display()
            ),
            exit::NOPERM,
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn refuse_lax_dir_perms(_dir: &Path) -> Result<(), (String, u8)> {
    Ok(())
}

/// Write the new binary to a same-directory temp path (same filesystem
/// ⇒ the final rename is atomic), owner-only perms, exec bit set.
fn stage_binary(bin_dir: &Path, binary: &[u8]) -> Result<PathBuf, (String, u8)> {
    let staged = bin_dir.join(format!(".mkit-self-update.{}", std::process::id()));
    std::fs::write(&staged, binary)
        .map_err(|e| (format!("stage {}: {e}", staged.display()), exit::CANTCREAT))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755)).map_err(|e| {
            let _ = std::fs::remove_file(&staged);
            (format!("chmod {}: {e}", staged.display()), exit::CANTCREAT)
        })?;
    }
    Ok(staged)
}

/// Run the staged binary's `version` and require the byte-exact
/// contract output for the target version — a truncated download or a
/// wrong-tag archive fails here, BEFORE the swap.
fn check_staged_version(staged: &Path, target_bare: &str) -> Result<(), String> {
    let out = std::process::Command::new(staged)
        .arg("version")
        .output()
        .map_err(|e| format!("run staged binary {}: {e}", staged.display()))?;
    let expected = format!("mkit {target_bare}\n");
    let got = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() || got != expected {
        return Err(format!(
            "staged binary self-check failed: `version` printed {:?} (exit {:?}), expected {:?}",
            got,
            out.status.code(),
            expected
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- version ordering ----

    #[test]
    fn cmp_versions_basic() {
        use std::cmp::Ordering::{Equal, Greater, Less};
        assert_eq!(cmp_versions("0.3.0", "0.4.0").unwrap(), Less);
        assert_eq!(cmp_versions("0.4.0", "0.4.0").unwrap(), Equal);
        assert_eq!(cmp_versions("0.10.0", "0.9.9").unwrap(), Greater);
        assert_eq!(cmp_versions("1.0.0-rc.1", "1.0.0").unwrap(), Less);
        assert_eq!(cmp_versions("1.0.0-rc.2", "1.0.0-rc.10").unwrap(), Less);
        assert_eq!(cmp_versions("1.0.0-alpha", "1.0.0-beta").unwrap(), Less);
        // Numeric prerelease segments order below alphanumeric (semver §11.4.3).
        assert_eq!(cmp_versions("1.0.0-1", "1.0.0-alpha").unwrap(), Less);
    }

    #[test]
    fn parse_version_rejects_garbage() {
        for bad in [
            "1.2",
            "1.2.3.4",
            "1.2.x",
            "01a.2.3",
            "1.2.3-",
            "1.2.3-a..b",
            "",
        ] {
            assert!(parse_version(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn validate_tag_matrix() {
        assert!(validate_tag("v0.4.0").is_ok());
        assert!(validate_tag("v1.2.3-rc.1").is_ok());
        assert!(validate_tag("0.4.0").is_err());
        assert!(validate_tag("v1.2").is_err());
    }

    // ---- embedded keys ----

    #[test]
    fn embedded_keys_parse() {
        let keys = parse_pubkeys(RELEASE_ATTEST_PUB).unwrap();
        assert!(!keys.is_empty());
    }

    /// The crate-local copy (packaged for `cargo publish`) must stay
    /// byte-identical to the canonical checked-in rotation set. Skips
    /// when the docs copy isn't present (published-crate builds).
    #[test]
    fn embedded_keys_match_docs_copy() {
        let docs =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../docs/keys/release-attest.pub");
        let Ok(canonical) = std::fs::read_to_string(&docs) else {
            return;
        };
        assert_eq!(
            canonical, RELEASE_ATTEST_PUB,
            "rust/crates/mkit-cli/keys/release-attest.pub is out of sync with \
             docs/keys/release-attest.pub — copy the docs file over the crate copy"
        );
    }

    // ---- receipts ----

    fn tmp_dir(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("mkit-self-update-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn receipt_roundtrip() {
        let d = tmp_dir("receipt");
        let p = d.join("installed-tag");
        write_receipt(&p, "v0.4.0").unwrap();
        assert_eq!(read_receipt(&p).as_deref(), Some("v0.4.0"));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "v0.4.0\n");
    }

    #[test]
    fn read_receipt_missing_or_empty_is_none() {
        let d = tmp_dir("receipt-empty");
        assert_eq!(read_receipt(&d.join("nope")), None);
        std::fs::write(d.join("empty"), "\n").unwrap();
        assert_eq!(read_receipt(&d.join("empty")), None);
    }

    // ---- guidance ----

    #[test]
    fn unmanaged_guidance_recognizes_channels() {
        let brew = unmanaged_guidance(Path::new("/opt/homebrew/Cellar/mkit/0.3.0/bin/mkit"));
        assert!(brew.contains("brew upgrade"), "{brew}");
        let cargo = unmanaged_guidance(Path::new("/home/u/.cargo/bin/mkit"));
        assert!(cargo.contains("cargo install --locked mkit-cli"), "{cargo}");
        let other = unmanaged_guidance(Path::new("/usr/local/bin/mkit"));
        assert!(other.contains("curl mkit.sh"), "{other}");
    }

    // ---- sha256 sidecar ----

    #[test]
    fn sha256_sidecar_matches() {
        let body = b"archive bytes";
        let hex = hash::to_hex_bytes(&sha2::Sha256::digest(body));
        let sidecar = format!("{hex}  mkit-0.4.0-x.tar.gz\n");
        verify_sha256_sidecar(body, sidecar.as_bytes(), "mkit-0.4.0-x.tar.gz").unwrap();
        let e = verify_sha256_sidecar(b"tampered", sidecar.as_bytes(), "mkit-0.4.0-x.tar.gz")
            .unwrap_err();
        assert!(e.contains("sha256 mismatch"), "{e}");
    }

    // ---- extraction ----

    fn tgz_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        for (path, body) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o755);
            h.set_cksum();
            builder.append_data(&mut h, path, *body).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn extract_binary_finds_only_the_binary() {
        let tgz = tgz_with(&[
            ("mkit-0.4.0-x/README.md", b"readme"),
            ("mkit-0.4.0-x/mkit", b"#!/bin/sh\necho hi\n"),
        ]);
        let bin = extract_binary(&tgz, "mkit-0.4.0-x").unwrap();
        assert_eq!(bin, b"#!/bin/sh\necho hi\n");
    }

    #[test]
    fn extract_binary_missing_member_errors() {
        let tgz = tgz_with(&[("mkit-0.4.0-x/README.md", b"readme")]);
        let e = extract_binary(&tgz, "mkit-0.4.0-x").unwrap_err();
        assert!(e.contains("no mkit-0.4.0-x/mkit member"), "{e}");
    }

    // ---- attestation verification (mirrors the release tool's tests
    // from the CONSUMER side) ----

    fn signed_dsse(seed_byte: u8, subjects: &[(&str, &[u8])], tag: &str) -> (Vec<u8>, [u8; 32]) {
        use mkit_attest::{Envelope, PAYLOAD_TYPE_IN_TOTO, Sig, Signer as _, jcs, statement};
        use zeroize::Zeroizing;
        let seed = Zeroizing::new([seed_byte; 32]);
        let pk = mkit_core::sign::KeyPair::from_seed_zeroizing(&seed)
            .public
            .0;
        let predicate = jcs::encode(&jcs::Value::Object(vec![jcs::Member::new(
            "tag",
            jcs::Value::String(tag.to_owned()),
        )]))
        .unwrap();
        let stmt = statement::encode(&statement::Statement {
            subjects: subjects
                .iter()
                .map(|(name, body)| statement::Subject {
                    name: Some((*name).to_owned()),
                    digest_blake3_hex: hash::to_hex(&hash::hash(body)),
                })
                .collect(),
            predicate_type: PREDICATE_TYPE_RELEASE_V1.to_owned(),
            predicate_jcs: predicate.as_bytes(),
        })
        .unwrap()
        .into_bytes();
        let mut signer = mkit_attest::signer_repo_key::RepoKeySigner::from_seed_zeroizing(&seed);
        let pae = mkit_attest::pae_of(PAYLOAD_TYPE_IN_TOTO, &stmt);
        let sig = signer.sign(&pae).unwrap();
        let dsse = Envelope {
            payload_type: PAYLOAD_TYPE_IN_TOTO.to_owned(),
            payload: stmt,
            signatures: vec![Sig {
                keyid: signer.keyid_string(),
                sig,
            }],
        }
        .encode()
        .unwrap()
        .into_bytes();
        (dsse, pk)
    }

    #[test]
    fn attestation_subset_check_passes_for_one_archive() {
        let a = b"archive-a".as_slice();
        let b = b"archive-b".as_slice();
        let (dsse, pk) = signed_dsse(7, &[("a.tar.gz", a), ("b.tar.gz", b)], "v0.4.0");
        // Holding only archive b (the updater's situation) verifies.
        verify_release_attestation(&dsse, &[pk], "v0.4.0", "b.tar.gz", b).unwrap();
    }

    #[test]
    fn attestation_rejects_wrong_key_tag_and_digest() {
        let a = b"archive-a".as_slice();
        let (dsse, pk) = signed_dsse(7, &[("a.tar.gz", a)], "v0.4.0");
        let other =
            mkit_core::sign::KeyPair::from_seed_zeroizing(&zeroize::Zeroizing::new([9u8; 32]))
                .public
                .0;
        let e = verify_release_attestation(&dsse, &[other], "v0.4.0", "a.tar.gz", a).unwrap_err();
        assert!(e.contains("no signature verified"), "{e}");
        let e = verify_release_attestation(&dsse, &[pk], "v0.4.1", "a.tar.gz", a).unwrap_err();
        assert!(e.contains("different release"), "{e}");
        let e = verify_release_attestation(&dsse, &[pk], "v0.4.0", "a.tar.gz", b"tampered")
            .unwrap_err();
        assert!(e.contains("does not match any attested subject"), "{e}");
        let e = verify_release_attestation(&dsse, &[pk], "v0.4.0", "b.tar.gz", a).unwrap_err();
        assert!(e.contains("does not match any attested subject"), "{e}");
    }

    // ---- staged-binary check + perms (unix) ----

    #[cfg(unix)]
    #[test]
    fn staged_version_check_enforces_contract() {
        let d = tmp_dir("staged");
        let ok = stage_binary(&d, b"#!/bin/sh\nprintf 'mkit 9.9.9\\n'\n").unwrap();
        check_staged_version(&ok, "9.9.9").unwrap();
        let e = check_staged_version(&ok, "9.9.8").unwrap_err();
        assert!(e.contains("self-check failed"), "{e}");
    }

    #[cfg(unix)]
    #[test]
    fn lax_dir_perms_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = tmp_dir("perms");
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o777)).unwrap();
        let (msg, code) = refuse_lax_dir_perms(&d).unwrap_err();
        assert_eq!(code, exit::NOPERM);
        assert!(msg.contains("writable"), "{msg}");
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        refuse_lax_dir_perms(&d).unwrap();
    }
}
