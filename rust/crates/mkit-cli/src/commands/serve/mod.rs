//! `mkit serve <path>` — the `mkit+ssh://` forced-command server: the
//! `mkit.rpc.v1.ssh` frame protocol (SPEC-TRANSPORT §4.2) on stdin/stdout
//! against a local repository.
//!
//! The engine is `mkit-server`'s: [`mkit_server::ssh::serve_session`] over
//! the pipeline, with the `.mkit` layout stores (`FsBlobStore` for
//! `<root>/packs/`, `FsLayoutStore` for `<root>/refs/`), so the files are
//! the ones `FileTransport`, `mkit+file://` remotes and `mkit-server
//! --repo-root` read and write. It runs under a blocking executor
//! (`futures::executor::block_on`): the CLI builds no async runtime, and
//! the stores do blocking I/O inside their futures. A reader thread feeds
//! stdin frames to the session and enforces the idle timeout
//! (`--idle-timeout-secs`, `stdio.rs`).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use mkit_core::repo_identity::RepositoryIdentity;
use mkit_core::repo_lock::{self, LockError, RepoLock};
use mkit_rpc::mkit::rpc::v1::ErrorCode;
use mkit_server::fs::{FsBlobStore, FsLayoutStore};
use mkit_server::pipeline::{AuthMode, Hooks, Pipeline, PipelineConfig};
use mkit_server::policy::WritePolicy;
use mkit_server::ssh::{SessionConfig, SessionEnd, WriteFrames, serve_session, upload_limits};
use mkit_server::{
    Addressing, NamespaceKey, NoopMetrics, Principal, RepoId, RepoName, SystemClock,
};

use crate::clap_shim;
use crate::cli::CLI_VERSION;
use crate::exit;

mod stdio;

use stdio::StdioFrameSource;

/// The default of `--idle-timeout-secs` (planner decision Q12).
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 60;

/// The largest `--idle-timeout-secs` and `--max-session-secs`: 7 days.
const MAX_TIMEOUT_SECS: u64 = 7 * 24 * 60 * 60;

#[derive(Debug, Parser)]
#[command(
    name = "mkit serve",
    about = "Speak the mkit-rpc SSH-frame protocol on stdin/stdout (the \
             mkit+ssh:// forced-command server). The HTTP and mkit+enc:// \
             listeners are the separate `mkit-server` binary."
)]
struct ServeOpts {
    /// Path to the repository to serve. Under `--root` it is the
    /// `<NAMESPACE>/<NAME>` the session binds; when it is omitted there,
    /// `SSH_ORIGINAL_COMMAND` supplies it.
    path: Option<String>,
    /// Serve the repositories under DIR: the path names one
    /// `<NAMESPACE>/<NAME>`, resolved to the directory
    /// `<DIR>/<NAMESPACE>/<NAME>`, and only the namespace's owner may
    /// write (SPEC-TRANSPORT §4 root mode).
    #[arg(long, value_name = "DIR")]
    root: Option<PathBuf>,
    /// The Ed25519 public key the sshd forced-command configuration
    /// asserts for this session: 64 lowercase hex characters (the raw
    /// 32-byte key, no prefix). It is a trust assertion — sshd attaches it
    /// to the key it already verified — and is never read from the
    /// environment or `SSH_ORIGINAL_COMMAND`.
    #[arg(long, value_name = "HEX", value_parser = parse_principal)]
    principal: Option<[u8; 32]>,
    /// End the session after this many seconds without a byte from the
    /// client; 0 disables the timeout (at most 604800, 7 days). A slow
    /// upload that keeps sending never trips it.
    #[arg(
        long,
        value_name = "SECS",
        default_value_t = DEFAULT_IDLE_TIMEOUT_SECS,
        value_parser = clap::value_parser!(u64).range(..=MAX_TIMEOUT_SECS)
    )]
    idle_timeout_secs: u64,
    /// End the process this many seconds after it starts, whatever the
    /// client is doing; 0 (the default) disables the cap (at most 604800,
    /// 7 days). It also bounds a client that trickles bytes or stops
    /// reading, which the idle timeout does not.
    #[arg(
        long,
        value_name = "SECS",
        default_value_t = 0,
        value_parser = clap::value_parser!(u64).range(..=MAX_TIMEOUT_SECS)
    )]
    max_session_secs: u64,
}

/// The listener flags `mkit serve` used to take, removed when the HTTP
/// (`--http`) and encrypted (`--listen-enc`) listeners moved to the
/// `mkit-server` binary. Clap rejects them as unknown arguments;
/// [`run`] then adds a pointer to `mkit-server`.
const REMOVED_LISTENER_FLAGS: &[&str] = &[
    "--http",
    "--http-token",
    "--unsafe-allow-any-http-peer",
    "--listen-enc",
    "--enc-authorized-peers",
    "--enc-server-key",
    "--unsafe-allow-any-enc-peer",
    "--enc-idle-timeout-secs",
    "--enc-handshake-timeout-secs",
];

/// The first removed listener flag in `args` (as `--flag` or
/// `--flag=value`), stopping at a `--` separator.
fn removed_listener_flag(args: &[String]) -> Option<&'static str> {
    args.iter()
        .take_while(|a| a.as_str() != "--")
        .find_map(|a| {
            let name = a.split_once('=').map_or(a.as_str(), |(n, _)| n);
            REMOVED_LISTENER_FLAGS.iter().copied().find(|f| *f == name)
        })
}

/// The repository identity `mkit serve` serves its root as: `mkit-server`'s
/// default `--repository`, so both address one root's refs alike.
const REPOSITORY: &str = "default";

/// `--principal`'s value: exactly the raw 32-byte Ed25519 public key as
/// 64 lowercase hex characters — no `ed25519-` prefix, no `0x`, nothing
/// else. Clap maps a refusal to USAGE before any frame is read.
fn parse_principal(text: &str) -> Result<[u8; 32], String> {
    let bad =
        || "expected 64 lowercase hex characters (a raw 32-byte Ed25519 public key)".to_owned();
    let hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
    if text.len() != 64 || !text.bytes().all(&hex) {
        return Err(bad());
    }
    let mut out = [0u8; 32];
    let nibble = |b: u8| {
        if b.is_ascii_digit() {
            b - b'0'
        } else {
            b - b'a' + 10
        }
    };
    for (byte, pair) in out.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *byte = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    Ok(out)
}

/// The repository path an `SSH_ORIGINAL_COMMAND` of exactly
/// `mkit serve <path>` carries (SPEC-TRANSPORT §4's forced-command form):
/// every byte is `[A-Za-z0-9._/-]` or a single space, the command splits
/// on single spaces into exactly `["mkit", "serve", path]`, and `path`
/// does not start with `-` (so no flag can be smuggled). Any other form —
/// extra arguments, `sh -c`, quotes, tabs or doubled spaces, NUL, CR/LF,
/// `;`, `$` — is refused.
fn parse_original_command(command: &str) -> Option<&str> {
    let ok_byte =
        |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-' | b' ');
    if !command.bytes().all(ok_byte) {
        return None;
    }
    let mut parts = command.split(' ');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("mkit"), Some("serve"), Some(path), None)
            if !path.is_empty() && !path.starts_with('-') =>
        {
            Some(path)
        }
        _ => None,
    }
}

/// The identity `path` names in root mode, validated and resolved under
/// `root`: `<NAMESPACE>/<NAME>` in the §7.4 grammar (a bare name, an
/// uppercase byte, `..` or another component is refused), then the
/// canonical `<ROOT>/<NAMESPACE>/<NAME>` must be that path exactly — a
/// surviving symlink component would serve one repository under
/// another's identity, which the owner check would then attribute
/// wrongly. `MKIT_SERVE_ROOT` pins the result like plain mode.
fn resolve_root_repo(root: &Path, path: &str) -> Result<(PathBuf, RepoId), u8> {
    let trimmed = path.trim_matches('/');
    let identity = RepositoryIdentity::parse(trimmed).map_err(|_| exit::USAGE)?;
    let Some(namespace) = identity.namespace() else {
        return Err(exit::USAGE);
    };
    let root = std::fs::canonicalize(root).map_err(|_| exit::NOINPUT)?;
    let expected = root.join(namespace.to_string()).join(identity.name());
    let resolved = std::fs::canonicalize(&expected).map_err(|_| exit::NOINPUT)?;
    if resolved != expected {
        return Err(exit::NOPERM);
    }
    if !resolved.is_dir() || !resolved.join(".mkit").is_dir() {
        return Err(exit::DATAERR);
    }
    if let Ok(pinned) = std::env::var("MKIT_SERVE_ROOT") {
        let pinned = std::fs::canonicalize(&pinned).map_err(|_| exit::NOPERM)?;
        if !resolved.starts_with(&pinned) {
            return Err(exit::NOPERM);
        }
    }
    Ok((
        resolved,
        RepoId {
            namespace: NamespaceKey::from_namespace(namespace),
            name: RepoName::new(identity.name()).map_err(|_| exit::USAGE)?,
        },
    ))
}

/// How old an upload's temp file must be before the startup sweep removes
/// it. A live upload rewrites its temp file continuously; see
/// [`sweep_crashed_uploads`].
const STALE_UPLOAD_AGE: Duration = Duration::from_hours(1);

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<ServeOpts>("mkit serve", args) {
        Ok(o) => o,
        Err(code) => {
            if let Some(flag) = removed_listener_flag(args) {
                eprintln!(
                    "hint: `mkit serve` no longer takes `{flag}`; it only speaks the ssh-frame \
                     protocol on stdin/stdout.\n\
                     \x20     Use SSH (`mkit serve`) or a Connect server such as vcs-worker.\n\
                     \x20     The mkit+enc:// transport is deprecated: no maintained server."
                );
            }
            return code;
        }
    };

    let principal = Principal::SshForcedCommand {
        key: opts.principal,
    };
    let target = match &opts.root {
        // Plain mode, unchanged: one repository directory, open writes.
        None => {
            let Some(path) = &opts.path else {
                eprintln!(
                    "error: the following required arguments were not provided:\n  <PATH>\n\n\
                     Usage: mkit serve <PATH>\n\n\
                     For more information, try '--help'."
                );
                return exit::USAGE;
            };
            match resolve_repo_path(path) {
                Ok(root) => ServeTarget {
                    root,
                    repo: repo_id(),
                    write_policy: WritePolicy::Open,
                    principal,
                },
                Err(code) => return code,
            }
        }
        // Root mode: the path (or `SSH_ORIGINAL_COMMAND`) names the one
        // `<NAMESPACE>/<NAME>` this process serves under `--root`.
        Some(root) => {
            let path = match &opts.path {
                Some(path) => Some(path.clone()),
                None => std::env::var("SSH_ORIGINAL_COMMAND")
                    .ok()
                    .and_then(|command| parse_original_command(&command).map(str::to_owned)),
            };
            let Some(path) = path else {
                eprintln!(
                    "mkit serve: --root serves <NAMESPACE>/<NAME>, from the path or \
                     `SSH_ORIGINAL_COMMAND` `mkit serve <NAMESPACE>/<NAME>`"
                );
                return exit::USAGE;
            };
            match resolve_root_repo(root, &path) {
                Ok((root, repo)) => ServeTarget {
                    root,
                    repo,
                    write_policy: WritePolicy::Owner,
                    principal,
                },
                Err(code) => return code,
            }
        }
    };

    // Held for the whole lifetime of this `serve` process
    // (SPEC-CONCURRENCY §3.1, MKIT-11/#655): local
    // worktree-mutating commands and `gc` probe this same lock (see
    // `commands::warn_if_served`) to detect a live `serve` and warn.
    // SHARED, not exclusive — SPEC-TRANSPORT documents multiple
    // concurrent `serve` processes against one root (e.g. one per SSH
    // forced-command connection) as a supported deployment, so `serve`
    // instances must not exclude each other.
    let _serve_guard = match lock_and_sweep(&target.root) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("mkit serve: serve lock: {e}");
            return exit::TEMPFAIL;
        }
    };

    if opts.max_session_secs > 0 {
        spawn_session_cap(Duration::from_secs(opts.max_session_secs));
    }

    // Test-only fault injection for the mkit#703 SSH retry regression
    // test (`tests/ssh_retry_e2e.rs`): end right after a successful
    // `Hello`/`HelloResponse`, before answering any verb, so the process
    // exits and the child pipe closes — simulating a mid-session
    // connection drop that the client's `SshTransport` retry/reconnect
    // path (SPEC-TRANSPORT §7) must recover from. Never set in
    // production.
    let stop_after_hello = std::env::var_os("MKIT_SERVE_TEST_DIE_AFTER_HELLO").is_some();
    let idle = (opts.idle_timeout_secs > 0).then(|| Duration::from_secs(opts.idle_timeout_secs));
    // `Stdin`/`Stdout`, not their locks: the reader thread needs `Send`,
    // and each call locks. `WriteFrames` flushes after every frame.
    serve_stdio(
        &target,
        std::io::stdin(),
        std::io::stdout(),
        idle,
        stop_after_hello,
    )
}

/// Resolve and validate the on-disk path supplied to `mkit serve`.
pub(crate) fn resolve_repo_path(path: &str) -> Result<PathBuf, u8> {
    let resolved = std::fs::canonicalize(path).map_err(|_| exit::NOINPUT)?;
    if !resolved.is_dir() {
        return Err(exit::DATAERR);
    }
    if !resolved.join(".mkit").is_dir() {
        return Err(exit::DATAERR);
    }
    if let Ok(root) = std::env::var("MKIT_SERVE_ROOT") {
        let pinned = std::fs::canonicalize(&root).map_err(|_| exit::NOPERM)?;
        if !resolved.starts_with(&pinned) {
            return Err(exit::NOPERM);
        }
    }
    Ok(resolved)
}

/// Take the shared `serve.lock` for this process's lifetime, first
/// sweeping crashed uploads when no other server holds it.
///
/// The sweep runs only while this process holds `serve.lock`
/// EXCLUSIVELY, taken without waiting: every `mkit serve` and
/// `mkit-server` holds it shared for its whole life, so while it is held
/// exclusively no streaming upload of theirs can be in flight, and a busy
/// lock (another server is up) skips the sweep. `FileTransport` writers
/// (`mkit push` to a `mkit+file://` remote) take no such lock, but write
/// each temp file in one go, so the age bound keeps theirs safe. The
/// exclusive hold is then released and the shared one taken, as before.
fn lock_and_sweep(repo_root: &Path) -> Result<RepoLock, LockError> {
    let dot_mkit = repo_root.join(".mkit");
    if let Ok(exclusive) =
        repo_lock::acquire(&dot_mkit, crate::commands::SERVE_LOCK, Duration::ZERO)
    {
        sweep_crashed_uploads(repo_root);
        drop(exclusive);
    }
    repo_lock::acquire_shared(
        &dot_mkit,
        crate::commands::SERVE_LOCK,
        repo_lock::DEFAULT_TIMEOUT,
    )
}

/// Remove the temp files (`packs/.<hex>.tmp.<pid>.<seq>`) that uploads
/// left when their process crashed, once they are [`STALE_UPLOAD_AGE`]
/// old. Best effort: a failure is ignored, and the next start retries.
fn sweep_crashed_uploads(repo_root: &Path) {
    let _ = FsBlobStore::new(repo_root).sweep_stale_uploads(STALE_UPLOAD_AGE);
}

/// `--max-session-secs`: a thread that ends the process once `max` has
/// passed. It must work while the main thread is blocked in a write to a
/// client that stopped reading, so it ends the process rather than
/// signalling the session. That is safe at any point: an upload's temp
/// file is never visible (and is swept later), every ref write is one
/// atomic rename, and the kernel releases the ref and serve locks.
fn spawn_session_cap(max: Duration) {
    let spawned = std::thread::Builder::new()
        .name("mkit-serve-session-cap".to_owned())
        .spawn(move || {
            std::thread::sleep(max);
            eprintln!(
                "mkit serve: session exceeded --max-session-secs {}; closing",
                max.as_secs()
            );
            std::process::exit(i32::from(exit::PROTOCOL_ERROR));
        });
    if let Err(e) = spawned {
        eprintln!("mkit serve: --max-session-secs is not enforced: {e}");
    }
}

/// The repository `mkit serve` serves in plain mode (see [`REPOSITORY`]).
fn repo_id() -> RepoId {
    RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new(REPOSITORY).unwrap_or_else(|_| unreachable!("a valid repo name")),
    }
}

/// What `serve_stdio` serves and as whom.
pub(crate) struct ServeTarget {
    /// The repository's canonical on-disk root.
    pub root: PathBuf,
    /// Its storage identity: `default` in the reserved `root` namespace
    /// in plain mode; the path's `<NAMESPACE>/<NAME>` in root mode.
    pub repo: RepoId,
    /// `Open` in plain mode, `Owner` in root mode.
    pub write_policy: WritePolicy,
    /// The session's principal; `key` only from `--principal`.
    pub principal: Principal,
}

/// Serve one ssh-frame session over `input` and `output` against
/// `target`, returning the exit code: [`exit::OK`] for a clean end or
/// a failed write (the client went away), [`exit::PROTOCOL_ERROR`] for a
/// protocol error or an idle timeout. `idle` bounds the time without a byte
/// from the client (`None` disables it); a timeout is answered, best
/// effort, with `Error{INVALID_REQUEST, "idle timeout"}`.
///
/// The ref store is opened with [`FsLayoutStore::open`], which refuses a
/// root whose refs live in `mkit-server`'s `SQLite` database.
pub(crate) fn serve_stdio<R, W>(
    target: &ServeTarget,
    input: R,
    output: W,
    idle: Option<Duration>,
    stop_after_hello: bool,
) -> u8
where
    R: Read + Send + 'static,
    W: Write + Send,
{
    let meta = match FsLayoutStore::open(&target.root, &target.repo) {
        Ok(meta) => meta,
        Err(e) => {
            eprintln!("mkit serve: {e}");
            return exit::CONFIG_ERROR;
        }
    };
    let mut cfg = PipelineConfig::new(
        Addressing::Single {
            repo: target.repo.clone(),
        },
        AuthMode::TransportIdentity,
        upload_limits(),
    );
    cfg.write_policy = target.write_policy;
    let pipeline = match Pipeline::new(
        FsBlobStore::new(&target.root),
        meta,
        Hooks::new(),
        cfg,
        Arc::new(SystemClock),
        Arc::new(NoopMetrics),
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("mkit serve: {}", e.public_message());
            return exit::SOFTWARE;
        }
    };
    let mut src = match StdioFrameSource::spawn(input, idle) {
        Ok(src) => src,
        Err(e) => {
            eprintln!("mkit serve: stdin reader: {e}");
            return exit::SOFTWARE;
        }
    };
    let mut sink = WriteFrames(output);
    let mut session = SessionConfig::new(format!("mkit serve/{CLI_VERSION}"));
    session.stop_after_hello = stop_after_hello;
    let end = futures::executor::block_on(serve_session(
        &pipeline,
        target.principal.clone(),
        &mut src,
        &mut sink,
        &session,
    ));
    // The reader thread may still be blocked on stdin; the process exits
    // under it.
    match end {
        SessionEnd::Clean | SessionEnd::IoError => exit::OK,
        SessionEnd::ProtocolError => exit::PROTOCOL_ERROR,
        SessionEnd::Timeout => {
            let frame = mkit_rpc::ssh_error_frame(ErrorCode::InvalidRequest, "idle timeout");
            let _ = mkit_rpc::write_frame(&mut sink.0, &frame);
            let _ = sink.0.flush();
            exit::PROTOCOL_ERROR
        }
    }
}

#[cfg(test)]
mod tests;
