//! URL-scheme → `Transport` dispatch for `mkit push` / `mkit pull`.
//!
//! The Rust binary wires all five shipping schemes here: `mkit+file://`,
//! `mkit+https://` (and `mkit+http://` for local dev), `mkit+s3://`, and
//! `mkit+ssh://`. The memory transport is in-process only, so it is
//! reached via [`push_all`] / [`pull_all`] with an `Arc<MemoryTransport>`
//! constructed in-process rather than URL-based construction. Integration
//! tests in the `mkit-cli` crate exercise the memory path directly.
//!
//! Credentials / environment sources:
//! - HTTP(S): optional `MKIT_API_TOKEN` bearer.
//! - S3/R2: `MKIT_R2_ACCESS_KEY_ID` + `MKIT_R2_SECRET_ACCESS_KEY` (plus
//!   optional `MKIT_R2_REGION`, default `auto`). Missing creds do NOT
//!   fail at connect time; the first signed request returns
//!   `TransportError::AccessDenied`.
//! - SSH: spawns `ssh(1)` subprocess — inherits the user's agent / keys /
//!   `~/.ssh/config`. Per-repo `.mkit/config` SSH options (host-key
//!   checking, known-hosts path, identity file) are wired through via
//!   `SshTransport::connect_with_options` when config is loaded.

use std::path::Path;
use std::sync::Arc;

use mkit_core::hash::Hash;
use mkit_core::object::Object;
use mkit_core::ops::merge::is_ancestor;
use mkit_core::ops::restore;
use mkit_core::pack::{self, PackError, PackReader, PackWriter};
use mkit_core::protocol::{PackKey, Transport, TransportError};
use mkit_core::refs::{self, Head};
use mkit_core::store::{ObjectStore, StoreError};
use mkit_core::transfer::{self, PackListError};
use mkit_transport_file::FileTransport;
use mkit_transport_http::HttpTransport;
use mkit_transport_s3::S3Transport;
use mkit_transport_ssh::{SshInitError, SshTransport};

const DEFAULT_REMOTE: &str = "default";

/// Errors returned by the push / pull helpers. Mapped to exit codes by
/// the commands themselves.
#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    #[error("unsupported URL scheme: {0}")]
    UnsupportedScheme(String),
    #[error("malformed URL: {0}")]
    MalformedUrl(String),
    #[error("no HEAD branch to push")]
    NoHead,
    /// A poll-loop checkpoint observed `signal::is_shutdown() == true`
    /// and aborted partway through. Callers should map this to
    /// `exit::TEMPFAIL` (75) so retries are safe — the transfer is
    /// half-finished but the remote is unmodified for any ref we
    /// hadn't reached yet.
    #[error("interrupted")]
    Interrupted,
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    #[error("refs: {0}")]
    Refs(#[from] refs::RefError),
    #[error("repo lock: {0}")]
    RepoLock(#[from] mkit_core::repo_lock::LockError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("pack: {0}")]
    Pack(#[from] PackError),
    #[error("packlist: {0}")]
    PackList(#[from] PackListError),
    #[error("ssh init: {0}")]
    SshInit(#[from] SshInitError),
    #[error("pull requires HEAD to point at a branch")]
    DetachedHead,
    #[error("remote branch '{0}' not found")]
    RemoteBranchMissing(String),
    #[error("pull would not fast-forward branch '{branch}'; merge or rebase first")]
    NonFastForwardPull { branch: String },
    #[error("restore safety: {0}")]
    RestoreSafety(String),
    #[error("object is not a commit")]
    NotCommit,
    #[error("restore: {0}")]
    Restore(#[from] restore::RestoreError),
    /// The per-endpoint credential-trust gate (#97) refused to build a
    /// credential-bearing transport for a repo-chosen endpoint the user
    /// has not explicitly trusted. The wrapped string is the actionable
    /// message produced by [`crate::config::endpoint_credential_trust`].
    #[error("{0}")]
    UntrustedRemote(String),
    /// A CAS ref write was rejected because the remote moved under us
    /// (non-fast-forward). Callers map this to an actionable
    /// fetch-then-retry / `--force-with-lease` hint.
    #[error(
        "updates were rejected for branch '{branch}' (non-fast-forward); fetch and merge first, or re-run with --force-with-lease / --force"
    )]
    NonFastForwardPush { branch: String },
}

/// Open a transport for `endpoint` only after the per-endpoint
/// credential-trust gate (#97) approves it.
///
/// This is the single choke point through which push / fetch / pull
/// (and named-remote callers in #175) MUST build a transport: it runs
/// [`crate::config::endpoint_credential_trust`] — keyed on the resolved
/// ENDPOINT and its `repo_chosen` provenance — *before* constructing
/// the transport, so a credential-bearing HTTP/S3 transport is never
/// instantiated for a repo-chosen endpoint the user hasn't trusted.
///
/// `repo_chosen` is `true` when the endpoint came from repo-scoped
/// config (the flat `remote_endpoint` or a `remote.<name>.url`),
/// `false` when it came from the user / an explicit CLI argument. Trust
/// is per ENDPOINT, never per remote name.
pub fn open_trusted(
    endpoint: &str,
    repo_chosen: bool,
    cfg: &crate::config::LayeredConfig,
) -> Result<Arc<dyn Transport>, DispatchError> {
    crate::config::endpoint_credential_trust(cfg, endpoint, repo_chosen)
        .map_err(DispatchError::UntrustedRemote)?;
    open(endpoint)
}

/// Open a transport for the given URL. Returns a type-erased `Arc`
/// so callers can treat all schemes uniformly.
///
/// Low-level scheme dispatch only — it does NOT enforce the credential
/// gate. Production push / fetch / pull paths go through
/// [`open_trusted`]; `open` stays public for file/memory integration
/// tests that have no ambient credentials to fence.
pub fn open(url: &str) -> Result<Arc<dyn Transport>, DispatchError> {
    if url.starts_with("git+") {
        return Err(DispatchError::UnsupportedScheme(format!(
            "'{url}' is a git-bridge remote — native push/pull/fetch/clone do not \
             speak git transports; use `mkit git export` / `mkit git import` / \
             `mkit git pull` (feature git-bridge)"
        )));
    }
    if let Some(rest) = url.strip_prefix("mkit+file://") {
        // mkit+file:///abs/path -> /abs/path
        let path = Path::new(rest);
        return Ok(Arc::new(FileTransport::new(path)));
    }
    if url.starts_with("mkit+memory://") {
        // Memory transport is in-process; the URL-based path is not
        // useful on its own but we accept it so `mkit remote add`
        // round-trips cleanly.
        return Err(DispatchError::UnsupportedScheme(
            "mkit+memory:// must be driven via in-process harness (see tests)".to_string(),
        ));
    }
    if url.starts_with("mkit+https://") || url.starts_with("mkit+http://") {
        // HttpTransport::connect strips the `mkit+` prefix itself and
        // reads MKIT_API_TOKEN from the environment.
        let tx = HttpTransport::connect(url)?;
        return Ok(Arc::new(tx));
    }
    if url.starts_with("mkit+s3://") {
        // S3Transport::connect reads MKIT_R2_ACCESS_KEY_ID /
        // MKIT_R2_SECRET_ACCESS_KEY from the environment. Missing
        // credentials surface as AccessDenied on the first signed call,
        // not at connect time.
        let tx = S3Transport::connect(url)?;
        return Ok(Arc::new(tx));
    }
    if url.starts_with("mkit+ssh://") {
        // SshTransport::connect parses the URL, spawns `ssh(1)`, and
        // performs the `Hello` / `HelloResponse` handshake. Any failure
        // here tears the child down before returning, so callers never
        // see a half-initialised transport.
        let tx = SshTransport::connect(url)?;
        return Ok(Arc::new(tx));
    }
    #[cfg(feature = "enc-transport")]
    if url.starts_with("mkit+enc://") {
        return open_enc(url);
    }
    Err(DispatchError::MalformedUrl(url.to_string()))
}

/// `mkit+enc://` dispatch (Phase 2 of issue #156).
///
/// Parses the URL, derives an ephemeral dialer keypair (keystore
/// integration is SPEC-TRANSPORT-ENC §6 item 5, still deferred), and
/// runs the encrypted-stream handshake against the URL-advertised
/// server public key.
///
/// Client identity (issue #178): an allowlisting server pins the
/// dialer's static ed25519 key. To survive across restarts the client
/// can supply a STABLE raw-32 key file via the `MKIT_ENC_CLIENT_KEY`
/// environment variable (a user-scoped / CLI-supplied path — never
/// repo-local `.mkit/config`, which `open_enc` has no access to anyway).
/// When the variable is unset we fall back to a fresh ephemeral key per
/// process, which still works against `--unsafe-allow-any-enc-peer`
/// servers.
#[cfg(feature = "enc-transport")]
const ENC_CLIENT_KEY_ENV: &str = "MKIT_ENC_CLIENT_KEY";

#[cfg(feature = "enc-transport")]
fn open_enc(url: &str) -> Result<Arc<dyn Transport>, DispatchError> {
    use mkit_transport_enc::url::parse_enc_url;

    let target = parse_enc_url(url).map_err(DispatchError::Transport)?;
    let sk = load_or_ephemeral_client_key()?;
    let tx = mkit_transport_enc::connect_tcp(&target.host, target.port, &target.server_pubkey, sk)
        .map_err(|e| DispatchError::Transport(TransportError::RemoteError(e.to_string())))?;
    Ok(Arc::new(tx))
}

/// Resolve the dialer's static signing key.
///
/// If `MKIT_ENC_CLIENT_KEY` points at a raw 32-byte key file, load it
/// (with the standard `load_raw_32` 0600/owner hardening) so the
/// client's public key is stable — letting an allowlisting server pin
/// it across restarts. Otherwise draw a fresh ephemeral key from the
/// system RNG (≥256 bits) for back-compat with allow-any servers.
#[cfg(feature = "enc-transport")]
fn load_or_ephemeral_client_key()
-> Result<commonware_cryptography::ed25519::PrivateKey, DispatchError> {
    use commonware_codec::DecodeExt as _;
    use commonware_cryptography::ed25519::PrivateKey;
    use zeroize::Zeroizing;

    let map_err = |e: String| DispatchError::Transport(TransportError::RemoteError(e));

    if let Some(path) = std::env::var_os(ENC_CLIENT_KEY_ENV).filter(|s| !s.is_empty()) {
        let seed = mkit_core::sign::load_raw_32(std::path::Path::new(&path))
            .map_err(|e| map_err(format!("load {ENC_CLIENT_KEY_ENV}: {e}")))?;
        return PrivateKey::decode(seed.as_ref())
            .map_err(|e| map_err(format!("client key construction failed: {e}")));
    }

    // Ephemeral fallback. Draw 32 bytes from `getrandom`, wrapped in
    // `Zeroizing` so the stack copy is scrubbed on drop; the resulting
    // `PrivateKey` carries its own `Secret`-based zeroization.
    let mut secret = Zeroizing::new([0u8; 32]);
    getrandom::fill(secret.as_mut()).map_err(|e| map_err(e.to_string()))?;
    PrivateKey::decode(secret.as_ref()).map_err(|e| map_err(e.to_string()))
}

/// Push every ref under `refs/heads/` to the remote. Returns the count of
/// refs pushed. Each branch is published with [`push_branch`], which sends
/// one delta-compressed pack of the objects the remote lacks, advertises it
/// via the `refs/mkit/packmap/<branch>` ref, then moves the branch ref.
pub fn push_all(cwd: &Path, tx: &dyn Transport) -> Result<usize, DispatchError> {
    push_all_with(cwd, tx, None, false)
}

/// CAS-aware mirror push (`mkit push --all`). Pushes every local
/// `refs/heads/*` to the remote, using the remote-tracking ref under
/// `refs/remotes/<remote>/<branch>` as the CAS lease (Missing when no
/// tracking ref exists, Match otherwise). `force` upgrades every write
/// to an unconditional `Any`. On success each pushed branch's
/// remote-tracking ref is advanced to the pushed tip.
///
/// `remote` is the remote NAME used for the local tracking-ref
/// namespace; `None` means the legacy `default`.
pub fn push_all_with(
    cwd: &Path,
    tx: &dyn Transport,
    remote: Option<&str>,
    force: bool,
) -> Result<usize, DispatchError> {
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);
    let store = crate::commands::open_store_configured(cwd)?;
    let refs_list = refs::list_refs(&mkit_dir)?;
    let remote = remote.unwrap_or(DEFAULT_REMOTE);
    let mut n = 0;
    for r in refs_list {
        if crate::signal::is_shutdown() {
            return Err(DispatchError::Interrupted);
        }
        let Some(h) = r.hash else { continue };
        let condition = if force {
            refs::RefWriteCondition::Any
        } else {
            match refs::read_remote_ref(&mkit_dir, remote, &r.name)? {
                Some(tracked) => refs::RefWriteCondition::Match(tracked),
                None => refs::RefWriteCondition::Missing,
            }
        };
        push_branch(tx, &store, &r.name, h, condition)?;
        refs::write_remote_ref(&mkit_dir, remote, &r.name, &h)?;
        n += 1;
    }
    Ok(n)
}

/// CAS lease policy for a default (current-branch → upstream) push.
#[derive(Debug, Clone, Copy)]
pub enum PushLease {
    /// Force — unconditional `Any`.
    Force,
    /// `--force-with-lease` — require the remote tip to equal the local
    /// remote-tracking ref (Match), or Missing when there is none.
    /// Identical mechanism to the default safe push; semantically it is
    /// the explicit, opt-in form that overwrites a fast-forward-failing
    /// branch *only* if the remote hasn't moved past what we last saw.
    WithLease,
    /// Default safe push: Match the local remote-tracking ref, or
    /// Missing when absent (first push of this branch).
    FastForward,
}

/// Resolve the CAS condition for a single-branch push from the local
/// remote-tracking ref `refs/remotes/<remote>/<branch>` and the lease
/// policy.
pub fn lease_condition(
    cwd: &Path,
    remote: &str,
    branch: &str,
    lease: PushLease,
) -> Result<refs::RefWriteCondition, DispatchError> {
    if matches!(lease, PushLease::Force) {
        return Ok(refs::RefWriteCondition::Any);
    }
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);
    Ok(match refs::read_remote_ref(&mkit_dir, remote, branch)? {
        Some(tracked) => refs::RefWriteCondition::Match(tracked),
        None => refs::RefWriteCondition::Missing,
    })
}

/// Push the current branch to its upstream and, on success, advance the
/// local remote-tracking ref `refs/remotes/<remote>/<branch>` to the
/// pushed tip.
///
/// `remote` is the upstream remote NAME (for the tracking-ref
/// namespace); `branch` is the local branch name; `remote_branch` is the
/// branch name on the remote (`refs/heads/<remote_branch>`).
pub fn push_branch_tracked(
    cwd: &Path,
    tx: &dyn Transport,
    remote: &str,
    branch: &str,
    remote_branch: &str,
    lease: PushLease,
) -> Result<Hash, DispatchError> {
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);
    let store = crate::commands::open_store_configured(cwd)?;
    let tip = refs::read_ref(&mkit_dir, branch)?
        .ok_or_else(|| DispatchError::RemoteBranchMissing(branch.to_owned()))?;
    // Default safe push requires a TRUE fast-forward: the new tip must
    // descend from the last-seen remote-tracking ref. The CAS `Match`
    // lease alone only proves the remote hasn't moved since we last
    // fetched — on its own it would still let a divergent local tip
    // (e.g. after a local `reset` to an unrelated commit) overwrite the
    // remote, which Git rejects as non-fast-forward. `--force-with-lease`
    // (`WithLease`) intentionally skips this check (overwrite as long as
    // the remote matches what we last saw); `Force` skips everything.
    if matches!(lease, PushLease::FastForward)
        && let Some(tracked) = refs::read_remote_ref(&mkit_dir, remote, remote_branch)?
        && !is_ancestor(&store, tracked, tip)?
    {
        return Err(DispatchError::NonFastForwardPush {
            branch: remote_branch.to_owned(),
        });
    }
    let condition = lease_condition(cwd, remote, remote_branch, lease)?;
    push_branch(tx, &store, remote_branch, tip, condition)?;
    refs::write_remote_ref(&mkit_dir, remote, remote_branch, &tip)?;
    Ok(tip)
}

/// Ref under which a branch's transfer packlist key is advertised. The
/// value is the BLAKE3 of the packlist blob (stored as a pack object); the
/// fetch side reads it to discover every pack needed to reconstruct the
/// branch. Lives in the `refs/mkit/` metadata namespace so it never
/// collides with real heads/tags. See [`mkit_core::transfer`].
fn packmap_ref(branch: &str) -> String {
    format!("refs/mkit/packmap/{branch}")
}

/// Download and decode a packlist blob by its key. A pruned / missing
/// packlist degrades to an empty list (the push then re-establishes one)
/// rather than failing.
fn download_packlist(tx: &dyn Transport, key: Hash) -> Result<Vec<Hash>, DispatchError> {
    match tx.download_pack(&PackKey::from_hash(key)) {
        Ok(bytes) => Ok(transfer::decode_packlist(&bytes)?),
        Err(TransportError::PackNotFound) => Ok(Vec::new()),
        Err(e) => Err(e.into()),
    }
}

/// Push one branch: upload a single delta-compressed pack carrying every
/// object reachable from `tip` that the remote lacks, advertise it via the
/// `refs/mkit/packmap/<branch>` metadata ref, then CAS-write
/// `refs/heads/<branch>` under `condition`.
///
/// Objects already present at the remote's current tip are never re-sent
/// (identical-object dedup), and changed `FastCDC` chunks are delta-encoded
/// against the prior version the remote already holds when that saves
/// bytes (see [`mkit_core::transfer::plan_pack`]). The pack is keyed by its
/// own BLAKE3 digest (SPEC-PACKFILE §7) — required because the digest-
/// checking storage server rejects a delta stored under the reconstructed
/// object's hash.
///
/// The packlist is advertised *before* the branch ref moves, so any fetcher
/// that observes the new tip always finds the packs that reconstruct it.
///
/// On a CAS failure ([`TransportError::RefConflict`]) this returns
/// [`DispatchError::NonFastForwardPush`] so callers can render an
/// actionable fetch-then-retry hint. Does NOT touch local
/// remote-tracking refs — the caller decides when to advance them.
pub fn push_branch(
    tx: &dyn Transport,
    store: &ObjectStore,
    branch: &str,
    tip: Hash,
    condition: refs::RefWriteCondition,
) -> Result<(), DispatchError> {
    // Diff against the remote's CURRENT tip so we send only what it lacks
    // and can delta against bases it already holds. Planning is an
    // optimization; the head CAS below remains authoritative.
    let remote_tip = tx.read_ref(&format!("refs/heads/{branch}"))?;
    let plan = transfer::plan_pack(store, tip, remote_tip)?;

    let packmap_name = packmap_ref(branch);
    // Read the prior packlist pointer before mutating anything so we can
    // append to it and CAS the packmap ref.
    let prior_pl_key = tx.read_ref(&packmap_name).unwrap_or(None);

    if !plan.is_empty() {
        if crate::signal::is_shutdown() {
            return Err(DispatchError::Interrupted);
        }

        // Build the pack from the deterministic plan: raws first (non-blobs
        // before blobs), then deltas (their bases are external — resolved
        // from the fetcher's store via earlier packs — so no in-pack
        // ordering is required, SPEC-PACKFILE §4).
        let mut w = PackWriter::new();
        for h in &plan.raw {
            let bytes = store.read(h)?;
            w.push_raw(*h, bytes)?;
        }
        for d in &plan.deltas {
            w.push_delta(&d.base, &d.stream)?;
        }
        let pack = w.finish()?;
        let pack_key = pack::pack_key(&pack);
        tx.upload_pack(&pack, &PackKey::from_hash(pack_key))?;

        // Cumulative packlist: reset to just this pack on a full-closure
        // (self-contained) push, otherwise append to the prior list so a
        // fresh clone downloads the whole history of packs in order.
        let mut new_list = match prior_pl_key {
            Some(k) if !plan.self_contained => download_packlist(tx, k)?,
            _ => Vec::new(),
        };
        new_list.push(pack_key);
        let pl_bytes = transfer::encode_packlist(&new_list)?;
        let pl_key = pack::pack_key(&pl_bytes);
        tx.upload_pack(&pl_bytes, &PackKey::from_hash(pl_key))?;

        // Advertise before moving the branch. CAS off the prior pointer so a
        // concurrent winner's packmap is not clobbered; a lost race here is
        // recovered by the fetch completeness pass, so it is best-effort.
        let pm_cond = match prior_pl_key {
            Some(k) => refs::RefWriteCondition::Match(k),
            None => refs::RefWriteCondition::Missing,
        };
        let _ = tx.update_ref(&packmap_name, pm_cond, &pl_key);
    }

    let full_name = format!("refs/heads/{branch}");
    match tx.update_ref(&full_name, condition, &tip) {
        Ok(()) => Ok(()),
        Err(TransportError::RefConflict) => Err(DispatchError::NonFastForwardPush {
            branch: branch.to_owned(),
        }),
        Err(e) => Err(e.into()),
    }
}

/// Fetch remote refs, then fast-forward the current local branch from
/// `refs/remotes/default/<branch>`. Fresh repos with no local branch tip
/// initialise from the current branch's remote-tracking ref, or the first
/// advertised remote branch when the current default branch is absent.
pub fn pull_all(cwd: &Path, tx: &dyn Transport, remote: &str) -> Result<usize, DispatchError> {
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);
    // ONE repo lock across BOTH phases — the fetch (object write + remote
    // refs) and the fast-forward (branch ref + HEAD + worktree). Validate
    // the repo first for a clean non-repo error, and do NOT re-acquire the
    // lock (it is a non-reentrant file lock): the fetch phase runs via the
    // non-locking `fetch_objects`, not `fetch_all` (#267).
    let store = crate::commands::open_store_configured(cwd)?;
    let _lock = mkit_core::repo_lock::acquire_default(&mkit_dir, "worktree.lock")?;
    let n = fetch_objects(&store, &mkit_dir, tx, remote)?;
    let remote_refs = refs::list_remote_refs(&mkit_dir, remote)?
        .into_iter()
        .filter_map(|r| r.hash.map(|hash| (r.name, hash)))
        .collect::<Vec<_>>();
    if remote_refs.is_empty() {
        return Ok(n);
    }

    let original_head = refs::read_head(&mkit_dir).ok();
    let (branch, local_tip, remote_tip) = match &original_head {
        Some(Head::Branch(branch)) => {
            let local_tip = refs::read_ref(&mkit_dir, branch)?;
            let selected = if local_tip.is_some() {
                remote_refs
                    .iter()
                    .find(|(name, _)| name == branch)
                    .ok_or_else(|| DispatchError::RemoteBranchMissing(branch.clone()))?
            } else {
                remote_refs
                    .iter()
                    .find(|(name, _)| name == branch)
                    .unwrap_or(&remote_refs[0])
            };
            (selected.0.clone(), local_tip, selected.1)
        }
        Some(Head::Detached(_)) => return Err(DispatchError::DetachedHead),
        None => (remote_refs[0].0.clone(), None, remote_refs[0].1),
    };

    let ref_condition = if let Some(local_tip) = local_tip {
        if local_tip == remote_tip {
            return Ok(n);
        }
        if !is_ancestor(&store, local_tip, remote_tip)? {
            return Err(DispatchError::NonFastForwardPull { branch });
        }
        refs::RefWriteCondition::Match(local_tip)
    } else {
        refs::RefWriteCondition::Missing
    };

    let tree = load_tree_hash(&store, remote_tip)?;
    crate::commands::ensure_restore_safe(cwd, &store, tree)
        .map_err(DispatchError::RestoreSafety)?;
    crate::commands::write_ref_recording_history(&mkit_dir, &branch, ref_condition, &remote_tip)?;
    if let Err(e) = refs::write_head_branch(&mkit_dir, &branch) {
        rollback_pull_ref(&mkit_dir, &branch, local_tip, remote_tip)?;
        return Err(e.into());
    }
    if let Err(e) = crate::commands::restore_worktree_and_index(cwd, &store, tree) {
        if let Err(rollback) =
            rollback_pull_ref_and_head(&mkit_dir, &branch, local_tip, remote_tip, original_head)
        {
            return Err(DispatchError::RestoreSafety(format!(
                "{e}; additionally failed to roll back ref: {rollback}"
            )));
        }
        return Err(DispatchError::RestoreSafety(e));
    }
    Ok(n)
}

fn rollback_pull_ref_and_head(
    mkit_dir: &Path,
    branch: &str,
    local_tip: Option<Hash>,
    remote_tip: Hash,
    original_head: Option<Head>,
) -> Result<(), String> {
    rollback_pull_ref(mkit_dir, branch, local_tip, remote_tip).map_err(|e| e.to_string())?;
    match original_head {
        Some(Head::Branch(name)) => refs::write_head_branch(mkit_dir, &name),
        Some(Head::Detached(hash)) => refs::write_head_detached(mkit_dir, &hash),
        None => Ok(()),
    }
    .map_err(|e| e.to_string())
}

fn rollback_pull_ref(
    mkit_dir: &Path,
    branch: &str,
    local_tip: Option<Hash>,
    remote_tip: Hash,
) -> Result<(), refs::RefError> {
    if let Some(local_tip) = local_tip {
        crate::commands::write_ref_recording_history(
            mkit_dir,
            branch,
            refs::RefWriteCondition::Match(remote_tip),
            &local_tip,
        )
    } else if refs::read_ref(mkit_dir, branch)? == Some(remote_tip) {
        refs::delete_ref(mkit_dir, branch)
    } else {
        Ok(())
    }
}

/// `fetch` — `pull_all` without the HEAD update. Downloads every object
/// reachable from each remote ref (via [`Transport::download_pack`] on
/// the object's own digest) and writes the ref into
/// `refs/remotes/default/<branch>`.
pub fn fetch_all(cwd: &Path, tx: &dyn Transport, remote: &str) -> Result<usize, DispatchError> {
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);
    // Validate the repo BEFORE locking so a non-repo reports cleanly rather
    // than as a lock error, then hold the repo lock across the whole
    // object-write + remote-ref-publish window. This serializes fetch
    // against `gc` so a concurrent `gc --grace-secs 0` can't prune freshly
    // downloaded objects before their refs make them reachable (#267).
    let store = crate::commands::open_store_configured(cwd)?;
    let _lock = mkit_core::repo_lock::acquire_default(&mkit_dir, "worktree.lock")?;
    fetch_objects(&store, &mkit_dir, tx, remote)
}

/// Download every remote `refs/heads/*` object closure and publish the
/// remote-tracking refs. The caller MUST already hold the repo lock (so the
/// object writes and ref publication are serialized against `gc`).
fn fetch_objects(
    store: &ObjectStore,
    mkit_dir: &Path,
    tx: &dyn Transport,
    remote: &str,
) -> Result<usize, DispatchError> {
    let remote_refs = tx.list_refs("refs/heads/")?;
    let mut n = 0;
    for r in remote_refs {
        if crate::signal::is_shutdown() {
            return Err(DispatchError::Interrupted);
        }
        let Some(h) = r.hash else { continue };
        // 1. If the remote advertises a packlist for this branch (the
        //    delta-aware push path), download and unpack every listed pack
        //    in dependency order — bases resolve from the store as earlier
        //    packs are applied. `read_ref` errors (e.g. an old server that
        //    rejects the `refs/mkit/` namespace) degrade to "no packlist".
        if let Some(pl_key) = tx.read_ref(&packmap_ref(&r.name)).unwrap_or(None) {
            fetch_packlist(store, tx, pl_key)?;
        }
        // 2. Completeness pass: walk the closure and per-object download
        //    anything still missing. For a packlist remote this finds
        //    everything already present (a no-op); for a legacy per-object
        //    remote it is the whole download path.
        fetch_object_closure(store, tx, &h)?;
        refs::write_remote_ref(mkit_dir, remote, &r.name, &h)?;
        n += 1;
    }
    Ok(n)
}

/// Maximum per-pack delta-base fallbacks during unpack. Bounds the retry
/// loop so a cyclic or genuinely-absent base fails loudly instead of
/// spinning. Real packlists never hit this (bases arrive in earlier
/// packs); it only bridges a pack whose base was uploaded by an older,
/// per-object push.
const MAX_BASE_FALLBACK: u32 = 256;

/// Download the packlist `pl_key` points at and unpack each listed pack in
/// order. A missing packlist or pack is tolerated — the caller's
/// completeness pass recovers anything left undelivered.
fn fetch_packlist(
    store: &ObjectStore,
    tx: &dyn Transport,
    pl_key: Hash,
) -> Result<(), DispatchError> {
    let bytes = match tx.download_pack(&PackKey::from_hash(pl_key)) {
        Ok(b) => b,
        Err(TransportError::PackNotFound) => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let list = transfer::decode_packlist(&bytes)?;
    for pk in list {
        if crate::signal::is_shutdown() {
            return Err(DispatchError::Interrupted);
        }
        let pack = match tx.download_pack(&PackKey::from_hash(pk)) {
            Ok(b) => b,
            Err(TransportError::PackNotFound) => continue,
            Err(e) => return Err(e.into()),
        };
        unpack_with_base_fallback(store, tx, &pack)?;
    }
    Ok(())
}

/// Unpack a pack, fetching any missing delta base per-object and retrying.
/// `PackReader` commits nothing until the whole pack resolves, so a retry
/// after fetching the base re-applies the pack cleanly.
fn unpack_with_base_fallback(
    store: &ObjectStore,
    tx: &dyn Transport,
    pack: &[u8],
) -> Result<(), DispatchError> {
    let mut attempts = 0;
    loop {
        match PackReader::read(pack, store) {
            Ok(_) => return Ok(()),
            Err(PackError::DeltaBaseMissing(hex)) if attempts < MAX_BASE_FALLBACK => {
                attempts += 1;
                let base = mkit_core::hash::from_hex(&hex)
                    .map_err(|_| DispatchError::Transport(TransportError::InvalidResponse))?;
                // Try to fetch the base directly (legacy per-object remote).
                fetch_object_closure(store, tx, &base)?;
                if !store.contains(&base) {
                    // Couldn't resolve it anywhere — surface the original error.
                    return Err(PackError::DeltaBaseMissing(hex).into());
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
}

fn load_tree_hash(store: &ObjectStore, commit_hash: Hash) -> Result<Hash, DispatchError> {
    match store.read_object(&commit_hash)? {
        Object::Commit(c) => Ok(c.tree_hash),
        Object::Remix(r) => Ok(r.tree_hash),
        _ => Err(DispatchError::NotCommit),
    }
}

/// Recursively download every object reachable from `root` into
/// `store`, fetching one digest at a time. Used by [`fetch_all`] /
/// [`pull_all`] when the remote's ref-advertise doesn't carry a
/// pack key (which is the current contract for the memory + file
/// transports).
fn fetch_object_closure(
    store: &ObjectStore,
    tx: &dyn Transport,
    root: &Hash,
) -> Result<(), DispatchError> {
    use std::collections::VecDeque;

    let mut queue: VecDeque<Hash> = VecDeque::new();
    queue.push_back(*root);
    let mut seen = std::collections::HashSet::new();

    while let Some(h) = queue.pop_front() {
        if crate::signal::is_shutdown() {
            return Err(DispatchError::Interrupted);
        }
        if !seen.insert(h) {
            continue;
        }
        if store.contains(&h) {
            // Already local — still walk to be sure children are
            // present. Read through the store to enqueue them.
        } else {
            // Download. Transports that keyed on the object digest
            // (memory, file) return raw object bytes here.
            let key = PackKey::from_hash(h);
            let bytes = match tx.download_pack(&key) {
                Ok(b) => b,
                Err(TransportError::PackNotFound) => {
                    // Accept as a no-op: the remote may have assembled
                    // a multi-object pack and thus does not key on the
                    // object digest. The per-object path can't see the
                    // pack in that case; the caller is expected to
                    // either download the pack explicitly (future: a
                    // proper ref-advertise carrying pack keys) or
                    // accept missing objects. For the memory/file
                    // transports the per-object mapping is always
                    // populated by the push side, so this branch is
                    // defensive.
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            // If the remote returned a real packfile, unpack it. Else,
            // treat the bytes as a single raw object.
            if bytes.starts_with(mkit_core::pack::MAGIC) {
                let _ = PackReader::read(&bytes, store)?;
            } else {
                let stored = store.write(&bytes)?;
                // Sanity check: the digest MUST match the key we asked
                // for — otherwise the remote is serving mismatched
                // content.
                if stored != h {
                    return Err(DispatchError::Transport(TransportError::InvalidResponse));
                }
            }
        }
        // Enqueue children so we walk the whole closure.
        if let Ok(obj) = store.read_object(&h) {
            use mkit_core::object::Object;
            match obj {
                Object::Commit(c) => {
                    queue.push_back(c.tree_hash);
                    for p in c.parents {
                        queue.push_back(p);
                    }
                }
                Object::Remix(r) => {
                    queue.push_back(r.tree_hash);
                    for p in r.parents {
                        queue.push_back(p);
                    }
                }
                Object::Tree(t) => {
                    for e in t.entries {
                        queue.push_back(e.object_hash);
                    }
                }
                Object::ChunkedBlob(cb) => {
                    for c in cb.chunks {
                        queue.push_back(c);
                    }
                }
                Object::Tag(t) => {
                    queue.push_back(t.target);
                }
                Object::Blob(_) | Object::Delta(_) => {}
            }
        }
    }
    Ok(())
}
