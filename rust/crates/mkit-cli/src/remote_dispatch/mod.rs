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

mod packmap;

use std::path::Path;
use std::sync::Arc;

use mkit_core::hash::Hash;
use mkit_core::object::Object;
use mkit_core::ops::merge::is_ancestor;
use mkit_core::ops::restore;
use mkit_core::pack::{self, PackError, PackWriter};
use mkit_core::protocol::{PackKey, Transport, TransportError};
use mkit_core::refs::{self, Head};
use mkit_core::store::{ObjectStore, StoreError};
use mkit_core::transfer::{self, PackListError};
use mkit_transport_file::FileTransport;
use mkit_transport_http::HttpTransport;
use mkit_transport_s3::S3Transport;
use mkit_transport_ssh::{SshInitError, SshTransport};

use packmap::{advance_packmap, fetch_pack_chain, packmap_ref};

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
    /// The branch's packmap pointer could not be durably advanced under
    /// sustained concurrent pushes. The branch ref was NOT moved, so the
    /// remote stays consistent; the push is safe to retry.
    #[error(
        "could not establish the pack map for branch '{branch}' under concurrent pushes; retry"
    )]
    PackmapContended { branch: String },
    /// A packmap chain was malformed — it exceeded the depth cap, contained
    /// a cycle, or a node could not be downloaded/decoded. Indicates a
    /// corrupt or hostile remote.
    #[error("pack map chain for branch '{branch}' is malformed (too deep, cyclic, or unreadable)")]
    PackChainInvalid { branch: String },
    /// The remote advertised a branch ref but no packmap
    /// (`refs/mkit/packmap/<branch>`) for it. mkit speaks a single,
    /// packmap-only transfer dialect: the push path ALWAYS advertises a
    /// packmap before moving the branch ref, so a branch with a tip but no
    /// packmap is a corrupt/incomplete remote, not a format we degrade to.
    /// We refuse to fetch rather than silently materialise a partial ref.
    #[error("remote advertised branch '{0}' but no pack map to reconstruct it")]
    PackmapMissing(String),
    /// The packmap advertised a pack the remote does not hold. The branch's
    /// closure cannot be reconstructed, so the fetch is aborted rather than
    /// publishing a ref to an incomplete history.
    #[error("remote advertised pack {pack} for branch '{branch}' but does not hold it")]
    AdvertisedPackMissing { branch: String, pack: String },
    /// After unpacking the branch's whole packmap chain, an object
    /// reachable from the fetched tip is still absent from the local store —
    /// the chain did not deliver the full closure. This is a pure integrity
    /// assertion (no recovery download is attempted): the remote's packmap
    /// is incomplete, so fetch aborts before publishing the ref.
    #[error("remote is missing object {0} needed to reconstruct the ref")]
    RemoteMissingObject(String),
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

/// `mkit+enc://` dispatch (issue #156).
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

/// True iff advancing a ref from `old` to `new` is a fast-forward (i.e.
/// `old` is an ancestor of `new`). A missing `old` (brand-new ref) and an
/// unchanged ref both count as fast-forwards. Used by `push`/`fetch` to
/// pick the git-style summary symbol (`..` vs `...`/`(forced update)`).
pub fn is_fast_forward(cwd: &Path, old: Option<Hash>, new: Hash) -> Result<bool, DispatchError> {
    match old {
        None => Ok(true),
        Some(o) if o == new => Ok(true),
        Some(o) => {
            let store = crate::commands::open_store_configured(cwd)?;
            Ok(is_ancestor(&store, o, new)?)
        }
    }
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

/// Push one branch: upload a single delta-compressed pack carrying every
/// object reachable from `tip` that the remote lacks, durably advertise it
/// via the `refs/mkit/packmap/<branch>` metadata ref, then CAS-write
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
/// The packmap is advanced *and confirmed* before the branch ref moves: if
/// the packmap can't be durably established the push aborts without
/// touching the head, so the head never points past a packmap that fails to
/// reconstruct it (even under concurrent pushers to the same branch).
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

        // Durably chain the pack onto the packmap BEFORE moving the head.
        // On failure we return without touching `refs/heads`, leaving the
        // uploaded pack orphaned (GC reclaims it) but the remote consistent.
        // `self_contained` lets a full-closure push reset a broken chain.
        advance_packmap(tx, branch, pack_key, plan.self_contained)?;
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

/// Reconstruct every remote `refs/heads/*` from its packmap chain and
/// publish the remote-tracking refs. The caller MUST already hold the repo
/// lock (so the object writes and ref publication are serialized against
/// `gc`).
///
/// mkit speaks a single, packmap-only transfer dialect (the legacy
/// per-object download path was removed): for every advertised branch the
/// flow is exactly
///
/// 1. read the branch's packmap ref (`refs/mkit/packmap/<branch>`),
/// 2. walk its chain oldest-first and unpack each pack
///    ([`packmap::fetch_pack_chain`]), then
/// 3. assert the tip's closure is fully present
///    ([`verify_closure_present`]) — a pure integrity check that downloads
///    nothing.
///
/// Both ends fail loudly: an absent packmap is [`DispatchError::PackmapMissing`]
/// and a present-but-incomplete packmap is [`DispatchError::RemoteMissingObject`].
/// We never publish a remote-tracking ref to a closure we couldn't fully
/// materialise locally.
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
        // A branch tip without a packmap is a corrupt/incomplete remote, not
        // a format we degrade to: the push path ALWAYS advertises a packmap
        // before moving the branch ref. A real transport error (network blip,
        // auth) propagates unchanged — only `Ok(None)` is the explicit
        // "no packmap" verdict, and it is now an error.
        let Some(chain_head) = tx.read_ref(&packmap_ref(&r.name))? else {
            return Err(DispatchError::PackmapMissing(r.name.clone()));
        };
        fetch_pack_chain(store, tx, &r.name, chain_head)?;
        // Integrity assertion only — NO downloads. The chain above is the
        // sole delivery mechanism; if it didn't deliver the whole closure the
        // remote's packmap is incomplete and we refuse to publish the ref.
        verify_closure_present(store, &h)?;
        refs::write_remote_ref(mkit_dir, remote, &r.name, &h)?;
        n += 1;
    }
    Ok(n)
}

/// Assert that every object reachable from `tip` is already present in the
/// local store after the packmap chain has been unpacked. This is a pure
/// integrity check — it walks the closure via [`mkit_core::ops::reachable_objects`]
/// (which reads each object and re-verifies its digest) and performs NO
/// network access. A reachable object that the chain failed to deliver
/// surfaces as [`StoreError::ObjectNotFound`], which we re-tag as
/// [`DispatchError::RemoteMissingObject`] so the fetch aborts loudly rather
/// than publishing a ref to a closure we can't reconstruct.
fn verify_closure_present(store: &ObjectStore, tip: &Hash) -> Result<(), DispatchError> {
    match mkit_core::ops::reachable_objects(store, tip) {
        Ok(_) => Ok(()),
        Err(StoreError::ObjectNotFound(hex)) => Err(DispatchError::RemoteMissingObject(hex)),
        Err(e) => Err(e.into()),
    }
}

fn load_tree_hash(store: &ObjectStore, commit_hash: Hash) -> Result<Hash, DispatchError> {
    match store.read_object(&commit_hash)? {
        Object::Commit(c) => Ok(c.tree_hash),
        Object::Remix(r) => Ok(r.tree_hash),
        _ => Err(DispatchError::NotCommit),
    }
}
