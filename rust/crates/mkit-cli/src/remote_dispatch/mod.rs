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

// `pub(crate)` so the `remote remove`/`rename` command handlers can drive
// the record's lifecycle ops (#545); everything else stays module-private.
pub(crate) mod applied_packs;
mod envelope_signer;
mod packmap;

use mkit_core::layout::RepoLayout;
use std::path::Path;
use std::sync::Arc;

use applied_packs::AppliedPacks;

use mkit_core::hash::Hash;
use mkit_core::object::Object;
use mkit_core::ops::merge::is_ancestor;
use mkit_core::ops::restore;
use mkit_core::pack::{self, PackError, PackWriter};
use mkit_core::protocol::{PackKey, Transport, TransportError};
use mkit_core::refs::{self, Head};
use mkit_core::store::{ObjectStore, StoreError};
use mkit_core::transfer::{self, PackListError};
use mkit_transport_connect::ConnectTransport;
use mkit_transport_file::FileTransport;
use mkit_transport_s3::S3Transport;
use mkit_transport_ssh::{SshInitError, SshOptions, SshTransport, parse_mkit_ssh_url};

use packmap::{
    ChainAction, advance_packmap, apply_fetched_chain, commit_head, packmap_ref, probe_chain,
    rebaseline_depth, resolve_and_download_chain,
};

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
    #[error("worktree discovery: {0}")]
    Discover(#[from] mkit_core::layout::DiscoverError),
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
    /// The fetched tip's object closure exceeds the
    /// [`mkit_core::ops::graph::MAX_REACHABLE`] verification cap, so
    /// completeness could not be confirmed. On the applied-pack skip path
    /// (#409) this closure walk is the sole guarantee the local store is
    /// whole; a truncated walk could silently pass over missing objects, so
    /// we fail closed rather than publish a ref we can't fully verify. This is
    /// NOT a self-heal trigger.
    #[error(
        "fetched history is too large to verify (closure exceeds the {0}-object cap); refusing to publish an unverified ref"
    )]
    ClosureTooLarge(usize),
    /// A commit/remix/tag newly introduced by this fetch failed Ed25519
    /// signature verification via [`mkit_core::sign::verify_commit`] /
    /// `verify_remix` / `verify_tag` — the exact check `mkit verify <rev>`
    /// runs manually (issue #692). A hostile remote (THREAT-MODEL §3.1) can
    /// otherwise push an unsigned or forged history that `clone`/`pull`/
    /// `fetch` would silently materialise. Deliberately distinct from
    /// [`RemoteMissingObject`](Self::RemoteMissingObject) so it does NOT
    /// feed the applied-pack self-heal retry (#409): an invalid signature
    /// is not evidence of local staleness, and clearing the applied-packs
    /// record would not make a hostile remote's history valid. Fails
    /// closed by default; opt out with `--no-verify-signatures` or the
    /// user-scoped `pull.require_signed = false` config (never settable
    /// from repo-scoped config — see [`crate::config::REPO_FORBIDDEN_KEYS`]).
    #[error("object {hash} failed signature verification: {reason}")]
    UnsignedOrInvalidObject { hash: String, reason: String },
    /// A remote name passed to the applied-packs record (#409) is not a legal
    /// ref name (per [`mkit_core::refs::validate_ref_name`]). A remote name
    /// *is* a ref name, so this should never occur for a config-registered
    /// remote; it is defence-in-depth against a malformed name being used as
    /// a raw path component under `.mkit/applied-packs/`.
    #[error("invalid remote name for applied-packs record: '{0}'")]
    InvalidRemoteName(String),
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
///
/// `layout` is needed only to resolve a repo-key-file envelope signer
/// when `cfg.merged.transport_auth == "envelope"` (see
/// [`envelope_signer_from_config`]) — every caller already has it at
/// hand (it discovered the repo before building `cfg`).
pub fn open_trusted(
    endpoint: &str,
    repo_chosen: bool,
    cfg: &crate::config::LayeredConfig,
    layout: &RepoLayout,
) -> Result<Arc<dyn Transport>, DispatchError> {
    crate::config::endpoint_credential_trust(cfg, endpoint, repo_chosen)
        .map_err(DispatchError::UntrustedRemote)?;
    open_with_config(endpoint, &cfg.merged, layout)
}

/// The single chokepoint that resolves SSH trust-pinning (issue #389) and
/// `mkit+https://` envelope-signing config from `cfg` and opens a
/// transport. Every config-bearing caller — [`open_trusted`] (push /
/// fetch / pull) and `clone` — routes through here, so both are resolved
/// and threaded in exactly ONE place. A new remote command physically
/// cannot forget them as long as it opens through config; the only
/// un-pinned path is the config-less [`open`], which production never
/// uses for `ssh` or envelope auth.
pub(crate) fn open_with_config(
    url: &str,
    cfg: &crate::config::Config,
    layout: &RepoLayout,
) -> Result<Arc<dyn Transport>, DispatchError> {
    let envelope_signer = if url.starts_with("mkit+https://") || url.starts_with("mkit+http://") {
        envelope_signer_from_config(cfg, layout)?
    } else {
        None
    };
    open_with_ssh_options(url, &ssh_options_from_config(cfg), envelope_signer)
}

/// Resolve an [`mkit_transport_connect::EnvelopeSigner`] from `cfg`, when
/// `cfg.transport_auth_envelope()` is set — `Ok(None)` otherwise (the
/// default: bearer-token-only, unchanged from #700/#701).
///
/// Reuses EXACTLY the same signer resolution as `mkit commit`'s
/// [`crate::commands::commit::load_commit_signer`] (`cfg.signer` ==
/// `""`/`"legacy"` -> the repo key file at `cfg.signing_key`; `"keystore"`
/// -> `cfg.key.ed25519_ref_or_fallback()` via `mkit-keystore`) rather than
/// inventing a parallel key path — the write envelope authenticates with
/// the SAME Ed25519 identity that already signs the user's commits.
///
/// Both signer kinds sign the raw envelope digest directly (no
/// SPEC-SIGNING commit/remix/tag domain prefix): the legacy path delegates
/// to the EXISTING `mkit_attest::RepoKeySigner` (its `sign` already signs
/// the given bytes directly — "the PAE's own `\"DSSEv1 \"` prefix is the
/// domain separator" per its own doc comment — so no new raw-Ed25519 call
/// site is needed here), the keystore path via `KeySigner::sign`, whose
/// own contract already documents "Ed25519 signers return the 64-byte
/// RFC 8032 signature over `msg`" — i.e. no domain digest applied, exactly
/// what the envelope needs. See `envelope_signer.rs` for both adapters.
pub(crate) fn envelope_signer_from_config(
    cfg: &crate::config::Config,
    layout: &RepoLayout,
) -> Result<Option<Arc<dyn mkit_transport_connect::EnvelopeSigner>>, DispatchError> {
    if !cfg.transport_auth_envelope() {
        return Ok(None);
    }
    let remote_error = |msg: String| DispatchError::Transport(TransportError::RemoteError(msg));
    match cfg.signer.as_str() {
        "" | "legacy" => {
            let key_path =
                crate::config::resolve_key_path(layout, &cfg.signing_key).map_err(|e| {
                    remote_error(format!("transport_auth = envelope: signing_key: {e}"))
                })?;
            if !key_path.exists() {
                return Err(remote_error(format!(
                    "transport_auth = envelope requires a signing key at {} — run `mkit keygen` first",
                    key_path.display()
                )));
            }
            let kp = mkit_core::sign::load_key(&key_path)
                .map_err(|e| remote_error(format!("transport_auth = envelope: load key: {e}")))?;
            Ok(Some(
                Arc::new(envelope_signer::RepoKeyEnvelopeSigner::new(kp))
                    as Arc<dyn mkit_transport_connect::EnvelopeSigner>,
            ))
        }
        "keystore" => {
            let signer = envelope_signer::KeystoreEnvelopeSigner::open(cfg)
                .map_err(|e| remote_error(format!("transport_auth = envelope: {e}")))?;
            Ok(Some(
                Arc::new(signer) as Arc<dyn mkit_transport_connect::EnvelopeSigner>
            ))
        }
        other => Err(remote_error(format!(
            "transport_auth = envelope: unknown signer `{other}` — expected `legacy` or `keystore`"
        ))),
    }
}

/// Map the three `ssh.*` trust-pinning keys from a merged [`Config`] into
/// the [`SshOptions`] carried to the spawned `ssh(1)` child. An empty
/// string means "unset" — `build_ssh_command` emits no flag for it, so
/// the user's `ssh(1)` defaults are inherited. The producer half of
/// issue #389 (the consumer half, `build_ssh_command`, wires the fields
/// into argv). Sole caller is [`open_with_config`].
fn ssh_options_from_config(cfg: &crate::config::Config) -> SshOptions {
    SshOptions {
        strict_host_key_checking: cfg.ssh_strict_host_key_checking.clone(),
        user_known_hosts_file: cfg.ssh_user_known_hosts_file.clone(),
        identity_file: cfg.ssh_identity_file.clone(),
    }
}

/// Open a transport for the given URL with **no** SSH trust-pinning.
/// Returns a type-erased `Arc` so callers can treat all schemes
/// uniformly.
///
/// Low-level scheme dispatch only — it neither enforces the credential
/// gate nor threads `ssh.*` config. Any caller that has a [`Config`]
/// must use `open_with_config` (directly, or via `open_trusted`) so
/// the trust-pinning keys reach the spawned `ssh(1)`; `open` stays
/// public only for file/memory integration tests that have no ambient
/// config to resolve.
///
/// [`Config`]: crate::config::Config
pub fn open(url: &str) -> Result<Arc<dyn Transport>, DispatchError> {
    open_with_ssh_options(url, &SshOptions::default(), None)
}

/// Scheme dispatch with explicit SSH options and an optional `mkit+https://`
/// / `mkit+http://` envelope signer. Identical to [`open`] for every
/// non-SSH, non-Connect scheme; the `mkit+ssh://` branch threads
/// `ssh_options` (issue #389) into the spawned `ssh(1)` child via
/// [`SshTransport::connect_with_options`], and the `mkit+https://`/
/// `mkit+http://` branch threads `envelope_signer` (issue #699 follow-up)
/// into [`ConnectTransport::connect_with_signer`]. Reached only via
/// [`open`] (no config — both `None`/default) and [`open_with_config`]
/// (config-derived).
fn open_with_ssh_options(
    url: &str,
    ssh_options: &SshOptions,
    envelope_signer: Option<Arc<dyn mkit_transport_connect::EnvelopeSigner>>,
) -> Result<Arc<dyn Transport>, DispatchError> {
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
        // ConnectTransport::connect_with_signer strips the `mkit+` prefix
        // itself and reads MKIT_API_TOKEN from the environment (mkit#701 —
        // the native mkit.transport.v1 ConnectRPC client, replacing the
        // retired mkit-transport-http JSON dialect as of
        // SPEC-TRANSPORT-CONNECT verb parity). `envelope_signer` is `None`
        // unless the caller resolved one via `open_with_config` (mkit#699
        // follow-up: `transport_auth = envelope`) — bearer token and
        // envelope signing are independent, additive auth modes.
        let tx = ConnectTransport::connect_with_signer(url, envelope_signer)?;
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
        // Parse the URL, then spawn `ssh(1)` with the caller-supplied
        // trust-pinning options (issue #389). `connect_with_options`
        // performs the `Hello` / `HelloResponse` handshake. Any failure
        // here tears the child down before returning, so callers never
        // see a half-initialised transport.
        let target = parse_mkit_ssh_url(url).map_err(SshInitError::from)?;
        let tx = SshTransport::connect_with_options(&target, ssh_options)?;
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
    let layout = mkit_core::layout::discover(cwd)?;
    let store = crate::commands::open_store_configured(&layout)?;
    let refs_list = refs::list_refs(&layout)?;
    let remote = remote.unwrap_or(DEFAULT_REMOTE);
    let mut n = 0;
    // Batch every pushed branch's remote-tracking-ref write (#645):
    // publishing lands each ref as soon as its branch's `push_branch`
    // succeeds (same visibility as before), but the directory fsync that
    // makes those renames crash-durable is deferred to one pass over the
    // distinct directories touched, below — instead of once per branch.
    let mut tracking = refs::RemoteRefBatch::new(&layout, remote)?;
    let result: Result<(), DispatchError> = (|| {
        for r in refs_list {
            if crate::signal::is_shutdown() {
                return Err(DispatchError::Interrupted);
            }
            let Some(h) = r.hash else { continue };
            let condition = if force {
                refs::RefWriteCondition::Any
            } else {
                match refs::read_remote_ref(&layout, remote, &r.name)? {
                    Some(tracked) => refs::RefWriteCondition::Match(tracked),
                    None => refs::RefWriteCondition::Missing,
                }
            };
            push_branch(tx, &store, &r.name, h, condition)?;
            tracking.write(&r.name, &h)?;
            n += 1;
        }
        Ok(())
    })();
    // Commit whatever tracking-ref writes succeeded regardless of how the
    // loop above ended, so a mid-loop failure still durably publishes the
    // prefix that already pushed successfully — matching the old
    // per-branch loop, where each completed ref write was independently
    // durable before the loop moved to the next branch.
    tracking.commit()?;
    result?;
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
            let layout = mkit_core::layout::discover(cwd)?;
            let store = crate::commands::open_store_configured(&layout)?;
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
    let layout = mkit_core::layout::discover(cwd)?;
    Ok(match refs::read_remote_ref(&layout, remote, branch)? {
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
    let layout = mkit_core::layout::discover(cwd)?;
    let store = crate::commands::open_store_configured(&layout)?;
    let tip = refs::read_ref(&layout, branch)?
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
        && let Some(tracked) = refs::read_remote_ref(&layout, remote, remote_branch)?
        && !is_ancestor(&store, tracked, tip)?
    {
        return Err(DispatchError::NonFastForwardPush {
            branch: remote_branch.to_owned(),
        });
    }
    let condition = lease_condition(cwd, remote, remote_branch, lease)?;
    push_branch(tx, &store, remote_branch, tip, condition)?;
    refs::write_remote_ref(&layout, remote, remote_branch, &tip)?;
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
/// Plans the pack FIRST (diffing against the remote's current tip). A no-op
/// push (empty plan — the remote already holds this closure) takes the cheap
/// head-only path and walks NO packmap chain (mkit #521 perf). Only when the
/// plan is non-empty does it resolve the branch's current packmap chain depth
/// (walking it exactly once, see `packmap::probe_chain`) and, if the chain
/// would grow past the re-baseline threshold (#406, see
/// `packmap::rebaseline_depth`) AND the transport's `advance_refs` is
/// transactional ([`Transport::supports_atomic_advance`], mkit #521) AND the
/// head write is CAS-conditioned (a force push's `Any` head condition takes
/// the safe append path — an `Any` condition makes even an atomic transport
/// fall back to the ordered two-PUT `advance_refs`, so a reset there is not
/// safe), re-plans as a full closure (diffs against no remote tip) and
/// carries that decision down to `advance_packmap` as
/// `ChainAction::ResetSelfContained` so it resets the chain to a single
/// fresh node instead of appending to it — bounding clone cost, which
/// otherwise grows with chain length.
///
/// On a transport WITHOUT transactional `advance_refs` (the default used by
/// file/S3/SSH/memory), crossing the threshold never triggers a reset: the
/// default `advance_refs` commits the packmap write before the head CAS, and
/// a reset (unlike an append) is not a superset of the prior chain, so a
/// lost head-CAS race after a committed reset would strand the (unmoved)
/// head pointing at a commit the packmap can no longer reconstruct. Such a
/// transport keeps appending — `ChainAction::Append` — past the
/// threshold; `packmap::MAX_PACK_CHAIN_DEPTH` (the pure runaway/cycle guard)
/// remains the only bound on chain growth there, unchanged by this gate.
///
/// A chain read that fails with [`DispatchError::PackChainInvalid`], or a
/// missing prior packmap (first push), is left alone here — depth is only
/// defined for a resolvable chain, and a broken chain already has its own
/// reset path in `advance_packmap` (the broken-chain escape hatch, gated on
/// `self_contained` alone, independent of this transactional-advance gate —
/// see `ChainAction::Append`'s doc comment).
///
/// The already-resolved chain from this probe (when not discarded by a
/// re-baseline decision) is threaded into `advance_packmap` so its first
/// CAS attempt does not have to walk the chain a second time (#521 perf
/// fix).
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
    push_branch_with_depth(tx, store, branch, tip, condition, rebaseline_depth())
}

/// [`push_branch`] with an explicit re-baseline threshold in place of the
/// configured one (`packmap::rebaseline_depth`: the
/// `MKIT_PACK_REBASELINE_DEPTH` env var, default 64). `0` disables
/// re-baselining. Semantics are otherwise identical — see [`push_branch`].
///
/// This is the depth-policy seam (#547): integration tests inject a small
/// threshold (e.g. 3) to exercise the re-baseline path in-process with a
/// handful of pushes, where reaching the default threshold would take ~64
/// real pushes and the env-var override cannot be set on the test's own
/// process (`std::env::set_var` is banned by `clippy::disallowed_methods` —
/// it races other threads on POSIX).
pub fn push_branch_with_depth(
    tx: &dyn Transport,
    store: &ObjectStore,
    branch: &str,
    tip: Hash,
    condition: refs::RefWriteCondition,
    rebaseline_threshold: usize,
) -> Result<(), DispatchError> {
    // Diff against the remote's CURRENT tip so we send only what it lacks
    // and can delta against bases it already holds. Planning is an
    // optimization; the head CAS below remains authoritative.
    let remote_tip = tx.read_ref(&format!("refs/heads/{branch}"))?;

    // Plan FIRST, against the remote's current tip (#521 perf): a no-op push
    // (the remote already holds this closure) yields an empty plan and takes
    // the cheap head-only path below WITHOUT walking the packmap chain. Only
    // a push that actually has objects to send pays the O(depth) chain probe.
    let mut plan = transfer::plan_pack(store, tip, remote_tip)?;

    if plan.is_empty() {
        // Nothing to send — the remote already holds the closure; just move
        // the head (no packmap change needed, so no chain walk and no atomic
        // two-ref advance).
        return commit_head(tx, &format!("refs/heads/{branch}"), condition, &tip, branch);
    }

    if crate::signal::is_shutdown() {
        return Err(DispatchError::Interrupted);
    }

    // Re-baseline decision (#406/#521), made only now that we know there IS
    // something to send: walk the current chain exactly once and decide
    // whether this push should reset the chain to a single self-contained
    // node instead of appending. When NOT re-baselining, the walk is cached
    // (`resolved_chain`) so `advance_packmap`'s append path can reuse it
    // instead of re-walking.
    //
    // A reset is committed together with the head; the ordered (non-atomic)
    // `advance_refs` fallback (packmap PUT then head PUT) would strand the
    // head at the old tip on a torn write, and a reset — unlike an append —
    // is not a superset of the prior chain, so it can't rebuild that stranded
    // closure. We therefore re-baseline ONLY when BOTH hold:
    //   * the transport advances both refs transactionally
    //     (`supports_atomic_advance`), AND
    //   * the head write is CAS-conditioned (not `Any`). A force push's `Any`
    //     head condition makes even an atomic transport fall back to the
    //     ordered two-PUT path (`Any` is not expressible on the atomic
    //     endpoint — see `HttpTransport::supports_atomic_advance`), so a
    //     force push MUST take the safe append path instead of resetting.
    let mut rebaseline = false;
    let mut resolved_chain = None;
    if rebaseline_threshold > 0
        && let Some(pm) = tx.read_ref(&packmap_ref(branch))?
    {
        match probe_chain(tx, branch, pm) {
            Ok(chain)
                if chain.depth + 1 > rebaseline_threshold
                    && tx.supports_atomic_advance()
                    && !matches!(condition, refs::RefWriteCondition::Any) =>
            {
                rebaseline = true;
            }
            Ok(chain) => resolved_chain = Some(chain),
            Err(DispatchError::PackChainInvalid { .. }) => {}
            Err(e) => return Err(e),
        }
    }

    if rebaseline {
        // Force a full-closure plan: no external bases, so the pack is
        // self-contained and safe to reset the chain onto.
        plan = transfer::plan_pack(store, tip, None)?;
    }

    // Build the pack from the deterministic plan: raws first (non-blobs
    // before blobs), then deltas (their bases are external — resolved from
    // the fetcher's store via earlier packs — so no in-pack ordering is
    // required, SPEC-PACKFILE §4).
    let mut w = PackWriter::new();
    for h in &plan.raw {
        let bytes = store.read(h)?;
        w.push_raw(*h, &bytes)?;
        // Honest progress (#711): one real object just got staged into
        // the outgoing pack. Never git's fabricated
        // Enumerating/Counting/Compressing lines — see `crate::progress`.
        crate::progress::report(crate::progress::Event::ObjectsPacked(1));
    }
    for d in &plan.deltas {
        w.push_delta(&d.base, &d.stream)?;
        crate::progress::report(crate::progress::Event::ObjectsPacked(1));
    }
    let pack = w.finish()?;
    let pack_key = pack::pack_key(&pack);
    tx.upload_pack(&pack, &PackKey::from_hash(pack_key))?;
    // Upload is complete — report the real byte count handed to the
    // transport, not an estimate.
    crate::progress::report(crate::progress::Event::PackUploaded(pack.len() as u64));

    // Chain the pack onto the packmap AND move the head together (#408): a
    // transactional transport applies both atomically, the default does
    // packmap-then-head. Either way the head never lands past a packmap that
    // can't reconstruct it. `Append`'s `self_contained` lets a full-closure
    // push reset a broken chain (unconditionally, on any transport);
    // `ResetSelfContained` proactively resets a healthy chain that has grown
    // too deep, and is only ever chosen above when the transport is
    // atomic-capable AND the head write is CAS-conditioned. A failed advance
    // leaves the head untouched.
    let action = if rebaseline {
        ChainAction::ResetSelfContained
    } else {
        ChainAction::Append {
            self_contained: plan.self_contained,
        }
    };
    advance_packmap(tx, branch, pack_key, action, resolved_chain, condition, tip)
}

/// [`pull_all_with`] with signature verification on — the CLI's default
/// (issue #692). Existing in-process callers (the integration-test suite)
/// that construct only validly-signed histories are unaffected.
pub fn pull_all(
    cwd: &Path,
    tx: &dyn Transport,
    remote: &str,
    target_branch: Option<&str>,
) -> Result<usize, DispatchError> {
    pull_all_with(cwd, tx, remote, target_branch, true)
}

/// Fetch remote refs, then fast-forward the current local branch from
/// `refs/remotes/default/<branch>`. Fresh repos with no local branch tip
/// initialise from the current branch's remote-tracking ref, or the first
/// advertised remote branch when the current default branch is absent.
///
/// `target_branch`, when `Some`, overrides which remote branch to land
/// on (used by `mkit clone -b <branch>`): the branch MUST exist among
/// the remote's advertised refs or the call fails with
/// [`DispatchError::RemoteBranchMissing`] rather than silently falling
/// back to another branch. `None` preserves the historical HEAD-driven
/// selection used by plain `pull`.
///
/// `require_signed` gates the post-fetch commit/remix/tag signature check
/// (issue #692) — `true` (the CLI's default, see [`pull_all`]) verifies
/// every newly-fetched object and fails closed; `false` is the explicit
/// `--no-verify-signatures` / `pull.require_signed = false` opt-out.
pub fn pull_all_with(
    cwd: &Path,
    tx: &dyn Transport,
    remote: &str,
    target_branch: Option<&str>,
    require_signed: bool,
) -> Result<usize, DispatchError> {
    let layout = mkit_core::layout::discover(cwd)?;
    let store = crate::commands::open_store_configured(&layout)?;
    // Fetch phase: `fetch_objects` takes the repo lock itself, narrowly and
    // per branch, around only the local unpack + remote-ref-publish window
    // (#642 — see `packmap::apply_fetched_chain`). No lock is held here
    // across the network transfer.
    let n = fetch_objects(&store, &layout, tx, remote, require_signed)?;
    let remote_refs = refs::list_remote_refs(&layout, remote)?
        .into_iter()
        .filter_map(|r| r.hash.map(|hash| (r.name, hash)))
        .collect::<Vec<_>>();
    if remote_refs.is_empty() {
        return Ok(n);
    }

    // Fast-forward phase (#642): branch ref + HEAD + worktree, narrowly
    // locked around just this window rather than bundled with the fetch
    // above. The objects `remote_tip` points at are already reachable via
    // the remote-tracking ref published during the fetch phase, so this
    // lock's job here is worktree-mutation exclusivity against concurrent
    // commands (e.g. a racing `commit`/`checkout`/`reset`), not GC
    // protection — that hazard was already closed before this lock was
    // taken.
    let _lock = mkit_core::repo_lock::acquire_default(
        layout.worktree_state_dir(),
        crate::commands::WORKTREE_LOCK,
    )?;
    let original_head = refs::read_head(&layout).ok();
    let (branch, local_tip, remote_tip) = match &original_head {
        Some(Head::Branch(head_branch)) => {
            let want_branch = target_branch.unwrap_or(head_branch.as_str());
            let local_tip = refs::read_ref(&layout, want_branch)?;
            let selected = if local_tip.is_some() || target_branch.is_some() {
                // An explicit `-b <branch>` (or an already-committed local
                // branch of that name) must match exactly — no silent
                // fallback to a different branch.
                remote_refs
                    .iter()
                    .find(|(name, _)| name == want_branch)
                    .ok_or_else(|| DispatchError::RemoteBranchMissing(want_branch.to_owned()))?
            } else {
                remote_refs
                    .iter()
                    .find(|(name, _)| name == want_branch)
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
    crate::commands::ensure_restore_safe(&layout, &store, tree)
        .map_err(DispatchError::RestoreSafety)?;
    crate::commands::write_ref_recording_history(&layout, &branch, ref_condition, &remote_tip)?;
    if let Err(e) = refs::write_head_branch(&layout, &branch) {
        rollback_pull_ref(&layout, &branch, local_tip, remote_tip)?;
        return Err(e.into());
    }
    if let Err(e) = crate::commands::restore_worktree_and_index(&layout, &store, tree) {
        if let Err(rollback) =
            rollback_pull_ref_and_head(&layout, &branch, local_tip, remote_tip, original_head)
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
    layout: &RepoLayout,
    branch: &str,
    local_tip: Option<Hash>,
    remote_tip: Hash,
    original_head: Option<Head>,
) -> Result<(), String> {
    rollback_pull_ref(layout, branch, local_tip, remote_tip).map_err(|e| e.to_string())?;
    match original_head {
        Some(Head::Branch(name)) => refs::write_head_branch(layout, &name),
        Some(Head::Detached(hash)) => refs::write_head_detached(layout, &hash),
        None => Ok(()),
    }
    .map_err(|e| e.to_string())
}

fn rollback_pull_ref(
    layout: &RepoLayout,
    branch: &str,
    local_tip: Option<Hash>,
    remote_tip: Hash,
) -> Result<(), refs::RefError> {
    if let Some(local_tip) = local_tip {
        crate::commands::write_ref_recording_history(
            layout,
            branch,
            refs::RefWriteCondition::Match(remote_tip),
            &local_tip,
        )
    } else if refs::read_ref(layout, branch)? == Some(remote_tip) {
        refs::delete_ref(layout, branch)
    } else {
        Ok(())
    }
}

/// [`fetch_all_with`] with signature verification on — the CLI's default
/// (issue #692). Existing in-process callers (the integration-test suite)
/// that construct only validly-signed histories are unaffected.
pub fn fetch_all(cwd: &Path, tx: &dyn Transport, remote: &str) -> Result<usize, DispatchError> {
    fetch_all_with(cwd, tx, remote, true)
}

/// `fetch` — `pull_all` without the HEAD update. Downloads every object
/// reachable from each remote ref (via [`Transport::download_pack`] on
/// the object's own digest) and writes the ref into
/// `refs/remotes/default/<branch>`.
///
/// See [`pull_all_with`] for the `require_signed` contract (issue #692).
pub fn fetch_all_with(
    cwd: &Path,
    tx: &dyn Transport,
    remote: &str,
    require_signed: bool,
) -> Result<usize, DispatchError> {
    let layout = mkit_core::layout::discover(cwd)?;
    // No outer lock here (#642): `fetch_objects` takes the repo lock
    // itself, narrowly and per branch, around only the local unpack +
    // remote-ref-publish window for that branch — never across the
    // network transfer. See `packmap::resolve_and_download_chain` /
    // `apply_fetched_chain` and `fetch_objects_inner` below.
    let store = crate::commands::open_store_configured(&layout)?;
    fetch_objects(&store, &layout, tx, remote, require_signed)
}

/// Reconstruct every remote `refs/heads/*` from its packmap chain and
/// publish the remote-tracking refs. Each branch's local object writes and
/// its ref publish happen under a repo lock acquired fresh for that branch
/// (#642) — see [`fetch_objects_inner`] — so the caller does NOT need to
/// hold the repo lock around this call.
///
/// mkit speaks a single, packmap-only transfer dialect (the legacy
/// per-object download path was removed): for every advertised branch the
/// flow is exactly
///
/// 1. read the branch's packmap ref (`refs/mkit/packmap/<branch>`),
/// 2. walk its chain oldest-first and download any pack the local
///    applied-pack record doesn't already have
///    ([`packmap::resolve_and_download_chain`]) — no repo lock held,
/// 3. acquire the repo lock, unpack the downloaded packs
///    ([`packmap::apply_fetched_chain`]), then
/// 4. assert the tip's closure is fully present
///    ([`verify_closure_present`]) — a pure integrity check that downloads
///    nothing (still under the lock from step 3), then publish the
///    branch's remote-tracking ref and release the lock (#642).
///
/// Steps 3 and 4 are both performed *inside* [`packmap::apply_fetched_chain`]
/// (rather than sequenced here) so a closure-completeness failure counts
/// toward that function's applied-pack self-heal retry (#409): if the
/// local record wrongly claims every pack in the chain is already applied
/// (e.g. `.mkit/objects` was wiped out-of-band while `applied-packs/`
/// survived), the very first symptom is exactly this closure check
/// failing, not a download/unpack error — the retry has to cover both.
///
/// Both ends fail loudly: an absent packmap is [`DispatchError::PackmapMissing`]
/// and a present-but-incomplete packmap (even after the self-heal retry) is
/// [`DispatchError::RemoteMissingObject`]. We never publish a
/// remote-tracking ref to a closure we couldn't fully materialise locally.
///
/// # Concurrent re-baseline (mkit #521)
///
/// We list branch tips (`list_refs`) BEFORE reading each branch's packmap,
/// so a concurrent push that re-baselines (resets the packmap to a fresh
/// single node, #406) between those two reads can leave us verifying an
/// OLD tip `h` against a packmap whose closure only covers the NEW tip —
/// surfacing as [`DispatchError::RemoteMissingObject`] (the reset chain
/// isn't a superset of the prior one, and the applied-pack self-heal can't
/// rescue a genuinely stale tip). This is transient — no bad ref was
/// published — so on that specific error we re-read the branch's CURRENT tip
/// and packmap and retry the chain once with the fresh pair, publishing the
/// fresh tip. A second failure (or a vanished branch) propagates unchanged.
///
/// # Applied-packs record: load once, persist once (mkit #546)
///
/// The applied-pack record (`<common dir>/applied-packs/<remote>`, #409) is
/// keyed by remote, not by branch, so this function — not
/// [`packmap::resolve_and_download_chain`] / [`packmap::apply_fetched_chain`]
/// — owns its lifecycle for the WHOLE fetch: loaded once before the branch
/// loop, persisted once after, however many branches are fetched. Those two
/// functions only mutate the record in memory (inserting applied digests,
/// or clearing on self-heal); neither touches disk. The final persist is
/// unconditional and best-effort — it runs on every outcome so a fetch that
/// applied packs before failing never loses that progress, and the record
/// is a pure performance cache whose own I/O must never fail a fetch whose
/// objects durably landed.
///
/// # Repo-lock scope (mkit #642)
///
/// Each branch acquires the repo lock fresh, right before
/// [`packmap::apply_fetched_chain`] unpacks that branch's downloaded packs,
/// and releases it right after the branch's remote-tracking ref is
/// published — see [`fetch_objects_inner`]. Nothing here holds the lock
/// during [`packmap::resolve_and_download_chain`]'s network I/O, and the
/// lock is released between branches, so only the local write + ref-publish
/// window for one branch at a time is ever locked. This still closes the
/// #267 GC-prune race: `gc` takes the very same lock before computing its
/// live set, so it can never observe a branch's objects on disk without
/// that branch's ref already published.
fn fetch_objects(
    store: &ObjectStore,
    layout: &RepoLayout,
    tx: &dyn Transport,
    remote: &str,
    require_signed: bool,
) -> Result<usize, DispatchError> {
    let mut applied = AppliedPacks::load_or_empty(layout, remote);
    let result = fetch_objects_inner(store, layout, tx, remote, &mut applied, require_signed);
    persist_record(&mut applied, remote);
    result
}

/// The branch loop proper — see [`fetch_objects`] for the load-once /
/// persist-once applied-packs contract this is called under.
fn fetch_objects_inner(
    store: &ObjectStore,
    layout: &RepoLayout,
    tx: &dyn Transport,
    remote: &str,
    applied: &mut AppliedPacks,
    require_signed: bool,
) -> Result<usize, DispatchError> {
    let remote_refs = tx.list_refs("refs/heads/")?;
    let mut n = 0;
    // Batch every fetched branch's remote-tracking-ref write (#645): see
    // `push_all_with` for the same pattern and its rationale. `tracking.write`
    // still runs inside this branch's `_lock` scope below, so ref visibility
    // timing is unchanged from the per-branch-publish-then-unlock model
    // (#642) — only the parent-directory fsync is deferred to one pass after
    // the loop. GC's #267 protection is unaffected: it depends on the
    // repo lock covering the object-write-to-ref-publish window (still true
    // per branch below), not on when the ref directory itself is fsynced.
    let mut tracking = refs::RemoteRefBatch::new(layout, remote)?;
    let result: Result<(), DispatchError> = (|| {
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

            // Phase 1 (#642): resolve this branch's chain and download its
            // packs — pure network I/O, no repo lock held (see
            // `packmap::resolve_and_download_chain`).
            let fetched = resolve_and_download_chain(tx, &r.name, chain_head, applied)?;

            // Phase 2 (#642): unpack + verify + publish this branch's ref,
            // under a repo lock acquired fresh for this branch and released
            // once this loop iteration ends — never held across another
            // branch's download. See `packmap::apply_fetched_chain`'s doc
            // comment for the safety contract (closing the #267 GC-prune
            // race) this depends on.
            let lock = mkit_core::repo_lock::acquire_default(
                layout.worktree_state_dir(),
                crate::commands::WORKTREE_LOCK,
            )?;
            // The tip we publish: normally the listed `h`, but if the chain fails
            // because a concurrent re-baseline moved the branch under us, the
            // freshly re-read tip (see this fn's doc comment). The match also
            // carries the lock guard out, so whichever branch runs, the
            // correct (possibly re-acquired) guard is what's held at
            // `tracking.write` below — see the retry branch's comment for why
            // there are two guards, not one held across the whole match.
            let (published_tip, _lock) = match apply_fetched_chain(
                store,
                tx,
                remote,
                &r.name,
                fetched,
                h,
                applied,
                require_signed,
            ) {
                Ok(()) => (h, lock),
                Err(e @ DispatchError::RemoteMissingObject(_)) => {
                    // Re-read the branch's CURRENT tip + packmap. If either
                    // is gone (branch deleted mid-fetch) the original error
                    // stands. Otherwise retry the chain ONCE with the fresh
                    // pair; a second failure propagates via `?`.
                    let (Some(fresh_h), Some(fresh_head)) = (
                        tx.read_ref(&format!("refs/heads/{}", r.name))?,
                        tx.read_ref(&packmap_ref(&r.name))?,
                    ) else {
                        return Err(e);
                    };
                    // Release the lock for the retry's network
                    // re-download too — mirrors phase 1's unlocked
                    // download exactly, rather than the previously
                    // "accepted trade" of holding the lock across a
                    // second network round-trip on this rare
                    // race-recovery path. Re-acquire before the
                    // retry's local unpack + publish, which still
                    // needs the same #267 protection phase 2 always
                    // has.
                    drop(lock);
                    let fresh_fetched =
                        resolve_and_download_chain(tx, &r.name, fresh_head, applied)?;
                    let lock = mkit_core::repo_lock::acquire_default(
                        layout.worktree_state_dir(),
                        crate::commands::WORKTREE_LOCK,
                    )?;
                    apply_fetched_chain(
                        store,
                        tx,
                        remote,
                        &r.name,
                        fresh_fetched,
                        fresh_h,
                        applied,
                        require_signed,
                    )?;
                    (fresh_h, lock)
                }
                Err(e) => return Err(e),
            };
            // Still inside `_lock`'s scope (the original guard, or the
            // retry's re-acquired one — see above).
            tracking.write(&r.name, &published_tip)?;
            n += 1;
        }
        Ok(())
    })();
    // Commit whatever tracking-ref writes succeeded regardless of how the
    // loop above ended — a mid-loop failure still durably publishes the
    // prefix that already verified successfully, matching the old
    // per-branch loop's per-write durability.
    tracking.commit()?;
    result?;
    Ok(n)
}

/// Best-effort persist of `applied` (a write failure is logged and
/// swallowed), called exactly once per fetch — see [`fetch_objects`] for
/// the load-once / persist-once contract.
fn persist_record(applied: &mut AppliedPacks, remote: &str) {
    if let Err(e) = applied.persist() {
        eprintln!(
            "warning: could not persist applied-packs record for remote '{remote}' ({e}); it will be rebuilt on the next fetch"
        );
    }
}

/// Assert that every object reachable from `tip` is already present in the
/// local store after the packmap chain has been unpacked. This is a pure
/// integrity check — it walks the closure via
/// [`mkit_core::ops::reachable_closure_checked`] (which reads each object and
/// re-verifies its digest) and performs NO network access. A reachable object
/// that the chain failed to deliver surfaces as [`StoreError::ObjectNotFound`],
/// which we re-tag as [`DispatchError::RemoteMissingObject`] so the fetch
/// aborts loudly rather than publishing a ref to a closure we can't
/// reconstruct.
///
/// When packs were skipped (the applied-pack fast path, #409) this walk is
/// the *sole* guarantee the store is complete, so it must not silently pass
/// on an unverified frontier: a closure exceeding the
/// [`mkit_core::ops::graph::MAX_REACHABLE`] cap leaves objects past the cap
/// unchecked, which over a partially-wiped store could hide missing objects.
/// We therefore surface truncation as a hard [`DispatchError::ClosureTooLarge`]
/// rather than dropping the flag. `ClosureTooLarge` is deliberately distinct
/// from `RemoteMissingObject` so it does NOT feed the self-heal retry — a
/// too-large history is not evidence of local staleness.
///
/// Called from [`packmap::fetch_pack_chain`] (not sequenced after it) so its
/// `RemoteMissingObject` result participates in that function's applied-pack
/// self-heal retry — see [`fetch_objects`]'s doc comment.
pub(crate) fn verify_closure_present(store: &ObjectStore, tip: &Hash) -> Result<(), DispatchError> {
    match mkit_core::ops::reachable_closure_checked(store, std::iter::once(tip)) {
        Ok((_, false)) => Ok(()),
        Ok((_, true)) => Err(DispatchError::ClosureTooLarge(
            mkit_core::ops::graph::MAX_REACHABLE,
        )),
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

#[cfg(test)]
mod tests {
    use super::ssh_options_from_config;
    use crate::config::Config;

    /// The three `ssh.*` trust-pinning keys, when set in `Config`, must
    /// map 1:1 into the `SshOptions` carried to the spawned `ssh(1)`
    /// child. This is the producer half of issue #389: without it the
    /// keys are parsed but never reach the subprocess.
    #[test]
    fn populated_config_maps_to_ssh_options() {
        let cfg = Config {
            ssh_strict_host_key_checking: "yes".to_string(),
            ssh_user_known_hosts_file: "/path/to/project.known_hosts".to_string(),
            ssh_identity_file: "/path/to/id_ed25519".to_string(),
            ..Config::default()
        };
        let opts = ssh_options_from_config(&cfg);
        assert_eq!(opts.strict_host_key_checking, "yes");
        assert_eq!(opts.user_known_hosts_file, "/path/to/project.known_hosts");
        assert_eq!(opts.identity_file, "/path/to/id_ed25519");
    }

    /// Empty `ssh.*` fields must map to empty `SshOptions` fields so
    /// `build_ssh_command` emits NO `-o`/`-i` flags and the user's
    /// `ssh(1)` defaults are inherited unchanged.
    #[test]
    fn empty_config_maps_to_empty_ssh_options() {
        let opts = ssh_options_from_config(&Config::default());
        assert!(opts.strict_host_key_checking.is_empty());
        assert!(opts.user_known_hosts_file.is_empty());
        assert!(opts.identity_file.is_empty());
    }
}
