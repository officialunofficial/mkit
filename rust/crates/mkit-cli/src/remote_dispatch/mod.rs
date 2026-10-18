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

mod envelope_signer;
pub(crate) mod grants;
mod packmap;

mod upload_receipts;

use mkit_core::layout::RepoLayout;
use std::path::Path;
use std::sync::Arc;

use mkit_core::hash::Hash;
use mkit_core::ops::merge::is_ancestor;
use mkit_core::ops::restore;
use mkit_core::pack::{self, PackError};
use mkit_core::protocol::{Transport, TransportError};
use mkit_core::refs;
use mkit_core::store::{ObjectStore, StoreError};
use mkit_core::transfer::PackListError;
use mkit_transport_connect::admission::{AdmissionPolicy, is_reserved};
use mkit_transport_connect::{
    ConnectTransport, PENDING_INTERRUPTED_MESSAGE, remote_identity_from_url,
};
use mkit_transport_file::FileTransport;
use mkit_transport_s3::S3Transport;
use mkit_transport_ssh::{SshInitError, SshOptions, SshTransport, parse_mkit_ssh_url};

pub use mkit_sync::push::{MAX_CHAIN_COMMITS, MAX_SPLIT_STEPS, PushControl, StepAuthority};

use packmap::rebaseline_depth;

const DEFAULT_REMOTE: &str = "default";

/// Errors returned by the push / pull helpers. Mapped to exit codes by
/// the commands themselves.
#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    #[error("unsupported URL scheme: {0}")]
    UnsupportedScheme(String),
    #[error("malformed URL: {0}")]
    MalformedUrl(String),
    #[error(
        "repository `{identity}` not found at {origin}; check the remote URL path against the server's configured name (an empty path selects `default` on a single-repository deployment)"
    )]
    RepositoryNotFound {
        identity: String,
        origin: String,
        source: mkit_sync::SourceError,
    },
    #[error("no HEAD branch to push")]
    NoHead,
    /// A poll-loop checkpoint observed `signal::is_shutdown() == true`
    /// and aborted partway through. Callers should map this to
    /// `exit::TEMPFAIL` (75) so retries are safe — the transfer is
    /// half-finished but the remote is unmodified for any ref we
    /// hadn't reached yet.
    #[error("interrupted")]
    Interrupted,
    #[error("{0}")]
    UploadInterrupted(String),
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    #[error("transport: {0}")]
    Source(#[source] mkit_sync::SourceError),
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
    PackChainInvalid {
        branch: String,
        source: Option<mkit_sync::SourceError>,
    },
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
    AdvertisedPackMissing {
        branch: String,
        pack: String,
        source: mkit_sync::SourceError,
    },
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
    /// One advance would need more data packs than the server permits per
    /// advance. `commit` names the single commit or merge that cannot be split
    /// further when the refusal came from the pre-flight dry seal, before
    /// anything was published; without it the seal-time backstop fired.
    #[error(
        "push needs {packs} data packs but this server permits {limit} per advance{}{}; ask the operator to raise max_pack_bytes",
        .commit.as_ref().map_or_else(String::new, |c| format!(" ({c} cannot be split further)")),
        if *.holds_remote_head {
            " (it is the first commit that contains the remote head: rebase onto the remote head, or merge it in a smaller or earlier commit)"
        } else {
            ""
        }
    )]
    PushTooLarge {
        packs: usize,
        limit: usize,
        commit: Option<String>,
        /// The unsplittable commit is the first that contains the remote head,
        /// so the split could not cut before it.
        holds_remote_head: bool,
    },
    /// A retry of one advance (a rejected ticket, a lost delta base) re-planned
    /// the push and the new plan no longer fits one advance. Found by a dry
    /// seal, so nothing was uploaded for the retry.
    #[error(
        "{reason}, and the retry needs {packs} data packs but this server permits {limit} per advance; nothing was uploaded for the retry"
    )]
    RetryTooLarge {
        reason: RetryReason,
        packs: usize,
        limit: usize,
    },
    /// A split push would exceed a bound (steps or chain length). Nothing was
    /// published.
    #[error("{0}")]
    PushSplitLimit(String),
    /// The stored grants do not authorize every advance of a split push.
    /// Nothing was published.
    #[error("{0}")]
    PushNotAuthorized(String),
    /// Force push refused before upload because discovery was unavailable.
    #[error(
        "force push requires successful atomic-advance capability discovery; reconnect and retry"
    )]
    ForceCapabilityUnknown,
    /// A split push failed after publishing some advances. `head` is the last
    /// advance this push published, a first-parent ancestor of the local tip
    /// (another pusher may have moved the branch since); re-running the push
    /// resumes from the remote branch unless a concurrent push caused the
    /// failure.
    #[error(
        "{cause}; {published} of {total} advances were published and the last published advance was {head} on branch '{branch}'{}",
        resume_hint(.cause)
    )]
    SplitInterrupted {
        branch: String,
        head: String,
        published: usize,
        total: usize,
        cause: Box<DispatchError>,
    },
    #[error("upload ticket was rejected after the push was retried")]
    TicketRejected,
    #[error("delta base is unavailable after a restart")]
    DeltaBaseUnavailable,
    #[error("packlist still names a pack absent from this repository after retry")]
    PacklistNotInRepository,
}

/// The closing advice of a split push's failure: resume, unless the failure
/// was a concurrent push (the branch then moved, and a re-run would only
/// compare against whatever the other pusher left).
fn resume_hint(cause: &DispatchError) -> &'static str {
    if matches!(cause, DispatchError::NonFastForwardPush { .. }) {
        "; the branch was moved by another push, so fetch and merge before pushing again"
    } else {
        "; re-run the push to resume"
    }
}

pub use mkit_sync::push::RetryReason;

/// The advances a split push published before it failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedPrefix {
    pub branch: String,
    pub published: usize,
    pub total: usize,
    pub head: String,
    /// Whether re-running the push is the advice (not after a concurrent push).
    pub resumable: bool,
}

impl PublishedPrefix {
    /// The note printed with any failure that left a prefix published.
    #[must_use]
    pub fn note(&self) -> String {
        format!(
            "{} of {} advances were published; the last published advance on branch '{}' was {}{}",
            self.published,
            self.total,
            self.branch,
            self.head,
            if self.resumable {
                "; re-run the push to resume"
            } else {
                "; the branch was moved by another push, so fetch and merge before pushing again"
            }
        )
    }
}

impl DispatchError {
    /// The error a split push failed with, without its published-prefix
    /// wrapper, and that prefix (`None` when no advance of this branch was published).
    #[must_use]
    pub fn into_published_prefix(self) -> (Self, Option<PublishedPrefix>) {
        match self {
            Self::SplitInterrupted {
                branch,
                head,
                published,
                total,
                cause,
            } => {
                let resumable = !matches!(*cause, Self::NonFastForwardPush { .. });
                (
                    *cause,
                    Some(PublishedPrefix {
                        branch,
                        published,
                        total,
                        head,
                        resumable,
                    }),
                )
            }
            other => (other, None),
        }
    }
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
/// `envelope_signer_from_config`) — every caller already has it at
/// hand (it discovered the repo before building `cfg`).
pub fn open_trusted(
    endpoint: &str,
    remote_name: &str,
    repo_chosen: bool,
    cfg: &crate::config::LayeredConfig,
    layout: &RepoLayout,
) -> Result<Remote, DispatchError> {
    crate::config::endpoint_credential_trust(cfg, endpoint, repo_chosen)
        .map_err(DispatchError::UntrustedRemote)?;
    open_with_config_for_remote(endpoint, &cfg.merged, layout, Some(remote_name))
}

/// A configured native remote. Connect operations use `ClientSource`; other
/// schemes retain their synchronous transport adapter.
pub enum Remote {
    Connect(Arc<ConnectTransport>),
    Transport(Arc<dyn Transport>),
}

impl std::fmt::Debug for Remote {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Remote")
            .field("connect", &matches!(self, Self::Connect(_)))
            .finish_non_exhaustive()
    }
}

impl Remote {
    /// Lend the configured source for one repository operation.
    ///
    /// # Errors
    /// The host adapter cannot prepare the operation.
    pub fn with_source<R>(
        &self,
        operation: impl FnOnce(&dyn mkit_sync::RemoteSource) -> R,
    ) -> Result<R, DispatchError> {
        match self {
            Self::Connect(transport) => transport.with_source(operation).map_err(Into::into),
            Self::Transport(transport) => Ok(operation(&cli_source(transport.as_ref()))),
        }
    }

    /// Bounds used for interruption guidance, from cached discovery.
    #[must_use]
    pub fn upload_limits(&self) -> mkit_core::protocol::UploadLimits {
        match self {
            Self::Connect(transport) => transport.upload_limits(),
            Self::Transport(transport) => transport.upload_limits(),
        }
    }
}

/// A remote opened for `mkit push`: the transport, and (for a signing Connect
/// client) the check that its stored grants authorize every advance of a split
/// push.
pub(crate) struct PushRemote {
    pub tx: Remote,
    pub authority: Option<Arc<dyn StepAuthority>>,
}

/// [`open_trusted`] for a push: the same trust gate and transport, plus the
/// grant pre-check a split push needs (WP-1.17b, B5).
///
/// # Errors
/// As [`open_trusted`].
pub(crate) fn open_trusted_for_push(
    endpoint: &str,
    remote_name: &str,
    repo_chosen: bool,
    cfg: &crate::config::LayeredConfig,
    layout: &RepoLayout,
) -> Result<PushRemote, DispatchError> {
    crate::config::endpoint_credential_trust(cfg, endpoint, repo_chosen)
        .map_err(DispatchError::UntrustedRemote)?;
    if !is_connect_url(endpoint) {
        return Ok(PushRemote {
            tx: open_with_config_for_remote(endpoint, &cfg.merged, layout, Some(remote_name))?,
            authority: None,
        });
    }
    let parts = open_connect_parts(endpoint, &cfg.merged, layout, Some(remote_name), true)?;
    let tx = Arc::new(parts.transport);
    let authority = parts
        .signer_key
        .zip(parts.grants)
        .map(|(signer_key, grants)| {
            Arc::new(grants::ConnectAuthority {
                transport: tx.clone(),
                grants,
                signer_key,
            }) as Arc<dyn StepAuthority>
        });
    Ok(PushRemote {
        tx: Remote::Connect(tx),
        authority,
    })
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
) -> Result<Remote, DispatchError> {
    open_with_config_for_remote(url, cfg, layout, None)
}

fn open_with_config_for_remote(
    url: &str,
    cfg: &crate::config::Config,
    layout: &RepoLayout,
    remote_name: Option<&str>,
) -> Result<Remote, DispatchError> {
    if is_connect_url(url) {
        return Ok(Remote::Connect(Arc::new(open_connect_with_config(
            url,
            cfg,
            layout,
            remote_name,
            true,
        )?)));
    }
    open_with_ssh_options(url, &ssh_options_from_config(cfg), None).map(Remote::Transport)
}

fn is_connect_url(url: &str) -> bool {
    url.starts_with("mkit+https://") || url.starts_with("mkit+http://")
}

/// [`open_trusted`] for a Connect endpoint, returning the concrete
/// [`ConnectTransport`] so callers can reach the epoch and visibility RPCs
/// (WP-2.14). `sign` chooses whether the ambient signing identity is used:
/// `mkit epoch` and statement-mode `mkit visibility set` send unsigned RPCs
/// and pass `false`; envelope-mode visibility passes `true` and so needs
/// `transport_auth = envelope` and a trusted remote, like `mkit push`.
///
/// # Errors
/// The credential-trust gate, a non-Connect endpoint, or connection setup.
pub(crate) fn open_connect_trusted(
    endpoint: &str,
    remote_name: &str,
    repo_chosen: bool,
    cfg: &crate::config::LayeredConfig,
    layout: &RepoLayout,
    sign: bool,
) -> Result<ConnectTransport, DispatchError> {
    crate::config::endpoint_credential_trust(cfg, endpoint, repo_chosen)
        .map_err(DispatchError::UntrustedRemote)?;
    if !is_connect_url(endpoint) {
        return Err(DispatchError::UnsupportedScheme(format!(
            "`{endpoint}` is not an mkit+https:// or mkit+http:// remote; grant epochs and repository visibility are served over Connect"
        )));
    }
    open_connect_with_config(endpoint, &cfg.merged, layout, Some(remote_name), sign)
}

/// Build the Connect transport for `url` from `cfg`: envelope signing (when
/// `sign` and configured), the user grant store as the `GrantSource`, the
/// upload receipt store, progress observers and the admission helper.
pub(crate) fn open_connect_with_config(
    url: &str,
    cfg: &crate::config::Config,
    layout: &RepoLayout,
    remote_name: Option<&str>,
    sign: bool,
) -> Result<ConnectTransport, DispatchError> {
    Ok(open_connect_parts(url, cfg, layout, remote_name, sign)?.transport)
}

/// A Connect transport with what a push needs to check its authority.
struct ConnectParts {
    transport: ConnectTransport,
    /// The user grants installed on the transport (none without a signer).
    grants: Option<Arc<grants::LocalGrants>>,
    /// The signing key's public hex, when requests are signed.
    signer_key: Option<String>,
}

fn open_connect_parts(
    url: &str,
    cfg: &crate::config::Config,
    layout: &RepoLayout,
    remote_name: Option<&str>,
    sign: bool,
) -> Result<ConnectParts, DispatchError> {
    let envelope_signer = if sign {
        if cfg.transport_auth_envelope() && cfg.trusted_remote_endpoint.trim() != url {
            return Err(DispatchError::UntrustedRemote(format!(
                "refusing request signing for untrusted destination `{url}`; run `mkit config trusted_remote_endpoint {url}` before using ambient signing identity"
            )));
        }
        envelope_signer_from_config(cfg, layout)?
    } else {
        None
    };
    validate_connect_repository(url)?;
    let signed = envelope_signer.is_some();
    let signer_key = envelope_signer
        .as_ref()
        .map(|signer| signer.public_key_hex());
    // Resolve only the selected config fallback: an authoritative environment
    // path must not be defeated by an ignored fallback's tilde/HOME error.
    let ca_file = if url.starts_with("mkit+https://")
        && std::env::var_os(mkit_transport_connect::tls::CA_FILE_ENV).is_none()
    {
        cfg.ssl_ca_file_path(layout).map_err(|error| {
            DispatchError::Transport(TransportError::TlsConfiguration(error.to_string()))
        })?
    } else {
        None
    };
    let mut tx = ConnectTransport::connect_with_signer_and_ca_file(
        url,
        envelope_signer,
        ca_file.as_deref(),
    )?
    .with_receipt_store(Arc::new(upload_receipts::FilePartReceiptStore::new(
        layout.upload_parts_dir(),
    )))
    .with_pending_observer(|event| {
        crate::progress::pending_event(event);
        !crate::signal::is_shutdown()
    })
    .with_upload_observer(|event| {
        crate::progress::upload_event(event);
        !crate::signal::is_shutdown()
    })
    .with_admission_receipt_observer(|receipt| {
        eprintln!(
            "note: remote returned a {} receipt for {}",
            receipt.header,
            receipt
                .procedure
                .rsplit('/')
                .next()
                .unwrap_or(receipt.procedure)
        );
    });
    // Grants ride only on signed requests (SPEC-WRITE-GRANTS §4.2), so the
    // store is read only when there is a signer to present them with.
    let grants = signed.then(|| Arc::new(grants::LocalGrants::from_stored(load_user_grants(cfg))));
    if let Some(grants) = &grants {
        tx = tx.with_grant_source(grants.clone());
    }
    if !cfg.admission_helper.is_empty() && cfg.trusted_remote_endpoint.trim() == url {
        let responder = Arc::new(crate::admission_helper::ExecResponder {
            path: cfg.admission_helper.clone().into(),
        });
        let mut policy = AdmissionPolicy::new(responder);
        if let Some(name) = remote_name
            && let Some(headers) = cfg.remote_admission_headers.get(name)
        {
            let bearer = std::env::var("MKIT_API_TOKEN").is_ok_and(|s| !s.is_empty());
            for header in headers.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                if is_reserved(header, bearer) {
                    eprintln!(
                        "warning: ignoring reserved header `{header}` in remote.{name}.admission_headers (see SPEC-TRANSPORT-CONNECT §5.1)"
                    );
                } else {
                    policy = policy.with_extra_allowed(header);
                }
            }
        }
        tx = tx.with_admission(policy);
    }
    Ok(ConnectParts {
        transport: tx,
        grants,
        signer_key,
    })
}

/// The verified grants in the user store, one warning per skipped file.
fn load_user_grants(cfg: &crate::config::Config) -> Vec<crate::grants::store::StoredGrant> {
    let rps = crate::grants::parse_relying_parties(&cfg.grant_webauthn_rp).unwrap_or_else(|e| {
        eprintln!("warning: grant.webauthn_rp: {e}; treating no relying party as pinned");
        Vec::new()
    });
    let store = match crate::grants::store::GrantStore::open_default() {
        Ok(store) => store,
        Err(e) => {
            eprintln!("warning: {e}; using no stored grants");
            return Vec::new();
        }
    };
    let report = store.load(&rps);
    for warning in &report.warnings {
        eprintln!("warning: {warning}");
    }
    report.grants
}

/// The configured mkit signing key as an owner signer for `mkit grant`,
/// `mkit epoch` and `mkit visibility`. Same key resolution as
/// [`envelope_signer_from_config`], without its `transport_auth` gate: the
/// owner asked for this signature explicitly.
pub(crate) fn owner_ed25519_signer(
    cfg: &crate::config::Config,
    layout: &RepoLayout,
) -> Result<Arc<dyn mkit_transport_connect::EnvelopeSigner>, String> {
    match cfg.signer.as_str() {
        "" | "legacy" => {
            let key_path = crate::config::resolve_key_path(layout, &cfg.signing_key)
                .map_err(|e| format!("signing_key: {e}"))?;
            if !key_path.exists() {
                return Err(format!(
                    "no signing key at {} — run `mkit keygen` first",
                    key_path.display()
                ));
            }
            let kp = mkit_core::sign::load_key(&key_path).map_err(|e| format!("load key: {e}"))?;
            Ok(Arc::new(envelope_signer::RepoKeyEnvelopeSigner::new(kp)))
        }
        "keystore" => Ok(Arc::new(envelope_signer::KeystoreEnvelopeSigner::open(
            cfg,
        )?)),
        other => Err(format!(
            "unknown signer `{other}` — expected `legacy` or `keystore`"
        )),
    }
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
/// into [`ConnectTransport::connect_with_signer`]. Reached via [`open`]
/// (no config — both `None`/default) and [`open_with_config`] for non-Connect
/// schemes; `open_with_config` handles Connect URLs itself, so the Connect
/// branch here is reached only from [`open`].
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
        validate_connect_repository(url)?;
        // ConnectTransport::connect_with_signer strips the `mkit+` prefix
        // itself and reads MKIT_API_TOKEN from the environment (mkit#701 —
        // the native mkit.transport.v1 ConnectRPC client, replacing the
        // retired mkit-transport-http JSON dialect as of
        // SPEC-TRANSPORT-CONNECT verb parity). Only the config-less `open`
        // reaches this branch (`open_with_config` returns early for Connect
        // URLs), so `envelope_signer` is always `None` here; bearer token and
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
    if let Some((scheme, rest)) = url
        .split_once("://")
        .filter(|(scheme, _)| matches!(*scheme, "https" | "http"))
    {
        // Never echo URL userinfo or a query into an error message; a URL
        // carrying userinfo gets the generic form instead of a rewrite.
        let rest = rest.split(['?', '#']).next().unwrap_or(rest);
        let shown = if rest.contains('@') {
            "<host>/<namespace>/<name>"
        } else {
            rest
        };
        return Err(DispatchError::UnsupportedScheme(format!(
            "`{scheme}://{shown}` is not a sync remote: at a server's origin, plain HTTP(S) serves objects by repository path (SPEC-HTTP-OBJECTS); sync remotes use `mkit+https://`, for example `mkit+https://{shown}`"
        )));
    }
    Err(DispatchError::MalformedUrl(url.to_string()))
}

fn validate_connect_repository(url: &str) -> Result<(), DispatchError> {
    remote_identity_from_url(url).map_err(|reason| {
        // Userinfo and queries are never echoed. A URL carrying either gets a
        // generic message: its segments can't be trusted to exclude
        // credential text.
        if url.contains(['@', '?', '#']) {
            return DispatchError::MalformedUrl(
                "the remote URL is not a valid mkit+https:// remote; use mkit+https://<host>/<namespace>/<name> without userinfo or a query".to_owned(),
            );
        }
        let path = url
            .split_once("://")
            .and_then(|(_, rest)| rest.split_once('/'))
            .map_or("", |(_, path)| path)
            .trim_matches('/');
        DispatchError::MalformedUrl(format!("repository identity `{path}` in {url}: {reason}"))
    })?;
    Ok(())
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
/// process, which still works against an allow-any enc listener.
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
    push_all_with(cwd, tx, None, false, None).map(|pushed| pushed.refs)
}

/// What a successful push published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pushed {
    /// Branches pushed.
    pub refs: usize,
    /// Advances published in total (one per branch unless a push was split).
    pub steps: usize,
}

/// CAS-aware mirror push (`mkit push --all`). Pushes every local
/// `refs/heads/*` to the remote, using the remote-tracking ref under
/// `refs/remotes/<remote>/<branch>` as the CAS lease (Missing when no
/// tracking ref exists, Match otherwise). `force` upgrades every write
/// to an unconditional `Any`. On success each pushed branch's
/// remote-tracking ref is advanced to the pushed tip.
///
/// `remote` is the remote NAME used for the local tracking-ref
/// namespace; `None` means the legacy `default`. A branch too large for one
/// advance is split (see [`push_branch_steps`]); its tracking ref follows each
/// published advance, so an interrupted push resumes where it stopped.
/// `authority` is checked before a split branch uploads anything.
pub fn push_all_with(
    cwd: &Path,
    tx: &dyn Transport,
    remote: Option<&str>,
    force: bool,
    authority: Option<&dyn StepAuthority>,
) -> Result<Pushed, DispatchError> {
    push_all_with_source(cwd, &cli_source(tx), remote, force, authority)
}

pub(crate) fn push_all_with_source(
    cwd: &Path,
    source: &dyn mkit_sync::RemoteSource,
    remote: Option<&str>,
    force: bool,
    authority: Option<&dyn StepAuthority>,
) -> Result<Pushed, DispatchError> {
    let (mut options, warning) = push_options(cwd, authority)?;
    let observer = PushObserver { warning };
    options.control.observer = &observer;
    options.remote_name = remote.unwrap_or(DEFAULT_REMOTE);
    options.target = mkit_sync::PushTarget::All { force };
    let report = mkit_sync::push(cwd, source, &options)?;
    Ok(Pushed {
        refs: report.refs,
        steps: report.steps,
    })
}

fn push_options<'a>(
    cwd: &Path,
    authority: Option<&'a dyn StepAuthority>,
) -> Result<(mkit_sync::PushOptions<'a>, Option<String>), DispatchError> {
    let layout = mkit_core::layout::discover(cwd)?;
    let mut options = mkit_sync::PushOptions::default();
    if let Ok(cfg) = crate::config::read_or_default(&layout) {
        options.sync_policy = cfg.object_sync_policy();
    }
    let (depth, warning) = packmap::configured_depth();
    options.rebaseline_threshold = depth;
    options.control.authority = authority;
    options.control.observer = &CliObserver;
    Ok((options, warning))
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
pub use mkit_sync::PushLease;

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
///
/// Returns the pushed tip and the number of advances it took: more than one
/// when the push was split along first-parent history (see
/// [`push_branch_steps`]). The tracking ref follows every published advance.
#[allow(clippy::too_many_arguments)]
pub fn push_branch_tracked(
    cwd: &Path,
    tx: &dyn Transport,
    remote: &str,
    branch: &str,
    remote_branch: &str,
    lease: PushLease,
    authority: Option<&dyn StepAuthority>,
) -> Result<(Hash, usize), DispatchError> {
    push_branch_tracked_source(
        cwd,
        &cli_source(tx),
        remote,
        branch,
        remote_branch,
        lease,
        authority,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn push_branch_tracked_source(
    cwd: &Path,
    source: &dyn mkit_sync::RemoteSource,
    remote: &str,
    branch: &str,
    remote_branch: &str,
    lease: PushLease,
    authority: Option<&dyn StepAuthority>,
) -> Result<(Hash, usize), DispatchError> {
    let (mut options, warning) = push_options(cwd, authority)?;
    let observer = PushObserver { warning };
    options.control.observer = &observer;
    options.remote_name = remote;
    options.target = mkit_sync::PushTarget::Branch {
        local: branch.into(),
        remote: remote_branch.into(),
        lease,
    };
    let report = mkit_sync::push(cwd, source, &options)?;
    Ok((report.tip.ok_or(DispatchError::NotCommit)?, report.steps))
}

/// Upload and advance a selected branch through the native sync engine.
/// Does not update local tracking refs; see [`push_branch_tracked`].
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
    push_branch_with_limits(
        tx,
        store,
        branch,
        tip,
        condition,
        rebaseline_threshold,
        pack::MAX_TOTAL_PAYLOAD,
    )
}

/// [`push_branch_with_depth`] with an explicit per-pack payload cap in
/// place of the format's hardcoded [`pack::MAX_TOTAL_PAYLOAD`] (issue
/// #831). Semantics are otherwise identical — see [`push_branch`].
///
/// This is the payload-cap test seam, mirroring the #547
/// `rebaseline_threshold` pattern: integration tests inject a tiny cap
/// (a few KiB) to exercise multi-pack splitting in-process without
/// moving a multi-GiB plan through it.
pub fn push_branch_with_limits(
    tx: &dyn Transport,
    store: &ObjectStore,
    branch: &str,
    tip: Hash,
    condition: refs::RefWriteCondition,
    rebaseline_threshold: usize,
    pack_payload_cap: u64,
) -> Result<(), DispatchError> {
    push_branch_steps(
        tx,
        store,
        branch,
        tip,
        condition,
        rebaseline_threshold,
        pack_payload_cap,
        &PushControl::default(),
        &mut |_| Ok(()),
    )
    .map(drop)
}

/// [`push_branch_with_limits`] that splits a push too large for one advance
/// along the branch's first-parent history (bounded split advances), and reports each
/// published advance to `on_step` with the commit the remote branch now
/// points at. Returns the number of advances.
///
/// The split applies only when the transport ticketed-uploads
/// ([`mkit_core::protocol::UploadLimits::tickets_per_advance`]) and the conservative estimate of the
/// push's packs exceeds the data-pack budget of one advance. Otherwise this is
/// exactly one [`push_branch_with_limits`] call. When it applies, the first
/// advance uses `condition`, and every later one is a `Match` on the previous
/// advance's commit, whatever `condition` was, so a long split never
/// overwrites a concurrent pusher. Each advance uploads its own packs just
/// before it lands; nothing is pre-uploaded.
///
/// A failure after the first advance is returned as
/// [`DispatchError::SplitInterrupted`], naming the published prefix; running
/// the push again resumes from it.
///
/// # Errors
/// The wrapper retains CLI progress and cancellation; it replaces the control's observer.
/// As [`push_branch`], plus the split's own refusals (see
/// [`plan_push_steps`]), and whatever `on_step` returns.
#[allow(clippy::too_many_arguments)]
pub fn push_branch_steps(
    tx: &dyn Transport,
    store: &ObjectStore,
    branch: &str,
    tip: Hash,
    condition: refs::RefWriteCondition,
    rebaseline_threshold: usize,
    pack_payload_cap: u64,
    control: &PushControl<'_>,
    on_step: &mut dyn FnMut(Hash) -> Result<(), mkit_sync::PushError>,
) -> Result<usize, DispatchError> {
    let control = PushControl {
        authority: control.authority,
        max_steps: control.max_steps,
        max_chain: control.max_chain,
        shallow: control.shallow.clone(),
        observer: &CliObserver,
    };
    mkit_sync::push::push_branch_steps(
        &cli_source(tx),
        store,
        branch,
        tip,
        condition,
        rebaseline_threshold,
        pack_payload_cap,
        &control,
        on_step,
    )
    .map_err(Into::into)
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

/// The settings every sync call from the CLI shares: the durability schedule
/// comes from the layered config exactly as `open_store_configured` reads it,
/// so a broken config falls back to the batched default rather than changing
/// write semantics.
fn sync_options(
    cwd: &Path,
    target_branch: Option<&str>,
    require_signed: bool,
) -> Result<mkit_sync::SyncOptions, DispatchError> {
    let layout = mkit_core::layout::discover(cwd)?;
    let sync_policy = crate::config::read_or_default(&layout)
        .map_or(mkit_core::store::SyncPolicy::Batch, |cfg| {
            cfg.object_sync_policy()
        });
    Ok(mkit_sync::SyncOptions::default()
        .with_verify_signatures(require_signed)
        .with_target_branch(target_branch.map(str::to_owned))
        .with_sync_policy(sync_policy))
}

/// Fetch remote refs, then fast-forward the current local branch from
/// `refs/remotes/default/<branch>`; see [`mkit_sync::pull`] for the contract.
/// Returns the number of remote branches fetched.
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
    pull_all_with_source(cwd, &cli_source(tx), remote, target_branch, require_signed)
}

pub(crate) fn pull_all_with_source(
    cwd: &Path,
    source: &dyn mkit_sync::RemoteSource,
    remote: &str,
    target_branch: Option<&str>,
    require_signed: bool,
) -> Result<usize, DispatchError> {
    let options = sync_options(cwd, target_branch, require_signed)?;
    let report = mkit_sync::pull(cwd, source, remote, &options, &CliObserver)?;
    Ok(report.fetch.branches_fetched)
}

/// [`fetch_all_with`] with signature verification on — the CLI's default
/// (issue #692). Existing in-process callers (the integration-test suite)
/// that construct only validly-signed histories are unaffected.
pub fn fetch_all(cwd: &Path, tx: &dyn Transport, remote: &str) -> Result<usize, DispatchError> {
    fetch_all_with(cwd, tx, remote, true)
}

/// `fetch` — `pull_all` without the HEAD update. Downloads every object
/// reachable from each remote ref and writes the ref into
/// `refs/remotes/<remote>/<branch>`; see [`mkit_sync::fetch`].
///
/// See [`pull_all_with`] for the `require_signed` contract (issue #692).
pub fn fetch_all_with(
    cwd: &Path,
    tx: &dyn Transport,
    remote: &str,
    require_signed: bool,
) -> Result<usize, DispatchError> {
    fetch_all_with_source(cwd, &cli_source(tx), remote, require_signed)
}

pub(crate) fn fetch_all_with_source(
    cwd: &Path,
    source: &dyn mkit_sync::RemoteSource,
    remote: &str,
    require_signed: bool,
) -> Result<usize, DispatchError> {
    let options = sync_options(cwd, None, require_signed)?;
    let report = mkit_sync::fetch(cwd, source, remote, &options, &CliObserver)?;
    Ok(report.branches_fetched)
}

/// The observer the CLI hands the sync engine: it prints exactly what the
/// pre-extraction code printed, drives the progress reporter, and cancels on
/// the process-wide shutdown flag.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CliObserver;

struct PushObserver {
    warning: Option<String>,
}
impl mkit_sync::SyncObserver for PushObserver {
    fn event(&self, event: &mkit_sync::SyncEvent) {
        if matches!(event, mkit_sync::SyncEvent::PushBranchStarted { .. })
            && let Some(warning) = &self.warning
        {
            eprintln!("{warning}");
        }
        mkit_sync::SyncObserver::event(&CliObserver, event);
    }
    fn cancelled(&self) -> bool {
        crate::signal::is_shutdown()
    }
}

impl mkit_sync::SyncObserver for CliObserver {
    fn event(&self, event: &mkit_sync::SyncEvent) {
        use mkit_sync::SyncEvent;
        match event {
            SyncEvent::ObjectsPacked { count } => {
                crate::progress::report(crate::progress::Event::ObjectsPacked(*count));
            }
            SyncEvent::PackUploaded { bytes } => {
                crate::progress::report(crate::progress::Event::PackUploaded(*bytes));
            }
            SyncEvent::PushStep { index, total } => {
                crate::progress::report(crate::progress::Event::Step {
                    index: *index,
                    total: *total,
                });
            }
            SyncEvent::PushStepCommitted { index, total, tip } => {
                crate::progress::step_committed(*index, *total, tip);
            }
            SyncEvent::ObjectsUnpacked { count } => {
                crate::progress::report(crate::progress::Event::ObjectsUnpacked(*count));
            }
            SyncEvent::BranchSkippedStale { branch } if crate::progress::should_report(false) => {
                eprintln!(
                    "fetch: skipping branch `{branch}`: listed by an eventual ListRefs but \
                     no longer present (deleted since the listing)"
                );
            }
            SyncEvent::AppliedPacksUnreadable { remote, error } => {
                eprintln!(
                    "warning: could not read applied-packs record for remote '{remote}' ({error}); continuing without redownload-avoidance for this fetch"
                );
            }
            SyncEvent::AppliedPacksStale {
                remote,
                branch,
                cause,
            } => {
                eprintln!(
                    "note: applied-packs record for remote '{remote}' branch '{branch}' looks stale ({cause}); clearing it and re-fetching the full pack chain"
                );
            }
            SyncEvent::AppliedPacksPersistFailed { remote, error } => {
                eprintln!(
                    "warning: could not persist applied-packs record for remote '{remote}' ({error}); it will be rebuilt on the next fetch"
                );
            }
            SyncEvent::RepositoryServed { worktree_root } => {
                use std::io::Write as _;
                let mut stderr = std::io::stderr().lock();
                let _ = writeln!(
                    stderr,
                    "warning: {} is currently being served by `mkit serve`; concurrent worktree \
                     mutation and `gc` are not coordinated with it (SPEC-CONCURRENCY §3.1)",
                    worktree_root.display()
                );
            }
            _ => {}
        }
    }

    fn cancelled(&self) -> bool {
        crate::signal::is_shutdown()
    }
}

/// Recognise the Connect client's two interruption messages on a
/// repository-level call; everything else falls through to the default
/// classification.
fn classify_repository_error(error: &mkit_sync::SourceError) -> Option<mkit_sync::SyncError> {
    if let mkit_sync::SourceError::RemoteError(message) = error {
        if message.starts_with("upload interrupted; ") {
            return Some(mkit_sync::SyncError::UploadInterrupted(message.clone()));
        }
        if message == PENDING_INTERRUPTED_MESSAGE {
            return Some(mkit_sync::SyncError::Interrupted);
        }
    }
    None
}

/// The sync engine's view of `tx`, with the CLI's error classification.
fn cli_source(tx: &dyn Transport) -> mkit_sync::TransportSource<'_> {
    mkit_sync::TransportSource::new(tx).with_error_classifier(&classify_repository_error)
}

// Preserve CLI handling as well as display for existing transport failures.
impl From<mkit_sync::SourceError> for DispatchError {
    fn from(error: mkit_sync::SourceError) -> Self {
        use mkit_sync::SourceError as S;
        let transport = match error {
            S::PackNotFound => TransportError::PackNotFound,
            S::AccessDenied => TransportError::AccessDenied,
            S::AdmissionConfiguration(value) => TransportError::AdmissionConfiguration(value),
            S::TlsConfiguration(value) => TransportError::TlsConfiguration(value),
            S::AdmissionHelperFailed(value) => TransportError::AdmissionHelperFailed(value),
            S::RemoteError(value) if value.starts_with("upload interrupted; ") => {
                return Self::UploadInterrupted(value);
            }
            S::RemoteError(value) if value == PENDING_INTERRUPTED_MESSAGE => {
                return Self::Interrupted;
            }
            S::RemoteError(value) => TransportError::RemoteError(value),
            S::RefConflict => TransportError::RefConflict,
            S::InvalidRef(value) => TransportError::InvalidRef(value),
            S::ConnectionFailed => TransportError::ConnectionFailed,
            S::ServerError { status } => TransportError::ServerError { status },
            S::InvalidResponse => TransportError::InvalidResponse,
            S::ProtocolError => TransportError::ProtocolError,
            S::PayloadTooLarge(value) => TransportError::PayloadTooLarge(value),
            S::InsecureScheme => TransportError::InsecureScheme,
            S::PaymentRequired { challenges } => TransportError::AdmissionRequired(challenges),
            other => return Self::Source(other),
        };
        Self::Transport(transport)
    }
}

impl From<mkit_sync::SyncError> for DispatchError {
    fn from(error: mkit_sync::SyncError) -> Self {
        use mkit_sync::SyncError as S;
        match error {
            S::Interrupted => Self::Interrupted,
            S::UploadInterrupted(message) => Self::UploadInterrupted(message),
            S::RepositoryNotFound {
                identity,
                origin,
                source,
            } => Self::RepositoryNotFound {
                identity,
                origin,
                source,
            },
            S::Source(e) => e.into(),
            S::Refs(e) => Self::Refs(e),
            S::RepoLock(e) => Self::RepoLock(e),
            S::Discover(e) => Self::Discover(e),
            S::Io(e) => Self::Io(e),
            S::Store(e) => Self::Store(e),
            S::Pack(e) => Self::Pack(e),
            S::PackList(e) => Self::PackList(e),
            S::DetachedHead => Self::DetachedHead,
            S::RemoteBranchMissing(b) => Self::RemoteBranchMissing(b),
            S::NonFastForwardPull { branch } => Self::NonFastForwardPull { branch },
            S::RestoreSafety(m) => Self::RestoreSafety(m),
            S::NotCommit => Self::NotCommit,
            S::Restore(e) => Self::Restore(e),
            S::PackChainInvalid { branch, source } => Self::PackChainInvalid { branch, source },
            S::PackmapMissing(b) => Self::PackmapMissing(b),
            S::AdvertisedPackMissing {
                branch,
                pack,
                source,
            } => Self::AdvertisedPackMissing {
                branch,
                pack,
                source,
            },
            S::RemoteMissingObject(h) => Self::RemoteMissingObject(h),
            S::ClosureTooLarge(n) => Self::ClosureTooLarge(n),
            S::UnsignedOrInvalidObject { hash, reason } => {
                Self::UnsignedOrInvalidObject { hash, reason }
            }
            S::InvalidRemoteName(n) => Self::InvalidRemoteName(n),
        }
    }
}

impl From<mkit_sync::PushError> for DispatchError {
    fn from(error: mkit_sync::PushError) -> Self {
        use mkit_sync::PushError as P;
        match error {
            P::Sync(mkit_sync::SyncError::Source(
                mkit_sync::SourceError::PendingVerification { retry_after },
            )) => Self::Transport(TransportError::PendingVerification { retry_after }),
            P::Sync(mkit_sync::SyncError::Source(mkit_sync::SourceError::MembershipNotVisible)) => {
                Self::Transport(TransportError::MembershipNotVisible)
            }
            P::Sync(mkit_sync::SyncError::Source(mkit_sync::SourceError::RetryAfter { ms })) => {
                Self::Transport(TransportError::RetryAfter { ms })
            }
            P::Sync(error) => error.into(),
            P::NonFastForwardPush { branch } => Self::NonFastForwardPush { branch },
            P::PackmapContended { branch } => Self::PackmapContended { branch },
            P::PushTooLarge {
                packs,
                limit,
                commit,
                holds_remote_head,
            } => Self::PushTooLarge {
                packs,
                limit,
                commit,
                holds_remote_head,
            },
            P::RetryTooLarge {
                reason,
                packs,
                limit,
            } => Self::RetryTooLarge {
                reason,
                packs,
                limit,
            },
            P::PushSplitLimit(message) => Self::PushSplitLimit(message),
            P::PushNotAuthorized(message) => Self::PushNotAuthorized(message),
            P::ForceCapabilityUnknown => Self::ForceCapabilityUnknown,
            P::SplitInterrupted {
                branch,
                head,
                published,
                total,
                cause,
            } => Self::SplitInterrupted {
                branch,
                head,
                published,
                total,
                cause: Box::new((*cause).into()),
            },
            P::TicketRejected => Self::TicketRejected,
            P::DeltaBaseUnavailable => Self::DeltaBaseUnavailable,
            P::PacklistNotInRepository => Self::PacklistNotInRepository,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn plan_push_steps(
    store: &ObjectStore,
    tip: Hash,
    remote_tip: Option<Hash>,
    limits: mkit_core::protocol::UploadLimits,
    pack_payload_cap: u64,
    control: &PushControl<'_>,
    condition: refs::RefWriteCondition,
    branch: &str,
) -> Result<Vec<Hash>, DispatchError> {
    let control = PushControl {
        authority: control.authority,
        max_steps: control.max_steps,
        max_chain: control.max_chain,
        shallow: control.shallow.clone(),
        observer: &CliObserver,
    };
    mkit_sync::push::plan_push_steps(
        store,
        tip,
        remote_tip,
        limits,
        pack_payload_cap,
        &control,
        condition,
        branch,
    )
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::ssh_options_from_config;
    use crate::config::Config;
    use mkit_core::layout::RepoLayout;

    #[test]
    fn push_mapping_preserves_transport_scheduling_outcomes() {
        use mkit_core::protocol::TransportError;
        for transport in [
            TransportError::PendingVerification {
                retry_after: std::time::Duration::from_secs(2),
            },
            TransportError::MembershipNotVisible,
            TransportError::RetryAfter { ms: 3 },
        ] {
            let expected = format!("transport: {transport}");
            let source = mkit_sync::SourceError::from(transport);
            let error = super::DispatchError::from(mkit_sync::PushError::Sync(
                mkit_sync::SyncError::Source(source),
            ));
            assert_eq!(error.to_string().as_bytes(), expected.as_bytes());
            assert!(matches!(error, super::DispatchError::Transport(_)));
        }
    }

    #[test]
    fn sync_context_mapping_preserves_remote_evidence_and_output_bytes() {
        use super::DispatchError;
        use mkit_sync::{RemoteDetail, RemoteFailure, SourceError, SyncError};

        fn remote() -> SourceError {
            SourceError::Remote(Box::new(RemoteFailure {
                code: "not_found".into(),
                message: "not visible".into(),
                details: vec![RemoteDetail {
                    type_url: "type.example/detail".into(),
                    value: Some("eA==".into()),
                }],
                status: 404,
                headers: vec![("x-evidence".into(), b"retained".to_vec())],
            }))
        }

        for (error, expected) in [
            (
                SyncError::Source(remote()),
                "transport: pack not found on remote",
            ),
            (
                SyncError::RepositoryNotFound {
                    identity: "repo".into(),
                    origin: "https://remote.example".into(),
                    source: remote(),
                },
                "repository `repo` not found at https://remote.example; check the remote URL path against the server's configured name (an empty path selects `default` on a single-repository deployment)",
            ),
            (
                SyncError::PackChainInvalid {
                    branch: "main".into(),
                    source: Some(remote()),
                },
                "pack map chain for branch 'main' is malformed (too deep, cyclic, or unreadable)",
            ),
            (
                SyncError::AdvertisedPackMissing {
                    branch: "main".into(),
                    pack: "abc".into(),
                    source: remote(),
                },
                "remote advertised pack abc for branch 'main' but does not hold it",
            ),
        ] {
            let error = DispatchError::from(error);
            assert_eq!(error.to_string().as_bytes(), expected.as_bytes());
            let source = std::error::Error::source(&error)
                .expect("CLI mapping must retain the source cause")
                .downcast_ref::<SourceError>()
                .expect("the source cause must stay typed");
            let SourceError::Remote(remote) = source else {
                panic!("CLI mapping lost remote evidence")
            };
            assert_eq!(remote.code, "not_found");
            assert_eq!(remote.message, "not visible");
            assert_eq!(remote.status, 404);
            assert_eq!(remote.details[0].type_url, "type.example/detail");
            assert_eq!(remote.details[0].value.as_deref(), Some("eA=="));
            assert_eq!(
                remote.headers,
                vec![("x-evidence".into(), b"retained".to_vec())]
            );
        }
    }

    #[test]
    fn sync_source_mapping_preserves_transport_output_bytes() {
        use super::DispatchError;
        use mkit_core::protocol::{AdmissionRequired, TransportError};
        for error in [
            TransportError::PackNotFound,
            TransportError::AccessDenied,
            TransportError::AdmissionRequired(Box::new(AdmissionRequired::new(
                Vec::new(),
                "pay".into(),
                Vec::new(),
                Vec::new(),
            ))),
            TransportError::AdmissionConfiguration("bad".into()),
            TransportError::TlsConfiguration("bad".into()),
            TransportError::AdmissionHelperFailed("bad".into()),
            TransportError::RemoteError("bad".into()),
            TransportError::RefConflict,
            TransportError::InvalidRef("bad".into()),
            TransportError::ConnectionFailed,
            TransportError::ServerError { status: 429 },
            TransportError::ServerError { status: 503 },
            TransportError::InvalidResponse,
            TransportError::ProtocolError,
            TransportError::PayloadTooLarge(42),
            TransportError::InsecureScheme,
        ] {
            let expected = format!("transport: {error}");
            let error = DispatchError::from(mkit_sync::SyncError::from(
                mkit_sync::SourceError::from(error),
            ));
            assert_eq!(error.to_string().as_bytes(), expected.as_bytes());
            assert!(matches!(error, DispatchError::Transport(_)));
        }
    }

    #[test]
    fn envelope_destination_trust_precedes_missing_key_resolution() {
        let directory = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(directory.path());
        for endpoint in ["mkit+https://untrusted.example", "mkit+http://127.0.0.1:1"] {
            let mut cfg = Config {
                transport_auth: "envelope".into(),
                signer: "legacy".into(),
                signing_key: ".mkit/keys/missing-signing-key".into(),
                ..Config::default()
            };
            let error = super::open_with_config(endpoint, &cfg, &layout)
                .expect_err("untrusted signing must fail");
            assert!(
                matches!(error, super::DispatchError::UntrustedRemote(_)),
                "destination rejection must precede key access: {error}"
            );
            cfg.trusted_remote_endpoint = endpoint.into();
            let error = super::open_with_config(endpoint, &cfg, &layout)
                .expect_err("trusted endpoint now resolves the absent key");
            assert!(
                error.to_string().contains("requires a signing key"),
                "trusted destination should reach key resolution: {error}"
            );
        }
    }

    #[test]
    fn configured_connect_open_reports_malformed_repository_identity() {
        let directory = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(directory.path());
        let url = "mkit+https://host/Uppercase";
        let error = super::open_with_config(url, &Config::default(), &layout)
            .expect_err("uppercase repository identity must be rejected");
        assert!(
            matches!(error, super::DispatchError::MalformedUrl(_)),
            "expected malformed URL, got {error:?}"
        );
        let message = error.to_string();
        assert!(message.contains("Uppercase"), "{message}");
        assert!(!message.contains("invalid response"), "{message}");
    }

    #[test]
    fn plain_https_remote_is_refused_with_sync_remote_guidance() {
        let uuid = "019c88c3-a904-7bd1-8a5d-3182a0c6978a";
        let url = format!("https://vcs.example/{uuid}/repo");
        let error = super::open(&url).err().expect("plain https must fail");
        assert!(
            matches!(error, super::DispatchError::UnsupportedScheme(_)),
            "plain https is an unsupported scheme, not a malformed URL: {error:?}"
        );
        let message = error.to_string();
        assert!(
            message.contains(&format!("mkit+{url}")),
            "{message} must suggest the mkit+ spelling"
        );
        assert!(message.contains("SPEC-HTTP-OBJECTS"), "{message}");

        // Userinfo and queries are never echoed.
        let error = super::open(&format!(
            "http://user:secret@vcs.example/{uuid}/repo?k=q1#f"
        ))
        .err()
        .expect("plain http must fail");
        let message = error.to_string();
        assert!(!message.contains("secret"), "{message}");
        assert!(
            !message.contains("q1") && !message.contains("#f"),
            "{message}"
        );
        assert!(message.contains("mkit+https://"), "{message}");
        let error = super::open(&format!("http://vcs.example/{uuid}/repo?k=q1"))
            .err()
            .expect("plain http must fail");
        let message = error.to_string();
        assert!(!message.contains("q1"), "{message}");
        assert!(
            message.contains(&format!("mkit+https://vcs.example/{uuid}/repo")),
            "{message}"
        );
        // A rejected identity does not echo the URL's userinfo or query.
        let error = super::open("mkit+https://user:secret@vcs.example/Bad/repo?k=q1")
            .err()
            .expect("bad namespace must fail");
        let message = error.to_string();
        assert!(
            !message.contains("secret") && !message.contains("q1"),
            "{message}"
        );
        for url in [
            "mkit+https://user:pa/ss@vcs.example/Bad/repo",
            "mkit+https://user:12/ss@vcs.example/Bad/repo",
        ] {
            let message = super::open(url).err().expect("must fail").to_string();
            assert!(
                !message.contains("ss@") && !message.contains("pa/"),
                "{message}"
            );
        }
    }

    #[test]
    fn connect_url_validation_names_the_offending_segment() {
        let uuid = "019c88c3-a904-7bd1-8a5d-3182a0c6978a";
        for (path, offending) in [("/Bad/repo", "`Bad`"), ("/repo/Name", "`Name`")] {
            let url = format!("mkit+https://vcs.example{path}");
            let error = super::open(&url)
                .err()
                .unwrap_or_else(|| panic!("{url} must fail"));
            let message = error.to_string();
            assert!(message.contains(offending), "{message}");
            assert!(message.contains("§7.4"), "{message}");
        }
        // An opaque authority-mode namespace validates under the union
        // grammar and builds a transport.
        assert!(super::open(&format!("mkit+https://vcs.example/{uuid}/repo")).is_ok());
    }

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
