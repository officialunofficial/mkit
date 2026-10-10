//! The typed operation model: every request, whatever its transport, is
//! decoded into one [`Operation`] before it reaches policy or storage.
//!
//! [`Procedure`], [`OpKind`] and [`Commitment`] are non-exhaustive: M1 adds
//! the upload and server-info procedures and the `part:` commitment, and M2
//! adds the epoch, visibility and URL-token procedures, without reshaping
//! [`Operation`].

use mkit_core::hash::{Hash, from_hex};
use mkit_core::protocol::{PackKey, RefWriteCondition};
use mkit_core::write_auth::{Authorized, is_hex};

use crate::error::ServerError;
use crate::principal::Principal;
use crate::repo::RepoId;

/// Path prefix shared by every `mkit.transport.v1.TransportService` method.
const SERVICE_PREFIX: &str = "/mkit.transport.v1.TransportService/";

/// A `mkit.transport.v1.TransportService` procedure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Procedure {
    /// Namespace repository listing.
    ListRepos,
    /// `ListRefs`.
    ListRefs,
    /// `ReadRef`.
    ReadRef,
    /// `UpdateRef`.
    UpdateRef,
    /// `AdvanceRefs`.
    AdvanceRefs,
    /// `BeginUpload` (unary ticket opening).
    BeginUpload,
    /// `UploadPart` (client streaming).
    UploadPart,
    /// `CompleteUpload` (unary multipart completion).
    CompleteUpload,
    /// `PackExists`.
    PackExists,
    /// `UploadPack` (client streaming).
    UploadPack,
    /// `DownloadPack` (server streaming).
    DownloadPack,
    /// `GetReceipt`.
    GetReceipt,
    /// `SetRepoVisibility` (envelope mode is replay-protected like a write).
    SetRepoVisibility,
    /// `ForkRepo`: a server-side fork of a published branch into an empty
    /// repository (SPEC-SERVER §9.9). Never a `TransportService` method: only
    /// the signed procedure name and the hook procedure name.
    Fork,
    /// `IssueObjectUrl`.
    IssueObjectUrl,
    /// An HTTP object read by id (`/mkit.http.v1/GetObject`, SPEC-HTTP-OBJECTS
    /// §7). Never a `TransportService` method: only the hook procedure name.
    HttpGetObject,
    /// An HTTP object read by ref path (`/mkit.http.v1/GetRefPath`).
    HttpGetRefPath,
}

impl Procedure {
    /// The full Connect path, e.g. `/mkit.transport.v1.TransportService/UpdateRef`.
    /// This is also the `procedure` field auth v2 signs.
    #[must_use]
    pub const fn connect_path(self) -> &'static str {
        match self {
            Self::ListRepos => "/mkit.transport.v1.TransportService/ListRepos",
            Self::ListRefs => "/mkit.transport.v1.TransportService/ListRefs",
            Self::ReadRef => "/mkit.transport.v1.TransportService/ReadRef",
            Self::UpdateRef => "/mkit.transport.v1.TransportService/UpdateRef",
            Self::AdvanceRefs => "/mkit.transport.v1.TransportService/AdvanceRefs",
            Self::BeginUpload => "/mkit.transport.v1.TransportService/BeginUpload",
            Self::UploadPart => "/mkit.transport.v1.TransportService/UploadPart",
            Self::CompleteUpload => "/mkit.transport.v1.TransportService/CompleteUpload",
            Self::PackExists => "/mkit.transport.v1.TransportService/PackExists",
            Self::UploadPack => "/mkit.transport.v1.TransportService/UploadPack",
            Self::DownloadPack => "/mkit.transport.v1.TransportService/DownloadPack",
            Self::GetReceipt => "/mkit.transport.v1.TransportService/GetReceipt",
            Self::SetRepoVisibility => "/mkit.transport.v1.TransportService/SetRepoVisibility",
            Self::Fork => "/mkit.server.v1/ForkRepo",
            Self::IssueObjectUrl => "/mkit.transport.v1.TransportService/IssueObjectUrl",
            Self::HttpGetObject => "/mkit.http.v1/GetObject",
            Self::HttpGetRefPath => "/mkit.http.v1/GetRefPath",
        }
    }

    /// The `TransportService` procedure a full Connect path names, if any.
    /// The HTTP procedures are not `TransportService` methods and are never
    /// returned.
    #[must_use]
    pub fn from_connect_path(path: &str) -> Option<Self> {
        Some(match path.strip_prefix(SERVICE_PREFIX)? {
            "ListRepos" => Self::ListRepos,
            "ListRefs" => Self::ListRefs,
            "ReadRef" => Self::ReadRef,
            "UpdateRef" => Self::UpdateRef,
            "AdvanceRefs" => Self::AdvanceRefs,
            "BeginUpload" => Self::BeginUpload,
            "UploadPart" => Self::UploadPart,
            "CompleteUpload" => Self::CompleteUpload,
            "PackExists" => Self::PackExists,
            "UploadPack" => Self::UploadPack,
            "DownloadPack" => Self::DownloadPack,
            "GetReceipt" => Self::GetReceipt,
            "SetRepoVisibility" => Self::SetRepoVisibility,
            "IssueObjectUrl" => Self::IssueObjectUrl,
            _ => return None,
        })
    }

    /// Whether the procedure mutates state. Every variant is classified:
    /// `GetServerInfo`, `GetGrantEpoch` and `SetGrantEpoch` stay outside
    /// `Procedure` by design (SPEC-WRITE-GRANTS §5.3, §9.2).
    #[must_use]
    pub const fn is_write(self) -> bool {
        match self {
            Self::UpdateRef
            | Self::AdvanceRefs
            | Self::BeginUpload
            | Self::UploadPack
            | Self::UploadPart
            | Self::CompleteUpload
            | Self::SetRepoVisibility
            | Self::Fork => true,
            Self::ListRepos
            | Self::ListRefs
            | Self::ReadRef
            | Self::PackExists
            | Self::DownloadPack
            | Self::GetReceipt
            | Self::IssueObjectUrl
            | Self::HttpGetObject
            | Self::HttpGetRefPath => false,
        }
    }

    /// Whether the procedure streams: `UploadPack`, `UploadPart` and `DownloadPack`.
    #[must_use]
    pub const fn is_streaming(self) -> bool {
        matches!(
            self,
            Self::UploadPack | Self::UploadPart | Self::DownloadPack
        )
    }
}

/// The content commitment an auth v2 signature covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Commitment {
    /// `body:<64 hex>`: digest of a unary request body.
    Body(Hash),
    /// `pack:<64 hex>:<decimal length>`: a streamed pack upload.
    Pack {
        /// Pack digest.
        id: Hash,
        /// Declared pack length in bytes.
        len: u64,
    },
    /// `part:<ticket>:<index>:<subtree>:<len>`.
    Part {
        /// Ticket id.
        ticket: Hash,
        /// Zero-based part index.
        index: u32,
        /// BLAKE3 non-root subtree chaining value.
        subtree: Hash,
        /// Part length.
        len: u64,
    },
}

impl Commitment {
    /// Parse the canonical text form. Uppercase hex, leading zeros and
    /// unknown prefixes are rejected, as auth v2 itself rejects them.
    ///
    /// # Errors
    /// [`crate::Code::InvalidArgument`] for any other input.
    pub fn parse(text: &str) -> Result<Self, ServerError> {
        let invalid = || ServerError::invalid_argument("invalid content commitment");
        if let Some(digest) = text.strip_prefix("body:") {
            return Ok(Self::Body(canonical_hash(digest).ok_or_else(invalid)?));
        }
        if let Some(part) = text.strip_prefix("part:") {
            let mut fields = part.split(':');
            let ticket = canonical_hash(fields.next().ok_or_else(invalid)?).ok_or_else(invalid)?;
            let index =
                canonical_decimal::<u32>(fields.next().ok_or_else(invalid)?).ok_or_else(invalid)?;
            let subtree = canonical_hash(fields.next().ok_or_else(invalid)?).ok_or_else(invalid)?;
            let len =
                canonical_decimal::<u64>(fields.next().ok_or_else(invalid)?).ok_or_else(invalid)?;
            if fields.next().is_some() {
                return Err(invalid());
            }
            return Ok(Self::Part {
                ticket,
                index,
                subtree,
                len,
            });
        }
        let (digest, len) = text
            .strip_prefix("pack:")
            .and_then(|pack| pack.split_once(':'))
            .ok_or_else(invalid)?;
        let len = canonical_decimal::<u64>(len).ok_or_else(invalid)?;
        Ok(Self::Pack {
            id: canonical_hash(digest).ok_or_else(invalid)?,
            len,
        })
    }
}

fn canonical_decimal<T: core::str::FromStr + ToString>(text: &str) -> Option<T> {
    text.parse::<T>().ok().filter(|n| n.to_string() == text)
}

/// Decode 64 lowercase hex characters; anything else is noncanonical.
fn canonical_hash(text: &str) -> Option<Hash> {
    if is_hex(text, 32) {
        from_hex(text).ok()
    } else {
        None
    }
}

/// A verified auth v2 authorization, decoded from
/// [`mkit_core::write_auth::Authorized`].
///
/// Non-exhaustive: later milestones add fields. Build it with
/// `VerifiedAuth::try_from(&authorized)`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedAuth {
    /// The signer's raw Ed25519 public key.
    pub signer: [u8; 32],
    /// Replay namespace: destination, repository, signer and nonce.
    pub replay_scope: Hash,
    /// Digest of every signed field; a replay with a different fingerprint
    /// is rejected.
    pub fingerprint: Hash,
    /// The operation nonce (idempotency key).
    pub nonce: String,
    /// The signed content commitment.
    pub commitment: Commitment,
    /// Expiry, Unix epoch milliseconds; replay records outlive it.
    pub expires_at_ms: i64,
    /// The signed `x-created-at`, Unix epoch milliseconds: when the client
    /// signed, so what it knew of the repository is at least this old
    /// (the ticketless §9.4 lag proxy, WP-4.17). `0` on a value built
    /// without the envelope, which opens no lag window.
    pub created_at_ms: i64,
}

impl TryFrom<&Authorized> for VerifiedAuth {
    type Error = ServerError;

    /// Decode the hex fields. `verify_headers` only produces canonical
    /// values, so a failure here means a hand-built or corrupted value.
    fn try_from(auth: &Authorized) -> Result<Self, Self::Error> {
        let malformed = || ServerError::unauthenticated("malformed auth v2 authorization");
        if !is_hex(&auth.nonce, 32) {
            return Err(malformed());
        }
        Ok(Self {
            signer: canonical_hash(&auth.public_key).ok_or_else(malformed)?,
            replay_scope: canonical_hash(&auth.scope).ok_or_else(malformed)?,
            fingerprint: canonical_hash(&auth.fingerprint).ok_or_else(malformed)?,
            nonce: auth.nonce.clone(),
            commitment: Commitment::parse(&auth.commitment).map_err(|_| malformed())?,
            expires_at_ms: auth.expires_at,
            created_at_ms: 0,
        })
    }
}

/// One conditional ref write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefUpdate {
    /// Full ref name, e.g. `refs/heads/main`.
    pub name: String,
    /// Compare-and-swap precondition.
    pub condition: RefWriteCondition,
    /// New target.
    /// New target, or `None` to delete the ref.
    pub new: Option<Hash>,
}

/// What an operation does, with its decoded arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OpKind {
    /// List repository names in the namespace selected by the request.
    ListRepos {
        /// Raw repository-name prefix.
        name_prefix: String,
    },
    /// List refs under `prefix`.
    ListRefs {
        /// Ref-name prefix; empty lists every ref.
        prefix: String,
    },
    /// Read one ref.
    ReadRef {
        /// Full ref name.
        name: String,
    },
    /// Conditionally write one ref.
    UpdateRef(RefUpdate),
    /// Advance a branch head and its packmap together.
    AdvanceRefs {
        /// The branch head update.
        head: RefUpdate,
        /// The packmap update.
        packmap: RefUpdate,
        /// Upload tickets consumed atomically with the ref advance.
        tickets: Vec<Hash>,
    },
    /// Open an upload ticket for a target ref.
    BeginUpload {
        /// Branch or tag to advance.
        ref_name: String,
        /// Pack commitment.
        key: PackKey,
        /// Declared byte count.
        bytes: u64,
    },
    /// Check whether a pack is present.
    PackExists {
        /// Pack digest.
        key: PackKey,
    },
    /// Upload a pack.
    UploadPack {
        /// Pack digest.
        key: PackKey,
        /// Length the client declared up front.
        declared_len: u64,
    },
    /// Download a pack.
    DownloadPack {
        /// Pack digest.
        key: PackKey,
    },
    /// Set the repository's visibility, in the envelope mode and in the
    /// statement mode (whose operation has no signed envelope and is
    /// attributed to the namespace owner).
    SetRepoVisibility {
        /// The visibility to store.
        visibility: mkit_attest::grant::Visibility,
    },
    /// Fork the published tip of `source_ref` of `source` into the operation's
    /// repository, which must be empty (SPEC-SERVER §9.9). The operation's
    /// repository is the destination.
    ForkRepo {
        /// The source repository.
        source: RepoId,
        /// The source branch.
        source_ref: String,
        /// The tip the caller expects the source to have published.
        expected_tip: Hash,
        /// The source's visibility, read in the same plan step as the fork;
        /// `None` when the deployment keeps no repository visibility.
        source_visibility: Option<mkit_attest::grant::Visibility>,
        /// The destination's requested visibility.
        dest_visibility: mkit_attest::grant::Visibility,
    },
    /// Mint a signed URL token for an object or ref path
    /// (SPEC-WRITE-GRANTS §9.4). The server does not resolve the target.
    IssueObjectUrl {
        /// The object or ref path the token binds.
        target: crate::url_token::UrlTarget,
        /// Requested lifetime in seconds; `0` asks for the configured TTL.
        ttl_seconds: u32,
    },
    /// An anonymous HTTP object read (SPEC-HTTP-OBJECTS §7): by id, or by
    /// ref path when `ref_name` is set. The hook schema has no object-id
    /// field, so the id is not part of the operation.
    HttpGet {
        /// The ref of a ref-path read; `None` for an id read.
        ref_name: Option<String>,
    },
}

impl OpKind {
    /// The procedure that carries this kind of operation.
    #[must_use]
    pub const fn procedure(&self) -> Procedure {
        match self {
            Self::ListRepos { .. } => Procedure::ListRepos,
            Self::ListRefs { .. } => Procedure::ListRefs,
            Self::ReadRef { .. } => Procedure::ReadRef,
            Self::UpdateRef(_) => Procedure::UpdateRef,
            Self::AdvanceRefs { .. } => Procedure::AdvanceRefs,
            Self::BeginUpload { .. } => Procedure::BeginUpload,
            Self::PackExists { .. } => Procedure::PackExists,
            Self::UploadPack { .. } => Procedure::UploadPack,
            Self::DownloadPack { .. } => Procedure::DownloadPack,
            Self::SetRepoVisibility { .. } => Procedure::SetRepoVisibility,
            Self::ForkRepo { .. } => Procedure::Fork,
            Self::IssueObjectUrl { .. } => Procedure::IssueObjectUrl,
            Self::HttpGet { ref_name: None } => Procedure::HttpGetObject,
            Self::HttpGet { ref_name: Some(_) } => Procedure::HttpGetRefPath,
        }
    }
}

/// A grant the Authorizer matched, with the namespace epoch it was checked
/// against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRef {
    /// Grant id.
    pub id: Hash,
    /// Namespace grant epoch at authorization time.
    pub epoch: u64,
    /// The ref-state constraint for an `ANY` change with only `c` or `f`.
    pub presence_requirement: Option<PresenceRequirement>,
}

/// Server-local §8.2 condition carried from authorization to each plan.
/// The ref name makes an `AdvanceRefs` constraint apply to its head only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresenceRequirement {
    /// `c` alone can create this ref only while it is absent.
    Absent(String),
    /// `f` alone can replace this ref only while it is present.
    Present(String),
}

/// The consistency and visibility view a caller is entitled to
/// (SPEC-SERVER §10.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum CallerView {
    /// An unsigned caller.
    #[default]
    Anonymous,
    /// A signed caller without write authority.
    Reader,
    /// An owner, a `write` grantee, or an authority-approved writer
    /// (SPEC-SERVER §6.2 `writer_view`).
    Writer,
}

/// Facts the Authorizer established, carried into `apply` as
/// preconditions. M1 establishes `owner`; M2 (WP-2.6) sets `grant` so the
/// pipeline can require `grant.epoch` when it commits.
///
/// Non-exhaustive: start from `AuthzFacts::default()` and set fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuthzFacts {
    /// The grant that authorized the operation, if any.
    pub grant: Option<GrantRef>,
    /// Whether the principal owns the namespace.
    pub owner: bool,
    /// The caller's view; `Writer` is honoured only when the
    /// authorizer's role is `Authority`.
    pub caller_view: CallerView,
    /// Generation of a trusted Authority allowance; preserved through retries.
    pub authority_generation: Option<u64>,
}

/// Namespace and repository creation facts for a write.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Creation {
    /// Whether the namespace is new.
    pub namespace: bool,
    /// Whether the repository is new.
    pub repo: bool,
}

/// A decoded request, ready for policy and storage.
///
/// Non-exhaustive: build it with [`Operation::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Operation {
    /// Target repository.
    pub repo: RepoId,
    /// Who the request acts as.
    pub principal: Principal,
    /// The auth v2 authorization, for signed requests.
    pub auth: Option<VerifiedAuth>,
    /// Presented grant header, outside the auth v2 signed string.
    pub write_grant: Option<crate::Redacted>,
    /// What the request does.
    pub kind: OpKind,
    /// Epoch leased for this D34 write; `None` under Single.
    pub leased_epoch: Option<u64>,
    /// Epoch observed in the Single-sharding read-ahead; `Some(0)` for an absent `e` key.
    pub observed_epoch: Option<u64>,
    /// Business clock value used to verify this request's auth v2 envelope.
    pub business_now_ms: Option<i64>,
    /// What the Authorizer established.
    pub authz: AuthzFacts,
    /// Pre-admission observation: racing first writes may both observe creation.
    pub creation: Creation,
    /// Creation committed by this operation; only one racing writer creates a row.
    pub created: Creation,
}

impl Operation {
    /// An operation with no Authorizer facts yet ([`AuthzFacts::default`]).
    #[must_use]
    pub fn new(
        repo: RepoId,
        principal: Principal,
        auth: Option<VerifiedAuth>,
        kind: OpKind,
    ) -> Self {
        Self {
            repo,
            principal,
            auth,
            write_grant: None,
            kind,
            leased_epoch: None,
            observed_epoch: None,
            business_now_ms: None,
            authz: AuthzFacts::default(),
            creation: Creation::default(),
            created: Creation::default(),
        }
    }

    /// The procedure that carries this operation.
    #[must_use]
    pub const fn procedure(&self) -> Procedure {
        self.kind.procedure()
    }
}

#[cfg(test)]
mod tests {
    use mkit_core::hash::to_hex;
    use mkit_core::write_auth::{Context, Headers, verify_headers};

    use super::*;
    use crate::error::Code;
    use crate::repo::{NamespaceKey, RepoName};

    const ALL: [(Procedure, &str); 14] = [
        (Procedure::ListRefs, "ListRefs"),
        (Procedure::ListRepos, "ListRepos"),
        (Procedure::ReadRef, "ReadRef"),
        (Procedure::UpdateRef, "UpdateRef"),
        (Procedure::AdvanceRefs, "AdvanceRefs"),
        (Procedure::BeginUpload, "BeginUpload"),
        (Procedure::UploadPart, "UploadPart"),
        (Procedure::CompleteUpload, "CompleteUpload"),
        (Procedure::PackExists, "PackExists"),
        (Procedure::UploadPack, "UploadPack"),
        (Procedure::DownloadPack, "DownloadPack"),
        (Procedure::GetReceipt, "GetReceipt"),
        (Procedure::SetRepoVisibility, "SetRepoVisibility"),
        (Procedure::IssueObjectUrl, "IssueObjectUrl"),
    ];

    /// `TransportService` RPCs that deliberately stay outside `Procedure`:
    /// unauthenticated forever (SPEC-WRITE-GRANTS §5.3, §9.2; STC §2.1).
    const EXEMPT: [&str; 5] = [
        "GetServerInfo",
        "GetGrantEpoch",
        "SetGrantEpoch",
        "GetAuthorityGeneration",
        "SetAuthorityGeneration",
    ];

    #[test]
    fn every_transport_rpc_is_classified_or_exempt() {
        let proto = include_str!("../../../../proto/mkit/transport/v1/transport.proto");
        let service = proto
            .split("service TransportService")
            .nth(1)
            .expect("TransportService");
        let mut names = Vec::new();
        for line in service.lines() {
            let line = line.trim_start();
            if let Some(rest) = line.strip_prefix("rpc ")
                && let Some(name) = rest.split('(').next()
            {
                names.push(name.trim());
            }
        }
        assert_eq!(names.len(), ALL.len() + EXEMPT.len());
        for name in &names {
            let path = format!("/mkit.transport.v1.TransportService/{name}");
            if EXEMPT.contains(name) {
                assert_eq!(Procedure::from_connect_path(&path), None, "{name}");
            } else {
                assert!(
                    Procedure::from_connect_path(&path).is_some(),
                    "{name} is not classified"
                );
            }
        }
        for (_, name) in ALL {
            assert!(names.contains(&name), "{name} missing from the proto");
        }
    }

    #[test]
    fn http_procedures_are_hook_names_only() {
        for (procedure, path) in [
            (Procedure::HttpGetObject, "/mkit.http.v1/GetObject"),
            (Procedure::HttpGetRefPath, "/mkit.http.v1/GetRefPath"),
        ] {
            assert_eq!(procedure.connect_path(), path);
            assert_eq!(Procedure::from_connect_path(path), None);
            assert!(!procedure.is_write());
            assert!(!procedure.is_streaming());
        }
        assert_eq!(
            OpKind::HttpGet { ref_name: None }.procedure(),
            Procedure::HttpGetObject
        );
        assert_eq!(
            OpKind::HttpGet {
                ref_name: Some("refs/heads/main".into())
            }
            .procedure(),
            Procedure::HttpGetRefPath
        );
    }

    #[test]
    fn procedure_paths_roundtrip() {
        // The service and method names in proto/mkit/transport/v1/transport.proto.
        for (procedure, method) in ALL {
            let path = procedure.connect_path();
            assert_eq!(
                path,
                format!("/mkit.transport.v1.TransportService/{method}")
            );
            assert_eq!(Procedure::from_connect_path(path), Some(procedure));
        }
        for bad in [
            "",
            "/mkit.transport.v1.TransportService/",
            "/mkit.transport.v1.TransportService/updateref",
            "/mkit.transport.v1.TransportService/UpdateRef/",
            "/mkit.repo.v1.RepoService/UpdateRef",
            "mkit.transport.v1.TransportService/UpdateRef",
        ] {
            assert_eq!(Procedure::from_connect_path(bad), None, "{bad}");
        }
    }

    #[test]
    fn procedure_write_and_streaming_classes() {
        let writes: Vec<_> = ALL
            .iter()
            .filter(|(p, _)| p.is_write())
            .map(|(p, _)| *p)
            .collect();
        assert_eq!(
            writes,
            [
                Procedure::UpdateRef,
                Procedure::AdvanceRefs,
                Procedure::BeginUpload,
                Procedure::UploadPart,
                Procedure::CompleteUpload,
                Procedure::UploadPack,
                Procedure::SetRepoVisibility
            ]
        );
        let streams: Vec<_> = ALL
            .iter()
            .filter(|(p, _)| p.is_streaming())
            .map(|(p, _)| *p)
            .collect();
        assert_eq!(
            streams,
            [
                Procedure::UploadPart,
                Procedure::UploadPack,
                Procedure::DownloadPack
            ]
        );
    }

    fn golden() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../tests/golden/auth-v2/unary.json")).unwrap()
    }

    fn authorized(commitment: &str) -> Authorized {
        Authorized {
            scope: "11".repeat(32),
            public_key: "22".repeat(32),
            nonce: "ab".repeat(32),
            fingerprint: "33".repeat(32),
            commitment: commitment.to_owned(),
            expires_at: 1_700_000_300_000,
        }
    }

    #[test]
    fn verified_auth_from_authorized_parses_body_and_pack_commitments() {
        let fixture = golden();
        let field = |name: &str| fixture[name].as_str().unwrap().to_owned();
        let created_at = fixture["created_at"].as_i64().unwrap();
        let expires_at = fixture["expires_at"].as_i64().unwrap();
        let headers = Headers {
            version: Some("2".into()),
            audience: Some(field("audience")),
            repository: Some(field("repository")),
            public_key: Some(field("public_key")),
            signature: Some(field("signature")),
            commitment: Some(field("commitment")),
            digest: Some(field("body_digest")),
            created_at: Some(created_at.to_string()),
            expires_at: Some(expires_at.to_string()),
            idempotency_key: Some(field("nonce")),
        };
        let audience = field("audience");
        let repository = field("repository");
        let commitment = field("commitment");
        let auth = verify_headers(
            Context {
                audience: &audience,
                repository: &repository,
            },
            &field("procedure"),
            Some(&commitment),
            created_at + 1,
            &headers,
        )
        .unwrap();

        let verified = VerifiedAuth::try_from(&auth).unwrap();
        assert_eq!(
            verified.commitment,
            Commitment::Body(from_hex(&field("body_digest")).unwrap())
        );
        assert_eq!(to_hex(&verified.signer), field("public_key"));
        assert_eq!(to_hex(&verified.fingerprint), field("signing_digest"));
        assert_eq!(to_hex(&verified.replay_scope), auth.scope);
        assert_eq!(verified.nonce, field("nonce"));
        assert_eq!(verified.expires_at_ms, expires_at);

        let pack = authorized(&format!("pack:{}:12", "cd".repeat(32)));
        let verified = VerifiedAuth::try_from(&pack).unwrap();
        assert_eq!(
            verified.commitment,
            Commitment::Pack {
                id: [0xcd; 32],
                len: 12
            }
        );
        assert_eq!(verified.signer, [0x22; 32]);
        assert_eq!(verified.replay_scope, [0x11; 32]);
    }

    #[test]
    fn verified_auth_rejects_noncanonical_fields() {
        let digest = "cd".repeat(32);
        for commitment in [
            format!("body:{}", digest.to_uppercase()),
            format!("body:{}", &digest[..62]),
            format!("pack:{digest}:012"),
            format!("pack:{digest}:+12"),
            format!("pack:{digest}:"),
            format!("pack:{digest}"),
            format!("pack:{digest}:18446744073709551616"),
            format!("part:{digest}:1"),
            String::new(),
        ] {
            assert_eq!(
                Commitment::parse(&commitment).unwrap_err().code(),
                Code::InvalidArgument,
                "{commitment}"
            );
            let err = VerifiedAuth::try_from(&authorized(&commitment)).unwrap_err();
            assert_eq!(err.code(), Code::Unauthenticated, "{commitment}");
        }
        let body = format!("body:{digest}");
        for broken in [
            Authorized {
                public_key: "AA".repeat(32),
                ..authorized(&body)
            },
            Authorized {
                scope: "11".repeat(31),
                ..authorized(&body)
            },
            Authorized {
                fingerprint: "zz".repeat(32),
                ..authorized(&body)
            },
            Authorized {
                nonce: "AB".repeat(32),
                ..authorized(&body)
            },
        ] {
            let err = VerifiedAuth::try_from(&broken).unwrap_err();
            assert_eq!(err.code(), Code::Unauthenticated);
        }
    }

    #[test]
    fn part_commitment_parses_canonically() {
        let text = format!("part:{}:2:{}:8388608", "ab".repeat(32), "cd".repeat(32));
        assert_eq!(
            Commitment::parse(&text).unwrap(),
            Commitment::Part {
                ticket: [0xab; 32],
                index: 2,
                subtree: [0xcd; 32],
                len: 8_388_608,
            }
        );
        for wrong in [
            text.replace(":2:", ":02:"),
            text.replace(":8388608", ":08388608"),
            text.to_uppercase(),
            format!("{text}:extra"),
        ] {
            assert_eq!(
                Commitment::parse(&wrong).unwrap_err().code(),
                Code::InvalidArgument
            );
        }
    }

    fn update(name: &str) -> RefUpdate {
        RefUpdate {
            name: name.to_owned(),
            condition: RefWriteCondition::Missing,
            new: Some([1; 32]),
        }
    }

    #[test]
    fn op_kind_maps_to_its_procedure() {
        let key = PackKey::new([9; 32]);
        let cases = [
            (
                OpKind::ListRefs {
                    prefix: String::new(),
                },
                Procedure::ListRefs,
            ),
            (
                OpKind::ReadRef {
                    name: "refs/heads/main".into(),
                },
                Procedure::ReadRef,
            ),
            (
                OpKind::UpdateRef(update("refs/heads/main")),
                Procedure::UpdateRef,
            ),
            (
                OpKind::AdvanceRefs {
                    head: update("refs/heads/main"),
                    packmap: update("refs/packmap/main"),
                    tickets: Vec::new(),
                },
                Procedure::AdvanceRefs,
            ),
            (OpKind::PackExists { key }, Procedure::PackExists),
            (
                OpKind::UploadPack {
                    key,
                    declared_len: 12,
                },
                Procedure::UploadPack,
            ),
            (OpKind::DownloadPack { key }, Procedure::DownloadPack),
            (
                OpKind::SetRepoVisibility {
                    visibility: mkit_attest::grant::Visibility::Private,
                },
                Procedure::SetRepoVisibility,
            ),
            (
                OpKind::IssueObjectUrl {
                    target: crate::url_token::UrlTarget::Object([0xaa; 32]),
                    ttl_seconds: 60,
                },
                Procedure::IssueObjectUrl,
            ),
        ];
        for (kind, procedure) in cases {
            assert_eq!(kind.procedure(), procedure);
        }
    }

    #[test]
    fn operation_authz_defaults_empty() {
        let op = Operation::new(
            RepoId {
                namespace: NamespaceKey::deployment_default(),
                name: RepoName::new("room-a").unwrap(),
            },
            Principal::Anonymous,
            None,
            OpKind::ReadRef {
                name: "refs/heads/main".into(),
            },
        );
        assert_eq!(op.authz, AuthzFacts::default());
        assert_eq!(op.authz.grant, None);
        assert!(!op.authz.owner);
        assert_eq!(op.procedure(), Procedure::ReadRef);
        assert!(!op.procedure().is_write());
    }
}
