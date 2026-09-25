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
    /// `ListRefs`.
    ListRefs,
    /// `ReadRef`.
    ReadRef,
    /// `UpdateRef`.
    UpdateRef,
    /// `AdvanceRefs`.
    AdvanceRefs,
    /// `PackExists`.
    PackExists,
    /// `UploadPack` (client streaming).
    UploadPack,
    /// `DownloadPack` (server streaming).
    DownloadPack,
}

impl Procedure {
    /// The full Connect path, e.g. `/mkit.transport.v1.TransportService/UpdateRef`.
    /// This is also the `procedure` field auth v2 signs.
    #[must_use]
    pub const fn connect_path(self) -> &'static str {
        match self {
            Self::ListRefs => "/mkit.transport.v1.TransportService/ListRefs",
            Self::ReadRef => "/mkit.transport.v1.TransportService/ReadRef",
            Self::UpdateRef => "/mkit.transport.v1.TransportService/UpdateRef",
            Self::AdvanceRefs => "/mkit.transport.v1.TransportService/AdvanceRefs",
            Self::PackExists => "/mkit.transport.v1.TransportService/PackExists",
            Self::UploadPack => "/mkit.transport.v1.TransportService/UploadPack",
            Self::DownloadPack => "/mkit.transport.v1.TransportService/DownloadPack",
        }
    }

    /// The procedure a full Connect path names, if any.
    #[must_use]
    pub fn from_connect_path(path: &str) -> Option<Self> {
        Some(match path.strip_prefix(SERVICE_PREFIX)? {
            "ListRefs" => Self::ListRefs,
            "ReadRef" => Self::ReadRef,
            "UpdateRef" => Self::UpdateRef,
            "AdvanceRefs" => Self::AdvanceRefs,
            "PackExists" => Self::PackExists,
            "UploadPack" => Self::UploadPack,
            "DownloadPack" => Self::DownloadPack,
            _ => return None,
        })
    }

    /// Whether the procedure mutates state: `UpdateRef`, `AdvanceRefs` and
    /// `UploadPack`.
    #[must_use]
    pub const fn is_write(self) -> bool {
        matches!(self, Self::UpdateRef | Self::AdvanceRefs | Self::UploadPack)
    }

    /// Whether the procedure streams: `UploadPack` and `DownloadPack`.
    #[must_use]
    pub const fn is_streaming(self) -> bool {
        matches!(self, Self::UploadPack | Self::DownloadPack)
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
        let (digest, len) = text
            .strip_prefix("pack:")
            .and_then(|pack| pack.split_once(':'))
            .ok_or_else(invalid)?;
        let len = len
            .parse::<u64>()
            .ok()
            .filter(|n| n.to_string() == len)
            .ok_or_else(invalid)?;
        Ok(Self::Pack {
            id: canonical_hash(digest).ok_or_else(invalid)?,
            len,
        })
    }
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub new: Hash,
}

/// What an operation does, with its decoded arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OpKind {
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
}

impl OpKind {
    /// The procedure that carries this kind of operation.
    #[must_use]
    pub const fn procedure(&self) -> Procedure {
        match self {
            Self::ListRefs { .. } => Procedure::ListRefs,
            Self::ReadRef { .. } => Procedure::ReadRef,
            Self::UpdateRef(_) => Procedure::UpdateRef,
            Self::AdvanceRefs { .. } => Procedure::AdvanceRefs,
            Self::PackExists { .. } => Procedure::PackExists,
            Self::UploadPack { .. } => Procedure::UploadPack,
            Self::DownloadPack { .. } => Procedure::DownloadPack,
        }
    }
}

/// A grant the Authorizer matched, with the namespace epoch it was checked
/// against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantRef {
    /// Grant id.
    pub id: Hash,
    /// Namespace grant epoch at authorization time.
    pub epoch: u64,
}

/// Facts the Authorizer established, carried into `apply` as
/// preconditions. Always the default in M0; M2 (WP-2.6) sets `grant` so the
/// pipeline can require `grant.epoch` when it commits.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthzFacts {
    /// The grant that authorized the operation, if any.
    pub grant: Option<GrantRef>,
    /// Whether the principal owns the namespace.
    pub owner: bool,
}

/// A decoded request, ready for policy and storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operation {
    /// Target repository.
    pub repo: RepoId,
    /// Who the request acts as.
    pub principal: Principal,
    /// The auth v2 authorization, for signed requests.
    pub auth: Option<VerifiedAuth>,
    /// What the request does.
    pub kind: OpKind,
    /// What the Authorizer established.
    pub authz: AuthzFacts,
}

impl Operation {
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

    const ALL: [(Procedure, &str); 7] = [
        (Procedure::ListRefs, "ListRefs"),
        (Procedure::ReadRef, "ReadRef"),
        (Procedure::UpdateRef, "UpdateRef"),
        (Procedure::AdvanceRefs, "AdvanceRefs"),
        (Procedure::PackExists, "PackExists"),
        (Procedure::UploadPack, "UploadPack"),
        (Procedure::DownloadPack, "DownloadPack"),
    ];

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
                Procedure::UploadPack
            ]
        );
        let streams: Vec<_> = ALL
            .iter()
            .filter(|(p, _)| p.is_streaming())
            .map(|(p, _)| *p)
            .collect();
        assert_eq!(streams, [Procedure::UploadPack, Procedure::DownloadPack]);
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

    fn update(name: &str) -> RefUpdate {
        RefUpdate {
            name: name.to_owned(),
            condition: RefWriteCondition::Missing,
            new: [1; 32],
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
        ];
        for (kind, procedure) in cases {
            assert_eq!(kind.procedure(), procedure);
        }
    }

    #[test]
    fn operation_authz_defaults_empty() {
        let op = Operation {
            repo: RepoId {
                namespace: NamespaceKey::deployment_default(),
                name: RepoName::new("room-a").unwrap(),
            },
            principal: Principal::Anonymous,
            auth: None,
            kind: OpKind::ReadRef {
                name: "refs/heads/main".into(),
            },
            authz: AuthzFacts::default(),
        };
        assert_eq!(op.authz.grant, None);
        assert!(!op.authz.owner);
        assert_eq!(op.procedure(), Procedure::ReadRef);
        assert!(!op.procedure().is_write());
    }
}
