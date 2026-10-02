//! [`GrantError`]: why a statement or header was rejected.

/// A rejected grant, epoch or visibility statement, `X-Write-Grant` header,
/// owner signature or verification step.
///
/// There is one variant per SPEC-WRITE-GRANTS §3.5 rule family, plus the §4.2
/// header errors, the §4 owner-signature errors, the §7 verification steps
/// and the verifier configuration errors. [`GrantError::reason`] is stable text for logs and golden
/// fixtures. It is never shown to clients: the server maps every variant to
/// one Connect code (§11), `permission_denied` on writes and `not_found` on
/// private reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
#[error("{}", self.reason())]
pub enum GrantError {
    /// Longer than `MAX_STATEMENT_BYTES`.
    StatementTooLong,
    /// A carriage return anywhere in the statement.
    CarriageReturn,
    /// A byte outside `0x21..=0x7E` inside a field (other than CR).
    ByteOutOfRange,
    /// A line feed as the last byte.
    FinalLineFeed,
    /// A field count other than the statement's.
    FieldCount,
    /// An empty field.
    EmptyField,
    /// A domain other than the statement's separator.
    Domain,
    /// A namespace outside the SPEC-TRANSPORT-CONNECT §7.4 grammar.
    Namespace,
    /// A repository scope that is neither `<namespace>/<name>` (§7.4) nor
    /// `<namespace>/*`.
    RepositoryScope,
    /// A repository scope in a namespace other than the `namespace` field.
    ScopeNamespaceMismatch,
    /// A decimal with a sign, a leading zero or a non-digit.
    Decimal,
    /// A decimal above its range (epoch `u64::MAX`, millis `i64::MAX`), or a
    /// negative timestamp on encode.
    DecimalOutOfRange,
    /// Uppercase or wrong-length hexadecimal.
    Hex,
    /// An unknown capability, or capabilities not in canonical spelling.
    Capabilities,
    /// An audience that fails the auth v2 origin rules.
    Audience,
    /// A `*` anywhere in the audience list.
    AudienceWildcard,
    /// More than `MAX_AUDIENCES` audiences, or none (encode only).
    AudienceCount,
    /// Audiences out of ascending byte order, or duplicated.
    AudiencesUnordered,
    /// Ref scopes other than `-` on a `read` grant.
    RefScopesOnRead,
    /// Ref scopes `-` on a grant with `write`.
    RefScopesMissing,
    /// A ref-scope pattern outside §3.3 (or an entry without `=`).
    RefPattern,
    /// A pattern that is, or begins with, `refs/mkit/packmap/`.
    PackmapPattern,
    /// A flag other than `c`, `u`, `f`, `d`.
    UnknownRefFlag,
    /// Empty flags, or flags repeated or out of the `cufd` order.
    RefFlagsNotCanonical,
    /// More than `MAX_REF_SCOPES` entries, or none (encode only).
    RefScopeCount,
    /// Ref-scope entries out of ascending byte order, or duplicated.
    RefScopesUnordered,
    /// Two ref-scope entries with one pattern.
    DuplicateRefPattern,
    /// `expiry <= created`.
    ExpiryNotAfterCreated,
    /// `expiry - created` above the statement's maximum lifetime.
    LifetimeTooLong,
    /// A header value longer than `MAX_GRANT_HEADER_BYTES`.
    HeaderTooLong,
    /// A header value that is not three non-empty `.`-separated segments.
    HeaderFormat,
    /// A header segment that is not canonical unpadded base64url.
    HeaderBase64,
    /// A scheme token not defined in §4.
    UnknownScheme,
    /// A visibility statement's repository that is not a full
    /// `<namespace>/<name>` identity (§9.1).
    Repository,
    /// A visibility other than `public` or `private` (§9.1).
    Visibility,
    /// §4: a scheme the deployment does not advertise.
    SchemeNotAdvertised,
    /// §4: a scheme not valid for the namespace form (`ed25519` needs an
    /// `ed25519-` namespace; the ECDSA schemes need a `0x` namespace).
    SchemeNamespaceMismatch,
    /// §4: a signature blob of the wrong length for its scheme.
    SignatureLength,
    /// §4: the owner signature does not verify (including a non-canonical
    /// Ed25519 signature or a small-order or invalid namespace key, and a
    /// `secp256k1-eip191` signature from which no key recovers).
    BadSignature,
    /// §4: a `secp256k1-eip191` `v` other than 27 or 28.
    SignatureRecoveryId,
    /// §4.4: an ECDSA `r` or `s` outside `[1, n - 1]`.
    SignatureScalar,
    /// §4.4: an ECDSA `s` above `n / 2` (never normalized).
    HighS,
    /// §4.1, §7 step 4: the recovered or derived owner address is not the
    /// namespace.
    OwnerMismatch,
    /// §4.1: a `webauthn-p256` public key that is not a valid P-256 point.
    InvalidOwnerKey,
    /// §4: a `webauthn-p256` blob that is not four length-prefixed fields
    /// with a 64-byte public key and a 64-byte signature, and nothing after.
    WebAuthnBlob,
    /// §4.3 rule 1: `authenticatorData` shorter than 37 bytes.
    AuthenticatorData,
    /// §4.3 rule 1: the user-present flag is clear.
    UserNotPresent,
    /// §4.3 rule 4: the rpIdHash is not the SHA-256 of a configured relying
    /// party id.
    RelyingPartyMismatch,
    /// §4.3 rule 2: `clientDataJSON` is not a JSON object, or has a
    /// duplicate member name at some depth.
    ClientData,
    /// §4.3 rule 2: `type` is not the string `webauthn.get`.
    ClientDataType,
    /// §4.3 rule 2: `challenge` is not the unpadded base64url of the
    /// statement's BLAKE3.
    Challenge,
    /// §4.3 rule 2: `crossOrigin` is present and not `false`.
    CrossOrigin,
    /// §4.3 rule 2: a `topOrigin` member is present.
    TopOrigin,
    /// §4.3 rule 4: `origin` is not an origin configured for the relying
    /// party that signed.
    OriginNotAllowed,
    /// §7 step 2: the grant's namespace is not the request repository's.
    NamespaceMismatch,
    /// §9.1: a visibility statement's repository is not `X-Repository`.
    RepositoryMismatch,
    /// §7 step 5, §5.2 check 4, §9.1: the deployment's own audience is not
    /// in `audiences` (byte comparison).
    AudienceNotListed,
    /// §7 step 6: the repository scope does not cover the repository.
    RepositoryNotInScope,
    /// §7 step 7: the capabilities do not cover the operation.
    CapabilityNotGranted,
    /// §7 step 9, §10: the grantee is not the signer or principal.
    GranteeMismatch,
    /// §7 step 10, §5.2 check 5, §9.1: `created > now + MAX_CLOCK_LEAD_MS`,
    /// or a negative clock reading.
    NotYetValid,
    /// §7 step 10, §5.2 check 5, §9.1: `now >= expiry` (expiry is
    /// exclusive).
    Expired,
    /// Verifier configuration: the deployment's own audience is a loopback
    /// origin (§3.2, §10) and loopback audiences were not explicitly allowed.
    LoopbackAudience,
    /// Verifier configuration: `webauthn-p256` accepted without a configured
    /// relying party (§4.3).
    NoRelyingParty,
    /// Verifier configuration: a relying party whose id is not a lowercase
    /// DNS name, with no origins, an empty, non-ASCII or duplicate origin,
    /// or an id configured twice.
    RelyingParty,
    /// Verifier configuration: a loopback relying party (id `localhost` or
    /// `*.localhost`, or a loopback origin) and loopback was not explicitly
    /// allowed.
    LoopbackRelyingParty,
}

impl GrantError {
    /// Stable reason text for logs and fixtures.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::StatementTooLong => "statement too long",
            Self::CarriageReturn => "carriage return",
            Self::ByteOutOfRange => "byte out of range",
            Self::FinalLineFeed => "final line feed",
            Self::FieldCount => "field count",
            Self::EmptyField => "empty field",
            Self::Domain => "domain",
            Self::Namespace => "namespace",
            Self::RepositoryScope => "repository scope",
            Self::ScopeNamespaceMismatch => "scope namespace mismatch",
            Self::Decimal => "noncanonical decimal",
            Self::DecimalOutOfRange => "decimal out of range",
            Self::Hex => "noncanonical hex",
            Self::Capabilities => "capabilities",
            Self::Audience => "audience",
            Self::AudienceWildcard => "audience wildcard",
            Self::AudienceCount => "audience count",
            Self::AudiencesUnordered => "audiences unordered",
            Self::RefScopesOnRead => "ref scopes on read grant",
            Self::RefScopesMissing => "ref scopes missing",
            Self::RefPattern => "ref pattern",
            Self::PackmapPattern => "packmap pattern",
            Self::UnknownRefFlag => "unknown ref flag",
            Self::RefFlagsNotCanonical => "noncanonical ref flags",
            Self::RefScopeCount => "ref scope count",
            Self::RefScopesUnordered => "ref scopes unordered",
            Self::DuplicateRefPattern => "duplicate ref pattern",
            Self::ExpiryNotAfterCreated => "expiry not after created",
            Self::LifetimeTooLong => "lifetime too long",
            Self::HeaderTooLong => "header too long",
            Self::HeaderFormat => "header format",
            Self::HeaderBase64 => "header base64",
            Self::UnknownScheme => "unknown scheme",
            Self::Repository => "repository",
            Self::Visibility => "visibility",
            Self::SchemeNotAdvertised => "scheme not advertised",
            Self::SchemeNamespaceMismatch => "scheme namespace mismatch",
            Self::SignatureLength => "signature length",
            Self::BadSignature => "bad signature",
            Self::SignatureRecoveryId => "signature recovery id",
            Self::SignatureScalar => "signature scalar",
            Self::HighS => "high s",
            Self::OwnerMismatch => "owner mismatch",
            Self::InvalidOwnerKey => "invalid owner key",
            Self::WebAuthnBlob => "webauthn blob",
            Self::AuthenticatorData => "authenticator data",
            Self::UserNotPresent => "user not present",
            Self::RelyingPartyMismatch => "relying party mismatch",
            Self::ClientData => "client data",
            Self::ClientDataType => "client data type",
            Self::Challenge => "challenge",
            Self::CrossOrigin => "cross origin",
            Self::TopOrigin => "top origin",
            Self::OriginNotAllowed => "origin not allowed",
            Self::NamespaceMismatch => "namespace mismatch",
            Self::RepositoryMismatch => "repository mismatch",
            Self::AudienceNotListed => "audience not listed",
            Self::RepositoryNotInScope => "repository not in scope",
            Self::CapabilityNotGranted => "capability not granted",
            Self::GranteeMismatch => "grantee mismatch",
            Self::NotYetValid => "not yet valid",
            Self::Expired => "expired",
            Self::LoopbackAudience => "loopback audience",
            Self::NoRelyingParty => "no relying party",
            Self::RelyingParty => "relying party",
            Self::LoopbackRelyingParty => "loopback relying party",
        }
    }
}
