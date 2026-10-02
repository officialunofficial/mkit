//! The `mkit-write-grant:v1` statement (SPEC-WRITE-GRANTS §3.2–§3.5).

use mkit_core::repo_identity::{Namespace, RepositoryIdentity};

use super::ref_scope::RefScopes;
use super::text::{
    audiences, check_lifetime, decimal_millis, decimal_u64, encode_audiences, encode_hex32,
    encode_millis, hex32, join_fields, split_fields,
};
use super::{DOMAIN_GRANT, GRANT_MAX_LIFETIME_MS, GrantError};

/// Field count of a grant statement.
const GRANT_FIELDS: usize = 11;

/// What a grant lets its grantee do (§3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Capabilities {
    /// `read`: read a private repository.
    Read,
    /// `read,write`.
    ReadWrite,
    /// `write`: change refs within the ref scopes.
    Write,
}

/// One operation a grant may cover (§7 step 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Capability {
    /// A read of a private repository.
    Read,
    /// A write procedure.
    Write,
}

impl Capabilities {
    /// The canonical token.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::ReadWrite => "read,write",
            Self::Write => "write",
        }
    }

    /// Parse the canonical token; `write,read` and every other spelling fail.
    ///
    /// # Errors
    /// `Capabilities`.
    pub fn parse(s: &str) -> Result<Self, GrantError> {
        match s {
            "read" => Ok(Self::Read),
            "read,write" => Ok(Self::ReadWrite),
            "write" => Ok(Self::Write),
            _ => Err(GrantError::Capabilities),
        }
    }

    /// Whether these capabilities cover `capability`.
    #[must_use]
    pub fn allows(self, capability: Capability) -> bool {
        matches!(
            (self, capability),
            (Self::Read | Self::ReadWrite, Capability::Read)
                | (Self::Write | Self::ReadWrite, Capability::Write)
        )
    }
}

/// The repositories a grant covers (§3.2).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RepoScope {
    /// One repository, `<namespace>/<name>`, in the grant's namespace.
    Repository(RepositoryIdentity),
    /// `<namespace>/*`: every repository in the grant's namespace, including
    /// ones that do not exist yet.
    Namespace,
}

impl RepoScope {
    /// §7 step 6: whether a grant for `namespace` with this scope covers
    /// `repository`. Both variants require `repository` to be in
    /// `namespace`, so a hand-built scope naming another namespace covers
    /// nothing.
    #[must_use]
    pub fn covers(&self, namespace: &Namespace, repository: &RepositoryIdentity) -> bool {
        repository.namespace() == Some(namespace)
            && match self {
                Self::Repository(id) => id == repository,
                Self::Namespace => true,
            }
    }

    fn parse(field: &str, namespace: &Namespace) -> Result<Self, GrantError> {
        let (scope, scope_ns) = if let Some(ns) = field.strip_suffix("/*") {
            let ns = Namespace::parse(ns).map_err(|_| GrantError::RepositoryScope)?;
            (Self::Namespace, ns)
        } else {
            // `parse` requires `<namespace>/<name>`: a bare name fails here.
            let id = RepositoryIdentity::parse(field).map_err(|_| GrantError::RepositoryScope)?;
            let ns = *id.namespace().ok_or(GrantError::RepositoryScope)?;
            (Self::Repository(id), ns)
        };
        if scope_ns != *namespace {
            return Err(GrantError::ScopeNamespaceMismatch);
        }
        Ok(scope)
    }

    fn encode(&self, namespace: &Namespace) -> Result<String, GrantError> {
        match self {
            Self::Namespace => Ok(format!("{namespace}/*")),
            Self::Repository(id) => match id.namespace() {
                None => Err(GrantError::RepositoryScope),
                Some(ns) if ns != namespace => Err(GrantError::ScopeNamespaceMismatch),
                Some(_) => Ok(id.to_string()),
            },
        }
    }
}

/// A parsed `mkit-write-grant:v1` statement.
///
/// [`Grant::parse`] accepts exactly the canonical encoding and
/// [`Grant::encode`] reproduces it, so `encode(parse(b)) == b` for every
/// accepted `b`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// The owner's self-certifying namespace.
    pub namespace: Namespace,
    /// The repositories covered, all in `namespace`.
    pub scope: RepoScope,
    /// The grantee's Ed25519 public key.
    pub grantee: [u8; 32],
    /// What the grantee may do.
    pub capabilities: Capabilities,
    /// 1 to 8 canonical origins in ascending byte order.
    pub audiences: Vec<String>,
    /// `None` exactly when `capabilities` is [`Capabilities::Read`].
    pub ref_scopes: Option<RefScopes>,
    /// Valid only while equal to the stored epoch.
    pub epoch: u64,
    /// Creation time, epoch milliseconds.
    pub created_ms: i64,
    /// Expiry, epoch milliseconds: `created < expiry <= created +
    /// GRANT_MAX_LIFETIME_MS`.
    pub expiry_ms: i64,
    /// 32 random bytes that make each grant distinct.
    pub nonce: [u8; 32],
}

fn ref_scopes_field(
    capabilities: Capabilities,
    field: &str,
) -> Result<Option<RefScopes>, GrantError> {
    match (capabilities, field) {
        (Capabilities::Read, "-") => Ok(None),
        (Capabilities::Read, _) => Err(GrantError::RefScopesOnRead),
        (_, "-") => Err(GrantError::RefScopesMissing),
        (_, field) => RefScopes::parse(field).map(Some),
    }
}

impl Grant {
    /// Parse a statement, enforcing every §3.5 rule. Never repairs.
    ///
    /// The §3.1 byte rules are checked first ([`super::text::split_fields`]),
    /// then each field in statement order, then the lifetime.
    ///
    /// # Errors
    /// The [`GrantError`] of the first failed rule.
    pub fn parse(bytes: &[u8]) -> Result<Self, GrantError> {
        let f = split_fields(bytes, GRANT_FIELDS)?;
        if f[0] != DOMAIN_GRANT {
            return Err(GrantError::Domain);
        }
        let namespace = Namespace::parse(f[1]).map_err(|_| GrantError::Namespace)?;
        let scope = RepoScope::parse(f[2], &namespace)?;
        let grantee = hex32(f[3])?;
        let capabilities = Capabilities::parse(f[4])?;
        let audiences = audiences(f[5])?;
        let ref_scopes = ref_scopes_field(capabilities, f[6])?;
        let epoch = decimal_u64(f[7])?;
        let created_ms = decimal_millis(f[8])?;
        let expiry_ms = decimal_millis(f[9])?;
        let nonce = hex32(f[10])?;
        check_lifetime(created_ms, expiry_ms, GRANT_MAX_LIFETIME_MS)?;
        Ok(Self {
            namespace,
            scope,
            grantee,
            capabilities,
            audiences,
            ref_scopes,
            epoch,
            created_ms,
            expiry_ms,
            nonce,
        })
    }

    /// Encode the canonical statement. Validates every rule [`Grant::parse`]
    /// enforces and never sorts or repairs, so `parse(encode(g)) == g`.
    ///
    /// # Errors
    /// The [`GrantError`] of the first failed rule.
    pub fn encode(&self) -> Result<Vec<u8>, GrantError> {
        let scope = self.scope.encode(&self.namespace)?;
        let audiences = encode_audiences(&self.audiences)?;
        let ref_scopes = match (self.capabilities, &self.ref_scopes) {
            (Capabilities::Read, None) => "-".to_owned(),
            (Capabilities::Read, Some(_)) => return Err(GrantError::RefScopesOnRead),
            (_, None) => return Err(GrantError::RefScopesMissing),
            (_, Some(scopes)) => scopes.to_string(),
        };
        check_lifetime(self.created_ms, self.expiry_ms, GRANT_MAX_LIFETIME_MS)?;
        join_fields(&[
            DOMAIN_GRANT,
            &self.namespace.to_string(),
            &scope,
            &encode_hex32(&self.grantee),
            self.capabilities.token(),
            &audiences,
            &ref_scopes,
            &self.epoch.to_string(),
            &encode_millis(self.created_ms)?,
            &encode_millis(self.expiry_ms)?,
            &encode_hex32(&self.nonce),
        ])
    }

    /// [`Grant::parse`], also returning the grant id (§3.4): the BLAKE3 of
    /// the accepted bytes, which are the canonical encoding.
    ///
    /// # Errors
    /// As [`Grant::parse`].
    pub fn parse_with_id(bytes: &[u8]) -> Result<(Self, [u8; 32]), GrantError> {
        let grant = Self::parse(bytes)?;
        Ok((grant, mkit_core::hash::hash(bytes)))
    }

    /// The grant id (§3.4): the BLAKE3 of the canonical statement,
    /// [`Grant::encode`]. It equals the id [`Grant::parse_with_id`] returns
    /// for the same grant, since `encode(parse(b)) == b`. The id covers
    /// neither the scheme nor the signature.
    ///
    /// The id records which grant a server accepted. It is not an audit
    /// binding: auth v2 does not sign the grant, so it does not show which
    /// grant the signer chose.
    ///
    /// # Errors
    /// As [`Grant::encode`], for a grant that is not valid.
    pub fn id(&self) -> Result<[u8; 32], GrantError> {
        Ok(mkit_core::hash::hash(&self.encode()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDR: &str = "0x8ba1f109551bd432803012645ac136ddd64dba72";
    const KEY: &str = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";
    const NONCE: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    /// The §3.4 example as fields, which each test edits.
    fn fields() -> Vec<String> {
        [
            "mkit-write-grant:v1",
            ADDR,
            &format!("{ADDR}/website"),
            KEY,
            "read,write",
            "https://git.example.com,https://git.example.org",
            "refs/heads/main=cu;refs/heads/wip/*=cufd",
            "0",
            "1790000000000",
            "1792592000000",
            NONCE,
        ]
        .map(str::to_owned)
        .to_vec()
    }

    fn with(i: usize, value: &str) -> Vec<u8> {
        let mut f = fields();
        f[i] = value.to_owned();
        f.join("\n").into_bytes()
    }

    fn rejects(bytes: &[u8], err: GrantError) {
        assert_eq!(
            Grant::parse(bytes),
            Err(err),
            "{}",
            String::from_utf8_lossy(bytes)
        );
    }

    #[test]
    fn spec_example_roundtrips() {
        let bytes = fields().join("\n").into_bytes();
        let g = Grant::parse(&bytes).unwrap();
        assert_eq!(g.capabilities, Capabilities::ReadWrite);
        assert_eq!(g.audiences.len(), 2);
        assert_eq!(g.encode().unwrap(), bytes);
        let (parsed, id) = Grant::parse_with_id(&bytes).unwrap();
        assert_eq!(id, mkit_core::hash::hash(&bytes));
        assert_eq!(parsed.id().unwrap(), id);
        let mut bad = parsed;
        bad.audiences.clear();
        assert_eq!(bad.id(), Err(GrantError::AudienceCount));
    }

    #[test]
    fn rejects_structure() {
        let f = fields();
        rejects(f[..10].join("\n").as_bytes(), GrantError::FieldCount);
        rejects(
            format!("{}\nx", f.join("\n")).as_bytes(),
            GrantError::FieldCount,
        );
        rejects(
            format!("{}\n", f.join("\n")).as_bytes(),
            GrantError::FinalLineFeed,
        );
        rejects(&with(7, "0\r"), GrantError::CarriageReturn);
        rejects(&with(3, &format!("{KEY} ")), GrantError::ByteOutOfRange);
        rejects(&with(3, &format!("{KEY}\x7f")), GrantError::ByteOutOfRange);
        let mut empty = fields();
        empty[7] = String::new();
        rejects(empty.join("\n").as_bytes(), GrantError::EmptyField);
        rejects(&with(0, "mkit-write-grant:v2"), GrantError::Domain);
        rejects(&with(0, "mkit-write-epoch:v1"), GrantError::Domain);
        rejects(&with(0, "mkit-write-grant:v1 "), GrantError::ByteOutOfRange);
    }

    #[test]
    fn rejects_statement_over_max_bytes() {
        // Pad the grantee field; the length check runs before field checks.
        let bytes = fields().join("\n");
        let pad = super::super::MAX_STATEMENT_BYTES + 1 - bytes.len();
        let over = with(3, &format!("{KEY}{}", "a".repeat(pad)));
        assert_eq!(over.len(), super::super::MAX_STATEMENT_BYTES + 1);
        rejects(&over, GrantError::StatementTooLong);
    }

    #[test]
    fn rejects_namespace_and_scope() {
        rejects(&with(1, &ADDR.to_uppercase()), GrantError::Namespace);
        rejects(&with(1, "root"), GrantError::Namespace);
        rejects(
            &with(2, &format!("{ADDR}/Website")),
            GrantError::RepositoryScope,
        );
        rejects(&with(2, "website"), GrantError::RepositoryScope);
        rejects(
            &with(2, &format!("{ADDR}/foo*")),
            GrantError::RepositoryScope,
        );
        rejects(&with(2, "*"), GrantError::RepositoryScope);
        rejects(
            &with(2, &format!("{ADDR}/a/*")),
            GrantError::RepositoryScope,
        );
        let other = "0x0000000000000000000000000000000000000001";
        rejects(
            &with(2, &format!("{other}/website")),
            GrantError::ScopeNamespaceMismatch,
        );
        rejects(
            &with(2, &format!("{other}/*")),
            GrantError::ScopeNamespaceMismatch,
        );
        let g = Grant::parse(&with(2, &format!("{ADDR}/*"))).unwrap();
        assert_eq!(g.scope, RepoScope::Namespace);
    }

    #[test]
    fn rejects_decimals() {
        rejects(&with(7, "+1"), GrantError::Decimal);
        rejects(&with(7, "01"), GrantError::Decimal);
        rejects(
            &with(7, "18446744073709551616"),
            GrantError::DecimalOutOfRange,
        );
        rejects(
            &with(8, "9223372036854775808"),
            GrantError::DecimalOutOfRange,
        );
        rejects(
            &with(9, "9223372036854775808"),
            GrantError::DecimalOutOfRange,
        );
        assert_eq!(
            Grant::parse(&with(7, "18446744073709551615"))
                .unwrap()
                .epoch,
            u64::MAX
        );
    }

    #[test]
    fn rejects_hex() {
        rejects(&with(3, &KEY.to_uppercase()), GrantError::Hex);
        rejects(&with(3, &KEY[..62]), GrantError::Hex);
        rejects(&with(10, &NONCE.to_uppercase()), GrantError::Hex);
        rejects(&with(10, &format!("{NONCE}00")), GrantError::Hex);
    }

    #[test]
    fn rejects_capabilities() {
        for bad in ["admin", "write,read", "Read", "read,read", "read,write,"] {
            rejects(&with(4, bad), GrantError::Capabilities);
        }
    }

    #[test]
    fn rejects_audiences() {
        rejects(&with(5, "https://Git.example.com"), GrantError::Audience);
        rejects(
            &with(5, "https://git.example.com:443"),
            GrantError::Audience,
        );
        rejects(&with(5, "https://git.example.com."), GrantError::Audience);
        rejects(&with(5, "https://git.example.com/x"), GrantError::Audience);
        rejects(&with(5, "https://u@git.example.com"), GrantError::Audience);
        rejects(&with(5, "*"), GrantError::AudienceWildcard);
        rejects(&with(5, "https://git.*.com"), GrantError::AudienceWildcard);
        let nine: Vec<String> = (1..=9).map(|i| format!("https://a{i}.example")).collect();
        rejects(&with(5, &nine.join(",")), GrantError::AudienceCount);
        rejects(
            &with(5, "https://git.example.org,https://git.example.com"),
            GrantError::AudiencesUnordered,
        );
        rejects(
            &with(5, "https://git.example.com,https://git.example.com"),
            GrantError::AudiencesUnordered,
        );
    }

    #[test]
    fn rejects_ref_scope_capability_mismatch() {
        rejects(&with(4, "read"), GrantError::RefScopesOnRead);
        let mut f = fields();
        f[4] = "write".into();
        f[6] = "-".into();
        rejects(f.join("\n").as_bytes(), GrantError::RefScopesMissing);
        f[4] = "read".into();
        let g = Grant::parse(f.join("\n").as_bytes()).unwrap();
        assert_eq!(g.ref_scopes, None);
        assert_eq!(g.encode().unwrap(), f.join("\n").into_bytes());
    }

    #[test]
    fn rejects_ref_scopes() {
        // SPEC-REFS §3 allows `a..b` (no segment starts with `.`).
        assert!(Grant::parse(&with(6, "refs/heads/a..b=c")).is_ok());
        rejects(&with(6, "refs/heads/a~b=c"), GrantError::RefPattern);
        rejects(&with(6, "refs/heads/main.lock=c"), GrantError::RefPattern);
        rejects(&with(6, "refs/heads/.x=c"), GrantError::RefPattern);
        rejects(&with(6, "*=c"), GrantError::RefPattern);
        rejects(&with(6, "refs/heads/*x=c"), GrantError::RefPattern);
        rejects(
            &with(6, "refs/mkit/packmap/*=u"),
            GrantError::PackmapPattern,
        );
        rejects(
            &with(6, "refs/mkit/packmap/main=u"),
            GrantError::PackmapPattern,
        );
        rejects(&with(6, "refs/heads/main=x"), GrantError::UnknownRefFlag);
        rejects(
            &with(6, "refs/heads/main=uc"),
            GrantError::RefFlagsNotCanonical,
        );
        rejects(
            &with(6, "refs/heads/main=cc"),
            GrantError::RefFlagsNotCanonical,
        );
        rejects(
            &with(6, "refs/heads/main="),
            GrantError::RefFlagsNotCanonical,
        );
        let seventeen: Vec<String> = (0..17).map(|i| format!("refs/heads/b{i:02}=c")).collect();
        rejects(&with(6, &seventeen.join(";")), GrantError::RefScopeCount);
        rejects(
            &with(6, "refs/heads/b=c;refs/heads/a=c"),
            GrantError::RefScopesUnordered,
        );
        rejects(
            &with(6, "refs/heads/main=c;refs/heads/main=cu"),
            GrantError::DuplicateRefPattern,
        );
    }

    #[test]
    fn rejects_lifetimes() {
        let mut f = fields();
        f[9] = f[8].clone();
        rejects(f.join("\n").as_bytes(), GrantError::ExpiryNotAfterCreated);
        f[9] = "1789999999999".into();
        rejects(f.join("\n").as_bytes(), GrantError::ExpiryNotAfterCreated);
        f[9] = (1_790_000_000_000_i64 + GRANT_MAX_LIFETIME_MS + 1).to_string();
        rejects(f.join("\n").as_bytes(), GrantError::LifetimeTooLong);
        f[9] = (1_790_000_000_000_i64 + GRANT_MAX_LIFETIME_MS).to_string();
        assert!(Grant::parse(f.join("\n").as_bytes()).is_ok());
    }

    #[test]
    fn encode_validates() {
        let good = Grant::parse(&fields().join("\n").into_bytes()).unwrap();
        let check = |edit: fn(&mut Grant), err: GrantError| {
            let mut g = good.clone();
            edit(&mut g);
            assert_eq!(g.encode(), Err(err));
        };
        check(|g| g.audiences.clear(), GrantError::AudienceCount);
        check(|g| g.audiences.reverse(), GrantError::AudiencesUnordered);
        check(
            |g| g.audiences[0] = "https://a,https://b".into(),
            GrantError::Audience,
        );
        check(|g| g.ref_scopes = None, GrantError::RefScopesMissing);
        check(
            |g| g.capabilities = Capabilities::Read,
            GrantError::RefScopesOnRead,
        );
        check(
            |g| g.expiry_ms = g.created_ms,
            GrantError::ExpiryNotAfterCreated,
        );
        check(|g| g.created_ms = -1, GrantError::DecimalOutOfRange);
        check(
            |g| {
                g.scope = RepoScope::Repository(
                    RepositoryIdentity::parse_bare_allowed("website").unwrap(),
                );
            },
            GrantError::RepositoryScope,
        );
        check(
            |g| g.namespace = Namespace::Address([0; 20]),
            GrantError::ScopeNamespaceMismatch,
        );
    }

    #[test]
    fn capabilities_allow() {
        use Capability::{Read, Write};
        assert!(Capabilities::Read.allows(Read) && !Capabilities::Read.allows(Write));
        assert!(Capabilities::Write.allows(Write) && !Capabilities::Write.allows(Read));
        assert!(Capabilities::ReadWrite.allows(Read) && Capabilities::ReadWrite.allows(Write));
    }

    #[test]
    fn scope_covers() {
        let ns = Namespace::parse(ADDR).unwrap();
        let repo = RepositoryIdentity::parse(&format!("{ADDR}/website")).unwrap();
        let other = RepositoryIdentity::parse(&format!("{ADDR}/blog")).unwrap();
        let foreign =
            RepositoryIdentity::parse("0x0000000000000000000000000000000000000001/website")
                .unwrap();
        let bare = RepositoryIdentity::parse_bare_allowed("website").unwrap();
        // A hand-built grant whose single-repo scope names another
        // namespace covers nothing, not even that repository.
        let mismatched = RepoScope::Repository(foreign.clone());
        assert!(!mismatched.covers(&ns, &foreign) && !mismatched.covers(&ns, &repo));
        let single = RepoScope::Repository(repo.clone());
        assert!(single.covers(&ns, &repo) && !single.covers(&ns, &other));
        assert!(!single.covers(&ns, &foreign) && !single.covers(&ns, &bare));
        let all = RepoScope::Namespace;
        assert!(all.covers(&ns, &repo) && all.covers(&ns, &other));
        assert!(!all.covers(&ns, &foreign) && !all.covers(&ns, &bare));
    }
}
