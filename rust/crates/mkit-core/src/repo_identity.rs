//! Repository identities (SPEC-TRANSPORT-CONNECT §7.4).
//!
//! ```abnf
//! repository = namespace "/" name / name   ; bare name: single-repository deployments only
//! namespace  = ed25519-ns / address-ns
//! ed25519-ns = "ed25519-" 64HEXLC
//! address-ns = "0x" 40HEXLC
//! name       = lead *99tail
//! lead       = %x61-7A / DIGIT
//! tail       = lead / "." / "_" / "-"
//! ```
//!
//! A client may also address a repository on a `namespace_mode = authority`
//! server (SPEC-SERVER §6.2.2), whose namespace is an opaque name that
//! certifies no owner:
//!
//! ```abnf
//! opaque-ns  = lead *71tail              ; never "root", "ed25519-"… or "0x"…
//! remote     = (namespace / opaque-ns) "/" name / name
//! ```
//!
//! The two grammars are disjoint, so which one a namespace is in never needs
//! the server's mode: [`OpaqueNamespace`], [`RemoteNamespace`] and
//! [`RemoteIdentity`] parse the union for client addressing
//! (SPEC-TRANSPORT-CONNECT §7.4).
//!
//! Parsing is strict: identities are lowercase only, so every identity has
//! exactly one spelling, and [`Display`](core::fmt::Display) writes that
//! spelling back. Nothing is repaired or case-folded. This is the one parser
//! for the grammars; the server's addressing and the grant codec
//! (SPEC-WRITE-GRANTS) both use it.

use core::fmt;

use crate::hash::to_hex_bytes;
use crate::write_auth::is_hex;

/// Longest valid identity in bytes: `ed25519-`, 64 hex digits, `/` and a
/// 100-byte name.
pub const MAX_IDENTITY_LEN: usize = 173;
/// Longest valid repository name in bytes.
pub const MAX_NAME_LEN: usize = 100;
/// Longest authority-mode namespace in bytes (SPEC-SERVER §6.2.2).
pub const MAX_OPAQUE_NAMESPACE_LEN: usize = 72;

const ED25519_PREFIX: &str = "ed25519-";
const ADDRESS_PREFIX: &str = "0x";

/// Why a string is not a §7.4 identity. A server maps every variant to
/// `invalid_argument`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IdentityError {
    /// Longer than [`MAX_IDENTITY_LEN`] bytes.
    #[error("repository identity longer than 173 bytes")]
    TooLong,
    /// The namespace is neither `ed25519-<64 hex>` nor `0x<40 hex>`, in
    /// lowercase.
    #[error("namespace outside the SPEC-TRANSPORT-CONNECT §7.4 grammar")]
    Namespace,
    /// The name is empty, longer than 100 bytes, starts with a byte other
    /// than `a-z0-9`, or holds a byte other than `a-z0-9._-`.
    #[error("repository name outside the SPEC-TRANSPORT-CONNECT §7.4 grammar")]
    Name,
    /// A bare name where only `namespace "/" name` is valid.
    #[error("bare repository name where a namespaced identity is required")]
    BareName,
}

/// A self-certifying namespace: it names its owner directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Namespace {
    /// `ed25519-<64 hex>`: owned by that Ed25519 public key.
    Ed25519([u8; 32]),
    /// `0x<40 hex>`: owned by any key whose derived 20-byte address matches.
    Address([u8; 20]),
}

impl Namespace {
    /// Parse the canonical lowercase text form.
    ///
    /// # Errors
    /// [`IdentityError::Namespace`] for any other form, including uppercase
    /// hex, a `0X` prefix and a wrong digit count.
    pub fn parse(s: &str) -> Result<Self, IdentityError> {
        if let Some(hex) = s.strip_prefix(ED25519_PREFIX) {
            decode_hex(hex).map(Self::Ed25519)
        } else if let Some(hex) = s.strip_prefix(ADDRESS_PREFIX) {
            decode_hex(hex).map(Self::Address)
        } else {
            Err(IdentityError::Namespace)
        }
    }
}

impl fmt::Display for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ed25519(key) => write!(f, "{ED25519_PREFIX}{}", to_hex_bytes(key)),
            Self::Address(addr) => write!(f, "{ADDRESS_PREFIX}{}", to_hex_bytes(addr)),
        }
    }
}

/// Lowercase fixed-length hex into `N` bytes.
fn decode_hex<const N: usize>(hex: &str) -> Result<[u8; N], IdentityError> {
    if !is_hex(hex, N) {
        return Err(IdentityError::Namespace);
    }
    let nibble = |b: u8| {
        if b.is_ascii_digit() {
            b - b'0'
        } else {
            b - b'a' + 10
        }
    };
    let mut out = [0u8; N];
    for (byte, pair) in out.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        *byte = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    Ok(out)
}

/// Validate a §7.4 `name`: 1 to 100 bytes, `[a-z0-9][a-z0-9._-]*`.
///
/// # Errors
/// [`IdentityError::Name`].
pub fn validate_name(name: &str) -> Result<(), IdentityError> {
    let lead = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let bytes = name.as_bytes();
    match bytes.split_first() {
        Some((&first, rest))
            if bytes.len() <= MAX_NAME_LEN
                && lead(first)
                && rest.iter().all(|&b| lead(b) || b"._-".contains(&b)) =>
        {
            Ok(())
        }
        _ => Err(IdentityError::Name),
    }
}

/// A repository identity: `namespace "/" name`, or a bare `name` on a
/// single-repository deployment.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RepositoryIdentity {
    namespace: Option<Namespace>,
    name: String,
}

impl RepositoryIdentity {
    /// Build an identity from its parts.
    ///
    /// # Errors
    /// [`IdentityError::Name`] if `name` is outside the grammar.
    pub fn new(namespace: Option<Namespace>, name: &str) -> Result<Self, IdentityError> {
        validate_name(name)?;
        Ok(Self {
            namespace,
            name: name.to_owned(),
        })
    }

    /// Parse `namespace "/" name`, the only form a multi-repository
    /// deployment accepts.
    ///
    /// # Errors
    /// [`IdentityError::BareName`] for a bare name, otherwise as
    /// [`Self::parse_bare_allowed`].
    pub fn parse(s: &str) -> Result<Self, IdentityError> {
        let id = Self::parse_bare_allowed(s)?;
        if id.namespace.is_none() {
            return Err(IdentityError::BareName);
        }
        Ok(id)
    }

    /// Parse either form. Only a single-repository deployment, which
    /// configures exactly one identity, may accept a bare name.
    ///
    /// # Errors
    /// [`IdentityError::TooLong`], [`IdentityError::Namespace`] or
    /// [`IdentityError::Name`] (which also covers a second `/`).
    pub fn parse_bare_allowed(s: &str) -> Result<Self, IdentityError> {
        if s.len() > MAX_IDENTITY_LEN {
            return Err(IdentityError::TooLong);
        }
        match s.split_once('/') {
            Some((namespace, name)) => Self::new(Some(Namespace::parse(namespace)?), name),
            None => Self::new(None, s),
        }
    }

    /// The namespace, or `None` for a bare name.
    #[must_use]
    pub fn namespace(&self) -> Option<&Namespace> {
        self.namespace.as_ref()
    }

    /// The name within the namespace.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for RepositoryIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.namespace {
            Some(namespace) => write!(f, "{namespace}/{}", self.name),
            None => f.write_str(&self.name),
        }
    }
}

/// An authority-mode namespace: `[a-z0-9][a-z0-9._-]{0,71}`, never `root`,
/// never starting with `ed25519-` or `0x`. It names no owner.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OpaqueNamespace(String);

impl OpaqueNamespace {
    /// Parse the canonical lowercase text form.
    ///
    /// # Errors
    /// [`IdentityError::Namespace`] for any other form.
    pub fn parse(s: &str) -> Result<Self, IdentityError> {
        if s.len() > MAX_OPAQUE_NAMESPACE_LEN
            || s == "root"
            || s.starts_with(ED25519_PREFIX)
            || s.starts_with(ADDRESS_PREFIX)
        {
            return Err(IdentityError::Namespace);
        }
        validate_name(s).map_err(|_| IdentityError::Namespace)?;
        Ok(Self(s.to_owned()))
    }

    /// The canonical lowercase text form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OpaqueNamespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A namespace a client may address: either grammar
/// (SPEC-TRANSPORT-CONNECT §7.4).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum RemoteNamespace {
    /// A self-certifying `ed25519-`/`0x` namespace; it names its owner.
    SelfCertifying(Namespace),
    /// An authority-mode opaque namespace; it names no owner.
    Opaque(OpaqueNamespace),
}

impl RemoteNamespace {
    /// Parse either grammar. The grammars are disjoint — an opaque
    /// namespace never starts with `ed25519-` or `0x` — so exactly one
    /// applies.
    ///
    /// # Errors
    /// [`IdentityError::Namespace`] for text outside both grammars.
    pub fn parse(s: &str) -> Result<Self, IdentityError> {
        Namespace::parse(s)
            .map(Self::SelfCertifying)
            .or_else(|_| OpaqueNamespace::parse(s).map(Self::Opaque))
    }
}

impl fmt::Display for RemoteNamespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelfCertifying(ns) => ns.fmt(f),
            Self::Opaque(ns) => ns.fmt(f),
        }
    }
}

/// A repository a client addresses: `namespace "/" name` in either grammar,
/// or a bare `name` on a single-repository deployment.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RemoteIdentity {
    namespace: Option<RemoteNamespace>,
    name: String,
}

impl RemoteIdentity {
    /// Parse `namespace "/" name`, the only form a multi-repository
    /// deployment accepts.
    ///
    /// # Errors
    /// [`IdentityError::BareName`] for a bare name, otherwise as
    /// [`Self::parse_bare_allowed`].
    pub fn parse(s: &str) -> Result<Self, IdentityError> {
        let remote = Self::parse_bare_allowed(s)?;
        if remote.namespace.is_none() {
            return Err(IdentityError::BareName);
        }
        Ok(remote)
    }

    /// Parse either form. Only a single-repository deployment, which
    /// configures exactly one identity, may accept a bare name.
    ///
    /// # Errors
    /// [`IdentityError::TooLong`], [`IdentityError::Namespace`] or
    /// [`IdentityError::Name`] (which also covers a second `/`).
    pub fn parse_bare_allowed(s: &str) -> Result<Self, IdentityError> {
        if s.len() > MAX_IDENTITY_LEN {
            return Err(IdentityError::TooLong);
        }
        let (namespace, name) = match s.split_once('/') {
            Some((namespace, name)) => (Some(RemoteNamespace::parse(namespace)?), name),
            None => (None, s),
        };
        validate_name(name)?;
        Ok(Self {
            namespace,
            name: name.to_owned(),
        })
    }

    /// The namespace, or `None` for a bare name.
    #[must_use]
    pub fn namespace(&self) -> Option<&RemoteNamespace> {
        self.namespace.as_ref()
    }

    /// The name within the namespace.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The strict self-certifying identity; `None` for an opaque namespace.
    /// A bare name yields a bare identity.
    #[must_use]
    pub fn to_identity(&self) -> Option<RepositoryIdentity> {
        let namespace = match self.namespace.as_ref() {
            None => None,
            Some(RemoteNamespace::SelfCertifying(ns)) => Some(*ns),
            Some(RemoteNamespace::Opaque(_)) => return None,
        };
        RepositoryIdentity::new(namespace, &self.name).ok()
    }
}

impl fmt::Display for RemoteIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.namespace {
            Some(namespace) => write!(f, "{namespace}/{}", self.name),
            None => f.write_str(&self.name),
        }
    }
}

impl From<RepositoryIdentity> for RemoteIdentity {
    fn from(identity: RepositoryIdentity) -> Self {
        Self {
            namespace: identity.namespace.map(RemoteNamespace::SelfCertifying),
            name: identity.name,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "ed25519-3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";
    const ADDR: &str = "0x8ba1f109551bd432803012645ac136ddd64dba72";

    fn roundtrip(s: &str) -> RepositoryIdentity {
        let id = RepositoryIdentity::parse(s).unwrap();
        assert_eq!(id.to_string(), s);
        id
    }

    #[test]
    fn accepts_both_namespace_forms() {
        let id = roundtrip(&format!("{KEY}/website"));
        assert!(matches!(id.namespace(), Some(Namespace::Ed25519(k)) if k[0] == 0x3b));
        assert_eq!(id.name(), "website");
        let id = roundtrip(&format!("{ADDR}/a.b_c-9"));
        assert!(matches!(id.namespace(), Some(Namespace::Address(a)) if a[19] == 0x72));
        assert_eq!(Namespace::parse(ADDR).unwrap().to_string(), ADDR);
    }

    #[test]
    fn accepts_the_longest_identity() {
        let s = format!("{KEY}/{}", "a".repeat(MAX_NAME_LEN));
        assert_eq!(s.len(), MAX_IDENTITY_LEN);
        roundtrip(&s);
        let s = format!("{KEY}/{}", "a".repeat(MAX_NAME_LEN + 1));
        assert_eq!(RepositoryIdentity::parse(&s), Err(IdentityError::TooLong));
    }

    #[test]
    fn rejects_bad_namespaces() {
        let upper = KEY.replace('b', "B");
        let cases = [
            upper.as_str(),
            "0x8BA1F109551BD432803012645AC136DDD64DBA72",
            "0X8ba1f109551bd432803012645ac136ddd64dba72",
            "0x8ba1f109551bd432803012645ac136ddd64dba7",
            "0x8ba1f109551bd432803012645ac136ddd64dba722",
            &KEY[..KEY.len() - 1],
            "ed25519-",
            "0x",
            "",
            "root",
            "ed25519:3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
        ];
        for ns in cases {
            assert_eq!(Namespace::parse(ns), Err(IdentityError::Namespace), "{ns}");
            assert_eq!(
                RepositoryIdentity::parse(&format!("{ns}/x")),
                Err(IdentityError::Namespace),
                "{ns}"
            );
        }
    }

    #[test]
    fn rejects_bad_names() {
        let long = "a".repeat(MAX_NAME_LEN + 1);
        for name in [
            "", ".x", "_x", "-x", "Web", "weB", "a/b", "a b", "a*", "é", &long,
        ] {
            assert_eq!(
                RepositoryIdentity::parse(&format!("{ADDR}/{name}")),
                Err(IdentityError::Name),
                "{name:?}"
            );
            assert!(
                RepositoryIdentity::parse_bare_allowed(name).is_err(),
                "{name:?}"
            );
        }
        assert_eq!(
            RepositoryIdentity::parse(&format!("{ADDR}/a/b")),
            Err(IdentityError::Name)
        );
        assert_eq!(
            RepositoryIdentity::parse(&format!("/{ADDR}/a")),
            Err(IdentityError::Namespace)
        );
    }

    #[test]
    fn bare_names_only_when_allowed() {
        assert_eq!(
            RepositoryIdentity::parse("default"),
            Err(IdentityError::BareName)
        );
        let id = RepositoryIdentity::parse_bare_allowed("default").unwrap();
        assert_eq!(id.namespace(), None);
        assert_eq!(id.to_string(), "default");
        // A bare name that happens to spell a namespace is still a name.
        let id = RepositoryIdentity::parse_bare_allowed(ADDR).unwrap();
        assert_eq!(id.namespace(), None);
        assert_eq!(
            RepositoryIdentity::parse_bare_allowed(&"a".repeat(MAX_NAME_LEN))
                .unwrap()
                .name()
                .len(),
            MAX_NAME_LEN
        );
    }

    #[test]
    fn opaque_namespace_accepts_name_grammar_names() {
        // The accepted/rejected lists mirror the server's disjointness test.
        for ns in [
            "alpha",
            "a",
            "0",
            "my-org",
            "team.alpha_beta",
            "019c88c3-a904-7bd1-8a5d-3182a0c6978a",
            "x",
            &"x".repeat(72),
        ] {
            assert_eq!(
                OpaqueNamespace::parse(ns).unwrap().as_str(),
                ns,
                "{ns} must parse"
            );
        }
    }

    #[test]
    fn opaque_namespace_rejects_reserved_and_out_of_grammar() {
        for ns in [
            // Reserved names / self-certifying prefixes.
            "root",
            "ed25519-3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
            "ed25519-x",
            "0x8ba1f109551bd432803012645ac136ddd64dba72",
            "0xg",
            // Name-grammar violations.
            "",
            "-leading",
            ".leading",
            "_leading",
            "UPPER",
            "has space",
            "a/b",
            "a?b",
            "a#b",
            &"x".repeat(73),
        ] {
            assert_eq!(
                OpaqueNamespace::parse(ns),
                Err(IdentityError::Namespace),
                "{ns} must not parse"
            );
        }
    }

    #[test]
    fn namespace_grammars_are_disjoint() {
        for text in [
            KEY,
            ADDR,
            "ed25519-z",
            "0xz",
            "alpha",
            "019c88c3-a904-7bd1-8a5d-3182a0c6978a",
            "root",
            "a",
            "UPPER",
            "a/b",
            &"x".repeat(72),
            &"x".repeat(73),
            "",
        ] {
            assert!(
                !(Namespace::parse(text).is_ok() && OpaqueNamespace::parse(text).is_ok()),
                "{text} must not parse under both grammars"
            );
        }
    }

    #[test]
    fn remote_namespace_selects_the_disjoint_grammar() {
        assert_eq!(
            RemoteNamespace::parse(KEY).unwrap(),
            RemoteNamespace::SelfCertifying(Namespace::parse(KEY).unwrap())
        );
        let uuid = "019c88c3-a904-7bd1-8a5d-3182a0c6978a";
        assert_eq!(
            RemoteNamespace::parse(uuid).unwrap(),
            RemoteNamespace::Opaque(OpaqueNamespace::parse(uuid).unwrap())
        );
        for bad in ["", "root", "ed25519-z", "0xz", "UPPER", "a/b"] {
            assert_eq!(
                RemoteNamespace::parse(bad),
                Err(IdentityError::Namespace),
                "{bad} must not parse"
            );
        }
        assert_eq!(RemoteNamespace::parse(uuid).unwrap().to_string(), uuid);
    }

    #[test]
    fn remote_identity_parse_bare_allowed_round_trips() {
        for text in [
            &format!("{KEY}/website"),
            &format!("{ADDR}/website"),
            "019c88c3-a904-7bd1-8a5d-3182a0c6978a/public",
            &format!("{}/{}", "x".repeat(72), "b".repeat(MAX_NAME_LEN)),
            "bare",
        ] {
            let remote = RemoteIdentity::parse_bare_allowed(text).unwrap();
            assert_eq!(remote.to_string(), text);
        }
    }

    #[test]
    fn remote_identity_parse_requires_a_namespace() {
        assert_eq!(
            RemoteIdentity::parse("019c88c3-a904-7bd1-8a5d-3182a0c6978a"),
            Err(IdentityError::BareName)
        );
        assert_eq!(RemoteIdentity::parse("repo"), Err(IdentityError::BareName));
        let uuid_repo = "019c88c3-a904-7bd1-8a5d-3182a0c6978a/public";
        let remote = RemoteIdentity::parse(uuid_repo).unwrap();
        assert_eq!(remote.name(), "public");
        assert!(matches!(
            remote.namespace(),
            Some(RemoteNamespace::Opaque(_))
        ));
        assert_eq!(remote.to_string(), uuid_repo);
    }

    #[test]
    fn remote_identity_rejects_malformed_in_order() {
        assert_eq!(
            RemoteIdentity::parse_bare_allowed(&"a".repeat(MAX_IDENTITY_LEN + 1)),
            Err(IdentityError::TooLong)
        );
        for bad in ["/repo", "-bad/repo", "ed25519-z/repo", "0xz/repo"] {
            assert_eq!(
                RemoteIdentity::parse_bare_allowed(bad),
                Err(IdentityError::Namespace),
                "{bad} must fail at the namespace"
            );
        }
        for bad in ["ns/extra/name", "ns//repo", &format!("{KEY}/Name")] {
            assert_eq!(
                RemoteIdentity::parse_bare_allowed(bad),
                Err(IdentityError::Name),
                "{bad} must fail at the name"
            );
        }
        assert_eq!(
            RemoteIdentity::parse_bare_allowed("UPPER"),
            Err(IdentityError::Name)
        );
    }

    #[test]
    fn remote_identity_to_identity() {
        assert!(
            RemoteIdentity::parse(&format!("{KEY}/website"))
                .unwrap()
                .to_identity()
                .is_some()
        );
        assert!(
            RemoteIdentity::parse_bare_allowed("bare")
                .unwrap()
                .to_identity()
                .is_some()
        );
        assert!(
            RemoteIdentity::parse("019c88c3-a904-7bd1-8a5d-3182a0c6978a/public")
                .unwrap()
                .to_identity()
                .is_none()
        );
    }

    #[test]
    fn remote_identity_from_identity() {
        let identity = RepositoryIdentity::parse(&format!("{KEY}/website")).unwrap();
        let remote = RemoteIdentity::from(identity.clone());
        assert_eq!(remote.to_string(), format!("{KEY}/website"));
        assert_eq!(remote.to_identity().unwrap(), identity);
        let bare = RepositoryIdentity::parse_bare_allowed("bare").unwrap();
        assert_eq!(RemoteIdentity::from(bare).to_string(), "bare");
    }

    #[test]
    fn new_validates_the_name() {
        let ns = Namespace::parse(ADDR).unwrap();
        assert!(RepositoryIdentity::new(Some(ns), "ok").is_ok());
        assert_eq!(
            RepositoryIdentity::new(Some(ns), "Bad"),
            Err(IdentityError::Name)
        );
    }
}
