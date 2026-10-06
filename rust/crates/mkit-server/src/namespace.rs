//! Deployment namespace grammar and trust model (SPEC-SERVER §6.2.2).

use crate::NamespaceKey;
use mkit_core::repo_identity::{
    IdentityError, MAX_IDENTITY_LEN, Namespace as OwnerNamespace, validate_name,
};
use std::fmt;

/// Deployment trust root for repository names. Defaults to self-certifying names.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NamespaceMode {
    /// The namespace identifies its owner key or address.
    #[default]
    SelfCertifying,
    /// Opaque names whose ownership comes only from the Authority hook.
    Authority,
}

impl NamespaceMode {
    /// Parse a deployment setting without repairing its spelling.
    /// # Errors
    /// Unknown mode names.
    pub fn parse(text: &str) -> Result<Self, &'static str> {
        match text {
            "self_certifying" => Ok(Self::SelfCertifying),
            "authority" => Ok(Self::Authority),
            _ => Err("NAMESPACE_MODE must be self_certifying or authority"),
        }
    }

    pub(crate) fn admin_namespace(self, text: &str) -> Result<(), IdentityError> {
        if text == "root" && self == Self::SelfCertifying {
            return Ok(());
        }
        self.namespace(text).map(|_| ())
    }

    pub(crate) fn admin_repository(self, text: &str) -> Result<(), IdentityError> {
        let (namespace, name) = text.split_once('/').ok_or(IdentityError::BareName)?;
        self.admin_namespace(namespace)?;
        validate_name(name)
    }

    /// Validate a namespace in this deployment's grammar.
    /// # Errors
    /// Wrong-mode, reserved, uppercase, empty, or oversized namespaces.
    pub fn namespace(self, text: &str) -> Result<Namespace, IdentityError> {
        match self {
            Self::SelfCertifying => OwnerNamespace::parse(text).map(Namespace::SelfCertifying),
            Self::Authority => {
                if text.len() > 72
                    || text == "root"
                    || text.starts_with("ed25519-")
                    || text.starts_with("0x")
                {
                    return Err(IdentityError::Namespace);
                }
                validate_name(text).map_err(|_| IdentityError::Namespace)?;
                Ok(Namespace::Authority(AuthorityName(text.to_owned())))
            }
        }
    }
}

/// A grammar-validated opaque namespace. Construct it with [`NamespaceMode::namespace`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AuthorityName(String);

/// A validated namespace with explicit ownership semantics.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Namespace {
    /// The unchanged owner-key or owner-address grammar.
    SelfCertifying(OwnerNamespace),
    /// A syntactically valid name, carrying no owner key.
    Authority(AuthorityName),
}

impl Namespace {
    /// Parse either grammar for a stored or deployment-signed selector.
    /// Request boundaries must use [`NamespaceMode::namespace`] instead.
    /// # Errors
    /// Text outside both grammars.
    pub fn parse_stored(text: &str) -> Result<Self, IdentityError> {
        NamespaceMode::SelfCertifying
            .namespace(text)
            .or_else(|_| NamespaceMode::Authority.namespace(text))
    }

    /// The storage key for this validated namespace.
    #[must_use]
    pub fn key(&self) -> NamespaceKey {
        NamespaceKey::from_stored(self.to_string())
    }
}

impl fmt::Display for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelfCertifying(ns) => ns.fmt(f),
            Self::Authority(name) => f.write_str(&name.0),
        }
    }
}

/// A server repository identity supporting both deployment grammars.
/// CLI and owner-statement codecs retain the strict core identity type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryIdentity {
    namespace: Option<Namespace>,
    name: String,
}

impl RepositoryIdentity {
    /// Parse either grammar for stored or deployment-signed identities.
    /// # Errors
    /// Invalid namespace, name, or total length.
    pub fn parse_stored_bare_allowed(text: &str) -> Result<Self, IdentityError> {
        Self::parse_inner(text, None, true)
    }

    /// Parse in a deployment's grammar. Bare names require Single addressing.
    /// # Errors
    /// Invalid or wrong-mode identities.
    pub fn parse(
        text: &str,
        mode: NamespaceMode,
        bare_allowed: bool,
    ) -> Result<Self, IdentityError> {
        Self::parse_inner(text, Some(mode), bare_allowed)
    }

    fn parse_inner(
        text: &str,
        mode: Option<NamespaceMode>,
        bare_allowed: bool,
    ) -> Result<Self, IdentityError> {
        if text.len() > MAX_IDENTITY_LEN {
            return Err(IdentityError::TooLong);
        }
        let (namespace, name) = match text.split_once('/') {
            Some((ns, name)) => (
                Some(match mode {
                    Some(mode) => mode.namespace(ns)?,
                    None => Namespace::parse_stored(ns)?,
                }),
                name,
            ),
            None if bare_allowed => (None, text),
            None => return Err(IdentityError::BareName),
        };
        validate_name(name)?;
        Ok(Self {
            namespace,
            name: name.to_owned(),
        })
    }

    /// The namespace, absent for a Single deployment's bare name.
    #[must_use]
    pub fn namespace(&self) -> Option<&Namespace> {
        self.namespace.as_ref()
    }
    /// Name within the namespace.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for RepositoryIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ns) = &self.namespace {
            write!(f, "{ns}/")?;
        }
        f.write_str(&self.name)
    }
}

pub(crate) fn owner_statements_refused() -> crate::ServerError {
    crate::ServerError::permission_denied(
        "owner statements are not supported in authority namespace mode",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn grammars_are_disjoint_bounded_and_url_safe() {
        let uuid = "019c88c3-a904-7bd1-8a5d-3182a0c6978a";
        let owner = format!("ed25519-{}", "a".repeat(64));
        let address = format!("0x{}", "b".repeat(40));
        for name in [uuid, "a", "a.b_c-9", &"a".repeat(72)] {
            let namespace = NamespaceMode::Authority.namespace(name).unwrap();
            assert_eq!(namespace.to_string(), name);
            assert!(NamespaceMode::SelfCertifying.namespace(name).is_err());
        }
        for name in [
            "",
            "root",
            "Root",
            "/",
            "a/b",
            ".a",
            "_a",
            "-a",
            "A",
            "a%2fb",
            "a~b",
            "a\n",
            "a b",
            "é",
            "ed25519-",
            "ed25519-a",
            "0x",
            "0xaddress",
            &owner,
            &address,
            &"a".repeat(73),
        ] {
            assert!(
                NamespaceMode::Authority.namespace(name).is_err(),
                "{name:?}"
            );
        }
        for name in [&owner, &address] {
            assert!(NamespaceMode::SelfCertifying.namespace(name).is_ok());
        }
        assert!(NamespaceMode::Authority.admin_namespace("root").is_err());
        assert!(NamespaceMode::SelfCertifying.admin_namespace(uuid).is_err());
        assert!(
            NamespaceMode::Authority
                .admin_repository(&format!("{owner}/repo"))
                .is_err()
        );
        let longest = format!("{}/{}", "a".repeat(72), "b".repeat(100));
        assert_eq!(
            RepositoryIdentity::parse(&longest, NamespaceMode::Authority, false)
                .unwrap()
                .to_string(),
            longest
        );
        assert!(
            RepositoryIdentity::parse(
                &format!("{uuid}/repo/other"),
                NamespaceMode::Authority,
                false
            )
            .is_err()
        );
        assert!(RepositoryIdentity::parse(uuid, NamespaceMode::Authority, false).is_err());
        assert_eq!(NamespaceMode::default(), NamespaceMode::SelfCertifying);
        for mode in ["", "Authority", "authority ", "self-certifying"] {
            assert!(NamespaceMode::parse(mode).is_err());
        }
    }
}
