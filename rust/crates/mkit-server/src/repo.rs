//! Repository and namespace identifiers (PRD §6.1).
//!
//! M0 serves a single repository per deployment. The `namespace/name`
//! grammar and multi-repository addressing arrive in M1
//! (SPEC-TRANSPORT-CONNECT v2 §7.4); until then a [`RepoName`] is validated
//! exactly like the auth v2 `repository` component.

use crate::error::ServerError;

/// Longest accepted repository name, matching the auth v2 `repository`
/// component bound (`mkit_core::write_auth`).
const MAX_REPO_NAME_BYTES: usize = 255;

/// The namespace a single-repository deployment uses: a reserved sentinel.
/// SPEC-TRANSPORT-CONNECT §7.4 namespaces are always `ed25519-<64 hex>` or
/// `0x<40 hex>`, so no request can ever select `root`. It matches the
/// `vcs-worker` `RefStore` instance name, so M0 needs no Durable Object
/// migration (planner default Q13).
const DEPLOYMENT_DEFAULT_NAMESPACE: &str = "root";

/// A repository name: 1..=255 bytes of printable ASCII with no whitespace
/// (bytes `0x21..=0x7e`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RepoName(String);

impl RepoName {
    /// Validate `name`.
    ///
    /// # Errors
    /// [`crate::Code::InvalidArgument`] if `name` is empty, longer than 255
    /// bytes, or holds a byte outside `0x21..=0x7e`.
    pub fn new(name: impl Into<String>) -> Result<Self, ServerError> {
        let name = name.into();
        if name.is_empty()
            || name.len() > MAX_REPO_NAME_BYTES
            || !name.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err(ServerError::invalid_argument(
                "repository name must be 1-255 printable ASCII bytes without whitespace",
            ));
        }
        Ok(Self(name))
    }

    /// The name as given.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A namespace key. Under D34 it selects the namespace coordinator and
/// prefixes every shard key. M0 has only the deployment default; the
/// self-certifying namespace grammar (D4) lands in M1.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NamespaceKey(String);

impl NamespaceKey {
    /// The namespace of a single-repository deployment: the reserved
    /// sentinel `"root"`, which the SPEC-TRANSPORT-CONNECT §7.4 namespace
    /// grammar (`ed25519-…` / `0x…`) can never select.
    #[must_use]
    pub fn deployment_default() -> Self {
        Self(DEPLOYMENT_DEFAULT_NAMESPACE.to_owned())
    }

    /// The key as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A repository's full identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RepoId {
    /// Owning namespace.
    pub namespace: NamespaceKey,
    /// Name within the namespace.
    pub name: RepoName,
}

/// How a deployment maps a request to a repository. M1 adds multi-repository
/// addressing (`Multi { policy }`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Addressing {
    /// One configured repository serves every request.
    Single {
        /// The configured repository.
        repo: RepoId,
    },
}

impl Addressing {
    /// Resolve the repository a request targets.
    ///
    /// M0 wire compatibility: on a single-repository deployment the
    /// `X-Repository` header is ignored and every request resolves to the
    /// configured repository. Reads are unaffected by it today; writes are
    /// bound to the deployment's repository by the auth v2 context instead.
    /// M1 validates the header against SPEC-TRANSPORT-CONNECT v2 §7.4.
    ///
    /// # Errors
    /// None in M0; M1 rejects a mismatched or malformed header.
    pub fn resolve(&self, x_repository: Option<&str>) -> Result<&RepoId, ServerError> {
        let _ = x_repository;
        match self {
            Self::Single { repo } => Ok(repo),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Code;

    #[test]
    fn repo_name_rejects_whitespace_newline_empty_and_256_bytes() {
        for bad in [
            String::new(),
            "has space".into(),
            "tab\there".into(),
            "line\nbreak".into(),
            "trailing\r".into(),
            "del\u{7f}".into(),
            "caf\u{e9}".into(),
            "a".repeat(256),
        ] {
            let err = RepoName::new(bad.clone()).expect_err(&bad);
            assert_eq!(err.code(), Code::InvalidArgument);
        }
        for good in [
            "a".to_owned(),
            "room-a".into(),
            "~!@#/x_y.z".into(),
            "a".repeat(255),
        ] {
            assert_eq!(RepoName::new(good.clone()).unwrap().as_str(), good);
        }
    }

    #[test]
    fn single_addressing_ignores_header_in_m0() {
        let repo = RepoId {
            namespace: NamespaceKey::deployment_default(),
            name: RepoName::new("room-a").unwrap(),
        };
        let addressing = Addressing::Single { repo: repo.clone() };
        // M0 wire compat: the header never changes the target. M1 replaces
        // this test when it starts validating `X-Repository`.
        assert_eq!(addressing.resolve(None).unwrap(), &repo);
        assert_eq!(addressing.resolve(Some("other")).unwrap(), &repo);
        assert_eq!(addressing.resolve(Some("")).unwrap(), &repo);
    }

    #[test]
    fn deployment_default_namespace_is_stable() {
        assert_eq!(NamespaceKey::deployment_default().as_str(), "root");
    }
}
