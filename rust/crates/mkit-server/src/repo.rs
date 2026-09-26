//! Repository and namespace identifiers (PRD §6.1).
//!
//! Single deployments retain their configured name and `root` namespace.
//! Multi deployments use SPEC-TRANSPORT-CONNECT §7.4 identities.

use mkit_core::repo_identity::{Namespace, RepositoryIdentity};

use crate::error::ServerError;

/// Longest accepted repository name, matching the auth v2 `repository`
/// component bound (`mkit_core::write_auth`).
pub(crate) const MAX_REPO_NAME_BYTES: usize = 255;

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
/// prefixes every shard key. Single deployments use the reserved default;
/// Multi deployments use a parsed self-certifying namespace (§7.4).
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

    /// A canonical namespace already validated by the shared grammar.
    pub(crate) fn from_namespace(namespace: &Namespace) -> Self {
        Self(namespace.to_string())
    }

    /// A key read back from storage (`Partition::decode`): the store only
    /// ever holds keys this server encoded.
    pub(crate) fn from_stored(key: String) -> Self {
        Self(key)
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

/// Multi-repository addressing. Namespace policy is added by WP-1.5.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MultiAddressing {}

impl MultiAddressing {
    /// Route requests using their namespaced `X-Repository` identity.
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }
}

/// A resolved request target and its byte-exact wire identity.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResolvedRepo {
    /// The storage identity (single deployments retain the M0 layout).
    pub repo: RepoId,
    /// The identity carried on the wire.
    pub identity: String,
}

/// How a deployment maps a request to a repository.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Addressing {
    /// One configured repository, with optional addressing on unsigned RPCs.
    Single {
        /// The configured repository.
        repo: RepoId,
    },
    /// Routes by `X-Repository`; not deployable until WP-1.10 lands pack membership.
    Multi(MultiAddressing),
}

impl Addressing {
    /// Resolve the request target using SPEC-TRANSPORT-CONNECT §7.4.
    /// Empty headers count as absent; identities are never normalized.
    ///
    /// # Errors
    /// `invalid_argument` for malformed identities or missing Multi headers;
    /// `unauthenticated` for missing signed Single headers; `not_found` for
    /// another well-formed identity on a Single deployment.
    pub fn resolve(
        &self,
        x_repository: Option<&str>,
        signed: bool,
    ) -> Result<ResolvedRepo, ServerError> {
        let header = x_repository.filter(|s| !s.is_empty());
        let invalid = || ServerError::invalid_argument("invalid X-Repository");
        match self {
            Self::Single { repo } => {
                if let Some(header) = header {
                    RepositoryIdentity::parse_bare_allowed(header).map_err(|_| invalid())?;
                    if header != repo.name.as_str() {
                        return Err(ServerError::not_found("repository not found"));
                    }
                } else if signed {
                    return Err(ServerError::unauthenticated(
                        "missing X-Repository on a signed request",
                    ));
                }
                Ok(ResolvedRepo {
                    repo: repo.clone(),
                    identity: repo.name.as_str().to_owned(),
                })
            }
            Self::Multi(_) => {
                let header = header.ok_or_else(invalid)?;
                let identity = RepositoryIdentity::parse(header).map_err(|_| invalid())?;
                let namespace = identity.namespace().ok_or_else(invalid)?;
                Ok(ResolvedRepo {
                    repo: RepoId {
                        namespace: NamespaceKey::from_namespace(namespace),
                        name: RepoName::new(identity.name())?,
                    },
                    identity: header.to_owned(),
                })
            }
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
    fn single_addressing_rejects_another_identity() {
        let addressing = Addressing::Single {
            repo: RepoId {
                namespace: NamespaceKey::deployment_default(),
                name: RepoName::new("room-a").unwrap(),
            },
        };
        assert_eq!(
            addressing
                .resolve(Some("room-b"), false)
                .unwrap_err()
                .code(),
            Code::NotFound
        );
    }

    fn single(identity: &str) -> Addressing {
        Addressing::Single {
            repo: RepoId {
                namespace: NamespaceKey::deployment_default(),
                name: RepoName::new(identity).unwrap(),
            },
        }
    }

    #[test]
    fn resolution_table_and_safe_errors() {
        let single = single("default");
        let multi = Addressing::Multi(MultiAddressing::new());
        for signed in [false, true] {
            for absent in [None, Some("")] {
                let result = single.resolve(absent, signed);
                if signed {
                    let e = result.unwrap_err();
                    assert_eq!(e.code(), Code::Unauthenticated);
                    assert_eq!(
                        e.public_message(),
                        "missing X-Repository on a signed request"
                    );
                } else {
                    assert_eq!(
                        result.unwrap(),
                        single.resolve(Some("default"), false).unwrap()
                    );
                }
                let e = multi.resolve(absent, signed).unwrap_err();
                assert_eq!(e.code(), Code::InvalidArgument);
                assert_eq!(e.public_message(), "invalid X-Repository");
            }
            assert_eq!(
                single
                    .resolve(Some("default"), signed)
                    .unwrap()
                    .repo
                    .namespace
                    .as_str(),
                "root"
            );
            for bad in ["Default", ".x", "has space", "a/b"] {
                let e = single.resolve(Some(bad), signed).unwrap_err();
                assert_eq!(e.code(), Code::InvalidArgument);
                assert_eq!(e.public_message(), "invalid X-Repository");
            }
            let identity = format!("ed25519-{}/one", "a".repeat(64));
            for other in ["other", &identity] {
                let e = single.resolve(Some(other), signed).unwrap_err();
                assert_eq!(e.code(), Code::NotFound);
                assert_eq!(e.public_message(), "repository not found");
            }
            let resolved = multi.resolve(Some(&identity), signed).unwrap();
            assert_eq!(resolved.identity, identity);
            assert_eq!(resolved.repo.namespace.as_str(), &identity[..72]);
            assert_eq!(resolved.repo.name.as_str(), "one");
            assert_eq!(
                multi.resolve(Some("default"), signed).unwrap_err().code(),
                Code::InvalidArgument
            );
            let configured = self::single(&identity)
                .resolve(Some(&identity), true)
                .unwrap();
            assert_eq!(configured.repo.namespace.as_str(), "root");
            assert_eq!(configured.repo.name.as_str(), identity);
        }
    }

    #[test]
    fn golden_repository_grammar_drives_both_modes() {
        #[derive(serde::Deserialize)]
        struct Case {
            identity: String,
            single_ok: bool,
            multi_ok: bool,
        }
        let bytes = include_bytes!("../../../tests/golden/transport/repository-grammar.json");
        let cases: Vec<Case> = serde_json::from_slice(bytes).unwrap();
        let manifest = include_str!("../../../tests/golden/transport/MANIFEST.txt");
        let digest = mkit_core::hash::to_hex(&mkit_core::hash::hash(bytes));
        assert!(
            manifest
                .lines()
                .any(|line| line == format!("repository-grammar.json {digest}"))
        );
        let multi = Addressing::Multi(MultiAddressing::new());
        for case in cases {
            // Valid Single cases configure their byte-exact identity; invalid
            // cases use a valid config and must fail grammar, not equality.
            for (addressing, valid) in [
                (
                    single(if case.single_ok {
                        &case.identity
                    } else {
                        "default"
                    }),
                    case.single_ok,
                ),
                (multi.clone(), case.multi_ok),
            ] {
                let result = addressing.resolve(Some(&case.identity), false);
                if valid {
                    assert_eq!(result.unwrap().identity, case.identity);
                } else {
                    assert_eq!(
                        result.unwrap_err().code(),
                        Code::InvalidArgument,
                        "{}",
                        case.identity
                    );
                }
            }
        }
    }

    #[test]
    fn deployment_default_namespace_is_stable() {
        assert_eq!(NamespaceKey::deployment_default().as_str(), "root");
    }
}
