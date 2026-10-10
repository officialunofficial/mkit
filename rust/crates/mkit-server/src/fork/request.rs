//! The fork request and its canonical body.
//!
//! A fork has no Connect binding in this revision: the embedder authenticates
//! the call with [`crate::pipeline::Pipeline::authenticate`] for
//! [`crate::Procedure::Fork`], passing [`ForkRequest::canonical_body`] as the
//! unary body, so the auth v2 `body:` commitment binds the source, the branch,
//! the tip and the destination visibility to the signature.

use super::ForkSpec;
use crate::error::ServerError;
use crate::repo::{NamespaceKey, RepoId, RepoName};
use mkit_attest::grant::Visibility;
use mkit_core::hash::{Hash, from_hex, to_hex};

/// First line of every canonical body.
const MAGIC: &str = "mkit-fork:v1";

/// A request to fork the published tip of one branch of `source` into the
/// operation's repository, which must not exist yet (the fork registers it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkRequest {
    /// The repository to fork.
    pub source: RepoId,
    /// The branch, `refs/heads/<name>`.
    pub source_ref: String,
    /// The tip the caller expects the source to have published: a required
    /// compare-and-swap. A different published tip answers
    /// `failed_precondition "source tip changed"`.
    pub expected_tip: Hash,
    /// The destination's visibility.
    pub dest_visibility: Visibility,
}

impl ForkRequest {
    /// The bytes the request signs: five `\n`-separated lines, no trailing
    /// newline.
    ///
    /// ```text
    /// mkit-fork:v1
    /// <source namespace>/<source repository>
    /// <source ref>
    /// <expected tip, 64 lowercase hex>
    /// public | private
    /// ```
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let visibility = match self.dest_visibility {
            Visibility::Public => "public",
            Visibility::Private => "private",
        };
        format!(
            "{MAGIC}\n{}/{}\n{}\n{}\n{visibility}",
            self.source.namespace.as_str(),
            self.source.name.as_str(),
            self.source_ref,
            to_hex(&self.expected_tip),
        )
        .into_bytes()
    }

    /// Decode a canonical body; the inverse of [`Self::canonical_body`].
    ///
    /// # Errors
    /// `invalid_argument` for anything else, including a body that decodes
    /// but is not the canonical form of what it names.
    pub fn parse(body: &[u8]) -> Result<Self, ServerError> {
        let bad = || ServerError::invalid_argument("invalid fork request");
        let text = core::str::from_utf8(body).map_err(|_| bad())?;
        let mut lines = text.split('\n');
        let (Some(MAGIC), Some(source), Some(source_ref), Some(tip), Some(visibility), None) = (
            lines.next(),
            lines.next(),
            lines.next(),
            lines.next(),
            lines.next(),
            lines.next(),
        ) else {
            return Err(bad());
        };
        let (namespace, name) = source.split_once('/').ok_or_else(bad)?;
        let request = Self {
            source: RepoId {
                namespace: NamespaceKey::from_stored(namespace.to_owned()),
                name: RepoName::new(name.to_owned()).map_err(|_| bad())?,
            },
            source_ref: source_ref.to_owned(),
            expected_tip: from_hex(tip).map_err(|_| bad())?,
            dest_visibility: match visibility {
                "public" => Visibility::Public,
                "private" => Visibility::Private,
                _ => return Err(bad()),
            },
        };
        if request.canonical_body() == body {
            Ok(request)
        } else {
            Err(bad())
        }
    }

    /// The engine's spec for forking into `dest`.
    #[must_use]
    pub fn spec_for(&self, dest: RepoId) -> ForkSpec {
        ForkSpec {
            source: self.source.clone(),
            source_ref: self.source_ref.clone(),
            expected_tip: self.expected_tip,
            dest,
            dest_visibility: self.dest_visibility,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ForkRequest {
        ForkRequest {
            source: RepoId {
                namespace: NamespaceKey::from_stored(
                    "0x0000000000000000000000000000000000000001".into(),
                ),
                name: RepoName::new("origin".to_owned()).unwrap(),
            },
            source_ref: "refs/heads/main".into(),
            expected_tip: [0xab; 32],
            dest_visibility: Visibility::Private,
        }
    }

    #[test]
    fn the_canonical_body_round_trips_and_is_the_only_spelling() {
        let request = request();
        let body = request.canonical_body();
        assert_eq!(ForkRequest::parse(&body).unwrap(), request);
        assert_eq!(
            String::from_utf8(body.clone()).unwrap(),
            "mkit-fork:v1\n0x0000000000000000000000000000000000000001/origin\nrefs/heads/main\n\
             abababababababababababababababababababababababababababababababab\nprivate"
        );
        // Upper-case hex, a trailing newline, a missing line and an unknown
        // visibility are not the canonical form.
        let text = String::from_utf8(body).unwrap();
        for wrong in [
            text.replace(&"ab".repeat(32), &"AB".repeat(32)),
            format!("{text}\n"),
            text.replace("\nprivate", ""),
            text.replace("private", "internal"),
            text.replace("mkit-fork:v1", "mkit-fork:v2"),
        ] {
            assert!(ForkRequest::parse(wrong.as_bytes()).is_err(), "{wrong}");
        }
    }
}
