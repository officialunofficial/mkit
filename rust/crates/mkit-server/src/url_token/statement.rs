//! The `mkit-url-token:v1` statement: the target grammar, the §3.1 field
//! codec and the `<statement>.<signature>` token encoding
//! (SPEC-WRITE-GRANTS §9.4).

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mkit_attest::grant::GrantError;
use mkit_attest::grant::text::{
    check_lifetime, decimal_millis, decimal_u64, encode_millis, join_fields, split_fields,
};
use mkit_core::hash::{Hash, from_hex, hash, to_hex, to_hex_bytes};
use mkit_core::repo_identity::RepositoryIdentity;
use mkit_core::write_auth::{is_hex, validate_audience};

use super::{DOMAIN, MAX_PATH_BYTES, MAX_TTL_MS, UrlTokenError};

/// The eight statement fields of §9.4.
const STATEMENT_FIELDS: usize = 8;

/// The longest token string: a statement of
/// `mkit_attest::grant::MAX_STATEMENT_BYTES` and a 64-byte signature
/// encode well under it, so a longer input can never be a valid token.
#[allow(dead_code)] // WP-2.11 Commit 5's `precheck` uses it.
pub(crate) const MAX_TOKEN_LEN: usize = 8192;

/// What `IssueObjectUrl` binds a token to (§9.4 `target`).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum UrlTarget {
    /// `object:<64 lowercase hex object id>`.
    Object(Hash),
    /// `path:<full ref name>:<unpadded base64url of the UTF-8 path>`; the
    /// decoded path names a tree entry, empty the root tree.
    Path {
        /// The full ref name (SPEC-REFS §3).
        reference: String,
        /// The UTF-8 path, `0..MAX_PATH_BYTES` bytes.
        path: String,
    },
}

/// An invalid `target` field: bad ref, path or encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid URL token target")]
pub struct TargetError;

impl UrlTarget {
    /// A path target after checking the ref name and the §9.4 path rules.
    ///
    /// # Errors
    /// [`TargetError`] for an invalid ref name, a path over
    /// [`MAX_PATH_BYTES`] bytes, or a nonempty path with a leading,
    /// trailing or repeated `/` or a `.`/`..` entry.
    pub fn path(
        reference: impl Into<String>,
        path: impl Into<String>,
    ) -> Result<Self, TargetError> {
        let (reference, path) = (reference.into(), path.into());
        if !crate::refs::validate_ref_name(&reference) || !valid_path(&path) {
            return Err(TargetError);
        }
        Ok(Self::Path { reference, path })
    }

    /// The canonical `target` field text.
    #[must_use]
    pub fn field(&self) -> String {
        match self {
            Self::Object(id) => format!("object:{}", to_hex(id)),
            Self::Path { reference, path } => {
                format!(
                    "path:{reference}:{}",
                    URL_SAFE_NO_PAD.encode(path.as_bytes())
                )
            }
        }
    }

    /// Parse a `target` field. Ref names contain no `:`, so the field
    /// splits at its first two.
    ///
    /// # Errors
    /// [`TargetError`] for anything [`field`] does not produce.
    pub fn parse_field(field: &str) -> Result<Self, TargetError> {
        if let Some(id) = field.strip_prefix("object:") {
            if !is_hex(id, 32) {
                return Err(TargetError);
            }
            return from_hex(id).map(Self::Object).map_err(|_| TargetError);
        }
        let rest = field.strip_prefix("path:").ok_or(TargetError)?;
        let (reference, encoded) = rest.split_once(':').ok_or(TargetError)?;
        let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| TargetError)?;
        let path = String::from_utf8(bytes).map_err(|_| TargetError)?;
        Self::path(reference, path)
    }
}

/// The §9.4 path grammar: at most [`MAX_PATH_BYTES`] bytes; empty names the
/// root tree; a nonempty path is `/`-joined entry names with no empty,
/// `.` or `..` entry.
fn valid_path(path: &str) -> bool {
    path.len() <= MAX_PATH_BYTES
        && (path.is_empty()
            || path
                .split('/')
                .all(|entry| !entry.is_empty() && entry != "." && entry != ".."))
}

/// A verified `mkit-url-token:v1` statement (§9.4).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct UrlTokenStatement {
    audience: String,
    repository: String,
    target: UrlTarget,
    epoch: u64,
    issued_ms: i64,
    expiry_ms: i64,
    key_id: [u8; 16],
}

impl UrlTokenStatement {
    /// Build from already-validated parts.
    pub(crate) fn new(
        audience: impl Into<String>,
        repository: impl Into<String>,
        target: UrlTarget,
        epoch: u64,
        issued_ms: i64,
        expiry_ms: i64,
        key_id: [u8; 16],
    ) -> Self {
        Self {
            audience: audience.into(),
            repository: repository.into(),
            target,
            epoch,
            issued_ms,
            expiry_ms,
            key_id,
        }
    }

    /// The issuing deployment's auth v2 audience.
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// The full repository identity.
    #[must_use]
    pub fn repository(&self) -> &str {
        &self.repository
    }

    /// The bound target.
    #[must_use]
    pub fn target(&self) -> &UrlTarget {
        &self.target
    }

    /// The namespace's stored epoch at issue time.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Issue time, Unix epoch milliseconds.
    #[must_use]
    pub fn issued_ms(&self) -> i64 {
        self.issued_ms
    }

    /// Expiry, Unix epoch milliseconds.
    #[must_use]
    pub fn expiry_ms(&self) -> i64 {
        self.expiry_ms
    }

    /// The signing key's id: `blake3(public key)[..16]`.
    #[must_use]
    pub fn key_id(&self) -> [u8; 16] {
        self.key_id
    }

    /// Encode the canonical statement. Validates every rule
    /// [`UrlTokenStatement::parse`] enforces.
    ///
    /// # Errors
    /// The [`UrlTokenError`] of the first failed rule.
    pub fn encode(&self) -> Result<Vec<u8>, UrlTokenError> {
        validate_audience(&self.audience).map_err(|_| GrantError::Audience)?;
        RepositoryIdentity::parse(&self.repository).map_err(|_| GrantError::Repository)?;
        check_lifetime(self.issued_ms, self.expiry_ms, max_ttl_i64())?;
        join_fields(&[
            DOMAIN,
            &self.audience,
            &self.repository,
            &self.target.field(),
            &self.epoch.to_string(),
            &encode_millis(self.issued_ms)?,
            &encode_millis(self.expiry_ms)?,
            &to_hex_bytes(&self.key_id),
        ])
        .map_err(Into::into)
    }

    /// Parse a canonical statement: the §3.1 text rules, then each §9.4
    /// field rule.
    ///
    /// # Errors
    /// The [`UrlTokenError`] of the first failed rule.
    pub fn parse(bytes: &[u8]) -> Result<Self, UrlTokenError> {
        let f = split_fields(bytes, STATEMENT_FIELDS)?;
        if f[0] != DOMAIN {
            return Err(GrantError::Domain.into());
        }
        validate_audience(f[1]).map_err(|_| GrantError::Audience)?;
        RepositoryIdentity::parse(f[2]).map_err(|_| GrantError::Repository)?;
        let target = UrlTarget::parse_field(f[3]).map_err(|_| UrlTokenError::Target)?;
        let epoch = decimal_u64(f[4])?;
        let issued_ms = decimal_millis(f[5])?;
        let expiry_ms = decimal_millis(f[6])?;
        check_lifetime(issued_ms, expiry_ms, max_ttl_i64())?;
        let key_id = key_id_hex(f[7])?;
        Ok(Self {
            audience: f[1].to_owned(),
            repository: f[2].to_owned(),
            target,
            epoch,
            issued_ms,
            expiry_ms,
            key_id,
        })
    }
}

/// The key-id field: 32 lowercase hex digits for the 16-byte id.
fn key_id_hex(field: &str) -> Result<[u8; 16], UrlTokenError> {
    if !is_hex(field, 16) {
        return Err(GrantError::Hex.into());
    }
    // `is_hex` accepted, so every pair is a hex byte.
    let mut id = [0; 16];
    for (i, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&field[2 * i..2 * i + 2], 16).map_err(|_| GrantError::Hex)?;
    }
    Ok(id)
}

/// `MAX_TTL_MS` in `check_lifetime`'s `i64` units.
fn max_ttl_i64() -> i64 {
    i64::try_from(MAX_TTL_MS).unwrap_or(i64::MAX)
}

/// The token's key id: `hex(blake3(public key)[..16])`.
pub(crate) fn key_id(public: &[u8; 32]) -> [u8; 16] {
    let mut id = [0; 16];
    id.copy_from_slice(&hash(public)[..16]);
    id
}

/// Split a token into its statement and signature bytes (§9.4):
/// `<b64url statement>.<b64url 64-byte signature>`, both unpadded and
/// strictly encoded.
#[allow(dead_code)] // WP-2.11 Commit 5's `precheck` uses it.
pub(crate) fn decode_token(token: &str) -> Result<(Vec<u8>, [u8; 64]), UrlTokenError> {
    if token.len() > MAX_TOKEN_LEN {
        return Err(UrlTokenError::Length);
    }
    let (statement, signature) = token.split_once('.').ok_or(UrlTokenError::Format)?;
    if statement.is_empty() || signature.is_empty() || signature.contains('.') {
        return Err(UrlTokenError::Format);
    }
    let statement = URL_SAFE_NO_PAD
        .decode(statement)
        .map_err(|_| UrlTokenError::Encoding)?;
    let signature: [u8; 64] = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| UrlTokenError::Encoding)?
        .try_into()
        .map_err(|_| UrlTokenError::SignatureLength)?;
    Ok((statement, signature))
}

/// Assemble `<b64url statement>.<b64url signature>`.
pub(crate) fn encode_token(statement: &[u8], signature: &[u8; 64]) -> String {
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(statement),
        URL_SAFE_NO_PAD.encode(signature)
    )
}
