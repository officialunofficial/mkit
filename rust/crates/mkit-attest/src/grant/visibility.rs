//! The `mkit-repo-visibility:v1` statement (SPEC-WRITE-GRANTS §9.1).

use mkit_core::repo_identity::RepositoryIdentity;

use super::text::{
    audiences, check_lifetime, decimal_millis, encode_audiences, encode_hex32, encode_millis,
    hex32, join_fields, split_fields,
};
use super::{DOMAIN_VISIBILITY, EPOCH_STATEMENT_MAX_LIFETIME_MS, GrantError};

/// Field count of a visibility statement.
const VISIBILITY_FIELDS: usize = 7;

/// A repository's visibility (§9.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Visibility {
    /// `public`: readable by every caller.
    Public,
    /// `private`: readable only through §6 with the `read` capability.
    Private,
}

impl Visibility {
    /// The canonical token.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
        }
    }

    /// Parse the canonical token.
    ///
    /// # Errors
    /// `Visibility` for anything but `public` or `private`.
    pub fn parse(s: &str) -> Result<Self, GrantError> {
        match s {
            "public" => Ok(Self::Public),
            "private" => Ok(Self::Private),
            _ => Err(GrantError::Visibility),
        }
    }
}

/// A parsed `mkit-repo-visibility:v1` statement: the owner sets a
/// repository's visibility (§9.1).
///
/// [`VisibilityStatement::parse`] accepts exactly the canonical encoding and
/// [`VisibilityStatement::encode`] reproduces it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VisibilityStatement {
    /// A full identity `<namespace>/<name>` (§7.4); never a bare name.
    pub repository: RepositoryIdentity,
    /// The visibility to store.
    pub visibility: Visibility,
    /// 1 to 8 canonical origins in ascending byte order.
    pub audiences: Vec<String>,
    /// Creation time, epoch milliseconds. The deployment accepts only a
    /// `created` greater than the last accepted one for the repository.
    pub created_ms: i64,
    /// Expiry, epoch milliseconds: `created < expiry <= created +
    /// EPOCH_STATEMENT_MAX_LIFETIME_MS`.
    pub expiry_ms: i64,
    /// 32 bytes of fresh randomness.
    pub nonce: [u8; 32],
}

impl VisibilityStatement {
    /// Parse a statement, enforcing the §3.1 rules and the §9.1 fields. Never
    /// repairs.
    ///
    /// # Errors
    /// The [`GrantError`] of the first failed rule; `Repository` for a bare
    /// name or an identity outside §7.4.
    pub fn parse(bytes: &[u8]) -> Result<Self, GrantError> {
        let f = split_fields(bytes, VISIBILITY_FIELDS)?;
        if f[0] != DOMAIN_VISIBILITY {
            return Err(GrantError::Domain);
        }
        // `parse` requires `<namespace>/<name>`: a bare name fails here.
        let repository = RepositoryIdentity::parse(f[1]).map_err(|_| GrantError::Repository)?;
        let visibility = Visibility::parse(f[2])?;
        let audiences = audiences(f[3])?;
        let created_ms = decimal_millis(f[4])?;
        let expiry_ms = decimal_millis(f[5])?;
        let nonce = hex32(f[6])?;
        check_lifetime(created_ms, expiry_ms, EPOCH_STATEMENT_MAX_LIFETIME_MS)?;
        Ok(Self {
            repository,
            visibility,
            audiences,
            created_ms,
            expiry_ms,
            nonce,
        })
    }

    /// Encode the canonical statement. Validates every rule
    /// [`VisibilityStatement::parse`] enforces and never sorts or repairs.
    ///
    /// # Errors
    /// The [`GrantError`] of the first failed rule.
    pub fn encode(&self) -> Result<Vec<u8>, GrantError> {
        if self.repository.namespace().is_none() {
            return Err(GrantError::Repository);
        }
        let audiences = encode_audiences(&self.audiences)?;
        check_lifetime(
            self.created_ms,
            self.expiry_ms,
            EPOCH_STATEMENT_MAX_LIFETIME_MS,
        )?;
        join_fields(&[
            DOMAIN_VISIBILITY,
            &self.repository.to_string(),
            self.visibility.token(),
            &audiences,
            &encode_millis(self.created_ms)?,
            &encode_millis(self.expiry_ms)?,
            &encode_hex32(&self.nonce),
        ])
    }

    /// The statement id: the BLAKE3 of the canonical statement.
    ///
    /// # Errors
    /// As [`VisibilityStatement::encode`].
    pub fn id(&self) -> Result<[u8; 32], GrantError> {
        Ok(mkit_core::hash::hash(&self.encode()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPO: &str = "0x8ba1f109551bd432803012645ac136ddd64dba72/website";
    const NONCE: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    fn fields() -> Vec<String> {
        [
            DOMAIN_VISIBILITY,
            REPO,
            "private",
            "https://git.example.com",
            "1790000000000",
            "1790086400000",
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
            VisibilityStatement::parse(bytes),
            Err(err),
            "{}",
            String::from_utf8_lossy(bytes)
        );
    }

    #[test]
    fn visibility_statement_roundtrips() {
        for token in ["public", "private"] {
            let bytes = with(2, token);
            let s = VisibilityStatement::parse(&bytes).unwrap();
            assert_eq!(s.visibility.token(), token);
            assert_eq!(s.repository.to_string(), REPO);
            assert_eq!(s.encode().unwrap(), bytes);
            assert_eq!(s.id().unwrap(), mkit_core::hash::hash(&bytes));
        }
    }

    #[test]
    fn visibility_statement_rejects_each_rule() {
        let f = fields();
        rejects(f[..6].join("\n").as_bytes(), GrantError::FieldCount);
        rejects(
            format!("{}\n", f.join("\n")).as_bytes(),
            GrantError::FinalLineFeed,
        );
        rejects(f.join("\r\n").as_bytes(), GrantError::CarriageReturn);
        rejects(&with(0, "mkit-write-epoch:v1"), GrantError::Domain);
        rejects(&with(0, "mkit-repo-visibility:v2"), GrantError::Domain);
        rejects(&with(1, "website"), GrantError::Repository);
        rejects(
            &with(1, &REPO.replace("website", "Website")),
            GrantError::Repository,
        );
        rejects(
            &with(1, &REPO.replace("website", "*")),
            GrantError::Repository,
        );
        rejects(&with(1, &REPO.replace("0x", "0X")), GrantError::Repository);
        for bad in ["Public", "internal", "public,private", "private "] {
            let err = if bad.ends_with(' ') {
                GrantError::ByteOutOfRange
            } else {
                GrantError::Visibility
            };
            rejects(&with(2, bad), err);
        }
        rejects(&with(3, "*"), GrantError::AudienceWildcard);
        rejects(
            &with(3, "https://git.example.com:443"),
            GrantError::Audience,
        );
        rejects(&with(4, "01"), GrantError::Decimal);
        rejects(&with(6, &NONCE.to_uppercase()), GrantError::Hex);
        rejects(&with(5, "1789999999999"), GrantError::ExpiryNotAfterCreated);
        let over = (1_790_000_000_000_i64 + EPOCH_STATEMENT_MAX_LIFETIME_MS + 1).to_string();
        rejects(&with(5, &over), GrantError::LifetimeTooLong);
    }

    #[test]
    fn visibility_statement_encode_validates() {
        let good = VisibilityStatement::parse(&fields().join("\n").into_bytes()).unwrap();
        let mut s = good.clone();
        s.repository = RepositoryIdentity::parse_bare_allowed("website").unwrap();
        assert_eq!(s.encode(), Err(GrantError::Repository));
        let mut s = good;
        s.audiences.reverse();
        s.audiences.push("https://a.example".into());
        assert_eq!(s.encode(), Err(GrantError::AudiencesUnordered));
    }
}
