//! The `mkit-write-epoch:v1` statement (SPEC-WRITE-GRANTS §5.1) and the
//! pure §5.2 check 7 ([`epoch_transition`]).

use mkit_core::repo_identity::Namespace;

use super::text::{
    audiences, check_lifetime, decimal_millis, decimal_u64, encode_audiences, encode_hex32,
    encode_millis, hex32, join_fields, split_fields,
};
use super::{DOMAIN_EPOCH, EPOCH_STATEMENT_MAX_LIFETIME_MS, GrantError, MAX_EPOCH_STEP};

/// Field count of an epoch statement.
const EPOCH_FIELDS: usize = 7;

/// A parsed `mkit-write-epoch:v1` statement: the owner raises the namespace's
/// epoch to `new_epoch`, revoking every grant at a lower epoch (§5).
///
/// [`EpochStatement::parse`] accepts exactly the canonical encoding (the
/// §3.5 rules with seven fields) and [`EpochStatement::encode`] reproduces
/// it, so `encode(parse(b)) == b` for every accepted `b`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochStatement {
    /// The owner's self-certifying namespace.
    pub namespace: Namespace,
    /// The epoch to store.
    pub new_epoch: u64,
    /// 1 to 8 canonical origins in ascending byte order.
    pub audiences: Vec<String>,
    /// Creation time, epoch milliseconds.
    pub created_ms: i64,
    /// Expiry, epoch milliseconds: `created < expiry <= created +
    /// EPOCH_STATEMENT_MAX_LIFETIME_MS`.
    pub expiry_ms: i64,
    /// 32 bytes of fresh randomness.
    pub nonce: [u8; 32],
}

impl EpochStatement {
    /// Parse a statement, enforcing every §3.5 rule that applies to its seven
    /// fields. Never repairs.
    ///
    /// # Errors
    /// The [`GrantError`] of the first failed rule.
    pub fn parse(bytes: &[u8]) -> Result<Self, GrantError> {
        let f = split_fields(bytes, EPOCH_FIELDS)?;
        if f[0] != DOMAIN_EPOCH {
            return Err(GrantError::Domain);
        }
        let namespace = Namespace::parse(f[1]).map_err(|_| GrantError::Namespace)?;
        let new_epoch = decimal_u64(f[2])?;
        let audiences = audiences(f[3])?;
        let created_ms = decimal_millis(f[4])?;
        let expiry_ms = decimal_millis(f[5])?;
        let nonce = hex32(f[6])?;
        check_lifetime(created_ms, expiry_ms, EPOCH_STATEMENT_MAX_LIFETIME_MS)?;
        Ok(Self {
            namespace,
            new_epoch,
            audiences,
            created_ms,
            expiry_ms,
            nonce,
        })
    }

    /// Encode the canonical statement. Validates every rule
    /// [`EpochStatement::parse`] enforces and never sorts or repairs.
    ///
    /// # Errors
    /// The [`GrantError`] of the first failed rule.
    pub fn encode(&self) -> Result<Vec<u8>, GrantError> {
        let audiences = encode_audiences(&self.audiences)?;
        check_lifetime(
            self.created_ms,
            self.expiry_ms,
            EPOCH_STATEMENT_MAX_LIFETIME_MS,
        )?;
        join_fields(&[
            DOMAIN_EPOCH,
            &self.namespace.to_string(),
            &self.new_epoch.to_string(),
            &audiences,
            &encode_millis(self.created_ms)?,
            &encode_millis(self.expiry_ms)?,
            &encode_hex32(&self.nonce),
        ])
    }

    /// The statement id: the BLAKE3 of the canonical statement.
    ///
    /// # Errors
    /// As [`EpochStatement::encode`].
    pub fn id(&self) -> Result<[u8; 32], GrantError> {
        Ok(mkit_core::hash::hash(&self.encode()?))
    }
}

/// The outcome of §5.2 check 7 and the retry rule for a verified epoch
/// statement against the stored epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpochTransition {
    /// `stored < new <= stored + MAX_EPOCH_STEP`: store `new`.
    Advance,
    /// `new == stored`: an idempotent retry; change nothing and answer as for
    /// the statement that set the epoch.
    Retry,
    /// Anything else (a decrease, or a step above `MAX_EPOCH_STEP`):
    /// `permission_denied`.
    Reject,
}

/// §5.2 check 7 plus the retry rule, for a statement that passed checks 1–6.
///
/// Computed without overflow: a namespace whose stored epoch is within
/// `MAX_EPOCH_STEP` of `u64::MAX` can still be raised to `u64::MAX`, and no
/// further.
#[must_use]
pub fn epoch_transition(stored: u64, new: u64) -> EpochTransition {
    if new == stored {
        EpochTransition::Retry
    } else if new > stored && new - stored <= MAX_EPOCH_STEP {
        EpochTransition::Advance
    } else {
        EpochTransition::Reject
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NS: &str = "ed25519-3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";
    const NONCE: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    fn fields() -> Vec<String> {
        [
            DOMAIN_EPOCH,
            NS,
            "5",
            "https://git.example.com,https://git.example.org",
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
            EpochStatement::parse(bytes),
            Err(err),
            "{}",
            String::from_utf8_lossy(bytes)
        );
    }

    #[test]
    fn epoch_statement_roundtrips() {
        let bytes = fields().join("\n").into_bytes();
        let s = EpochStatement::parse(&bytes).unwrap();
        assert_eq!(s.new_epoch, 5);
        assert_eq!(s.encode().unwrap(), bytes);
        assert_eq!(s.id().unwrap(), mkit_core::hash::hash(&bytes));
        let max = EpochStatement::parse(&with(2, "18446744073709551615")).unwrap();
        assert_eq!(max.new_epoch, u64::MAX);
    }

    #[test]
    fn epoch_statement_rejects_each_rule() {
        let f = fields();
        rejects(f[..6].join("\n").as_bytes(), GrantError::FieldCount);
        rejects(
            format!("{}\nx", f.join("\n")).as_bytes(),
            GrantError::FieldCount,
        );
        rejects(
            format!("{}\n", f.join("\n")).as_bytes(),
            GrantError::FinalLineFeed,
        );
        rejects(f.join("\r\n").as_bytes(), GrantError::CarriageReturn);
        rejects(&with(2, "5 "), GrantError::ByteOutOfRange);
        let mut empty = fields();
        empty[2] = String::new();
        rejects(empty.join("\n").as_bytes(), GrantError::EmptyField);
        rejects(&with(0, "mkit-write-grant:v1"), GrantError::Domain);
        rejects(&with(0, "mkit-write-epoch:v2"), GrantError::Domain);
        rejects(&with(1, &NS.to_uppercase()), GrantError::Namespace);
        rejects(&with(1, &format!("{NS}/repo")), GrantError::Namespace);
        rejects(&with(2, "+5"), GrantError::Decimal);
        rejects(&with(2, "05"), GrantError::Decimal);
        rejects(
            &with(2, "18446744073709551616"),
            GrantError::DecimalOutOfRange,
        );
        rejects(&with(3, "*"), GrantError::AudienceWildcard);
        rejects(&with(3, "https://git.example.com/"), GrantError::Audience);
        rejects(
            &with(3, "https://git.example.org,https://git.example.com"),
            GrantError::AudiencesUnordered,
        );
        let nine: Vec<String> = (1..=9).map(|i| format!("https://a{i}.example")).collect();
        rejects(&with(3, &nine.join(",")), GrantError::AudienceCount);
        rejects(
            &with(4, "9223372036854775808"),
            GrantError::DecimalOutOfRange,
        );
        rejects(&with(6, &NONCE.to_uppercase()), GrantError::Hex);
        rejects(&with(6, &NONCE[..62]), GrantError::Hex);
        rejects(&with(5, "1790000000000"), GrantError::ExpiryNotAfterCreated);
        let over = (1_790_000_000_000_i64 + EPOCH_STATEMENT_MAX_LIFETIME_MS + 1).to_string();
        rejects(&with(5, &over), GrantError::LifetimeTooLong);
        let max = (1_790_000_000_000_i64 + EPOCH_STATEMENT_MAX_LIFETIME_MS).to_string();
        assert!(EpochStatement::parse(&with(5, &max)).is_ok());
        let long = with(6, &format!("{NONCE}{}", "a".repeat(4096)));
        rejects(&long, GrantError::StatementTooLong);
    }

    #[test]
    fn epoch_statement_encode_validates() {
        let good = EpochStatement::parse(&fields().join("\n").into_bytes()).unwrap();
        let mut s = good.clone();
        s.audiences.clear();
        assert_eq!(s.encode(), Err(GrantError::AudienceCount));
        let mut s = good.clone();
        s.expiry_ms = s.created_ms;
        assert_eq!(s.encode(), Err(GrantError::ExpiryNotAfterCreated));
        let mut s = good;
        s.created_ms = -1;
        assert_eq!(s.encode(), Err(GrantError::DecimalOutOfRange));
    }

    #[test]
    fn epoch_transition_bounds() {
        use EpochTransition::{Advance, Reject, Retry};
        assert_eq!(epoch_transition(0, 1), Advance);
        assert_eq!(epoch_transition(0, 1024), Advance);
        assert_eq!(epoch_transition(0, 1025), Reject);
        assert_eq!(epoch_transition(5, 5), Retry);
        assert_eq!(epoch_transition(5, 4), Reject);
        assert_eq!(epoch_transition(5, 0), Reject);
        assert_eq!(epoch_transition(u64::MAX - 10, u64::MAX), Advance);
        assert_eq!(epoch_transition(u64::MAX - 1024, u64::MAX), Advance);
        assert_eq!(epoch_transition(u64::MAX - 1025, u64::MAX), Reject);
        assert_eq!(epoch_transition(u64::MAX, u64::MAX), Retry);
        assert_eq!(epoch_transition(u64::MAX, 0), Reject);
        assert_eq!(epoch_transition(0, u64::MAX), Reject);
    }
}
