//! SPEC-WRITE-GRANTS §3.1 canonical text rules, shared by every statement the
//! spec defines (grant, epoch, visibility, URL token).
//!
//! Each parser here accepts exactly one encoding of a value and never
//! repairs; each encoder produces that encoding or fails.

use mkit_core::hash::{from_hex, to_hex};
use mkit_core::write_auth::{is_hex, validate_audience};

use super::{GrantError, MAX_AUDIENCES, MAX_STATEMENT_BYTES};

/// Split a statement into exactly `n` fields, enforcing the §3.1 byte rules.
///
/// Checks run in this order, so a given input always yields the same error:
/// length (`StatementTooLong`), then the first bad byte (`CarriageReturn` or
/// `ByteOutOfRange`), then `FinalLineFeed`, `FieldCount` and `EmptyField`.
///
/// # Errors
/// As listed above.
pub fn split_fields(bytes: &[u8], n: usize) -> Result<Vec<&str>, GrantError> {
    if bytes.len() > MAX_STATEMENT_BYTES {
        return Err(GrantError::StatementTooLong);
    }
    for &b in bytes {
        if b == b'\r' {
            return Err(GrantError::CarriageReturn);
        }
        if b != b'\n' && !(0x21..=0x7e).contains(&b) {
            return Err(GrantError::ByteOutOfRange);
        }
    }
    if bytes.last() == Some(&b'\n') {
        return Err(GrantError::FinalLineFeed);
    }
    // Every byte is ASCII by now, so this cannot fail.
    let text = core::str::from_utf8(bytes).map_err(|_| GrantError::ByteOutOfRange)?;
    let fields: Vec<&str> = text.split('\n').collect();
    if fields.len() != n {
        return Err(GrantError::FieldCount);
    }
    if fields.iter().any(|f| f.is_empty()) {
        return Err(GrantError::EmptyField);
    }
    Ok(fields)
}

/// Join fields with `\n` into a statement, checking the result with
/// [`split_fields`] so an encoder can never emit bytes its parser rejects.
///
/// # Errors
/// As [`split_fields`] (for example `StatementTooLong`).
pub fn join_fields(fields: &[&str]) -> Result<Vec<u8>, GrantError> {
    let out = fields.join("\n").into_bytes();
    split_fields(&out, fields.len())?;
    Ok(out)
}

fn canonical_digits(s: &str) -> Result<(), GrantError> {
    let bytes = s.as_bytes();
    if bytes.is_empty()
        || !bytes.iter().all(u8::is_ascii_digit)
        || (bytes.len() > 1 && bytes[0] == b'0')
    {
        return Err(GrantError::Decimal);
    }
    Ok(())
}

/// A canonical decimal epoch, at most `u64::MAX`.
///
/// # Errors
/// `Decimal` (sign, leading zero, non-digit) or `DecimalOutOfRange`.
pub fn decimal_u64(s: &str) -> Result<u64, GrantError> {
    canonical_digits(s)?;
    s.parse().map_err(|_| GrantError::DecimalOutOfRange)
}

/// A canonical decimal millisecond timestamp, at most `i64::MAX`.
///
/// # Errors
/// `Decimal` (sign, leading zero, non-digit) or `DecimalOutOfRange`.
pub fn decimal_millis(s: &str) -> Result<i64, GrantError> {
    canonical_digits(s)?;
    s.parse().map_err(|_| GrantError::DecimalOutOfRange)
}

/// Encode a millisecond timestamp. The text form has no sign.
///
/// # Errors
/// `DecimalOutOfRange` for a negative value.
pub fn encode_millis(ms: i64) -> Result<String, GrantError> {
    if ms < 0 {
        return Err(GrantError::DecimalOutOfRange);
    }
    Ok(ms.to_string())
}

/// 64 lowercase hex digits.
///
/// # Errors
/// `Hex` for uppercase, a non-hex digit or a wrong length.
pub fn hex32(s: &str) -> Result<[u8; 32], GrantError> {
    if !is_hex(s, 32) {
        return Err(GrantError::Hex);
    }
    from_hex(s).map_err(|_| GrantError::Hex)
}

/// Encode 32 bytes as 64 lowercase hex digits.
#[must_use]
pub fn encode_hex32(bytes: &[u8; 32]) -> String {
    to_hex(bytes)
}

/// Whether `items` is in strictly ascending byte order (so without
/// duplicates).
#[must_use]
pub fn strictly_ascending<S: AsRef<str>>(items: &[S]) -> bool {
    items
        .windows(2)
        .all(|w| w[0].as_ref().as_bytes() < w[1].as_ref().as_bytes())
}

/// Check an audience list (§3.2): no `*` anywhere, 1 to `MAX_AUDIENCES`
/// items, each a canonical auth v2 origin, strictly ascending. Checks run in
/// that order.
fn check_audiences<S: AsRef<str>>(items: &[S]) -> Result<(), GrantError> {
    if items.iter().any(|a| a.as_ref().contains('*')) {
        return Err(GrantError::AudienceWildcard);
    }
    if items.is_empty() || items.len() > MAX_AUDIENCES {
        return Err(GrantError::AudienceCount);
    }
    for audience in items {
        validate_audience(audience.as_ref()).map_err(|_| GrantError::Audience)?;
    }
    if !strictly_ascending(items) {
        return Err(GrantError::AudiencesUnordered);
    }
    Ok(())
}

/// Parse an audience field: 1 to 8 origins joined by `,`.
///
/// No origin contains `,` (the auth v2 origin rules exclude it), so the
/// split is unambiguous.
///
/// # Errors
/// `AudienceWildcard`, `AudienceCount`, `Audience` or `AudiencesUnordered`.
pub fn audiences(field: &str) -> Result<Vec<String>, GrantError> {
    let items: Vec<&str> = field.split(',').collect();
    check_audiences(&items)?;
    Ok(items.into_iter().map(str::to_owned).collect())
}

/// Encode an audience list, rejecting any list [`audiences`] would reject.
/// It never sorts or deduplicates.
///
/// # Errors
/// As [`audiences`].
pub fn encode_audiences(items: &[String]) -> Result<String, GrantError> {
    check_audiences(items)?;
    Ok(items.join(","))
}

/// Check `created < expiry` and `expiry - created <= max_lifetime_ms`, with
/// both timestamps in the text range.
///
/// # Errors
/// `DecimalOutOfRange`, `ExpiryNotAfterCreated` or `LifetimeTooLong`.
pub fn check_lifetime(
    created_ms: i64,
    expiry_ms: i64,
    max_lifetime_ms: i64,
) -> Result<(), GrantError> {
    if created_ms < 0 || expiry_ms < 0 {
        return Err(GrantError::DecimalOutOfRange);
    }
    if expiry_ms <= created_ms {
        return Err(GrantError::ExpiryNotAfterCreated);
    }
    // Both are non-negative and expiry > created, so this cannot overflow.
    if expiry_ms - created_ms > max_lifetime_ms {
        return Err(GrantError::LifetimeTooLong);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_fields_enforces_the_byte_rules() {
        assert_eq!(split_fields(b"a\nb\nc", 3).unwrap(), ["a", "b", "c"]);
        assert_eq!(split_fields(b"a\nb", 3), Err(GrantError::FieldCount));
        assert_eq!(split_fields(b"a\nb\nc\nd", 3), Err(GrantError::FieldCount));
        assert_eq!(split_fields(b"", 1), Err(GrantError::EmptyField));
        assert_eq!(split_fields(b"a\n\nc", 3), Err(GrantError::EmptyField));
        assert_eq!(split_fields(b"a\nb\n", 2), Err(GrantError::FinalLineFeed));
        assert_eq!(split_fields(b"a\r\nb", 2), Err(GrantError::CarriageReturn));
        assert_eq!(split_fields(b"a b\nc", 2), Err(GrantError::ByteOutOfRange));
        assert_eq!(
            split_fields(b"a\x7f\nc", 2),
            Err(GrantError::ByteOutOfRange)
        );
        assert_eq!(split_fields(b"a\tb", 1), Err(GrantError::ByteOutOfRange));
        assert_eq!(
            split_fields("é".as_bytes(), 1),
            Err(GrantError::ByteOutOfRange)
        );
        let max = vec![b'x'; MAX_STATEMENT_BYTES];
        assert!(split_fields(&max, 1).is_ok());
        let over = vec![b'x'; MAX_STATEMENT_BYTES + 1];
        assert_eq!(split_fields(&over, 1), Err(GrantError::StatementTooLong));
    }

    #[test]
    fn join_fields_rejects_what_split_rejects() {
        assert_eq!(join_fields(&["a", "b"]).unwrap(), b"a\nb");
        assert_eq!(join_fields(&["", "a"]), Err(GrantError::EmptyField));
        assert_eq!(join_fields(&["a", ""]), Err(GrantError::FinalLineFeed));
        assert_eq!(join_fields(&["a\nb"]), Err(GrantError::FieldCount));
        assert_eq!(join_fields(&["a b"]), Err(GrantError::ByteOutOfRange));
    }

    #[test]
    fn decimals_are_canonical_and_bounded() {
        assert_eq!(decimal_u64("0"), Ok(0));
        assert_eq!(decimal_u64("18446744073709551615"), Ok(u64::MAX));
        assert_eq!(
            decimal_u64("18446744073709551616"),
            Err(GrantError::DecimalOutOfRange)
        );
        assert_eq!(decimal_millis("9223372036854775807"), Ok(i64::MAX));
        assert_eq!(
            decimal_millis("9223372036854775808"),
            Err(GrantError::DecimalOutOfRange)
        );
        for bad in ["+1", "-1", "01", "00", "", "1a", " 1", "1.0", "0x1"] {
            assert_eq!(decimal_u64(bad), Err(GrantError::Decimal), "{bad:?}");
            assert_eq!(decimal_millis(bad), Err(GrantError::Decimal), "{bad:?}");
        }
        assert_eq!(encode_millis(0).unwrap(), "0");
        assert_eq!(encode_millis(-1), Err(GrantError::DecimalOutOfRange));
    }

    #[test]
    fn hex32_is_lowercase_fixed_length() {
        let lower = "ab".repeat(32);
        assert_eq!(hex32(&lower), Ok([0xab; 32]));
        assert_eq!(encode_hex32(&[0xab; 32]), lower);
        assert_eq!(hex32(&"AB".repeat(32)), Err(GrantError::Hex));
        assert_eq!(hex32(&"ab".repeat(31)), Err(GrantError::Hex));
        assert_eq!(hex32(&format!("{lower}a")), Err(GrantError::Hex));
        assert_eq!(hex32(&"gg".repeat(32)), Err(GrantError::Hex));
    }

    #[test]
    fn audience_lists() {
        assert_eq!(
            audiences("http://[::1]:8443,https://a.example").unwrap(),
            ["http://[::1]:8443", "https://a.example"]
        );
        let cases: &[(&str, GrantError)] = &[
            ("https://*.example", GrantError::AudienceWildcard),
            ("*", GrantError::AudienceWildcard),
            ("https://a.example,*", GrantError::AudienceWildcard),
            ("https://A.example", GrantError::Audience),
            ("https://a.example:443", GrantError::Audience),
            ("http://a.example:80", GrantError::Audience),
            ("https://a.example.", GrantError::Audience),
            ("https://a.example/", GrantError::Audience),
            ("https://a.example/x", GrantError::Audience),
            ("https://u@a.example", GrantError::Audience),
            ("ftp://a.example", GrantError::Audience),
            ("https://a.example,", GrantError::Audience),
            (
                "https://b.example,https://a.example",
                GrantError::AudiencesUnordered,
            ),
            (
                "https://a.example,https://a.example",
                GrantError::AudiencesUnordered,
            ),
        ];
        for (field, err) in cases {
            assert_eq!(audiences(field), Err(*err), "{field}");
        }
        let nine: Vec<String> = (1..=9).map(|i| format!("https://a{i}.example")).collect();
        assert_eq!(audiences(&nine.join(",")), Err(GrantError::AudienceCount));
        assert_eq!(audiences(&nine[..8].join(",")).unwrap().len(), 8);
        assert_eq!(encode_audiences(&[]), Err(GrantError::AudienceCount));
        assert_eq!(
            encode_audiences(&["https://b.example".into(), "https://a.example".into()]),
            Err(GrantError::AudiencesUnordered)
        );
    }

    #[test]
    fn lifetimes() {
        assert_eq!(check_lifetime(0, 1, 10), Ok(()));
        assert_eq!(check_lifetime(0, 10, 10), Ok(()));
        assert_eq!(check_lifetime(0, 11, 10), Err(GrantError::LifetimeTooLong));
        assert_eq!(
            check_lifetime(5, 5, 10),
            Err(GrantError::ExpiryNotAfterCreated)
        );
        assert_eq!(
            check_lifetime(5, 4, 10),
            Err(GrantError::ExpiryNotAfterCreated)
        );
        assert_eq!(
            check_lifetime(-1, 4, 10),
            Err(GrantError::DecimalOutOfRange)
        );
        assert_eq!(check_lifetime(i64::MAX - 1, i64::MAX, 10), Ok(()));
    }
}
