//! Bounded, transport-neutral admission challenges (STC §5.1).

/// Maximum number of challenges in one decision.
pub const MAX_CHALLENGES: usize = 8;
/// Maximum ASCII scheme length.
pub const MAX_SCHEME_BYTES: usize = 64;
/// Maximum challenge value length.
pub const MAX_VALUE_BYTES: usize = 8_192;
/// Maximum human-readable description length.
pub const MAX_DESCRIPTION_BYTES: usize = 512;

/// A violation of the public challenge bounds. No credential content is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundError {
    /// The challenge count is outside 1–8.
    Count,
    /// A scheme is not a lowercase token of at most 64 bytes.
    Scheme,
    /// A value is too long or contains a forbidden control byte.
    Value,
    /// A description is too long or contains a forbidden control byte.
    Description,
}

/// The STC lowercase scheme grammar.
#[must_use]
pub fn is_valid_scheme(scheme: &str) -> bool {
    let bytes = scheme.as_bytes();
    (1..=MAX_SCHEME_BYTES).contains(&bytes.len())
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-".contains(byte))
}

/// Validate an ordered challenge list and its description.
///
/// # Errors
/// Returns the first violated bound without echoing the offending value.
pub fn validate_challenges(
    challenges: &[(&str, &str)],
    description: &str,
) -> Result<(), BoundError> {
    if !(1..=MAX_CHALLENGES).contains(&challenges.len()) {
        return Err(BoundError::Count);
    }
    for (scheme, value) in challenges {
        if !is_valid_scheme(scheme) {
            return Err(BoundError::Scheme);
        }
        if value.len() > MAX_VALUE_BYTES || value.chars().any(forbidden_control) {
            return Err(BoundError::Value);
        }
    }
    if description.len() > MAX_DESCRIPTION_BYTES || description.chars().any(forbidden_control) {
        return Err(BoundError::Description);
    }
    Ok(())
}

fn forbidden_control(ch: char) -> bool {
    ch != '\t' && ch.is_control()
}

fn varint(mut value: usize, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn field(number: u8, value: &[u8], out: &mut Vec<u8>) {
    out.push((number << 3) | 2);
    varint(value.len(), out);
    out.extend_from_slice(value);
}

/// Encode the validated STC protobuf detail without a protobuf dependency.
#[must_use]
pub fn encode_admission_challenge(challenges: &[(&str, &str)], description: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for (scheme, value) in challenges {
        let mut entry = Vec::new();
        if !scheme.is_empty() {
            field(1, scheme.as_bytes(), &mut entry);
        }
        if !value.is_empty() {
            field(2, value.as_bytes(), &mut entry);
        }
        field(1, &entry, &mut out);
    }
    if !description.is_empty() {
        field(2, description.as_bytes(), &mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_bytes() {
        let challenges = [
            (
                "mpp",
                "Payment id=\"fake-example-not-valid\", method=\"tempo\", intent=\"charge\", request=\"fake-example-request-not-valid\"",
            ),
            ("x402", "fake-example-payment-required-not-valid"),
        ];
        assert_eq!(
            encode_admission_challenge(&challenges, "Example upload payment required."),
            include_bytes!("../../../tests/golden/transport/admission-challenge.bin")
        );
    }

    #[test]
    fn bounds() {
        for good in ["a", "0", "mpp.v1-2", &"a".repeat(64)] {
            assert!(is_valid_scheme(good));
        }
        for bad in ["", "A", "mpp_1", "-mpp", &"a".repeat(65)] {
            assert!(!is_valid_scheme(bad));
        }
        assert_eq!(validate_challenges(&[], ""), Err(BoundError::Count));
        assert!(validate_challenges(&vec![("mpp", "v"); 8], "").is_ok());
        assert_eq!(
            validate_challenges(&vec![("mpp", "v"); 9], ""),
            Err(BoundError::Count)
        );
        assert!(validate_challenges(&[("mpp", &"v".repeat(8192))], &"d".repeat(512)).is_ok());
        assert_eq!(
            validate_challenges(&[("mpp", &"v".repeat(8193))], ""),
            Err(BoundError::Value)
        );
        assert_eq!(
            validate_challenges(&[("mpp", "v")], &"d".repeat(513)),
            Err(BoundError::Description)
        );
        assert_eq!(
            validate_challenges(&[("mpp", "a\r")], ""),
            Err(BoundError::Value)
        );
        assert_eq!(
            validate_challenges(&[("mpp", "a")], "a\n"),
            Err(BoundError::Description)
        );
        assert_eq!(
            validate_challenges(&[("mpp", "a\u{85}")], ""),
            Err(BoundError::Value)
        );
    }
}
