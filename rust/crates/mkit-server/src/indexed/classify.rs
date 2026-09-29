//! Ticketed upload classification by its first four bytes.

use crate::ServerError;

/// The two indexed upload types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadType {
    /// MKIT pack.
    Pack,
    /// MKPL packlist node.
    Packlist,
}

/// Classify from the first four bytes, rejecting a shorter or unknown blob.
pub fn classify(prefix: &[u8]) -> Result<UploadType, ServerError> {
    match prefix.get(..4) {
        Some(b"MKIT") => Ok(UploadType::Pack),
        Some(b"MKPL") => Ok(UploadType::Packlist),
        _ => Err(ServerError::invalid_argument("unknown upload type")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_magic_and_short_input() {
        assert_eq!(classify(b"MKITx").unwrap(), UploadType::Pack);
        assert_eq!(classify(b"MKPLx").unwrap(), UploadType::Packlist);
        for bytes in [b"MKI".as_slice(), b"", b"NOPE", b"mkit"] {
            assert_eq!(
                classify(bytes).unwrap_err().public_message(),
                "unknown upload type"
            );
        }
    }
}
