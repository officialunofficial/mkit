//! The `X-Write-Grant` header value (SPEC-WRITE-GRANTS §4.2):
//! `<statement>.<scheme>.<blob>`.

use base64::Engine as _;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};

use super::{GrantError, MAX_GRANT_HEADER_BYTES};

/// Unpadded base64url (RFC 4648 §5) that rejects padding, characters outside
/// the alphabet and non-zero unused trailing bits, so each byte string has
/// exactly one encoding. Spelled out rather than taken from
/// `URL_SAFE_NO_PAD` so a change of defaults cannot loosen it.
const B64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone)
        .with_decode_allow_trailing_bits(false),
);

/// An owner signature scheme (§4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OwnerScheme {
    /// `ed25519`: an Ed25519 signature over the BLAKE3 of the statement;
    /// `ed25519-` namespaces only.
    Ed25519,
    /// `secp256k1-eip191`: an EIP-191 personal-message signature; `0x`
    /// namespaces only.
    Secp256k1Eip191,
    /// `webauthn-p256`: a `WebAuthn` P-256 assertion; `0x` namespaces only.
    WebAuthnP256,
}

impl OwnerScheme {
    /// Every scheme, in §4 table order.
    pub const ALL: [Self; 3] = [Self::Ed25519, Self::Secp256k1Eip191, Self::WebAuthnP256];

    /// The scheme token.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::Secp256k1Eip191 => "secp256k1-eip191",
            Self::WebAuthnP256 => "webauthn-p256",
        }
    }

    /// The scheme with exactly this token.
    #[must_use]
    pub fn from_token(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|scheme| scheme.token() == s)
    }
}

/// A decoded `X-Write-Grant` value. It carries grants, epoch statements and
/// visibility statements alike; the caller parses `statement` and verifies
/// `blob` under `scheme`.
///
/// "At most one `X-Write-Grant` header per request" is the HTTP layer's
/// check; this type sees one value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedHeader {
    /// The statement bytes (not yet parsed).
    pub statement: Vec<u8>,
    /// The owner signature scheme.
    pub scheme: OwnerScheme,
    /// The signature blob (not yet verified).
    pub blob: Vec<u8>,
}

impl SignedHeader {
    /// Decode a header value.
    ///
    /// # Errors
    /// `HeaderTooLong` above `MAX_GRANT_HEADER_BYTES`; `HeaderFormat` unless
    /// there are exactly three non-empty `.`-separated segments;
    /// `UnknownScheme`; `HeaderBase64` for padding, a character outside the
    /// base64url alphabet, or non-zero trailing bits.
    pub fn parse(value: &str) -> Result<Self, GrantError> {
        if value.len() > MAX_GRANT_HEADER_BYTES {
            return Err(GrantError::HeaderTooLong);
        }
        let mut parts = value.split('.');
        let (Some(statement), Some(scheme), Some(blob), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(GrantError::HeaderFormat);
        };
        if statement.is_empty() || scheme.is_empty() || blob.is_empty() {
            return Err(GrantError::HeaderFormat);
        }
        let scheme = OwnerScheme::from_token(scheme).ok_or(GrantError::UnknownScheme)?;
        let decode = |s: &str| B64.decode(s).map_err(|_| GrantError::HeaderBase64);
        Ok(Self {
            statement: decode(statement)?,
            scheme,
            blob: decode(blob)?,
        })
    }

    /// Encode the header value.
    ///
    /// # Errors
    /// `HeaderFormat` for an empty statement or blob (no segment may be
    /// empty); `HeaderTooLong` above `MAX_GRANT_HEADER_BYTES`.
    pub fn encode(&self) -> Result<String, GrantError> {
        if self.statement.is_empty() || self.blob.is_empty() {
            return Err(GrantError::HeaderFormat);
        }
        let value = format!(
            "{}.{}.{}",
            B64.encode(&self.statement),
            self.scheme.token(),
            B64.encode(&self.blob)
        );
        if value.len() > MAX_GRANT_HEADER_BYTES {
            return Err(GrantError::HeaderTooLong);
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(statement: &[u8], blob: &[u8]) -> SignedHeader {
        SignedHeader {
            statement: statement.to_vec(),
            scheme: OwnerScheme::Ed25519,
            blob: blob.to_vec(),
        }
    }

    #[test]
    fn scheme_tokens() {
        for scheme in OwnerScheme::ALL {
            assert_eq!(OwnerScheme::from_token(scheme.token()), Some(scheme));
        }
        for bad in [
            "",
            "Ed25519",
            "ed25519 ",
            "secp256k1",
            "webauthn-p256k",
            "p256",
        ] {
            assert_eq!(OwnerScheme::from_token(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn roundtrip() {
        for scheme in OwnerScheme::ALL {
            for (s, b) in [
                (&b"a"[..], &b"b"[..]),
                (b"ab", b"abc"),
                (b"\xff\xfe\xfd", &[0u8; 65][..]),
            ] {
                let h = SignedHeader {
                    statement: s.to_vec(),
                    scheme,
                    blob: b.to_vec(),
                };
                let text = h.encode().unwrap();
                assert!(!text.contains('='));
                assert_eq!(SignedHeader::parse(&text), Ok(h));
            }
        }
        assert_eq!(
            header(b"\xfb\xff", b"a").encode().unwrap(),
            "-_8.ed25519.YQ"
        );
    }

    #[test]
    fn rejects_non_canonical_base64() {
        // Padding.
        assert_eq!(
            SignedHeader::parse("YQ==.ed25519.YQ"),
            Err(GrantError::HeaderBase64)
        );
        assert_eq!(
            SignedHeader::parse("YQ.ed25519.YQ="),
            Err(GrantError::HeaderBase64)
        );
        // Standard alphabet.
        assert_eq!(
            SignedHeader::parse("+_8.ed25519.YQ"),
            Err(GrantError::HeaderBase64)
        );
        assert_eq!(
            SignedHeader::parse("-/8.ed25519.YQ"),
            Err(GrantError::HeaderBase64)
        );
        // Non-zero trailing bits: "QQ" is the only encoding of "A"; "QR" .. "QZ"
        // decode to the same byte if trailing bits were allowed.
        assert!(SignedHeader::parse("QQ.ed25519.YQ").is_ok());
        assert_eq!(
            SignedHeader::parse("QR.ed25519.YQ"),
            Err(GrantError::HeaderBase64)
        );
        assert_eq!(
            SignedHeader::parse("YQ.ed25519.YR"),
            Err(GrantError::HeaderBase64)
        );
        // "AA" and "AB" for one zero byte.
        assert!(SignedHeader::parse("AA.ed25519.YQ").is_ok());
        assert_eq!(
            SignedHeader::parse("AB.ed25519.YQ"),
            Err(GrantError::HeaderBase64)
        );
        // A length that is 1 mod 4 encodes no byte string.
        assert_eq!(
            SignedHeader::parse("QUJDR.ed25519.YQ"),
            Err(GrantError::HeaderBase64)
        );
        // Whitespace.
        assert_eq!(
            SignedHeader::parse("Y Q.ed25519.YQ"),
            Err(GrantError::HeaderBase64)
        );
    }

    #[test]
    fn rejects_bad_structure() {
        for bad in [
            "YQ.ed25519",
            "YQ",
            "YQ.ed25519.YQ.YQ",
            "YQ..ed25519.YQ",
            ".ed25519.YQ",
            "YQ.ed25519.",
            "YQ..YQ",
            "",
        ] {
            assert_eq!(
                SignedHeader::parse(bad),
                Err(GrantError::HeaderFormat),
                "{bad:?}"
            );
        }
        assert_eq!(
            SignedHeader::parse("YQ.rsa.YQ"),
            Err(GrantError::UnknownScheme)
        );
        assert_eq!(
            SignedHeader::parse("YQ.ED25519.YQ"),
            Err(GrantError::UnknownScheme)
        );
        assert_eq!(header(b"", b"a").encode(), Err(GrantError::HeaderFormat));
        assert_eq!(header(b"a", b"").encode(), Err(GrantError::HeaderFormat));
    }

    #[test]
    fn header_length_bound() {
        // 6135 bytes encode to 8180 characters; ".ed25519.YWI" adds 12.
        let exact = header(&[b'x'; 6135], b"ab").encode().unwrap();
        assert_eq!(exact.len(), MAX_GRANT_HEADER_BYTES);
        assert!(SignedHeader::parse(&exact).is_ok());
        let over = format!("{exact}A");
        assert_eq!(over.len(), MAX_GRANT_HEADER_BYTES + 1);
        assert_eq!(SignedHeader::parse(&over), Err(GrantError::HeaderTooLong));
        assert_eq!(
            header(&vec![b'x'; MAX_GRANT_HEADER_BYTES], b"a").encode(),
            Err(GrantError::HeaderTooLong)
        );
    }
}
