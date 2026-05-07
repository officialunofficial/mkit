//! ECDSA-DER → compact-P-256 conversion. The CTAP authenticator
//! returns DER-encoded ECDSA signatures; mkit-rpc carries them as
//! 64-byte compact `r || s` per SPEC-ATTESTATIONS. This module is
//! the only place we touch DER bytes, so the wire-shape invariants
//! are tested in one place.

use crate::SignerError;

/// Convert a DER-encoded ECDSA signature (as every CTAP authenticator
/// returns) to a 64-byte compact `r || s`, low-S-normalised per P-256
/// group order.
///
/// # Errors
/// [`SignerError::SigConvert`] with a short literal reason.
pub(crate) fn der_to_compact_p256(der: &[u8]) -> Result<[u8; 64], SignerError> {
    if der.len() < 8 {
        return Err(SignerError::SigConvert("DER too short"));
    }
    if der[0] != 0x30 {
        return Err(SignerError::SigConvert("expected SEQUENCE tag 0x30"));
    }

    let (seq_len, mut pos) = parse_der_len(&der[1..])?;
    pos += 1;
    if pos + seq_len > der.len() {
        return Err(SignerError::SigConvert("SEQ length past end"));
    }

    if der.get(pos) != Some(&0x02) {
        return Err(SignerError::SigConvert("expected INTEGER tag for r"));
    }
    pos += 1;
    let (r_len, r_hdr) = parse_der_len(&der[pos..])?;
    pos += r_hdr;
    if pos + r_len > der.len() {
        return Err(SignerError::SigConvert("r length past end"));
    }
    let r = &der[pos..pos + r_len];
    pos += r_len;

    if der.get(pos) != Some(&0x02) {
        return Err(SignerError::SigConvert("expected INTEGER tag for s"));
    }
    pos += 1;
    let (s_len, s_hdr) = parse_der_len(&der[pos..])?;
    pos += s_hdr;
    if pos + s_len > der.len() {
        return Err(SignerError::SigConvert("s length past end"));
    }
    let s = &der[pos..pos + s_len];

    let r_fixed = to_fixed_32(r)?;
    let s_fixed = to_fixed_32(s)?;
    let s_norm = low_s_normalise(&s_fixed);

    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&r_fixed);
    out[32..].copy_from_slice(&s_norm);
    Ok(out)
}

/// DER length parser. Short-form (high bit clear) is 1 byte;
/// long-form `0x81 LL` is 2 bytes; longer encodings refused —
/// ECDSA signatures never need them.
fn parse_der_len(bytes: &[u8]) -> Result<(usize, usize), SignerError> {
    let first = *bytes
        .first()
        .ok_or(SignerError::SigConvert("empty length"))?;
    if first < 0x80 {
        Ok((first as usize, 1))
    } else if first == 0x81 {
        let second = *bytes
            .get(1)
            .ok_or(SignerError::SigConvert("truncated long-form length"))?;
        Ok((second as usize, 2))
    } else {
        Err(SignerError::SigConvert("unsupported DER length encoding"))
    }
}

fn to_fixed_32(int_body: &[u8]) -> Result<[u8; 32], SignerError> {
    let mut body = int_body;
    while body.len() > 1 && body[0] == 0 {
        body = &body[1..];
    }
    if body.len() > 32 {
        return Err(SignerError::SigConvert("integer longer than 32 bytes"));
    }
    let mut out = [0u8; 32];
    out[32 - body.len()..].copy_from_slice(body);
    Ok(out)
}

/// P-256 group order `n`.
const P256_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

/// Return `s` if already low-S, else return `n - s`. The high-bit-of-s
/// fast path covers every signature any real curve produces.
fn low_s_normalise(s: &[u8; 32]) -> [u8; 32] {
    if s[0] <= 0x7F {
        return *s;
    }
    let mut out = [0u8; 32];
    let mut borrow: u16 = 0;
    for i in (0..32).rev() {
        let lhs = u16::from(P256_N[i]);
        let rhs = u16::from(s[i]) + borrow;
        if lhs >= rhs {
            out[i] = u8::try_from(lhs - rhs).unwrap_or(0);
            borrow = 0;
        } else {
            out[i] = u8::try_from((lhs + 256) - rhs).unwrap_or(0);
            borrow = 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_to_compact_roundtrips_known_signature() {
        // Construct: r = 0x008000...01 (33 bytes incl leading 0), s = 0x07
        let mut der = vec![
            0x30, // SEQUENCE
            0x26, // body length = 38
            0x02, // INTEGER
            0x21, // length 33 (includes leading 0x00)
            0x00,
        ];
        der.extend_from_slice(&[0u8; 31]);
        der.extend_from_slice(&[
            0x42, 0x02, // INTEGER
            0x01, // length 1
            0x07,
        ]);
        let compact = der_to_compact_p256(&der).unwrap();
        assert_eq!(compact[31], 0x42);
        assert_eq!(compact[63], 0x07);
        assert_eq!(&compact[..31], &[0u8; 31]);
        assert_eq!(&compact[32..63], &[0u8; 31]);
    }

    #[test]
    fn der_to_compact_rejects_too_short() {
        let err = der_to_compact_p256(&[0x30, 0x00]).unwrap_err();
        assert!(matches!(err, SignerError::SigConvert(_)));
    }

    #[test]
    fn der_to_compact_rejects_bad_tag() {
        let bogus = vec![0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        let err = der_to_compact_p256(&bogus).unwrap_err();
        assert!(matches!(err, SignerError::SigConvert(_)));
    }

    #[test]
    fn low_s_identity_when_already_low() {
        let s = [0x10u8; 32];
        assert_eq!(low_s_normalise(&s), s);
    }

    #[test]
    fn low_s_flips_high_s() {
        // s = n - 1 is high-S. n - s = 1.
        let mut s = P256_N;
        s[31] -= 1;
        let out = low_s_normalise(&s);
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(out, expected);
    }

    #[test]
    fn der_to_compact_crossvalidates_against_p256_crate() {
        use p256::ecdsa::{Signature as P256Sig, SigningKey, signature::Signer as _};
        let sk = SigningKey::from_bytes(&[9u8; 32].into()).unwrap();
        let msg = b"cross-check message";
        let sig: P256Sig = sk.sign(msg);
        let sig = sig.normalize_s().unwrap_or(sig);

        let compact_expected = sig.to_bytes();
        let der = sig.to_der();
        let compact_ours = der_to_compact_p256(der.as_bytes()).unwrap();

        assert_eq!(
            compact_ours.as_slice(),
            compact_expected.as_slice(),
            "our DER->compact must match p256 crate's native conversion"
        );
    }
}
