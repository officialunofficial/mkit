//! Wire-shape types for v1 request / v1.1 response plus the
//! DER→compact-P-256 signature conversion used to normalise
//! authenticator output.
//!
//! The request type matches SPEC-EXTERNAL-SIGNER §3. The response
//! type matches §14.2. We derive `Deserialize` on the request so the
//! signer is forgiving of key order, and we hand-render the response
//! so the field order matches every §14 example (keyid, sig_base64,
//! webauthn).

use serde::{Deserialize, Serialize};

use crate::SignerError;

#[derive(Debug, Deserialize)]
pub(crate) struct SignRequest {
    pub pae_base64: String,
    pub algorithm: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct SignResponse {
    pub keyid: String,
    pub sig_base64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webauthn: Option<WebAuthnResponse>,
}

#[derive(Debug, Serialize)]
pub(crate) struct WebAuthnResponse {
    pub authenticator_data: String,
    pub client_data_json: String,
}

/// Render the v1.1 response with the exact key order and quoting
/// every §14 example uses. We deliberately don't use `serde_json`'s
/// auto-derive here because its default writer sorts map keys by
/// insertion (preserved) rather than alphabetically — behaviour
/// that's stable but not what the spec examples illustrate. The
/// hand-render guarantees one canonical shape.
pub(crate) fn render_response_json(r: &SignResponse) -> String {
    // Escape what needs escaping — keyid / sig_base64 are restricted
    // character sets (hex, base64) so they never contain escape-prone
    // bytes, but we escape anyway for defence-in-depth.
    let keyid = json_escape(&r.keyid);
    let sig = json_escape(&r.sig_base64);
    match &r.webauthn {
        Some(w) => {
            let ad = json_escape(&w.authenticator_data);
            let cdj = json_escape(&w.client_data_json);
            format!(
                "{{\"keyid\":\"{keyid}\",\"sig_base64\":\"{sig}\",\"webauthn\":{{\"authenticator_data\":\"{ad}\",\"client_data_json\":\"{cdj}\"}}}}"
            )
        }
        None => format!("{{\"keyid\":\"{keyid}\",\"sig_base64\":\"{sig}\"}}"),
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Convert a DER-encoded ECDSA signature (as every CTAP
/// authenticator returns) to a 64-byte compact `r || s`,
/// low-S-normalised per P-256 group order. DER parsing here is
/// hand-rolled — the message is a trusted shape from the
/// authenticator, but we still reject malformed inputs so the
/// wire-layer error surface stays sharp.
///
/// # Errors
/// [`SignerError::SigConvert`] with a short literal reason.
pub(crate) fn der_to_compact_p256(der: &[u8]) -> Result<[u8; 64], SignerError> {
    // Minimum valid ECDSA DER is 8 bytes: SEQ + len + INT + len + r + INT + len + s.
    if der.len() < 8 {
        return Err(SignerError::SigConvert("DER too short"));
    }
    if der[0] != 0x30 {
        return Err(SignerError::SigConvert("expected SEQUENCE tag 0x30"));
    }

    // SEQUENCE length. We tolerate both short-form (length < 128) and
    // one-byte long-form (0x81, length 0..=255). Two-byte long-form
    // (0x82, ≥256) is not produced by any real ECDSA signature
    // (max ~72 bytes) so we refuse it.
    let (seq_len, mut pos) = parse_der_len(&der[1..])?;
    // +1 to skip the leading 0x30 tag byte.
    pos += 1;
    if pos + seq_len > der.len() {
        return Err(SignerError::SigConvert("SEQ length past end"));
    }

    // r
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

    // s
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

    // Low-S normalise. The P-256 group order `n`:
    //   FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551
    // If s > n/2, replace with n - s. This produces the canonical
    // form mkit-attest's verify_p256 requires.
    let s_norm = low_s_normalise(&s_fixed);

    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&r_fixed);
    out[32..].copy_from_slice(&s_norm);
    Ok(out)
}

/// Parse a DER length field from `bytes`. Returns `(length,
/// bytes-consumed)`. Short-form (high bit clear) consumes 1 byte;
/// long-form `0x81 LL` consumes 2 bytes.
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
        // 0x82+ would mean a length ≥ 256; ECDSA DER never does that.
        Err(SignerError::SigConvert("unsupported DER length encoding"))
    }
}

/// Convert a DER INTEGER body to a 32-byte big-endian, stripping any
/// leading 0x00 padding and left-zero-padding short values.
fn to_fixed_32(int_body: &[u8]) -> Result<[u8; 32], SignerError> {
    // DER INTEGER may have a leading 0x00 if the high bit would
    // otherwise mark it negative. Strip all leading zeros.
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

/// Return `s` if already low-S (i.e. `s <= n/2`), else return `n - s`.
///
/// Low-S check is done as a big-endian `s < n_half_rounded_up`: we
/// compute n/2 (integer floor; n is odd so floor = (n-1)/2, but high
/// bit being ≤ 0x7F is the practical test used everywhere in the
/// ecosystem).
fn low_s_normalise(s: &[u8; 32]) -> [u8; 32] {
    // Fast path: top bit of s is 0 → s < n/2 → already low-S.
    if s[0] <= 0x7F {
        return *s;
    }
    // n - s big-endian subtract. u16 widen so the cast back to u8 is a
    // documented in-range narrowing.
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
    fn request_parses() {
        let req: SignRequest =
            serde_json::from_str(r#"{"pae_base64":"aGVsbG8=","algorithm":"p256"}"#).unwrap();
        assert_eq!(req.pae_base64, "aGVsbG8=");
        assert_eq!(req.algorithm, "p256");
    }

    #[test]
    fn response_renders_with_webauthn_block() {
        let r = SignResponse {
            keyid: "p256:abcd".into(),
            sig_base64: "SIG==".into(),
            webauthn: Some(WebAuthnResponse {
                authenticator_data: "AUTH".into(),
                client_data_json: "CDJ".into(),
            }),
        };
        let s = render_response_json(&r);
        // Exact field order per spec §14 examples.
        assert_eq!(
            s,
            r#"{"keyid":"p256:abcd","sig_base64":"SIG==","webauthn":{"authenticator_data":"AUTH","client_data_json":"CDJ"}}"#
        );
    }

    #[test]
    fn response_renders_without_webauthn() {
        let r = SignResponse {
            keyid: "p256:abcd".into(),
            sig_base64: "SIG==".into(),
            webauthn: None,
        };
        let s = render_response_json(&r);
        assert_eq!(s, r#"{"keyid":"p256:abcd","sig_base64":"SIG=="}"#);
    }

    #[test]
    fn der_to_compact_roundtrips_known_signature() {
        // A real p256-crate-emitted DER sig for a known key / msg.
        // We build it in-line to avoid a hex dep; the bytes below are
        // the DER-encoding of an arbitrary (r, s) pair where r and s
        // are small enough to need a leading 0x00 (common DER case).
        //
        // Construct: r = 0x008000...01 (33 bytes incl leading 0), s = 0x01
        // SEQ (1 + 2 + 34 + 2 + 1) = 40-byte body, len=0x28.
        let mut der = Vec::new();
        der.push(0x30); // SEQUENCE
        der.push(0x26); // body length = 38
        der.push(0x02); // INTEGER
        der.push(0x21); // length 33 (includes leading 0x00)
        der.push(0x00);
        der.extend_from_slice(&[0u8; 31]);
        der.push(0x42);
        der.push(0x02); // INTEGER
        der.push(0x01); // length 1
        der.push(0x07);
        let compact = der_to_compact_p256(&der).unwrap();
        // r ends at byte 31, s ends at byte 63.
        assert_eq!(compact[31], 0x42);
        assert_eq!(compact[63], 0x07);
        // Rest of r is zero, rest of s is zero.
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
        // Wrong leading tag.
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
        // s = n - 1 is definitely high-S. n - s = 1.
        let mut s = P256_N;
        s[31] -= 1;
        let out = low_s_normalise(&s);
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(out, expected);
    }

    #[test]
    fn der_to_compact_crossvalidates_against_p256_crate() {
        // Generate a signature with the p256 crate (pulled in by
        // mkit-attest) and confirm our DER parser produces the same
        // compact bytes the crate's own Signature::to_bytes() does.
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
