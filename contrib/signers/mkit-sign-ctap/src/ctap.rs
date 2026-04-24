//! Thin wrapper over `ctap-hid-fido2` that exposes exactly the two
//! ceremonies the signer needs: `make_credential` for `enroll` and
//! `get_assertion` for `sign`. Every hardware-touching call lives
//! here so the rest of the binary can be unit-tested without a
//! physical authenticator attached.
//!
//! The `ctap-hid-fido2` crate uses `anyhow::Error` internally; we
//! flatten those into a single [`SignerError::Ctap(String)`] so the
//! public error surface stays small and one-variant-per-cause.

use ctap_hid_fido2::fidokey::{GetAssertionArgsBuilder, MakeCredentialArgsBuilder};
use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};

use crate::SignerError;

/// Returned by [`make_credential`] — the minimum mkit needs to
/// record an enrolment. `public_key_sec1_uncompressed` is the 65-byte
/// `0x04 || x || y` form CTAP returns; if the authenticator does not
/// emit a parsable pubkey (older devices) the field is empty.
#[derive(Debug, Clone)]
pub struct EnrolledCredential {
    pub credential_id: Vec<u8>,
    pub public_key_sec1_uncompressed: Vec<u8>,
    pub keyid: String,
}

/// Returned by [`get_assertion`] — the raw bits the v1.1 response
/// needs: `auth_data` (as base64url-no-pad on the wire), `signature`
/// (DER; converted to compact 64-byte r||s by `proto`), and the
/// credential id the authenticator echoed back.
#[derive(Debug, Clone)]
pub struct SignedAssertion {
    pub auth_data: Vec<u8>,
    pub signature: Vec<u8>,
    #[allow(dead_code)]
    // Useful for callers that want to cross-check; `sign` uses the CLI-provided id.
    pub credential_id: Vec<u8>,
}

/// Run a CTAP `make_credential` ceremony. The `user_name` doubles as
/// the CTAP user handle; in a multi-credential world the caller would
/// want something more structured, but for a reference signer the
/// display-name-as-handle approach is fine.
///
/// # Errors
/// * [`SignerError::Ctap`] — no device attached, user cancelled,
///   PIN required but missing, etc.
pub fn make_credential(
    rp_id: &str,
    // Kept on the signature for future use — CTAP uses this on the
    // `user.name` field of the credential descriptor, but the
    // ctap-hid-fido2 builder we use here does not expose that field
    // in v3.5. Underscored so clippy / rustc don't warn.
    _user_name: &str,
    pin: Option<&str>,
) -> Result<EnrolledCredential, SignerError> {
    // A fresh random challenge for the enrolment attestation. The
    // verifier doesn't use this challenge (we trust the device
    // binding via the stored credential_id + pubkey), but the
    // authenticator refuses a zero challenge.
    let challenge = make_challenge();

    let mut builder = MakeCredentialArgsBuilder::new(rp_id, &challenge);
    if let Some(p) = pin {
        builder = builder.pin(p);
    }
    let args = builder.build();

    let device = FidoKeyHidFactory::create(&Cfg::init())
        .map_err(|e| SignerError::Ctap(format!("open device: {e}")))?;
    let attestation = device
        .make_credential_with_args(&args)
        .map_err(|e| SignerError::Ctap(format!("make_credential: {e}")))?;

    let credential_id = attestation.credential_descriptor.id;
    let pubkey_der = attestation.credential_publickey.der;
    // Convert the DER-SPKI pubkey to SEC1-uncompressed. Easiest path:
    // strip the known 26-byte SPKI prefix for id-ecPublicKey +
    // prime256v1 + BIT STRING, leaving the raw 65-byte SEC1.
    let pubkey_sec1 = spki_der_to_sec1_uncompressed(&pubkey_der).unwrap_or_default();
    let keyid = if pubkey_sec1.len() == 65 {
        // Build the p256:<hex-compressed> keyid by compressing the
        // uncompressed form. Compression: take y-parity from byte 64
        // and emit `0x02`/`0x03` || x.
        let parity = if pubkey_sec1[64] & 1 == 0 {
            0x02u8
        } else {
            0x03u8
        };
        let mut compressed = Vec::with_capacity(33);
        compressed.push(parity);
        compressed.extend_from_slice(&pubkey_sec1[1..33]);
        format!("p256:{}", to_hex(&compressed))
    } else {
        // Fallback: no pubkey from the authenticator. Let the caller
        // ship a webauthn:<credential-id> keyid instead.
        use base64::Engine as _;
        format!(
            "webauthn:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&credential_id)
        )
    };

    Ok(EnrolledCredential {
        credential_id,
        public_key_sec1_uncompressed: pubkey_sec1,
        keyid,
    })
}

/// Run a CTAP `get_assertion` ceremony. `client_data_json` is the
/// raw UTF-8 JSON the verifier will reconstruct; the underlying crate
/// takes it as the `challenge` and internally computes SHA-256 —
/// which is exactly the hash the authenticator signs under.
///
/// # Errors
/// [`SignerError::Ctap`] on any hardware / timeout / cancel failure.
pub fn get_assertion(
    rp_id: &str,
    credential_id: &[u8],
    client_data_json: &[u8],
    pin: Option<&str>,
) -> Result<SignedAssertion, SignerError> {
    let mut builder =
        GetAssertionArgsBuilder::new(rp_id, client_data_json).credential_id(credential_id);
    if let Some(p) = pin {
        builder = builder.pin(p);
    } else {
        // No PIN and no UV was explicitly configured — let the
        // authenticator decide. For a credential enrolled without a
        // PIN (e.g. UV=always via a platform auth) this works; for a
        // PIN-enrolled credential this will fail with a clear CTAP
        // error we propagate.
        builder = builder.without_pin_and_uv();
    }
    let args = builder.build();

    let device = FidoKeyHidFactory::create(&Cfg::init())
        .map_err(|e| SignerError::Ctap(format!("open device: {e}")))?;
    let assertions = device
        .get_assertion_with_args(&args)
        .map_err(|e| SignerError::Ctap(format!("get_assertion: {e}")))?;
    let first = assertions
        .into_iter()
        .next()
        .ok_or_else(|| SignerError::Ctap("authenticator returned 0 assertions".to_owned()))?;

    Ok(SignedAssertion {
        auth_data: first.auth_data,
        signature: first.signature,
        credential_id: first.credential_id,
    })
}

/// 32-byte random challenge for `make_credential`. `ctap-hid-fido2`
/// ships a `verifier::create_challenge` but pulling in a crate just
/// for that is overkill — we use `std::time` + a tiny hash instead.
/// Not cryptographically rigorous; good enough for a value the
/// authenticator signs once and the verifier never checks.
fn make_challenge() -> Vec<u8> {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Weak diversity but we only need "not zero and varies per run".
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let seed = [
        now.as_secs().to_le_bytes(),
        (now.subsec_nanos() as u64).to_le_bytes(),
    ]
    .concat();
    // Expand to 32 bytes by simple repetition. Enough entropy for the
    // purpose — the challenge is a nonce, not a secret.
    let mut out = Vec::with_capacity(32);
    for i in 0..32 {
        out.push(seed[i % seed.len()] ^ (i as u8));
    }
    out
}

/// Strip the 26-byte SPKI prefix that wraps a NIST P-256 pubkey and
/// return the raw SEC1-uncompressed 65-byte body. Returns `None` if
/// the input does not start with the expected prefix — we'd rather
/// surface an empty pubkey and let the caller fall back to a
/// `webauthn:<credential-id>` keyid than silently mis-decode.
fn spki_der_to_sec1_uncompressed(der: &[u8]) -> Option<Vec<u8>> {
    // The prefix is fixed for id-ecPublicKey + prime256v1 + BIT
    // STRING, unused=0. Observed across every CTAP pubkey we've seen.
    const SPKI_PREFIX: &[u8] = &[
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    if der.len() < SPKI_PREFIX.len() + 65 {
        return None;
    }
    if !der.starts_with(SPKI_PREFIX) {
        return None;
    }
    Some(der[SPKI_PREFIX.len()..SPKI_PREFIX.len() + 65].to_vec())
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spki_strip_known_prefix() {
        // Assemble a valid SPKI body: prefix + 65 bytes starting 0x04.
        let mut der = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        der.push(0x04);
        der.extend_from_slice(&[0x11u8; 64]);
        let body = spki_der_to_sec1_uncompressed(&der).unwrap();
        assert_eq!(body.len(), 65);
        assert_eq!(body[0], 0x04);
    }

    #[test]
    fn spki_strip_rejects_unknown_prefix() {
        let der = vec![0u8; 200];
        assert!(spki_der_to_sec1_uncompressed(&der).is_none());
    }

    #[test]
    fn make_challenge_is_32_bytes_nonzero() {
        let c = make_challenge();
        assert_eq!(c.len(), 32);
        assert!(c.iter().any(|&b| b != 0), "challenge must not be all zeros");
    }

    #[test]
    fn to_hex_roundtrip_matches_lowercase() {
        assert_eq!(to_hex(&[0x0a, 0xff]), "0aff");
        assert_eq!(to_hex(&[]), "");
    }
}
