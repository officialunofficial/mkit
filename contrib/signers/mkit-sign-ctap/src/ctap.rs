//! CTAP-HID device abstraction.
//!
//! [`CtapDevice`] is the trait the signer drives. The production impl
//! [`RealCtapDevice`] uses `ctap-hid-fido2` to talk to a plugged-in
//! authenticator and is gated on the `ctap-hw` Cargo feature so the
//! crate compiles on platforms / containers that lack `hidapi` or
//! `libudev`. Unit tests use [`MockCtapDevice`] to exercise the
//! signer's wire-protocol logic without hardware.
//!
//! Every hardware-touching call lives behind the trait so the rest of
//! the binary can be unit-tested without a physical authenticator
//! attached.

use crate::SignerError;

/// What [`CtapDevice::make_credential`] returns. `public_key_sec1_uncompressed`
/// is the 65-byte `0x04 || x || y` form CTAP returns; if the
/// authenticator does not emit a parsable pubkey (older devices) the
/// field is empty.
#[derive(Debug, Clone)]
pub struct EnrolledCredential {
    pub credential_id: Vec<u8>,
    pub public_key_sec1_uncompressed: Vec<u8>,
    pub keyid: String,
}

/// What [`CtapDevice::get_assertion`] returns. `auth_data` and the
/// signed `client_data_json` together form the WebAuthn assertion the
/// verifier reconstructs.
#[derive(Debug, Clone)]
pub struct SignedAssertion {
    pub auth_data: Vec<u8>,
    /// DER-encoded ECDSA. Convert with `proto::der_to_compact_p256`
    /// before placing in a `SignerFrame`.
    pub signature: Vec<u8>,
    #[allow(dead_code)]
    // Useful for callers that want to cross-check; we use the
    // CLI-provided id instead.
    pub credential_id: Vec<u8>,
}

/// CTAP-HID surface the signer needs.
///
/// Two methods only — `make_credential` for the `enroll` subcommand
/// and `get_assertion` for the `sign` subcommand. Both take `&self`
/// so a single device handle can be reused across calls.
pub trait CtapDevice {
    /// Run a CTAP `make_credential` ceremony.
    ///
    /// # Errors
    /// [`SignerError::Ctap`] on no device / cancellation / PIN required
    /// but missing.
    fn make_credential(
        &self,
        rp_id: &str,
        user_name: &str,
        pin: Option<&str>,
    ) -> Result<EnrolledCredential, SignerError>;

    /// Run a CTAP `get_assertion` ceremony. `client_data_json` is the
    /// raw UTF-8 JSON the verifier will reconstruct; the underlying
    /// driver takes it as the `challenge` and internally computes
    /// SHA-256 — matching the hash the authenticator signs under.
    ///
    /// # Errors
    /// [`SignerError::Ctap`] on any hardware / timeout / cancel
    /// failure.
    fn get_assertion(
        &self,
        rp_id: &str,
        credential_id: &[u8],
        client_data_json: &[u8],
        pin: Option<&str>,
    ) -> Result<SignedAssertion, SignerError>;
}

// ----------------------------------------------------------------------------
// Real impl — driven by `ctap-hid-fido2`. Behind the `ctap-hw` feature
// so builds on platforms without hidapi / libudev still link.

#[cfg(feature = "ctap-hw")]
mod real {
    use super::{CtapDevice, EnrolledCredential, SignedAssertion};
    use crate::SignerError;
    use ctap_hid_fido2::fidokey::{GetAssertionArgsBuilder, MakeCredentialArgsBuilder};
    use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};

    /// Production CTAP device backed by `ctap-hid-fido2`.
    #[derive(Debug, Default)]
    pub struct RealCtapDevice;

    impl CtapDevice for RealCtapDevice {
        fn make_credential(
            &self,
            rp_id: &str,
            // Kept on the signature for future use — CTAP uses this on
            // the `user.name` field of the credential descriptor, but
            // the ctap-hid-fido2 builder we use does not expose that
            // field in v3.5.
            _user_name: &str,
            pin: Option<&str>,
        ) -> Result<EnrolledCredential, SignerError> {
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
            let pubkey_sec1 = spki_der_to_sec1_uncompressed(&pubkey_der).ok_or_else(|| {
                SignerError::Ctap(
                    "make_credential did not return a parseable P-256 public key".into(),
                )
            })?;
            let keyid = build_keyid(&credential_id, &pubkey_sec1);

            Ok(EnrolledCredential {
                credential_id,
                public_key_sec1_uncompressed: pubkey_sec1,
                keyid,
            })
        }

        fn get_assertion(
            &self,
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
                // No PIN and no UV explicitly configured — let the
                // authenticator decide. For a credential enrolled
                // without a PIN this works; for a PIN-enrolled
                // credential it surfaces a clear CTAP error.
                builder = builder.without_pin_and_uv();
            }
            let args = builder.build();

            let device = FidoKeyHidFactory::create(&Cfg::init())
                .map_err(|e| SignerError::Ctap(format!("open device: {e}")))?;
            let assertions = device
                .get_assertion_with_args(&args)
                .map_err(|e| SignerError::Ctap(format!("get_assertion: {e}")))?;
            let first = assertions.into_iter().next().ok_or_else(|| {
                SignerError::Ctap("authenticator returned 0 assertions".to_owned())
            })?;

            Ok(SignedAssertion {
                auth_data: first.auth_data,
                signature: first.signature,
                credential_id: first.credential_id,
            })
        }
    }

    /// 32-byte challenge for `make_credential`. Not cryptographically
    /// rigorous; the authenticator signs it once and the verifier
    /// never checks.
    fn make_challenge() -> Vec<u8> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let seed = [
            now.as_secs().to_le_bytes(),
            (now.subsec_nanos() as u64).to_le_bytes(),
        ]
        .concat();
        let mut out = Vec::with_capacity(32);
        for i in 0..32 {
            out.push(seed[i % seed.len()] ^ (i as u8));
        }
        out
    }

    /// Derive the `p256:<hex>` (compressed) keyid from an SEC1 65-byte
    /// uncompressed pubkey.
    fn build_keyid(credential_id: &[u8], pubkey_sec1: &[u8]) -> String {
        if pubkey_sec1.len() == 65 {
            let parity = if pubkey_sec1[64] & 1 == 0 {
                0x02u8
            } else {
                0x03u8
            };
            let mut compressed = Vec::with_capacity(33);
            compressed.push(parity);
            compressed.extend_from_slice(&pubkey_sec1[1..33]);
            format!("p256:{}", super::to_hex(&compressed))
        } else {
            use base64::Engine as _;
            // Defensive fallback for malformed test inputs only. Real
            // enrollment rejects credentials without a parseable public key.
            format!(
                "webauthn:{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(credential_id)
            )
        }
    }

    /// Strip the 26-byte SPKI prefix that wraps a NIST P-256 pubkey
    /// and return the raw SEC1-uncompressed 65-byte body. Returns
    /// `None` if the input does not start with the expected prefix.
    fn spki_der_to_sec1_uncompressed(der: &[u8]) -> Option<Vec<u8>> {
        const SPKI_PREFIX: &[u8] = &[
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        if der.len() < SPKI_PREFIX.len() + 65 || !der.starts_with(SPKI_PREFIX) {
            return None;
        }
        Some(der[SPKI_PREFIX.len()..SPKI_PREFIX.len() + 65].to_vec())
    }
}
#[cfg(feature = "ctap-hw")]
pub use real::RealCtapDevice;

// ----------------------------------------------------------------------------
// Stub when `ctap-hw` is off — the binary still compiles but every
// hardware call returns `SignerError::Ctap("ctap-hw feature disabled")`.

#[cfg(not(feature = "ctap-hw"))]
pub struct RealCtapDevice;

#[cfg(not(feature = "ctap-hw"))]
impl CtapDevice for RealCtapDevice {
    fn make_credential(
        &self,
        _rp_id: &str,
        _user_name: &str,
        _pin: Option<&str>,
    ) -> Result<EnrolledCredential, SignerError> {
        Err(SignerError::Ctap(
            "mkit-sign-ctap built without `ctap-hw` feature — no hardware support".into(),
        ))
    }

    fn get_assertion(
        &self,
        _rp_id: &str,
        _credential_id: &[u8],
        _client_data_json: &[u8],
        _pin: Option<&str>,
    ) -> Result<SignedAssertion, SignerError> {
        Err(SignerError::Ctap(
            "mkit-sign-ctap built without `ctap-hw` feature — no hardware support".into(),
        ))
    }
}

// ----------------------------------------------------------------------------
// Mock — used by integration tests in tests/protocol_shape.rs to drive
// the wire protocol without a real authenticator. Public so tests in a
// sibling crate (or the `tests/` integration tests) can construct one.

/// Scripted CTAP device. Returns the canned [`SignedAssertion`] and
/// [`EnrolledCredential`] supplied at construction. Records the
/// arguments of the most recent call for assertions.
///
/// Public so a sibling integration test (or a downstream consumer
/// extracting this binary into a library) can drive the protocol
/// loop without hardware. The non-test binary build never constructs
/// it, so we suppress the dead-code lint here rather than gating the
/// type on `cfg(test)` — that would prevent re-use.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct MockCtapDevice {
    pub canned_credential: EnrolledCredential,
    pub canned_assertion: SignedAssertion,
}

impl CtapDevice for MockCtapDevice {
    fn make_credential(
        &self,
        _rp_id: &str,
        _user_name: &str,
        _pin: Option<&str>,
    ) -> Result<EnrolledCredential, SignerError> {
        Ok(self.canned_credential.clone())
    }

    fn get_assertion(
        &self,
        _rp_id: &str,
        _credential_id: &[u8],
        _client_data_json: &[u8],
        _pin: Option<&str>,
    ) -> Result<SignedAssertion, SignerError> {
        Ok(self.canned_assertion.clone())
    }
}

/// Hex helper shared between real + mock. Lowercase, no separators.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
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
    fn mock_returns_canned_credential() {
        let mock = MockCtapDevice {
            canned_credential: EnrolledCredential {
                credential_id: b"cred".to_vec(),
                public_key_sec1_uncompressed: vec![0x04; 65],
                keyid: "p256:abc".into(),
            },
            canned_assertion: SignedAssertion {
                auth_data: vec![],
                signature: vec![],
                credential_id: vec![],
            },
        };
        let c = mock.make_credential("rp", "user", None).unwrap();
        assert_eq!(c.credential_id, b"cred");
        assert_eq!(c.keyid, "p256:abc");
    }

    #[test]
    fn to_hex_lowercase() {
        assert_eq!(to_hex(&[0x0a, 0xff, 0x00]), "0aff00");
        assert_eq!(to_hex(&[]), "");
    }
}
