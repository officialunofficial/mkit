//! `WebAuthn` signature-wrapping helper — Protocol v1.1 extension.
//!
//! See `docs/specs/SPEC-EXTERNAL-SIGNER.md` §14 for the normative description.
//!
//! Background: FIDO2/`WebAuthn` roaming authenticators (`YubiKey`,
//! `Nitrokey`, `SoloKey`) do NOT sign arbitrary byte strings. They sign
//! `authenticatorData || SHA256(clientDataJSON)` where the challenge
//! is embedded inside the `clientDataJSON` under `challenge`
//! (base64url-no-pad). To integrate with mkit's DSSE external-signer
//! protocol, the signer places the PAE bytes into
//! `clientDataJSON.challenge` and returns the wrapping material
//! alongside the signature so the verifier can reconstruct the bytes
//! that were actually signed.
//!
//! This module owns the verifier helper. The core `verify_signature`
//! path is unchanged — callers that want `WebAuthn` dispatch call
//! [`verify_webauthn_wrapping`] explicitly, after extracting the
//! wrapping from wherever their transport stashes it (mkit places it
//! inside the in-toto Statement's `predicate` under a reserved
//! `_webauthn_wrapping` key so the DSSE envelope shape is untouched).

#![cfg(feature = "algo-p256")]

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as B64_STD, URL_SAFE_NO_PAD as B64_URL_NOPAD};
use sha2::{Digest, Sha256};

use crate::Error;
use crate::signer_p256::verify_p256;

/// Decoded `WebAuthn` wrapping material. Both fields are the raw
/// bytes (NOT base64) — deserialise from the wire via
/// [`WebAuthnWrapping::from_b64url_fields`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebAuthnWrapping {
    /// Raw `authenticatorData` bytes — `rpIdHash(32) || flags(1) ||
    /// signCount(4) || [attestedCredData] || [extensions]`.
    pub authenticator_data: Vec<u8>,
    /// Raw `clientDataJSON` bytes — a UTF-8 JSON object with
    /// `type`, `challenge`, and `origin` at minimum.
    pub client_data_json: Vec<u8>,
}

impl WebAuthnWrapping {
    /// Decode a pair of base64url-no-pad strings as they appear on the
    /// wire. Either field being malformed base64 surfaces as
    /// [`Error::WebAuthnBadAuthenticatorData`] /
    /// [`Error::WebAuthnBadClientDataJson`].
    ///
    /// # Errors
    /// See above.
    pub fn from_b64url_fields(
        authenticator_data_b64: &str,
        client_data_json_b64: &str,
    ) -> Result<Self, Error> {
        let authenticator_data = B64_URL_NOPAD
            .decode(authenticator_data_b64.as_bytes())
            .map_err(|_| Error::WebAuthnBadAuthenticatorData)?;
        let client_data_json = B64_URL_NOPAD
            .decode(client_data_json_b64.as_bytes())
            .map_err(|_| Error::WebAuthnBadClientDataJson)?;
        Ok(Self {
            authenticator_data,
            client_data_json,
        })
    }

    /// Encode back to wire form — the two base64url-no-pad strings
    /// the spec's §14 JSON shape carries.
    #[must_use]
    pub fn to_b64url_fields(&self) -> (String, String) {
        (
            B64_URL_NOPAD.encode(&self.authenticator_data),
            B64_URL_NOPAD.encode(&self.client_data_json),
        )
    }
}

/// Authenticator-data flag bit: User Present (UP). Set when the
/// authenticator confirmed a physical gesture (touch).
const AUTH_FLAG_UP: u8 = 0x01;
/// Authenticator-data flag bit: User Verified (UV). Set when the
/// authenticator additionally verified the user (PIN / biometric).
const AUTH_FLAG_UV: u8 = 0x04;

/// Ceremony policy for [`verify_webauthn_wrapping_with_policy`].
///
/// Each knob is **independent** by design — strict UV would lock out a
/// UP-only roaming authenticator, and a strict counter would reject the
/// many authenticators that report `signCount == 0` — so they are never
/// coupled. [`WebAuthnPolicy::permissive`] (also the [`Default`]) leaves
/// every knob off, exactly reproducing the pre-policy
/// cryptographic-only behaviour.
///
/// These checks layer on top of (and never replace) the cryptographic
/// wrapping verification: even a fully-permissive policy still requires
/// the challenge to bind to the PAE and the signature to verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebAuthnPolicy {
    /// Expected Relying Party ID. When `Some`, the first 32 bytes of
    /// `authenticatorData` (the rpIdHash) must equal
    /// `SHA256(expected_rp_id)`. When `None`, the RP ID is not checked.
    pub expected_rp_id: Option<String>,
    /// Allowed `origin` values from `clientDataJSON`. When `Some`, the
    /// origin must match one entry exactly. When `None`, any origin is
    /// accepted.
    pub allowed_origins: Option<Vec<String>>,
    /// Require the User Present (UP) flag. Off by default.
    pub require_user_presence: bool,
    /// Require the User Verified (UV) flag. Off by default (would break
    /// UP-only authenticators).
    pub require_user_verification: bool,
    /// Allow `crossOrigin: true` in `clientDataJSON`. Defaults to `true`
    /// (permissive). Set `false` to reject cross-origin ceremonies.
    pub allow_cross_origin: bool,
    /// Previously-observed signature counter. When `Some`, the
    /// assertion's `signCount` must be `>=` this value (rollback is
    /// rejected). `signCount == 0` with `previous_sign_count == Some(0)`
    /// is accepted. When `None`, the counter is not enforced.
    pub previous_sign_count: Option<u32>,
}

impl Default for WebAuthnPolicy {
    /// The [`Default`] is [`WebAuthnPolicy::permissive`] — note this is
    /// NOT the field-wise zero default (`allow_cross_origin` is `true`),
    /// which is why `Default` is hand-written.
    fn default() -> Self {
        Self::permissive()
    }
}

impl WebAuthnPolicy {
    /// The hardware-friendly default: no RP-ID binding, any origin,
    /// UP/UV not required, cross-origin allowed, counter not enforced.
    /// This reproduces the behaviour of [`verify_webauthn_wrapping`]
    /// exactly (cryptographic checks only).
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            expected_rp_id: None,
            allowed_origins: None,
            require_user_presence: false,
            require_user_verification: false,
            allow_cross_origin: true,
            previous_sign_count: None,
        }
    }
}

/// Verify a `WebAuthn`-wrapped P-256 signature against a DSSE PAE,
/// applying [`WebAuthnPolicy`] ceremony checks.
///
/// This is the policy-aware counterpart of [`verify_webauthn_wrapping`]
/// (which delegates here with [`WebAuthnPolicy::permissive`]). The
/// cryptographic steps are identical; the policy adds RP-ID-hash,
/// origin, `crossOrigin`, UP/UV-flag, and counter-rollback checks, each
/// surfacing a distinct typed error.
///
/// Order of operations:
/// 1. Length / `authenticatorData` shape check (>= 37 bytes).
/// 2. Parse `authenticatorData`: rpIdHash(0..32), flags(32),
///    signCount(33..37 big-endian).
/// 3. Policy: rpIdHash == `SHA256(expected_rp_id)` if set.
/// 4. Policy: UP/UV flags if required.
/// 5. Policy: signCount >= `previous_sign_count` if set.
/// 6. Parse `clientDataJSON`; assert `type == "webauthn.get"`.
/// 7. Policy: origin in allow-list if set; crossOrigin allowed.
/// 8. Assert `challenge == base64url_nopad(pae)`.
/// 9. Reconstruct `authenticatorData || SHA256(clientDataJSON)` and
///    delegate to [`verify_p256`].
///
/// Why this shape: a direct signer over `SHA256(pae)` would be
/// incompatible with every `WebAuthn` authenticator on the market —
/// the authenticator firmware is the one thing we cannot change.
/// Moving the wrapping into the transport layer and verifying it on
/// the host preserves mkit's "we control the signed bytes" invariant
/// without forking the DSSE spec.
///
/// NOTE: this helper enforces *ceremony* policy only. Trust-root binding
/// (which public key is authorised to attest) stays in envelope
/// verification — see `docs/specs/SPEC-EXTERNAL-SIGNER.md` §14.
///
/// # Errors
/// * [`Error::WebAuthnBadAuthenticatorData`] — `authenticator_data`
///   is shorter than the 37-byte minimum (rpIdHash + flags + signCount).
/// * [`Error::WebAuthnRpIdMismatch`] — rpIdHash != SHA256(expected RP ID).
/// * [`Error::WebAuthnUserPresenceRequired`] — UP flag clear but required.
/// * [`Error::WebAuthnUserVerificationRequired`] — UV flag clear but required.
/// * [`Error::WebAuthnCounterRollback`] — signCount < previous counter.
/// * [`Error::WebAuthnBadClientDataJson`] — `client_data_json` is not a
///   JSON object with string `type` / `challenge`, or `type` is not
///   `"webauthn.get"`. The `create`-ceremony type is explicitly refused.
/// * [`Error::WebAuthnOriginNotAllowed`] — origin not in allow-list.
/// * [`Error::WebAuthnCrossOriginNotAllowed`] — crossOrigin=true but disallowed.
/// * [`Error::WebAuthnChallengeMismatch`] — `challenge` decoded to bytes
///   not equal to the PAE bytes.
/// * [`Error::WebAuthnSignatureFailed`] — crypto verdict says no.
pub fn verify_webauthn_wrapping_with_policy(
    pae: &[u8],
    wrapping: &WebAuthnWrapping,
    pubkey_sec1: &[u8],
    sig_compact: &[u8],
    policy: &WebAuthnPolicy,
) -> Result<(), Error> {
    // Minimum authenticatorData is 37 bytes: 32 (rpIdHash) + 1 (flags)
    // + 4 (signCount). Anything shorter cannot be a well-formed
    // assertion and pre-empts the crypto step with a clearer error.
    // This bound also guarantees the fixed-offset slices below are
    // always in range.
    if wrapping.authenticator_data.len() < 37 {
        return Err(Error::WebAuthnBadAuthenticatorData);
    }
    let auth = &wrapping.authenticator_data;
    let rp_id_hash = &auth[0..32];
    let flags = auth[32];
    // signCount is a 4-byte big-endian unsigned counter at offset 33.
    let sign_count = u32::from_be_bytes([auth[33], auth[34], auth[35], auth[36]]);

    // -- Policy: RP-ID hash binding ----------------------------------
    if let Some(rp_id) = policy.expected_rp_id.as_deref() {
        let expected = Sha256::digest(rp_id.as_bytes());
        // Constant-time-ish equality is not required here: rpIdHash is
        // not secret, and a timing oracle on a 32-byte public hash
        // leaks nothing useful.
        if rp_id_hash != expected.as_slice() {
            return Err(Error::WebAuthnRpIdMismatch);
        }
    }

    // -- Policy: UP / UV flags (independent knobs) -------------------
    if policy.require_user_presence && (flags & AUTH_FLAG_UP) == 0 {
        return Err(Error::WebAuthnUserPresenceRequired);
    }
    if policy.require_user_verification && (flags & AUTH_FLAG_UV) == 0 {
        return Err(Error::WebAuthnUserVerificationRequired);
    }

    // -- Policy: counter rollback ------------------------------------
    if let Some(prev) = policy.previous_sign_count
        && sign_count < prev
    {
        // signCount == 0 with prev == 0 passes (0 >= 0); only a strict
        // decrease is rejected. Many authenticators always report 0.
        return Err(Error::WebAuthnCounterRollback);
    }

    // Parse clientDataJSON. We intentionally use serde_json here
    // because this is on the VERIFY path — same justification as the
    // envelope decoder: we parse third-party input, we never emit it.
    let client_data: serde_json::Value = serde_json::from_slice(&wrapping.client_data_json)
        .map_err(|_| Error::WebAuthnBadClientDataJson)?;
    let obj = client_data
        .as_object()
        .ok_or(Error::WebAuthnBadClientDataJson)?;

    let ty = obj
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or(Error::WebAuthnBadClientDataJson)?;
    if ty != "webauthn.get" {
        return Err(Error::WebAuthnBadClientDataJson);
    }

    // -- Policy: origin allow-list -----------------------------------
    if let Some(allowed) = policy.allowed_origins.as_deref() {
        let origin = obj
            .get("origin")
            .and_then(serde_json::Value::as_str)
            .ok_or(Error::WebAuthnOriginNotAllowed)?;
        if !allowed.iter().any(|o| o == origin) {
            return Err(Error::WebAuthnOriginNotAllowed);
        }
    }

    // -- Policy: crossOrigin -----------------------------------------
    if !policy.allow_cross_origin {
        // Absent crossOrigin is treated as false per the WebAuthn spec
        // default. Only an explicit `true` is rejected.
        let cross = obj
            .get("crossOrigin")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        if cross {
            return Err(Error::WebAuthnCrossOriginNotAllowed);
        }
    }

    let challenge_str = obj
        .get("challenge")
        .and_then(serde_json::Value::as_str)
        .ok_or(Error::WebAuthnBadClientDataJson)?;
    // WebAuthn spec pins the encoding to base64url-no-pad. Accept only
    // that; padded or standard-base64 challenges are a red flag that
    // either the signer speaks a different profile or an attacker
    // transcoded something.
    let challenge_bytes = B64_URL_NOPAD
        .decode(challenge_str.as_bytes())
        .map_err(|_| Error::WebAuthnChallengeMismatch)?;
    if challenge_bytes != pae {
        return Err(Error::WebAuthnChallengeMismatch);
    }

    // Reconstruct the WebAuthn signed bytes. The authenticator signed
    // `authenticatorData || SHA256(clientDataJSON)` and the P-256
    // signer inside the authenticator hashed THAT with SHA-256 before
    // applying ECDSA. Our `verify_p256` takes the pre-hash message
    // and hashes internally, so we pass the concatenation directly.
    let mut to_verify = Vec::with_capacity(wrapping.authenticator_data.len() + 32);
    to_verify.extend_from_slice(&wrapping.authenticator_data);
    let cd_hash = Sha256::digest(&wrapping.client_data_json);
    to_verify.extend_from_slice(&cd_hash);

    verify_p256(pubkey_sec1, &to_verify, sig_compact).map_err(|_| Error::WebAuthnSignatureFailed)
}

/// Verify a `WebAuthn`-wrapped P-256 signature against a DSSE PAE,
/// performing cryptographic-only checks (no ceremony policy).
///
/// This is a thin compatibility wrapper that delegates to
/// [`verify_webauthn_wrapping_with_policy`] with
/// [`WebAuthnPolicy::permissive`]. It checks the `type`, the challenge
/// binding, the `authenticatorData` shape, and the signature — but does
/// NOT check RP-ID, origin, `crossOrigin`, UP/UV flags, or the counter.
/// Callers that need those guarantees must use the policy-aware variant.
///
/// # Errors
/// See [`verify_webauthn_wrapping_with_policy`]; only the
/// non-policy variants can be returned here:
/// [`Error::WebAuthnBadAuthenticatorData`],
/// [`Error::WebAuthnBadClientDataJson`],
/// [`Error::WebAuthnChallengeMismatch`],
/// [`Error::WebAuthnSignatureFailed`].
pub fn verify_webauthn_wrapping(
    pae: &[u8],
    wrapping: &WebAuthnWrapping,
    pubkey_sec1: &[u8],
    sig_compact: &[u8],
) -> Result<(), Error> {
    verify_webauthn_wrapping_with_policy(
        pae,
        wrapping,
        pubkey_sec1,
        sig_compact,
        &WebAuthnPolicy::permissive(),
    )
}

/// Convenience: build a `clientDataJSON` body for a given PAE + origin.
/// This is shipped as part of the public API because `contrib/signers`
/// want to build identical bodies on the signer side — and mirroring
/// the construction keeps the verifier and signer on the same page
/// byte-for-byte (the JSON key ordering matters: `type`, `challenge`,
/// `origin`, `crossOrigin`).
///
/// Not JCS-canonical by design — `WebAuthn` authenticators don't
/// canonicalise. The exact bytes produced here are what the signer
/// feeds to the authenticator, and what the verifier re-hashes.
#[must_use]
pub fn build_client_data_json(pae: &[u8], rp_origin: &str, cross_origin: bool) -> Vec<u8> {
    let challenge = B64_URL_NOPAD.encode(pae);
    // Hand-assembled so the field order is fixed and stable. The order
    // chosen here matches what the Chromium / Firefox authenticators
    // emit on macOS, which keeps the attestation body indistinguishable
    // from a real browser-originated one.
    let body = format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"{}\",\"crossOrigin\":{}}}",
        challenge,
        json_escape(rp_origin),
        cross_origin,
    );
    body.into_bytes()
}

/// Decode a standard-base64 (padded) PAE — matches the v1 request
/// shape from `SPEC-EXTERNAL-SIGNER` §3 — for signer implementations
/// that want to consume the spec's `pae_base64` field and re-emit it
/// as the `challenge` in their `clientDataJSON`.
///
/// # Errors
/// Passes through the base64 crate's decode error as
/// [`Error::WebAuthnBadClientDataJson`]. This isn't strictly a
/// client-data-JSON failure, but the signer would only call this
/// while preparing the body and the caller probably wants a single
/// error type to report back.
pub fn decode_pae_b64_standard(pae_b64: &str) -> Result<Vec<u8>, Error> {
    B64_STD
        .decode(pae_b64.as_bytes())
        .map_err(|_| Error::WebAuthnBadClientDataJson)
}

// -- internals ------------------------------------------------------

/// Minimal JSON string escape: handles the six mandatory escapes plus
/// control characters. Good enough for `origin` values (hostnames,
/// which do not contain control bytes); we explicitly do NOT support
/// arbitrary Unicode-escape emission because the inputs we take are
/// tightly scoped.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer_p256::P256Signer;
    use p256::ecdsa::{Signature as P256Sig, SigningKey, signature::Signer as _};

    const TEST_SECRET: [u8; 32] = [7u8; 32];

    /// Build an authenticator-data prefix: `rpIdHash(32) || flags(1) ||
    /// signCount(4)`. `flags` = 0x05 (UP + UV). `signCount` = 0.
    fn mock_auth_data(rp_id: &str) -> Vec<u8> {
        let rp_id_hash = Sha256::digest(rp_id.as_bytes());
        let mut out = Vec::with_capacity(37);
        out.extend_from_slice(&rp_id_hash);
        out.push(0x05);
        out.extend_from_slice(&[0u8; 4]);
        out
    }

    /// End-to-end mock of what a `WebAuthn` authenticator does, using
    /// our in-process P-256 signer as the "authenticator". Returns
    /// `(wrapping, sig)` so tests can poke individual fields without
    /// re-deriving everything.
    fn sign_webauthn(
        pae: &[u8],
        rp_id: &str,
        origin: &str,
        secret: [u8; 32],
    ) -> (WebAuthnWrapping, Vec<u8>) {
        let auth_data = mock_auth_data(rp_id);
        let cdj = build_client_data_json(pae, origin, false);

        // WebAuthn signs authenticatorData || SHA256(clientDataJSON).
        let mut to_sign = Vec::with_capacity(auth_data.len() + 32);
        to_sign.extend_from_slice(&auth_data);
        to_sign.extend_from_slice(&Sha256::digest(&cdj));

        let sk = SigningKey::from_bytes(&secret.into()).unwrap();
        let sig: P256Sig = sk.sign(&to_sign);
        let sig = sig.normalize_s();
        (
            WebAuthnWrapping {
                authenticator_data: auth_data,
                client_data_json: cdj,
            },
            sig.to_bytes().to_vec(),
        )
    }

    #[test]
    fn valid_wrapping_verifies() {
        let pae = b"DSSEv1 28 application/vnd.in-toto+json 2 {}";
        let (wrap, sig) = sign_webauthn(pae, "mkit.local", "https://mkit.local", TEST_SECRET);
        let signer = P256Signer::new(TEST_SECRET).unwrap();
        verify_webauthn_wrapping(pae, &wrap, &signer.public_key_sec1(), &sig)
            .expect("happy path verifies");
    }

    #[test]
    fn challenge_mismatch_is_rejected() {
        let pae = b"the real pae";
        let (mut wrap, sig) = sign_webauthn(pae, "mkit.local", "https://mkit.local", TEST_SECRET);
        let signer = P256Signer::new(TEST_SECRET).unwrap();

        // Swap the challenge to something else — matching the rest of
        // the body so only the challenge binding fails.
        wrap.client_data_json =
            build_client_data_json(b"different pae", "https://mkit.local", false);

        let err = verify_webauthn_wrapping(pae, &wrap, &signer.public_key_sec1(), &sig)
            .expect_err("must reject challenge mismatch");
        assert!(
            matches!(err, Error::WebAuthnChallengeMismatch),
            "got {err:?}"
        );
    }

    #[test]
    fn bad_client_data_json_is_rejected() {
        let pae = b"pae";
        let (mut wrap, sig) = sign_webauthn(pae, "mkit.local", "https://mkit.local", TEST_SECRET);
        let signer = P256Signer::new(TEST_SECRET).unwrap();

        wrap.client_data_json = b"not json at all".to_vec();

        let err = verify_webauthn_wrapping(pae, &wrap, &signer.public_key_sec1(), &sig)
            .expect_err("must reject non-JSON clientDataJSON");
        assert!(
            matches!(err, Error::WebAuthnBadClientDataJson),
            "got {err:?}"
        );
    }

    #[test]
    fn wrong_type_field_is_rejected() {
        let pae = b"pae";
        let signer = P256Signer::new(TEST_SECRET).unwrap();

        // Build a clientDataJSON with type=webauthn.create — legitimate
        // for enrollment but not for assertions, and the helper
        // intentionally refuses it.
        let challenge = B64_URL_NOPAD.encode(pae);
        let cdj = format!(
            "{{\"type\":\"webauthn.create\",\"challenge\":\"{challenge}\",\"origin\":\"https://mkit.local\",\"crossOrigin\":false}}"
        );
        let auth_data = mock_auth_data("mkit.local");

        let mut to_sign = Vec::new();
        to_sign.extend_from_slice(&auth_data);
        to_sign.extend_from_slice(&Sha256::digest(cdj.as_bytes()));

        let sk = SigningKey::from_bytes(&TEST_SECRET.into()).unwrap();
        let sig: P256Sig = sk.sign(&to_sign);
        let sig = sig.normalize_s().to_bytes().to_vec();

        let wrap = WebAuthnWrapping {
            authenticator_data: auth_data,
            client_data_json: cdj.into_bytes(),
        };
        let err = verify_webauthn_wrapping(pae, &wrap, &signer.public_key_sec1(), &sig)
            .expect_err("must reject webauthn.create type");
        assert!(
            matches!(err, Error::WebAuthnBadClientDataJson),
            "got {err:?}"
        );
    }

    #[test]
    fn wrong_pubkey_yields_signature_failed() {
        let pae = b"pae";
        let (wrap, sig) = sign_webauthn(pae, "mkit.local", "https://mkit.local", TEST_SECRET);
        let other = P256Signer::new([0x42; 32]).unwrap();
        let err = verify_webauthn_wrapping(pae, &wrap, &other.public_key_sec1(), &sig)
            .expect_err("wrong key must fail");
        assert!(matches!(err, Error::WebAuthnSignatureFailed), "got {err:?}");
    }

    #[test]
    fn truncated_authenticator_data_is_rejected() {
        let pae = b"pae";
        let (mut wrap, sig) = sign_webauthn(pae, "mkit.local", "https://mkit.local", TEST_SECRET);
        let signer = P256Signer::new(TEST_SECRET).unwrap();
        wrap.authenticator_data.truncate(20);
        let err = verify_webauthn_wrapping(pae, &wrap, &signer.public_key_sec1(), &sig)
            .expect_err("short auth_data must be rejected");
        assert!(
            matches!(err, Error::WebAuthnBadAuthenticatorData),
            "got {err:?}"
        );
    }

    #[test]
    fn b64url_field_roundtrip() {
        let w = WebAuthnWrapping {
            authenticator_data: vec![1, 2, 3, 4, 5],
            client_data_json: vec![b'{', b'}'],
        };
        let (a_b64, c_b64) = w.to_b64url_fields();
        let decoded = WebAuthnWrapping::from_b64url_fields(&a_b64, &c_b64).unwrap();
        assert_eq!(decoded, w);
    }

    #[test]
    fn b64url_field_rejects_bad_base64() {
        // `!` is not in the base64url alphabet, so decode fails. Each
        // arm exercises one of the two fields so we cover both typed
        // error paths.
        let err = WebAuthnWrapping::from_b64url_fields("!not base64!", "abcd").unwrap_err();
        assert!(
            matches!(err, Error::WebAuthnBadAuthenticatorData),
            "got {err:?}"
        );
        let err = WebAuthnWrapping::from_b64url_fields("abcd", "!not base64!").unwrap_err();
        assert!(
            matches!(err, Error::WebAuthnBadClientDataJson),
            "got {err:?}"
        );
    }

    /// Like [`mock_auth_data`] but with caller-chosen flags and
    /// signCount, so policy tests can flip individual bits.
    fn mock_auth_data_full(rp_id: &str, flags: u8, sign_count: u32) -> Vec<u8> {
        let rp_id_hash = Sha256::digest(rp_id.as_bytes());
        let mut out = Vec::with_capacity(37);
        out.extend_from_slice(&rp_id_hash);
        out.push(flags);
        out.extend_from_slice(&sign_count.to_be_bytes());
        out
    }

    /// Sign with explicit flags / signCount / crossOrigin so each policy
    /// knob can be exercised in isolation.
    fn sign_webauthn_full(
        pae: &[u8],
        rp_id: &str,
        origin: &str,
        flags: u8,
        sign_count: u32,
        cross_origin: bool,
        secret: [u8; 32],
    ) -> (WebAuthnWrapping, Vec<u8>) {
        let auth_data = mock_auth_data_full(rp_id, flags, sign_count);
        let cdj = build_client_data_json(pae, origin, cross_origin);
        let mut to_sign = Vec::with_capacity(auth_data.len() + 32);
        to_sign.extend_from_slice(&auth_data);
        to_sign.extend_from_slice(&Sha256::digest(&cdj));
        let sk = SigningKey::from_bytes(&secret.into()).unwrap();
        let sig: P256Sig = sk.sign(&to_sign);
        let sig = sig.normalize_s();
        (
            WebAuthnWrapping {
                authenticator_data: auth_data,
                client_data_json: cdj,
            },
            sig.to_bytes().to_vec(),
        )
    }

    #[test]
    fn permissive_policy_allows_up_only_and_zero_counter() {
        // flags = UP only (0x01), signCount = 0 — the hardware-friendly
        // baseline the permissive default must accept.
        let pae = b"pae";
        let (wrap, sig) = sign_webauthn_full(
            pae,
            "mkit.local",
            "https://mkit.local",
            AUTH_FLAG_UP,
            0,
            false,
            TEST_SECRET,
        );
        let signer = P256Signer::new(TEST_SECRET).unwrap();
        verify_webauthn_wrapping_with_policy(
            pae,
            &wrap,
            &signer.public_key_sec1(),
            &sig,
            &WebAuthnPolicy::permissive(),
        )
        .expect("permissive policy accepts UP-only, signCount=0");
    }

    #[test]
    fn policy_rejects_wrong_rp_id() {
        let pae = b"pae";
        let (wrap, sig) = sign_webauthn(pae, "mkit.local", "https://mkit.local", TEST_SECRET);
        let signer = P256Signer::new(TEST_SECRET).unwrap();
        let policy = WebAuthnPolicy {
            expected_rp_id: Some("evil.example".to_owned()),
            ..WebAuthnPolicy::permissive()
        };
        let err = verify_webauthn_wrapping_with_policy(
            pae,
            &wrap,
            &signer.public_key_sec1(),
            &sig,
            &policy,
        )
        .expect_err("wrong RP ID must be rejected");
        assert!(matches!(err, Error::WebAuthnRpIdMismatch), "got {err:?}");
    }

    #[test]
    fn policy_accepts_matching_rp_id() {
        let pae = b"pae";
        let (wrap, sig) = sign_webauthn(pae, "mkit.local", "https://mkit.local", TEST_SECRET);
        let signer = P256Signer::new(TEST_SECRET).unwrap();
        let policy = WebAuthnPolicy {
            expected_rp_id: Some("mkit.local".to_owned()),
            ..WebAuthnPolicy::permissive()
        };
        verify_webauthn_wrapping_with_policy(pae, &wrap, &signer.public_key_sec1(), &sig, &policy)
            .expect("matching RP ID verifies");
    }

    #[test]
    fn policy_rejects_origin_not_in_allowlist() {
        let pae = b"pae";
        let (wrap, sig) = sign_webauthn(pae, "mkit.local", "https://mkit.local", TEST_SECRET);
        let signer = P256Signer::new(TEST_SECRET).unwrap();
        let policy = WebAuthnPolicy {
            allowed_origins: Some(vec!["https://other.example".to_owned()]),
            ..WebAuthnPolicy::permissive()
        };
        let err = verify_webauthn_wrapping_with_policy(
            pae,
            &wrap,
            &signer.public_key_sec1(),
            &sig,
            &policy,
        )
        .expect_err("origin not in allow-list must be rejected");
        assert!(
            matches!(err, Error::WebAuthnOriginNotAllowed),
            "got {err:?}"
        );
    }

    #[test]
    fn policy_accepts_allowed_origin() {
        let pae = b"pae";
        let (wrap, sig) = sign_webauthn(pae, "mkit.local", "https://mkit.local", TEST_SECRET);
        let signer = P256Signer::new(TEST_SECRET).unwrap();
        let policy = WebAuthnPolicy {
            allowed_origins: Some(vec![
                "https://mkit.local".to_owned(),
                "https://other.example".to_owned(),
            ]),
            ..WebAuthnPolicy::permissive()
        };
        verify_webauthn_wrapping_with_policy(pae, &wrap, &signer.public_key_sec1(), &sig, &policy)
            .expect("allowed origin verifies");
    }

    #[test]
    fn policy_rejects_missing_user_presence() {
        // flags = UV only (0x04), no UP bit — require_user_presence must
        // reject it.
        let pae = b"pae";
        let (wrap, sig) = sign_webauthn_full(
            pae,
            "mkit.local",
            "https://mkit.local",
            AUTH_FLAG_UV,
            0,
            false,
            TEST_SECRET,
        );
        let signer = P256Signer::new(TEST_SECRET).unwrap();
        let policy = WebAuthnPolicy {
            require_user_presence: true,
            ..WebAuthnPolicy::permissive()
        };
        let err = verify_webauthn_wrapping_with_policy(
            pae,
            &wrap,
            &signer.public_key_sec1(),
            &sig,
            &policy,
        )
        .expect_err("missing UP must be rejected");
        assert!(
            matches!(err, Error::WebAuthnUserPresenceRequired),
            "got {err:?}"
        );
    }

    #[test]
    fn policy_rejects_missing_user_verification() {
        // flags = UP only (0x01), no UV bit — require_user_verification
        // must reject it. This is the knob that, if defaulted on, would
        // break UP-only authenticators — hence it stays independent.
        let pae = b"pae";
        let (wrap, sig) = sign_webauthn_full(
            pae,
            "mkit.local",
            "https://mkit.local",
            AUTH_FLAG_UP,
            0,
            false,
            TEST_SECRET,
        );
        let signer = P256Signer::new(TEST_SECRET).unwrap();
        let policy = WebAuthnPolicy {
            require_user_verification: true,
            ..WebAuthnPolicy::permissive()
        };
        let err = verify_webauthn_wrapping_with_policy(
            pae,
            &wrap,
            &signer.public_key_sec1(),
            &sig,
            &policy,
        )
        .expect_err("missing UV must be rejected");
        assert!(
            matches!(err, Error::WebAuthnUserVerificationRequired),
            "got {err:?}"
        );
    }

    #[test]
    fn policy_rejects_cross_origin_when_disallowed() {
        let pae = b"pae";
        let (wrap, sig) = sign_webauthn_full(
            pae,
            "mkit.local",
            "https://mkit.local",
            AUTH_FLAG_UP,
            0,
            true, // crossOrigin: true
            TEST_SECRET,
        );
        let signer = P256Signer::new(TEST_SECRET).unwrap();
        let policy = WebAuthnPolicy {
            allow_cross_origin: false,
            ..WebAuthnPolicy::permissive()
        };
        let err = verify_webauthn_wrapping_with_policy(
            pae,
            &wrap,
            &signer.public_key_sec1(),
            &sig,
            &policy,
        )
        .expect_err("crossOrigin=true must be rejected when disallowed");
        assert!(
            matches!(err, Error::WebAuthnCrossOriginNotAllowed),
            "got {err:?}"
        );
    }

    #[test]
    fn policy_rejects_counter_rollback() {
        // signCount = 3 but policy has seen 5 — a decrease signals a
        // possibly-cloned authenticator.
        let pae = b"pae";
        let (wrap, sig) = sign_webauthn_full(
            pae,
            "mkit.local",
            "https://mkit.local",
            AUTH_FLAG_UP,
            3,
            false,
            TEST_SECRET,
        );
        let signer = P256Signer::new(TEST_SECRET).unwrap();
        let policy = WebAuthnPolicy {
            previous_sign_count: Some(5),
            ..WebAuthnPolicy::permissive()
        };
        let err = verify_webauthn_wrapping_with_policy(
            pae,
            &wrap,
            &signer.public_key_sec1(),
            &sig,
            &policy,
        )
        .expect_err("counter rollback must be rejected");
        assert!(matches!(err, Error::WebAuthnCounterRollback), "got {err:?}");
    }

    #[test]
    fn policy_allows_counter_advance_and_zero_equal() {
        let signer = P256Signer::new(TEST_SECRET).unwrap();
        let pae = b"pae";

        // signCount 7 >= previously-seen 5: accepted.
        let (wrap, sig) = sign_webauthn_full(
            pae,
            "mkit.local",
            "https://mkit.local",
            AUTH_FLAG_UP,
            7,
            false,
            TEST_SECRET,
        );
        let policy = WebAuthnPolicy {
            previous_sign_count: Some(5),
            ..WebAuthnPolicy::permissive()
        };
        verify_webauthn_wrapping_with_policy(pae, &wrap, &signer.public_key_sec1(), &sig, &policy)
            .expect("counter advance verifies");

        // signCount 0 with previously-seen 0: accepted (0 >= 0).
        let (wrap0, sig0) = sign_webauthn_full(
            pae,
            "mkit.local",
            "https://mkit.local",
            AUTH_FLAG_UP,
            0,
            false,
            TEST_SECRET,
        );
        let policy0 = WebAuthnPolicy {
            previous_sign_count: Some(0),
            ..WebAuthnPolicy::permissive()
        };
        verify_webauthn_wrapping_with_policy(
            pae,
            &wrap0,
            &signer.public_key_sec1(),
            &sig0,
            &policy0,
        )
        .expect("signCount 0 with prev 0 verifies");
    }

    #[test]
    fn bare_helper_delegates_permissively() {
        // The bare helper must behave exactly like the permissive
        // policy: UP-only / signCount=0 / cross-origin all pass.
        let pae = b"pae";
        let (wrap, sig) = sign_webauthn_full(
            pae,
            "mkit.local",
            "https://anything.example",
            AUTH_FLAG_UP,
            0,
            true,
            TEST_SECRET,
        );
        let signer = P256Signer::new(TEST_SECRET).unwrap();
        verify_webauthn_wrapping(pae, &wrap, &signer.public_key_sec1(), &sig)
            .expect("bare helper is permissive");
    }

    #[test]
    fn build_client_data_json_contains_challenge() {
        let pae = b"hello world";
        let body = build_client_data_json(pae, "https://mkit.local", false);
        let s = std::str::from_utf8(&body).unwrap();
        let want_challenge = B64_URL_NOPAD.encode(pae);
        assert!(s.contains(&format!("\"challenge\":\"{want_challenge}\"")));
        assert!(s.contains("\"type\":\"webauthn.get\""));
        assert!(s.contains("\"origin\":\"https://mkit.local\""));
    }
}
