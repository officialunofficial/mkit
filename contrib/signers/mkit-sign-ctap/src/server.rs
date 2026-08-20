// `clippy::ref_option` flags `&Option<T>` arguments. Wire-frame
// fields are `Option<T>` (Edition 2023 explicit presence).
#![allow(clippy::ref_option)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::too_many_lines)]

//! Length-prefixed mkit-rpc signer protocol loop for the CTAP signer.
//!
//! Generic over a [`CtapDevice`] so unit tests can drive the protocol
//! with a [`MockCtapDevice`](crate::ctap::MockCtapDevice) and assert
//! on wire bytes without a real authenticator. The production binary
//! constructs a [`RealCtapDevice`](crate::ctap::RealCtapDevice).

use std::io::{Read, Write};

use base64::Engine as _;
use mkit_attest::build_client_data_json;
use mkit_rpc::mkit::rpc::v1::signer::{
    Capabilities, HelloResponse, PinPrompt, SignResponse, SignerFrame, WebAuthnData, signer_frame,
};
use mkit_rpc::mkit::rpc::v1::{Algorithm as RpcAlgorithm, ErrorCode, KeyForm, ProtocolVersion};
use mkit_rpc::{FrameError, read_frame, signer_error_frame, write_frame};

use crate::ctap::CtapDevice;
use crate::{SignerError, cred_store, proto};

/// Optional argv-supplied defaults that shape sign requests when the
/// caller doesn't put values in the SignRequest body itself.
#[derive(Debug, Default, Clone)]
pub struct SignDefaults {
    pub credential_id_b64url: Option<String>,
    pub rp_id: Option<String>,
    pub pin: Option<String>,
    pub origin: Option<String>,
}

/// Drive the protocol loop until stdin closes or a fatal error.
pub fn serve<R, W, D>(
    r: &mut R,
    w: &mut W,
    device: &D,
    defaults: &SignDefaults,
) -> Result<(), SignerError>
where
    R: Read,
    W: Write,
    D: CtapDevice,
{
    loop {
        let req: SignerFrame = match read_frame(r) {
            Ok(f) => f,
            Err(FrameError::LengthTruncated) => return Ok(()),
            Err(FrameError::LengthTooLarge(n)) => {
                let _ = write_error(
                    w,
                    ErrorCode::InvalidRequest,
                    format!("frame length {n} exceeds 1 MiB cap"),
                );
                return Err(SignerError::Io("oversize frame".into()));
            }
            Err(FrameError::BodyTruncated { expected, .. }) => {
                let _ = write_error(
                    w,
                    ErrorCode::InvalidRequest,
                    format!("frame body truncated (expected {expected} bytes)"),
                );
                return Err(SignerError::Io("truncated frame".into()));
            }
            Err(FrameError::DecodeFailed) => {
                let _ = write_error(
                    w,
                    ErrorCode::InvalidRequest,
                    "frame failed to decode as SignerFrame".to_owned(),
                );
                return Err(SignerError::Io("decode failure".into()));
            }
            Err(FrameError::Io(e)) => return Err(SignerError::Io(format!("read frame: {e}"))),
        };

        match req.body {
            Some(signer_frame::Body::Hello(_)) => {
                let resp = SignerFrame {
                    body: Some(signer_frame::Body::HelloResponse(Box::new(HelloResponse {
                        protocol: Some(ProtocolVersion::ProtocolVersion1.into()),
                        signer_id: Some(format!("mkit-sign-ctap/{}", env!("CARGO_PKG_VERSION"))),
                        capabilities: buffa::MessageField::some(Capabilities {
                            // The reference CTAP signer currently enrolls and
                            // verifies P-256 credentials only.
                            algorithms: vec![RpcAlgorithm::P256.into()],
                            key_forms: vec![KeyForm::OpaqueHandle.into()],
                            supports_pin: Some(true),
                            supports_certificate_chain: Some(false),
                            max_payload_bytes: Some(0),
                            requires_user_presence: Some(true),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }))),
                    ..Default::default()
                };
                write_frame(w, &resp).map_err(|e| SignerError::Io(format!("write hello: {e}")))?;
            }

            Some(signer_frame::Body::SignRequest(req_box)) => {
                let resp = handle_sign(r, w, &req_box, device, defaults)?;
                write_frame(w, &resp).map_err(|e| SignerError::Io(format!("write sign: {e}")))?;
            }

            // `handle_sign` above solicits any PinResponse it needs
            // itself, via a direct read on `r` mid-request (see
            // `request_pin_in_band`) — so a PinResponse reaching this
            // top-level dispatch is always out of turn.
            Some(signer_frame::Body::PinResponse(_)) => {
                write_error(
                    w,
                    ErrorCode::InvalidRequest,
                    "unexpected PinResponse outside an active PIN round trip".to_owned(),
                )?;
            }

            Some(_) => {
                write_error(
                    w,
                    ErrorCode::InvalidRequest,
                    "unexpected frame body".to_owned(),
                )?;
            }
            None => {
                write_error(w, ErrorCode::InvalidRequest, "empty frame body".to_owned())?;
            }
        }
    }
}

fn handle_sign<R: Read, W: Write, D: CtapDevice>(
    r: &mut R,
    w: &mut W,
    req: &mkit_rpc::mkit::rpc::v1::signer::SignRequest,
    device: &D,
    defaults: &SignDefaults,
) -> Result<SignerFrame, SignerError> {
    // The reference CTAP signer only supports P-256 credentials. Reject
    // other WebAuthn algorithms until their public-key/signature formats
    // are implemented end-to-end.
    if !req.algorithm.is_some_and(|a| a == RpcAlgorithm::P256) {
        return Ok(signer_error_frame(
            ErrorCode::UnsupportedAlgorithm,
            "mkit-sign-ctap only signs ALGORITHM_P256".to_owned(),
        ));
    }

    // CTAP signers require an opaque credential_id handle. Current mkit
    // releases send RAW_BYTES with an empty key_ref for argv-configured
    // external signers, so tolerate that legacy host form only when the
    // credential handle comes from --credential-id.
    let key_form = req.key_form.unwrap_or_default();
    let has_key_ref = req
        .key_ref
        .as_ref()
        .is_some_and(|key_ref| !key_ref.is_empty());
    let has_default_credential = defaults
        .credential_id_b64url
        .as_deref()
        .is_some_and(|credential_id| !credential_id.is_empty());
    if !ctap_key_form_allowed(key_form, has_key_ref, has_default_credential) {
        return Ok(signer_error_frame(
            ErrorCode::UnsupportedKeyForm,
            "mkit-sign-ctap only supports KEY_FORM_OPAQUE_HANDLE (the credential_id)".to_owned(),
        ));
    }

    // Resolve credential_id from key_ref (preferred) or argv default.
    let credential_id = req.key_ref.clone().filter(|b| !b.is_empty()).or_else(|| {
        defaults.credential_id_b64url.as_deref().and_then(|s| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(s)
                .ok()
        })
    });
    let credential_id = match credential_id {
        Some(c) => c,
        None => {
            return Ok(signer_error_frame(
                ErrorCode::InvalidRequest,
                "no credential — pass --credential-id on argv or set SignRequest.key_ref"
                    .to_owned(),
            ));
        }
    };

    // Resolve credential metadata from the local store so SignResponse can
    // include the public key that mkit validates before accepting a signature.
    let credential_id_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&credential_id);
    let store_path = match cred_store::default_path() {
        Ok(p) => p,
        Err(e) => return Ok(signer_error_frame(ErrorCode::Internal, e.to_string())),
    };
    let store = cred_store::Store::load(&store_path).unwrap_or_default();
    handle_sign_with_store(
        r,
        w,
        req,
        device,
        defaults,
        &store,
        &credential_id,
        &credential_id_b64,
    )
}

fn ctap_key_form_allowed(
    key_form: buffa::EnumValue<KeyForm>,
    has_key_ref: bool,
    has_default_credential: bool,
) -> bool {
    key_form == KeyForm::Unspecified
        || key_form == KeyForm::OpaqueHandle
        || (key_form == KeyForm::RawBytes && !has_key_ref && has_default_credential)
}

fn handle_sign_with_store<R: Read, W: Write, D: CtapDevice>(
    r: &mut R,
    w: &mut W,
    req: &mkit_rpc::mkit::rpc::v1::signer::SignRequest,
    device: &D,
    defaults: &SignDefaults,
    store: &cred_store::Store,
    credential_id: &[u8],
    credential_id_b64: &str,
) -> Result<SignerFrame, SignerError> {
    if !req.algorithm.is_some_and(|a| a == RpcAlgorithm::P256) {
        return Ok(signer_error_frame(
            ErrorCode::UnsupportedAlgorithm,
            "mkit-sign-ctap only signs ALGORITHM_P256".to_owned(),
        ));
    }

    let Some(record) = store.find_by_credential_id(credential_id_b64) else {
        return Ok(signer_error_frame(
            ErrorCode::InvalidRequest,
            format!(
                "credential metadata for {credential_id_b64} is missing; run `mkit-sign-ctap enroll` so the signer can return a public_key"
            ),
        ));
    };
    let public_key = match hex_decode(&record.public_key_sec1_uncompressed_hex) {
        Ok(key) if key.len() == 65 => key,
        _ => {
            return Ok(signer_error_frame(
                ErrorCode::Internal,
                format!("stored public key for credential {credential_id_b64} is invalid"),
            ));
        }
    };

    let rp_id = defaults
        .rp_id
        .clone()
        .unwrap_or_else(|| record.rp_id.clone());
    let origin = defaults
        .origin
        .clone()
        .unwrap_or_else(|| format!("https://{rp_id}"));

    let pae = req.payload.clone().unwrap_or_default();
    let client_data_json = build_client_data_json(&pae, &origin, false);

    // First attempt: the (deprecated) argv `--pin` default, if the
    // caller passed one, else no PIN at all. Real authenticators with
    // no PIN configured succeed here.
    let mut assertion = device.get_assertion(
        &rp_id,
        credential_id,
        &client_data_json,
        defaults.pin.as_deref(),
    );

    // SPEC-EXTERNAL-SIGNER §4: source the PIN in-band rather than
    // requiring `--pin` on argv. Only attempted when the caller didn't
    // already supply one (argv still wins during the deprecation
    // window — see `warn_pin_argv_deprecated` in main.rs) and only
    // once: a wrong PIN decrements the authenticator's own retry
    // counter, so blind looping against it would burn attempts.
    //
    // The mock/no-`ctap-hw` device surfaces every failure as an opaque
    // `SignerError::Ctap(String)` — there is no PIN-specific error
    // variant to key off yet (`ctap-hid-fido2`'s CTAP2 status codes
    // aren't threaded through `CtapDevice` today), so any first-attempt
    // failure with no PIN supplied is treated as "might need a PIN"
    // and retried once with one. A future revision that plumbs real
    // CTAP2 status codes through `CtapDevice::get_assertion` can narrow
    // this to just `CTAP2_ERR_PIN_REQUIRED`.
    if assertion.is_err() && defaults.pin.is_none() {
        match request_pin_in_band(r, w, "authenticator PIN required", 0, true) {
            Ok(pin) if !pin.is_empty() => {
                assertion =
                    device.get_assertion(&rp_id, credential_id, &client_data_json, Some(&pin));
            }
            Ok(_) => {}
            Err(e) => return Err(e),
        }
    }

    let assertion = match assertion {
        Ok(a) => a,
        Err(SignerError::Ctap(msg)) => {
            return Ok(signer_error_frame(ErrorCode::HardwareError, msg));
        }
        Err(e) => return Ok(signer_error_frame(ErrorCode::Internal, e.to_string())),
    };

    let sig_compact = match proto::der_to_compact_p256(&assertion.signature) {
        Ok(c) => c.to_vec(),
        Err(e) => return Ok(signer_error_frame(ErrorCode::Internal, e.to_string())),
    };

    let key_id = if record.keyid.is_empty() {
        format!("webauthn:{credential_id_b64}")
    } else {
        record.keyid.clone()
    };

    Ok(SignerFrame {
        body: Some(signer_frame::Body::SignResponse(Box::new(SignResponse {
            signature: Some(sig_compact),
            public_key: Some(public_key),
            // Pass through the caller's `Option` unchanged (incl. None);
            // `with_algorithm` would force an unwrap and lose that.
            algorithm: req.algorithm,
            key_id: Some(key_id),
            certificate_chain: Vec::new(),
            webauthn: buffa::MessageField::some(
                WebAuthnData::default()
                    .with_authenticator_data(assertion.auth_data)
                    .with_client_data_json(client_data_json),
            ),
            ..Default::default()
        }))),
        ..Default::default()
    })
}

/// Emit a `PinPrompt` frame and block for the caller's `PinResponse`,
/// returning the PIN it carried (possibly empty, for a touch-only
/// prompt — see `PinPrompt.wants_pin`). Any other frame — including an
/// out-of-turn `SignRequest` — is a protocol violation: this signer
/// doesn't pipeline while a PIN round trip is outstanding.
fn request_pin_in_band<R: Read, W: Write>(
    r: &mut R,
    w: &mut W,
    reason: &str,
    retries_remaining: u32,
    wants_pin: bool,
) -> Result<String, SignerError> {
    let prompt = SignerFrame {
        body: Some(signer_frame::Body::PinPrompt(Box::new(
            PinPrompt::default()
                .with_reason(reason.to_owned())
                .with_retries_remaining(retries_remaining)
                .with_wants_pin(wants_pin),
        ))),
        ..Default::default()
    };
    write_frame(w, &prompt).map_err(|e| SignerError::Io(format!("write pin prompt: {e}")))?;

    let resp: SignerFrame =
        read_frame(r).map_err(|e| SignerError::Io(format!("read pin response: {e}")))?;
    match resp.body {
        Some(signer_frame::Body::PinResponse(pr)) => Ok(pr.pin.unwrap_or_default()),
        other => Err(SignerError::Io(format!(
            "expected PinResponse, got {}",
            signer_frame_body_name(&other)
        ))),
    }
}

/// Stringify a `SignerFrame` body variant for diagnostics. Small local
/// mirror of `mkit-attest`'s private `frame_name` — not worth sharing
/// across crates for six match arms.
fn signer_frame_body_name(b: &Option<signer_frame::Body>) -> &'static str {
    use signer_frame::Body;
    match b {
        Some(Body::Hello(_)) => "hello",
        Some(Body::HelloResponse(_)) => "hello_response",
        Some(Body::SignRequest(_)) => "sign_request",
        Some(Body::SignResponse(_)) => "sign_response",
        Some(Body::PinPrompt(_)) => "pin_prompt",
        Some(Body::PinResponse(_)) => "pin_response",
        Some(Body::Error(_)) => "error",
        None => "(empty body)",
    }
}

fn write_error<W: Write>(w: &mut W, code: ErrorCode, message: String) -> Result<(), SignerError> {
    let frame = signer_error_frame(code, message);
    write_frame(w, &frame).map_err(|e| SignerError::Io(format!("write error frame: {e}")))
}

fn hex_decode(s: &str) -> Result<Vec<u8>, &'static str> {
    if !s.len().is_multiple_of(2) {
        return Err("odd hex length");
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks_exact(2) {
        out.push(from_hex_nibble(chunk[0])? << 4 | from_hex_nibble(chunk[1])?);
    }
    Ok(out)
}

fn from_hex_nibble(c: u8) -> Result<u8, &'static str> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err("not hex"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cred_store::{Record, Store};
    use crate::ctap::{EnrolledCredential, MockCtapDevice, SignedAssertion};
    use buffa::Message;
    use mkit_rpc::mkit::rpc::v1::signer::{Hello, SignRequest};
    use std::io::Cursor;

    /// Encode a slice of frames as the wire bytes a stdin pipe would
    /// carry: 4-byte LE length + protobuf body, repeated.
    fn encode(frames: &[SignerFrame]) -> Vec<u8> {
        let mut out = Vec::new();
        for f in frames {
            let body = f.encode_to_vec();
            out.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
            out.extend_from_slice(&body);
        }
        out
    }

    /// Decode framed stdout bytes back into SignerFrames.
    fn decode(mut bytes: &[u8]) -> Vec<SignerFrame> {
        let mut out = Vec::new();
        while bytes.len() >= 4 {
            let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
            bytes = &bytes[4..];
            assert!(bytes.len() >= len, "truncated body in stdout");
            out.push(SignerFrame::decode_from_slice(&bytes[..len]).expect("decode SignerFrame"));
            bytes = &bytes[len..];
        }
        out
    }

    /// Compute a real P-256 signature with a canned key over
    /// `auth_data || SHA-256(client_data_json)` so the server's
    /// DER→compact conversion has a real signature to chew on. The
    /// test does not verify cryptographically; verification lives
    /// elsewhere. This ensures the bytes are well-formed DER.
    fn canned_assertion(rp_id: &str, payload: &[u8], origin: &str) -> SignedAssertion {
        use mkit_attest::build_client_data_json;
        use p256::ecdsa::{Signature as P256Sig, SigningKey, signature::Signer as _};
        use sha2::{Digest, Sha256};

        let rp_id_hash = Sha256::digest(rp_id.as_bytes());
        let mut auth_data = Vec::with_capacity(37);
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(0x05); // UP + UV flags
        auth_data.extend_from_slice(&[0u8; 4]); // signCount = 0

        let cdj = build_client_data_json(payload, origin, false);
        let mut signed = Vec::with_capacity(auth_data.len() + 32);
        signed.extend_from_slice(&auth_data);
        signed.extend_from_slice(&Sha256::digest(&cdj));

        let sk = SigningKey::from_bytes(&[42u8; 32].into()).unwrap();
        let sig: P256Sig = sk.sign(&signed);
        let sig = sig.normalize_s();

        SignedAssertion {
            auth_data,
            signature: sig.to_der().as_bytes().to_vec(),
            credential_id: b"mock-cred".to_vec(),
        }
    }

    fn mock_device() -> MockCtapDevice {
        MockCtapDevice {
            canned_credential: EnrolledCredential {
                credential_id: b"mock-cred".to_vec(),
                public_key_sec1_uncompressed: vec![0x04; 65],
                keyid: "p256:mock".into(),
            },
            canned_assertion: canned_assertion(
                "mkit.local",
                b"DSSEv1 28 application/vnd.in-toto+json 2 {}",
                "https://mkit.local",
            ),
            requires_pin: false,
        }
    }

    fn store_with_mock_credential() -> Store {
        let credential_id_b64url =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"mock-cred");
        let mut store = Store::default();
        store.upsert(Record {
            credential_id_b64url,
            public_key_sec1_uncompressed_hex: "04".to_owned() + &"aa".repeat(64),
            rp_id: "mkit.local".to_owned(),
            user_name: "alice".to_owned(),
            keyid: "p256:mock".to_owned(),
        });
        store
    }

    #[test]
    fn hello_response_advertises_p256_and_opaque_handle() {
        let frames = vec![SignerFrame {
            body: Some(signer_frame::Body::Hello(Box::new(
                Hello::default()
                    .with_protocol(ProtocolVersion::ProtocolVersion1)
                    .with_want_capabilities(true),
            ))),
            ..Default::default()
        }];
        let mut input = Cursor::new(encode(&frames));
        let mut output = Vec::new();
        let device = mock_device();
        serve(&mut input, &mut output, &device, &SignDefaults::default()).unwrap();

        let frames = decode(&output);
        assert_eq!(frames.len(), 1);
        let resp = match frames[0].body.clone() {
            Some(signer_frame::Body::HelloResponse(h)) => *h,
            other => panic!("expected HelloResponse, got {other:?}"),
        };
        let caps = resp.capabilities.into_option().expect("capabilities set");
        assert_eq!(
            caps.algorithms,
            vec![buffa::EnumValue::from(RpcAlgorithm::P256)]
        );
        assert_eq!(
            caps.key_forms,
            vec![buffa::EnumValue::from(KeyForm::OpaqueHandle)]
        );
        assert_eq!(caps.supports_pin, Some(true));
        assert_eq!(caps.requires_user_presence, Some(true));
    }

    #[test]
    fn sign_request_emits_webauthn_extension() {
        let device = mock_device();
        let store = store_with_mock_credential();
        let credential_id_b64url =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"mock-cred");
        let req = SignRequest::default()
            .with_algorithm(RpcAlgorithm::P256)
            .with_key_form(KeyForm::OpaqueHandle)
            .with_key_ref(b"mock-cred".to_vec())
            .with_payload(b"DSSEv1 28 application/vnd.in-toto+json 2 {}".to_vec());
        let mut r = Cursor::new(Vec::new());
        let mut w = Vec::new();
        let resp = handle_sign_with_store(
            &mut r,
            &mut w,
            &req,
            &device,
            &SignDefaults::default(),
            &store,
            b"mock-cred",
            &credential_id_b64url,
        )
        .unwrap();
        let sign_resp = match resp.body.clone() {
            Some(signer_frame::Body::SignResponse(s)) => *s,
            Some(signer_frame::Body::Error(e)) => panic!("server returned Error: {e:?}"),
            other => panic!("expected SignResponse, got {other:?}"),
        };

        // 64-byte compact P-256 signature.
        assert_eq!(sign_resp.signature.as_ref().map(Vec::len), Some(64));
        assert_eq!(sign_resp.public_key.as_ref().map(Vec::len), Some(65));

        // WebAuthnData populated.
        let webauthn = sign_resp.webauthn.into_option().expect("webauthn set");
        assert_eq!(webauthn.authenticator_data.as_ref().map(Vec::len), Some(37));
        let cdj_bytes = webauthn.client_data_json.expect("client_data_json set");
        assert!(cdj_bytes.starts_with(b"{"));
    }

    #[test]
    fn sign_request_without_stored_public_key_returns_invalid_request() {
        let device = mock_device();
        let req = SignRequest::default()
            .with_algorithm(RpcAlgorithm::P256)
            .with_key_form(KeyForm::OpaqueHandle)
            .with_key_ref(b"mock-cred".to_vec())
            .with_payload(b"x".to_vec());
        let mut r = Cursor::new(Vec::new());
        let mut w = Vec::new();
        let resp = handle_sign_with_store(
            &mut r,
            &mut w,
            &req,
            &device,
            &SignDefaults::default(),
            &Store::default(),
            b"mock-cred",
            "bW9jay1jcmVk",
        )
        .unwrap();

        let err = match resp.body.clone() {
            Some(signer_frame::Body::Error(e)) => e,
            other => panic!("expected Error, got {other:?}"),
        };
        assert_eq!(err.code, Some(ErrorCode::InvalidRequest.into()));
        assert!(
            err.message
                .as_deref()
                .is_some_and(|message| message.contains("credential metadata"))
        );
    }

    #[test]
    fn ed25519_webauthn_returns_unsupported_algorithm() {
        let device = mock_device();
        let store = store_with_mock_credential();
        let req = SignRequest::default()
            .with_algorithm(RpcAlgorithm::Ed25519Webauthn)
            .with_key_form(KeyForm::OpaqueHandle)
            .with_key_ref(b"mock-cred".to_vec())
            .with_payload(b"x".to_vec());
        let mut r = Cursor::new(Vec::new());
        let mut w = Vec::new();
        let resp = handle_sign_with_store(
            &mut r,
            &mut w,
            &req,
            &device,
            &SignDefaults::default(),
            &store,
            b"mock-cred",
            "bW9jay1jcmVk",
        )
        .unwrap();

        let err = match resp.body.clone() {
            Some(signer_frame::Body::Error(e)) => e,
            other => panic!("expected Error, got {other:?}"),
        };
        assert_eq!(err.code, Some(ErrorCode::UnsupportedAlgorithm.into()));
    }

    #[test]
    fn raw_key_form_is_allowed_only_for_mkit_argv_default_compatibility() {
        assert!(ctap_key_form_allowed(KeyForm::RawBytes.into(), false, true));
        assert!(!ctap_key_form_allowed(KeyForm::RawBytes.into(), true, true));
        assert!(!ctap_key_form_allowed(
            KeyForm::RawBytes.into(),
            false,
            false
        ));
    }

    #[test]
    fn unsupported_algorithm_returns_error_frame() {
        let frames = vec![
            SignerFrame {
                body: Some(signer_frame::Body::Hello(Box::new(
                    Hello::default().with_protocol(ProtocolVersion::ProtocolVersion1),
                ))),
                ..Default::default()
            },
            SignerFrame {
                body: Some(signer_frame::Body::SignRequest(Box::new(
                    // CTAP signer doesn't support raw Ed25519.
                    SignRequest::default()
                        .with_algorithm(RpcAlgorithm::Ed25519)
                        .with_key_form(KeyForm::OpaqueHandle)
                        .with_key_ref(b"any".to_vec())
                        .with_payload(b"x".to_vec()),
                ))),
                ..Default::default()
            },
        ];
        let mut input = Cursor::new(encode(&frames));
        let mut output = Vec::new();
        let device = mock_device();
        serve(&mut input, &mut output, &device, &SignDefaults::default()).unwrap();

        let frames = decode(&output);
        let err = match frames[1].body.clone() {
            Some(signer_frame::Body::Error(e)) => e,
            other => panic!("expected Error, got {other:?}"),
        };
        assert_eq!(err.code, Some(ErrorCode::UnsupportedAlgorithm.into()));
    }

    #[test]
    fn missing_credential_id_returns_invalid_request() {
        let frames = vec![SignerFrame {
            body: Some(signer_frame::Body::SignRequest(Box::new(
                SignRequest::default()
                    .with_algorithm(RpcAlgorithm::P256)
                    .with_key_form(KeyForm::OpaqueHandle)
                    .with_key_ref(Vec::new()) // explicitly empty
                    .with_payload(b"x".to_vec()),
            ))),
            ..Default::default()
        }];
        let mut input = Cursor::new(encode(&frames));
        let mut output = Vec::new();
        let device = mock_device();
        serve(&mut input, &mut output, &device, &SignDefaults::default()).unwrap();

        let frames = decode(&output);
        let err = match frames[0].body.clone() {
            Some(signer_frame::Body::Error(e)) => e,
            other => panic!("expected Error, got {other:?}"),
        };
        assert_eq!(err.code, Some(ErrorCode::InvalidRequest.into()));
    }

    #[test]
    fn pin_required_device_completes_via_in_band_round_trip() {
        // Issue #694 / SPEC-EXTERNAL-SIGNER §4: a device that rejects
        // the pin-less first attempt must be answered with a
        // PinPrompt, and a well-formed PinResponse on the wire must
        // let the sign complete — without `--pin` ever touching argv.
        let mut device = mock_device();
        device.requires_pin = true;
        let store = store_with_mock_credential();

        let req = SignRequest::default()
            .with_algorithm(RpcAlgorithm::P256)
            .with_key_form(KeyForm::OpaqueHandle)
            .with_key_ref(b"mock-cred".to_vec())
            .with_payload(b"DSSEv1 28 application/vnd.in-toto+json 2 {}".to_vec());

        // `handle_sign_with_store` reads any in-band PinResponse
        // directly off `r` mid-request (see `request_pin_in_band`) —
        // feed it just that one trailing frame.
        let pin_response = SignerFrame {
            body: Some(signer_frame::Body::PinResponse(Box::new(
                mkit_rpc::mkit::rpc::v1::signer::PinResponse::default().with_pin("1234"),
            ))),
            ..Default::default()
        };
        let mut r = Cursor::new(encode(&[pin_response]));
        let mut w = Vec::new();

        let resp = handle_sign_with_store(
            &mut r,
            &mut w,
            &req,
            &device,
            &SignDefaults::default(),
            &store,
            b"mock-cred",
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"mock-cred"),
        )
        .expect("PinPrompt round trip must not error");

        // The signer must have written exactly one PinPrompt to `w`
        // before returning the terminal SignResponse.
        let emitted = decode(&w);
        assert_eq!(
            emitted.len(),
            1,
            "expected exactly one emitted frame (PinPrompt)"
        );
        let prompt = match emitted[0].body.clone() {
            Some(signer_frame::Body::PinPrompt(p)) => *p,
            other => panic!("expected PinPrompt, got {other:?}"),
        };
        assert!(prompt.wants_pin.unwrap_or(false));

        match resp.body {
            Some(signer_frame::Body::SignResponse(_)) => {}
            other => panic!("expected SignResponse after the PIN round trip, got {other:?}"),
        }
    }
}
