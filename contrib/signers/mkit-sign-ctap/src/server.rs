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
use base64::engine::general_purpose::STANDARD as B64_STD;
use mkit_attest::build_client_data_json;
use mkit_rpc::mkit::rpc::v1::signer::{
    Capabilities, HelloResponse, SignResponse, SignerFrame, WebAuthnData, signer_frame,
};
use mkit_rpc::mkit::rpc::v1::{
    Algorithm as RpcAlgorithm, Error as RpcError, ErrorCode, KeyForm, ProtocolVersion,
};
use mkit_rpc::{FrameError, read_frame, write_frame};

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
                    ErrorCode::ERROR_CODE_INVALID_REQUEST,
                    format!("frame length {n} exceeds 1 MiB cap"),
                );
                return Err(SignerError::Io("oversize frame".into()));
            }
            Err(FrameError::BodyTruncated { expected, .. }) => {
                let _ = write_error(
                    w,
                    ErrorCode::ERROR_CODE_INVALID_REQUEST,
                    format!("frame body truncated (expected {expected} bytes)"),
                );
                return Err(SignerError::Io("truncated frame".into()));
            }
            Err(FrameError::DecodeFailed) => {
                let _ = write_error(
                    w,
                    ErrorCode::ERROR_CODE_INVALID_REQUEST,
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
                        protocol: Some(ProtocolVersion::PROTOCOL_VERSION_1.into()),
                        signer_id: Some(format!("mkit-sign-ctap/{}", env!("CARGO_PKG_VERSION"))),
                        capabilities: buffa::MessageField::some(Capabilities {
                            // CTAP authenticators sign over WebAuthn-
                            // wrapped P-256 (most), or Ed25519
                            // (a handful). We advertise the wrapping
                            // algorithms the protocol enum names.
                            algorithms: vec![
                                RpcAlgorithm::ALGORITHM_P256.into(),
                                RpcAlgorithm::ALGORITHM_ED25519_WEBAUTHN.into(),
                            ],
                            key_forms: vec![KeyForm::KEY_FORM_OPAQUE_HANDLE.into()],
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
                let resp = handle_sign(&req_box, device, defaults);
                write_frame(w, &resp).map_err(|e| SignerError::Io(format!("write sign: {e}")))?;
            }

            // CTAP signer doesn't request PINs in-band right now; argv
            // `--pin` covers it. A stray PinResponse is a protocol bug.
            Some(signer_frame::Body::PinResponse(_)) => {
                write_error(
                    w,
                    ErrorCode::ERROR_CODE_INVALID_REQUEST,
                    "mkit-sign-ctap does not solicit PINs in-band; pass --pin instead".to_owned(),
                )?;
            }

            Some(_) => {
                write_error(
                    w,
                    ErrorCode::ERROR_CODE_INVALID_REQUEST,
                    "unexpected frame body".to_owned(),
                )?;
            }
            None => {
                write_error(
                    w,
                    ErrorCode::ERROR_CODE_INVALID_REQUEST,
                    "empty frame body".to_owned(),
                )?;
            }
        }
    }
}

fn handle_sign<D: CtapDevice>(
    req: &mkit_rpc::mkit::rpc::v1::signer::SignRequest,
    device: &D,
    defaults: &SignDefaults,
) -> SignerFrame {
    // CTAP authenticators only speak P-256 ECDSA (and a handful Ed25519
    // via webauthn wrapping). Reject anything else loudly.
    let algorithm = req.algorithm.as_ref().map_or(0, buffa::EnumValue::to_i32);
    if algorithm != RpcAlgorithm::ALGORITHM_P256 as i32
        && algorithm != RpcAlgorithm::ALGORITHM_ED25519_WEBAUTHN as i32
    {
        return error_frame(
            ErrorCode::ERROR_CODE_UNSUPPORTED_ALGORITHM,
            "mkit-sign-ctap only signs ALGORITHM_P256 and ALGORITHM_ED25519_WEBAUTHN".to_owned(),
        );
    }

    // CTAP signers require an opaque credential_id handle.
    let key_form = req.key_form.as_ref().map_or(0, buffa::EnumValue::to_i32);
    if key_form != KeyForm::KEY_FORM_OPAQUE_HANDLE as i32 && key_form != 0 {
        return error_frame(
            ErrorCode::ERROR_CODE_UNSUPPORTED_KEY_FORM,
            "mkit-sign-ctap only supports KEY_FORM_OPAQUE_HANDLE (the credential_id)".to_owned(),
        );
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
            return error_frame(
                ErrorCode::ERROR_CODE_INVALID_REQUEST,
                "no credential — pass --credential-id on argv or set SignRequest.key_ref"
                    .to_owned(),
            );
        }
    };

    // Look up rp_id / keyid in the local store; fall back to argv defaults.
    let credential_id_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&credential_id);
    let store_path = match cred_store::default_path() {
        Ok(p) => p,
        Err(e) => return error_frame(ErrorCode::ERROR_CODE_INTERNAL, e.to_string()),
    };
    let store = cred_store::Store::load(&store_path).unwrap_or_default();
    let record = store.find_by_credential_id(&credential_id_b64);

    let rp_id = defaults
        .rp_id
        .clone()
        .or_else(|| record.map(|r| r.rp_id.clone()))
        .unwrap_or_else(|| "mkit.local".to_owned());
    let origin = defaults
        .origin
        .clone()
        .unwrap_or_else(|| format!("https://{rp_id}"));

    let pae = req.payload.clone().unwrap_or_default();
    let client_data_json = build_client_data_json(&pae, &origin, false);

    let assertion = match device.get_assertion(
        &rp_id,
        &credential_id,
        &client_data_json,
        defaults.pin.as_deref(),
    ) {
        Ok(a) => a,
        Err(SignerError::Ctap(msg)) => {
            return error_frame(ErrorCode::ERROR_CODE_HARDWARE_ERROR, msg);
        }
        Err(e) => return error_frame(ErrorCode::ERROR_CODE_INTERNAL, e.to_string()),
    };

    let sig_compact = match proto::der_to_compact_p256(&assertion.signature) {
        Ok(c) => c.to_vec(),
        Err(e) => return error_frame(ErrorCode::ERROR_CODE_INTERNAL, e.to_string()),
    };

    let key_id = record.map_or_else(
        || format!("webauthn:{credential_id_b64}"),
        |r| r.keyid.clone(),
    );
    let public_key = record
        .map(|r| hex_decode(&r.public_key_sec1_uncompressed_hex).unwrap_or_default())
        .unwrap_or_default();

    SignerFrame {
        body: Some(signer_frame::Body::SignResponse(Box::new(SignResponse {
            signature: Some(sig_compact),
            public_key: Some(public_key),
            algorithm: req.algorithm,
            key_id: Some(key_id),
            certificate_chain: Vec::new(),
            webauthn: buffa::MessageField::some(WebAuthnData {
                authenticator_data: Some(assertion.auth_data),
                client_data_json: Some(client_data_json),
                ..Default::default()
            }),
            ..Default::default()
        }))),
        ..Default::default()
    }
}

fn write_error<W: Write>(w: &mut W, code: ErrorCode, message: String) -> Result<(), SignerError> {
    let frame = error_frame(code, message);
    write_frame(w, &frame).map_err(|e| SignerError::Io(format!("write error frame: {e}")))
}

fn error_frame(code: ErrorCode, message: String) -> SignerFrame {
    SignerFrame {
        body: Some(signer_frame::Body::Error(Box::new(RpcError {
            code: Some(code.into()),
            message: Some(message),
            details: Some(Vec::new()),
            ..Default::default()
        }))),
        ..Default::default()
    }
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

// Helper used by both ALGORITHM_ED25519_WEBAUTHN and ALGORITHM_P256
// signers — kept here so callers don't repeat themselves.
#[allow(dead_code)]
fn b64_encode(b: &[u8]) -> String {
    B64_STD.encode(b)
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let sig = sig.normalize_s().unwrap_or(sig);

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
        }
    }

    #[test]
    fn hello_response_advertises_p256_and_opaque_handle() {
        let frames = vec![SignerFrame {
            body: Some(signer_frame::Body::Hello(Box::new(Hello {
                protocol: Some(ProtocolVersion::PROTOCOL_VERSION_1.into()),
                want_capabilities: Some(true),
                ..Default::default()
            }))),
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
        let alg_set: Vec<i32> = caps
            .algorithms
            .iter()
            .map(buffa::EnumValue::to_i32)
            .collect();
        assert!(alg_set.contains(&(RpcAlgorithm::ALGORITHM_P256 as i32)));
        assert!(alg_set.contains(&(RpcAlgorithm::ALGORITHM_ED25519_WEBAUTHN as i32)));
        let key_forms: Vec<i32> = caps
            .key_forms
            .iter()
            .map(buffa::EnumValue::to_i32)
            .collect();
        assert_eq!(key_forms, vec![KeyForm::KEY_FORM_OPAQUE_HANDLE as i32]);
        assert_eq!(caps.supports_pin, Some(true));
        assert_eq!(caps.requires_user_presence, Some(true));
    }

    #[test]
    fn sign_request_emits_webauthn_extension() {
        let frames = vec![
            SignerFrame {
                body: Some(signer_frame::Body::Hello(Box::new(Hello {
                    protocol: Some(ProtocolVersion::PROTOCOL_VERSION_1.into()),
                    ..Default::default()
                }))),
                ..Default::default()
            },
            SignerFrame {
                body: Some(signer_frame::Body::SignRequest(Box::new(SignRequest {
                    algorithm: Some(RpcAlgorithm::ALGORITHM_P256.into()),
                    key_form: Some(KeyForm::KEY_FORM_OPAQUE_HANDLE.into()),
                    key_ref: Some(b"mock-cred".to_vec()),
                    payload: Some(b"DSSEv1 28 application/vnd.in-toto+json 2 {}".to_vec()),
                    ..Default::default()
                }))),
                ..Default::default()
            },
        ];
        let mut input = Cursor::new(encode(&frames));
        let mut output = Vec::new();
        let device = mock_device();
        serve(&mut input, &mut output, &device, &SignDefaults::default()).unwrap();

        let frames = decode(&output);
        assert_eq!(frames.len(), 2, "want HelloResponse + SignResponse");
        let sign_resp = match frames[1].body.clone() {
            Some(signer_frame::Body::SignResponse(s)) => *s,
            Some(signer_frame::Body::Error(e)) => panic!("server returned Error: {e:?}"),
            other => panic!("expected SignResponse, got {other:?}"),
        };

        // 64-byte compact P-256 signature.
        assert_eq!(sign_resp.signature.as_ref().map(Vec::len), Some(64));

        // WebAuthnData populated.
        let webauthn = sign_resp.webauthn.into_option().expect("webauthn set");
        assert_eq!(webauthn.authenticator_data.as_ref().map(Vec::len), Some(37));
        let cdj_bytes = webauthn.client_data_json.expect("client_data_json set");
        assert!(cdj_bytes.starts_with(b"{"));
    }

    #[test]
    fn unsupported_algorithm_returns_error_frame() {
        let frames = vec![
            SignerFrame {
                body: Some(signer_frame::Body::Hello(Box::new(Hello {
                    protocol: Some(ProtocolVersion::PROTOCOL_VERSION_1.into()),
                    ..Default::default()
                }))),
                ..Default::default()
            },
            SignerFrame {
                body: Some(signer_frame::Body::SignRequest(Box::new(SignRequest {
                    // CTAP signer doesn't support raw Ed25519.
                    algorithm: Some(RpcAlgorithm::ALGORITHM_ED25519.into()),
                    key_form: Some(KeyForm::KEY_FORM_OPAQUE_HANDLE.into()),
                    key_ref: Some(b"any".to_vec()),
                    payload: Some(b"x".to_vec()),
                    ..Default::default()
                }))),
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
        assert_eq!(
            err.code.as_ref().unwrap().to_i32(),
            ErrorCode::ERROR_CODE_UNSUPPORTED_ALGORITHM as i32
        );
    }

    #[test]
    fn missing_credential_id_returns_invalid_request() {
        let frames = vec![SignerFrame {
            body: Some(signer_frame::Body::SignRequest(Box::new(SignRequest {
                algorithm: Some(RpcAlgorithm::ALGORITHM_P256.into()),
                key_form: Some(KeyForm::KEY_FORM_OPAQUE_HANDLE.into()),
                key_ref: Some(Vec::new()), // explicitly empty
                payload: Some(b"x".to_vec()),
                ..Default::default()
            }))),
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
        assert_eq!(
            err.code.as_ref().unwrap().to_i32(),
            ErrorCode::ERROR_CODE_INVALID_REQUEST as i32
        );
    }
}
