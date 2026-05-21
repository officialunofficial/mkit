//! mkit-rpc signer protocol loop for the TPM signer.
//!
//! Generic over [`TpmSigner`] so unit tests can drive the protocol
//! with an in-process P-256 signer (no TPM required); the production
//! binary uses [`RealTpmSigner`] which delegates to the `tpm` module's
//! tss-esapi-backed `sign()` (gated on the `tpm2` Cargo feature +
//! Linux/Windows target).

use std::io::{Read, Write};

use mkit_rpc::mkit::rpc::v1::signer::{
    Capabilities, HelloResponse, SignResponse, SignerFrame, signer_frame,
};
use mkit_rpc::mkit::rpc::v1::{
    Algorithm as RpcAlgorithm, Error as RpcError, ErrorCode, KeyForm, ProtocolVersion,
};
use mkit_rpc::{FrameError, read_frame, write_frame};

use crate::SignerError;

/// What the protocol layer needs from a TPM-flavoured signer.
///
/// The trait abstraction lets tests substitute an in-process P-256
/// signer for the real TPM, exercising the full wire-protocol path
/// without hardware. Production code uses [`RealTpmSigner`].
pub trait TpmSigner {
    /// Sign `pae` with the persistent key at `handle`. Returns
    /// `(pubkey_compressed_33_bytes, sig_compact_normalised_64_bytes)`.
    ///
    /// # Errors
    /// Surfaces [`SignerError::Tpm`] on any hardware failure.
    fn sign(&self, handle: u32, pae: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SignerError>;
}

/// Production signer — delegates to the `tpm` module which links
/// `tss-esapi` when built with `--features tpm2` on Linux/Windows.
/// On other platforms or without the feature, every call returns a
/// `SignerError::Tpm("…feature off…")`.
#[derive(Debug, Default)]
pub struct RealTpmSigner;

impl TpmSigner for RealTpmSigner {
    fn sign(&self, handle: u32, pae: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SignerError> {
        crate::tpm::sign(handle, pae)
    }
}

/// Drive the protocol on `(r, w)` until the caller closes the stream.
pub fn serve<R, W, T>(
    r: &mut R,
    w: &mut W,
    handle_default: Option<u32>,
    signer: &T,
) -> Result<(), SignerError>
where
    R: Read,
    W: Write,
    T: TpmSigner,
{
    loop {
        let req: SignerFrame = match read_frame(r) {
            Ok(f) => f,
            Err(FrameError::LengthTruncated) => return Ok(()),
            Err(FrameError::LengthTooLarge(n)) => {
                let _ = write_error(
                    w,
                    ErrorCode::ERROR_CODE_INVALID_REQUEST,
                    format!("frame length {n} exceeds 1 MiB"),
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
                        signer_id: Some(format!("mkit-sign-tpm/{}", env!("CARGO_PKG_VERSION"))),
                        capabilities: buffa::MessageField::some(Capabilities {
                            algorithms: vec![RpcAlgorithm::ALGORITHM_P256.into()],
                            key_forms: vec![KeyForm::KEY_FORM_OPAQUE_HANDLE.into()],
                            supports_pin: Some(false),
                            supports_certificate_chain: Some(false),
                            max_payload_bytes: Some(0),
                            requires_user_presence: Some(false),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }))),
                    ..Default::default()
                };
                write_frame(w, &resp).map_err(|e| SignerError::Io(format!("write hello: {e}")))?;
            }

            Some(signer_frame::Body::SignRequest(req_box)) => {
                let resp = handle_sign(&req_box, handle_default, signer);
                write_frame(w, &resp).map_err(|e| SignerError::Io(format!("write sign: {e}")))?;
            }

            Some(signer_frame::Body::PinResponse(_)) => {
                write_error(
                    w,
                    ErrorCode::ERROR_CODE_INVALID_REQUEST,
                    "mkit-sign-tpm does not request PINs".to_owned(),
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

fn handle_sign<T: TpmSigner>(
    req: &mkit_rpc::mkit::rpc::v1::signer::SignRequest,
    handle_default: Option<u32>,
    signer: &T,
) -> SignerFrame {
    let algorithm = req.algorithm.as_ref().map_or(0, buffa::EnumValue::to_i32);
    if algorithm != RpcAlgorithm::ALGORITHM_P256 as i32 {
        return error_frame(
            ErrorCode::ERROR_CODE_UNSUPPORTED_ALGORITHM,
            "mkit-sign-tpm signs ALGORITHM_P256 only".to_owned(),
        );
    }

    let key_form = req.key_form.as_ref().map_or(0, buffa::EnumValue::to_i32);
    if key_form != KeyForm::KEY_FORM_OPAQUE_HANDLE as i32 && key_form != 0 {
        return error_frame(
            ErrorCode::ERROR_CODE_UNSUPPORTED_KEY_FORM,
            "mkit-sign-tpm only supports KEY_FORM_OPAQUE_HANDLE (the persistent handle)".to_owned(),
        );
    }

    // Resolve the persistent handle. Either:
    //   - SignRequest.key_ref carries a 4-byte big-endian u32, or
    //   - the binary was started with `--handle 0x81010001` and we
    //     fall back to that argv value.
    let handle = match req.key_ref.as_ref() {
        Some(b) if b.len() == 4 => Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]])),
        Some(b) if b.is_empty() => None,
        Some(_) => {
            return error_frame(
                ErrorCode::ERROR_CODE_INVALID_REQUEST,
                "key_ref must be a 4-byte big-endian u32 persistent handle".to_owned(),
            );
        }
        None => None,
    }
    .or(handle_default);

    let Some(handle) = handle else {
        return error_frame(
            ErrorCode::ERROR_CODE_INVALID_REQUEST,
            "no persistent handle — pass --handle on argv or set SignRequest.key_ref to the 4-byte BE handle".to_owned(),
        );
    };

    let pae = req.payload.clone().unwrap_or_default();
    let (pubkey, sig) = match signer.sign(handle, &pae) {
        Ok(out) => out,
        Err(SignerError::Tpm(msg)) => {
            return error_frame(ErrorCode::ERROR_CODE_HARDWARE_ERROR, msg);
        }
        Err(e) => return error_frame(ErrorCode::ERROR_CODE_INTERNAL, e.to_string()),
    };

    if pubkey.len() != 33 {
        return error_frame(
            ErrorCode::ERROR_CODE_INTERNAL,
            format!("signer returned pubkey {} bytes, want 33", pubkey.len()),
        );
    }
    if sig.len() != 64 {
        return error_frame(
            ErrorCode::ERROR_CODE_INTERNAL,
            format!("signer returned signature {} bytes, want 64", sig.len()),
        );
    }

    let key_id = format!("p256:{}", crate::to_hex(&pubkey));

    SignerFrame {
        body: Some(signer_frame::Body::SignResponse(Box::new(
            SignResponse::default()
                .with_signature(sig)
                .with_public_key(pubkey)
                .with_algorithm(RpcAlgorithm::ALGORITHM_P256)
                .with_key_id(key_id),
        ))),
        ..Default::default()
    }
}

fn write_error<W: Write>(w: &mut W, code: ErrorCode, message: String) -> Result<(), SignerError> {
    let frame = error_frame(code, message);
    write_frame(w, &frame).map_err(|e| SignerError::Io(format!("write error frame: {e}")))
}

fn error_frame(code: ErrorCode, message: String) -> SignerFrame {
    SignerFrame {
        body: Some(signer_frame::Body::Error(Box::new(
            RpcError::default()
                .with_code(code)
                .with_message(message)
                .with_details(Vec::new()),
        ))),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use buffa::Message;
    use mkit_rpc::mkit::rpc::v1::signer::{Hello, SignRequest};
    use std::io::Cursor;

    /// In-process P-256 signer. Mirrors the shape of the TPM result
    /// (33-byte SEC1-compressed pubkey, 64-byte compact normalised
    /// signature) without touching hardware.
    struct MockSigner {
        secret: [u8; 32],
    }

    impl TpmSigner for MockSigner {
        fn sign(&self, _handle: u32, pae: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SignerError> {
            use p256::ecdsa::{Signature as P256Sig, SigningKey, signature::Signer as _};
            let sk = SigningKey::from_bytes(&self.secret.into())
                .map_err(|e| SignerError::Tpm(format!("init: {e}")))?;
            let vk = sk.verifying_key();
            let pub_compressed = vk.to_encoded_point(true).as_bytes().to_vec();
            let sig: P256Sig = sk.sign(pae);
            let sig = sig.normalize_s().unwrap_or(sig);
            Ok((pub_compressed, sig.to_bytes().to_vec()))
        }
    }

    fn encode(frames: &[SignerFrame]) -> Vec<u8> {
        let mut out = Vec::new();
        for f in frames {
            let body = f.encode_to_vec();
            out.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
            out.extend_from_slice(&body);
        }
        out
    }

    fn decode(mut bytes: &[u8]) -> Vec<SignerFrame> {
        let mut out = Vec::new();
        while bytes.len() >= 4 {
            let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
            bytes = &bytes[4..];
            out.push(SignerFrame::decode_from_slice(&bytes[..len]).unwrap());
            bytes = &bytes[len..];
        }
        out
    }

    #[test]
    fn hello_response_advertises_p256_only() {
        let frames = vec![SignerFrame {
            body: Some(signer_frame::Body::Hello(Box::new(
                Hello::default()
                    .with_protocol(ProtocolVersion::PROTOCOL_VERSION_1)
                    .with_want_capabilities(true),
            ))),
            ..Default::default()
        }];
        let mut input = Cursor::new(encode(&frames));
        let mut output = Vec::new();
        let signer = MockSigner { secret: [9u8; 32] };
        serve(&mut input, &mut output, None, &signer).unwrap();

        let frames = decode(&output);
        let resp = match frames[0].body.clone() {
            Some(signer_frame::Body::HelloResponse(h)) => *h,
            other => panic!("expected HelloResponse, got {other:?}"),
        };
        let caps = resp.capabilities.into_option().expect("capabilities");
        assert_eq!(
            caps.algorithms
                .iter()
                .map(buffa::EnumValue::to_i32)
                .collect::<Vec<_>>(),
            vec![RpcAlgorithm::ALGORITHM_P256 as i32]
        );
    }

    #[test]
    fn sign_request_with_be_handle_in_key_ref_succeeds() {
        let handle: u32 = 0x8101_0001;
        let pae = b"DSSEv1 28 application/vnd.in-toto+json 2 {}";

        let frames = vec![
            SignerFrame {
                body: Some(signer_frame::Body::Hello(Box::new(
                    Hello::default().with_protocol(ProtocolVersion::PROTOCOL_VERSION_1),
                ))),
                ..Default::default()
            },
            SignerFrame {
                body: Some(signer_frame::Body::SignRequest(Box::new(
                    SignRequest::default()
                        .with_algorithm(RpcAlgorithm::ALGORITHM_P256)
                        .with_key_form(KeyForm::KEY_FORM_OPAQUE_HANDLE)
                        .with_key_ref(handle.to_be_bytes().to_vec())
                        .with_payload(pae.to_vec()),
                ))),
                ..Default::default()
            },
        ];
        let mut input = Cursor::new(encode(&frames));
        let mut output = Vec::new();
        let signer = MockSigner { secret: [42u8; 32] };
        serve(&mut input, &mut output, None, &signer).unwrap();

        let frames = decode(&output);
        let sign_resp = match frames[1].body.clone() {
            Some(signer_frame::Body::SignResponse(s)) => *s,
            Some(signer_frame::Body::Error(e)) => panic!("server returned Error: {e:?}"),
            other => panic!("expected SignResponse, got {other:?}"),
        };
        assert_eq!(sign_resp.signature.as_ref().map(Vec::len), Some(64));
        assert_eq!(sign_resp.public_key.as_ref().map(Vec::len), Some(33));
        assert!(sign_resp.key_id.unwrap().starts_with("p256:"));
    }

    #[test]
    fn sign_request_uses_handle_default_when_key_ref_empty() {
        let pae = b"DSSEv1 28 application/vnd.in-toto+json 2 {}";
        let frames = vec![SignerFrame {
            body: Some(signer_frame::Body::SignRequest(Box::new(
                SignRequest::default()
                    .with_algorithm(RpcAlgorithm::ALGORITHM_P256)
                    .with_key_form(KeyForm::KEY_FORM_OPAQUE_HANDLE)
                    .with_key_ref(Vec::new())
                    .with_payload(pae.to_vec()),
            ))),
            ..Default::default()
        }];
        let mut input = Cursor::new(encode(&frames));
        let mut output = Vec::new();
        let signer = MockSigner { secret: [99u8; 32] };
        serve(&mut input, &mut output, Some(0x8101_0001), &signer).unwrap();

        let frames = decode(&output);
        match frames[0].body.clone() {
            Some(signer_frame::Body::SignResponse(_)) => {}
            other => panic!("expected SignResponse via default handle, got {other:?}"),
        }
    }

    #[test]
    fn unsupported_algorithm_returns_error() {
        let frames = vec![SignerFrame {
            body: Some(signer_frame::Body::SignRequest(Box::new(
                SignRequest::default()
                    .with_algorithm(RpcAlgorithm::ALGORITHM_ED25519)
                    .with_key_form(KeyForm::KEY_FORM_OPAQUE_HANDLE)
                    .with_key_ref(b"\x81\x01\x00\x01".to_vec())
                    .with_payload(b"x".to_vec()),
            ))),
            ..Default::default()
        }];
        let mut input = Cursor::new(encode(&frames));
        let mut output = Vec::new();
        let signer = MockSigner { secret: [1u8; 32] };
        serve(&mut input, &mut output, None, &signer).unwrap();
        let frames = decode(&output);
        let err = match frames[0].body.clone() {
            Some(signer_frame::Body::Error(e)) => e,
            other => panic!("expected Error, got {other:?}"),
        };
        assert_eq!(
            err.code.as_ref().unwrap().to_i32(),
            ErrorCode::ERROR_CODE_UNSUPPORTED_ALGORITHM as i32
        );
    }
}
