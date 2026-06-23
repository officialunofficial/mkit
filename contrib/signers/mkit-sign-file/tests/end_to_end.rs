//! End-to-end: spawn `mkit-sign-file` as a subprocess, exchange framed
//! `SignerFrame` messages over stdin/stdout, and verify the returned
//! signature via mkit-attest's verifier paths.
//!
//! Covered:
//!
//! * Hello → `HelloResponse` with the expected capabilities.
//! * `SignRequest` → `SignResponse` for each algorithm (Ed25519, secp256k1,
//!   P-256), with the signature verified by mkit-attest.
//! * Multiple `SignRequests` on a single connection (the protocol allows
//!   it; the file signer handles it).
//! * Bad request: `KEY_FORM_PKCS8_DER` must come back as
//!   `ERROR_CODE_UNSUPPORTED_KEY_FORM`, not crash the binary.
//! * Unix permission enforcement: a key file with mode 0644 must be
//!   refused at startup with a non-zero exit and a stderr message —
//!   stdout MUST stay empty in that path so callers don't see a
//!   half-frame.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use buffa::Message;
use mkit_attest::{Algorithm, verify_signature};
use mkit_rpc::mkit::rpc::v1::signer::{Hello, SignRequest, SignerFrame, signer_frame};
use mkit_rpc::mkit::rpc::v1::{Algorithm as RpcAlgorithm, ErrorCode, KeyForm, ProtocolVersion};

/// Resolve the built `mkit-sign-file` binary path. Cargo sets
/// `CARGO_BIN_EXE_<name>` for each `[[bin]]` in the current package
/// before running integration tests.
fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mkit-sign-file"))
}

/// Write `bytes` to `<tmp>/key.bin` with mode 0600 and return the
/// absolute path.
fn write_key(tmp: &Path, bytes: &[u8; 32]) -> PathBuf {
    let path = tmp.join("key.bin");
    std::fs::write(&path, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut d = std::fs::metadata(tmp).unwrap().permissions();
        d.set_mode(0o700);
        std::fs::set_permissions(tmp, d).unwrap();
        let mut p = std::fs::metadata(&path).unwrap().permissions();
        p.set_mode(0o600);
        std::fs::set_permissions(&path, p).unwrap();
    }
    path
}

/// Encode a slice of frames as the on-wire byte stream the signer
/// reads from stdin (each frame: 4-byte LE length + protobuf body).
fn encode_frames(frames: &[SignerFrame]) -> Vec<u8> {
    let mut out = Vec::new();
    for f in frames {
        let body = f.encode_to_vec();
        out.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
        out.extend_from_slice(&body);
    }
    out
}

/// Decode the signer's stdout into a sequence of `SignerFrame`s.
fn decode_frames(mut bytes: &[u8]) -> Vec<SignerFrame> {
    let mut out = Vec::new();
    while bytes.len() >= 4 {
        let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        bytes = &bytes[4..];
        assert!(bytes.len() >= len, "truncated body in stdout");
        let body = &bytes[..len];
        out.push(SignerFrame::decode_from_slice(body).expect("decode SignerFrame"));
        bytes = &bytes[len..];
    }
    assert!(
        bytes.is_empty(),
        "trailing junk on stdout: {} bytes",
        bytes.len()
    );
    out
}

/// Spawn the signer, write `request_bytes` to stdin, capture stdout +
/// stderr + exit status. Tolerates `BrokenPipe` (matches earlier behaviour
/// when the child rejects the request before consuming stdin).
fn run_signer(
    key_path: &Path,
    request_bytes: &[u8],
) -> (Vec<u8>, String, std::process::ExitStatus) {
    let mut child = Command::new(binary())
        .arg("--key")
        .arg(key_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mkit-sign-file");
    {
        let stdin = child.stdin.as_mut().expect("stdin piped");
        let _ = stdin.write_all(request_bytes);
    }
    let out = child.wait_with_output().expect("wait");
    (
        out.stdout,
        String::from_utf8(out.stderr).unwrap(),
        out.status,
    )
}

/// Drive a single Hello + `SignRequest` round-trip and return the
/// (`HelloResponse`, `SignResponse`) pair, asserting both bodies are the
/// expected variants.
fn sign_one(
    key: &Path,
    alg: RpcAlgorithm,
) -> (
    mkit_rpc::mkit::rpc::v1::signer::HelloResponse,
    mkit_rpc::mkit::rpc::v1::signer::SignResponse,
) {
    let frames = vec![
        SignerFrame {
            body: Some(signer_frame::Body::Hello(Box::new(Hello {
                protocol: Some(ProtocolVersion::ProtocolVersion1.into()),
                caller_id: Some("e2e/0.1".into()),
                want_capabilities: Some(true),
                ..Default::default()
            }))),
            ..Default::default()
        },
        SignerFrame {
            body: Some(signer_frame::Body::SignRequest(Box::new(SignRequest {
                algorithm: Some(alg.into()),
                key_form: Some(KeyForm::RawBytes.into()),
                key_ref: Some(Vec::new()),
                payload: Some(PAE.to_vec()),
                context: Some(Vec::new()),
                ..Default::default()
            }))),
            ..Default::default()
        },
    ];
    let (stdout, stderr, status) = run_signer(key, &encode_frames(&frames));
    assert!(status.success(), "signer failed: stderr={stderr}");
    let frames = decode_frames(&stdout);
    assert_eq!(
        frames.len(),
        2,
        "want HelloResponse + SignResponse, got {} frames",
        frames.len()
    );

    let hello_resp = match frames[0].body.clone() {
        Some(signer_frame::Body::HelloResponse(h)) => *h,
        other => panic!("frame[0] expected HelloResponse, got {other:?}"),
    };
    let sign_resp = match frames[1].body.clone() {
        Some(signer_frame::Body::SignResponse(s)) => *s,
        Some(signer_frame::Body::Error(e)) => panic!("signer returned Error: {e:?}"),
        other => panic!("frame[1] expected SignResponse, got {other:?}"),
    };
    (hello_resp, sign_resp)
}

/// DSSE-flavoured PAE; content is irrelevant for sign/verify roundtrip.
const PAE: &[u8] = b"DSSEv1 28 application/vnd.in-toto+json 2 {}";

// --- Hello / capabilities ------------------------------------------

#[test]
fn hello_response_advertises_three_algorithms_and_raw_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let key = write_key(tmp.path(), &[0u8; 32]);
    let (hello_resp, _) = sign_one(&key, RpcAlgorithm::Ed25519);

    assert_eq!(
        hello_resp.protocol,
        Some(ProtocolVersion::ProtocolVersion1.into())
    );
    assert!(hello_resp.signer_id.unwrap().starts_with("mkit-sign-file/"));

    let caps = hello_resp
        .capabilities
        .into_option()
        .expect("capabilities set");
    assert!(caps.algorithms.contains(&RpcAlgorithm::Ed25519.into()));
    assert!(caps.algorithms.contains(&RpcAlgorithm::Secp256k1.into()));
    assert!(caps.algorithms.contains(&RpcAlgorithm::P256.into()));
    assert_eq!(
        caps.key_forms,
        vec![buffa::EnumValue::from(KeyForm::RawBytes)]
    );
    assert_eq!(caps.supports_pin, Some(false));
    assert_eq!(caps.supports_certificate_chain, Some(false));
    assert_eq!(caps.requires_user_presence, Some(false));
}

// --- Per-algorithm round trips --------------------------------------

#[test]
fn ed25519_roundtrip_through_subprocess() {
    let tmp = tempfile::tempdir().unwrap();
    let seed = [0x11u8; 32];
    let key = write_key(tmp.path(), &seed);
    let (_, resp) = sign_one(&key, RpcAlgorithm::Ed25519);

    assert!(resp.key_id.as_deref().unwrap().starts_with("blake3:"));
    let sig = resp.signature.expect("signature present");
    assert_eq!(sig.len(), 64);
    let pubkey = resp.public_key.expect("public_key present");
    assert_eq!(pubkey.len(), 32, "ed25519 pubkey is 32 bytes");

    let kp = mkit_core::sign::KeyPair::from_seed(seed);
    assert_eq!(pubkey, kp.public.0.to_vec());
    verify_signature(Algorithm::Ed25519, &pubkey, PAE, &sig)
        .expect("ed25519 signature must verify");
}

#[test]
fn secp256k1_roundtrip_through_subprocess() {
    let tmp = tempfile::tempdir().unwrap();
    let mut seed = [0u8; 32];
    seed[31] = 1;
    let key = write_key(tmp.path(), &seed);
    let (_, resp) = sign_one(&key, RpcAlgorithm::Secp256k1);

    assert!(resp.key_id.as_deref().unwrap().starts_with("secp256k1:"));
    let sig = resp.signature.expect("signature present");
    assert_eq!(sig.len(), 64, "secp256k1 compact sig is 64 bytes");
    let pubkey = resp.public_key.expect("public_key present");
    // SEC1 compressed pubkey is 33 bytes.
    assert_eq!(pubkey.len(), 33);
    verify_signature(Algorithm::Secp256k1, &pubkey, PAE, &sig)
        .expect("secp256k1 signature must verify");
}

#[test]
fn p256_roundtrip_through_subprocess() {
    let tmp = tempfile::tempdir().unwrap();
    let seed: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    let key = write_key(tmp.path(), &seed);
    let (_, resp) = sign_one(&key, RpcAlgorithm::P256);

    assert!(resp.key_id.as_deref().unwrap().starts_with("p256:"));
    let sig = resp.signature.expect("signature present");
    assert_eq!(sig.len(), 64, "p256 compact sig is 64 bytes");
    let pubkey = resp.public_key.expect("public_key present");
    assert_eq!(pubkey.len(), 33, "p256 SEC1 compressed pubkey is 33 bytes");
    verify_signature(Algorithm::P256, &pubkey, PAE, &sig).expect("p256 signature must verify");
}

// --- Multi-request on one connection -------------------------------

/// The protocol does not require one-shot semantics; the file signer
/// loops until stdin closes. A test driver SHOULD be able to send two
/// `SignRequests` on a single subprocess and get two `SignResponses`.
#[test]
fn two_signs_on_one_connection() {
    let tmp = tempfile::tempdir().unwrap();
    let key = write_key(tmp.path(), &[0x33u8; 32]);

    let frames = vec![
        SignerFrame {
            body: Some(signer_frame::Body::Hello(Box::new(Hello {
                protocol: Some(ProtocolVersion::ProtocolVersion1.into()),
                caller_id: Some("e2e/0.1".into()),
                want_capabilities: Some(false),
                ..Default::default()
            }))),
            ..Default::default()
        },
        SignerFrame {
            body: Some(signer_frame::Body::SignRequest(Box::new(SignRequest {
                algorithm: Some(RpcAlgorithm::Ed25519.into()),
                key_form: Some(KeyForm::RawBytes.into()),
                payload: Some(b"first".to_vec()),
                ..Default::default()
            }))),
            ..Default::default()
        },
        SignerFrame {
            body: Some(signer_frame::Body::SignRequest(Box::new(SignRequest {
                algorithm: Some(RpcAlgorithm::Ed25519.into()),
                key_form: Some(KeyForm::RawBytes.into()),
                payload: Some(b"second".to_vec()),
                ..Default::default()
            }))),
            ..Default::default()
        },
    ];
    let (stdout, stderr, status) = run_signer(&key, &encode_frames(&frames));
    assert!(status.success(), "stderr={stderr}");
    let frames = decode_frames(&stdout);
    assert_eq!(frames.len(), 3);

    // First is HelloResponse, next two are SignResponses with
    // different signatures over the different payloads.
    assert!(matches!(
        frames[0].body,
        Some(signer_frame::Body::HelloResponse(_))
    ));
    let s1 = match &frames[1].body {
        Some(signer_frame::Body::SignResponse(s)) => s.signature.clone().unwrap(),
        other => panic!("expected SignResponse, got {other:?}"),
    };
    let s2 = match &frames[2].body {
        Some(signer_frame::Body::SignResponse(s)) => s.signature.clone().unwrap(),
        other => panic!("expected SignResponse, got {other:?}"),
    };
    assert_ne!(s1, s2);
}

// --- Error path: unsupported key form -------------------------------

#[test]
fn pkcs8_key_form_returns_unsupported_error() {
    let tmp = tempfile::tempdir().unwrap();
    let key = write_key(tmp.path(), &[0u8; 32]);

    let frames = vec![
        SignerFrame {
            body: Some(signer_frame::Body::Hello(Box::new(Hello {
                protocol: Some(ProtocolVersion::ProtocolVersion1.into()),
                want_capabilities: Some(false),
                ..Default::default()
            }))),
            ..Default::default()
        },
        SignerFrame {
            body: Some(signer_frame::Body::SignRequest(Box::new(SignRequest {
                algorithm: Some(RpcAlgorithm::Ed25519.into()),
                // PKCS#8 — the file signer doesn't support it.
                key_form: Some(KeyForm::Pkcs8Der.into()),
                payload: Some(PAE.to_vec()),
                ..Default::default()
            }))),
            ..Default::default()
        },
    ];
    let (stdout, _stderr, status) = run_signer(&key, &encode_frames(&frames));
    assert!(
        status.success(),
        "binary keeps running on per-request errors"
    );
    let frames = decode_frames(&stdout);
    let err = match &frames[1].body {
        Some(signer_frame::Body::Error(e)) => e,
        other => panic!("expected Error frame, got {other:?}"),
    };
    assert_eq!(
        err.code.as_ref().unwrap().to_i32(),
        ErrorCode::UnsupportedKeyForm as i32
    );
}

// --- Permission enforcement (Unix only) -----------------------------

/// Mode 0644 (world-readable) MUST cause the signer to bail out at
/// startup, before it reads a single frame. Stdout MUST stay empty on
/// that path — no half-formed frame, no partial response.
#[cfg(unix)]
#[test]
fn rejects_key_with_world_readable_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("bad.key");
    std::fs::write(&path, [0x22u8; 32]).unwrap();

    let mut dperm = std::fs::metadata(tmp.path()).unwrap().permissions();
    dperm.set_mode(0o700);
    std::fs::set_permissions(tmp.path(), dperm).unwrap();
    let mut perm = std::fs::metadata(&path).unwrap().permissions();
    perm.set_mode(0o644);
    std::fs::set_permissions(&path, perm).unwrap();

    // Send a normal Hello frame; the binary should never get to it.
    let frames = vec![SignerFrame {
        body: Some(signer_frame::Body::Hello(Box::new(Hello {
            protocol: Some(ProtocolVersion::ProtocolVersion1.into()),
            want_capabilities: Some(false),
            ..Default::default()
        }))),
        ..Default::default()
    }];
    let (stdout, stderr, status) = run_signer(&path, &encode_frames(&frames));
    assert!(!status.success(), "signer must reject 0644 key");
    assert!(stdout.is_empty(), "no stdout on setup-phase error");
    assert!(
        stderr.contains("0644") || stderr.contains("permissions"),
        "stderr should mention the permission failure, got {stderr:?}"
    );
}

#[cfg(unix)]
#[test]
fn accepts_key_with_owner_only_permissions() {
    let tmp = tempfile::tempdir().unwrap();
    let key = write_key(tmp.path(), &[0x22u8; 32]);
    let (_, resp) = sign_one(&key, RpcAlgorithm::Ed25519);
    assert!(resp.signature.is_some());
}
