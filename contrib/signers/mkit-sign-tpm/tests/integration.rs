#![allow(clippy::items_after_statements)]
#![allow(clippy::cast_possible_truncation)]

//! Integration tests for `mkit-sign-tpm`.
//!
//! Wire-protocol behaviour is unit-tested in `src/server.rs` against
//! an in-process P-256 mock signer. These tests exercise the binary
//! itself: argv parsing, help text, exit codes, and (when a TPM is
//! available + the `tpm2` feature is on) a real keygen → sign →
//! delete round-trip via framed mkit-rpc messages.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use buffa::Message;
use mkit_rpc::mkit::rpc::v1::signer::{Hello, SignRequest, SignerFrame, signer_frame};
use mkit_rpc::mkit::rpc::v1::{Algorithm as RpcAlgorithm, ErrorCode, KeyForm, ProtocolVersion};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mkit-sign-tpm"))
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
        if bytes.len() < len {
            break;
        }
        out.push(SignerFrame::decode_from_slice(&bytes[..len]).unwrap());
        bytes = &bytes[len..];
    }
    out
}

/// Help text prints on `-h`. Doesn't require a TPM.
#[test]
fn help_flag_exits_cleanly() {
    let out = Command::new(binary()).arg("-h").output().expect("spawn -h");
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("mkit-sign-tpm"));
    assert!(stderr.contains("keygen") && stderr.contains("sign"));
}

#[test]
fn unknown_subcommand_errors() {
    let out = Command::new(binary())
        .arg("wibble")
        .output()
        .expect("spawn");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unknown subcommand") || stderr.contains("wibble"),
        "expected unknown-subcommand message, got {stderr}"
    );
}

/// Drive the framed protocol with an unsupported algorithm and assert
/// the binary returns an Error frame (it does NOT exit non-zero per
/// request — per-request errors are protocol frames, not exit codes).
/// Doesn't require a TPM: the algorithm gate runs before any TPM call.
#[test]
fn rejects_non_p256_algorithm_via_protocol() {
    let frames = vec![
        SignerFrame {
            body: Some(signer_frame::Body::Hello(Box::new(Hello {
                protocol: Some(ProtocolVersion::ProtocolVersion1.into()),
                ..Default::default()
            }))),
            ..Default::default()
        },
        SignerFrame {
            body: Some(signer_frame::Body::SignRequest(Box::new(SignRequest {
                algorithm: Some(RpcAlgorithm::Ed25519.into()),
                key_form: Some(KeyForm::OpaqueHandle.into()),
                key_ref: Some(0x8101_0001u32.to_be_bytes().to_vec()),
                payload: Some(b"x".to_vec()),
                ..Default::default()
            }))),
            ..Default::default()
        },
    ];

    let mut child = Command::new(binary())
        .args(["sign", "--handle", "0x81010001"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    {
        let stdin = child.stdin.as_mut().unwrap();
        let _ = stdin.write_all(&encode(&frames));
    }
    let out = child.wait_with_output().expect("wait");
    assert!(
        out.status.success(),
        "binary should exit 0 on per-request error; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let frames = decode(&out.stdout);
    let err = match frames[1].body.clone() {
        Some(signer_frame::Body::Error(e)) => e,
        other => panic!("expected Error, got {other:?}"),
    };
    assert_eq!(
        err.code.as_ref().unwrap().to_i32(),
        ErrorCode::UnsupportedAlgorithm as i32
    );
}

// -- TPM-dependent path ------------------------------------------------

/// End-to-end keygen → framed sign → delete on a real TPM (or swtpm
/// simulator). Builds with `--features tpm2`; ignored when not running
/// against TPM hardware.
#[test]
#[cfg_attr(
    not(tpm_available),
    ignore = "no TPM detected at build time; run with --ignored on a TPM-equipped host"
)]
fn tpm_keygen_sign_delete_roundtrip() {
    let handle_str = format!("0x810101{:02x}", std::process::id() as u8);
    let handle: u32 = u32::from_str_radix(handle_str.trim_start_matches("0x"), 16).unwrap();

    // Keygen — still emits keyid on stdout (CLI utility, not a
    // protocol call).
    let keygen_out = Command::new(binary())
        .args(["keygen", "--handle", &handle_str])
        .output()
        .expect("spawn keygen");
    if !keygen_out.status.success() {
        let stderr = String::from_utf8_lossy(&keygen_out.stderr);
        if stderr.contains("built without the `tpm2` feature") {
            eprintln!(
                "skipping TPM test: binary lacks tpm2 feature — run `cargo test -p mkit-sign-tpm --features tpm2 -- --ignored`"
            );
            return;
        }
        panic!("keygen failed: {stderr}");
    }

    let keyid = String::from_utf8_lossy(&keygen_out.stdout)
        .trim()
        .to_string();
    assert!(
        keyid.starts_with("p256:") && keyid.len() == 71,
        "keygen keyid malformed: {keyid}"
    );

    // Sign — framed protocol.
    let frames = vec![
        SignerFrame {
            body: Some(signer_frame::Body::Hello(Box::new(Hello {
                protocol: Some(ProtocolVersion::ProtocolVersion1.into()),
                ..Default::default()
            }))),
            ..Default::default()
        },
        SignerFrame {
            body: Some(signer_frame::Body::SignRequest(Box::new(SignRequest {
                algorithm: Some(RpcAlgorithm::P256.into()),
                key_form: Some(KeyForm::OpaqueHandle.into()),
                key_ref: Some(handle.to_be_bytes().to_vec()),
                payload: Some(b"DSSEv1 28 application/vnd.in-toto+json 2 {}".to_vec()),
                ..Default::default()
            }))),
            ..Default::default()
        },
    ];
    let mut child = Command::new(binary())
        .args(["sign", "--handle", &handle_str])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sign");
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(&encode(&frames)).unwrap();
    }
    let sign_out = child.wait_with_output().expect("wait sign");
    assert!(
        sign_out.status.success(),
        "sign failed: stderr={}",
        String::from_utf8_lossy(&sign_out.stderr)
    );
    let resp_frames = decode(&sign_out.stdout);
    let sign_resp = match resp_frames[1].body.clone() {
        Some(signer_frame::Body::SignResponse(s)) => *s,
        Some(signer_frame::Body::Error(e)) => panic!("server returned Error: {e:?}"),
        other => panic!("expected SignResponse, got {other:?}"),
    };
    assert_eq!(sign_resp.signature.as_ref().map(Vec::len), Some(64));
    assert_eq!(sign_resp.public_key.as_ref().map(Vec::len), Some(33));

    // Cleanup.
    let _ = Command::new(binary())
        .args(["delete", "--handle", &handle_str])
        .output();
}
