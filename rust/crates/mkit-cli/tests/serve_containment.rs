//! Integration tests for `mkit serve` path-containment (finding A1).
//!
//! These are driven by spawning the real `mkit` binary so we can set
//! `MKIT_SERVE_ROOT` in the child environment without mutating the
//! parent process state. The parent crate has `#![forbid(unsafe_code)]`,
//! so `std::env::set_var` (unsafe since edition 2024) is not available
//! in-process tests.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

/// Minimal valid HELLO frame the server expects before entering the loop.
/// We never send anything after HELLO — the server will either reject
/// the path before reading any frame (fast-exit) or run the handshake
/// and then EOF out.
fn encode_hello_frame() -> Vec<u8> {
    // Frame = [op(1)] [len(4-LE)] [payload]. We piggyback on the crate's
    // protocol module via a dependency? Instead, construct by hand per
    // docs/SSH-TRANSPORT.md: hello payload = ver(1) + name_len(1) + name
    // + ver_len(1) + ver_str. Name = "mkit", ver = "cli/test".
    let name = b"mkit";
    let ver = b"cli/test";
    let mut payload = Vec::new();
    payload.push(1u8); // SSH_PROTO_VERSION
    payload.push(u8::try_from(name.len()).unwrap());
    payload.extend_from_slice(name);
    payload.push(u8::try_from(ver.len()).unwrap());
    payload.extend_from_slice(ver);

    let mut frame = Vec::new();
    frame.push(0x00u8); // OP_HELLO
    frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
    frame.extend_from_slice(&payload);
    frame
}

fn run_serve(env: &[(&str, &Path)], arg: &str) -> std::process::ExitStatus {
    let mut cmd = Command::new(mkit_bin());
    cmd.arg("serve").arg(arg);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn mkit serve");
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(&encode_hello_frame());
        drop(stdin);
    }
    let out = child.wait_with_output().expect("wait mkit serve");
    if !out.stderr.is_empty() {
        eprintln!("mkit serve stderr: {}", String::from_utf8_lossy(&out.stderr));
    }
    out.status
}

#[test]
fn serve_rejects_path_outside_serve_root() {
    let root_td = tempfile::tempdir().unwrap();
    let outside_td = tempfile::tempdir().unwrap();
    fs::create_dir_all(outside_td.path().join(".mkit")).unwrap();

    let status = run_serve(
        &[("MKIT_SERVE_ROOT", root_td.path())],
        outside_td.path().to_str().unwrap(),
    );
    // exit::NOPERM = 77 (sysexits EX_NOPERM).
    assert_eq!(status.code(), Some(77));
}

#[test]
fn serve_accepts_path_inside_serve_root() {
    let root_td = tempfile::tempdir().unwrap();
    let inside = root_td.path().join("repo");
    fs::create_dir_all(inside.join(".mkit")).unwrap();

    let status = run_serve(
        &[("MKIT_SERVE_ROOT", root_td.path())],
        inside.to_str().unwrap(),
    );
    // Handshake succeeds, client closes stdin → server exits OK(0).
    assert_eq!(status.code(), Some(0));
}

#[test]
fn serve_rejects_nonrepo_directory() {
    let td = tempfile::tempdir().unwrap();
    // No .mkit/ subdir.
    let status = run_serve(&[], td.path().to_str().unwrap());
    // exit::DATAERR = 65.
    assert_eq!(status.code(), Some(65));
}

#[test]
fn serve_rejects_missing_path() {
    let status = run_serve(&[], "/definitely/does/not/exist/xyzzy/mkit-serve");
    // exit::NOINPUT = 66.
    assert_eq!(status.code(), Some(66));
}
