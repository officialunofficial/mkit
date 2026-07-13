//! Regression test for issue #694: `--pin` on argv must emit a
//! deprecation warning on stderr rather than being silently accepted
//! forever — it's readable by any other local user via `ps` /
//! `/proc/<pid>/cmdline` (docs/THREAT-MODEL.md §3.2's exposure class).
//! See docs/specs/SPEC-EXTERNAL-SIGNER.md §4 for the in-band
//! `PinPrompt`/`PinResponse` round trip `--pin` is being replaced by.
//!
//! Drives the real compiled binary (no `ctap-hw` feature needed — the
//! warning fires during argv parsing, before any hardware call).

use std::process::{Command, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit-sign-ctap")
}

#[test]
fn sign_with_pin_argv_emits_deprecation_warning() {
    let mut child = Command::new(bin())
        .args(["sign", "--credential-id", "AAAA", "--pin", "1234"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mkit-sign-ctap");
    // Close stdin immediately: the protocol loop exits cleanly on the
    // resulting truncated length prefix (EOF). We only care about the
    // stderr warning printed before it ever tries to read a frame.
    drop(child.stdin.take());
    let output = child.wait_with_output().expect("wait for signer");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("deprecated"),
        "expected a --pin deprecation warning on stderr, got: {stderr}"
    );
}

#[test]
fn enroll_with_pin_argv_emits_deprecation_warning() {
    // Without the `ctap-hw` feature `enroll` fails closed (no hardware
    // support) — the deprecation warning still fires first, during
    // argv parsing, before that failure.
    let output = Command::new(bin())
        .args([
            "enroll",
            "--rp-id",
            "mkit.local",
            "--user-name",
            "alice",
            "--pin",
            "1234",
        ])
        .output()
        .expect("run mkit-sign-ctap enroll");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("deprecated"),
        "expected a --pin deprecation warning on stderr, got: {stderr}"
    );
}

#[test]
fn sign_without_pin_argv_has_no_deprecation_warning() {
    let mut child = Command::new(bin())
        .args(["sign", "--credential-id", "AAAA"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mkit-sign-ctap");
    drop(child.stdin.take());
    let output = child.wait_with_output().expect("wait for signer");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("deprecated"),
        "no --pin on argv should not warn, got: {stderr}"
    );
}
