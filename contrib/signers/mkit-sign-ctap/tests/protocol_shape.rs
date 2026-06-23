//! CLI smoke tests for `mkit-sign-ctap`.
//!
//! Wire-protocol behaviour is unit-tested in `src/server.rs` against
//! the mock CTAP device. These tests exercise the binary itself: argv
//! parsing, help text, exit codes. The hardware-gated end-to-end test
//! lives in `tests/e2e.sh`.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

#[test]
fn binary_help_exits_zero() {
    let bin = env!("CARGO_BIN_EXE_mkit-sign-ctap");
    let out = std::process::Command::new(bin)
        .arg("--help")
        .output()
        .unwrap();
    assert!(out.status.success(), "--help must exit 0");
}

#[test]
fn binary_unknown_subcommand_fails() {
    let bin = env!("CARGO_BIN_EXE_mkit-sign-ctap");
    let out = std::process::Command::new(bin).arg("wat").output().unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(!out.stderr.is_empty());
}

#[test]
fn binary_no_subcommand_fails_with_usage_hint() {
    let bin = env!("CARGO_BIN_EXE_mkit-sign-ctap");
    let out = std::process::Command::new(bin).output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("subcommand"),
        "stderr should mention the missing subcommand: {stderr:?}"
    );
}
