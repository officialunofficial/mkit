//! Snapshot test for the `mkit version` stdout contract.
//!
//! This is the byte-exact contract asserted by Homebrew / Scoop. Any
//! cosmetic change — extra whitespace, a newline at the wrong place,
//! a prefix like `mkit-rs` — breaks downstream packaging and must be
//! treated as a major-version semver break. See `docs/CLI.md`.

use std::process::Command;

/// Resolve the built `mkit` binary. Cargo sets `CARGO_BIN_EXE_<name>`
/// for every binary target in the *current* crate, which is exactly
/// `mkit-cli` here.
fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

#[test]
fn version_stdout_is_byte_exact() {
    let output = Command::new(mkit_bin())
        .arg("version")
        .output()
        .expect("spawn `mkit version`");
    assert!(output.status.success(), "`mkit version` must exit 0");

    let expected = format!("mkit {}\n", env!("CARGO_PKG_VERSION"));
    let actual = String::from_utf8(output.stdout).expect("stdout is utf-8");
    assert_eq!(
        actual, expected,
        "`mkit version` stdout contract broken — see docs/CLI.md"
    );

    // stderr must be empty — we do not print warnings on the happy
    // path.
    assert!(
        output.stderr.is_empty(),
        "`mkit version` must not write to stderr, got: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
}
