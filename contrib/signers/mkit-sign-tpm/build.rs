//! Build script — detect whether a TPM 2.0 TSS stack is available on
//! this host, so integration tests can gate themselves at compile time.
//!
//! We emit the `tpm_available` cfg flag when either of these is true:
//!
//!   1. `pkg-config --exists tss2-esys` succeeds (the native library
//!      is installed — Linux with `libtss2-dev` or equivalent).
//!   2. `/dev/tpmrm0` or `/dev/tpm0` exists (a real TPM or kernel
//!      resource-manager device is visible).
//!
//! The cfg is *informational only*: `cargo test -p mkit-sign-tpm` on
//! a bare macOS host (no TPM, no tpm2-tss package) still compiles
//! fine, but tests tagged `#[cfg_attr(not(tpm_available), ignore)]`
//! are skipped by default on those hosts and runnable on request via
//! `cargo test -- --ignored`.

use std::path::Path;
use std::process::Command;

fn main() {
    // Cargo-stable well-known name. Rustc 1.80+ warns on unknown cfgs
    // unless we declare them; doing so keeps the build warning-free
    // on modern toolchains.
    println!("cargo:rustc-check-cfg=cfg(tpm_available)");

    if has_pkg_config_tss() || has_tpm_device() {
        println!("cargo:rustc-cfg=tpm_available");
    }

    // Rebuild when the user's TPM stack changes. No env vars to pin;
    // `pkg-config` and `/dev/tpm*` are checked at build time only.
    println!("cargo:rerun-if-changed=build.rs");
}

fn has_pkg_config_tss() -> bool {
    Command::new("pkg-config")
        .args(["--exists", "tss2-esys"])
        .status()
        .is_ok_and(|s| s.success())
}

fn has_tpm_device() -> bool {
    Path::new("/dev/tpmrm0").exists() || Path::new("/dev/tpm0").exists()
}
