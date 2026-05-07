//! Build script — detect whether a real TPM device is reachable on
//! this host, so integration tests gate themselves at compile time.
//!
//! We emit the `tpm_available` cfg flag ONLY when `/dev/tpmrm0` or
//! `/dev/tpm0` exists. Earlier revisions also accepted "pkg-config
//! reports tss2-esys is installed", but that produced false positives
//! on Ubuntu CI runners — `libtss2-dev` is installed for the
//! Linux-only build (so the workspace compiles), but the runner has
//! no TPM hardware and `Tss2_Tcti_Device_Init` fails the moment a
//! test calls into the TPM. Requiring the actual device file matches
//! what the runtime test path actually needs.
//!
//! The cfg is *informational only*: `cargo test -p mkit-sign-tpm` on
//! a bare macOS host (no TPM) still compiles, but tests tagged
//! `#[cfg_attr(not(tpm_available), ignore)]` are skipped by default
//! and remain runnable via `cargo test -- --ignored`.

use std::path::Path;

fn main() {
    // Cargo-stable well-known name. Rustc 1.80+ warns on unknown cfgs
    // unless we declare them; doing so keeps the build warning-free
    // on modern toolchains.
    println!("cargo:rustc-check-cfg=cfg(tpm_available)");

    if has_tpm_device() {
        println!("cargo:rustc-cfg=tpm_available");
    }

    // Rebuild when the user's TPM stack changes. The device-presence
    // check is path-existence only.
    println!("cargo:rerun-if-changed=build.rs");
}

fn has_tpm_device() -> bool {
    Path::new("/dev/tpmrm0").exists() || Path::new("/dev/tpm0").exists()
}
