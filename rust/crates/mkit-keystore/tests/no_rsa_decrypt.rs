// Regression guard for RUSTSEC-2023-0071.
//
// The yubikey 0.9.0-pre.0 crate transitively pulls in an RSA crate
// version vulnerable to a Marvin-attack timing leak on the private-key
// decrypt path. mkit ignores this advisory in `rust/deny.toml` because
// no mkit-* crate calls the affected entrypoint — we only ever invoke
// the *signing* paths (`yubikey::piv::sign_data`) on yubikey devices,
// never `yubikey::piv::decrypt_data` (or any other PIV-RSA-decrypt
// surface).
//
// This test scans every Rust source file in the workspace and fails
// if a future patch reintroduces a reference to the affected
// entrypoint. If it ever needs to legitimately fire, the deny.toml
// ignore MUST be dropped at the same time (or, at minimum, this test
// removed with a follow-up issue and an updated advisory).
//
// Implementation note: we do not use compile_fail or trybuild-style
// negative tests here because the symbol lives in a transitive crate
// and a missing reference IS the success state — we have nothing to
// compile-fail against. A textual scan is the simplest possible
// regression check that keeps working as the workspace grows.

use std::fs;
use std::path::{Path, PathBuf};

/// Tokens that indicate a call into the vulnerable RSA decrypt path.
/// Keep this list narrow so the test does not false-positive on
/// strings that legitimately appear in comments or doc.
const FORBIDDEN_TOKENS: &[&str] = &["yubikey::piv::decrypt_data", "piv::decrypt_data"];

/// Walk `dir` recursively and collect every `.rs` file path. We bail
/// on `target/` so a cargo build with debug artifacts doesn't slow
/// the test or trip on generated code.
fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if path.is_dir() {
            // Skip build artifacts and vendored dependencies; we only
            // want first-party mkit source.
            if file_name == "target" || file_name == ".git" || file_name == "node_modules" {
                continue;
            }
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            // Skip this very test file — it has to mention the
            // forbidden tokens to assert against them.
            if file_name == "no_rsa_decrypt.rs" {
                continue;
            }
            out.push(path);
        }
    }
}

#[test]
fn workspace_does_not_call_yubikey_rsa_decrypt() {
    // CARGO_MANIFEST_DIR points at the mkit-keystore crate; walk up
    // two levels to land on `rust/crates`, then one more to land on
    // `rust/`. We scan the whole `rust/` tree so any new crate that
    // grows a `yubikey::piv::decrypt_data` reference is caught.
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let rust_root = crate_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("CARGO_MANIFEST_DIR has at least two ancestors")
        .to_path_buf();

    let mut rs_files = Vec::new();
    collect_rs_files(&rust_root, &mut rs_files);
    assert!(
        !rs_files.is_empty(),
        "expected to scan some .rs files under {}",
        rust_root.display()
    );

    let mut offenders: Vec<(PathBuf, &'static str)> = Vec::new();
    for path in &rs_files {
        let Ok(contents) = fs::read_to_string(path) else {
            continue;
        };
        for token in FORBIDDEN_TOKENS {
            if contents.contains(token) {
                offenders.push((path.clone(), token));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "RUSTSEC-2023-0071 regression: mkit-* crate(s) now reference the yubikey RSA decrypt path. \
         If this is intentional, drop the deny.toml ignore for RUSTSEC-2023-0071 at the same time. \
         Offenders: {offenders:?}"
    );
}
