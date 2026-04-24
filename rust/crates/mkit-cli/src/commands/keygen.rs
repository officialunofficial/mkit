//! `mkit keygen` — generate a fresh Ed25519 signing key at
//! `.mkit/keys/default.key`.

use std::io::Write;

use mkit_core::sign::{KeyPair, save_key};

use crate::exit;
use crate::format;

#[must_use]
pub fn run(_args: &[String]) -> u8 {
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cannot read cwd: {e}"), exit::NOINPUT),
    };
    let key_path = cwd.join(crate::config::DEFAULT_SIGNING_KEY);
    if key_path.exists() {
        return emit_err(
            &format!("signing key already exists: {}", key_path.display()),
            exit::GENERAL_ERROR,
        );
    }
    let kp = match KeyPair::generate() {
        Ok(kp) => kp,
        Err(e) => return emit_err(&format!("rng failed: {e}"), exit::GENERAL_ERROR),
    };
    if let Err(e) = save_key(&key_path, &kp) {
        return emit_err(&format!("save key: {e}"), exit::CANTCREAT);
    }
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "generated signing key at {}", key_path.display());
    let _ = writeln!(stdout, "public:  ed25519:{}", hex32(&kp.public.0));
    let _ = writeln!(
        stdout,
        "identity: {}",
        format::short_identity(&mkit_core::Identity::ed25519(kp.public.0))
    );
    exit::OK
}

fn hex32(bytes: &[u8; 32]) -> String {
    let h: mkit_core::hash::Hash = *bytes;
    mkit_core::hash::to_hex(&h)
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
