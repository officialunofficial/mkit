//! `mkit keygen` — generate a fresh signing key for one of the three
//! attestation algorithms.
//!
//! ```text
//! mkit keygen [--algorithm ed25519|secp256k1|p256] [--force] [--print-pubkey]
//! ```
//!
//! Behaviour:
//!
//! * `--algorithm` defaults to `ed25519` (backward-compat with the
//!   original single-algorithm command). `ed25519` writes to
//!   `.mkit/keys/default.key`; `secp256k1` / `p256` write to the path
//!   configured via `attest.<algo>_key_path` (default
//!   `.mkit/keys/<algo>.key`).
//! * `--force` overwrites an existing key file; without it, refuse with
//!   a clear error.
//! * `--print-pubkey` emits the canonical keyid on stdout so downstream
//!   tooling can populate trust-roots entries without needing to parse
//!   key files:
//!     * `ed25519:<64-hex>`
//!     * `secp256k1:<66-hex>` (33-byte compressed SEC1)
//!     * `p256:<66-hex>`     (33-byte compressed SEC1)
//!
//! Key-file layout mirrors what the repo-key signer factory loads:
//! a raw 32-byte secret, mode `0600` on Unix. The mode is set on the
//! open file handle (not via a post-write `chmod`/`rename`) so the
//! secret is never briefly world-readable in a TOCTOU window between
//! creating the file and tightening its permissions.

use std::io::Write;
use std::path::Path;

use clap::Parser;
use mkit_attest::Algorithm;
use mkit_core::sign::{KeyPair, load_raw_32, save_key, save_raw_32};
use zeroize::Zeroizing;

use crate::clap_shim;
use crate::commands::attest_factory;
use crate::exit;
use crate::format;

#[derive(Debug, Parser)]
#[command(name = "mkit keygen", about = "Generate a fresh signing key.")]
struct KeygenOpts {
    /// Algorithm: `ed25519` (default), `secp256k1`, or `p256`.
    #[arg(long)]
    algorithm: Option<String>,
    /// Overwrite an existing key file at the target path.
    #[arg(long)]
    force: bool,
    /// Emit the canonical keyid on stdout for trust-roots entries.
    #[arg(long)]
    print_pubkey: bool,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let parsed = match clap_shim::parse::<KeygenOpts>("mkit keygen", args) {
        Ok(o) => o,
        Err(code) => return code,
    };

    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cannot read cwd: {e}"), exit::NOINPUT),
    };

    let alg_str = parsed
        .algorithm
        .clone()
        .unwrap_or_else(|| "ed25519".to_owned());
    let Ok(algorithm) = attest_factory::parse_algorithm(&alg_str) else {
        return emit_err(
            &format!("unknown algorithm '{alg_str}' — expected one of: ed25519, secp256k1, p256"),
            exit::USAGE,
        );
    };

    // Resolve the target key path from config. Each algorithm reads
    // its own config knob so `mkit keygen`, `mkit commit`, and
    // `mkit attest` agree on where the key lives — a user with
    // `signing_key = /home/u/.mkit/global.key` in their user-scoped
    // config gets that path written/read consistently.
    let layout = super::resolve_layout(&cwd);
    let cfg = match crate::config::read_or_default(&layout) {
        Ok(c) => c,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };
    let rel_path: &str = match algorithm {
        Algorithm::Ed25519 => {
            if cfg.signing_key.is_empty() {
                crate::config::DEFAULT_SIGNING_KEY
            } else {
                cfg.signing_key.as_str()
            }
        }
        Algorithm::Secp256k1 => cfg.attest.secp256k1_key_path_or_default(),
        Algorithm::P256 => cfg.attest.p256_key_path_or_default(),
        #[cfg(feature = "bls-threshold")]
        Algorithm::Bls12381Threshold => {
            return emit_err(
                "BLS threshold keygen is not supported here; use `mkit key generate` (issue #160)",
                exit::UNAVAILABLE,
            );
        }
    };
    let key_path = match crate::config::resolve_key_path(&layout, rel_path) {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("{e}"), exit::CONFIG_ERROR),
    };

    match algorithm {
        Algorithm::Ed25519 => run_ed25519(&key_path, parsed.force, parsed.print_pubkey),
        Algorithm::Secp256k1 => run_secp256k1(&key_path, parsed.force, parsed.print_pubkey),
        Algorithm::P256 => run_p256(&key_path, parsed.force, parsed.print_pubkey),
        #[cfg(feature = "bls-threshold")]
        Algorithm::Bls12381Threshold => emit_err(
            "BLS threshold keygen is not supported here; use `mkit key generate` (issue #160)",
            exit::UNAVAILABLE,
        ),
    }
}

fn run_ed25519(key_path: &Path, force: bool, print_pubkey: bool) -> u8 {
    let exists = key_path.exists();
    // When `--print-pubkey` is set and the key already exists, load it
    // and print — acts as an idempotent "show me the pubkey" path that
    // downstream tooling can script against.
    if exists && print_pubkey && !force {
        let kp = match mkit_core::sign::load_key(key_path) {
            Ok(kp) => kp,
            Err(e) => return emit_err(&format!("load key: {e}"), exit::GENERAL_ERROR),
        };
        print_ed25519_pubkey(&kp);
        return exit::OK;
    }
    if exists && !force {
        return emit_err(
            &format!(
                "signing key already exists: {} (pass --force to overwrite)",
                key_path.display()
            ),
            exit::GENERAL_ERROR,
        );
    }
    let kp = match KeyPair::generate() {
        Ok(kp) => kp,
        Err(e) => return emit_err(&format!("rng failed: {e}"), exit::GENERAL_ERROR),
    };
    if let Err(e) = save_key(key_path, &kp) {
        return emit_err(&format!("save key: {e}"), exit::CANTCREAT);
    }
    let pk_hex = hex32(&kp.public.0);
    {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "generated signing key at {}", key_path.display());
        let _ = writeln!(stderr, "public:  ed25519:{pk_hex}");
        let _ = writeln!(
            stderr,
            "identity: {}",
            format::short_identity(&mkit_core::Identity::ed25519(kp.public.0))
        );
    }
    if print_pubkey {
        // The key string IS the data when --print-pubkey is set.
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "ed25519:{pk_hex}");
    }
    exit::OK
}

fn run_secp256k1(key_path: &Path, force: bool, print_pubkey: bool) -> u8 {
    // Idempotent read path for --print-pubkey.
    if key_path.exists() && print_pubkey && !force {
        let secret = match load_raw_32(key_path) {
            Ok(s) => s,
            Err(e) => return emit_err(&format!("load key: {e}"), exit::GENERAL_ERROR),
        };
        // Borrow through `from_seed_zeroizing` so no plain `[u8; 32]`
        // is materialised on this frame — the constructor copies
        // through a scratch buffer that it scrubs itself.
        let signer = match mkit_attest::signer_k256::Secp256k1Signer::from_seed_zeroizing(&secret) {
            Ok(s) => s,
            Err(e) => return emit_err(&format!("invalid secp256k1 key: {e}"), exit::GENERAL_ERROR),
        };
        let pk = signer.public_key_sec1();
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "secp256k1:{}", hex_lower(&pk));
        return exit::OK;
    }
    if key_path.exists() && !force {
        return emit_err(
            &format!(
                "signing key already exists: {} (pass --force to overwrite)",
                key_path.display()
            ),
            exit::GENERAL_ERROR,
        );
    }

    // Generate a valid secp256k1 scalar. Sampling uniformly from a 32-byte
    // space: the probability of hitting zero or >= n on a single draw is
    // ~2^-128 for the >= n case and 2^-256 for zero; a small retry loop
    // just lets `Secp256k1Signer::new` be the authoritative validator.
    let (signer, secret) = match generate_secp256k1_signer() {
        Ok(x) => x,
        Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
    };
    if let Err(e) = save_raw_32(key_path, &secret) {
        return emit_err(&format!("save key: {e}"), exit::CANTCREAT);
    }
    drop(secret);

    let pk = signer.public_key_sec1();
    {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "generated signing key at {}", key_path.display());
        let _ = writeln!(stderr, "public:  secp256k1:{}", hex_lower(&pk));
    }
    if print_pubkey {
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "secp256k1:{}", hex_lower(&pk));
    }
    exit::OK
}

fn run_p256(key_path: &Path, force: bool, print_pubkey: bool) -> u8 {
    if key_path.exists() && print_pubkey && !force {
        let secret = match load_raw_32(key_path) {
            Ok(s) => s,
            Err(e) => return emit_err(&format!("load key: {e}"), exit::GENERAL_ERROR),
        };
        // Borrow-through pattern matches the secp256k1 arm above.
        let signer = match mkit_attest::signer_p256::P256Signer::from_seed_zeroizing(&secret) {
            Ok(s) => s,
            Err(e) => return emit_err(&format!("invalid p256 key: {e}"), exit::GENERAL_ERROR),
        };
        let pk = signer.public_key_sec1();
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "p256:{}", hex_lower(&pk));
        return exit::OK;
    }
    if key_path.exists() && !force {
        return emit_err(
            &format!(
                "signing key already exists: {} (pass --force to overwrite)",
                key_path.display()
            ),
            exit::GENERAL_ERROR,
        );
    }

    let (signer, secret) = match generate_p256_signer() {
        Ok(x) => x,
        Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
    };
    if let Err(e) = save_raw_32(key_path, &secret) {
        return emit_err(&format!("save key: {e}"), exit::CANTCREAT);
    }
    drop(secret);

    let pk = signer.public_key_sec1();
    {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "generated signing key at {}", key_path.display());
        let _ = writeln!(stderr, "public:  p256:{}", hex_lower(&pk));
    }
    if print_pubkey {
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "p256:{}", hex_lower(&pk));
    }
    exit::OK
}

/// Draw a 32-byte secret until the curve's `SigningKey::from_bytes`
/// accepts it (rejects zero and values >= n). The retry loop is
/// effectively one-shot; 256 iterations is an upper bound that would
/// require astronomical RNG bias to reach.
///
/// The returned secret lives inside a [`Zeroizing`] wrapper so it is
/// scrubbed when the keygen command finishes — the only persistent
/// copy is the one written to `path` at mode 0600. Note: the signer
/// constructor takes the secret by value (Copy), so we must pass a
/// fresh copy in; the wrapper here scrubs the local buffer after.
fn generate_secp256k1_signer() -> Result<
    (
        mkit_attest::signer_k256::Secp256k1Signer,
        Zeroizing<[u8; 32]>,
    ),
    String,
> {
    for _ in 0..256 {
        let mut buf: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
        getrandom::fill(buf.as_mut_slice()).map_err(|e| format!("rng failed: {e}"))?;
        if let Ok(signer) = mkit_attest::signer_k256::Secp256k1Signer::from_seed_zeroizing(&buf) {
            return Ok((signer, buf));
        }
        // `buf` drops here, scrubbing the rejected scalar.
    }
    Err("rng produced 256 consecutive invalid secp256k1 scalars (impossible in practice)".into())
}

fn generate_p256_signer()
-> Result<(mkit_attest::signer_p256::P256Signer, Zeroizing<[u8; 32]>), String> {
    for _ in 0..256 {
        let mut buf: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
        getrandom::fill(buf.as_mut_slice()).map_err(|e| format!("rng failed: {e}"))?;
        if let Ok(signer) = mkit_attest::signer_p256::P256Signer::from_seed_zeroizing(&buf) {
            return Ok((signer, buf));
        }
    }
    Err("rng produced 256 consecutive invalid p256 scalars (impossible in practice)".into())
}

fn print_ed25519_pubkey(kp: &KeyPair) {
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "ed25519:{}", hex32(&kp.public.0));
}

// -- hex helpers --

fn hex32(bytes: &[u8; 32]) -> String {
    let h: mkit_core::hash::Hash = *bytes;
    mkit_core::hash::to_hex(&h)
}

fn hex_lower(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push(HEX[(byte >> 4) as usize] as char);
        s.push(HEX[(byte & 0x0F) as usize] as char);
    }
    s
}

use super::error as emit_err;

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::KeygenOpts;

    #[test]
    fn parse_defaults() {
        let p = KeygenOpts::try_parse_from(["mkit keygen"]).unwrap();
        assert!(p.algorithm.is_none());
        assert!(!p.force);
        assert!(!p.print_pubkey);
    }

    #[test]
    fn parse_all_flags() {
        let p = KeygenOpts::try_parse_from([
            "mkit keygen",
            "--algorithm",
            "secp256k1",
            "--force",
            "--print-pubkey",
        ])
        .unwrap();
        assert_eq!(p.algorithm.as_deref(), Some("secp256k1"));
        assert!(p.force);
        assert!(p.print_pubkey);
    }

    #[test]
    fn parse_unknown_flag_rejected() {
        assert!(KeygenOpts::try_parse_from(["mkit keygen", "--bogus"]).is_err());
    }
}
