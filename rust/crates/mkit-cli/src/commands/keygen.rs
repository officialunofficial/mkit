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
//! a raw 32-byte secret, mode `0600` on Unix (set on the open file
//! handle to avoid a TOCTOU `rename(2)` window; see finding H3).

use std::fs;
use std::io::Write;
use std::path::Path;

use mkit_attest::Algorithm;
use mkit_core::sign::{KeyPair, save_key};
use zeroize::Zeroizing;

use crate::commands::attest_factory;
use crate::exit;
use crate::format;

struct Args {
    algorithm: Option<String>,
    force: bool,
    print_pubkey: bool,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut out = Args {
        algorithm: None,
        force: false,
        print_pubkey: false,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--algorithm" if i + 1 < args.len() => {
                out.algorithm = Some(args[i + 1].clone());
                i += 2;
            }
            "--force" => {
                out.force = true;
                i += 1;
            }
            "--print-pubkey" => {
                out.print_pubkey = true;
                i += 1;
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(out)
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let parsed = match parse_args(args) {
        Ok(p) => p,
        Err(e) => {
            return emit_err(
                &format!(
                    "{e}\nusage: mkit keygen [--algorithm ed25519|secp256k1|p256] [--force] [--print-pubkey]"
                ),
                exit::USAGE,
            );
        }
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

    // Resolve the target key path from config.
    let cfg = match crate::config::read_or_default(&cwd) {
        Ok(c) => c,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };
    let rel_path = match algorithm {
        Algorithm::Ed25519 => crate::config::DEFAULT_SIGNING_KEY,
        Algorithm::Secp256k1 => cfg.attest.secp256k1_key_path_or_default(),
        Algorithm::P256 => cfg.attest.p256_key_path_or_default(),
    };
    let key_path = cwd.join(rel_path);

    match algorithm {
        Algorithm::Ed25519 => run_ed25519(&key_path, parsed.force, parsed.print_pubkey),
        Algorithm::Secp256k1 => run_secp256k1(&key_path, parsed.force, parsed.print_pubkey),
        Algorithm::P256 => run_p256(&key_path, parsed.force, parsed.print_pubkey),
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
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "generated signing key at {}", key_path.display());
    let pk_hex = hex32(&kp.public.0);
    let _ = writeln!(stdout, "public:  ed25519:{pk_hex}");
    let _ = writeln!(
        stdout,
        "identity: {}",
        format::short_identity(&mkit_core::Identity::ed25519(kp.public.0))
    );
    if print_pubkey {
        let _ = writeln!(stdout, "ed25519:{pk_hex}");
    }
    exit::OK
}

fn run_secp256k1(key_path: &Path, force: bool, print_pubkey: bool) -> u8 {
    // Idempotent read path for --print-pubkey.
    if key_path.exists() && print_pubkey && !force {
        let secret = match load_raw_32(key_path) {
            Ok(s) => s,
            Err(e) => return e,
        };
        // `*secret` copies the inner [u8;32] into the constructor; the
        // `Zeroizing` wrapper around `secret` is dropped at end of
        // scope, scrubbing our local copy.
        let signer = match mkit_attest::signer_k256::Secp256k1Signer::new(*secret) {
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
    if let Err(e) = write_raw_32(key_path, &secret) {
        return emit_err(&format!("save key: {e}"), exit::CANTCREAT);
    }
    drop(secret);

    let pk = signer.public_key_sec1();
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "generated signing key at {}", key_path.display());
    let _ = writeln!(stdout, "public:  secp256k1:{}", hex_lower(&pk));
    if print_pubkey {
        let _ = writeln!(stdout, "secp256k1:{}", hex_lower(&pk));
    }
    exit::OK
}

fn run_p256(key_path: &Path, force: bool, print_pubkey: bool) -> u8 {
    if key_path.exists() && print_pubkey && !force {
        let secret = match load_raw_32(key_path) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let signer = match mkit_attest::signer_p256::P256Signer::new(*secret) {
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
    if let Err(e) = write_raw_32(key_path, &secret) {
        return emit_err(&format!("save key: {e}"), exit::CANTCREAT);
    }
    drop(secret);

    let pk = signer.public_key_sec1();
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "generated signing key at {}", key_path.display());
    let _ = writeln!(stdout, "public:  p256:{}", hex_lower(&pk));
    if print_pubkey {
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
        if let Ok(signer) = mkit_attest::signer_k256::Secp256k1Signer::new(*buf) {
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
        if let Ok(signer) = mkit_attest::signer_p256::P256Signer::new(*buf) {
            return Ok((signer, buf));
        }
    }
    Err("rng produced 256 consecutive invalid p256 scalars (impossible in practice)".into())
}

fn print_ed25519_pubkey(kp: &KeyPair) {
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "ed25519:{}", hex32(&kp.public.0));
}

/// Write `secret` to `path` crash-atomically with mode 0600 on Unix.
///
/// Mirrors the hardening `mkit_core::sign::save_key` applies to
/// `default.key`: tmp file in same dir + `O_EXCL | O_NOFOLLOW` + mode
/// 0600 + fsync + rename + parent-dir fsync. The parent directory is
/// tightened to 0700 first.
fn write_raw_32(path: &Path, secret: &[u8; 32]) -> std::io::Result<()> {
    let parent: &Path = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    fs::create_dir_all(parent)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        // Refuse to chmod a symlinked parent dir's target.
        let pmeta = fs::symlink_metadata(parent)?;
        if pmeta.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("key directory is a symlink: {}", parent.display()),
            ));
        }
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;

        let filename = path.file_name().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "key path has no filename")
        })?;
        let mut tmp_name = std::ffi::OsString::from(".");
        tmp_name.push(filename);
        tmp_name.push(format!(".tmp.{}", std::process::id()));
        let tmp_path = parent.join(&tmp_name);

        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&tmp_path)?;
        if let Err(e) = f.write_all(secret) {
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }
        if let Err(e) = f.sync_all() {
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }
        drop(f);
        if let Err(e) = fs::rename(&tmp_path, path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }
        let dir = fs::File::open(parent)?;
        dir.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let filename = path.file_name().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "key path has no filename")
        })?;
        let mut tmp_name = std::ffi::OsString::from(".");
        tmp_name.push(filename);
        tmp_name.push(format!(".tmp.{}", std::process::id()));
        let tmp_path = parent.join(&tmp_name);
        fs::write(&tmp_path, secret)?;
        if let Err(e) = fs::rename(&tmp_path, path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }
    }
    Ok(())
}

/// Load a raw 32-byte secret. On Unix opens with `O_NOFOLLOW`,
/// fstat-checks mode 0600 / owner uid, and reads exactly 32 bytes
/// straight into a stack array (no `fs::read` heap residue). The
/// returned `Zeroizing` wrapper scrubs the bytes when the caller drops
/// it.
fn load_raw_32(path: &Path) -> Result<Zeroizing<[u8; 32]>, u8> {
    #[cfg(unix)]
    {
        use std::io::Read as _;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let mut f = match fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(f) => f,
            Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
                return Err(emit_err(
                    &format!("key path is a symlink: {}", path.display()),
                    exit::NOINPUT,
                ));
            }
            Err(e) => return Err(emit_err(&format!("open key: {e}"), exit::NOINPUT)),
        };
        let meta = match f.metadata() {
            Ok(m) => m,
            Err(e) => return Err(emit_err(&format!("fstat key: {e}"), exit::NOINPUT)),
        };
        let mode = meta.mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(emit_err(
                &format!("key file mode {mode:#o} is broader than 0600"),
                exit::NOPERM,
            ));
        }
        // SAFETY: `geteuid(2)` is parameterless, always succeeds, and
        // never reads or writes user memory. Sole `unsafe` in the cli
        // crate; gated through the same review path as `mkit-core`'s
        // single SAFETY-noted callsite.
        #[allow(unsafe_code)]
        let euid = unsafe { libc::geteuid() };
        if meta.uid() != euid {
            return Err(emit_err(
                &format!(
                    "key file owner uid {} does not match process euid {}",
                    meta.uid(),
                    euid
                ),
                exit::NOPERM,
            ));
        }
        let mut buf: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
        if let Err(e) = f.read_exact(buf.as_mut_slice()) {
            return Err(emit_err(&format!("read key: {e}"), exit::DATAERR));
        }
        let mut probe = [0u8; 1];
        if f.read(&mut probe).unwrap_or(0) != 0 {
            return Err(emit_err(
                &format!("invalid key file: expected 32 bytes, got {}", meta.len()),
                exit::DATAERR,
            ));
        }
        Ok(buf)
    }
    #[cfg(not(unix))]
    {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(e) => return Err(emit_err(&format!("read key: {e}"), exit::NOINPUT)),
        };
        if bytes.len() != 32 {
            return Err(emit_err(
                &format!("invalid key file: expected 32 bytes, got {}", bytes.len()),
                exit::DATAERR,
            ));
        }
        let mut buf: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
        buf.copy_from_slice(&bytes);
        let mut bytes = bytes;
        bytes.zeroize();
        Ok(buf)
    }
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

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_defaults() {
        let p = parse_args(&[]).unwrap();
        assert!(p.algorithm.is_none());
        assert!(!p.force);
        assert!(!p.print_pubkey);
    }

    #[test]
    fn parse_args_all_flags() {
        let args = vec![
            "--algorithm".into(),
            "secp256k1".into(),
            "--force".into(),
            "--print-pubkey".into(),
        ];
        let p = parse_args(&args).unwrap();
        assert_eq!(p.algorithm.as_deref(), Some("secp256k1"));
        assert!(p.force);
        assert!(p.print_pubkey);
    }

    #[test]
    fn parse_args_unknown() {
        assert!(parse_args(&["--bogus".into()]).is_err());
    }
}
