//! `mkit config` — show or set values.
//!
//! Most keys live in the per-repo `<repo>/.mkit/config`. Security-
//! sensitive keys (see [`config::REPO_FORBIDDEN_KEYS`]) live in the
//! user-scoped `$XDG_CONFIG_HOME/mkit/config` and are written there
//! when set via this command. Unknown keys are rejected.

use std::io::Write;

use crate::config::{self, Config, REPO_FORBIDDEN_KEYS};
use crate::exit;

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let mut cfg = match config::read_or_default(&cwd) {
        Ok(c) => c,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };

    if args.is_empty() {
        return show_all(&cfg);
    }
    if args.len() == 1 {
        return show_one(&cfg, &args[0]);
    }
    // `key value` pair.
    let key = &args[0];
    let value = &args[1];
    if let Err(e) = config::validate_value(value) {
        return emit_err(&format!("invalid value: {e}"), exit::CONFIG_ERROR);
    }
    let normalized_value = if key == "user.identity" {
        match config::expand_user_identity(value) {
            Ok(v) => v,
            Err(e) => return emit_err(&format!("{key}: {e}"), exit::CONFIG_ERROR),
        }
    } else {
        value.clone()
    };
    // Path-traversal validation for any key whose value is a filesystem
    // path. Catches `..` even on the user-scoped path.
    if is_path_key(key)
        && let Err(e) = config::validate_key_path(&normalized_value)
    {
        return emit_err(&format!("{e}"), exit::CONFIG_ERROR);
    }
    if REPO_FORBIDDEN_KEYS.contains(&key.as_str()) {
        return write_user_scoped(key, &normalized_value);
    }
    if let Err(code) = apply(&mut cfg, key, &normalized_value) {
        return code;
    }
    match config::write(&cwd, &cfg) {
        Ok(()) => exit::OK,
        Err(e) => emit_err(&format!("write config: {e}"), exit::CANTCREAT),
    }
}

fn is_path_key(key: &str) -> bool {
    matches!(
        key,
        "signing_key"
            | "ssh.user_known_hosts_file"
            | "ssh.identity_file"
            | "attest.external_signer_path"
            | "attest.secp256k1_key_path"
            | "attest.p256_key_path"
    )
}

fn write_user_scoped(key: &str, value: &str) -> u8 {
    match config::write_user_kv(key, value) {
        Ok(()) => {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(
                stderr,
                "wrote `{key}` to user-scoped config at {}",
                config::user_config_path().display()
            );
            exit::OK
        }
        Err(e) => emit_err(
            &format!(
                "write user config at {}: {e}",
                config::user_config_path().display()
            ),
            exit::CANTCREAT,
        ),
    }
}

/// Apply a key/value to the in-memory `Config`. Only repo-safe keys
/// are reachable here — security-sensitive keys (including
/// `user.identity`) are intercepted by [`run`] via `REPO_FORBIDDEN_KEYS`
/// and routed to user-scoped storage before this is called.
fn apply(cfg: &mut Config, key: &str, value: &str) -> Result<(), u8> {
    match key {
        "default_branch" => value.clone_into(&mut cfg.default_branch),
        "remote_endpoint" => value.clone_into(&mut cfg.remote_endpoint),
        "remote_bucket" => value.clone_into(&mut cfg.remote_bucket),
        "remote_type" => value.clone_into(&mut cfg.remote_type),
        "author_mid" => {
            return Err(emit_err(
                "config key `author_mid` has been removed; use `user.identity` (mid:<N>)",
                exit::CONFIG_ERROR,
            ));
        }
        _ => {
            return Err(emit_err(
                &format!("unknown config key: {key}"),
                exit::CONFIG_ERROR,
            ));
        }
    }
    Ok(())
}

fn show_all(cfg: &Config) -> u8 {
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "user.identity = {}", cfg.user_identity);
    let _ = writeln!(stdout, "signing_key = {}", cfg.signing_key);
    let _ = writeln!(stdout, "default_branch = {}", cfg.default_branch);
    let _ = writeln!(stdout, "remote_endpoint = {}", cfg.remote_endpoint);
    let _ = writeln!(stdout, "remote_bucket = {}", cfg.remote_bucket);
    let _ = writeln!(stdout, "remote_type = {}", cfg.remote_type);
    let _ = writeln!(
        stdout,
        "ssh.strict_host_key_checking = {}",
        cfg.ssh_strict_host_key_checking
    );
    let _ = writeln!(
        stdout,
        "ssh.user_known_hosts_file = {}",
        cfg.ssh_user_known_hosts_file
    );
    let _ = writeln!(stdout, "ssh.identity_file = {}", cfg.ssh_identity_file);
    exit::OK
}

fn show_one(cfg: &Config, key: &str) -> u8 {
    let v = match key {
        "user.identity" => &cfg.user_identity,
        "signing_key" => &cfg.signing_key,
        "default_branch" => &cfg.default_branch,
        "remote_endpoint" => &cfg.remote_endpoint,
        "remote_bucket" => &cfg.remote_bucket,
        "remote_type" => &cfg.remote_type,
        "ssh.strict_host_key_checking" => &cfg.ssh_strict_host_key_checking,
        "ssh.user_known_hosts_file" => &cfg.ssh_user_known_hosts_file,
        "ssh.identity_file" => &cfg.ssh_identity_file,
        _ => return emit_err(&format!("unknown config key: {key}"), exit::CONFIG_ERROR),
    };
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "{v}");
    exit::OK
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
