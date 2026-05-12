//! `mkit config` — show or set values.
//!
//! Most keys live in the per-repo `<repo>/.mkit/config`. Security-
//! sensitive keys (see [`config::REPO_FORBIDDEN_KEYS`]) live in the
//! user-scoped `$XDG_CONFIG_HOME/mkit/config` and are written there
//! when set via this command. Unknown keys are rejected.

use std::io::Write;

use crate::config::{self, Config, REPO_FORBIDDEN_KEYS};
use crate::exit;
use crate::format;

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

    // Parse `--format=json` / `--format json` out of args first so
    // we can use it for both show modes.
    let mut json = false;
    let mut positional: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--format=json" => json = true,
            "--format" if i + 1 < args.len() => {
                match args[i + 1].as_str() {
                    "json" => json = true,
                    "default" => json = false,
                    other => {
                        return super::usage_error(&format!("unknown --format value: {other}"));
                    }
                }
                i += 1;
            }
            other => positional.push(other),
        }
        i += 1;
    }

    if positional.is_empty() {
        return show_all(&cfg, json);
    }
    if positional.len() == 1 {
        return show_one(&cfg, positional[0], json);
    }
    // `key value` pair.
    let key = positional[0];
    let value = positional[1];
    if let Err(e) = config::validate_value(value) {
        return emit_err(&format!("invalid value: {e}"), exit::CONFIG_ERROR);
    }
    let normalized_value = if key == "user.identity" {
        match config::expand_user_identity(value) {
            Ok(v) => v,
            Err(e) => return emit_err(&format!("{key}: {e}"), exit::CONFIG_ERROR),
        }
    } else {
        value.to_owned()
    };
    // Path-traversal validation for any key whose value is a filesystem
    // path. Catches `..` even on the user-scoped path.
    if is_path_key(key)
        && let Err(e) = config::validate_key_path(&normalized_value)
    {
        return emit_err(&format!("{e}"), exit::CONFIG_ERROR);
    }
    if REPO_FORBIDDEN_KEYS.contains(&key) {
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

/// Stable schema for the JSON form: every key the CLI knows about,
/// paired with its value. Keys are emitted in alphabetical order so
/// the output is deterministic and easy to snapshot-test.
const CONFIG_KEYS: &[&str] = &[
    "default_branch",
    "remote_bucket",
    "remote_endpoint",
    "remote_type",
    "signing_key",
    "ssh.identity_file",
    "ssh.strict_host_key_checking",
    "ssh.user_known_hosts_file",
    "trusted_remote_endpoint",
    "user.identity",
];

fn lookup<'a>(cfg: &'a Config, key: &str) -> Option<&'a str> {
    match key {
        "user.identity" => Some(&cfg.user_identity),
        "trusted_remote_endpoint" => Some(&cfg.trusted_remote_endpoint),
        "signing_key" => Some(&cfg.signing_key),
        "default_branch" => Some(&cfg.default_branch),
        "remote_endpoint" => Some(&cfg.remote_endpoint),
        "remote_bucket" => Some(&cfg.remote_bucket),
        "remote_type" => Some(&cfg.remote_type),
        "ssh.strict_host_key_checking" => Some(&cfg.ssh_strict_host_key_checking),
        "ssh.user_known_hosts_file" => Some(&cfg.ssh_user_known_hosts_file),
        "ssh.identity_file" => Some(&cfg.ssh_identity_file),
        _ => None,
    }
}

fn show_all(cfg: &Config, json: bool) -> u8 {
    let mut stdout = std::io::stdout().lock();
    if json {
        // Flat object with every known key. Unset values render as
        // empty strings, matching the default-mode behaviour.
        let _ = stdout.write_all(b"{");
        for (i, key) in CONFIG_KEYS.iter().enumerate() {
            if i > 0 {
                let _ = stdout.write_all(b",");
            }
            let v = lookup(cfg, key).unwrap_or("");
            let _ = write!(
                stdout,
                "\"{}\":\"{}\"",
                format::json_escape(key),
                format::json_escape(v)
            );
        }
        let _ = stdout.write_all(b"}\n");
        return exit::OK;
    }
    for key in CONFIG_KEYS {
        let v = lookup(cfg, key).unwrap_or("");
        let _ = writeln!(stdout, "{key} = {v}");
    }
    exit::OK
}

fn show_one(cfg: &Config, key: &str, json: bool) -> u8 {
    let Some(v) = lookup(cfg, key) else {
        return emit_err(&format!("unknown config key: {key}"), exit::CONFIG_ERROR);
    };
    let mut stdout = std::io::stdout().lock();
    if json {
        let _ = writeln!(
            stdout,
            "{{\"{}\":\"{}\"}}",
            format::json_escape(key),
            format::json_escape(v)
        );
    } else {
        let _ = writeln!(stdout, "{v}");
    }
    exit::OK
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
