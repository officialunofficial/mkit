//! `mkit config` — show or set values in `.mkit/config`.

use std::io::Write;

use crate::config::{self, Config};
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
    if let Err(code) = apply(&mut cfg, key, value) {
        return code;
    }
    match config::write(&cwd, &cfg) {
        Ok(()) => exit::OK,
        Err(e) => emit_err(&format!("write config: {e}"), exit::CANTCREAT),
    }
}

fn apply(cfg: &mut Config, key: &str, value: &str) -> Result<(), u8> {
    match key {
        "user.identity" => {
            let canon = config::expand_user_identity(value)
                .map_err(|e| emit_err(&format!("{key}: {e}"), exit::CONFIG_ERROR))?;
            cfg.user_identity = canon;
        }
        "signing_key" => value.clone_into(&mut cfg.signing_key),
        "default_branch" => value.clone_into(&mut cfg.default_branch),
        "remote_endpoint" => value.clone_into(&mut cfg.remote_endpoint),
        "remote_bucket" => value.clone_into(&mut cfg.remote_bucket),
        "remote_type" => value.clone_into(&mut cfg.remote_type),
        "ssh.strict_host_key_checking" => value.clone_into(&mut cfg.ssh_strict_host_key_checking),
        "ssh.user_known_hosts_file" => value.clone_into(&mut cfg.ssh_user_known_hosts_file),
        "ssh.identity_file" => value.clone_into(&mut cfg.ssh_identity_file),
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
