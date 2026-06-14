//! `mkit config` — show or set values.
//!
//! Most keys live in the per-repo `<repo>/.mkit/config`. Security-
//! sensitive keys (see [`config::REPO_FORBIDDEN_KEYS`]) live in the
//! user-scoped `$XDG_CONFIG_HOME/mkit/config` and are written there
//! when set via this command. Unknown keys are rejected.

use std::borrow::Cow;
use std::io::Write;

use clap::{Parser, ValueEnum};

use crate::clap_shim;
use crate::config::{self, Config, REPO_FORBIDDEN_KEYS};
use crate::exit;
use crate::format;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ConfigFormat {
    Default,
    Json,
}

#[derive(Debug, Parser)]
#[command(name = "mkit config", about = "Show or set configuration values.")]
struct ConfigOpts {
    /// Output format for the show forms.
    #[arg(long, value_enum, default_value = "default")]
    format: ConfigFormat,
    /// Optional `<key>` to show, or `<key> <value>` pair to set.
    args: Vec<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<ConfigOpts>("mkit config", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    // Read both layers: the merged view drives `show`, but a write must
    // persist ONLY the repo layer — serializing the merged config would
    // copy user-scoped values (e.g. a private `user.email`) into
    // `.mkit/config`, which travels with clones.
    let layered = match config::read_layered(&cwd) {
        Ok(l) => l,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };
    let json = matches!(opts.format, ConfigFormat::Json);

    match opts.args.len() {
        0 => return show_all(&layered.merged, json),
        1 => return show_one(&layered.merged, &opts.args[0], json),
        2 => {}
        _ => {
            return super::usage_error(&format!(
                "too many arguments: expected 0, 1, or 2 positional args, got {}",
                opts.args.len()
            ));
        }
    }
    let key = opts.args[0].as_str();
    let value = opts.args[1].as_str();
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
    // Apply to the repo layer only and persist that — never the merged
    // config — so user-scoped values are not materialized into the repo
    // file (see the scope note above).
    let mut repo_cfg = layered.repo;
    if let Err(code) = apply(&mut repo_cfg, key, &normalized_value) {
        return code;
    }
    match config::write(&cwd, &repo_cfg) {
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
        // Git-compatibility aliases. Accepted and round-tripped, but
        // **non-authoritative**: they never feed the signed commit author
        // (that is `user.identity` / the signing key), so they are
        // repo-safe and not in `REPO_FORBIDDEN_KEYS`.
        "user.name" => value.clone_into(&mut cfg.user_name),
        "user.email" => value.clone_into(&mut cfg.user_email),
        "default_branch" => value.clone_into(&mut cfg.default_branch),
        // SPEC-OBJECTS §10.1 durability escape hatch. Validated at the
        // set boundary (unlike the lenient config-load fallback) so a
        // typo can't silently leave the user on the batched default when
        // they asked for the strict per-object schedule.
        "durability.objects" => match value.trim().to_ascii_lowercase().as_str() {
            "" | "batch" | "per-object" | "per_object" => value.clone_into(&mut cfg.durability_objects),
            _ => {
                return Err(emit_err(
                    &format!(
                        "invalid value for durability.objects: `{value}` (expected `batch` or `per-object`)"
                    ),
                    exit::CONFIG_ERROR,
                ));
            }
        },
        "remote_endpoint" => value.clone_into(&mut cfg.remote_endpoint),
        "remote_bucket" => value.clone_into(&mut cfg.remote_bucket),
        "remote_type" => value.clone_into(&mut cfg.remote_type),
        "author_mid" => {
            return Err(emit_err(
                "config key `author_mid` has been removed; use `user.identity` (mid:<N>)",
                exit::CONFIG_ERROR,
            ));
        }
        // Inert git-compat `core.*` keys (section matched case-insensitively):
        // store the allowlisted ones, and refuse the dangerous ones (they
        // would change what mkit executes if honored). Anything else under
        // `core.` is an unknown key.
        k if config::is_core_section(k) => {
            let name = k
                .split_once('.')
                .map_or("", |(_, n)| n)
                .to_ascii_lowercase();
            if let Some(suffix) = config::core_allowed_suffix(k) {
                cfg.core.insert(suffix, value.to_string());
            } else if config::CORE_DENIED_KEYS.contains(&name.as_str()) {
                return Err(emit_err(
                    &format!(
                        "config key `{key}` is not honored by mkit and is rejected for safety"
                    ),
                    exit::CONFIG_ERROR,
                ));
            } else {
                return Err(emit_err(
                    &format!("unknown config key: {key}"),
                    exit::CONFIG_ERROR,
                ));
            }
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
    "attest.default_algorithm",
    "attest.external_signer_args",
    "attest.external_signer_path",
    "attest.external_signer_timeout_secs",
    "attest.p256_key_path",
    "attest.secp256k1_key_path",
    "attest.signer",
    "default_branch",
    "durability.objects",
    "key.backend",
    "key.default_ref",
    "key.ed25519_ref",
    "key.p256_ref",
    "key.secp256k1_ref",
    "remote_bucket",
    "remote_endpoint",
    "remote_type",
    "signer",
    "signing_key",
    "ssh.identity_file",
    "ssh.strict_host_key_checking",
    "ssh.user_known_hosts_file",
    "trusted_remote_endpoint",
    "user.email",
    "user.identity",
    "user.name",
];

fn lookup<'a>(cfg: &'a Config, key: &str) -> Option<Cow<'a, str>> {
    match key {
        "user.identity" => Some(Cow::Borrowed(&cfg.user_identity)),
        "user.name" => Some(Cow::Borrowed(&cfg.user_name)),
        "user.email" => Some(Cow::Borrowed(&cfg.user_email)),
        "trusted_remote_endpoint" => Some(Cow::Borrowed(&cfg.trusted_remote_endpoint)),
        "signing_key" => Some(Cow::Borrowed(&cfg.signing_key)),
        "default_branch" => Some(Cow::Borrowed(&cfg.default_branch)),
        "durability.objects" => Some(Cow::Borrowed(&cfg.durability_objects)),
        "remote_endpoint" => Some(Cow::Borrowed(&cfg.remote_endpoint)),
        "remote_bucket" => Some(Cow::Borrowed(&cfg.remote_bucket)),
        "remote_type" => Some(Cow::Borrowed(&cfg.remote_type)),
        "ssh.strict_host_key_checking" => Some(Cow::Borrowed(&cfg.ssh_strict_host_key_checking)),
        "ssh.user_known_hosts_file" => Some(Cow::Borrowed(&cfg.ssh_user_known_hosts_file)),
        "ssh.identity_file" => Some(Cow::Borrowed(&cfg.ssh_identity_file)),
        "signer" => Some(Cow::Borrowed(&cfg.signer)),
        "key.backend" => Some(Cow::Borrowed(cfg.key.backend_or_fallback())),
        "key.default_ref" => Some(Cow::Borrowed(cfg.key.default_ref_or_fallback())),
        "key.ed25519_ref" => Some(Cow::Borrowed(cfg.key.ed25519_ref_or_fallback())),
        "key.secp256k1_ref" => Some(Cow::Borrowed(cfg.key.secp256k1_ref_or_fallback())),
        "key.p256_ref" => Some(Cow::Borrowed(cfg.key.p256_ref_or_fallback())),
        "attest.default_algorithm" => {
            Some(Cow::Borrowed(cfg.attest.default_algorithm_or_fallback()))
        }
        "attest.external_signer_args" => {
            Some(Cow::Owned(cfg.attest.external_signer_args.join("|")))
        }
        "attest.external_signer_path" => Some(Cow::Borrowed(&cfg.attest.external_signer_path)),
        "attest.external_signer_timeout_secs" => Some(Cow::Owned(
            cfg.attest
                .external_signer_timeout_secs
                .map_or_else(String::new, |s| s.to_string()),
        )),
        "attest.secp256k1_key_path" => {
            Some(Cow::Borrowed(cfg.attest.secp256k1_key_path_or_default()))
        }
        "attest.p256_key_path" => Some(Cow::Borrowed(cfg.attest.p256_key_path_or_default())),
        "attest.signer" => Some(Cow::Borrowed(cfg.attest.signer_or_fallback())),
        // Inert git-compat `core.*` keys (section matched case-insensitively):
        // an allowlisted key returns its stored value (empty if unset, like
        // the other keys); anything else under `core.` is unknown.
        k if config::is_core_section(k) => config::core_allowed_suffix(k).map(|suffix| {
            cfg.core
                .get(&suffix)
                .map_or(Cow::Borrowed(""), |v| Cow::Owned(v.clone()))
        }),
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
            let v = lookup(cfg, key).unwrap_or(Cow::Borrowed(""));
            let _ = write!(
                stdout,
                "\"{}\":\"{}\"",
                format::json_escape(key),
                format::json_escape(&v)
            );
        }
        // Dynamic, set-only `core.*` git-compat keys.
        for (k, v) in &cfg.core {
            let _ = write!(
                stdout,
                ",\"core.{}\":\"{}\"",
                format::json_escape(k),
                format::json_escape(v)
            );
        }
        let _ = stdout.write_all(b"}\n");
        return exit::OK;
    }
    for key in CONFIG_KEYS {
        let v = lookup(cfg, key).unwrap_or(Cow::Borrowed(""));
        let _ = writeln!(stdout, "{key} = {v}");
    }
    for (k, v) in &cfg.core {
        let _ = writeln!(stdout, "core.{k} = {v}");
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
            format::json_escape(&v)
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
