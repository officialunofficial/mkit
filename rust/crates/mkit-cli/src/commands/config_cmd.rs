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
    /// Remove `<KEY>` instead of showing or setting it. Deletes from
    /// whichever scope a `set` of that key would use — the repo layer
    /// for a repo-safe key, the user-scoped layer for a
    /// `REPO_FORBIDDEN_KEYS` key — unless overridden by `--local` /
    /// `--global`. Takes no positional arguments.
    #[arg(long, value_name = "KEY")]
    unset: Option<String>,
    /// Force the repo-scoped layer (`<repo>/.mkit/config`) for `--unset`
    /// or a `<key> <value>` set. Refused for a `REPO_FORBIDDEN_KEYS` key
    /// — those must never be storable in a clone-traveling repo config.
    #[arg(long, conflicts_with = "global")]
    local: bool,
    /// Force the user-scoped layer (`$XDG_CONFIG_HOME/mkit/config`) for
    /// `--unset` or a `<key> <value>` set, even for a key that would
    /// otherwise be repo-safe.
    #[arg(long, conflicts_with = "local")]
    global: bool,
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
    let layout = match super::resolve_layout(&cwd) {
        Ok(layout) => layout,
        Err(code) => return code,
    };
    // Read both layers: the merged view drives `show`, but a write must
    // persist ONLY the repo layer — serializing the merged config would
    // copy user-scoped values (e.g. a private `user.email`) into
    // `.mkit/config`, which travels with clones.
    let layered = match config::read_layered(&layout) {
        Ok(l) => l,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };
    let json = matches!(opts.format, ConfigFormat::Json);

    if let Some(raw_key) = opts.unset.as_deref() {
        if !opts.args.is_empty() {
            return super::usage_error("mkit config --unset takes no positional arguments");
        }
        return run_unset(&layout, &layered, raw_key, opts.local, opts.global);
    }

    match opts.args.len() {
        0 => return show_all(&layered.merged, json),
        1 => {
            return show_one(
                &layered.merged,
                &config::normalize_config_key(&opts.args[0]),
                json,
            );
        }
        2 => {}
        _ => {
            return super::usage_error(&format!(
                "too many arguments: expected 0, 1, or 2 positional args, got {}",
                opts.args.len()
            ));
        }
    }
    // Git treats config section + variable names case-insensitively
    // (`User.Name` == `user.name`), but subsection names (`remote.<name>`,
    // `branch.<branch>`) are case-sensitive. Normalize before every
    // downstream check — crucially BEFORE `REPO_FORBIDDEN_KEYS`, so a
    // case-variant like `User.Identity` can never bypass the spoof guard
    // and land in the repo layer.
    let key_normalized = config::normalize_config_key(&opts.args[0]);
    let key = key_normalized.as_str();
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
    let forbidden = REPO_FORBIDDEN_KEYS.contains(&key);
    if opts.local && forbidden {
        return emit_err(
            &format!(
                "config key `{key}` cannot be stored in the repo (--local); it is user-scoped only"
            ),
            exit::CONFIG_ERROR,
        );
    }
    // `--global` forces the user-scoped layer even for an otherwise
    // repo-safe key; a bare `forbidden` key always goes there regardless
    // of flags (that's the whole point of `REPO_FORBIDDEN_KEYS`); `--local`
    // is only meaningful (and already validated above) for repo-safe keys,
    // where it's a no-op since that's the default.
    if forbidden || opts.global {
        return write_user_scoped(key, &normalized_value);
    }
    // Apply to the repo layer only and persist that — never the merged
    // config — so user-scoped values are not materialized into the repo
    // file (see the scope note above).
    let mut repo_cfg = layered.repo;
    if let Err(code) = apply(&mut repo_cfg, key, &normalized_value) {
        return code;
    }
    match config::write(&layout, &repo_cfg) {
        Ok(()) => exit::OK,
        Err(e) => emit_err(&format!("write config: {e}"), exit::CANTCREAT),
    }
}

/// `mkit config --unset <key>` — delete `<key>` from the scope a `set`
/// of it would use (or the scope forced by `--local`/`--global`).
/// Idempotent: unsetting an already-absent key is a silent success,
/// like `rm -f`, not an error — only an unknown key name is rejected.
fn run_unset(
    layout: &mkit_core::layout::RepoLayout,
    layered: &config::LayeredConfig,
    raw_key: &str,
    local: bool,
    global: bool,
) -> u8 {
    let key_normalized = config::normalize_config_key(raw_key);
    let key = key_normalized.as_str();
    if lookup(&Config::default(), key).is_none() {
        return emit_err(&format!("unknown config key: {key}"), exit::CONFIG_ERROR);
    }
    let forbidden = REPO_FORBIDDEN_KEYS.contains(&key);
    if local && forbidden {
        return emit_err(
            &format!(
                "config key `{key}` cannot be unset from the repo (--local); it is user-scoped only"
            ),
            exit::CONFIG_ERROR,
        );
    }
    if forbidden || global {
        return match config::remove_user_kv(key) {
            Ok(removed) => {
                if removed {
                    let mut stderr = std::io::stderr().lock();
                    let _ = writeln!(
                        stderr,
                        "removed `{key}` from user-scoped config at {}",
                        config::user_config_path().display()
                    );
                }
                exit::OK
            }
            Err(e) => emit_err(
                &format!(
                    "remove user config at {}: {e}",
                    config::user_config_path().display()
                ),
                exit::CANTCREAT,
            ),
        };
    }
    let mut repo_cfg = layered.repo.clone();
    match unset_repo_key(&mut repo_cfg, key) {
        Ok(_removed) => {}
        Err(code) => return code,
    }
    match config::write(layout, &repo_cfg) {
        Ok(()) => exit::OK,
        Err(e) => emit_err(&format!("write config: {e}"), exit::CANTCREAT),
    }
}

/// Clear a repo-safe key from the in-memory `Config`, mirroring
/// [`apply`]'s key match but removing instead of setting. Only
/// repo-safe keys are reachable here — [`run_unset`] routes
/// `REPO_FORBIDDEN_KEYS` keys to the user-scoped removal path before
/// this is called. Returns whether the key had a value to remove
/// (informational only — [`run_unset`] treats both outcomes as
/// success).
fn unset_repo_key(cfg: &mut Config, key: &str) -> Result<bool, u8> {
    fn take_nonempty(field: &mut String) -> bool {
        if field.is_empty() {
            false
        } else {
            field.clear();
            true
        }
    }
    match key {
        "user.name" => Ok(take_nonempty(&mut cfg.user_name)),
        "user.email" => Ok(take_nonempty(&mut cfg.user_email)),
        "default_branch" => Ok(take_nonempty(&mut cfg.default_branch)),
        "durability.objects" => Ok(take_nonempty(&mut cfg.durability_objects)),
        "remote_endpoint" => Ok(take_nonempty(&mut cfg.remote_endpoint)),
        "remote_bucket" => Ok(take_nonempty(&mut cfg.remote_bucket)),
        "remote_type" => Ok(take_nonempty(&mut cfg.remote_type)),
        "transport_auth" => Ok(take_nonempty(&mut cfg.transport_auth)),
        k if config::is_core_section(k) => match config::core_allowed_suffix(k) {
            Some(suffix) => Ok(cfg.core.remove(&suffix).is_some()),
            None => Err(emit_err(
                &format!("unknown config key: {key}"),
                exit::CONFIG_ERROR,
            )),
        },
        _ => Err(emit_err(
            &format!("unknown config key: {key}"),
            exit::CONFIG_ERROR,
        )),
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
            "" | "batch" | "per-object" | "per_object" => {
                value.clone_into(&mut cfg.durability_objects);
            }
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
        // Write-auth mode for `mkit+https://`/`mkit+http://` remotes — see
        // `Config::transport_auth`'s doc comment. Validated here (unlike
        // the lenient config-load fallback in `config::apply_kv`, which
        // tolerates unknown values for forward-compat with hand-edited
        // files) so a typo doesn't silently leave `mkit push` on
        // bearer-only auth when the user asked for signed envelopes.
        "transport_auth" => match value.trim().to_ascii_lowercase().as_str() {
            "" | "bearer" | "envelope" => value.clone_into(&mut cfg.transport_auth),
            _ => {
                return Err(emit_err(
                    &format!(
                        "invalid value for transport_auth: `{value}` (expected `bearer` or `envelope`)"
                    ),
                    exit::CONFIG_ERROR,
                ));
            }
        },
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
    "transport_auth",
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
        "transport_auth" => Some(Cow::Borrowed(&cfg.transport_auth)),
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

use super::error as emit_err;
