//! `mkit remote` — show / add / set the configured remote.
//!
//! URL validation: only `mkit+<scheme>://` is accepted. Recognised
//! schemes: `file`, `https`, `s3`, `ssh`, `memory`.

use std::io::Write;

use clap::{Parser, Subcommand, ValueEnum};

use crate::clap_shim;
use crate::config::{self, Config, RemoteEntry};
use crate::exit;
use crate::format;

const ACCEPTED_SCHEMES: &[(&str, &str)] = &[
    ("mkit+file://", "file"),
    ("mkit+https://", "http"),
    ("mkit+s3://", "s3"),
    ("mkit+ssh://", "ssh"),
    ("mkit+memory://", "memory"),
];

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RemoteFormat {
    Default,
    Json,
}

#[derive(Debug, Parser)]
#[command(name = "mkit remote", about = "Show or configure the remote.")]
struct RemoteOpts {
    /// Output format for the show form. JSON object with `--format=json`.
    #[arg(long, value_enum, default_value = "default")]
    format: RemoteFormat,
    #[command(subcommand)]
    sub: Option<RemoteCmd>,
}

#[derive(Debug, Subcommand)]
enum RemoteCmd {
    /// Configure a remote. With one argument, sets the flat default
    /// remote (`mkit remote add <url>`). With two, adds/updates a named
    /// remote (`mkit remote add <name> <url>`). The URL must be
    /// `mkit+<scheme>://...`.
    Add {
        name_or_url: String,
        url: Option<String>,
    },
    /// Alias for `add`.
    Set {
        name_or_url: String,
        url: Option<String>,
    },
    /// Remove a named remote (`mkit remote remove <name>`). Use the
    /// reserved name `default` to clear the flat default remote.
    #[command(alias = "rm")]
    Remove { name: String },
    /// Rename a named remote (`mkit remote rename <old> <new>`). Also
    /// rewrites any `branch.<b>.remote` upstream pointing at `<old>`.
    #[command(alias = "mv")]
    Rename { old: String, new: String },
}

#[must_use]
#[allow(clippy::too_many_lines)] // flat dispatch over the remote subcommands
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<RemoteOpts>("mkit remote", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let layered = match config::read_layered(&cwd) {
        Ok(c) => c,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };
    // `show` reflects the merged view; every mutating subcommand operates
    // on and persists ONLY the repo layer, so a user-scoped value (e.g. a
    // private `user.email`) is never materialized into the clone-traveling
    // `.mkit/config` by `config::write`.
    if opts.sub.is_none() {
        return show(&layered.merged, matches!(opts.format, RemoteFormat::Json));
    }
    let mut cfg = layered.repo;

    match opts.sub {
        None => unreachable!("handled above"),
        Some(RemoteCmd::Add { name_or_url, url } | RemoteCmd::Set { name_or_url, url }) => {
            // Two forms:
            //   `mkit remote add <url>`         -> flat default remote
            //   `mkit remote add <name> <url>`  -> named remote
            let (name, url) = match url {
                Some(url) => (Some(name_or_url), url),
                None => (None, name_or_url),
            };
            // Reject control characters (newline et al.) before the URL
            // ever reaches `config::write`, which emits values raw — a
            // newline would inject extra `key = value` lines into
            // `.mkit/config` (config injection).
            if config::validate_value(&url).is_err() {
                return emit_err(
                    &format!("invalid remote URL '{url}': contains control characters"),
                    exit::PROTOCOL_ERROR,
                );
            }
            let Some(scheme) = validate_url(&url) else {
                return emit_err(
                    &format!(
                        "invalid remote URL '{url}': must start with 'mkit+<scheme>://'\n\
                         hint: URL must start with mkit+<scheme>:// (e.g. mkit+https://, mkit+ssh://, mkit+file://, mkit+s3://)",
                    ),
                    exit::PROTOCOL_ERROR,
                );
            };
            if let Some(name) = name {
                if let Err(code) = validate_remote_name(&name) {
                    return code;
                }
                cfg.remotes.insert(
                    name,
                    RemoteEntry {
                        url,
                        remote_type: scheme.to_owned(),
                    },
                );
            } else {
                cfg.remote_endpoint = url;
                scheme.clone_into(&mut cfg.remote_type);
            }
            match config::write(&cwd, &cfg) {
                Ok(()) => exit::OK,
                Err(e) => emit_err(&format!("write: {e}"), exit::CANTCREAT),
            }
        }
        Some(RemoteCmd::Remove { name }) => {
            // Removing a remote only touches the repo-scoped address
            // book. The user-scoped `trusted_remote_endpoint` (#97) is
            // keyed by exact URL, not by remote name, and is never
            // serialised by `config::write`, so the credential-trust
            // boundary is unaffected: a later remote reusing the same URL
            // would still be trusted, and one with a new URL still
            // requires an explicit `config trusted_remote_endpoint`.
            if name == config::DEFAULT_REMOTE_NAME {
                if cfg.remote_endpoint.is_empty() {
                    return emit_err("no default remote configured", exit::GENERAL_ERROR);
                }
                cfg.remote_endpoint.clear();
                cfg.remote_type.clear();
                cfg.remote_bucket.clear();
            } else if cfg.remotes.remove(&name).is_none() {
                return emit_err(&format!("remote '{name}' not found"), exit::GENERAL_ERROR);
            }
            match config::write(&cwd, &cfg) {
                Ok(()) => exit::OK,
                Err(e) => emit_err(&format!("write: {e}"), exit::CANTCREAT),
            }
        }
        Some(RemoteCmd::Rename { old, new }) => {
            if old == config::DEFAULT_REMOTE_NAME || new == config::DEFAULT_REMOTE_NAME {
                return emit_err(
                    "cannot rename the reserved `default` remote; use `remote add`/`remote remove`",
                    exit::PROTOCOL_ERROR,
                );
            }
            if let Err(code) = validate_remote_name(&new) {
                return code;
            }
            let Some(entry) = cfg.remotes.remove(&old) else {
                return emit_err(&format!("remote '{old}' not found"), exit::GENERAL_ERROR);
            };
            if cfg.remotes.contains_key(&new) {
                // Put the source back so a failed rename is a no-op.
                cfg.remotes.insert(old, entry);
                return emit_err(&format!("remote '{new}' already exists"), exit::CANTCREAT);
            }
            cfg.remotes.insert(new.clone(), entry);
            // Repoint any branch upstreams that tracked the old name.
            for up in cfg.branch_upstreams.values_mut() {
                if up.remote == old {
                    up.remote.clone_from(&new);
                }
            }
            match config::write(&cwd, &cfg) {
                Ok(()) => exit::OK,
                Err(e) => emit_err(&format!("write: {e}"), exit::CANTCREAT),
            }
        }
    }
}

/// Validate a named-remote name: rejects control characters, non
/// ref-safe names, dots (which would collide with the
/// `remote.<name>.<field>` config key grammar), and the reserved
/// `default` name. Returns the CLI exit code to propagate on failure.
fn validate_remote_name(name: &str) -> Result<(), u8> {
    if config::validate_value(name).is_err() {
        return Err(emit_err(
            &format!("invalid remote name '{name}': contains control characters"),
            exit::PROTOCOL_ERROR,
        ));
    }
    if !mkit_core::refs::validate_ref_name(name)
        || name.contains('.')
        || name == config::DEFAULT_REMOTE_NAME
    {
        return Err(emit_err(
            &format!(
                "invalid remote name '{name}': must be a dot-free ref-safe name \
                 (and not the reserved `default`)"
            ),
            exit::PROTOCOL_ERROR,
        ));
    }
    Ok(())
}

fn validate_url(url: &str) -> Option<&'static str> {
    for (prefix, kind) in ACCEPTED_SCHEMES {
        if url.starts_with(prefix) {
            return Some(kind);
        }
    }
    None
}

fn show(cfg: &Config, json: bool) -> u8 {
    let has_default = !cfg.remote_endpoint.is_empty();
    if !has_default && cfg.remotes.is_empty() {
        // Empty listing → empty stdout in both modes. The default
        // mode emits a human note on stderr.
        if !json {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "(no remote configured)");
        }
        return exit::OK;
    }
    let mut stdout = std::io::stdout().lock();
    if json {
        // Additive shape: when only the default remote is configured,
        // emit the historical single-line object so existing JSON
        // snapshots stay valid. When named remotes exist, emit one JSON
        // object per line (JSONL) carrying a `name` field; the default
        // remote (if any) appears as `name=default`.
        if has_default && cfg.remotes.is_empty() {
            let _ = stdout.write_all(b"{");
            let _ = write!(
                stdout,
                "\"url\":\"{}\"",
                format::json_escape(&cfg.remote_endpoint)
            );
            let _ = write!(
                stdout,
                ",\"transport\":\"{}\"",
                format::json_escape(&cfg.remote_type)
            );
            let _ = stdout.write_all(b"}\n");
            return exit::OK;
        }
        if has_default {
            let _ = writeln!(
                stdout,
                "{{\"name\":\"{}\",\"url\":\"{}\",\"transport\":\"{}\"}}",
                config::DEFAULT_REMOTE_NAME,
                format::json_escape(&cfg.remote_endpoint),
                format::json_escape(&cfg.remote_type)
            );
        }
        for (name, entry) in &cfg.remotes {
            let _ = writeln!(
                stdout,
                "{{\"name\":\"{}\",\"url\":\"{}\",\"transport\":\"{}\"}}",
                format::json_escape(name),
                format::json_escape(&entry.url),
                format::json_escape(&entry.remote_type)
            );
        }
        return exit::OK;
    }
    // Default (human) form. Keep the legacy two-line output when only
    // the flat default remote is configured.
    if has_default && cfg.remotes.is_empty() {
        let _ = writeln!(stdout, "remote_endpoint = {}", cfg.remote_endpoint);
        let _ = writeln!(stdout, "remote_type = {}", cfg.remote_type);
        return exit::OK;
    }
    if has_default {
        let _ = writeln!(
            stdout,
            "{}\t{} ({})",
            config::DEFAULT_REMOTE_NAME,
            cfg.remote_endpoint,
            cfg.remote_type
        );
    }
    for (name, entry) in &cfg.remotes {
        let _ = writeln!(stdout, "{name}\t{} ({})", entry.url, entry.remote_type);
    }
    exit::OK
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
