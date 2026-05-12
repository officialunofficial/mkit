//! `mkit remote` — show / add / set the configured remote.
//!
//! URL validation: only `mkit+<scheme>://` is accepted. Recognised
//! schemes: `file`, `https`, `s3`, `ssh`, `memory`.

use std::io::Write;

use clap::{Parser, Subcommand, ValueEnum};

use crate::clap_shim;
use crate::config::{self, Config};
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
    /// Configure the remote URL (must be `mkit+<scheme>://...`).
    Add { url: String },
    /// Alias for `add`.
    Set { url: String },
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<RemoteOpts>("mkit remote", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let mut cfg = match config::read_or_default(&cwd) {
        Ok(c) => c,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };

    match opts.sub {
        None => show(&cfg, matches!(opts.format, RemoteFormat::Json)),
        Some(RemoteCmd::Add { url } | RemoteCmd::Set { url }) => {
            let Some(scheme) = validate_url(&url) else {
                return emit_err(
                    &format!(
                        "invalid remote URL '{url}': must start with 'mkit+<scheme>://'\n\
                         hint: URL must start with mkit+<scheme>:// (e.g. mkit+https://, mkit+ssh://, mkit+file://, mkit+s3://)",
                    ),
                    exit::PROTOCOL_ERROR,
                );
            };
            cfg.remote_endpoint = url;
            scheme.clone_into(&mut cfg.remote_type);
            match config::write(&cwd, &cfg) {
                Ok(()) => exit::OK,
                Err(e) => emit_err(&format!("write: {e}"), exit::CANTCREAT),
            }
        }
    }
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
    if cfg.remote_endpoint.is_empty() {
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
        // Single-line JSON object (future multi-remote support would
        // switch this to JSONL).
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
    let _ = writeln!(stdout, "remote_endpoint = {}", cfg.remote_endpoint);
    let _ = writeln!(stdout, "remote_type = {}", cfg.remote_type);
    exit::OK
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
