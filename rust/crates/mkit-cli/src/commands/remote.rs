//! `mkit remote` — show / add / set the configured remote.
//!
//! URL validation: only `mkit+<scheme>://` is accepted. Recognised
//! schemes: `file`, `https`, `s3`, `ssh`, `memory`.

use std::io::Write;

use crate::config::{self, Config};
use crate::exit;

const ACCEPTED_SCHEMES: &[(&str, &str)] = &[
    ("mkit+file://", "file"),
    ("mkit+https://", "http"),
    ("mkit+s3://", "s3"),
    ("mkit+ssh://", "ssh"),
    ("mkit+memory://", "memory"),
];

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
        return show(&cfg);
    }

    match args[0].as_str() {
        "add" | "set" => {
            let Some(url) = args.get(1) else {
                return super::usage_error("usage: mkit remote add <url>");
            };
            let Some(scheme) = validate_url(url) else {
                return emit_err(
                    &format!(
                        "invalid remote URL '{url}': must start with 'mkit+<scheme>://'\n\
                         hint: URL must start with mkit+<scheme>:// (e.g. mkit+https://, mkit+ssh://, mkit+file://, mkit+s3://)",
                    ),
                    exit::PROTOCOL_ERROR,
                );
            };
            url.clone_into(&mut cfg.remote_endpoint);
            scheme.clone_into(&mut cfg.remote_type);
            match config::write(&cwd, &cfg) {
                Ok(()) => exit::OK,
                Err(e) => emit_err(&format!("write: {e}"), exit::CANTCREAT),
            }
        }
        other => super::usage_error(&format!("unknown remote subcommand: {other}")),
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

fn show(cfg: &Config) -> u8 {
    if cfg.remote_endpoint.is_empty() {
        // Empty listing → empty stdout. The human note goes to stderr.
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "(no remote configured)");
        return exit::OK;
    }
    // Config values ARE the data — keep on stdout.
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "remote_endpoint = {}", cfg.remote_endpoint);
    let _ = writeln!(stdout, "remote_type = {}", cfg.remote_type);
    exit::OK
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
