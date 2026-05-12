//! `mkit remote` — show / add / set the configured remote.
//!
//! URL validation: only `mkit+<scheme>://` is accepted. Recognised
//! schemes: `file`, `https`, `s3`, `ssh`, `memory`.

use std::io::Write;

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

    // Parse optional --format=json out of args before sub-dispatch.
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
        return show(&cfg, json);
    }

    match positional[0] {
        "add" | "set" => {
            let Some(url) = positional.get(1) else {
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
            (*url).clone_into(&mut cfg.remote_endpoint);
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
