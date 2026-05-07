//! `mkit push` — push refs/packs to the configured remote.
//!
//! Scheme dispatch lives in `remote_dispatch::open`, which now covers
//! `mkit+file://`, `mkit+https://` (and `mkit+http://`), `mkit+s3://`,
//! and `mkit+ssh://`. `mkit+memory://` remains in-process only.

use std::io::Write;

use crate::config;
use crate::exit;
use crate::remote_dispatch;

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let dry_run = args.iter().any(|a| a == "--dry-run");
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let cfg = match config::read_layered(&cwd) {
        Ok(c) => c,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };
    let endpoint = cfg.merged.remote_endpoint.trim();
    if endpoint.is_empty() {
        return emit_err(
            "no remote configured — use `mkit remote add <url>`",
            exit::CONFIG_ERROR,
        );
    }
    if dry_run {
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "(dry-run) would push to {endpoint}");
        return exit::OK;
    }
    if let Err(msg) = config::enforce_trusted_remote_endpoint(&cfg) {
        return emit_err(&msg, exit::CONFIG_ERROR);
    }
    match remote_dispatch::open(endpoint) {
        Ok(tx) => match remote_dispatch::push_all(&cwd, tx.as_ref()) {
            Ok(n) => {
                let mut stdout = std::io::stdout().lock();
                let _ = writeln!(stdout, "pushed {n} ref(s) to {endpoint}");
                exit::OK
            }
            Err(e) => emit_err(&format!("push: {e}"), exit::GENERAL_ERROR),
        },
        Err(e) => emit_err(&format!("open remote: {e}"), exit::PROTOCOL_ERROR),
    }
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
