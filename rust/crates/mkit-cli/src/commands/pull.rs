//! `mkit pull` — fetch refs from the configured remote and update
//! local ref pointers. No merge yet. The binary only dispatches when
//! the URL is `mkit+memory://` or `mkit+file://`; the remaining schemes
//! are follow-ups.

use std::io::Write;

use clap::Parser;

use crate::clap_shim;
use crate::config;
use crate::exit;
use crate::remote_dispatch;

#[derive(Debug, Parser)]
#[command(name = "mkit pull", about = "Pull changes from the configured remote.")]
struct PullOpts {}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    if let Err(code) = clap_shim::parse::<PullOpts>("mkit pull", args) {
        return code;
    }
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
    if let Err(msg) = config::enforce_trusted_remote_endpoint(&cfg) {
        return emit_err(&msg, exit::CONFIG_ERROR);
    }
    match remote_dispatch::open(endpoint) {
        Ok(tx) => match remote_dispatch::pull_all(&cwd, tx.as_ref()) {
            Ok(n) => {
                let mut stderr = std::io::stderr().lock();
                let _ = writeln!(stderr, "pulled {n} ref(s) from {endpoint}");
                exit::OK
            }
            Err(remote_dispatch::DispatchError::Interrupted) => {
                emit_err("pull: interrupted", exit::TEMPFAIL)
            }
            Err(e) => emit_err(&format!("pull: {e}"), exit::GENERAL_ERROR),
        },
        Err(e) => emit_err(&format!("open remote: {e}"), exit::PROTOCOL_ERROR),
    }
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
