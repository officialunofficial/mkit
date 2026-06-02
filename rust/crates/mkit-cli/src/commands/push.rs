//! `mkit push` — push refs/packs to the configured remote.
//!
//! Scheme dispatch lives in `remote_dispatch::open`, which now covers
//! `mkit+file://`, `mkit+https://` (and `mkit+http://`), `mkit+s3://`,
//! and `mkit+ssh://`. `mkit+memory://` remains in-process only.

use std::io::Write;

use clap::Parser;

use crate::clap_shim;
use crate::config;
use crate::exit;
use crate::remote_dispatch;

#[derive(Debug, Parser)]
#[command(
    name = "mkit push",
    about = "Push refs and packs to the configured remote."
)]
struct PushOpts {
    /// Print what would be pushed without contacting the remote.
    #[arg(long)]
    dry_run: bool,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<PushOpts>("mkit push", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let dry_run = opts.dry_run;
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
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "(dry-run) would push to {endpoint}");
        return exit::OK;
    }
    let repo_chosen = cfg.repo.remote_endpoint.trim() == endpoint;
    match remote_dispatch::open_trusted(endpoint, repo_chosen, &cfg) {
        Ok(tx) => match remote_dispatch::push_all(&cwd, tx.as_ref()) {
            Ok(n) => {
                let mut stderr = std::io::stderr().lock();
                let _ = writeln!(stderr, "pushed {n} ref(s) to {endpoint}");
                exit::OK
            }
            Err(remote_dispatch::DispatchError::Interrupted) => {
                emit_err("push: interrupted", exit::TEMPFAIL)
            }
            Err(e) => emit_err(&format!("push: {e}"), exit::GENERAL_ERROR),
        },
        Err(remote_dispatch::DispatchError::UntrustedRemote(msg)) => {
            emit_err(&msg, exit::CONFIG_ERROR)
        }
        Err(e) => emit_err(&format!("open remote: {e}"), exit::PROTOCOL_ERROR),
    }
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
