//! `mkit fetch` — like `pull` but does NOT move HEAD. Downloads every
//! object reachable from each remote ref into the local object store
//! and updates `refs/heads/<name>`.

use std::io::Write;

use clap::Parser;

use crate::clap_shim;
use crate::config;
use crate::exit;
use crate::remote_dispatch;

#[derive(Debug, Parser)]
#[command(
    name = "mkit fetch",
    about = "Download from the configured remote without merging."
)]
struct FetchOpts {}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    if let Err(code) = clap_shim::parse::<FetchOpts>("mkit fetch", args) {
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
    let repo_chosen = cfg.repo.remote_endpoint.trim() == endpoint;
    match remote_dispatch::open_trusted(endpoint, repo_chosen, &cfg) {
        Ok(tx) => match remote_dispatch::fetch_all(&cwd, tx.as_ref()) {
            Ok(n) => {
                let mut stderr = std::io::stderr().lock();
                let _ = writeln!(stderr, "fetched {n} ref(s) from {endpoint}");
                exit::OK
            }
            Err(remote_dispatch::DispatchError::Interrupted) => {
                emit_err("fetch: interrupted", exit::TEMPFAIL)
            }
            Err(e) => emit_err(&format!("fetch: {e}"), exit::GENERAL_ERROR),
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
