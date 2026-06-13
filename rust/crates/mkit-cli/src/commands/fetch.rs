//! `mkit fetch [<remote>]` — like `pull` but does NOT move HEAD.
//! Downloads every object reachable from each remote ref and updates
//! the `refs/remotes/<remote>/<name>` tracking refs.

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
struct FetchOpts {
    /// Named remote to fetch from (default: the flat default remote).
    remote: Option<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<FetchOpts>("mkit fetch", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let cfg = match config::read_layered(&cwd) {
        Ok(c) => c,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };
    let Some(resolved) = config::resolve_remote(&cfg, opts.remote.as_deref().unwrap_or("")) else {
        return emit_err(
            &match opts.remote.as_deref() {
                Some(name) => format!("unknown remote '{name}'"),
                None => "no remote configured — use `mkit remote add <url>`".to_owned(),
            },
            exit::CONFIG_ERROR,
        );
    };
    let endpoint = resolved.endpoint.as_str();
    match remote_dispatch::open_trusted(endpoint, resolved.repo_chosen, &cfg) {
        Ok(tx) => match remote_dispatch::fetch_all(&cwd, tx.as_ref(), &resolved.name) {
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
