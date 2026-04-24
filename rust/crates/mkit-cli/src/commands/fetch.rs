//! `mkit fetch` — like `pull` but does NOT move HEAD. Downloads every
//! object reachable from each remote ref into the local object store
//! and updates `refs/heads/<name>`.

use std::io::Write;

use crate::config;
use crate::exit;
use crate::remote_dispatch;

#[must_use]
pub fn run(_args: &[String]) -> u8 {
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let cfg = match config::read_or_default(&cwd) {
        Ok(c) => c,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };
    let endpoint = cfg.remote_endpoint.trim();
    if endpoint.is_empty() {
        return emit_err(
            "no remote configured — use `mkit remote add <url>`",
            exit::CONFIG_ERROR,
        );
    }
    match remote_dispatch::open(endpoint) {
        Ok(tx) => match remote_dispatch::fetch_all(&cwd, tx.as_ref()) {
            Ok(n) => {
                let mut stdout = std::io::stdout().lock();
                let _ = writeln!(stdout, "fetched {n} ref(s) from {endpoint}");
                exit::OK
            }
            Err(e) => emit_err(&format!("fetch: {e}"), exit::GENERAL_ERROR),
        },
        Err(e) => emit_err(&format!("open remote: {e}"), exit::PROTOCOL_ERROR),
    }
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
