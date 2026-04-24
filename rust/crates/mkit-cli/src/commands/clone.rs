//! `mkit clone <url> [<dir>]` — initialise a new repo and pull from
//! the URL. The destination defaults to the final path segment of the
//! URL when `<dir>` is omitted.
//!
//! Dispatches to the same transport-open path used by `mkit pull` —
//! `file://`, `https://`, `s3://`, and `ssh://` are all wired via
//! `remote_dispatch::open`. Shallow and sparse clone flags (`--depth`,
//! `--sparse`) are recognised but deferred; we reject them with a clear
//! message rather than silently ignoring.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use mkit_core::refs;
use mkit_core::store::{ObjectStore, StoreError};

use crate::config::{self, Config};
use crate::exit;
use crate::remote_dispatch;

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let mut url: Option<&str> = None;
    let mut dir: Option<&str> = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--depth" || a == "--sparse" {
            return super::usage_error(&format!("mkit clone: {a} is not yet wired"));
        }
        if a.starts_with("--") {
            return super::usage_error(&format!("mkit clone: unknown flag {a}"));
        }
        if url.is_none() {
            url = Some(a);
        } else if dir.is_none() {
            dir = Some(a);
        } else {
            return super::usage_error("usage: mkit clone <url> [<dir>]");
        }
        i += 1;
    }
    let Some(url) = url else {
        return super::usage_error("usage: mkit clone <url> [<dir>]");
    };
    let target: PathBuf = match dir {
        Some(d) => PathBuf::from(d),
        None => PathBuf::from(derive_dir_from_url(url)),
    };
    if target.exists() {
        return emit_err(
            &format!("destination '{}' already exists", target.display()),
            exit::CANTCREAT,
        );
    }
    if let Err(e) = fs::create_dir_all(&target) {
        return emit_err(
            &format!("create {}: {e}", target.display()),
            exit::CANTCREAT,
        );
    }
    match ObjectStore::init(&target) {
        Ok(_) => {}
        Err(StoreError::AlreadyInitialized) => {
            return emit_err("already a mkit repository", exit::GENERAL_ERROR);
        }
        Err(e) => return emit_err(&format!("init: {e}"), exit::CANTCREAT),
    }
    if let Err(e) = refs::init(&target.join(mkit_core::MKIT_DIR)) {
        return emit_err(&format!("refs init: {e}"), exit::CANTCREAT);
    }
    let mut cfg = Config::with_defaults();
    url.clone_into(&mut cfg.remote_endpoint);
    cfg.remote_type = scheme_of(url).unwrap_or_default().to_string();
    if let Err(e) = config::write(&target, &cfg) {
        return emit_err(&format!("write config: {e}"), exit::CANTCREAT);
    }

    match remote_dispatch::open(url) {
        Ok(tx) => match remote_dispatch::pull_all(&target, tx.as_ref()) {
            Ok(n) => {
                let mut stdout = std::io::stdout().lock();
                let _ = writeln!(
                    stdout,
                    "cloned {n} ref(s) from {url} into {}",
                    target.display()
                );
                exit::OK
            }
            Err(e) => emit_err(&format!("pull: {e}"), exit::GENERAL_ERROR),
        },
        Err(e) => emit_err(&format!("open remote: {e}"), exit::PROTOCOL_ERROR),
    }
}

fn derive_dir_from_url(url: &str) -> String {
    let trimmed = url.trim_end_matches('/');
    let last = trimmed.rsplit('/').next().unwrap_or(trimmed);
    let stripped = last.strip_suffix(".mkit").unwrap_or(last);
    if stripped.is_empty() {
        "repo".to_string()
    } else {
        stripped.to_string()
    }
}

fn scheme_of(url: &str) -> Option<&'static str> {
    for (prefix, kind) in [
        ("mkit+file://", "file"),
        ("mkit+https://", "http"),
        ("mkit+s3://", "s3"),
        ("mkit+ssh://", "ssh"),
        ("mkit+memory://", "memory"),
    ] {
        if url.starts_with(prefix) {
            return Some(kind);
        }
    }
    None
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
