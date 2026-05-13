//! `mkit verify <hash>` — verify the signature on a commit or remix.

use std::io::Write;

use clap::Parser;
use mkit_core::hash::from_hex;
use mkit_core::object::Object;
use mkit_core::sign::{verify_commit, verify_remix};
use mkit_core::store::ObjectStore;

use crate::clap_shim;
use crate::exit;

#[derive(Debug, Parser)]
#[command(
    name = "mkit verify",
    about = "Verify the signature on a commit or remix."
)]
struct VerifyOpts {
    /// 64-char hex object hash.
    hash: String,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<VerifyOpts>("mkit verify", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let hex = &opts.hash;
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let store = match ObjectStore::open(&cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let h = match from_hex(hex) {
        Ok(h) => h,
        Err(e) => return emit_err(&format!("bad hash: {e}"), exit::DATAERR),
    };
    let obj = match store.read_object(&h) {
        Ok(o) => o,
        Err(e) => return emit_err(&format!("read: {e}"), exit::NOINPUT),
    };
    let res = match &obj {
        Object::Commit(c) => verify_commit(c),
        Object::Remix(r) => verify_remix(r),
        _ => {
            return emit_err("object is neither a commit nor a remix", exit::DATAERR);
        }
    };
    let mut stdout = std::io::stdout().lock();
    match res {
        Ok(()) => {
            let _ = writeln!(stdout, "ok: signature valid");
            exit::OK
        }
        Err(e) => {
            let _ = writeln!(stdout, "bad: {e}");
            exit::DATAERR
        }
    }
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
