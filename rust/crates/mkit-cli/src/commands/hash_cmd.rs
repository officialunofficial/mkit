//! `mkit hash <file>` — hash a file as a blob, store it, print the hash.

use std::io::Write;

use clap::Parser;
use mkit_core::object::{Blob, Object};
use mkit_core::serialize;
use mkit_core::store::ObjectStore;

use crate::clap_shim;
use crate::exit;
use crate::format;

#[derive(Debug, Parser)]
#[command(name = "mkit hash", about = "Hash a file as a blob and store it.")]
struct HashOpts {
    /// File to hash and store.
    file: String,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<HashOpts>("mkit hash", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let path = &opts.file;
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let store = match ObjectStore::open(&cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => return emit_err(&format!("read {path}: {e}"), exit::NOINPUT),
    };
    let blob = Object::Blob(Blob { data: bytes });
    let serialized = match serialize::serialize(&blob) {
        Ok(b) => b,
        Err(e) => return emit_err(&format!("serialize: {e}"), exit::DATAERR),
    };
    match store.write(&serialized) {
        Ok(h) => {
            let mut stdout = std::io::stdout().lock();
            let _ = writeln!(stdout, "{}", format::hex_hash(&h));
            exit::OK
        }
        Err(e) => emit_err(&format!("store: {e}"), exit::CANTCREAT),
    }
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
