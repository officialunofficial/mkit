//! `mkit verify <rev>` — verify the signature on a commit, remix, or
//! signed tag.

use std::io::Write;

use clap::Parser;
use mkit_core::object::Object;
use mkit_core::sign::{verify_commit, verify_remix, verify_tag};
use mkit_core::store::ObjectStore;

use crate::clap_shim;
use crate::exit;

#[derive(Debug, Parser)]
#[command(
    name = "mkit verify",
    about = "Verify the signature on a commit, remix, or signed tag."
)]
struct VerifyOpts {
    /// Revision to verify: an object hash (full or short), a branch /
    /// tag name, or `HEAD`. A tag name resolves to its annotated-tag
    /// object when one exists.
    revision: String,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<VerifyOpts>("mkit verify", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let layout = match super::resolve_layout(&cwd) {
        Ok(layout) => layout,
        Err(code) => return code,
    };
    let store = match ObjectStore::open(&layout) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let h = match super::revspec::resolve_revision(&store, &layout, &opts.revision) {
        Ok(h) => h,
        Err(e) => return emit_err(&format!("{e}"), exit::DATAERR),
    };
    let obj = match store.read_object(&h) {
        Ok(o) => o,
        Err(e) => return emit_err(&format!("read: {e}"), exit::NOINPUT),
    };
    let res = match &obj {
        Object::Commit(c) => verify_commit(c),
        Object::Remix(r) => verify_remix(r),
        Object::Tag(t) => verify_tag(t),
        _ => {
            return emit_err(
                "object is not a commit, remix, or signed tag",
                exit::DATAERR,
            );
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

use super::error as emit_err;
