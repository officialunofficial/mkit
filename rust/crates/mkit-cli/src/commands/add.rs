//! `mkit add <path>` / `mkit add .` — stage a file (or the whole
//! worktree) into `.mkit/index`.

use std::io::Write;
use std::path::Path;

use mkit_core::index::{self, EntryStatus, Index, IndexEntry};
use mkit_core::object::{Blob, Object};
use mkit_core::serialize;
use mkit_core::store::ObjectStore;

use crate::exit;

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let Some(target) = args.first() else {
        return super::usage_error("usage: mkit add <path> | .");
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let store = match ObjectStore::open(&cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let mut idx = match index::read_index(&cwd) {
        Ok(i) => i,
        Err(_) => Index::new(),
    };
    if target == "." {
        if let Err(code) = add_tree(&cwd, &cwd, &store, &mut idx) {
            return code;
        }
    } else if let Err(code) = add_one(&cwd, Path::new(target), &store, &mut idx) {
        return code;
    }
    match index::write_index(&cwd, &idx) {
        Ok(()) => exit::OK,
        Err(e) => emit_err(&format!("write index: {e}"), exit::CANTCREAT),
    }
}

fn add_one(root: &Path, rel: &Path, store: &ObjectStore, idx: &mut Index) -> Result<(), u8> {
    let abs = if rel.is_absolute() {
        rel.to_path_buf()
    } else {
        root.join(rel)
    };
    if !abs.is_file() {
        return Err(emit_err(
            &format!("not a regular file: {}", abs.display()),
            exit::NOINPUT,
        ));
    }
    let rel_str = abs
        .strip_prefix(root)
        .unwrap_or(rel)
        .to_string_lossy()
        .replace('\\', "/");
    if !index::validate_index_path(&rel_str) {
        return Err(emit_err(&format!("invalid path: {rel_str}"), exit::DATAERR));
    }
    let bytes = std::fs::read(&abs)
        .map_err(|e| emit_err(&format!("read {}: {e}", abs.display()), exit::NOINPUT))?;
    let blob = Object::Blob(Blob { data: bytes });
    let ser = serialize::serialize(&blob)
        .map_err(|e| emit_err(&format!("serialize: {e}"), exit::DATAERR))?;
    let h = store
        .write(&ser)
        .map_err(|e| emit_err(&format!("store: {e}"), exit::CANTCREAT))?;
    let entry = IndexEntry {
        path: rel_str,
        status: EntryStatus::Blob,
        object_hash: h,
    };
    if let Some(existing) = idx.find_entry(&entry.path) {
        idx.entries[existing] = entry;
    } else {
        idx.entries.push(entry);
    }
    Ok(())
}

fn add_tree(root: &Path, dir: &Path, store: &ObjectStore, idx: &mut Index) -> Result<(), u8> {
    let rd = std::fs::read_dir(dir)
        .map_err(|e| emit_err(&format!("read dir {}: {e}", dir.display()), exit::NOINPUT))?;
    for ent in rd.flatten() {
        let p = ent.path();
        let name = ent.file_name();
        let name_s = name.to_string_lossy();
        if name_s == ".mkit" || name_s == ".git" {
            continue;
        }
        if p.is_dir() {
            add_tree(root, &p, store, idx)?;
        } else if p.is_file() {
            add_one(root, &p, store, idx)?;
        }
    }
    Ok(())
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
