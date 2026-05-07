//! `mkit rm <path>` — mark a path for removal in the next commit.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use mkit_core::hash::ZERO;
use mkit_core::index::{self, EntryStatus, IndexEntry};
use mkit_core::store::ObjectStore;

use crate::exit;

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let Some(path) = args.first() else {
        return super::usage_error("usage: mkit rm <path>");
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let store = match ObjectStore::open(&cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let mut idx = match super::read_or_seed_index_from_head(&cwd, &store) {
        Ok(i) => i,
        Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
    };
    let rel_path = match index_path_for_arg(&cwd, Path::new(path)) {
        Ok(p) => p,
        Err(e) => return emit_err(&e, exit::DATAERR),
    };
    let entry = IndexEntry {
        path: rel_path.clone(),
        status: EntryStatus::Removed,
        object_hash: ZERO,
    };
    if let Some(at) = idx.find_entry(&rel_path) {
        idx.entries[at] = entry;
    } else {
        idx.entries.push(entry);
    }
    match index::write_index(&cwd, &idx) {
        Ok(()) => exit::OK,
        Err(e) => emit_err(&format!("write index: {e}"), exit::CANTCREAT),
    }
}

fn index_path_for_arg(root: &Path, arg: &Path) -> Result<String, String> {
    let rel = if arg.is_absolute() {
        absolute_arg_to_repo_relative(root, arg)?
    } else {
        arg.to_path_buf()
    };

    let mut parts: Vec<String> = Vec::new();
    for component in rel.as_path().components() {
        match component {
            Component::Normal(part) => {
                let part = part
                    .to_str()
                    .ok_or_else(|| "path is not valid UTF-8".to_string())?;
                parts.push(part.to_string());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if parts.pop().is_none() {
                    return Err(format!("invalid path: {}", arg.display()));
                }
            }
            Component::Prefix(_) | Component::RootDir => {
                return Err(format!("invalid path: {}", arg.display()));
            }
        }
    }

    let path = parts.join("/");
    if !index::validate_index_path(&path) {
        return Err(format!("invalid path: {path}"));
    }
    Ok(path)
}

fn absolute_arg_to_repo_relative(root: &Path, arg: &Path) -> Result<PathBuf, String> {
    let root = root.canonicalize().map_err(|e| format!("repo root: {e}"))?;

    if let Ok(rel) = arg.strip_prefix(&root) {
        return Ok(rel.to_path_buf());
    }

    let mut suffix: Vec<OsString> = vec![
        arg.file_name()
            .ok_or_else(|| format!("invalid path: {}", arg.display()))?
            .to_os_string(),
    ];
    let mut ancestor = arg
        .parent()
        .ok_or_else(|| format!("invalid path: {}", arg.display()))?;
    while ancestor.symlink_metadata().is_err() {
        let name = ancestor
            .file_name()
            .ok_or_else(|| format!("path is outside repository: {}", arg.display()))?;
        suffix.push(name.to_os_string());
        ancestor = ancestor
            .parent()
            .ok_or_else(|| format!("path is outside repository: {}", arg.display()))?;
    }

    let mut normalized = ancestor
        .canonicalize()
        .map_err(|e| format!("path {}: {e}", ancestor.display()))?;
    for component in suffix.iter().rev() {
        normalized.push(component);
    }

    normalized
        .strip_prefix(&root)
        .map(Path::to_path_buf)
        .map_err(|_| format!("path is outside repository: {}", arg.display()))
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
