//! `mkit prove <revision> [<path>]` — build a disclosure bundle for a
//! path, chunk, or byte range under a commit (or remix).

use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use clap::{Parser, ValueEnum};
use mkit_core::hash::{Hash, hash};
use mkit_core::store::ObjectStore;
use mkit_core::verify::{Selector, VerifyError, build_disclosure};

use super::revspec;
use crate::clap_shim;
use crate::exit;
use crate::format::{self, JsonObject};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProveFormat {
    Default,
    Json,
}

#[derive(Debug, Parser)]
#[command(
    name = "mkit prove",
    about = "Build a disclosure bundle proving a path, chunk, or byte range belongs to a commit."
)]
struct ProveOpts {
    /// Revision: an object hash, a branch/tag name, or `HEAD`.
    revision: String,
    /// Repository-relative path, split on `/`. Omitted: disclose the root tree.
    path: Option<String>,
    /// Disclose chunk N of a `ChunkedBlob` (0-based data-chunk index).
    #[arg(long, value_name = "N", conflicts_with = "range")]
    chunk: Option<u32>,
    /// Disclose OFFSET:LEN decimal bytes of the file (LEN must be > 0).
    #[arg(
        long,
        value_name = "OFFSET:LEN",
        conflicts_with = "chunk",
        value_parser = parse_range_arg
    )]
    range: Option<(u64, u64)>,
    /// Include per-preceding-chunk length proofs so the range's absolute
    /// file offset is authenticated. Only valid with `--range`.
    #[arg(long, requires = "range")]
    with_offsets: bool,
    /// Write the bundle to FILE instead of stdout.
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    output: Option<PathBuf>,
    /// Emit a JSON summary. The bundle still goes to `-o` or (non-TTY) stdout.
    #[arg(long, value_enum, default_value = "default")]
    format: ProveFormat,
}

fn parse_range_arg(s: &str) -> Result<(u64, u64), String> {
    let (off, len) = s
        .split_once(':')
        .ok_or_else(|| "range must be OFFSET:LEN (decimal bytes)".to_string())?;
    let offset: u64 = off
        .parse()
        .map_err(|_| format!("invalid range offset '{off}'"))?;
    let length: u64 = len
        .parse()
        .map_err(|_| format!("invalid range length '{len}'"))?;
    if length == 0 {
        return Err("range length must be greater than 0".into());
    }
    Ok((offset, length))
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<ProveOpts>("mkit prove", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let json = matches!(opts.format, ProveFormat::Json);
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
    let commit_id = match revspec::resolve_revision(&store, &layout, &opts.revision) {
        Ok(h) => h,
        Err(e) => return emit_err(&format!("{e}"), exit::DATAERR),
    };
    let path_owned = match split_repo_path(opts.path.as_deref().unwrap_or("")) {
        Ok(p) => p,
        Err(msg) => return emit_err(&msg, exit::USAGE),
    };
    let path_refs: Vec<&[u8]> = path_owned.iter().map(Vec::as_slice).collect();
    let selector = match (&opts.chunk, opts.range, opts.with_offsets) {
        (None, None, false) => Selector::Object,
        (Some(n), None, false) => Selector::Chunk(*n),
        (None, Some((offset, len)), with_offsets) => Selector::Range {
            offset,
            len,
            with_offsets,
        },
        _ => return emit_err("invalid selector combination", exit::USAGE),
    };
    let bundle = match build_disclosure(&store, &commit_id, &path_refs, selector) {
        Ok(b) => b,
        Err(e) => return emit_err(&e.to_string(), map_prove_error(&e)),
    };
    let dest = match write_bundle(&bundle, opts.output.as_deref()) {
        Ok(d) => d,
        Err((msg, code)) => return emit_err(&msg, code),
    };
    let path_display = display_path(opts.path.as_deref());
    let kind = selector_kind(selector);
    let status_to_stderr = opts.output.is_none();
    if json {
        emit_prove_json(
            &commit_id,
            &path_display,
            selector,
            bundle.len(),
            &hash(&bundle),
            &dest,
            status_to_stderr,
        );
    } else {
        let line = format!(
            "proof: {} B for {} @ {} ({kind})",
            bundle.len(),
            path_display,
            format::short_hash(&commit_id, format::SUMMARY_ABBREV),
        );
        emit_status(&line, status_to_stderr);
    }
    exit::OK
}

fn write_bundle(bundle: &[u8], output: Option<&Path>) -> Result<String, (String, u8)> {
    if let Some(path) = output {
        fs_write(path, bundle)?;
        return Ok(path.display().to_string());
    }
    if io::stdout().is_terminal() {
        return Err((
            "refusing to write a binary proof to a TTY; pass -o FILE or redirect stdout".into(),
            exit::USAGE,
        ));
    }
    io::stdout()
        .write_all(bundle)
        .map_err(|e| (format!("write stdout: {e}"), exit::CANTCREAT))?;
    Ok("-".into())
}

fn fs_write(path: &Path, bytes: &[u8]) -> Result<(), (String, u8)> {
    std::fs::write(path, bytes)
        .map_err(|e| (format!("write {}: {e}", path.display()), exit::CANTCREAT))
}

fn emit_status(line: &str, to_stderr: bool) {
    if to_stderr {
        let mut stderr = io::stderr().lock();
        let _ = writeln!(stderr, "{line}");
    } else {
        let mut stdout = io::stdout().lock();
        let _ = writeln!(stdout, "{line}");
    }
}

fn emit_prove_json(
    commit_id: &Hash,
    path: &str,
    selector: Selector,
    bundle_bytes: usize,
    bundle_blake3: &Hash,
    output: &str,
    to_stderr: bool,
) {
    let mut sel = JsonObject::new();
    match selector {
        Selector::Object => {
            sel.field_str("kind", "object");
        }
        Selector::Chunk(index) => {
            sel.field_str("kind", "chunk")
                .field_u64("index", u64::from(index));
        }
        Selector::Range {
            offset,
            len,
            with_offsets,
        } => {
            sel.field_str("kind", "range")
                .field_u64("offset", offset)
                .field_u64("len", len)
                .field_bool("with_offsets", with_offsets);
        }
    }
    let mut top = JsonObject::new();
    top.field_hash("commit_id", commit_id)
        .field_str("path", path)
        .field_raw("selector", &sel.finish())
        .field_u64("bundle_bytes", bundle_bytes as u64)
        .field_hash("bundle_blake3", bundle_blake3)
        .field_str("output", output);
    let line = top.finish();
    emit_status(&line, to_stderr);
}

fn selector_kind(selector: Selector) -> &'static str {
    match selector {
        Selector::Object => "object",
        Selector::Chunk(_) => "chunk",
        Selector::Range { .. } => "range",
    }
}

pub(crate) fn split_repo_path(path: &str) -> Result<Vec<Vec<u8>>, String> {
    if path.is_empty() || path == "/" || path == "." {
        return Ok(Vec::new());
    }
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let mut parts = Vec::new();
    for p in trimmed.split('/') {
        if p.is_empty() || p == "." {
            continue;
        }
        if p == ".." {
            return Err("path must be repository-relative without '..'".into());
        }
        if p.len() > 255 {
            return Err("path component exceeds 255 bytes".into());
        }
        parts.push(p.as_bytes().to_vec());
    }
    Ok(parts)
}

pub(crate) fn display_path(path: Option<&str>) -> String {
    match path {
        None | Some("" | "/" | ".") => "/".into(),
        Some(p) => p.trim_matches('/').to_owned(),
    }
}

pub(crate) fn map_prove_error(e: &VerifyError) -> u8 {
    match e {
        VerifyError::PathNotFound(_)
        | VerifyError::PathThroughNonTree
        | VerifyError::Store(mkit_core::store::StoreError::ObjectNotFound(_)) => exit::NOINPUT,
        VerifyError::RangeCrossesChunkBoundary
        | VerifyError::SelectorLeafMismatch
        | VerifyError::RangeOutOfBounds
        | VerifyError::ZeroLengthRange
        | VerifyError::ChunkIndexOutOfRange { .. }
        | VerifyError::NotACommitOrRemix(_) => exit::DATAERR,
        _ => exit::GENERAL_ERROR,
    }
}

use super::error as emit_err;

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(args: &[String]) -> Result<ProveOpts, clap::Error> {
        let mut full: Vec<String> = vec!["mkit prove".into()];
        full.extend_from_slice(args);
        ProveOpts::try_parse_from(full)
    }

    #[test]
    fn parse_revision_only() {
        let p = parse_args(&["HEAD".into()]).unwrap();
        assert_eq!(p.revision, "HEAD");
        assert!(p.path.is_none());
        assert!(p.chunk.is_none());
        assert!(p.range.is_none());
        assert!(!p.with_offsets);
    }

    #[test]
    fn parse_chunk_and_range_conflict() {
        let err = parse_args(&[
            "HEAD".into(),
            "a.txt".into(),
            "--chunk".into(),
            "0".into(),
            "--range".into(),
            "0:10".into(),
        ]);
        assert!(err.is_err());
    }

    #[test]
    fn parse_with_offsets_requires_range() {
        let err = parse_args(&["HEAD".into(), "a.txt".into(), "--with-offsets".into()]);
        assert!(err.is_err());
    }

    #[test]
    fn parse_range_rejects_zero_len() {
        let err = parse_args(&[
            "HEAD".into(),
            "a.txt".into(),
            "--range".into(),
            "0:0".into(),
        ]);
        assert!(err.is_err());
    }

    #[test]
    fn split_path_nested() {
        let p = split_repo_path("src/lib.rs").unwrap();
        assert_eq!(p, vec![b"src".to_vec(), b"lib.rs".to_vec()]);
    }
}
