//! `mkit closure export|verify` — full-disclosure pack export and verify.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{Parser, ValueEnum};
use mkit_core::hash::{Hash, from_hex, to_hex};
use mkit_core::pack_key;
use mkit_core::store::{ObjectStore, StoreError};
use mkit_core::verify::{ClosureReport, export_closure, verify_closure, verify_closure_manifest};
use mkit_core::{ClosureMode, reachable_objects, reachable_snapshot};

use super::revspec;
use crate::clap_shim;
use crate::exit;
use crate::format::{self, JsonObject};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ClosureFormat {
    Default,
    Json,
}

#[derive(Debug, Parser)]
#[command(
    name = "mkit closure",
    about = "Export or verify a commit's object-set closure (full disclosure)."
)]
enum Cmd {
    /// Write MANIFEST.mkcl and raw-only pack files for a revision.
    Export(ExportArgs),
    /// Verify a closure against a trusted id (`--from`) or the local store.
    Verify(VerifyArgs),
}

#[derive(Debug, Parser)]
struct ExportArgs {
    /// Revision to export (commit, remix, or tag).
    revision: String,
    /// Export the full ancestry (history mode). Default is snapshot.
    #[arg(long)]
    history: bool,
    /// Output directory (default: `./<short-id>.closure/`).
    #[arg(short = 'o', long = "output", value_name = "DIR")]
    output: Option<PathBuf>,
    /// Overwrite a non-empty output directory.
    #[arg(long)]
    force: bool,
    #[arg(long, value_enum, default_value = "default")]
    format: ClosureFormat,
}

#[derive(Debug, Parser)]
struct VerifyArgs {
    /// With `--from`, a trusted 64-hex id. Without, a revision in the local store.
    #[arg(value_name = "COMMIT-ID")]
    commit_id: String,
    /// Directory containing `MANIFEST.mkcl` and `<pack_key>.pack` files.
    #[arg(long, value_name = "DIR")]
    from: Option<PathBuf>,
    /// History mode for a local (no `--from`) check. With `--from`, the
    /// manifest's mode is used.
    #[arg(long)]
    history: bool,
    #[arg(long, value_enum, default_value = "default")]
    format: ClosureFormat,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let cmd = match clap_shim::parse::<Cmd>("mkit closure", args) {
        Ok(c) => c,
        Err(code) => return code,
    };
    match cmd {
        Cmd::Export(opts) => run_export(&opts),
        Cmd::Verify(opts) => run_verify(&opts),
    }
}

fn run_export(opts: &ExportArgs) -> u8 {
    let json = matches!(opts.format, ClosureFormat::Json);
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
    let root = match revspec::resolve_revision(&store, &layout, &opts.revision) {
        Ok(h) => h,
        Err(e) => return emit_err(&format!("{e}"), exit::DATAERR),
    };
    let mode = if opts.history {
        ClosureMode::History
    } else {
        ClosureMode::Snapshot
    };
    let export = match export_closure(&store, &root, mode) {
        Ok(e) => e,
        Err(e) => return emit_err(&e.to_string(), super::prove::map_prove_error(&e)),
    };
    let dir = opts.output.clone().unwrap_or_else(|| {
        PathBuf::from(format!(
            "{}.closure",
            format::short_hash(&root, format::SUMMARY_ABBREV)
        ))
    });
    if let Err((msg, code)) = prepare_dir(&dir, opts.force) {
        return emit_err(&msg, code);
    }
    let manifest_name = "MANIFEST.mkcl";
    if let Err(e) = fs::write(dir.join(manifest_name), &export.manifest) {
        return emit_err(
            &format!("write {}: {e}", dir.join(manifest_name).display()),
            exit::CANTCREAT,
        );
    }
    let mut pack_infos = Vec::new();
    let mut total = export.manifest.len() as u64;
    for pack in &export.packs {
        let key = pack_key(pack);
        let hex = to_hex(&key);
        let file = format!("{hex}.pack");
        if let Err(e) = fs::write(dir.join(&file), pack) {
            return emit_err(
                &format!("write {}: {e}", dir.join(&file).display()),
                exit::CANTCREAT,
            );
        }
        total += pack.len() as u64;
        pack_infos.push((file, key, pack.len() as u64));
    }
    let n_objects = match object_count(&store, &root, mode) {
        Ok(n) => n,
        Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
    };
    let mode_str = mode_name(mode);
    if json {
        emit_export_json(&root, mode_str, &pack_infos, n_objects, manifest_name);
    } else {
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(
            stdout,
            "closure: {mode_str}, {n_objects} objects in {} pack(s), {total} B -> {}",
            pack_infos.len(),
            dir.display()
        );
    }
    exit::OK
}

fn run_verify(opts: &VerifyArgs) -> u8 {
    let json = matches!(opts.format, ClosureFormat::Json);
    if let Some(dir) = opts.from.as_deref() {
        run_verify_from(opts, dir, json)
    } else {
        run_verify_local(opts, json)
    }
}

fn run_verify_from(opts: &VerifyArgs, dir: &Path, json: bool) -> u8 {
    let root = match from_hex(&opts.commit_id) {
        Ok(h) => h,
        Err(e) => {
            return emit_err(
                &format!(
                    "with --from, commit-id must be a trusted 64-hex id (not a revision): {e}"
                ),
                exit::DATAERR,
            );
        }
    };
    let manifest_path = dir.join("MANIFEST.mkcl");
    let manifest = match fs::read(&manifest_path) {
        Ok(b) => b,
        Err(e) => {
            return emit_err(
                &format!("read {}: {e}", manifest_path.display()),
                exit::NOINPUT,
            );
        }
    };
    let decoded = match mkit_core::verify::ClosureManifest::decode(&manifest) {
        Ok(m) => m,
        Err(e) => return emit_err(&e.to_string(), exit::DATAERR),
    };
    if opts.history && decoded.mode != ClosureMode::History {
        return emit_err(
            "manifest mode is snapshot; omit --history or re-export with --history",
            exit::DATAERR,
        );
    }
    let mut packs = Vec::new();
    for key in &decoded.packs {
        let file = dir.join(format!("{}.pack", to_hex(key)));
        match fs::read(&file) {
            Ok(b) => packs.push(b),
            Err(e) => {
                return emit_err(&format!("read {}: {e}", file.display()), exit::NOINPUT);
            }
        }
    }
    let refs: Vec<&[u8]> = packs.iter().map(Vec::as_slice).collect();
    let report = match verify_closure_manifest(&root, &manifest, &refs) {
        Ok(r) => r,
        Err(e) => return emit_err(&e.to_string(), exit::DATAERR),
    };
    emit_report(&report, json)
}

fn run_verify_local(opts: &VerifyArgs, json: bool) -> u8 {
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
    let root = match revspec::resolve_revision(&store, &layout, &opts.commit_id) {
        Ok(h) => h,
        Err(e) => return emit_err(&format!("{e}"), exit::DATAERR),
    };
    let mode = if opts.history {
        ClosureMode::History
    } else {
        ClosureMode::Snapshot
    };
    let hashes = match store.iter_object_hashes() {
        Ok(h) => h,
        Err(e) => return emit_err(&format!("enumerate objects: {e}"), exit::GENERAL_ERROR),
    };
    let mut objects = Vec::new();
    for h in hashes {
        match store.read(&h) {
            Ok(b) => objects.push(b),
            Err(StoreError::ObjectNotFound(_)) => {}
            Err(e) => return emit_err(&format!("read {}: {e}", to_hex(&h)), exit::DATAERR),
        }
    }
    let report = match verify_closure(&root, mode, objects.iter().map(Vec::as_slice)) {
        Ok(r) => r,
        Err(e) => return emit_err(&e.to_string(), exit::DATAERR),
    };
    emit_report(&report, json)
}

fn emit_report(report: &ClosureReport, json: bool) -> u8 {
    if json {
        emit_report_json(report);
    } else {
        emit_report_text(report);
    }
    if report.is_complete() {
        exit::OK
    } else {
        exit::DATAERR
    }
}

fn emit_report_text(report: &ClosureReport) {
    let mut stdout = std::io::stdout().lock();
    let mode = mode_name(report.mode);
    if report.is_complete() {
        let _ = writeln!(
            stdout,
            "ok: closure complete ({} objects, {mode})",
            report.verified
        );
    } else {
        let _ = writeln!(
            stdout,
            "bad: closure incomplete: {} missing, {} corrupt",
            report.missing.len(),
            report.corrupt.len()
        );
        print_id_list(&mut stdout, &report.missing, None);
        let corrupt_ids: Vec<Hash> = report.corrupt.iter().map(|(id, _)| *id).collect();
        print_id_list(&mut stdout, &corrupt_ids, Some(&report.corrupt));
    }
    if !report.unreferenced.is_empty() {
        let _ = writeln!(stdout, "note: {} unreferenced", report.unreferenced.len());
        print_id_list(&mut stdout, &report.unreferenced, None);
    }
}

fn print_id_list(stdout: &mut impl Write, ids: &[Hash], corrupt: Option<&[(Hash, String)]>) {
    let show = ids.len().min(10);
    for id in ids.iter().take(show) {
        if let Some(pairs) = corrupt {
            let reason = pairs
                .iter()
                .find(|(h, _)| h == id)
                .map_or("", |(_, r)| r.as_str());
            let _ = writeln!(stdout, "{} ({reason})", to_hex(id));
        } else {
            let _ = writeln!(stdout, "{}", to_hex(id));
        }
    }
    if ids.len() > 10 {
        let _ = writeln!(stdout, "... and {} more", ids.len() - 10);
    }
}

fn emit_report_json(report: &ClosureReport) {
    let missing: Vec<String> = report.missing.iter().map(to_hex).collect();
    let unreferenced: Vec<String> = report.unreferenced.iter().map(to_hex).collect();
    let mut corrupt_items = Vec::new();
    for (id, reason) in &report.corrupt {
        let mut obj = JsonObject::new();
        obj.field_hash("id", id).field_str("reason", reason);
        corrupt_items.push(obj.finish());
    }
    let mut top = JsonObject::new();
    top.field_hash("root", &report.root)
        .field_str("mode", mode_name(report.mode))
        .field_u64("verified", report.verified as u64)
        .field_bool("complete", report.is_complete())
        .field_raw("missing", &format::json_string_array(&missing))
        .field_raw("corrupt", &format!("[{}]", corrupt_items.join(",")))
        .field_raw("unreferenced", &format::json_string_array(&unreferenced));
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "{}", top.finish());
}

fn emit_export_json(
    root: &Hash,
    mode: &str,
    packs: &[(String, Hash, u64)],
    objects: usize,
    manifest: &str,
) {
    let mut pack_items = Vec::new();
    for (file, key, bytes) in packs {
        let mut obj = JsonObject::new();
        obj.field_str("file", file)
            .field_hash("blake3", key)
            .field_u64("bytes", *bytes);
        pack_items.push(obj.finish());
    }
    let mut top = JsonObject::new();
    top.field_hash("root", root)
        .field_str("mode", mode)
        .field_raw("packs", &format!("[{}]", pack_items.join(",")))
        .field_u64("objects", objects as u64)
        .field_str("manifest", manifest);
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "{}", top.finish());
}

fn prepare_dir(dir: &Path, force: bool) -> Result<(), (String, u8)> {
    if dir.exists() {
        if dir.is_file() {
            return Err((
                format!("{} exists and is not a directory", dir.display()),
                exit::CANTCREAT,
            ));
        }
        let empty = fs::read_dir(dir)
            .map_err(|e| (format!("read {}: {e}", dir.display()), exit::NOINPUT))?
            .next()
            .is_none();
        if !empty && !force {
            return Err((
                format!("{} is not empty; pass --force to overwrite", dir.display()),
                exit::CANTCREAT,
            ));
        }
    } else {
        fs::create_dir_all(dir)
            .map_err(|e| (format!("create {}: {e}", dir.display()), exit::CANTCREAT))?;
    }
    Ok(())
}

fn object_count(store: &ObjectStore, root: &Hash, mode: ClosureMode) -> Result<usize, String> {
    let set = match mode {
        ClosureMode::Snapshot => reachable_snapshot(store, root),
        ClosureMode::History => reachable_objects(store, root),
    }
    .map_err(|e| format!("count objects: {e}"))?;
    Ok(set.len())
}

fn mode_name(mode: ClosureMode) -> &'static str {
    match mode {
        ClosureMode::Snapshot => "snapshot",
        ClosureMode::History => "history",
    }
}

use super::error as emit_err;

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(args: &[String]) -> Result<Cmd, clap::Error> {
        let mut full: Vec<String> = vec!["mkit closure".into()];
        full.extend_from_slice(args);
        Cmd::try_parse_from(full)
    }

    #[test]
    fn parse_export_defaults() {
        let Cmd::Export(p) = parse_args(&["export".into(), "HEAD".into()]).unwrap() else {
            panic!("expected export");
        };
        assert_eq!(p.revision, "HEAD");
        assert!(!p.history);
        assert!(!p.force);
    }

    #[test]
    fn parse_verify_from() {
        let Cmd::Verify(p) = parse_args(&[
            "verify".into(),
            "aa".repeat(32),
            "--from".into(),
            "/tmp/c".into(),
        ])
        .unwrap() else {
            panic!("expected verify");
        };
        assert!(p.from.is_some());
        assert!(!p.history);
    }
}
