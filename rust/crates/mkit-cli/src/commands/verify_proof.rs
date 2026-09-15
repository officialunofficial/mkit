//! `mkit verify-proof <commit-id> <bundle>` — verify a disclosure bundle
//! against a trusted commit id.

use std::io::{self, Read, Write};
use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use mkit_core::hash::{from_hex, hash, to_hex, to_hex_bytes};
use mkit_core::object::EntryMode;
use mkit_core::verify::{Disclosed, DisclosedPayload, verify_disclosure};

use super::prove::display_path;
use super::trust_roots;
use crate::clap_shim;
use crate::exit;
use crate::format::{self, JsonObject};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum VerifyProofFormat {
    Default,
    Json,
}

#[derive(Debug, Parser)]
#[command(
    name = "mkit verify-proof",
    about = "Verify a disclosure bundle against a trusted 64-hex commit id."
)]
struct VerifyProofOpts {
    /// Trusted 64-hex commit (or remix) id. Not a revision: this command
    /// does not resolve refs.
    #[arg(value_name = "COMMIT-ID")]
    commit_id: String,
    /// Bundle file, or `-` to read from stdin.
    #[arg(value_name = "BUNDLE")]
    bundle: String,
    /// Fail with dataerr if the authenticated path does not match PATH.
    /// This is the SPEC-DISCLOSURE rule that the caller compares the
    /// returned path; the bundle does not authenticate the request.
    #[arg(long, value_name = "PATH")]
    expect_path: Option<String>,
    /// Also cross-check the signer against the trust-roots registry
    /// (default path). `signature_valid == false` is a failure with this flag.
    #[arg(long)]
    trusted: bool,
    /// Path to a trust-roots TOML file. Implies `--trusted`.
    #[arg(long, value_name = "PATH")]
    trust_roots: Option<String>,
    /// Emit the wasm `verify_disclosure` JSON shape (plus `signer_trusted`).
    #[arg(long, value_enum, default_value = "default")]
    format: VerifyProofFormat,
    /// Write the verified payload bytes (object, chunk, or range) to FILE.
    #[arg(long, value_name = "FILE")]
    payload_out: Option<PathBuf>,
}

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<VerifyProofOpts>("mkit verify-proof", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let json = matches!(opts.format, VerifyProofFormat::Json);
    let commit_id = match from_hex(&opts.commit_id) {
        Ok(h) => h,
        Err(e) => {
            return emit_err(
                &format!("commit-id must be 64 hex characters: {e}"),
                exit::DATAERR,
            );
        }
    };
    let bundle = match read_bundle(&opts.bundle) {
        Ok(b) => b,
        Err((msg, code)) => return emit_err(&msg, code),
    };
    let disclosed = match verify_disclosure(&commit_id, &bundle) {
        Ok(d) => d,
        Err(e) => {
            emit_human(&format!("bad: {e}"), json);
            return exit::DATAERR;
        }
    };
    if let Some(expect) = opts.expect_path.as_deref() {
        let got = authenticated_path(&disclosed.path);
        let want = display_path(Some(expect));
        if !paths_match(&got, &want) {
            emit_human(
                &format!("bad: authenticated path '{got}' does not match --expect-path '{want}'"),
                json,
            );
            return exit::DATAERR;
        }
    }

    let want_trust = opts.trusted || opts.trust_roots.is_some();
    let mut signer_trusted: Option<bool> = None;
    let mut trusted_keyid: Option<String> = None;
    if want_trust {
        let cwd = match std::env::current_dir() {
            Ok(p) => p,
            Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
        };
        let layout = match super::resolve_layout(&cwd) {
            Ok(layout) => layout,
            Err(code) => return code,
        };
        let trust_path = opts
            .trust_roots
            .as_deref()
            .map_or_else(trust_roots::default_trust_roots_path, PathBuf::from);
        if let Err(code) = trust_roots::warn_if_unsafe_trust_roots(
            &trust_path,
            layout.common_dir(),
            opts.trust_roots.is_some(),
        ) {
            return code;
        }
        trust_roots::note_if_missing(&trust_path);
        let entries = match trust_roots::load_entries(&trust_path) {
            Ok(e) => e,
            Err((msg, code)) => return emit_err(&msg, code),
        };
        if let Some(keyid) = trust_roots::find_ed25519_signer(&entries, &disclosed.signer) {
            signer_trusted = Some(true);
            trusted_keyid = Some(trust_roots::short_keyid(keyid));
        } else {
            signer_trusted = Some(false);
        }
        if !disclosed.signature_valid {
            emit_result(
                &disclosed,
                signer_trusted.as_ref(),
                trusted_keyid.as_deref(),
                json,
            );
            return exit::DATAERR;
        }
        if signer_trusted == Some(false) {
            emit_result(
                &disclosed,
                signer_trusted.as_ref(),
                trusted_keyid.as_deref(),
                json,
            );
            return exit::DATAERR;
        }
    }

    if let Some(path) = opts.payload_out.as_deref() {
        let bytes = payload_bytes(&disclosed.payload);
        if let Err(e) = std::fs::write(path, bytes) {
            return emit_err(&format!("write {}: {e}", path.display()), exit::CANTCREAT);
        }
    }

    emit_result(
        &disclosed,
        signer_trusted.as_ref(),
        trusted_keyid.as_deref(),
        json,
    );
    if want_trust && (signer_trusted != Some(true) || !disclosed.signature_valid) {
        exit::DATAERR
    } else {
        exit::OK
    }
}

fn read_bundle(spec: &str) -> Result<Vec<u8>, (String, u8)> {
    if spec == "-" {
        let mut buf = Vec::new();
        io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| (format!("read stdin: {e}"), exit::NOINPUT))?;
        return Ok(buf);
    }
    std::fs::read(spec).map_err(|e| (format!("read {spec}: {e}"), exit::NOINPUT))
}

fn emit_result(
    d: &Disclosed,
    signer_trusted: Option<&bool>,
    trusted_keyid: Option<&str>,
    json: bool,
) {
    let failed =
        matches!(signer_trusted, Some(false)) || (signer_trusted.is_some() && !d.signature_valid);
    if json {
        emit_json(d, signer_trusted.copied());
        emit_human(&human_line(d, trusted_keyid, failed), true);
    } else {
        emit_human(&human_line(d, trusted_keyid, failed), false);
    }
}

fn emit_human(line: &str, to_stderr: bool) {
    if to_stderr {
        let mut stderr = io::stderr().lock();
        let _ = writeln!(stderr, "{line}");
    } else {
        let mut stdout = io::stdout().lock();
        let _ = writeln!(stdout, "{line}");
    }
}

fn human_line(d: &Disclosed, trusted_keyid: Option<&str>, failed: bool) -> String {
    let kind = payload_kind(&d.payload);
    let path = authenticated_path(&d.path);
    let short = format::short_hash(&d.commit_id, format::SUMMARY_ABBREV);
    let nbytes = payload_bytes(&d.payload).len();
    let keyid = trusted_keyid.map_or_else(
        || {
            let hex = to_hex_bytes(&d.signer);
            if hex.len() > 16 {
                format!("{}…", &hex[..16])
            } else {
                hex
            }
        },
        ToOwned::to_owned,
    );
    let sig = if d.signature_valid {
        "valid signature"
    } else {
        "INVALID signature"
    };
    let trust = if trusted_keyid.is_some() {
        ", signer trusted"
    } else {
        ""
    };
    if failed && !d.signature_valid {
        format!("bad: {kind} {path} @ {short}, {nbytes} B, signer {keyid} ({sig}){trust}")
    } else if failed {
        format!(
            "bad: signature valid, but signer {} is not in the trust-roots registry",
            to_hex_bytes(&d.signer)
        )
    } else {
        format!("ok: {kind} {path} @ {short}, {nbytes} B, signer {keyid} ({sig}){trust}")
    }
}

fn emit_json(d: &Disclosed, signer_trusted: Option<bool>) {
    let mut top = JsonObject::new();
    top.field_hash("commit_id", &d.commit_id)
        .field_hash("tree_hash", &d.tree_hash)
        .field_raw("path", &path_json(&d.path))
        .field_hash("leaf_id", &d.leaf_id)
        .field_str("signer", &to_hex_bytes(&d.signer))
        .field_bool("signature_valid", d.signature_valid)
        .field_raw("payload", &payload_json(&d.payload))
        .field_raw("step_inner_roots", &hashes_json(&d.step_inner_roots))
        .field_opt_hash("chunk_inner_root", d.chunk_inner_root.as_ref());
    match signer_trusted {
        Some(v) => {
            top.field_bool("signer_trusted", v);
        }
        None => {
            top.field_raw("signer_trusted", "null");
        }
    }
    let mut stdout = io::stdout().lock();
    let _ = writeln!(stdout, "{}", top.finish());
}

fn hashes_json(hashes: &[mkit_core::hash::Hash]) -> String {
    let items: Vec<String> = hashes
        .iter()
        .map(|h| format!("\"{}\"", to_hex(h)))
        .collect();
    format!("[{}]", items.join(","))
}

fn path_json(path: &[(Vec<u8>, EntryMode)]) -> String {
    let mut items = Vec::with_capacity(path.len());
    for (name, mode) in path {
        let mut obj = JsonObject::new();
        match std::str::from_utf8(name) {
            Ok(s) => {
                obj.field_str("name", s);
            }
            Err(_) => {
                obj.field_raw("name", "null");
            }
        }
        obj.field_str("name_hex", &to_hex_bytes(name))
            .field_str("mode", mode_str(*mode));
        items.push(obj.finish());
    }
    format!("[{}]", items.join(","))
}

fn payload_json(payload: &DisclosedPayload) -> String {
    let bytes = payload_bytes(payload);
    let bytes_len = bytes.len() as u64;
    let bytes_blake3 = to_hex(&hash(bytes));
    let mut obj = JsonObject::new();
    match payload {
        DisclosedPayload::Object { .. } => {
            obj.field_str("kind", "object")
                .field_u64("bytes_len", bytes_len)
                .field_str("bytes_blake3", &bytes_blake3);
        }
        DisclosedPayload::Chunk {
            total_size,
            chunk_size,
            index,
            ..
        } => {
            obj.field_str("kind", "chunk")
                .field_u64("bytes_len", bytes_len)
                .field_str("bytes_blake3", &bytes_blake3)
                .field_u64("index", u64::from(*index))
                .field_u64("total_size", *total_size)
                .field_u64("chunk_size", u64::from(*chunk_size));
        }
        DisclosedPayload::Range {
            blob_id,
            chunk,
            offset_in_blob,
            absolute_offset,
            ..
        } => {
            obj.field_str("kind", "range")
                .field_u64("bytes_len", bytes_len)
                .field_str("bytes_blake3", &bytes_blake3)
                .field_hash("blob_id", blob_id);
            match chunk {
                None => {
                    obj.field_raw("chunk", "null");
                }
                Some((index, total_size, chunk_size)) => {
                    let mut c = JsonObject::new();
                    c.field_u64("index", u64::from(*index))
                        .field_u64("total_size", *total_size)
                        .field_u64("chunk_size", u64::from(*chunk_size));
                    obj.field_raw("chunk", &c.finish());
                }
            }
            obj.field_u64("offset_in_blob", *offset_in_blob);
            match absolute_offset {
                Some(off) => {
                    obj.field_u64("absolute_offset", *off);
                }
                None => {
                    obj.field_raw("absolute_offset", "null");
                }
            }
        }
    }
    obj.finish()
}

fn payload_bytes(payload: &DisclosedPayload) -> &[u8] {
    match payload {
        DisclosedPayload::Object { bytes }
        | DisclosedPayload::Chunk { bytes, .. }
        | DisclosedPayload::Range { bytes, .. } => bytes,
    }
}

fn payload_kind(payload: &DisclosedPayload) -> &'static str {
    match payload {
        DisclosedPayload::Object { .. } => "object",
        DisclosedPayload::Chunk { .. } => "chunk",
        DisclosedPayload::Range { .. } => "range",
    }
}

fn mode_str(mode: EntryMode) -> &'static str {
    match mode {
        EntryMode::Blob => "blob",
        EntryMode::Tree => "tree",
        EntryMode::Symlink => "symlink",
        EntryMode::Executable => "exec",
    }
}

fn authenticated_path(path: &[(Vec<u8>, EntryMode)]) -> String {
    if path.is_empty() {
        return "/".into();
    }
    path.iter()
        .map(|(n, _)| String::from_utf8_lossy(n).into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

fn paths_match(got: &str, want: &str) -> bool {
    normalize_path(got) == normalize_path(want)
}

fn normalize_path(p: &str) -> String {
    let t = p.trim_matches('/');
    if t.is_empty() {
        String::new()
    } else {
        t.to_owned()
    }
}

use super::error as emit_err;

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(args: &[String]) -> Result<VerifyProofOpts, clap::Error> {
        let mut full: Vec<String> = vec!["mkit verify-proof".into()];
        full.extend_from_slice(args);
        VerifyProofOpts::try_parse_from(full)
    }

    #[test]
    fn parse_positional() {
        let p = parse_args(&["aa".repeat(32), "bundle.bin".into()]).unwrap();
        assert_eq!(p.bundle, "bundle.bin");
        assert!(p.expect_path.is_none());
        assert!(!p.trusted);
    }

    #[test]
    fn paths_match_root_aliases() {
        assert!(paths_match("/", ""));
        assert!(paths_match("/", "/"));
        assert!(paths_match("src/a.txt", "/src/a.txt"));
        assert!(!paths_match("a.txt", "b.txt"));
    }
}
