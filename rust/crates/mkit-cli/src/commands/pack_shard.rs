//! `mkit pack-shard <hash>` — encode an existing pack into Reed-Solomon
//! shards plus a manifest.
//!
//! This is the producer side of SPEC-PACK-SHARDS. Given a pack
//! object hash, it reads the pack bytes from the local store, gates on
//! the SPEC §6 size threshold (1 MiB), runs the encoder, and writes:
//!
//! ```text
//!   <out>/packs/<hex>/shards.manifest    (manifest, MKSH/v0 bytes)
//!   <out>/packs/<hex>/shards/<index>     (one file per shard)
//! ```
//!
//! Operators publish those files to whichever HTTP / S3 location their
//! clients hit. Shard-aware clients (`mkit-transport-http`,
//! `mkit-transport-s3` with `--features pack-shards`) discover them via
//! the predictable URL / key paths.
//!
//! Compiled only when the CLI is built with `--features pack-shards`
//! (default off — the commonware dep stack is large).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use clap::Parser;
use mkit_core::hash::{Hash, from_hex, to_hex};
use mkit_core::pack_shard::{SHARD_SIZE_THRESHOLD, encode_manifest, encode_pack_to_shards};
use mkit_core::store::ObjectStore;

use crate::clap_shim;
use crate::exit;

#[derive(Debug, Parser)]
#[command(
    name = "mkit pack-shard",
    about = "Encode a stored pack into Reed-Solomon shards (+ manifest)."
)]
struct ShardOpts {
    /// Hex-encoded BLAKE3 hash of the pack object to shard.
    hash: String,

    /// Output directory. Defaults to `<repo>/.mkit/pack-shards`.
    /// Shards are written under `<out>/packs/<hex>/`.
    #[arg(long)]
    out: Option<PathBuf>,

    /// Encode even if the pack is below the SPEC §6 size threshold
    /// (1 MiB). Useful for tests; production producers should leave
    /// this off.
    #[arg(long)]
    force: bool,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<ShardOpts>("mkit pack-shard", args) {
        Ok(o) => o,
        Err(code) => return code,
    };

    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };

    let hash: Hash = match from_hex(&opts.hash) {
        Ok(h) => h,
        Err(_) => {
            return emit_err(
                &format!("invalid hash '{}': expected 64 hex chars", opts.hash),
                exit::USAGE,
            );
        }
    };

    let layout = super::resolve_layout(&cwd);
    let store = match ObjectStore::open(&layout) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };

    let pack = match store.read(&hash) {
        Ok(b) => b,
        Err(e) => return emit_err(&format!("read pack {}: {e}", to_hex(&hash)), exit::NOINPUT),
    };

    // SPEC §6 size gate. Producers should not waste bytes on packs
    // below 1 MiB; the per-shard Merkle overhead dominates.
    if !opts.force && (pack.len() as u64) < SHARD_SIZE_THRESHOLD {
        return emit_err(
            &format!(
                "pack is {} bytes, below the {} byte (1 MiB) shard threshold; \
                 pass --force to encode anyway",
                pack.len(),
                SHARD_SIZE_THRESHOLD
            ),
            exit::USAGE,
        );
    }

    let out_root = opts.out.unwrap_or_else(|| layout.pack_shards_dir());

    let (shards, manifest) =
        match encode_pack_to_shards(&pack, mkit_core::pack_shard::default_config()) {
            Ok(p) => p,
            Err(e) => return emit_err(&format!("encode: {e}"), exit::DATAERR),
        };

    let hex = to_hex(&hash);
    let pack_dir = out_root.join("packs").join(&hex);
    let shards_dir = pack_dir.join("shards");

    if let Err(e) = fs::create_dir_all(&shards_dir) {
        return emit_err(
            &format!("mkdir {}: {e}", shards_dir.display()),
            exit::CANTCREAT,
        );
    }

    // Shards first, manifest last — the manifest is the *publish
    // commit point*. Clients that race the producer either see no
    // manifest (clean fall-through to monolithic) or see manifest +
    // all shards (clean shard path). Writing the manifest before the
    // shards would let a racing reader observe "manifest present,
    // shards missing", which forces a shard-fetch failure and either
    // a noisy retry loop or (worse) a silent downgrade.
    let manifest_bytes = match encode_manifest(&manifest) {
        Ok(b) => b,
        Err(e) => return emit_err(&format!("encode manifest: {e}"), exit::DATAERR),
    };

    for shard in &shards {
        let path = shards_dir.join(shard.index.to_string());
        if let Err(e) = write_atomic(&path, &shard.bytes) {
            return emit_err(&format!("write {}: {e}", path.display()), exit::CANTCREAT);
        }
    }

    let manifest_path = pack_dir.join("shards.manifest");
    if let Err(e) = write_atomic(&manifest_path, &manifest_bytes) {
        return emit_err(
            &format!("write {}: {e}", manifest_path.display()),
            exit::CANTCREAT,
        );
    }

    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(
        stdout,
        "wrote {} shards + manifest under {}",
        shards.len(),
        pack_dir.display()
    );
    exit::OK
}

/// Write `bytes` to `path` via a same-dir tempfile + rename. Mirrors
/// the atomic-write pattern used elsewhere in mkit-core but tailored
/// to the cli's "no-deps" footprint — we don't need fsync since
/// shards are recoverable from the source pack at any time.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = path.to_path_buf();
    let fname = path.file_name().and_then(|f| f.to_str()).unwrap_or("shard");
    tmp.set_file_name(format!(".{fname}.tmp"));
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
    }
    fs::rename(&tmp, path).inspect_err(|_| {
        // Best-effort cleanup; the tmp file is the only thing left behind.
        let _ = fs::remove_file(&tmp);
        let _ = parent; // unused, but kept for clarity in case we add fsync(parent)
    })
}

use super::error as emit_err;

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn invalid_hex_returns_usage_error() {
        // Run with a hash that isn't 64 hex chars. We don't need to
        // be in a real repo because the error fires before ObjectStore
        // is touched.
        let dir = tempfile::tempdir().unwrap();
        // The env::set_current_dir / set_var pair is process-global;
        // mkit's other unit tests do the same and run single-threaded
        // by default.
        let saved_cwd = env::current_dir().ok();
        env::set_current_dir(dir.path()).unwrap();
        let code = run(&["not-hex".to_string()]);
        assert_eq!(code, exit::USAGE);
        if let Some(p) = saved_cwd {
            env::set_current_dir(p).unwrap();
        }
    }
}
