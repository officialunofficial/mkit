//! Generator for the refs/index golden vectors.
//!
//! Run with `cargo run -p mkit-core --example generate_refs_index_goldens
//! -- <out-dir>` (defaults to `rust/tests/golden/refs-index`). Idempotent:
//! every input is a fixed constant; re-running emits byte-identical
//! files.
//!
//! This generator is the source of truth for these vectors; the
//! crate's unit tests prove the same bytes round-trip through the
//! parser.

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use mkit_core::hash;
use mkit_core::index::{EntryStatus, Index, IndexEntry};
use mkit_core::refs::encode_ref_wire;

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let out_dir = args.get(1).map_or_else(
        || PathBuf::from("rust/tests/golden/refs-index"),
        PathBuf::from,
    );
    fs::create_dir_all(&out_dir)?;

    // 1. index_empty.bin — 9 bytes (header only).
    let empty = Index::new();
    let empty_bytes = empty.serialize();
    assert_eq!(empty_bytes.len(), 9);
    write_vector(&out_dir, "index_empty", &empty_bytes)?;

    // 2. index_3entries.bin — blob + tree + executable, fixed paths.
    let mut idx = Index::new();
    idx.entries.push(IndexEntry {
        path: "README.md".to_string(),
        status: EntryStatus::Blob,
        object_hash: hash::hash(b"phase4-blob"),
        mtime_ns: 0,
        size: 0,
        ino: 0,
        ctime_ns: 0,
    });
    idx.entries.push(IndexEntry {
        path: "src".to_string(),
        status: EntryStatus::Tree,
        object_hash: hash::hash(b"phase4-tree"),
        mtime_ns: 0,
        size: 0,
        ino: 0,
        ctime_ns: 0,
    });
    idx.entries.push(IndexEntry {
        path: "scripts/build".to_string(),
        status: EntryStatus::Executable,
        object_hash: hash::hash(b"phase4-exe"),
        mtime_ns: 0,
        size: 0,
        ino: 0,
        ctime_ns: 0,
    });
    let idx_bytes = idx.serialize();
    write_vector(&out_dir, "index_3entries", &idx_bytes)?;

    // 3. ref_detached.bin — 65-byte ref wire (lowercase hex + \n).
    let detached = hash::hash(b"phase4-detached-head");
    let wire = encode_ref_wire(&detached);
    write_vector(&out_dir, "ref_detached", &wire)?;

    // 4. head_symbolic.bin — `ref: refs/heads/main\n`.
    let head_sym = b"ref: refs/heads/main\n";
    write_vector(&out_dir, "head_symbolic", head_sym)?;

    // Manifest for the integration tests.
    let mut manifest = String::new();
    manifest.push_str("# Refs/index golden vectors (deterministic)\n");
    manifest.push_str("# Produced by examples/generate_refs_index_goldens.rs\n");
    manifest.push_str("# Format: <name> <blake3-hex-of-bin-bytes>\n");
    for name in [
        "index_empty",
        "index_3entries",
        "ref_detached",
        "head_symbolic",
    ] {
        let bytes = fs::read(out_dir.join(format!("{name}.bin")))?;
        let h = hash::hash(&bytes);
        writeln!(manifest, "{name} {}", hash::to_hex(&h)).expect("write to String never fails");
    }
    fs::write(out_dir.join("MANIFEST.txt"), manifest)?;

    println!("refs-index goldens written to {}", out_dir.display());
    Ok(())
}

fn write_vector(out: &std::path::Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    let bin_path = out.join(format!("{name}.bin"));
    let json_path = out.join(format!("{name}.json"));
    fs::write(&bin_path, bytes)?;
    let digest = hash::to_hex(&hash::hash(bytes));
    let json = format!(
        "{{\n  \"name\": \"{name}\",\n  \"bin\": \"{name}.bin\",\n  \"size\": {},\n  \"blake3\": \"{digest}\"\n}}\n",
        bytes.len()
    );
    fs::write(&json_path, json)?;
    Ok(())
}
