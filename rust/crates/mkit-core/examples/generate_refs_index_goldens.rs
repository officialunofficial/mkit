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

use mkit_core::hash::{self, HASH_LEN};
use mkit_core::index::{EntryStatus, Index, IndexEntry, MAGIC};
use mkit_core::refs::encode_ref_wire;

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let out_dir = args.get(1).map_or_else(
        || PathBuf::from("rust/tests/golden/refs-index"),
        PathBuf::from,
    );
    fs::create_dir_all(&out_dir)?;

    // The two index fixtures share the same logical entries; only the
    // on-disk version differs. The `_v1` files (no `_v2` suffix) pin the
    // legacy read-compat layout (version 0x01, no stat cache) and are
    // emitted via `serialize_v1` below so re-running never clobbers them
    // with the v2 layout. The `_v2` files pin exactly what the live
    // `Index::serialize` emits today (version 0x02, zeroed stat cache).
    // See SPEC-INDEX §6/§7.

    let empty = Index::new();
    let three = three_entry_index();

    // 1a. index_empty.bin — v1 read-compat header (9 bytes).
    let empty_v1 = serialize_v1(&empty);
    assert_eq!(empty_v1.len(), 9);
    write_vector(&out_dir, "index_empty", &empty_v1)?;

    // 1b. index_empty_v2.bin — current writer output (9 bytes header).
    let empty_v2 = empty.serialize();
    assert_eq!(empty_v2[4], 0x02);
    write_vector(&out_dir, "index_empty_v2", &empty_v2)?;

    // 2a. index_3entries.bin — v1 layout: blob + tree + executable.
    let three_v1 = serialize_v1(&three);
    write_vector(&out_dir, "index_3entries", &three_v1)?;

    // 2b. index_3entries_v2.bin — same entries, current v2 layout.
    let three_v2 = three.serialize();
    assert_eq!(three_v2[4], 0x02);
    write_vector(&out_dir, "index_3entries_v2", &three_v2)?;

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
        "index_empty_v2",
        "index_3entries",
        "index_3entries_v2",
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

/// The fixed three-entry index shared by the v1 and v2 fixtures:
/// blob + tree + executable with pinned paths and zeroed stat cache.
fn three_entry_index() -> Index {
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
    idx
}

/// Serialise an [`Index`] in the legacy v1 layout (version `0x01`, no
/// stat-cache fields). `Index::serialize` only ever emits v2, so this
/// local encoder keeps the read-compat fixtures byte-stable across
/// re-runs. Mirrors the v1 wire described in SPEC-INDEX §2/§6.
fn serialize_v1(idx: &Index) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.push(0x01); // FORMAT_VERSION_V1
    let count = u32::try_from(idx.entries.len()).expect("entry count fits in u32");
    out.extend_from_slice(&count.to_le_bytes());
    for entry in &idx.entries {
        out.push(entry.status as u8);
        out.extend_from_slice(&entry.object_hash);
        debug_assert_eq!(entry.object_hash.len(), HASH_LEN);
        let path_len = u16::try_from(entry.path.len()).expect("path length fits in u16");
        out.extend_from_slice(&path_len.to_le_bytes());
        out.extend_from_slice(entry.path.as_bytes());
    }
    out
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
