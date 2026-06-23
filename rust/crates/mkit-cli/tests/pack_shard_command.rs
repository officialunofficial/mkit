//! Integration test for `mkit pack-shard <hash>`.
//!
//! Initialises a temp repo, writes a 2 MiB synthetic blob via
//! `ObjectStore::write`, then dispatches the CLI command through the
//! same in-process `dispatch` entry point production uses. Verifies
//! the output directory layout and that the resulting shards
//! reconstruct the original bytes via `decode_pack_from_shards`.
//!
//! Only compiled with `--features pack-shards`.

#![cfg(feature = "pack-shards")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::env;
use std::fs;
use std::sync::Mutex;

/// Serialise CWD-sensitive tests within this file. Cargo runs
/// integration tests in parallel by default; without this guard one
/// test would step on another's `set_current_dir`. Other CLI tests
/// avoid CWD entirely; the producer pipeline genuinely needs to
/// drive `dispatch` (which reads `std::env::current_dir()`).
static CWD_LOCK: Mutex<()> = Mutex::new(());

use mkit_cli::{dispatch, exit};
use mkit_core::hash::{Hash, hash, to_hex};
use mkit_core::pack_shard::{Shard, decode_manifest, decode_pack_from_shards};
use mkit_core::store::ObjectStore;

fn synthetic_blob(size: usize) -> Vec<u8> {
    let mut x: u64 = 0xDEAD_BEEF_CAFE_F00D;
    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(size);
    out
}

/// Run `body` with the current working directory pointed at `path`,
/// always restoring the prior CWD on the way out — even on panic. The
/// in-process `dispatch` reads `std::env::current_dir()`, so tests
/// need to be careful about cross-test CWD bleed.
fn with_cwd(path: &std::path::Path, body: impl FnOnce()) {
    // PoisonError::into_inner() — a previous panicked test has
    // already restored cwd, the lock is just dirty.
    let _guard = CWD_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let saved = env::current_dir().ok();
    env::set_current_dir(path).unwrap();
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
    if let Some(p) = saved {
        let _ = env::set_current_dir(p);
    }
    if let Err(e) = panicked {
        std::panic::resume_unwind(e);
    }
}

#[test]
fn pack_shard_produces_decodable_shards() {
    let dir = tempfile::tempdir().unwrap();
    with_cwd(dir.path(), || {
        // Initialise a repo and write a 2 MiB synthetic blob.
        let store = ObjectStore::init(dir.path()).unwrap();
        let blob = synthetic_blob(2 * 1024 * 1024);
        let h: Hash = store.write(&blob).unwrap();
        assert_eq!(h, hash(&blob));

        let argv = vec!["mkit".to_string(), "pack-shard".to_string(), to_hex(&h)];
        let code = dispatch(&argv);
        assert_eq!(code, exit::OK, "dispatch returned {code}");

        let pack_dir = dir
            .path()
            .join(".mkit")
            .join("pack-shards")
            .join("packs")
            .join(to_hex(&h));
        let manifest_path = pack_dir.join("shards.manifest");
        assert!(manifest_path.exists(), "manifest missing");
        let manifest_bytes = fs::read(&manifest_path).unwrap();
        let manifest = decode_manifest(&manifest_bytes).unwrap();
        assert_eq!(manifest.pack_hash, h);
        assert_eq!(manifest.shard_hashes.len(), 20);

        let shards_dir = pack_dir.join("shards");
        let mut shards: Vec<Shard> = Vec::with_capacity(20);
        for i in 0..20u16 {
            let p = shards_dir.join(i.to_string());
            let bytes = fs::read(&p).unwrap();
            shards.push(Shard { index: i, bytes });
        }
        let recovered = decode_pack_from_shards(&shards, &manifest).unwrap();
        assert_eq!(recovered, blob);
    });
}

#[test]
fn pack_shard_rejects_packs_below_threshold_without_force() {
    let dir = tempfile::tempdir().unwrap();
    with_cwd(dir.path(), || {
        let store = ObjectStore::init(dir.path()).unwrap();
        let blob = synthetic_blob(512 * 1024);
        let h = store.write(&blob).unwrap();

        let argv = vec!["mkit".to_string(), "pack-shard".to_string(), to_hex(&h)];
        let code = dispatch(&argv);
        assert_eq!(code, exit::USAGE);

        let argv_force = vec![
            "mkit".to_string(),
            "pack-shard".to_string(),
            to_hex(&h),
            "--force".to_string(),
        ];
        let code = dispatch(&argv_force);
        assert_eq!(code, exit::OK);
    });
}
