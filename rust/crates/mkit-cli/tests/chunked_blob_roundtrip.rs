//! Golden round-trip for files above the chunking threshold (#203).
//!
//! A clean tracked file larger than `CHUNK_THRESHOLD` (1 MiB) is stored
//! as a `ChunkedBlob` by `mkit add`, exactly as `worktree::build_tree`
//! would. Because `add`, the commit/index tree builder, the
//! `build_tree` worktree-hashing path, and the `rm` dirty-guard now all
//! agree on that single representation, the file must:
//!
//! - commit without a "non-blob object" failure,
//! - report clean across `status` and `diff` while untouched,
//! - be removable by a plain `mkit rm` (the dirty-guard must not
//!   false-positive a clean large file),
//! - round-trip byte-identically through `add` → `commit` → `checkout`,
//! - and `mkit cat <hash>` must stream its reassembled content rather
//!   than the `Object::chunked_blob` placeholder.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::process::Command;

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run_in(cwd: &std::path::Path, args: &[&str]) -> std::process::Output {
    let xdg = tempfile::tempdir().expect("xdg tempdir");
    let out = Command::new(mkit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg.path())
        .output()
        .expect("spawn mkit");
    drop(xdg);
    out
}

/// A deterministic, > 1 MiB pseudo-random buffer. The splitmix64 mixing
/// gives `FastCdc` real boundary candidates so the file genuinely chunks
/// into more than one `Blob` (a uniform buffer would still be a
/// `ChunkedBlob` but with a single max-sized chunk).
fn big_payload() -> Vec<u8> {
    let n = 1024 * 1024 + 256 * 1024; // CHUNK_THRESHOLD + 256 KiB
    let mut buf = Vec::with_capacity(n);
    let mut state: u64 = 0x00C0_FFEE;
    for _ in 0..n {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        buf.push((z & 0xFF) as u8);
    }
    buf
}

#[test]
fn large_file_roundtrips_and_reports_clean() {
    let td = tempfile::tempdir().unwrap();
    let p = td.path();
    assert!(run_in(p, &["init"]).status.success(), "init failed");
    assert!(run_in(p, &["keygen"]).status.success(), "keygen failed");

    let payload = big_payload();
    fs::write(p.join("big.bin"), &payload).unwrap();

    // add → commit. The commit path (build_tree_from_index) must accept
    // the ChunkedBlob the >1 MiB file stages as.
    let out = run_in(p, &["add", "big.bin"]);
    assert!(out.status.success(), "add failed: {out:?}");
    let out = run_in(p, &["commit", "-m", "big"]);
    assert!(
        out.status.success(),
        "commit of >1 MiB file must succeed (no non-blob error): {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // status: clean. The worktree-hashing path and the index path now
    // produce the same hash for the untouched large file.
    let out = run_in(p, &["status", "--porcelain"]);
    assert!(out.status.success(), "status failed: {out:?}");
    assert!(
        out.stdout.is_empty(),
        "clean >1 MiB file must report unmodified, got: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );

    // diff (HEAD vs worktree): empty.
    let out = run_in(p, &["diff"]);
    assert!(out.status.success(), "diff failed: {out:?}");
    assert!(
        out.stdout.is_empty(),
        "clean >1 MiB file must produce no diff, got: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// Run `mkit cat <hash>` and return stdout as bytes, asserting success.
fn cat(cwd: &std::path::Path, hex: &str) -> Vec<u8> {
    let out = run_in(cwd, &["cat", hex]);
    assert!(
        out.status.success(),
        "cat {hex} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

#[test]
fn cat_reassembles_chunked_blob() {
    let td = tempfile::tempdir().unwrap();
    let p = td.path();
    assert!(run_in(p, &["init"]).status.success());
    assert!(run_in(p, &["keygen"]).status.success());

    let payload = big_payload();
    fs::write(p.join("big.bin"), &payload).unwrap();
    assert!(run_in(p, &["add", "big.bin"]).status.success());
    assert!(
        run_in(p, &["commit", "-m", "big"]).status.success(),
        "commit failed"
    );

    // Resolve the canonical object hash for big.bin by walking the
    // committed tree: HEAD tree → the `big.bin` entry. The committed
    // tree hash comes from `log --format=json` (full 64-hex `tree`
    // field), avoiding a dependency on `mkit hash`, which is a
    // blob-only debug tool.
    let log = run_in(p, &["log", "--format=json"]);
    assert!(log.status.success(), "log failed: {log:?}");
    let log_out = String::from_utf8(log.stdout).unwrap();
    let first = log_out.lines().next().expect("at least one commit");
    let needle = "\"tree\":\"";
    let start = first.find(needle).expect("json has a tree field") + needle.len();
    let tree_hex = first[start..start + 64].to_owned();
    assert_eq!(tree_hex.len(), 64, "tree hex must be full 64 chars");

    // `cat <tree>` prints `<mode> <hash> <name>` per entry.
    let tree_dump = String::from_utf8(cat(p, &tree_hex)).unwrap();
    let entry_hex = tree_dump
        .lines()
        .find(|l| l.ends_with(" big.bin"))
        .and_then(|l| l.split_whitespace().nth(1))
        .expect("tree has a big.bin entry")
        .to_owned();

    // `mkit cat <chunked-blob-hash>` must reassemble and stream the full
    // content, NOT print the `Object::chunked_blob` placeholder.
    let dumped = cat(p, &entry_hex);
    assert_eq!(
        dumped, payload,
        "cat must reassemble the chunked blob byte-identically"
    );
}

#[test]
fn rm_dirty_guard_does_not_false_positive_clean_large_file() {
    let td = tempfile::tempdir().unwrap();
    let p = td.path();
    assert!(run_in(p, &["init"]).status.success());
    assert!(run_in(p, &["keygen"]).status.success());

    let payload = big_payload();
    fs::write(p.join("big.bin"), &payload).unwrap();
    assert!(run_in(p, &["add", "big.bin"]).status.success());
    assert!(
        run_in(p, &["commit", "-m", "big"]).status.success(),
        "commit failed"
    );

    // A plain `mkit rm` (no --force, no --cached) runs the dirty-guard.
    // The clean large file must NOT be reported as locally modified.
    let out = run_in(p, &["rm", "big.bin"]);
    assert!(
        out.status.success(),
        "rm of a clean >1 MiB file must not trip the dirty-guard: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !p.join("big.bin").exists(),
        "rm should have deleted the worktree file"
    );
}

#[test]
fn checkout_restores_chunked_file_byte_identically() {
    let td = tempfile::tempdir().unwrap();
    let p = td.path();
    assert!(run_in(p, &["init"]).status.success());
    assert!(run_in(p, &["keygen"]).status.success());

    let payload = big_payload();
    fs::write(p.join("big.bin"), &payload).unwrap();
    assert!(run_in(p, &["add", "big.bin"]).status.success());
    assert!(
        run_in(p, &["commit", "-m", "big"]).status.success(),
        "commit failed"
    );

    // Branch off, drop the chunked file there, and commit. Switching to
    // that branch removes big.bin from the worktree without leaving the
    // worktree dirty (the deletion is committed).
    assert!(run_in(p, &["branch", "without"]).status.success());
    assert!(run_in(p, &["checkout", "without"]).status.success());
    assert!(
        run_in(p, &["rm", "big.bin"]).status.success(),
        "rm on the side branch failed"
    );
    assert!(
        run_in(p, &["commit", "-m", "drop big"]).status.success(),
        "commit of removal failed"
    );
    assert!(
        !p.join("big.bin").exists(),
        "big.bin should be gone on the side branch"
    );

    // Switching back to main must reassemble and restore the ChunkedBlob
    // byte-identically.
    let out = run_in(p, &["checkout", "main"]);
    assert!(
        out.status.success(),
        "checkout main failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let restored = fs::read(p.join("big.bin")).unwrap();
    assert_eq!(
        restored, payload,
        "checkout must restore the >1 MiB file byte-identically"
    );
}
