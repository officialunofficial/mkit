//! End-to-end CLI coverage for `prove` / `verify-proof` / `closure`
//! (issue #1015 verifier kit PR 5).
#![allow(clippy::unwrap_used)]

mod common;

use std::fs;

use common::{KEY_SEED, Repo};
use mkit_core::hash::to_hex_bytes;
use mkit_core::sign::KeyPair;

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn head(repo: &Repo) -> String {
    stdout(&repo.ok(&["rev-parse", "HEAD"])).trim().to_owned()
}

fn signer_hex() -> String {
    let kp = KeyPair::from_seed(KEY_SEED);
    to_hex_bytes(&kp.public.0)
}

fn write_trust_roots(path: &std::path::Path, pubkey_hex: &str) {
    fs::write(
        path,
        format!(
            "[[trust_root]]\nkeyid = \"ed25519:{pubkey_hex}\"\nkind = \"ed25519\"\npubkey_hex = \"{pubkey_hex}\"\n"
        ),
    )
    .unwrap();
}

fn json_has(text: &str, key: &str) -> bool {
    text.contains(&format!("\"{key}\""))
}

fn fixture_repo() -> Repo {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"hello proof\n", "small");
    repo.write("src/nested.txt", b"nested body\n");
    repo.ok(&["add", "src/nested.txt"]);
    repo.ok(&["commit", "-m", "nested"]);
    repo
}

#[test]
fn prove_verify_root_tree() {
    let repo = fixture_repo();
    let commit = head(&repo);
    repo.ok(&["prove", "HEAD", "-o", "root.mkdp"]);
    let out = repo.ok(&["verify-proof", &commit, "root.mkdp"]);
    let text = stdout(&out);
    assert!(text.starts_with("ok: object / @"), "got: {text}");
    assert!(text.contains("valid signature"), "{text}");
}

#[test]
fn prove_verify_small_file() {
    let repo = fixture_repo();
    let commit = head(&repo);
    let out = repo.ok(&["prove", "HEAD", "a.txt", "-o", "a.mkdp"]);
    let status = stdout(&out);
    assert!(status.contains("proof:"), "{status}");
    assert!(status.contains("a.txt"), "{status}");
    let out = repo.ok(&["verify-proof", &commit, "a.mkdp", "--expect-path", "a.txt"]);
    let text = stdout(&out);
    assert!(text.contains("ok: object a.txt"), "{text}");
}

#[test]
fn prove_verify_nested_file() {
    let repo = fixture_repo();
    let commit = head(&repo);
    repo.ok(&["prove", "HEAD", "src/nested.txt", "-o", "n.mkdp"]);
    let out = repo.ok(&[
        "verify-proof",
        &commit,
        "n.mkdp",
        "--expect-path",
        "src/nested.txt",
    ]);
    assert!(stdout(&out).contains("ok: object src/nested.txt"));
}

#[test]
fn prove_verify_chunk_and_range() {
    let repo = fixture_repo();
    let mut big = vec![0u8; 3 * 1024 * 1024];
    let mut x = 0u8;
    for b in &mut big {
        *b = x;
        x = x.wrapping_add(1);
    }
    repo.write("big.bin", &big);
    repo.ok(&["add", "big.bin"]);
    repo.ok(&["commit", "-m", "chunked"]);
    let commit = head(&repo);

    repo.ok(&["prove", "HEAD", "big.bin", "--chunk", "0", "-o", "c.mkdp"]);
    let out = repo.ok(&["verify-proof", &commit, "c.mkdp"]);
    assert!(
        stdout(&out).contains("ok: chunk big.bin"),
        "{}",
        stdout(&out)
    );

    repo.ok(&[
        "prove", "HEAD", "big.bin", "--range", "0:100", "-o", "r.mkdp",
    ]);
    let out = repo.ok(&[
        "verify-proof",
        &commit,
        "r.mkdp",
        "--payload-out",
        "slice.bin",
    ]);
    assert!(
        stdout(&out).contains("ok: range big.bin"),
        "{}",
        stdout(&out)
    );
    let got = fs::read(repo.path().join("slice.bin")).unwrap();
    assert_eq!(got, &big[..100]);

    repo.ok(&[
        "prove",
        "HEAD",
        "big.bin",
        "--range",
        "0:100",
        "--with-offsets",
        "-o",
        "ro.mkdp",
    ]);
    let out = repo.ok(&["verify-proof", &commit, "ro.mkdp"]);
    assert!(
        stdout(&out).contains("ok: range big.bin"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn expect_path_mismatch_is_dataerr() {
    let repo = fixture_repo();
    let commit = head(&repo);
    repo.ok(&["prove", "HEAD", "a.txt", "-o", "a.mkdp"]);
    let out = repo.run(&[
        "verify-proof",
        &commit,
        "a.mkdp",
        "--expect-path",
        "other.txt",
    ]);
    assert_eq!(out.status.code(), Some(65));
    assert!(
        stdout(&out).contains("bad: authenticated path"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn tampered_bundle_fails() {
    let repo = fixture_repo();
    let commit = head(&repo);
    repo.ok(&["prove", "HEAD", "a.txt", "-o", "a.mkdp"]);
    let path = repo.path().join("a.mkdp");
    let mut bytes = fs::read(&path).unwrap();
    let i = bytes.len() / 2;
    bytes[i] ^= 0xff;
    fs::write(&path, bytes).unwrap();
    let out = repo.run(&["verify-proof", &commit, "a.mkdp"]);
    assert_eq!(out.status.code(), Some(65));
    assert!(stdout(&out).contains("bad:"), "{}", stdout(&out));
}

#[test]
fn trusted_signer_and_unlisted() {
    let repo = fixture_repo();
    let commit = head(&repo);
    repo.ok(&["prove", "HEAD", "a.txt", "-o", "a.mkdp"]);
    let hex = signer_hex();
    let good = repo.path().join("good.toml");
    write_trust_roots(&good, &hex);
    let out = repo.ok(&[
        "verify-proof",
        &commit,
        "a.mkdp",
        "--trusted",
        "--trust-roots",
        good.to_str().unwrap(),
    ]);
    assert!(stdout(&out).contains("signer trusted"), "{}", stdout(&out));

    let bad = repo.path().join("bad.toml");
    write_trust_roots(&bad, &"99".repeat(32));
    let out = repo.run(&[
        "verify-proof",
        &commit,
        "a.mkdp",
        "--trusted",
        "--trust-roots",
        bad.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(65));
    assert!(
        stdout(&out).contains("not in the trust-roots registry"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn prove_and_verify_json_keys() {
    let repo = fixture_repo();
    let commit = head(&repo);
    let out = repo.ok(&["prove", "HEAD", "a.txt", "-o", "a.mkdp", "--format=json"]);
    let js = stdout(&out);
    for key in [
        "commit_id",
        "path",
        "selector",
        "bundle_bytes",
        "bundle_blake3",
        "output",
    ] {
        assert!(json_has(&js, key), "prove json missing {key}: {js}");
    }
    let out = repo.ok(&["verify-proof", &commit, "a.mkdp", "--format=json"]);
    let js = stdout(&out);
    for key in [
        "commit_id",
        "tree_hash",
        "path",
        "leaf_id",
        "signer",
        "signature_valid",
        "payload",
        "signer_trusted",
    ] {
        assert!(json_has(&js, key), "verify-proof json missing {key}: {js}");
    }
}

#[test]
fn closure_export_verify_roundtrip() {
    let repo = fixture_repo();
    let commit = head(&repo);
    repo.ok(&["closure", "export", "HEAD", "-o", "snap.closure"]);
    let out = repo.ok(&["closure", "verify", &commit, "--from", "snap.closure"]);
    assert!(
        stdout(&out).contains("ok: closure complete"),
        "{}",
        stdout(&out)
    );
    assert!(stdout(&out).contains("snapshot"), "{}", stdout(&out));

    repo.ok(&[
        "closure",
        "export",
        "HEAD",
        "--history",
        "-o",
        "hist.closure",
    ]);
    let out = repo.ok(&[
        "closure",
        "verify",
        &commit,
        "--from",
        "hist.closure",
        "--history",
    ]);
    assert!(
        stdout(&out).contains("ok: closure complete"),
        "{}",
        stdout(&out)
    );
    assert!(stdout(&out).contains("history"), "{}", stdout(&out));

    let out = repo.ok(&["closure", "verify", "HEAD"]);
    assert!(
        stdout(&out).contains("ok: closure complete"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn closure_missing_or_corrupt_pack() {
    let repo = fixture_repo();
    let commit = head(&repo);
    repo.ok(&["closure", "export", "HEAD", "-o", "c.closure"]);
    let dir = repo.path().join("c.closure");
    let packs: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "pack"))
        .collect();
    assert!(!packs.is_empty());
    fs::remove_file(&packs[0]).unwrap();
    let out = repo.run(&["closure", "verify", &commit, "--from", "c.closure"]);
    assert_eq!(out.status.code(), Some(66));
    assert!(
        stderr(&out).contains("error:") || stdout(&out).contains("bad:"),
        "stdout={} stderr={}",
        stdout(&out),
        stderr(&out)
    );

    repo.ok(&["closure", "export", "HEAD", "-o", "c2.closure", "--force"]);
    let dir = repo.path().join("c2.closure");
    let pack = fs::read_dir(&dir)
        .unwrap()
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "pack"))
        .unwrap();
    let mut bytes = fs::read(&pack).unwrap();
    let i = bytes.len() / 2;
    bytes[i] ^= 0xff;
    fs::write(&pack, bytes).unwrap();
    let out = repo.run(&["closure", "verify", &commit, "--from", "c2.closure"]);
    assert_eq!(out.status.code(), Some(65));
    let combined = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        combined.contains("hash does not match") || combined.contains("bad:"),
        "{combined}"
    );
}

#[test]
fn closure_local_reports_missing_blob() {
    let repo = Repo::new();
    repo.commit_file("keep.txt", b"keep\n", "base");
    repo.commit_file("only-head.txt", b"unique-to-head\n", "head");
    let listing = stdout(&repo.ok(&["ls-tree", "-r", "HEAD"]));
    let blob_hex = listing
        .lines()
        .find(|l| l.contains("only-head.txt"))
        .and_then(|l| l.split_whitespace().nth(2))
        .expect("blob hex")
        .to_owned();
    let obj = repo
        .mkit_dir()
        .join("objects")
        .join(&blob_hex[..2])
        .join(&blob_hex[2..]);
    fs::remove_file(&obj).unwrap();
    let out = repo.run(&["closure", "verify", "HEAD"]);
    assert_eq!(out.status.code(), Some(65), "stderr={}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("bad: closure incomplete"), "{text}");
    assert!(text.contains("missing"), "{text}");
}

#[test]
fn closure_local_reports_corrupt_blob() {
    let repo = Repo::new();
    repo.commit_file("keep.txt", b"keep\n", "base");
    repo.commit_file("only-head.txt", b"unique-to-head\n", "head");
    let listing = stdout(&repo.ok(&["ls-tree", "-r", "HEAD"]));
    let blob_hex = listing
        .lines()
        .find(|l| l.contains("only-head.txt"))
        .and_then(|l| l.split_whitespace().nth(2))
        .expect("blob hex")
        .to_owned();
    let obj = repo
        .mkit_dir()
        .join("objects")
        .join(&blob_hex[..2])
        .join(&blob_hex[2..]);
    let mut bytes = fs::read(&obj).unwrap();
    let i = bytes.len() / 2;
    bytes[i] ^= 0xff;
    fs::write(&obj, bytes).unwrap();
    let out = repo.run(&["closure", "verify", "HEAD"]);
    assert_eq!(out.status.code(), Some(65), "stderr={}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains("bad: closure incomplete: 0 missing, 1 corrupt"),
        "{text}"
    );
}

#[test]
fn closure_local_hides_unreferenced_unless_flag() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"first\n", "first");
    let first = head(&repo);
    repo.commit_file("b.txt", b"second\n", "second");

    let out = repo.ok(&["closure", "verify", &first]);
    let text = stdout(&out);
    assert!(text.contains("ok: closure complete"), "{text}");
    assert!(!text.contains("unreferenced"), "{text}");

    let out = repo.ok(&["closure", "verify", &first, "--show-unreferenced"]);
    let text = stdout(&out);
    assert!(text.contains("unreferenced"), "{text}");
}

#[test]
fn closure_json_keys() {
    let repo = fixture_repo();
    let commit = head(&repo);
    let out = repo.ok(&[
        "closure",
        "export",
        "HEAD",
        "-o",
        "j.closure",
        "--format=json",
    ]);
    let js = stdout(&out);
    for key in ["root", "mode", "packs", "objects", "manifest"] {
        assert!(json_has(&js, key), "export json missing {key}: {js}");
    }
    let out = repo.ok(&[
        "closure",
        "verify",
        &commit,
        "--from",
        "j.closure",
        "--format=json",
    ]);
    let js = stdout(&out);
    for key in [
        "root",
        "mode",
        "verified",
        "complete",
        "missing",
        "corrupt",
        "unreferenced",
    ] {
        assert!(json_has(&js, key), "verify json missing {key}: {js}");
    }
}
