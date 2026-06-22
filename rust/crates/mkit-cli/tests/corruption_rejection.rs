//! Fault injection — corrupted-object / invalid-ref rejection.
//!
//! Mutate on-disk artifacts (loose objects, ref files, HEAD, signatures) and
//! assert the reading command rejects them **cleanly**: an allowlisted non-OK
//! exit, no panic, and never a silent success. The validator unit test proved
//! *detection* on read (`validator_detects_tampered_object`); this proves the **CLI commands**
//! surface corruption as documented errors rather than crashing — the gap the
//! pre-open-source audit flagged (only the bit-flip case was covered before).
//!
//! Two families:
//!   * **hash-mismatch** — corrupt an existing object/ref in place; the read
//!     fails content-addressing / ref decode.
//!   * **deserialize** — write a *content-addressed* garbage object (bytes whose
//!     BLAKE3 matches the path) so it passes content-addressing and then fails
//!     to decode (bad magic / truncated / bad type).

mod common;

use std::fs;
use std::path::PathBuf;

use common::{Repo, check_exit};
use mkit_core::object::Object;
use mkit_core::serialize::serialize;
use mkit_core::store::ObjectStore;
use mkit_core::{hash, refs, to_hex};

/// A repo with one commit and one annotated (signed) tag.
fn committed_repo() -> Repo {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"hello\n", "first");
    repo.ok(&["tag", "-a", "v1", "-m", "release"]);
    repo
}

fn object_file(repo: &Repo, hex: &str) -> PathBuf {
    repo.mkit_dir()
        .join("objects")
        .join(&hex[..2])
        .join(&hex[2..])
}

/// Run a reading command and assert it rejected corruption cleanly: exit in the
/// allowlist (no panic / no signal), and NOT a success.
fn assert_rejected(repo: &Repo, args: &[&str], case: &str) {
    let out = repo.run(args);
    check_exit(&out, case).unwrap_or_else(|e| panic!("{case}: {e}"));
    assert!(
        !out.status.success(),
        "{case}: expected `mkit {}` to reject corruption, but it exited 0\nstdout: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stdout)
    );
}

/// Run a command and assert it SUCCEEDED (for accepted-compatibility cases).
fn assert_accepted(repo: &Repo, args: &[&str], case: &str) {
    let out = repo.run(args);
    check_exit(&out, case).unwrap_or_else(|e| panic!("{case}: {e}"));
    assert!(
        out.status.success(),
        "{case}: expected `mkit {}` to be accepted, but it failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// Object corruption — hash-mismatch family (corrupt an existing object)
// ---------------------------------------------------------------------------

#[test]
fn flipped_object_byte_is_rejected() {
    let repo = committed_repo();
    let head = to_hex(&refs::resolve_head(&repo.mkit_dir()).unwrap().unwrap());
    let path = object_file(&repo, &head);
    let mut bytes = fs::read(&path).unwrap();
    bytes[0] ^= 0xff;
    fs::write(&path, &bytes).unwrap();
    assert_rejected(&repo, &["cat-file", &head], "flipped object byte");
}

#[test]
fn truncated_object_is_rejected() {
    let repo = committed_repo();
    let head = to_hex(&refs::resolve_head(&repo.mkit_dir()).unwrap().unwrap());
    let path = object_file(&repo, &head);
    fs::write(&path, b"\x03MK").unwrap(); // 3 bytes — shorter than the prologue
    assert_rejected(&repo, &["cat-file", &head], "truncated object");
}

// ---------------------------------------------------------------------------
// Object corruption — deserialize family (content-addressed garbage)
// ---------------------------------------------------------------------------

/// Write raw bytes at their own BLAKE3 path so they pass content-addressing,
/// returning the hex hash to address them by.
fn write_raw_object(repo: &Repo, bytes: &[u8]) -> String {
    let hex = to_hex(&hash::hash(bytes));
    let path = object_file(repo, &hex);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, bytes).unwrap();
    hex
}

#[test]
fn content_addressed_garbage_is_rejected_on_decode() {
    // Each variant loads past content-addressing, then must fail to decode.
    let cases: &[(&str, Vec<u8>)] = &[
        ("empty", Vec::new()),
        ("short-prologue", vec![0x03, b'M', b'K']),
        ("bad-magic", {
            let mut v = vec![0x03];
            v.extend_from_slice(b"XXXX");
            v.push(0x01);
            v
        }),
        ("bad-type", {
            let mut v = vec![0x09]; // 0x09 is not a valid ObjectType
            v.extend_from_slice(b"MKT1");
            v.push(0x01);
            v
        }),
    ];
    for (name, bytes) in cases {
        let repo = committed_repo();
        let hex = write_raw_object(&repo, bytes);
        assert_rejected(&repo, &["cat-file", &hex], &format!("decode/{name}"));
    }
}

// ---------------------------------------------------------------------------
// Ref / HEAD corruption
// ---------------------------------------------------------------------------

#[test]
fn malformed_branch_ref_is_rejected() {
    let valid = {
        let repo = committed_repo();
        fs::read_to_string(repo.mkit_dir().join("refs/heads/main")).unwrap()
    };
    let good64 = valid.trim_end().to_owned();
    assert_eq!(good64.len(), 64);

    let cases: &[(&str, String)] = &[
        ("uppercase-hex", format!("{}\n", good64.to_uppercase())),
        ("too-short", format!("{}\n", &good64[..32])),
        ("non-hex", format!("{}\n", "z".repeat(64))),
        ("too-long", format!("{good64}{good64}\n")),
    ];
    for (name, contents) in cases {
        let repo = committed_repo();
        fs::write(repo.mkit_dir().join("refs/heads/main"), contents).unwrap();
        // Drive the STRICT ref reader: `gc`'s `collect_roots` fails closed on an
        // undecodable ref. (Porcelain like `log` is intentionally lenient — a
        // malformed ref reads as `None`, i.e. an unborn branch — so it is the
        // wrong oracle for ref corruption.)
        assert_rejected(&repo, &["gc"], &format!("ref/{name}"));
    }
}

#[test]
fn branch_ref_without_trailing_newline_is_accepted() {
    // `decode_ref_wire` trims optional trailing whitespace, so a 64-hex ref with
    // NO trailing newline is valid (compatibility), not a corruption.
    let repo = committed_repo();
    let p = repo.mkit_dir().join("refs/heads/main");
    let good64 = fs::read_to_string(&p).unwrap().trim_end().to_owned();
    fs::write(&p, &good64).unwrap(); // no '\n'
    // Drive the STRICT ref reader (`gc`/`collect_roots`), not lenient `log`:
    // lenient porcelain can exit 0 on a ref it failed to resolve, which would
    // mask a strict-decode regression that started rejecting newline-less refs.
    assert_accepted(&repo, &["gc"], "ref/no-trailing-newline");
}

#[test]
fn malformed_head_is_rejected() {
    let repo = committed_repo();
    fs::write(repo.mkit_dir().join("HEAD"), b"this is not a head\n").unwrap();
    assert_rejected(&repo, &["status"], "HEAD/garbage");
}

// ---------------------------------------------------------------------------
// Signature tampering (content-valid object, invalid signature)
// ---------------------------------------------------------------------------

#[test]
fn tampered_commit_signature_is_rejected_by_verify() {
    let repo = committed_repo();
    let head = refs::resolve_head(&repo.mkit_dir()).unwrap().unwrap();
    let store = ObjectStore::open(repo.path()).unwrap();
    let Object::Commit(mut c) = store.read_object(&head).unwrap() else {
        panic!("HEAD is not a commit");
    };
    c.signature[0] ^= 0xff; // valid bytes, invalid signature
    let bytes = serialize(&Object::Commit(c)).unwrap();
    let new = store.write(&bytes).unwrap(); // re-store at its (new) content hash
    let hex = to_hex(&new);
    assert_rejected(&repo, &["verify", &hex], "tampered commit signature");
}

#[test]
fn tampered_tag_signature_is_rejected_by_verify() {
    let repo = committed_repo();
    let tag_hash = refs::read_tag(&repo.mkit_dir(), "v1")
        .unwrap()
        .expect("annotated tag v1 ref");
    let store = ObjectStore::open(repo.path()).unwrap();
    let Object::Tag(mut t) = store.read_object(&tag_hash).unwrap() else {
        panic!("v1 is not an annotated tag object");
    };
    t.signature[0] ^= 0xff;
    let bytes = serialize(&Object::Tag(t)).unwrap();
    let new = store.write(&bytes).unwrap();
    let hex = to_hex(&new);
    assert_rejected(&repo, &["verify", &hex], "tampered tag signature");
}
