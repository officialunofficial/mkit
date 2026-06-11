//! Round-trip proof of SPEC-GIT-BRIDGE §1.1/§9/§10: translate a real
//! mkit store's closure to git objects, reconstruct every object from
//! the git bytes alone, and require bit-identical mkit bytes, equal
//! BLAKE3 hashes, and original-signature re-verification — plus a
//! determinism check (two independent translations agree) and a
//! differential check against the real `git` binary when present.

use mkit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tag, Tree, TreeEntry};
use mkit_core::sign::{KeyPair, sign_commit, sign_tag};
use mkit_core::{Hash, ObjectStore};
use mkit_git_bridge::gitobj::{GitObject, sha1_hex};
use mkit_git_bridge::translate::translate_closure;
use mkit_git_bridge::verify::{ShallowVerdict, shallow_verify};
use mkit_git_bridge::{BridgeError, reconstruct};
use std::collections::HashMap;
use std::process::{Command, Stdio};

const KEY_SEED: [u8; 32] = [0x11; 32];
const TS: u64 = 1_700_000_000;

fn store() -> (tempfile::TempDir, ObjectStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = ObjectStore::init(dir.path()).unwrap();
    (dir, store)
}

fn put(store: &ObjectStore, obj: &Object) -> Hash {
    store.write(&mkit_core::serialize(obj).unwrap()).unwrap()
}

fn signed_commit(store: &ObjectStore, tree_hash: Hash, parents: Vec<Hash>, message: &str) -> Hash {
    let kp = KeyPair::from_seed(KEY_SEED);
    let mut c = Commit::new_unannotated(
        tree_hash,
        parents,
        Identity::ed25519(kp.public.0),
        kp.public.0,
        message.as_bytes().to_vec(),
        TS,
        [0; 64],
    );
    c.signature = sign_commit(&c, &kp).unwrap().0;
    put(store, &Object::Commit(c))
}

/// Build a small but feature-complete history:
/// root commit → child commit whose tree exercises the divergent
/// sort case, a symlink, an executable, a nested tree, and a >1 MiB
/// chunked blob; plus a signed annotated tag on the child.
fn build_fixture(store: &ObjectStore) -> (Hash, Hash) {
    let blob = put(
        store,
        &Object::Blob(Blob {
            data: b"hello\n".to_vec(),
        }),
    );
    let empty_tree = put(store, &Object::Tree(Tree { entries: vec![] }));
    let root = signed_commit(store, empty_tree, vec![], "root\n");

    // >1 MiB content goes through the worktree chunker for realism.
    let big: Vec<u8> = (0u32..300_000).flat_map(u32::to_le_bytes).collect();
    assert!(big.len() > 1024 * 1024);
    let big_hash = mkit_core::worktree::store_file_object(store, &big).unwrap();
    assert!(matches!(
        store.read_object(&big_hash).unwrap(),
        Object::ChunkedBlob(_)
    ));

    let link_target = put(
        store,
        &Object::Blob(Blob {
            data: b"hello.txt".to_vec(),
        }),
    );
    let sub = put(
        store,
        &Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: b"big.bin".to_vec(),
                mode: EntryMode::Blob,
                object_hash: big_hash,
            }],
        }),
    );
    // mkit byte-lex order: foo, foo.txt — git order is foo.txt, foo/.
    let tree = put(
        store,
        &Object::Tree(Tree {
            entries: vec![
                TreeEntry {
                    name: b"foo".to_vec(),
                    mode: EntryMode::Tree,
                    object_hash: sub,
                },
                TreeEntry {
                    name: b"foo.txt".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: blob,
                },
                TreeEntry {
                    name: b"link".to_vec(),
                    mode: EntryMode::Symlink,
                    object_hash: link_target,
                },
                TreeEntry {
                    name: b"run.sh".to_vec(),
                    mode: EntryMode::Executable,
                    object_hash: blob,
                },
            ],
        }),
    );
    let child = signed_commit(store, tree, vec![root], "child with everything\n");

    let kp = KeyPair::from_seed(KEY_SEED);
    let mut tag = Tag {
        target: child,
        target_type: mkit_core::ObjectType::Commit,
        name: b"v1.0.0".to_vec(),
        tagger: Identity::opaque(b"Release Bot".to_vec()),
        signer: kp.public.0,
        message: b"first release\n".to_vec(),
        timestamp: TS,
        signature: [0; 64],
    };
    tag.signature = sign_tag(&tag, &kp).unwrap().0;
    let tag_hash = put(store, &Object::Tag(tag));
    (child, tag_hash)
}

type Emitted = Vec<(Hash, GitObject)>;

fn translate_all(store: &ObjectStore, root: &Hash) -> (HashMap<Hash, [u8; 20]>, Emitted) {
    let mut known = HashMap::new();
    let mut emitted = Vec::new();
    translate_closure(store, root, &mut known, &mut |h, g| {
        emitted.push((*h, g.clone()));
        Ok(())
    })
    .unwrap();
    (known, emitted)
}

#[test]
fn full_round_trip_bit_exact_with_signatures() {
    let (_d, store) = store();
    let (_child, tag_hash) = build_fixture(&store);
    let (known, emitted) = translate_all(&store, &tag_hash);

    // sha1 → blake3 inverse for tree reconstruction.
    let inverse: HashMap<[u8; 20], Hash> = known.iter().map(|(k, v)| (*v, *k)).collect();

    let mut chunks_seen: HashMap<Hash, Vec<u8>> = HashMap::new();
    for (mkit_hash, git_obj) in &emitted {
        let original = store.read(mkit_hash).unwrap();
        // Chunked manifests reconstruct from the flattened blob along
        // with their chunk blobs; everything else 1:1.
        let rec = reconstruct::reconstruct(git_obj, &|id| inverse.get(id).copied()).unwrap();
        assert_eq!(rec.hash, *mkit_hash, "hash mismatch");
        assert_eq!(
            rec.bytes,
            original,
            "byte mismatch for {}",
            mkit_core::to_hex(mkit_hash)
        );
        for (h, bytes) in rec.extras {
            chunks_seen.insert(h, bytes);
        }
        // Shallow verification on commits/tags: originals are signed.
        match git_obj.gtype {
            mkit_git_bridge::GitType::Commit | mkit_git_bridge::GitType::Tag => {
                assert_eq!(shallow_verify(git_obj).unwrap(), ShallowVerdict::Verified);
            }
            _ => {}
        }
    }
    // Re-chunked extras must be the exact original chunk objects.
    for (h, bytes) in chunks_seen {
        assert_eq!(
            store.read(&h).unwrap(),
            bytes,
            "chunk {}",
            mkit_core::to_hex(&h)
        );
    }
}

#[test]
fn translation_is_deterministic_across_runs() {
    let (_d1, s1) = store();
    let (_d2, s2) = store();
    let (_, t1) = build_fixture(&s1);
    let (_, t2) = build_fixture(&s2);
    assert_eq!(t1, t2, "fixture itself must be deterministic");
    let (k1, e1) = translate_all(&s1, &t1);
    let (k2, e2) = translate_all(&s2, &t2);
    assert_eq!(k1, k2, "blake3→sha1 maps differ");
    let b1: Vec<_> = e1.iter().map(|(h, g)| (*h, g.raw())).collect();
    let b2: Vec<_> = e2.iter().map(|(h, g)| (*h, g.raw())).collect();
    assert_eq!(b1, b2, "emitted git bytes differ");
}

#[test]
fn unsigned_commit_reports_unsigned_not_tampered() {
    let (_d, store) = store();
    let empty_tree = put(&store, &Object::Tree(Tree { entries: vec![] }));
    let c = Commit::new_unannotated(
        empty_tree,
        vec![],
        Identity::opaque(b"importer".to_vec()),
        [0; 32],
        b"unsigned\n".to_vec(),
        TS,
        [0; 64],
    );
    let h = put(&store, &Object::Commit(c));
    let (_known, emitted) = translate_all(&store, &h);
    let (_, commit_obj) = emitted
        .iter()
        .find(|(eh, _)| eh == &h)
        .expect("commit emitted");
    assert_eq!(
        shallow_verify(commit_obj).unwrap(),
        ShallowVerdict::Unsigned
    );
}

#[test]
fn remix_refusal_is_typed() {
    let (_d, store) = store();
    let empty_tree = put(&store, &Object::Tree(Tree { entries: vec![] }));
    let kp = KeyPair::from_seed(KEY_SEED);
    let remix = mkit_core::object::Remix {
        tree_hash: empty_tree,
        parents: vec![],
        sources: vec![],
        author: Identity::ed25519(kp.public.0),
        signer: kp.public.0,
        message: b"remix\n".to_vec(),
        timestamp: TS,
        signature: [1; 64],
    };
    let h = put(&store, &Object::Remix(remix));
    let mut known = HashMap::new();
    let err = translate_closure(&store, &h, &mut known, &mut |_, _| Ok(())).unwrap_err();
    assert!(
        matches!(
            err,
            BridgeError::Refused(mkit_git_bridge::Refusal::Remix { .. })
        ),
        "got {err}"
    );
}

#[test]
fn reconstruct_rejects_foreign_git_commit() {
    // A plain git commit (no mkit-* headers) must not reconstruct.
    let body = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
author A <a@example.com> 1700000000 +0000\n\
committer A <a@example.com> 1700000000 +0000\n\
\n\
plain git commit\n";
    let err = reconstruct::reconstruct_commit(body).unwrap_err();
    assert!(matches!(err, BridgeError::NotBridgeObject(_)), "got {err}");
}

#[test]
fn reconstruct_rejects_gitlink_mode() {
    // tree with a 160000 (gitlink) entry: no mkit equivalent.
    let mut body = Vec::new();
    body.extend_from_slice(b"160000 sub\0");
    body.extend_from_slice(&[0u8; 20]);
    let err = reconstruct::reconstruct_tree(&body, &|_| Some([0u8; 32])).unwrap_err();
    assert!(matches!(err, BridgeError::NotBridgeObject(_)), "got {err}");
}

// ─── differential vs real git ───────────────────────────────────────

fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Every translated object's id must equal what `git hash-object`
/// computes for the same content, and a repo assembled from our loose
/// objects must pass `git fsck`.
#[test]
fn differential_ids_and_fsck_against_real_git() {
    if !git_available() {
        eprintln!("skipping: no git on PATH");
        return;
    }
    let (_d, store) = store();
    let (child, tag_hash) = build_fixture(&store);
    let (known, emitted) = translate_all(&store, &tag_hash);

    let repo = tempfile::tempdir().unwrap();
    let out = Command::new("git")
        .args(["init", "--bare", "--initial-branch=main", "."])
        .current_dir(repo.path())
        .output()
        .unwrap();
    assert!(out.status.success());

    for (_h, g) in &emitted {
        // Differential id check via hash-object --literally -w.
        let mut cmd = Command::new("git")
            .args([
                "hash-object",
                "-t",
                g.gtype.name(),
                "-w",
                "--stdin",
                "--literally",
            ])
            .current_dir(repo.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        std::io::Write::write_all(cmd.stdin.as_mut().unwrap(), &g.body).unwrap();
        let out = cmd.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let got = String::from_utf8(out.stdout).unwrap().trim().to_owned();
        assert_eq!(
            got,
            sha1_hex(&g.id()),
            "git disagrees on a {} id",
            g.gtype.name()
        );
    }

    // Point refs at the translated head + tag, then fsck the graph.
    let head = sha1_hex(&known[&child]);
    let tag = sha1_hex(&known[&tag_hash]);
    for (r, id) in [("refs/heads/main", &head), ("refs/tags/v1.0.0", &tag)] {
        let out = Command::new("git")
            .args(["update-ref", r, id])
            .current_dir(repo.path())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let out = Command::new("git")
        .args(["fsck", "--strict", "--no-dangling"])
        .current_dir(repo.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git fsck rejected bridge objects:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
