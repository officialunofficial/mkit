//! Round-trip proof of SPEC-GIT-BRIDGE §1.1/§9/§10: translate a real
//! mkit store's closure to git objects, reconstruct every object from
//! the git bytes alone, and require bit-identical mkit bytes, equal
//! BLAKE3 hashes, and original-signature re-verification — plus a
//! determinism check (two independent translations agree) and a
//! differential check against the real `git` binary when present.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

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

use mkit_test_util::require_tool;

/// Every translated object's id must equal what `git hash-object`
/// computes for the same content, and a repo assembled from our loose
/// objects must pass `git fsck`.
#[test]
fn differential_ids_and_fsck_against_real_git() {
    if !require_tool("git") {
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

// ─── §4 / §6.2 / §7.1 refusal arms ──────────────────────────────────

#[test]
fn fixed_size_chunking_is_refused() {
    let (_d, store) = store();
    let chunk = put(
        &store,
        &Object::Blob(Blob {
            data: vec![7u8; 4096],
        }),
    );
    let manifest = put(
        &store,
        &Object::ChunkedBlob(mkit_core::object::ChunkedBlob {
            total_size: 4096,
            chunk_size: 4096,
            chunks: vec![chunk],
        }),
    );
    let mut known = HashMap::new();
    let err = translate_closure(&store, &manifest, &mut known, &mut |_, _| Ok(())).unwrap_err();
    assert!(
        matches!(
            err,
            BridgeError::Refused(mkit_git_bridge::Refusal::FixedSizeChunking { .. })
        ),
        "got {err}"
    );
}

#[test]
fn below_threshold_manifest_is_refused() {
    let (_d, store) = store();
    let chunk = put(
        &store,
        &Object::Blob(Blob {
            data: vec![7u8; 4096],
        }),
    );
    let manifest = put(
        &store,
        &Object::ChunkedBlob(mkit_core::object::ChunkedBlob {
            total_size: 4096,
            chunk_size: 0,
            chunks: vec![chunk],
        }),
    );
    let mut known = HashMap::new();
    let err = translate_closure(&store, &manifest, &mut known, &mut |_, _| Ok(())).unwrap_err();
    assert!(
        matches!(
            err,
            BridgeError::Refused(mkit_git_bridge::Refusal::NonCanonicalChunking { .. })
        ),
        "got {err}"
    );
}

#[test]
fn non_canonical_boundaries_are_refused() {
    let (_d, store) = store();
    // >1 MiB in a single chunk cannot match pinned FastCDC, whose max
    // chunk is 256 KiB.
    let big: Vec<u8> = (0u32..300_000).flat_map(u32::to_le_bytes).collect();
    let chunk = put(&store, &Object::Blob(Blob { data: big.clone() }));
    let manifest = put(
        &store,
        &Object::ChunkedBlob(mkit_core::object::ChunkedBlob {
            total_size: big.len() as u64,
            chunk_size: 0,
            chunks: vec![chunk],
        }),
    );
    let mut known = HashMap::new();
    let err = translate_closure(&store, &manifest, &mut known, &mut |_, _| Ok(())).unwrap_err();
    assert!(
        matches!(
            err,
            BridgeError::Refused(mkit_git_bridge::Refusal::NonCanonicalChunking { .. })
        ),
        "got {err}"
    );
}

#[test]
fn timestamp_overflow_is_refused() {
    let (_d, store) = store();
    let empty_tree = put(&store, &Object::Tree(Tree { entries: vec![] }));
    let c = Commit::new_unannotated(
        empty_tree,
        vec![],
        Identity::opaque(b"x".to_vec()),
        [0; 32],
        b"m".to_vec(),
        u64::MAX,
        [0; 64],
    );
    let h = put(&store, &Object::Commit(c));
    let mut known = HashMap::new();
    let err = translate_closure(&store, &h, &mut known, &mut |_, _| Ok(())).unwrap_err();
    assert!(
        matches!(
            err,
            BridgeError::Refused(mkit_git_bridge::Refusal::TimestampOverflow { .. })
        ),
        "got {err}"
    );
}

#[test]
fn tag_name_outside_grammar_is_refused() {
    let (_d, store) = store();
    let empty_tree = put(&store, &Object::Tree(Tree { entries: vec![] }));
    let root = signed_commit(&store, empty_tree, vec![], "r\n");
    let tag = Tag {
        target: root,
        target_type: mkit_core::ObjectType::Commit,
        name: b"has space".to_vec(),
        tagger: Identity::opaque(b"t".to_vec()),
        signer: [0; 32],
        message: vec![],
        timestamp: TS,
        signature: [0; 64],
    };
    let h = put(&store, &Object::Tag(tag));
    let mut known = HashMap::new();
    let err = translate_closure(&store, &h, &mut known, &mut |_, _| Ok(())).unwrap_err();
    assert!(
        matches!(
            err,
            BridgeError::Refused(mkit_git_bridge::Refusal::TagName { .. })
        ),
        "got {err}"
    );
}

// ─── review-round additions ─────────────────────────────────────────

/// §3: plain blobs above the chunking threshold cannot round-trip and
/// must refuse (a conformant writer would have chunked them).
#[test]
fn oversized_plain_blob_is_refused() {
    let (_d, store) = store();
    let big: Vec<u8> = (0u32..300_000).flat_map(u32::to_le_bytes).collect();
    let h = put(&store, &Object::Blob(Blob { data: big }));
    let mut known = HashMap::new();
    let err = translate_closure(&store, &h, &mut known, &mut |_, _| Ok(())).unwrap_err();
    assert!(
        matches!(
            err,
            BridgeError::Refused(mkit_git_bridge::Refusal::NonCanonicalChunking { .. })
        ),
        "got {err}"
    );
}

/// §9: forged git trees that no mkit source could produce (illegal or
/// duplicate entry names) must fail reconstruction, not round-trip.
#[test]
fn reconstruct_rejects_mkit_illegal_tree_names() {
    let blob_id = [0x11u8; 20];
    let resolve = |_: &[u8; 20]| Some([0x22u8; 32]);
    let entry = |name: &[u8]| {
        let mut e = Vec::new();
        e.extend_from_slice(b"100644 ");
        e.extend_from_slice(name);
        e.push(0);
        e.extend_from_slice(&blob_id);
        e
    };
    // `.git` is git-legal but mkit-illegal (SPEC-OBJECTS §4.1).
    let err = reconstruct::reconstruct_tree(&entry(b".git"), &resolve).unwrap_err();
    assert!(
        matches!(err, BridgeError::NotBridgeObject(_)),
        "dot-git: got {err}"
    );
    // Duplicate names: distinct git sort keys cannot collide for
    // blob+blob, so build blob+tree with the same name.
    let mut dup = entry(b"same");
    dup.extend_from_slice(b"40000 same\0");
    dup.extend_from_slice(&[0x33u8; 20]);
    let resolve2 = |id: &[u8; 20]| {
        Some(if *id == blob_id {
            [0x22u8; 32]
        } else {
            [0x44u8; 32]
        })
    };
    let err = reconstruct::reconstruct_tree(&dup, &resolve2).unwrap_err();
    assert!(
        matches!(
            err,
            BridgeError::NotBridgeObject(_) | BridgeError::Integrity(_)
        ),
        "duplicate: got {err}"
    );
}

/// Helper: the translated git body of a signed commit.
///
/// #505 PR 5/5: deliberately minimal (empty tree, no parents) — the
/// tests below only mutate the synthesized `mkit-*` headers of a bridge
/// commit body, so they don't need `build_fixture`'s full >1 MiB
/// chunked-blob / nested-tree / tag fixture (that fixture exists for the
/// full round-trip tests above, which actually exercise those shapes).
fn minimal_signed_commit_body() -> Vec<u8> {
    let (_d, store) = store();
    let empty_tree = put(&store, &Object::Tree(Tree { entries: vec![] }));
    let commit = signed_commit(&store, empty_tree, vec![], "minimal\n");
    let (_known, emitted) = translate_all(&store, &commit);
    emitted
        .iter()
        .find(|(h, _)| h == &commit)
        .map(|(_, g)| g.body.clone())
        .expect("commit emitted")
}

fn as_commit(body: Vec<u8>) -> GitObject {
    GitObject {
        gtype: mkit_git_bridge::GitType::Commit,
        body,
    }
}

/// #505 PR 5/5: split from the former `shallow_verify_reports_failed_on_tamper`
/// mega-test (also switched off the >1 MiB `build_fixture` fixture — see
/// `minimal_signed_commit_body`). §10: a tampered signature reports
/// Failed — never Unsigned, never Verified.
#[test]
fn shallow_verify_reports_failed_on_tampered_signature() {
    let body = String::from_utf8(minimal_signed_commit_body()).unwrap();

    // Flip one hex digit of the signature value.
    let sig_line_start = body.find("mkit-signature ").unwrap() + "mkit-signature ".len();
    let mut tampered = body.clone();
    let old = tampered.as_bytes()[sig_line_start];
    let new = if old == b'0' { '1' } else { '0' };
    tampered.replace_range(sig_line_start..=sig_line_start, &new.to_string());
    assert_eq!(
        shallow_verify(&as_commit(tampered.into_bytes())).unwrap(),
        ShallowVerdict::Failed,
        "tampered signature"
    );
}

/// #505 PR 5/5: split from the former `shallow_verify_reports_failed_on_tamper`
/// mega-test. §10: a tampered carried `mkit-tree` (signed bytes change)
/// reports Failed — never Unsigned, never Verified.
#[test]
fn shallow_verify_reports_failed_on_tampered_tree() {
    let body = String::from_utf8(minimal_signed_commit_body()).unwrap();

    // Flip one hex digit of the carried mkit-tree (signed bytes change).
    let tree_start = body.find("mkit-tree ").unwrap() + "mkit-tree ".len();
    let mut tampered = body.clone();
    let old = tampered.as_bytes()[tree_start];
    let new = if old == b'0' { '1' } else { '0' };
    tampered.replace_range(tree_start..=tree_start, &new.to_string());
    assert_eq!(
        shallow_verify(&as_commit(tampered.into_bytes())).unwrap(),
        ShallowVerdict::Failed,
        "tampered mkit-tree"
    );
}

/// #505 PR 5/5: split from the former table-driven `reconstruct_fail_closed_branches`
/// mega-test (also switched off the >1 MiB `build_fixture` fixture — see
/// `minimal_signed_commit_body`) so each fail-closed branch below is its
/// own localizable test. §1.2/§9: a schema bump (`mkit-schema 2`) refuses.
#[test]
fn reconstruct_fail_closed_schema_bump() {
    assert_fail_closed(&minimal_signed_commit_body(), |body| {
        body.replace("mkit-schema 1", "mkit-schema 2")
    });
}

/// §1.2/§9: a missing `mkit-schema` header refuses.
#[test]
fn reconstruct_fail_closed_schema_missing() {
    assert_fail_closed(&minimal_signed_commit_body(), |body| {
        body.replace("mkit-schema 1\n", "")
    });
}

/// §1.2/§9: an unexpected reserved header (`mkit-remix-source` on a
/// plain commit) refuses.
#[test]
fn reconstruct_fail_closed_reserved_header() {
    assert_fail_closed(&minimal_signed_commit_body(), |body| {
        body.replace("mkit-schema 1\n", "mkit-schema 1\nmkit-remix-source 00\n")
    });
}

/// §1.2/§9: a duplicated `mkit-signer` header refuses.
#[test]
fn reconstruct_fail_closed_duplicate_signer() {
    assert_fail_closed(&minimal_signed_commit_body(), |body| {
        let line_start = body.find("mkit-signer ").unwrap();
        let line_end = body[line_start..].find('\n').unwrap() + line_start + 1;
        let line = &body[line_start..line_end];
        format!("{}{}{}", &body[..line_end], line, &body[line_end..])
    });
}

/// §1.2/§9: a continuation line on the `mkit-schema` header refuses.
#[test]
fn reconstruct_fail_closed_continuation_line() {
    assert_fail_closed(&minimal_signed_commit_body(), |body| {
        body.replace("mkit-schema 1\n", "mkit-schema 1\n continuation\n")
    });
}

/// §1.2/§9: an unknown `mkit-*` header refuses.
#[test]
fn reconstruct_fail_closed_unknown_header() {
    assert_fail_closed(&minimal_signed_commit_body(), |body| {
        body.replace("mkit-schema 1\n", "mkit-schema 1\nmkit-unknown x\n")
    });
}

/// Shared assertion for the `reconstruct_fail_closed_*` tests above:
/// apply `mutate` to the decoded `body`, then assert `reconstruct_commit`
/// refuses it with a typed fail-closed error.
fn assert_fail_closed(body: &[u8], mutate: impl FnOnce(&str) -> String) {
    let body = String::from_utf8(body.to_vec()).unwrap();
    let mutated = mutate(&body);
    let err = reconstruct::reconstruct_commit(mutated.as_bytes()).unwrap_err();
    assert!(
        matches!(
            err,
            BridgeError::NotBridgeObject(_) | BridgeError::Integrity(_)
        ),
        "got {err}"
    );
}

/// §1.2 store-side: a future-schema object refuses with the typed
/// `SchemaVersion` refusal.
#[test]
fn future_schema_object_is_typed_refusal() {
    let (_d, store) = store();
    let blob_bytes = mkit_core::serialize(&Object::Blob(Blob {
        data: b"x".to_vec(),
    }))
    .unwrap();
    let mut future = blob_bytes.clone();
    future[5] = 0x02; // prologue schema_version
    let h = store.write(&future).unwrap();
    let mut known = HashMap::new();
    let err = translate_closure(&store, &h, &mut known, &mut |_, _| Ok(())).unwrap_err();
    assert!(
        matches!(
            err,
            BridgeError::Refused(mkit_git_bridge::Refusal::SchemaVersion { .. })
        ),
        "got {err}"
    );
}

/// §6.2 applies to tags too.
#[test]
fn tag_timestamp_overflow_is_refused() {
    let (_d, store) = store();
    let empty_tree = put(&store, &Object::Tree(Tree { entries: vec![] }));
    let root = signed_commit(&store, empty_tree, vec![], "r\n");
    let tag = Tag {
        target: root,
        target_type: mkit_core::ObjectType::Commit,
        name: b"v1".to_vec(),
        tagger: Identity::opaque(b"t".to_vec()),
        signer: [0; 32],
        message: vec![],
        timestamp: u64::MAX,
        signature: [0; 64],
    };
    let h = put(&store, &Object::Tag(tag));
    let mut known = HashMap::new();
    let err = translate_closure(&store, &h, &mut known, &mut |_, _| Ok(())).unwrap_err();
    assert!(
        matches!(
            err,
            BridgeError::Refused(mkit_git_bridge::Refusal::TimestampOverflow { .. })
        ),
        "got {err}"
    );
}

/// Loose objects read back through the verifying reader; malformed
/// `parse_raw` inputs are rejected.
#[test]
fn loose_read_verifies_and_parse_raw_rejects_junk() {
    use mkit_git_bridge::gitobj::GitObject as GO;
    let dir = tempfile::tempdir().unwrap();
    let obj = mkit_git_bridge::gitobj::GitObject {
        gtype: mkit_git_bridge::GitType::Blob,
        body: b"abc".to_vec(),
    };
    let id = obj.write_loose(dir.path()).unwrap();
    let back = GO::read_loose(dir.path(), &id).unwrap();
    assert_eq!(back, obj);
    assert!(GO::parse_raw(b"blob 4\0abc").is_none(), "wrong length");
    assert!(GO::parse_raw(b"blobby 3\0abc").is_none(), "unknown type");
    assert!(GO::parse_raw(b"blob3\0abc").is_none(), "no space");
}
