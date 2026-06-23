//! SPEC-GIT-IMPORT invariants, hermetic (hand-crafted git bytes — no
//! git binary): per-key determinism, idempotent re-import, importer
//! signatures verify, provenance digests, the refusal matrix, and the
//! SHA-SHARING invariant — exporting imported history with the
//! reversed import map preloaded reproduces the ORIGINAL upstream
//! sha1s and translates only native work on top (the fork-mode core,
//! SPEC-GIT-BRIDGE §14.1).

// `drop(imp)` is load-bearing: it ends the Importer's &mut borrows
// so the owned sink/map/raws can move; the struct itself has no Drop.
#![allow(clippy::drop_non_drop)]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use mkit_core::Hash;
use mkit_core::object::{Identity, Object, ObjectType};
use mkit_core::sign::{KeyPair, sign_commit, sign_tag, verify_commit, verify_tag};
use mkit_git_bridge::error::{BridgeError, Refusal};
use mkit_git_bridge::gitobj::Sha1Id;
use mkit_git_bridge::gitsrc::GitObjKind;
use mkit_git_bridge::import::{
    DepthMemo, ImportOptions, ImportSigner, ImportedRef, Importer, MemGitSource, MemSink,
    ObjectSink,
};
use mkit_git_bridge::translate::{ObjectSource, translate_closure};
use std::collections::HashMap;

const KEY_SEED: [u8; 32] = [0x42; 32];

/// Build a small upstream: blob, tree, two commits, annotated tag.
fn upstream() -> (MemGitSource, Sha1Id, Sha1Id) {
    let mut src = MemGitSource::default();
    let blob = src.put(GitObjKind::Blob, b"hello upstream\n".to_vec());
    let mut tree = Vec::new();
    tree.extend_from_slice(b"100644 a.txt\0");
    tree.extend_from_slice(&blob);
    let tree = src.put(GitObjKind::Tree, tree);
    let c1 = commit_body(&tree, &[], "first upstream\n", 1_600_000_000);
    let c1 = src.put(GitObjKind::Commit, c1);
    let c2 = commit_body(&tree, &[c1], "second upstream\n", 1_600_000_100);
    let c2 = src.put(GitObjKind::Commit, c2);
    let tag = format!(
        "object {}\ntype commit\ntag v1\ntagger Tagger T <t@up> 1600000200 +0100\n\nrelease one\n",
        hex(&c2)
    );
    let tag = src.put(GitObjKind::Tag, tag.into_bytes());
    (src, c2, tag)
}

fn commit_body(tree: &Sha1Id, parents: &[Sha1Id], msg: &str, ts: u64) -> Vec<u8> {
    use std::fmt::Write as _;
    let mut b = format!("tree {}\n", hex(tree));
    for p in parents {
        let _ = writeln!(b, "parent {}", hex(p));
    }
    let _ = write!(
        b,
        "author Up Stream <up@example.com> {ts} +0200\ncommitter See Omitter <c@example.com> {ts} -0700\n\n{msg}"
    );
    b.into_bytes()
}

fn hex(id: &Sha1Id) -> String {
    mkit_git_bridge::gitobj::sha1_hex(id)
}

struct Run {
    sink: MemSink,
    map: HashMap<Sha1Id, Hash>,
    raws: HashMap<Sha1Id, Vec<u8>>,
    head: ImportedRef,
    tag_head: ImportedRef,
}

fn run_import(seed: [u8; 32]) -> Run {
    let (mut src, head, tag) = upstream();
    let kp = KeyPair::from_seed(seed);
    let mut sink = MemSink::default();
    let mut map = HashMap::new();
    let mut raws: HashMap<Sha1Id, Vec<u8>> = HashMap::new();
    let public = kp.public.0;
    let mut sc = |c: &mkit_core::object::Commit| {
        Ok(sign_commit(c, &kp)
            .map_err(|e| BridgeError::Source(e.to_string()))?
            .0)
    };
    let mut st = |t: &mkit_core::object::Tag| {
        Ok(sign_tag(t, &kp)
            .map_err(|e| BridgeError::Source(e.to_string()))?
            .0)
    };
    let mut retain = |id: &Sha1Id, raw: &[u8]| {
        raws.insert(*id, raw.to_vec());
        Ok(())
    };
    let mut imp = Importer {
        source: &mut src,
        sink: &mut sink,
        signer: ImportSigner {
            public,
            sign_commit: &mut sc,
            sign_tag: &mut st,
        },
        map: &mut map,
        retain_raw: &mut retain,
        options: ImportOptions::default(),
        depth_memo: DepthMemo::default(),
    };
    let head = imp.import_ref(&head).unwrap();
    let tag_head = imp.import_ref(&tag).unwrap();
    drop(imp); // end the &mut borrows of sink/map/raws
    Run {
        sink,
        map,
        raws,
        head,
        tag_head,
    }
}

#[test]
fn import_is_deterministic_per_key_and_signed() {
    let a = run_import(KEY_SEED);
    let b = run_import(KEY_SEED);
    assert_eq!(a.head.head, b.head.head, "same key ⇒ same hashes");
    assert_eq!(a.map, b.map);
    assert_eq!(a.sink.0, b.sink.0, "byte-identical stores");

    // A different key forks the whole universe.
    let c = run_import([0x43; 32]);
    assert_ne!(a.head.head, c.head.head);

    // Importer signatures verify; authorship is the upstream author.
    let Object::Commit(head) = de(&a.sink, &a.head.head) else {
        panic!("head not a commit")
    };
    verify_commit(&head).expect("importer signature verifies");
    assert_eq!(
        head.author,
        Identity::opaque(b"Up Stream <up@example.com>".to_vec())
    );
    assert_eq!(head.timestamp, 1_600_000_100, "committer epoch");
    let Object::Tag(tag) = de(&a.sink, &a.tag_head.head) else {
        panic!("tag head not a tag")
    };
    verify_tag(&tag).expect("importer tag signature verifies");
    assert_eq!(tag.target, a.head.head);
    assert_eq!(tag.target_type, ObjectType::Commit);
}

#[test]
fn reimport_is_a_noop_and_content_digest_binds_raw_bytes() {
    let mut a = run_import(KEY_SEED);
    // Re-import with the warm map: zero new pairs.
    let (mut src, head, _) = upstream();
    let kp = KeyPair::from_seed(KEY_SEED);
    let public = kp.public.0;
    let mut sc = |c: &mkit_core::object::Commit| {
        Ok(sign_commit(c, &kp)
            .map_err(|e| BridgeError::Source(e.to_string()))?
            .0)
    };
    let mut st = |t: &mkit_core::object::Tag| {
        Ok(sign_tag(t, &kp)
            .map_err(|e| BridgeError::Source(e.to_string()))?
            .0)
    };
    let mut retain = |_: &Sha1Id, _: &[u8]| Ok(());
    let mut imp = Importer {
        source: &mut src,
        sink: &mut a.sink,
        signer: ImportSigner {
            public,
            sign_commit: &mut sc,
            sign_tag: &mut st,
        },
        map: &mut a.map,
        retain_raw: &mut retain,
        options: ImportOptions::default(),
        depth_memo: DepthMemo::default(),
    };
    let again = imp.import_ref(&head).unwrap();
    assert!(again.new_pairs.is_empty(), "warm re-import emits nothing");
    drop(imp);

    // content_digest == BLAKE3(retained raw bytes) for every commit.
    let (_, upstream_head, _) = upstream();
    let Object::Commit(c) = de(&a.sink, &a.head.head) else {
        panic!()
    };
    let raw = &a.raws[&upstream_head];
    assert_eq!(c.content_digest, mkit_core::hash::hash(raw));
    assert!(raw.starts_with(b"commit "), "framed git bytes retained");
}

#[test]
fn sha_sharing_invariant_fork_mode_export() {
    // Import, then build ONE native mkit commit on top, then export
    // with `known` preloaded from the reversed import map.
    let run = run_import(KEY_SEED);
    let kp = KeyPair::from_seed(KEY_SEED);
    let Object::Commit(imported_head) = de(&run.sink, &run.head.head) else {
        panic!()
    };
    let mut native = mkit_core::object::Commit::new_unannotated(
        imported_head.tree_hash,
        vec![run.head.head],
        Identity::ed25519(kp.public.0),
        kp.public.0,
        b"native work on top\n".to_vec(),
        1_600_000_300,
        [0; 64],
    );
    native.signature = sign_commit(&native, &kp).unwrap().0;
    let native_bytes = mkit_core::serialize(&Object::Commit(native)).unwrap();
    let mut sink = run.sink;
    let native_hash = sink.write_object(&native_bytes).unwrap();

    // Export: seed known with blake3→sha1 (reversed import map).
    let mut known: HashMap<Hash, [u8; 20]> = run
        .map
        .iter()
        .map(|(sha1, blake3)| (*blake3, *sha1))
        .collect();
    let store = SinkSource(&sink);
    let mut emitted: Vec<(Hash, mkit_git_bridge::GitObject)> = Vec::new();
    let batch = translate_closure(&store, &native_hash, &mut known, &mut |h, g| {
        emitted.push((*h, g.clone()));
        Ok(())
    })
    .unwrap();

    // ONLY the native commit was emitted; everything imported passed
    // through as its original sha1.
    assert_eq!(emitted.len(), 1, "imported prefix must not re-translate");
    let (h, git) = &emitted[0];
    assert_eq!(*h, native_hash);
    assert_eq!(batch.root, git.id());

    // The native commit's parent line is the ORIGINAL upstream sha1.
    let (_, upstream_head, _) = upstream();
    let body = String::from_utf8_lossy(&git.body);
    assert!(
        body.contains(&format!("parent {}", hex(&upstream_head))),
        "boundary commit must parent the original sha1:\n{body}"
    );
    // And its tree resolved through the import map to the original
    // upstream tree sha1 (shared content keeps upstream ids).
    let (src, _, _) = upstream();
    let tree_sha1 = src
        .0
        .iter()
        .find(|(_, (k, _))| *k == GitObjKind::Tree)
        .map(|(id, _)| *id)
        .unwrap();
    assert!(body.contains(&format!("tree {}", hex(&tree_sha1))));
}

#[test]
#[allow(clippy::too_many_lines)] // one block per refusal arm
fn refusal_matrix_inbound() {
    let kp = KeyPair::from_seed(KEY_SEED);
    let public = kp.public.0;

    let run_one = |src: &mut MemGitSource, tip: &Sha1Id| -> Result<ImportedRef, BridgeError> {
        let mut sink = MemSink::default();
        let mut map = HashMap::new();
        let mut sc = |c: &mkit_core::object::Commit| {
            Ok(sign_commit(c, &kp)
                .map_err(|e| BridgeError::Source(e.to_string()))?
                .0)
        };
        let mut st = |t: &mkit_core::object::Tag| {
            Ok(sign_tag(t, &kp)
                .map_err(|e| BridgeError::Source(e.to_string()))?
                .0)
        };
        let mut retain = |_: &Sha1Id, _: &[u8]| Ok(());
        let mut imp = Importer {
            source: src,
            sink: &mut sink,
            signer: ImportSigner {
                public,
                sign_commit: &mut sc,
                sign_tag: &mut st,
            },
            map: &mut map,
            retain_raw: &mut retain,
            options: ImportOptions::default(),
            depth_memo: DepthMemo::default(),
        };
        imp.import_ref(tip)
    };

    // Gitlink.
    let mut src = MemGitSource::default();
    let mut tree = Vec::new();
    tree.extend_from_slice(b"160000 sub\0");
    tree.extend_from_slice(&[1u8; 20]);
    let t = src.put(GitObjKind::Tree, tree);
    let c = src.put(GitObjKind::Commit, commit_body(&t, &[], "m\n", 5));
    assert!(matches!(
        run_one(&mut src, &c),
        Err(BridgeError::Refused(Refusal::Gitlink { .. }))
    ));

    // mkit-illegal tree name (Windows device stem).
    let mut src = MemGitSource::default();
    let blob = src.put(GitObjKind::Blob, b"x".to_vec());
    let mut tree = Vec::new();
    tree.extend_from_slice(b"100644 aux.c\0");
    tree.extend_from_slice(&blob);
    let t = src.put(GitObjKind::Tree, tree);
    let c = src.put(GitObjKind::Commit, commit_body(&t, &[], "m\n", 5));
    assert!(matches!(
        run_one(&mut src, &c),
        Err(BridgeError::Refused(Refusal::TreeEntryName { .. }))
    ));

    // Negative timestamp.
    let mut src = MemGitSource::default();
    let blob = src.put(GitObjKind::Blob, b"x".to_vec());
    let mut tree = Vec::new();
    tree.extend_from_slice(b"100644 ok.txt\0");
    tree.extend_from_slice(&blob);
    let t = src.put(GitObjKind::Tree, tree);
    let body = format!(
        "tree {}\nauthor A <a@x> -5 +0000\ncommitter A <a@x> -5 +0000\n\nold\n",
        hex(&t)
    );
    let c = src.put(GitObjKind::Commit, body.into_bytes());
    assert!(matches!(
        run_one(&mut src, &c),
        Err(BridgeError::Refused(Refusal::NegativeTimestamp { .. }))
    ));

    // Unknown tree mode.
    let mut src = MemGitSource::default();
    let blob = src.put(GitObjKind::Blob, b"x".to_vec());
    let mut tree = Vec::new();
    tree.extend_from_slice(b"100777 odd\0");
    tree.extend_from_slice(&blob);
    let t = src.put(GitObjKind::Tree, tree);
    let c = src.put(GitObjKind::Commit, commit_body(&t, &[], "m\n", 5));
    assert!(matches!(
        run_one(&mut src, &c),
        Err(BridgeError::Refused(Refusal::UnknownTreeMode { .. }))
    ));

    // Historic mode normalizes in plain mode, refuses in fork mode.
    let mut src = MemGitSource::default();
    let blob = src.put(GitObjKind::Blob, b"x".to_vec());
    let mut tree = Vec::new();
    tree.extend_from_slice(b"100664 group.txt\0");
    tree.extend_from_slice(&blob);
    let t = src.put(GitObjKind::Tree, tree);
    let c = src.put(GitObjKind::Commit, commit_body(&t, &[], "m\n", 5));
    let ok = run_one(&mut src, &c).unwrap();
    assert!(
        ok.normalized_modes,
        "plain mode normalizes with a warn flag"
    );
    // Fork mode refusal:
    let mut sink = MemSink::default();
    let mut map = HashMap::new();
    let mut sc = |cm: &mkit_core::object::Commit| {
        Ok(sign_commit(cm, &kp)
            .map_err(|e| BridgeError::Source(e.to_string()))?
            .0)
    };
    let mut st = |tg: &mkit_core::object::Tag| {
        Ok(sign_tag(tg, &kp)
            .map_err(|e| BridgeError::Source(e.to_string()))?
            .0)
    };
    let mut retain = |_: &Sha1Id, _: &[u8]| Ok(());
    let mut imp = Importer {
        source: &mut src,
        sink: &mut sink,
        signer: ImportSigner {
            public,
            sign_commit: &mut sc,
            sign_tag: &mut st,
        },
        map: &mut map,
        retain_raw: &mut retain,
        options: ImportOptions { fork_mode: true },
        depth_memo: DepthMemo::default(),
    };
    assert!(matches!(
        imp.import_ref(&c),
        Err(BridgeError::Refused(Refusal::NormalizedModeInFork { .. }))
    ));
}

#[test]
fn big_blob_chunks_with_writer_rule() {
    let mut src = MemGitSource::default();
    let big: Vec<u8> = (0u32..300_000).flat_map(u32::to_le_bytes).collect();
    let blob = src.put(GitObjKind::Blob, big.clone());
    let mut tree = Vec::new();
    tree.extend_from_slice(b"100644 big.bin\0");
    tree.extend_from_slice(&blob);
    let t = src.put(GitObjKind::Tree, tree);
    let c = src.put(GitObjKind::Commit, commit_body(&t, &[], "big\n", 5));

    let kp = KeyPair::from_seed(KEY_SEED);
    let public = kp.public.0;
    let mut sink = MemSink::default();
    let mut map = HashMap::new();
    let mut sc = |cm: &mkit_core::object::Commit| {
        Ok(sign_commit(cm, &kp)
            .map_err(|e| BridgeError::Source(e.to_string()))?
            .0)
    };
    let mut st = |tg: &mkit_core::object::Tag| {
        Ok(sign_tag(tg, &kp)
            .map_err(|e| BridgeError::Source(e.to_string()))?
            .0)
    };
    let mut retain = |_: &Sha1Id, _: &[u8]| Ok(());
    let mut imp = Importer {
        source: &mut src,
        sink: &mut sink,
        signer: ImportSigner {
            public,
            sign_commit: &mut sc,
            sign_tag: &mut st,
        },
        map: &mut map,
        retain_raw: &mut retain,
        options: ImportOptions::default(),
        depth_memo: DepthMemo::default(),
    };
    imp.import_ref(&c).unwrap();
    drop(imp);
    let manifest_hash = map[&blob];
    let Object::ChunkedBlob(m) = de(&sink, &manifest_hash) else {
        panic!("big blob must import as a chunked manifest")
    };
    assert_eq!(m.total_size, big.len() as u64);
    assert_eq!(m.chunk_size, 0);
    // The imported manifest is exportable: the export-side canonical
    // boundary check passes (writer-rule symmetry).
    let store = SinkSource(&sink);
    let mut known = HashMap::new();
    translate_closure(&store, &manifest_hash, &mut known, &mut |_, _| Ok(())).unwrap();
}

// ─── helpers ────────────────────────────────────────────────────────

fn de(sink: &MemSink, h: &Hash) -> Object {
    mkit_core::deserialize(&sink.0[h]).unwrap()
}

/// Adapter: read translated objects back out of a `MemSink` for the
/// export-side closure driver.
struct SinkSource<'a>(&'a MemSink);

impl ObjectSource for SinkSource<'_> {
    fn read_object(&self, h: &Hash) -> Result<Object, BridgeError> {
        self.0
            .0
            .get(h)
            .map(|b| mkit_core::deserialize(b).unwrap())
            .ok_or_else(|| BridgeError::Source("missing".into()))
    }
}

/// Review-round additions: the remaining typed refusal arms.
#[test]
#[allow(clippy::too_many_lines)] // one block per refusal arm
fn refusal_matrix_inbound_extras() {
    let kp = KeyPair::from_seed(KEY_SEED);
    let public = kp.public.0;
    let run_one = |src: &mut MemGitSource, tip: &Sha1Id| -> Result<ImportedRef, BridgeError> {
        let mut sink = MemSink::default();
        let mut map = HashMap::new();
        let mut sc = |c: &mkit_core::object::Commit| {
            Ok(sign_commit(c, &kp)
                .map_err(|e| BridgeError::Source(e.to_string()))?
                .0)
        };
        let mut st = |t: &mkit_core::object::Tag| {
            Ok(sign_tag(t, &kp)
                .map_err(|e| BridgeError::Source(e.to_string()))?
                .0)
        };
        let mut retain = |_: &Sha1Id, _: &[u8]| Ok(());
        let mut imp = Importer {
            source: src,
            sink: &mut sink,
            signer: ImportSigner {
                public,
                sign_commit: &mut sc,
                sign_tag: &mut st,
            },
            map: &mut map,
            retain_raw: &mut retain,
            options: ImportOptions::default(),
            depth_memo: DepthMemo::default(),
        };
        imp.import_ref(tip)
    };

    // Duplicate names after mkit re-sort (file `a` + dir `a`).
    let mut src = MemGitSource::default();
    let blob = src.put(GitObjKind::Blob, b"x".to_vec());
    let mut sub = Vec::new();
    sub.extend_from_slice(b"100644 inner\0");
    sub.extend_from_slice(&blob);
    let sub = src.put(GitObjKind::Tree, sub);
    let mut tree = Vec::new();
    // git order: "a" (blob) sorts before "a/" (dir key).
    tree.extend_from_slice(b"100644 a\0");
    tree.extend_from_slice(&blob);
    tree.extend_from_slice(b"40000 a\0");
    tree.extend_from_slice(&sub);
    let t = src.put(GitObjKind::Tree, tree);
    let c = src.put(GitObjKind::Commit, commit_body(&t, &[], "dup\n", 5));
    assert!(matches!(
        run_one(&mut src, &c),
        Err(BridgeError::Refused(Refusal::DuplicateTreeEntry { .. }))
    ));

    // Tree nesting beyond 128.
    let mut src = MemGitSource::default();
    let blob = src.put(GitObjKind::Blob, b"x".to_vec());
    let mut child_id = blob;
    let mut child_mode: &[u8] = b"100644";
    for _ in 0..140 {
        let mut t = Vec::new();
        t.extend_from_slice(child_mode);
        t.extend_from_slice(b" d\0");
        t.extend_from_slice(&child_id);
        child_id = src.put(GitObjKind::Tree, t);
        child_mode = b"40000";
    }
    let c = src.put(GitObjKind::Commit, commit_body(&child_id, &[], "deep\n", 5));
    assert!(matches!(
        run_one(&mut src, &c),
        Err(BridgeError::Refused(Refusal::TreeTooDeep { .. }))
    ));

    // Tag name outside the grammar (`+build`).
    let mut src = MemGitSource::default();
    let blob = src.put(GitObjKind::Blob, b"x".to_vec());
    let mut tree = Vec::new();
    tree.extend_from_slice(b"100644 a\0");
    tree.extend_from_slice(&blob);
    let t = src.put(GitObjKind::Tree, tree);
    let c = src.put(GitObjKind::Commit, commit_body(&t, &[], "m\n", 5));
    let tag = src.put(
        GitObjKind::Tag,
        format!(
            "object {}\ntype commit\ntag v1.0+build\ntagger T <t@x> 5 +0000\n\nm\n",
            hex(&c)
        )
        .into_bytes(),
    );
    assert!(matches!(
        run_one(&mut src, &tag),
        Err(BridgeError::Refused(Refusal::TagName { .. }))
    ));

    // Tag chains: depth 16 imports, depth 17 refuses.
    let mut src = MemGitSource::default();
    let blob = src.put(GitObjKind::Blob, b"x".to_vec());
    let mut tree = Vec::new();
    tree.extend_from_slice(b"100644 a\0");
    tree.extend_from_slice(&blob);
    let t = src.put(GitObjKind::Tree, tree);
    let c = src.put(GitObjKind::Commit, commit_body(&t, &[], "m\n", 5));
    let mut target = c;
    let mut target_type = "commit";
    let mut chain16 = None;
    for i in 0..17 {
        let tag = src.put(
            GitObjKind::Tag,
            format!(
                "object {}\ntype {}\ntag chain{}\ntagger T <t@x> 5 +0000\n\nm\n",
                hex(&target),
                target_type,
                i
            )
            .into_bytes(),
        );
        if i == 15 {
            chain16 = Some(tag); // 16 tag objects deep (0..=15)
        }
        target = tag;
        target_type = "tag";
    }
    assert!(
        run_one(&mut src, &chain16.unwrap()).is_ok(),
        "16 deep imports"
    );
    assert!(matches!(
        run_one(&mut src, &target),
        Err(BridgeError::Refused(Refusal::TagChain { .. }))
    ));

    // Author payload over 4096 bytes.
    let mut src = MemGitSource::default();
    let blob = src.put(GitObjKind::Blob, b"x".to_vec());
    let mut tree = Vec::new();
    tree.extend_from_slice(b"100644 a\0");
    tree.extend_from_slice(&blob);
    let t = src.put(GitObjKind::Tree, tree);
    let long = "n".repeat(5000);
    let body = format!(
        "tree {}\nauthor {long} <l@x> 5 +0000\ncommitter C <c@x> 5 +0000\n\nm\n",
        hex(&t)
    );
    let c = src.put(GitObjKind::Commit, body.into_bytes());
    assert!(matches!(
        run_one(&mut src, &c),
        Err(BridgeError::Refused(Refusal::AuthorPayload { .. }))
    ));
}

/// Peer-review fixes: composition caps on map-cache hits and the
/// declared-vs-actual tag target type check.
#[test]
#[allow(clippy::too_many_lines)] // three vectors, one shared harness
fn map_hits_enforce_composition_caps_and_tag_types() {
    let kp = KeyPair::from_seed(KEY_SEED);
    let public = kp.public.0;

    // One shared map + sink across two refs, like a real state dir.
    let run = |src: &mut MemGitSource,
               sink: &mut MemSink,
               map: &mut HashMap<Sha1Id, mkit_core::Hash>,
               tip: &Sha1Id|
     -> Result<ImportedRef, BridgeError> {
        let mut sc = |c: &mkit_core::object::Commit| {
            Ok(sign_commit(c, &kp)
                .map_err(|e| BridgeError::Source(e.to_string()))?
                .0)
        };
        let mut st = |t: &mkit_core::object::Tag| {
            Ok(sign_tag(t, &kp)
                .map_err(|e| BridgeError::Source(e.to_string()))?
                .0)
        };
        let mut retain = |_: &Sha1Id, _: &[u8]| Ok(());
        let mut imp = Importer {
            source: src,
            sink,
            signer: ImportSigner {
                public,
                sign_commit: &mut sc,
                sign_tag: &mut st,
            },
            map,
            retain_raw: &mut retain,
            options: ImportOptions::default(),
            depth_memo: DepthMemo::default(),
        };
        imp.import_ref(tip)
    };

    // A LEGAL 120-deep tree imported by ref 1; ref 2 wraps the
    // already-mapped subtree 20 levels deeper. The map hit at depth
    // 20 must measure the subtree and refuse the composition
    // (120 + 20 > 128), not silently store a tree mkit cannot read.
    let mut src = MemGitSource::default();
    let mut sink = MemSink::default();
    let mut map: HashMap<Sha1Id, mkit_core::Hash> = HashMap::new();
    let blob = src.put(GitObjKind::Blob, b"x".to_vec());
    let mut deep = blob;
    let mut mode: &[u8] = b"100644";
    for _ in 0..120 {
        let mut t = Vec::new();
        t.extend_from_slice(mode);
        t.extend_from_slice(b" d\0");
        t.extend_from_slice(&deep);
        deep = src.put(GitObjKind::Tree, t);
        mode = b"40000";
    }
    let c1 = src.put(GitObjKind::Commit, commit_body(&deep, &[], "legal\n", 5));
    run(&mut src, &mut sink, &mut map, &c1).expect("120-deep subtree is legal");

    let mut wrap = deep;
    for _ in 0..20 {
        let mut t = Vec::new();
        t.extend_from_slice(b"40000 w\0");
        t.extend_from_slice(&wrap);
        wrap = src.put(GitObjKind::Tree, t);
    }
    let c2 = src.put(GitObjKind::Commit, commit_body(&wrap, &[], "wrapped\n", 6));
    assert!(
        matches!(
            run(&mut src, &mut sink, &mut map, &c2),
            Err(BridgeError::Refused(Refusal::TreeTooDeep { .. }))
        ),
        "composed depth past the cap must refuse on the map hit"
    );

    // Same composition rule for tag chains: 10 legal + 10 wrapping
    // the mapped chain = 20 > 16.
    let mut src = MemGitSource::default();
    let mut sink = MemSink::default();
    let mut map: HashMap<Sha1Id, mkit_core::Hash> = HashMap::new();
    let blob = src.put(GitObjKind::Blob, b"x".to_vec());
    let mut tree = Vec::new();
    tree.extend_from_slice(b"100644 a\0");
    tree.extend_from_slice(&blob);
    let t = src.put(GitObjKind::Tree, tree);
    let c = src.put(GitObjKind::Commit, commit_body(&t, &[], "m\n", 5));
    let mut chain = c;
    let mut target_type = "commit";
    for i in 0..10 {
        chain = src.put(
            GitObjKind::Tag,
            format!(
                "object {}\ntype {target_type}\ntag t{i}\ntagger T <t@x> 5 +0000\n\nm\n",
                hex(&chain)
            )
            .into_bytes(),
        );
        target_type = "tag";
    }
    run(&mut src, &mut sink, &mut map, &chain).expect("10-deep chain is legal");
    let mut wrapped = chain;
    for i in 10..20 {
        wrapped = src.put(
            GitObjKind::Tag,
            format!(
                "object {}\ntype tag\ntag t{i}\ntagger T <t@x> 5 +0000\n\nm\n",
                hex(&wrapped)
            )
            .into_bytes(),
        );
    }
    assert!(
        matches!(
            run(&mut src, &mut sink, &mut map, &wrapped),
            Err(BridgeError::Refused(Refusal::TagChain { .. }))
        ),
        "composed chain past the cap must refuse on the map hit"
    );

    // Declared tag target type must match the actual object: `type
    // commit` over a blob signs an inconsistent mkit tag.
    let mut src = MemGitSource::default();
    let mut sink = MemSink::default();
    let mut map: HashMap<Sha1Id, mkit_core::Hash> = HashMap::new();
    let blob = src.put(GitObjKind::Blob, b"x".to_vec());
    let lying = src.put(
        GitObjKind::Tag,
        format!(
            "object {}\ntype commit\ntag liar\ntagger T <t@x> 5 +0000\n\nm\n",
            hex(&blob)
        )
        .into_bytes(),
    );
    match run(&mut src, &mut sink, &mut map, &lying) {
        Err(BridgeError::Refused(Refusal::Unparsable { detail, .. })) => {
            assert!(detail.contains("target type"), "{detail}");
        }
        other => panic!("expected target-type refusal, got {other:?}"),
    }
}
