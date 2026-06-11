//! Golden vectors for SPEC-GIT-BRIDGE §13, pinned under
//! `rust/tests/golden/git-bridge/`.
//!
//! Layout per vector `<name>`:
//! - `<name>.mkit.bin` — serialized mkit v1 object bytes
//! - `<name>.git.bin`  — full git object bytes (`"<type> <len>\0"+body`)
//! - `<name>.json`     — human-readable ids
//! - `MANIFEST.txt`    — `<name> <blake3-of-mkit.bin> <git-sha1>`
//!
//! The chunked-blob vector (§13.9) pins ids only (json + manifest):
//! its ~1.2 MiB content is regenerated deterministically here instead
//! of being committed.
//!
//! Default mode is read-only assertion (the repo convention). Set
//! `UPDATE_GOLDEN=1` to (re)write the files after a *deliberate,
//! spec-versioned* mapping change.

use mkit_core::object::{
    Blob, ChunkedBlob, Commit, EntryMode, Identity, Object, Tag, Tree, TreeEntry,
};
use mkit_core::sign::{KeyPair, sign_commit, sign_tag};
use mkit_core::{ChunkIterator, FastCdc, Hash};
use mkit_git_bridge::BridgeError;
use mkit_git_bridge::gitobj::{GitObject, sha1_hex};
use mkit_git_bridge::translate::{ObjectSource, translate_closure};
use std::collections::HashMap;
use std::path::PathBuf;

const KEY_SEED: [u8; 32] = [0x11; 32];
const TS: u64 = 1_700_000_000;

fn golden_dir() -> PathBuf {
    // crates/mkit-git-bridge -> crates -> rust, then tests/golden/git-bridge
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.join("tests").join("golden").join("git-bridge")
}

struct MemSource(HashMap<Hash, Object>);

impl MemSource {
    fn put(&mut self, obj: Object) -> Hash {
        let bytes = mkit_core::serialize(&obj).unwrap();
        let h = mkit_core::hash::hash(&bytes);
        self.0.insert(h, obj);
        h
    }
}

impl ObjectSource for MemSource {
    fn read_object(&self, h: &Hash) -> Result<Object, BridgeError> {
        self.0
            .get(h)
            .cloned()
            .ok_or_else(|| BridgeError::Source("missing".into()))
    }
}

/// §13 fixture set, in dependency order. Returns (name, hash) pairs
/// for the nine pinned vectors plus the source they live in.
fn build_vectors() -> (MemSource, Vec<(&'static str, Hash)>) {
    let mut src = MemSource(HashMap::new());
    let kp = KeyPair::from_seed(KEY_SEED);
    let mut vectors = Vec::new();

    // 1. blob
    let blob = src.put(Object::Blob(Blob {
        data: b"hello bridge\n".to_vec(),
    }));
    vectors.push(("blob", blob));

    // 2. empty tree
    let empty_tree = src.put(Object::Tree(Tree { entries: vec![] }));
    vectors.push(("tree_empty", empty_tree));

    // 3. single-entry tree
    let tree_single = src.put(Object::Tree(Tree {
        entries: vec![TreeEntry {
            name: b"README.md".to_vec(),
            mode: EntryMode::Blob,
            object_hash: blob,
        }],
    }));
    vectors.push(("tree_single", tree_single));

    // 4. divergent-sort tree: mkit orders foo < foo.txt, git reverses.
    let sub = src.put(Object::Tree(Tree {
        entries: vec![TreeEntry {
            name: b"inner.txt".to_vec(),
            mode: EntryMode::Blob,
            object_hash: blob,
        }],
    }));
    let tree_divergent = src.put(Object::Tree(Tree {
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
        ],
    }));
    vectors.push(("tree_divergent_sort", tree_divergent));

    // 5. root commit, ed25519 identity, zero annotation slots.
    let mut root = Commit::new_unannotated(
        empty_tree,
        vec![],
        Identity::ed25519(kp.public.0),
        kp.public.0,
        b"root commit\n".to_vec(),
        TS,
        [0; 64],
    );
    root.signature = sign_commit(&root, &kp).unwrap().0;
    let root_hash = src.put(Object::Commit(root));
    vectors.push(("commit_root", root_hash));

    // 6. two-parent commit with annotations + base64-fallback identity.
    let mut second = Commit::new_unannotated(
        tree_single,
        vec![],
        Identity::ed25519(kp.public.0),
        kp.public.0,
        b"second root\n".to_vec(),
        TS,
        [0; 64],
    );
    second.signature = sign_commit(&second, &kp).unwrap().0;
    let second_hash = src.put(Object::Commit(second));
    let mut merge = Commit {
        tree_hash: tree_divergent,
        parents: vec![root_hash, second_hash],
        author: Identity::opaque(b"Author <with@angle.brackets>".to_vec()),
        signer: kp.public.0,
        message: b"merge with annotations\n".to_vec(),
        timestamp: TS,
        message_hash: [0xAA; 32],
        content_digest: [0xBB; 32],
        signature: [0; 64],
    };
    merge.signature = sign_commit(&merge, &kp).unwrap().0;
    let merge_hash = src.put(Object::Commit(merge));
    vectors.push(("commit_merge_annotated", merge_hash));

    // 7. unsigned annotated tag (all-zero signature carried as-is).
    let tag_unsigned = src.put(Object::Tag(Tag {
        target: root_hash,
        target_type: mkit_core::ObjectType::Commit,
        name: b"unsigned-tag".to_vec(),
        tagger: Identity::opaque(b"Tagger".to_vec()),
        signer: [0; 32],
        message: b"annotated, unsigned\n".to_vec(),
        timestamp: TS,
        signature: [0; 64],
    }));
    vectors.push(("tag_unsigned", tag_unsigned));

    // 8. signed tag.
    let mut tag = Tag {
        target: merge_hash,
        target_type: mkit_core::ObjectType::Commit,
        name: b"v1.0.0".to_vec(),
        tagger: Identity::ed25519(kp.public.0),
        signer: kp.public.0,
        message: b"release\n".to_vec(),
        timestamp: TS,
        signature: [0; 64],
    };
    tag.signature = sign_tag(&tag, &kp).unwrap().0;
    let tag_signed = src.put(Object::Tag(tag));
    vectors.push(("tag_signed", tag_signed));

    // 9. chunked blob (>1 MiB), pinned by ids only.
    let big = chunked_content();
    let chunks: Vec<Hash> = ChunkIterator::new(FastCdc::v1(), &big)
        .map(|b| {
            src.put(Object::Blob(Blob {
                data: big[b.offset..b.offset + b.length].to_vec(),
            }))
        })
        .collect();
    let manifest = src.put(Object::ChunkedBlob(ChunkedBlob {
        total_size: big.len() as u64,
        chunk_size: 0,
        chunks,
    }));
    vectors.push(("chunked_blob", manifest));

    (src, vectors)
}

fn chunked_content() -> Vec<u8> {
    (0u32..300_000).flat_map(u32::to_le_bytes).collect()
}

/// Vectors whose (large) content is regenerated, not committed.
const ID_ONLY: &[&str] = &["chunked_blob"];

fn translate_vectors(
    src: &MemSource,
    vectors: &[(&'static str, Hash)],
) -> HashMap<Hash, GitObject> {
    let mut known = HashMap::new();
    let mut emitted: HashMap<Hash, GitObject> = HashMap::new();
    for (_, h) in vectors {
        translate_closure(src, h, &mut known, &mut |eh, g| {
            emitted.insert(*eh, g.clone());
            Ok(())
        })
        .unwrap();
    }
    emitted
}

#[test]
fn golden_vectors_match() {
    let dir = golden_dir();
    let (src, vectors) = build_vectors();
    let emitted = translate_vectors(&src, &vectors);

    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(&dir).unwrap();
        let mut manifest = String::from(
            "# SPEC-GIT-BRIDGE §13 vectors. <name> <blake3-of-mkit-bytes> <git-sha1>\n\
             # Regenerate with: UPDATE_GOLDEN=1 cargo test -p mkit-git-bridge --test golden\n",
        );
        for (name, h) in &vectors {
            let mkit_bytes = mkit_core::serialize(&src.read_object(h).unwrap()).unwrap();
            let git = &emitted[h];
            let sha1 = sha1_hex(&git.id());
            if !ID_ONLY.contains(name) {
                std::fs::write(dir.join(format!("{name}.mkit.bin")), &mkit_bytes).unwrap();
                std::fs::write(dir.join(format!("{name}.git.bin")), git.raw()).unwrap();
            }
            std::fs::write(
                dir.join(format!("{name}.json")),
                format!(
                    "{{\"name\":\"{name}\",\"mkit_blake3\":\"{}\",\"git_sha1\":\"{sha1}\",\"git_type\":\"{}\"}}\n",
                    mkit_core::to_hex(h),
                    git.gtype.name()
                ),
            )
            .unwrap();
            manifest.push_str(&format!("{name} {} {sha1}\n", mkit_core::to_hex(h)));
        }
        std::fs::write(dir.join("MANIFEST.txt"), manifest).unwrap();
        eprintln!("golden vectors rewritten at {}", dir.display());
        return;
    }

    let manifest = std::fs::read_to_string(dir.join("MANIFEST.txt"))
        .expect("golden vectors missing — run UPDATE_GOLDEN=1 once");
    let mut pinned: HashMap<&str, (&str, &str)> = HashMap::new();
    for line in manifest
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let mut parts = line.split(' ');
        let (Some(n), Some(b3), Some(s1)) = (parts.next(), parts.next(), parts.next()) else {
            panic!("malformed manifest line {line:?}");
        };
        pinned.insert(n, (b3, s1));
    }
    assert_eq!(pinned.len(), vectors.len(), "vector count drifted");

    for (name, h) in &vectors {
        let (b3, s1) = pinned[name];
        let git = &emitted[h];
        assert_eq!(mkit_core::to_hex(h), b3, "{name}: mkit hash drifted");
        assert_eq!(sha1_hex(&git.id()), s1, "{name}: git sha1 drifted");
        if ID_ONLY.contains(name) {
            continue;
        }
        let mkit_bin = std::fs::read(dir.join(format!("{name}.mkit.bin"))).unwrap();
        let git_bin = std::fs::read(dir.join(format!("{name}.git.bin"))).unwrap();
        let obj_bytes = mkit_core::serialize(&src.read_object(h).unwrap()).unwrap();
        assert_eq!(obj_bytes, mkit_bin, "{name}: mkit bytes drifted");
        assert_eq!(git.raw(), git_bin, "{name}: git bytes drifted");
    }

    // The empty tree pins git's well-known id (§13.2).
    let empty = vectors.iter().find(|(n, _)| *n == "tree_empty").unwrap();
    assert_eq!(
        sha1_hex(&emitted[&empty.1].id()),
        "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
    );

    // Divergent-sort vector really exercises the §5 re-sort.
    let div = vectors
        .iter()
        .find(|(n, _)| *n == "tree_divergent_sort")
        .unwrap();
    let body = &emitted[&div.1].body;
    let foo_txt_pos = body
        .windows(7)
        .position(|w| w == b"foo.txt")
        .expect("foo.txt present");
    let foo_dir_pos = body
        .windows(4)
        .position(|w| w == b"foo\0")
        .expect("foo dir present");
    assert!(
        foo_txt_pos < foo_dir_pos,
        "git order must place foo.txt before foo/"
    );
}
