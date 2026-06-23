//! Golden vectors for SPEC-GIT-IMPORT §9, pinned under
//! `rust/tests/golden/git-import/`. Hermetic: source git objects are
//! hand-crafted bytes (no git binary), imported under the fixed test
//! key `[0x42; 32]`.
//!
//! Layout per vector `<name>`: `<name>.git.bin` (source git body),
//! `<name>.mkit.bin` (imported mkit object bytes), `<name>.json`
//! (ids), `MANIFEST.txt` (`<name> <git-sha1> <mkit-object-id>`). The
//! `big_blob` vector pins ids only (content regenerates).
//!
//! `UPDATE_GOLDEN=1` rewrites after a deliberate, spec-versioned
//! mapping change.

// `drop(imp)` is load-bearing: it ends the Importer's &mut borrows
// so the owned sink/map/raws can move; the struct itself has no Drop.
#![allow(clippy::drop_non_drop)]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use mkit_core::Hash;
use mkit_core::sign::{KeyPair, sign_commit, sign_tag, verify_commit, verify_tag};
use mkit_git_bridge::BridgeError;
use mkit_git_bridge::gitobj::{Sha1Id, sha1_hex};
use mkit_git_bridge::gitsrc::GitObjKind;
use mkit_git_bridge::import::{
    DepthMemo, ImportOptions, ImportSigner, Importer, MemGitSource, MemSink,
};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::PathBuf;

const KEY_SEED: [u8; 32] = [0x42; 32];

fn golden_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.join("tests").join("golden").join("git-import")
}

fn hex(id: &Sha1Id) -> String {
    sha1_hex(id)
}

/// §9's nine vectors: (name, source git kind+body, tip-to-import).
/// Supporting objects (trees/blobs/parents) are added to the source
/// but only the named tip is pinned.
#[allow(clippy::too_many_lines)] // one block per spec vector
fn build_vectors() -> (MemGitSource, Vec<(&'static str, Sha1Id)>) {
    let mut src = MemGitSource::default();
    let mut vectors = Vec::new();

    let blob = src.put(GitObjKind::Blob, b"vector content\n".to_vec());
    let mut tree = Vec::new();
    tree.extend_from_slice(b"100644 file.txt\0");
    tree.extend_from_slice(&blob);
    let tree = src.put(GitObjKind::Tree, tree);

    // 1. Plain commit (author == committer, UTC).
    let c1 = src.put(
        GitObjKind::Commit,
        format!(
            "tree {}\nauthor Plain <p@x> 1600000000 +0000\ncommitter Plain <p@x> 1600000000 +0000\n\nplain\n",
            hex(&tree)
        )
        .into_bytes(),
    );
    vectors.push(("commit_plain", c1));

    // 2. Committer ≠ author, non-UTC zones.
    let c2 = src.put(
        GitObjKind::Commit,
        format!(
            "tree {}\nparent {}\nauthor Auth Or <a@x> 1600000100 +0530\ncommitter Com Itter <c@y> 1600000200 -0800\n\nzones\n",
            hex(&tree),
            hex(&c1)
        )
        .into_bytes(),
    );
    vectors.push(("commit_zones", c2));

    // 3. gpgsig with continuation lines.
    let gpgsig_lines: &[&str] = &[
        "tree {T}",
        "author A <a@x> 1600000300 +0000",
        "committer A <a@x> 1600000300 +0000",
        "gpgsig -----BEGIN PGP SIGNATURE-----",
        " iQEzBAABCAAdFiEE",
        " =AbCd",
        " -----END PGP SIGNATURE-----",
        "",
        "signed upstream\n",
    ];
    let body = gpgsig_lines.join("\n").replace("{T}", &hex(&tree));
    let c3 = src.put(GitObjKind::Commit, body.into_bytes());
    vectors.push(("commit_gpgsig", c3));

    // 4. latin-1 message with encoding header.
    let mut body = format!(
        "tree {}\nauthor L <l@x> 1600000400 +0100\ncommitter L <l@x> 1600000400 +0100\nencoding ISO-8859-1\n\ncaf",
        hex(&tree)
    )
    .into_bytes();
    body.push(0xE9); // 'é' in latin-1 — NOT valid UTF-8
    body.push(b'\n');
    let c4 = src.put(GitObjKind::Commit, body);
    vectors.push(("commit_latin1", c4));

    // 5. Historic mode 100664 (normalize-declared-lossy).
    let mut htree = Vec::new();
    htree.extend_from_slice(b"100664 group.txt\0");
    htree.extend_from_slice(&blob);
    let htree = src.put(GitObjKind::Tree, htree);
    let c5 = src.put(
        GitObjKind::Commit,
        format!(
            "tree {}\nauthor H <h@x> 1600000500 +0000\ncommitter H <h@x> 1600000500 +0000\n\nhistoric mode\n",
            hex(&htree)
        )
        .into_bytes(),
    );
    vectors.push(("commit_historic_mode", c5));

    // 6. Octopus merge (3 parents).
    let c6 = src.put(
        GitObjKind::Commit,
        format!(
            "tree {}\nparent {}\nparent {}\nparent {}\nauthor O <o@x> 1600000600 +0000\ncommitter O <o@x> 1600000600 +0000\n\noctopus\n",
            hex(&tree),
            hex(&c1),
            hex(&c2),
            hex(&c3)
        )
        .into_bytes(),
    );
    vectors.push(("commit_octopus", c6));

    // 7. Annotated tag.
    let t7 = src.put(
        GitObjKind::Tag,
        format!(
            "object {}\ntype commit\ntag v1.0.0\ntagger Tagger <t@x> 1600000700 +0200\n\nannotated\n",
            hex(&c6)
        )
        .into_bytes(),
    );
    vectors.push(("tag_annotated", t7));

    // 8. Signed git tag (PGP block in the message).
    let t8 = src.put(
        GitObjKind::Tag,
        format!(
            "object {}\ntype commit\ntag v1.0.1\ntagger Tagger <t@x> 1600000800 +0000\n\nsigned tag\n-----BEGIN PGP SIGNATURE-----\nABCD\n-----END PGP SIGNATURE-----\n",
            hex(&c6)
        )
        .into_bytes(),
    );
    vectors.push(("tag_signed", t8));

    // 9. > 1 MiB blob (ids only — content regenerates).
    let big: Vec<u8> = (0u32..300_000).flat_map(u32::to_le_bytes).collect();
    let b9 = src.put(GitObjKind::Blob, big);
    vectors.push(("big_blob", b9));

    (src, vectors)
}

/// Vectors whose large content is regenerated, not committed.
const IDS_ONLY: &[&str] = &["big_blob"];

fn import_all(
    src: &mut MemGitSource,
    vectors: &[(&'static str, Sha1Id)],
) -> (MemSink, HashMap<Sha1Id, Hash>) {
    let kp = KeyPair::from_seed(KEY_SEED);
    let public = kp.public.0;
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
    for (_, tip) in vectors {
        imp.import_ref(tip).unwrap();
    }
    drop(imp);
    (sink, map)
}

#[test]
fn golden_import_vectors_match() {
    let dir = golden_dir();
    let (mut src, vectors) = build_vectors();
    let git_bodies: HashMap<Sha1Id, Vec<u8>> = src
        .0
        .iter()
        .map(|(id, (_, body))| (*id, body.clone()))
        .collect();
    let (sink, map) = import_all(&mut src, &vectors);

    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(&dir).unwrap();
        let mut manifest = String::from(
            "# SPEC-GIT-IMPORT §9 vectors. <name> <git-sha1> <mkit-object-id>\n\
             # Fixed importer key seed [0x42;32]. Regenerate with:\n\
             # UPDATE_GOLDEN=1 cargo test -p mkit-git-bridge --test golden_import\n",
        );
        for (name, sha1) in &vectors {
            let blake3 = map[sha1];
            if !IDS_ONLY.contains(name) {
                std::fs::write(dir.join(format!("{name}.git.bin")), &git_bodies[sha1]).unwrap();
                std::fs::write(dir.join(format!("{name}.mkit.bin")), &sink.0[&blake3]).unwrap();
            }
            std::fs::write(
                dir.join(format!("{name}.json")),
                format!(
                    "{{\"name\":\"{name}\",\"git_sha1\":\"{}\",\"mkit_id\":\"{}\"}}\n",
                    hex(sha1),
                    mkit_core::to_hex(&blake3)
                ),
            )
            .unwrap();
            let _ = writeln!(
                manifest,
                "{name} {} {}",
                hex(sha1),
                mkit_core::to_hex(&blake3)
            );
        }
        std::fs::write(dir.join("MANIFEST.txt"), manifest).unwrap();
        eprintln!("git-import golden vectors rewritten at {}", dir.display());
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
        let (Some(n), Some(s1), Some(b3)) = (parts.next(), parts.next(), parts.next()) else {
            panic!("malformed manifest line {line:?}");
        };
        pinned.insert(n, (s1, b3));
    }
    assert_eq!(vectors.len(), 9, "SPEC-GIT-IMPORT §9 pins nine vectors");
    assert_eq!(pinned.len(), vectors.len(), "vector count drifted");

    for (name, sha1) in &vectors {
        let (s1, b3) = pinned[name];
        let blake3 = map[sha1];
        assert_eq!(hex(sha1), s1, "{name}: git sha1 drifted");
        assert_eq!(mkit_core::to_hex(&blake3), b3, "{name}: mkit hash drifted");
        if IDS_ONLY.contains(name) {
            continue;
        }
        let git_bin = std::fs::read(dir.join(format!("{name}.git.bin"))).unwrap();
        let mkit_bin = std::fs::read(dir.join(format!("{name}.mkit.bin"))).unwrap();
        assert_eq!(git_bodies[sha1], git_bin, "{name}: git bytes drifted");
        assert_eq!(sink.0[&blake3], mkit_bin, "{name}: mkit bytes drifted");
    }

    // §9 closing MUSTs: byte-stability is the re-derivation above;
    // every signed vector verifies under the test key.
    for (name, sha1) in &vectors {
        let blake3 = map[sha1];
        match mkit_core::deserialize(&sink.0[&blake3]).unwrap() {
            mkit_core::object::Object::Commit(c) => {
                verify_commit(&c).unwrap_or_else(|e| panic!("{name}: {e}"));
            }
            mkit_core::object::Object::Tag(t) => {
                verify_tag(&t).unwrap_or_else(|e| panic!("{name}: {e}"));
            }
            _ => {}
        }
    }

    // Vector 4's message is genuinely non-UTF-8 (the latin-1 é).
    let (_, c4) = vectors.iter().find(|(n, _)| *n == "commit_latin1").unwrap();
    let mkit_core::object::Object::Commit(c) = mkit_core::deserialize(&sink.0[&map[c4]]).unwrap()
    else {
        panic!()
    };
    assert!(
        std::str::from_utf8(&c.message).is_err(),
        "latin-1 must survive verbatim"
    );
    // Vector 2 pins the committer-timestamp rule.
    let (_, c2) = vectors.iter().find(|(n, _)| *n == "commit_zones").unwrap();
    let mkit_core::object::Object::Commit(c) = mkit_core::deserialize(&sink.0[&map[c2]]).unwrap()
    else {
        panic!()
    };
    assert_eq!(c.timestamp, 1_600_000_200, "committer epoch, not author");
}

/// SPEC-GIT-IMPORT §9 refusal vectors, pinned: each hostile input is
/// built deterministically and its TYPED refusal is recorded in
/// `REFUSALS.txt` (`<name> <git-sha1> <refusal-variant>`). Catches a
/// regression where e.g. a gitlink tree starts importing silently.
#[test]
#[allow(clippy::too_many_lines)] // four vectors, one harness
fn refusal_vectors_pinned() {
    let kp = KeyPair::from_seed(KEY_SEED);
    let public = kp.public.0;

    let mut src = MemGitSource::default();
    let mut vectors: Vec<(&'static str, Sha1Id)> = Vec::new();

    let blob = src.put(GitObjKind::Blob, b"x\n".to_vec());

    // Gitlink (submodule) tree entry.
    let mut t = Vec::new();
    t.extend_from_slice(b"160000 sub\0");
    t.extend_from_slice(&blob); // any 20 bytes — gitlinks aren't followed
    let t = src.put(GitObjKind::Tree, t);
    let c = src.put(
        GitObjKind::Commit,
        format!(
            "tree {}\nauthor A <a@x> 5 +0000\ncommitter A <a@x> 5 +0000\n\nsub\n",
            hex(&t)
        )
        .into_bytes(),
    );
    vectors.push(("refuse_gitlink", c));

    // Windows-reserved tree entry name (`aux.c`).
    let mut t = Vec::new();
    t.extend_from_slice(b"100644 aux.c\0");
    t.extend_from_slice(&blob);
    let t = src.put(GitObjKind::Tree, t);
    let c = src.put(
        GitObjKind::Commit,
        format!(
            "tree {}\nauthor A <a@x> 5 +0000\ncommitter A <a@x> 5 +0000\n\naux\n",
            hex(&t)
        )
        .into_bytes(),
    );
    vectors.push(("refuse_tree_name", c));

    // Negative committer timestamp.
    let mut t = Vec::new();
    t.extend_from_slice(b"100644 f\0");
    t.extend_from_slice(&blob);
    let t = src.put(GitObjKind::Tree, t);
    let c = src.put(
        GitObjKind::Commit,
        format!(
            "tree {}\nauthor A <a@x> -5 +0000\ncommitter A <a@x> -5 +0000\n\nold\n",
            hex(&t)
        )
        .into_bytes(),
    );
    vectors.push(("refuse_negative_timestamp", c));

    // Tag name outside the mkit grammar (`v1.0+build`).
    let mut t = Vec::new();
    t.extend_from_slice(b"100644 f\0");
    t.extend_from_slice(&blob);
    let t = src.put(GitObjKind::Tree, t);
    let good = src.put(
        GitObjKind::Commit,
        format!(
            "tree {}\nauthor A <a@x> 5 +0000\ncommitter A <a@x> 5 +0000\n\nok\n",
            hex(&t)
        )
        .into_bytes(),
    );
    let tag = src.put(
        GitObjKind::Tag,
        format!(
            "object {}\ntype commit\ntag v1.0+build\ntagger T <t@x> 5 +0000\n\nm\n",
            hex(&good)
        )
        .into_bytes(),
    );
    vectors.push(("refuse_tag_name", tag));

    // Import each tip; record the typed refusal.
    let mut lines = String::new();
    for (name, tip) in &vectors {
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
        let err = imp.import_ref(tip).expect_err("hostile vector must refuse");
        drop(imp);
        let BridgeError::Refused(refusal) = err else {
            panic!("{name}: expected a typed Refusal, got {err:?}");
        };
        // The variant name is the stable token (Display text may evolve).
        let debug = format!("{refusal:?}");
        let variant = debug.split([' ', '{']).next().unwrap().to_owned();
        let _ = writeln!(lines, "{name} {} {variant}", hex(tip));
    }

    let path = golden_dir().join("REFUSALS.txt");
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(
            &path,
            format!(
                "# SPEC-GIT-IMPORT §9 refusal vectors. <name> <git-sha1> <refusal-variant>\n\
                 # Regenerate with: UPDATE_GOLDEN=1 cargo test -p mkit-git-bridge --test golden_import\n{lines}"
            ),
        )
        .unwrap();
        eprintln!("refusal vectors rewritten at {}", path.display());
        return;
    }
    let pinned =
        std::fs::read_to_string(&path).expect("refusal vectors missing — run UPDATE_GOLDEN=1 once");
    let pinned_body: String =
        pinned
            .lines()
            .filter(|l| !l.starts_with('#'))
            .fold(String::new(), |mut acc, l| {
                acc.push_str(l);
                acc.push('\n');
                acc
            });
    assert_eq!(pinned_body, lines, "typed refusals drifted from the pin");
}
