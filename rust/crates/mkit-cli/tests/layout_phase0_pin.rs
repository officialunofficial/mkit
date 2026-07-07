//! Phase 0 of #493 (`RepoLayout`) promises a byte-identical on-disk
//! layout for classic single-worktree repositories. These tests pin
//! that contract: the exact `.mkit/` structure a scripted command
//! sequence produces, and the agreement between `RepoLayout`'s
//! accessors and the real files the binary writes.
//!
//! Later phases (linked worktrees) MUST keep these passing untouched —
//! a single-worktree repo's on-disk shape is a compatibility surface.

mod common;

use std::collections::BTreeSet;
use std::path::Path;

use common::Repo;
use mkit_core::layout::RepoLayout;

/// Collect `.mkit`-relative paths (files and dirs), excluding
/// content-addressed interiors whose names vary run-to-run (object
/// shards, history journal blobs) and lock files that exist only while
/// a command runs.
fn mkit_entries(mkit: &Path) -> BTreeSet<String> {
    fn walk(dir: &Path, base: &Path, out: &mut BTreeSet<String>) {
        for entry in std::fs::read_dir(dir).expect("read_dir") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            let rel = path
                .strip_prefix(base)
                .expect("under .mkit")
                .to_string_lossy()
                .replace('\\', "/");
            // Content-addressed interiors: presence pinned via the
            // parent dir, contents vary with commit timestamps.
            let volatile_interior = rel.starts_with("objects/") || rel.starts_with("history/");
            if !volatile_interior {
                out.insert(rel.clone());
            }
            if path.is_dir() && !volatile_interior {
                walk(&path, base, out);
            }
        }
    }
    let mut out = BTreeSet::new();
    walk(mkit, mkit, &mut out);
    out.retain(|p| {
        std::path::Path::new(p)
            .extension()
            .is_none_or(|e| e != "lock")
    });
    out
}

/// The `.mkit` structure after init + commit + branch + tag + stash is
/// exactly the historical single-worktree layout — nothing moved,
/// nothing added, nothing renamed.
#[test]
fn scripted_sequence_produces_historical_layout() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "first");
    repo.ok(&["branch", "side"]);
    repo.ok(&["tag", "v1"]);
    // Dirty the tree, stash it away.
    repo.write("a.txt", b"two\n");
    repo.ok(&["stash", "save", "-m", "wip"]);

    let entries = mkit_entries(&repo.mkit_dir());
    let expected: BTreeSet<String> = [
        "HEAD",
        "format",
        "index",
        "keys",
        "keys/default.key",
        "objects",
        "refs",
        "refs/heads",
        "refs/heads/main",
        "refs/heads/side",
        "refs/remotes",
        "refs/tags",
        "refs/tags/v1",
        "stash",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    // `history/` only materialises when the binary ships history-mmr;
    // accept both shapes without weakening the rest of the pin.
    let entries: BTreeSet<String> = entries.into_iter().filter(|e| e != "history").collect();
    assert_eq!(
        entries, expected,
        "single-worktree .mkit layout drifted — Phase 0/1 of #493 forbids this"
    );
}

/// `RepoLayout::single` accessors point at exactly the files the real
/// binary reads and writes — the layout is an accurate map, not a
/// parallel convention.
#[test]
fn layout_accessors_agree_with_binary_output() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "first");
    repo.ok(&["tag", "v1"]);
    repo.write("a.txt", b"two\n");
    repo.ok(&["stash", "save", "-m", "wip"]);

    let layout = RepoLayout::single(repo.path());
    assert!(layout.is_single());
    assert_eq!(layout.common_dir(), repo.mkit_dir().as_path());
    assert_eq!(layout.worktree_state_dir(), repo.mkit_dir().as_path());

    for (name, path) in [
        ("head_file", layout.head_file()),
        ("index_file", layout.index_file()),
        ("format_file", layout.format_file()),
        ("stash_file", layout.stash_file()),
    ] {
        assert!(path.is_file(), "{name} missing at {}", path.display());
    }
    for (name, path) in [
        ("objects_dir", layout.objects_dir()),
        ("heads_dir", layout.heads_dir()),
        ("tags_dir", layout.tags_dir()),
        ("remotes_dir", layout.remotes_dir()),
        ("keys_dir", layout.keys_dir()),
    ] {
        assert!(path.is_dir(), "{name} missing at {}", path.display());
    }
    assert!(layout.heads_dir().join("main").is_file());
    assert!(layout.tags_dir().join("v1").is_file());

    // Op-state accessors point where the binary parks in-progress
    // state: force a merge conflict and check the sidecars. (The
    // stashed edit stays stashed, so the tree is clean to branch.)
    repo.ok(&["checkout", "-b", "side", "HEAD"]);
    repo.write("a.txt", b"theirs\n");
    repo.ok(&["add", "a.txt"]);
    repo.ok(&["commit", "-m", "theirs"]);
    repo.ok(&["checkout", "main"]);
    repo.write("a.txt", b"ours\n");
    repo.ok(&["add", "a.txt"]);
    repo.ok(&["commit", "-m", "ours"]);
    let merge = repo.run(&["merge", "side"]);
    assert!(
        !merge.status.success(),
        "merge should conflict: {}",
        String::from_utf8_lossy(&merge.stdout)
    );
    assert!(
        layout.merge_head_file().is_file(),
        "MERGE_HEAD not at layout.merge_head_file()"
    );
    assert!(
        layout.orig_head_file().is_file(),
        "ORIG_HEAD not at layout.orig_head_file()"
    );
    assert!(
        layout.conflicts_file().is_file(),
        "conflict sidecar not at layout.conflicts_file()"
    );
}
