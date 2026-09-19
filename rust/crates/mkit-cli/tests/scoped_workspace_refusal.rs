//! Scoped-workspace boundary: ordinary commands refuse scoped roots.
//!
//! A scoped workspace's `.mkit` is the marker FILE `mkit-scoped: 1\n`, not
//! a repository state dir — every ordinary command (`init`, `status`,
//! `checkout`, `gc`, `rev-parse --show-toplevel`) invoked at the root, in
//! a nested directory, or through global `-C` must refuse BEFORE walking
//! up into an ancestor repository or creating ordinary files. The same
//! refusal applies to recognizable-but-incomplete scoped installs (a
//! `.mkit-scoped` carrying `CURRENT`/`generations` metadata without the
//! marker). An unrelated directory that merely happens to be named
//! `.mkit-scoped` is not authority and must not trip `init`.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in integration tests

mod common;

use std::path::{Path, PathBuf};

use common::{Repo, check_exit, mkit};

const COMMANDS: &[&[&str]] = &[
    &["status"],
    &["checkout", "main"],
    &["gc"],
    &["rev-parse", "--show-toplevel"],
];

/// Hand-build a scoped workspace root: exact marker file plus a minimal
/// `.mkit-scoped` tree (the classifier only needs the marker, but the
/// state dir makes the fixture honest).
fn scoped_root(parent: &Path, name: &str) -> PathBuf {
    let root = parent.join(name);
    let state = root.join(".mkit-scoped");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(state.join("workspace.lock"), b"").unwrap();
    std::fs::write(root.join(".mkit"), b"mkit-scoped: 1\n").unwrap();
    root
}

/// Hand-build a torn scoped install: recognizable `.mkit-scoped/CURRENT`
/// metadata, no marker.
fn incomplete_root(parent: &Path, name: &str) -> PathBuf {
    let root = parent.join(name);
    let state = root.join(".mkit-scoped");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(state.join("CURRENT"), b"MKCR\x01incomplete").unwrap();
    root
}

fn assert_refused(cwd: &Path, xdg: &Path, args: &[&str], ctx: &str) {
    let out = mkit(cwd, xdg, args);
    assert!(
        !out.status.success(),
        "{ctx}: `mkit {}` must refuse inside a scoped workspace",
        args.join(" ")
    );
    check_exit(&out, ctx).unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("scoped"),
        "{ctx}: `mkit {}` stderr must name the scoped workspace, got: {stderr}",
        args.join(" ")
    );
}

fn refused_from_everywhere(root: &Path, xdg: &Path, ctx: &str) {
    let nested = root.join("deep/nested");
    std::fs::create_dir_all(&nested).unwrap();
    for args in COMMANDS {
        assert_refused(root, xdg, args, &format!("{ctx} root"));
        assert_refused(&nested, xdg, args, &format!("{ctx} nested"));
        for (target, tag) in [(root, "root"), (nested.as_path(), "nested")] {
            let global: Vec<&str> = std::iter::once("-C")
                .chain(std::iter::once(target.to_str().unwrap()))
                .chain(args.iter().copied())
                .collect();
            let out = mkit(xdg, xdg, &global);
            assert!(
                !out.status.success(),
                "{ctx} -C {tag}: `mkit {}` must refuse inside a scoped workspace",
                global.join(" ")
            );
            check_exit(&out, ctx).unwrap();
            assert!(
                String::from_utf8_lossy(&out.stderr).contains("scoped"),
                "{ctx} -C {tag}: stderr must name the scoped workspace"
            );
        }
    }
    // `init` refuses too — and creates no ordinary `.mkit` directory.
    for cwd in [root, &nested] {
        let out = mkit(cwd, xdg, &["init"]);
        assert!(!out.status.success(), "{ctx}: init must refuse");
        assert!(!cwd.join(".mkit").is_dir(), "{ctx}: init created .mkit");
    }
    // A scoped marker file, when present, is untouched.
    let marker = root.join(".mkit");
    if marker.is_file() {
        assert_eq!(std::fs::read(&marker).unwrap(), b"mkit-scoped: 1\n");
    }
}

#[test]
fn scoped_workspace_root_refuses_ordinary_commands() {
    let host = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let root = scoped_root(host.path(), "ws");
    refused_from_everywhere(&root, xdg.path(), "scoped");
}

#[test]
fn incomplete_scoped_install_refuses_ordinary_commands() {
    let host = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let root = incomplete_root(host.path(), "ws");
    refused_from_everywhere(&root, xdg.path(), "incomplete");
}

#[test]
fn scoped_root_inside_ordinary_repo_does_not_reach_the_repo() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"data\n", "seed");
    let root = scoped_root(repo.path(), "ws");
    let out = mkit(&root, repo.xdg(), &["status"]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("scoped"),
        "status must refuse with the scoped diagnostic, not reach the outer repo"
    );
    // rev-parse --show-toplevel must not resolve the ancestor repo root.
    let out = mkit(&root, repo.xdg(), &["rev-parse", "--show-toplevel"]);
    assert!(!out.status.success());
    assert!(!String::from_utf8_lossy(&out.stdout).contains(".mkit"));
    // init refuses and does not create a nested `.mkit` dir.
    let out = mkit(&root, repo.xdg(), &["init"]);
    assert!(!out.status.success());
    assert!(!root.join(".mkit").is_dir());
}

#[test]
fn unrelated_mkit_scoped_directory_does_not_block_init() {
    let host = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let dir = host.path().join("plain");
    let unrelated = dir.join(".mkit-scoped");
    std::fs::create_dir_all(&unrelated).unwrap();
    std::fs::write(unrelated.join("workspace.lock"), b"").unwrap();
    std::fs::write(unrelated.join("notes.txt"), b"unrelated\n").unwrap();
    let out = mkit(&dir, xdg.path(), &["init"]);
    assert!(
        out.status.success(),
        "init must ignore an unrelated .mkit-scoped dir: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(dir.join(".mkit").is_dir());
}
