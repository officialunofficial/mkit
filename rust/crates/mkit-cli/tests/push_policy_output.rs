//! Byte-exact timing and multiplicity of host-owned push policy warnings.
#![allow(clippy::unwrap_used)]

mod common;

use common::Repo;
use mkit_core::{layout::RepoLayout, refs, to_hex};

const INVALID_DEPTH: &[(&str, &str)] = &[("MKIT_PACK_REBASELINE_DEPTH", "invalid")];
const WARNING: &str = "warning: MKIT_PACK_REBASELINE_DEPTH='invalid' is not a valid non-negative integer; using the default 64 (set it to 0 to disable re-baselining)\n";

#[test]
fn rejected_tracked_push_does_not_print_unused_policy_warning() {
    let repo = Repo::new();
    repo.commit_file("file.txt", b"base\n", "base");
    let base = refs::read_ref(&RepoLayout::single(repo.path()), "main")
        .unwrap()
        .unwrap();
    let remote = tempfile::tempdir().unwrap();
    let endpoint = format!("mkit+file://{}", remote.path().display());
    repo.ok(&["remote", "add", "origin", &endpoint]);
    repo.ok_env(&["push", "origin"], &[("MKIT_PACK_REBASELINE_DEPTH", "64")]);
    repo.commit_file("file.txt", b"later\n", "later");
    repo.ok_env(&["push"], &[("MKIT_PACK_REBASELINE_DEPTH", "64")]);
    repo.ok(&["reset", "--hard", "-f", &to_hex(&base)]);

    // The local non-fast-forward gate rejects before the branch push begins.
    let normal = repo.run_env(&["push"], &[("MKIT_PACK_REBASELINE_DEPTH", "64")]);
    let malformed = repo.run_env(&["push"], INVALID_DEPTH);
    assert_eq!(normal.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&normal.stderr).contains("non-fast-forward"));
    assert_eq!(malformed.status.code(), normal.status.code());
    assert_eq!(malformed.stdout, normal.stdout);
    assert_eq!(malformed.stderr, normal.stderr);
    assert!(!String::from_utf8_lossy(&malformed.stderr).contains("MKIT_PACK_REBASELINE_DEPTH"));
}

#[test]
fn mirror_push_prints_policy_warning_once_per_branch() {
    let repo = Repo::new();
    repo.commit_file("file.txt", b"base\n", "base");
    repo.ok(&["branch", "feature"]);
    let remote = tempfile::tempdir().unwrap();
    let endpoint = format!("mkit+file://{}", remote.path().display());
    repo.ok(&["remote", "add", "origin", &endpoint]);

    let out = repo.ok_env(&["push", "origin", "--all"], INVALID_DEPTH);
    assert_eq!(out.stdout, [] as [u8; 0]);
    assert_eq!(
        out.stderr,
        format!("{WARNING}{WARNING}pushed 2 ref(s) to origin ({endpoint})\n").as_bytes()
    );
    assert!(remote.path().join("refs/heads/main").exists());
    assert!(remote.path().join("refs/heads/feature").exists());
}
