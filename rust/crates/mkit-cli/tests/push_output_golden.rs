//! Byte-exact push reporting; the endpoint and commit ids are fixture inputs.
#![allow(clippy::unwrap_used)]

mod common;

use common::Repo;
use mkit_core::{layout::RepoLayout, refs, to_hex};

#[test]
fn push_output_stays_byte_identical() {
    let repo = Repo::new();
    repo.commit_file("file.txt", b"first\n", "first");
    let remote = tempfile::tempdir().unwrap();
    let endpoint = format!("mkit+file://{}", remote.path().display());
    repo.ok(&["remote", "add", "origin", &endpoint]);

    let first = repo.ok(&["push", "origin"]);
    assert_eq!(first.stdout, [] as [u8; 0]);
    assert_eq!(
        first.stderr,
        format!("To {endpoint}\n * [new branch]      main -> main\n").as_bytes()
    );
    let no_op = repo.ok(&["push"]);
    assert_eq!(no_op.stdout, [] as [u8; 0]);
    assert_eq!(no_op.stderr, b"Everything up-to-date\n");

    let layout = RepoLayout::single(repo.path());
    let old = to_hex(&refs::read_ref(&layout, "main").unwrap().unwrap());
    repo.commit_file("file.txt", b"second\n", "second");
    let new = to_hex(&refs::read_ref(&layout, "main").unwrap().unwrap());
    let append = repo.ok(&["push"]);
    assert_eq!(append.stdout, [] as [u8; 0]);
    assert_eq!(
        append.stderr,
        format!(
            "To {endpoint}\n   {}..{}  main -> main\n",
            &old[..7],
            &new[..7]
        )
        .as_bytes()
    );
}
