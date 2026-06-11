//! End-to-end suite for `mkit git export` (feature `git-export`),
//! driving the real binaries (`mkit` + system `git`).
//!
//! Covers SPEC-GIT-BRIDGE's behavioral promises at the CLI level:
//! mirror passes `git fsck --strict`, mirror refs mirror mkit refs,
//! `git log` subjects match `mkit log`, re-export is a no-op, history
//! rewrite force-pushes under the recorded lease, translation is
//! deterministic from fresh state, per-ref refusals skip-and-warn,
//! and all-skipped exports fail. The closing test is a stateful
//! multi-round loop (commit/branch/tag/amend → export → invariants)
//! complementing the default-features proptest state machine, which
//! cannot carry feature-gated ops.
#![cfg(feature = "git-export")]

mod common;

use common::{Repo, check_invariants};
use std::path::Path;
use std::process::{Command, Output};

fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn git(dir: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .expect("spawn git")
}

fn git_ok(dir: &Path, args: &[&str]) -> String {
    let out = git(dir, args);
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn fsck_strict(mirror: &Path) {
    let out = git(mirror, &["fsck", "--strict", "--no-dangling"]);
    assert!(
        out.status.success(),
        "git fsck rejected the mirror:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// All mirror refs as sorted `<ref> <sha1>` lines.
fn mirror_refs(mirror: &Path) -> Vec<String> {
    let mut v: Vec<String> = git_ok(
        mirror,
        &["for-each-ref", "--format=%(refname) %(objectname)"],
    )
    .lines()
    .map(str::to_owned)
    .collect();
    v.sort();
    v
}

/// Per-test scratch dir for mirrors. Mirrors must NOT live directly
/// in the shared system temp dir: a leftover mirror from a previous
/// run would (correctly) fail the create-lease push with "stale info".
fn mirror_root() -> tempfile::TempDir {
    tempfile::tempdir().expect("mirror tempdir")
}

/// A repo with two commits on main (incl. >1 MiB chunked file,
/// symlink-free for portability, subdir, executable bit not relied
/// on), a side branch, and an annotated tag.
fn fixture() -> Repo {
    let r = Repo::new();
    r.commit_file("hi.txt", b"hello bridge\n", "first commit");
    let big: Vec<u8> = (0u32..300_000).flat_map(u32::to_le_bytes).collect();
    r.write("big.bin", &big);
    r.write("sub/inner.txt", b"inner\n");
    r.ok(&["add", "-A"]);
    r.ok(&["commit", "-m", "second commit"]);
    r.ok(&["branch", "side"]);
    r.ok(&["tag", "-a", "v1", "-m", "release one"]);
    r
}

#[test]
fn export_produces_fsck_clean_matching_mirror() {
    if !git_available() {
        return;
    }
    let r = fixture();
    let mroot = mirror_root();
    let mirror = mroot.path().join("mirror-a");
    let out = r.ok(&["git", "export", mirror.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout.matches("exported ").count(),
        3,
        "main, side, v1:\n{stdout}"
    );

    fsck_strict(&mirror);
    let refs = mirror_refs(&mirror);
    let names: Vec<&str> = refs.iter().map(|l| l.split(' ').next().unwrap()).collect();
    assert_eq!(
        names,
        [
            "refs/heads/main",
            "refs/heads/side",
            "refs/mkit/attestations",
            "refs/tags/v1"
        ]
    );

    // git log subjects match mkit log (newest first), modulo ids.
    let git_subjects = git_ok(&mirror, &["log", "--format=%s", "refs/heads/main"]);
    let mkit_log = r.ok(&["log", "--oneline"]);
    let mkit_subjects: Vec<String> = String::from_utf8_lossy(&mkit_log.stdout)
        .lines()
        .map(|l| l.split_once(' ').unwrap().1.to_owned())
        .collect();
    assert_eq!(
        git_subjects.lines().collect::<Vec<_>>(),
        mkit_subjects.iter().map(String::as_str).collect::<Vec<_>>()
    );

    // The >1 MiB chunked blob flattened to one git blob with the
    // exact original content.
    let size = git_ok(&mirror, &["cat-file", "-s", "refs/heads/main:big.bin"]);
    assert_eq!(size.trim(), "1200000");

    // One attestation per exported head, named by git sha.
    let att = git_ok(
        &mirror,
        &["ls-tree", "--name-only", "refs/mkit/attestations"],
    );
    assert_eq!(att.lines().count(), 3);
    assert!(att.lines().all(|l| {
        std::path::Path::new(l)
            .extension()
            .is_some_and(|e| e == "dsse")
    }));

    // mkit-side invariants still hold after exporting.
    check_invariants(r.path(), "post-export").unwrap();
}

#[test]
fn reexport_is_noop_and_rewrite_force_pushes() {
    if !git_available() {
        return;
    }
    let r = fixture();
    let mroot = mirror_root();
    let mirror = mroot.path().join("mirror-b");
    let dest = mirror.to_str().unwrap();
    r.ok(&["git", "export", dest]);
    let first = mirror_refs(&mirror);

    // Second export: byte-identical mirror state (incl. attestations).
    r.ok(&["git", "export", dest]);
    assert_eq!(mirror_refs(&mirror), first, "re-export must be a no-op");

    // Amend = history rewrite: export force-pushes under the lease.
    r.ok(&["commit", "--amend", "-m", "second commit, amended"]);
    r.ok(&["git", "export", dest]);
    let after = mirror_refs(&mirror);
    assert_ne!(after, first, "rewritten head must move the mirror");
    fsck_strict(&mirror);
    let subj = git_ok(&mirror, &["log", "-1", "--format=%s", "refs/heads/main"]);
    assert_eq!(subj.trim(), "second commit, amended");
}

#[test]
fn translation_is_deterministic_from_fresh_state() {
    if !git_available() {
        return;
    }
    let r = fixture();
    let mroot = mirror_root();
    let m1 = mroot.path().join("mirror-c1");
    let m2 = mroot.path().join("mirror-c2");
    r.ok(&["git", "export", m1.to_str().unwrap()]);
    // Nuke ALL bridge state: map cache, ref state, staging repo.
    std::fs::remove_dir_all(r.mkit_dir().join("git")).unwrap();
    r.ok(&[
        "git",
        "export",
        "--remote-name",
        "second",
        m2.to_str().unwrap(),
    ]);

    let strip_attest = |v: Vec<String>| -> Vec<String> {
        // Attestation envelopes embed signer keyids; ref/object ids
        // for translated history must match exactly.
        v.into_iter()
            .filter(|l| !l.starts_with("refs/mkit/attestations"))
            .collect()
    };
    assert_eq!(
        strip_attest(mirror_refs(&m1)),
        strip_attest(mirror_refs(&m2)),
        "fresh-state re-translation must yield identical SHA-1s"
    );
}

#[test]
fn git_illegal_ref_is_skipped_with_warning_rest_exported() {
    if !git_available() {
        return;
    }
    let r = fixture();
    // Leading-dot branch: mkit-legal (SPEC-REFS §3), git-illegal (§12.1).
    r.ok(&["branch", ".hidden"]);
    let mroot = mirror_root();
    let mirror = mroot.path().join("mirror-d");
    let out = r.ok(&["git", "export", mirror.to_str().unwrap()]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("skipping refs/heads/.hidden"),
        "expected a skip warning, got:\n{stderr}"
    );
    let names = mirror_refs(&mirror);
    assert!(names.iter().any(|l| l.starts_with("refs/heads/main ")));
    assert!(!names.iter().any(|l| l.contains(".hidden")));
}

#[test]
fn all_skipped_export_fails() {
    if !git_available() {
        return;
    }
    let r = fixture();
    r.ok(&["branch", ".hidden"]);
    let mroot = mirror_root();
    let mirror = mroot.path().join("mirror-e");
    let out = r.run(&[
        "git",
        "export",
        "--ref",
        "refs/heads/.hidden",
        mirror.to_str().unwrap(),
    ]);
    assert!(
        !out.status.success(),
        "all-skipped export must exit non-zero"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("every requested ref was skipped"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn json_output_is_well_formed() {
    if !git_available() {
        return;
    }
    let r = fixture();
    let mroot = mirror_root();
    let mirror = mroot.path().join("mirror-f");
    let out = r.ok(&["git", "export", "--json", mirror.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.starts_with("{\"ok\":true,\"exported\":["),
        "{stdout}"
    );
    assert!(stdout.trim_end().ends_with("],\"skipped\":[]}"), "{stdout}");
    assert_eq!(stdout.matches("\"ref\":").count(), 3);
}

/// Stateful multi-round loop: mutate → export → verify, every round.
/// Deterministic (fixed key, fixed content), so failures replay.
#[test]
fn stateful_rounds_keep_mirror_and_repo_invariants() {
    if !git_available() {
        return;
    }
    let r = Repo::new();
    let mroot = mirror_root();
    let mirror = mroot.path().join("mirror-g");
    let dest = mirror.to_str().unwrap();

    for round in 0u32..6 {
        // Mutate: alternating shapes — plain commits, a branch, a
        // tag, an amend (rewrite), a big chunked file.
        match round % 6 {
            0 => r.commit_file("a.txt", format!("round {round}\n").as_bytes(), "add a"),
            1 => {
                r.commit_file("b/b.txt", b"nested\n", "add nested");
                r.ok(&["branch", &format!("side-{round}")]);
            }
            2 => {
                r.ok(&["tag", "-a", &format!("v0.{round}"), "-m", "round tag"]);
            }
            3 => {
                r.commit_file("a.txt", b"rewritten\n", "pre-amend");
                r.ok(&["commit", "--amend", "-m", "amended"]);
            }
            4 => {
                let big: Vec<u8> = (0u32..280_000).flat_map(u32::to_le_bytes).collect();
                r.write("big.bin", &big);
                r.ok(&["add", "-A"]);
                r.ok(&["commit", "-m", "big file"]);
            }
            _ => r.commit_file("c.txt", b"last\n", "add c"),
        }

        // Export.
        r.ok(&["git", "export", dest]);

        // Invariants, every round.
        fsck_strict(&mirror);
        check_invariants(r.path(), &format!("round {round}")).unwrap();

        // Mirror branch/tag refs == mkit branch/tag refs (count + names).
        let mkit_refs = r.ok(&["show-ref"]);
        let mkit_names: Vec<String> = String::from_utf8_lossy(&mkit_refs.stdout)
            .lines()
            .map(|l| l.split(' ').next_back().unwrap().to_owned())
            .filter(|n| n.starts_with("refs/heads/") || n.starts_with("refs/tags/"))
            .collect();
        let mirror_names: Vec<String> = mirror_refs(&mirror)
            .iter()
            .map(|l| l.split(' ').next().unwrap().to_owned())
            .filter(|n| n.starts_with("refs/heads/") || n.starts_with("refs/tags/"))
            .collect();
        let mut a = mkit_names.clone();
        a.sort();
        assert_eq!(a, mirror_names, "round {round}: mirror refs drifted");
    }

    // Closing determinism audit: fresh state, fresh mirror, same ids.
    std::fs::remove_dir_all(r.mkit_dir().join("git")).unwrap();
    let m2 = mroot.path().join("mirror-g2");
    r.ok(&[
        "git",
        "export",
        "--remote-name",
        "audit",
        m2.to_str().unwrap(),
    ]);
    let strip = |v: Vec<String>| -> Vec<String> {
        v.into_iter()
            .filter(|l| !l.starts_with("refs/mkit/attestations"))
            .collect()
    };
    assert_eq!(strip(mirror_refs(&mirror)), strip(mirror_refs(&m2)));
}
