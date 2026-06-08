//! Phase-2 fault injection — crash / partial-write recovery.
//!
//! mkit's single-file writes are atomic (temp→fsync→rename), so the crash risk
//! is the **multi-file** operation state: a conflicted merge/cherry-pick/revert
//! writes 4 sidecar files in sequence via plain `fs::write`, rebase writes 6. A
//! crash between any two leaves a *partial set*. Because that set is small and
//! enumerable, we simulate every crash point **deterministically on disk** — no
//! SIGKILL races, no production fault hooks.
//!
//! Oracle by state class (the key correctness rule):
//!   * **garbled / unparseable** image → assert ONLY: exit allowlisted, no
//!     panic, and `check_store_intact` (the object DAG is not corrupted). The
//!     full `check_invariants` would correctly fail-closed here because
//!     `live_objects()` reads the malformed operation-state roots.
//!   * **parseable partial** image → the same, PLUS: if the recovery command
//!     reports success, the full `check_invariants` must hold.
//!   * **successful `--abort`** → no in-progress marker / residue remains.

mod common;

use std::fs;

use common::{
    Repo, check_exit, check_invariants, check_store_intact, conflicted, in_progress,
    operation_residue,
};

/// The ordered sidecar write sequence for the three top-level conflict ops.
const SIDECAR_OPS: &[(&str, &[&str])] = &[
    (
        "merge",
        &["MERGE_HEAD", "ORIG_HEAD", "MERGE_MSG", "mkit-conflicts"],
    ),
    (
        "cherry-pick",
        &[
            "CHERRY_PICK_HEAD",
            "ORIG_HEAD",
            "CHERRY_PICK_MSG",
            "mkit-conflicts",
        ],
    ),
    (
        "revert",
        &["REVERT_HEAD", "ORIG_HEAD", "REVERT_MSG", "mkit-conflicts"],
    ),
];

/// Recovery argv for `verb` + one of {status, abort, continue}.
fn recovery_args<'a>(verb: &'a str, recovery: &'a str) -> Vec<&'a str> {
    match recovery {
        "status" => vec!["status"],
        flag => vec![verb, flag],
    }
}

/// Run a recovery command against a reconstructed crash image and apply the
/// per-state-class oracle.
fn assert_recovers(repo: &Repo, verb: &str, recovery: &str, label: &str) {
    let args = recovery_args(verb, recovery);
    let out = repo.run(&args);

    // Universal: never panic, always an allowlisted exit, DAG never corrupted.
    check_exit(&out, label).unwrap_or_else(|e| panic!("{label}: {e}"));
    check_store_intact(repo.path(), label).unwrap_or_else(|e| panic!("{label}: {e}"));

    // The FULL battery is only valid once the operation state is fully resolved
    // — an incomplete/garbled in-progress state legitimately makes
    // `live_objects()` (via `collect_roots`) fail closed, which is not repo
    // corruption. So gate on "no op in progress AND no residue" after recovery,
    // regardless of how the crash image was built.
    let resolved = in_progress(&repo.mkit_dir()).is_none()
        && operation_residue(&repo.mkit_dir(), verb).is_none();
    if out.status.success() && resolved {
        check_invariants(repo.path(), label).unwrap_or_else(|e| panic!("{label}: {e}"));
    }
    // A successful `--abort` must fully resolve the operation.
    if recovery == "--abort" && out.status.success() {
        assert!(
            resolved,
            "{label}: successful --abort left an op in progress / residue"
        );
    }
}

// ---------------------------------------------------------------------------
// 1a. Creation-phase crash images (write prefixes + garbled)
// ---------------------------------------------------------------------------

#[test]
fn sidecar_write_prefix_crashes_recover() {
    for &(verb, sidecars) in SIDECAR_OPS {
        // Crash after writing `keep` of the ordered sidecar files: keep the
        // first `keep`, delete the rest. `keep == sidecars.len()` is the full
        // (control) state.
        for keep in 1..=sidecars.len() {
            for recovery in ["status", "--abort", "--continue"] {
                let repo = conflicted(verb);
                for rel in &sidecars[keep..] {
                    let _ = fs::remove_file(repo.mkit_dir().join(rel));
                }
                let label = format!("{verb}/keep{keep}/{recovery}");
                assert_recovers(&repo, verb, recovery, &label);
            }
        }
    }
}

#[test]
fn garbled_sidecar_crashes_do_not_panic() {
    for &(verb, sidecars) in SIDECAR_OPS {
        for recovery in ["status", "--abort", "--continue"] {
            let repo = conflicted(verb);
            // Garble the primary marker (non-hex where a hash is expected).
            fs::write(repo.mkit_dir().join(sidecars[0]), b"NOT-A-HASH\n").unwrap();
            let label = format!("{verb}/garbled/{recovery}");
            assert_recovers(&repo, verb, recovery, &label);
        }
    }
}

#[test]
fn partial_rebase_state_recovers() {
    // A representative member of each rebase-apply parsing shape: a text file
    // (`head-name`), a single-hash file (`onto`), and a hash-list file (`todo`).
    // The remaining members (orig-head/actions/done) parse like one of these.
    let rebase_files = ["head-name", "onto", "todo"];
    // Remove or garble one rebase-apply file at a time, then drive each rebase
    // recovery flag. rebase-apply existing makes mkit see "rebase in progress",
    // so a missing/garbled member must yield a clean error, never a panic.
    for victim in rebase_files {
        for recovery in ["status", "--abort", "--continue", "--skip"] {
            // Missing-file image.
            let repo = conflicted("rebase");
            let _ = fs::remove_file(repo.mkit_dir().join("rebase-apply").join(victim));
            let label = format!("rebase/missing-{victim}/{recovery}");
            assert_recovers(&repo, "rebase", recovery, &label);

            // Garbled-file image.
            let repo = conflicted("rebase");
            fs::write(
                repo.mkit_dir().join("rebase-apply").join(victim),
                b"GARBAGE\n",
            )
            .unwrap();
            let label = format!("rebase/garbled-{victim}/{recovery}");
            assert_recovers(&repo, "rebase", recovery, &label);
        }
    }
}

// ---------------------------------------------------------------------------
// 1b. Cleanup-phase crash images (residue left after a concluded op)
// ---------------------------------------------------------------------------

#[test]
fn stray_cleanup_residue_does_not_corrupt() {
    // Simulate a crash mid-cleanup: the in-progress *marker* was removed but a
    // message / conflict sidecar lingers. With no marker, mkit sees no op in
    // progress, so ordinary commands must tolerate the stray file and never
    // panic or corrupt the DAG.
    let strays = [
        "MERGE_MSG",
        "CHERRY_PICK_MSG",
        "REVERT_MSG",
        "mkit-conflicts",
        "ORIG_HEAD",
    ];
    for stray in strays {
        for cmd in [vec!["status"], vec!["log"], vec!["gc", "--grace-secs", "0"]] {
            let repo = Repo::new();
            repo.commit_file("a.txt", b"hi\n", "c1");
            fs::write(repo.mkit_dir().join(stray), b"stray residue\n").unwrap();
            let label = format!("stray-{stray}/{}", cmd.join("+"));
            let out = repo.run(&cmd);
            check_exit(&out, &label).unwrap_or_else(|e| panic!("{label}: {e}"));
            check_store_intact(repo.path(), &label).unwrap_or_else(|e| panic!("{label}: {e}"));
        }
    }
}

#[test]
fn partial_rebase_apply_removal_does_not_panic() {
    // Cleanup that removed most of rebase-apply/ but left a stray member: mkit
    // still sees "rebase in progress" and any command must fail cleanly.
    for leftover in ["head-name", "todo", "done"] {
        let repo = conflicted("rebase");
        let dir = repo.mkit_dir().join("rebase-apply");
        // Keep only `leftover`; remove every other member.
        for ent in fs::read_dir(&dir).unwrap().flatten() {
            if ent.file_name() != std::ffi::OsStr::new(leftover) {
                let _ = fs::remove_file(ent.path());
            }
        }
        for recovery in ["status", "--abort", "--continue"] {
            // Fresh image per recovery command (recovery mutates state).
            let repo = conflicted("rebase");
            let dir = repo.mkit_dir().join("rebase-apply");
            for ent in fs::read_dir(&dir).unwrap().flatten() {
                if ent.file_name() != std::ffi::OsStr::new(leftover) {
                    let _ = fs::remove_file(ent.path());
                }
            }
            let label = format!("rebase-leftover-{leftover}/{recovery}");
            assert_recovers(&repo, "rebase", recovery, &label);
        }
    }
}

// ---------------------------------------------------------------------------
// 1c. Commit / recovery-log boundaries
// ---------------------------------------------------------------------------

#[test]
fn orphan_commit_object_is_benign() {
    // "object written, ref not moved": a commit object exists in the store but
    // the branch ref still points at its parent. `reset --soft HEAD~1` produces
    // exactly this (the new commit object stays; the ref rolls back). The repo
    // must stay consistent, a follow-up commit must work, and gc must tolerate
    // the orphan.
    let repo = Repo::new();
    repo.commit_file("a.txt", b"v1\n", "c1");
    repo.commit_file("a.txt", b"v2\n", "c2"); // c2 object now in the store
    repo.ok(&["reset", "--soft", "HEAD~1"]); // ref → c1; c2 object orphaned

    check_invariants(repo.path(), "orphan/after-reset").unwrap();
    repo.ok(&["gc", "--grace-secs", "0"]);
    check_invariants(repo.path(), "orphan/after-gc").unwrap();
    // A normal commit still works afterward.
    repo.commit_file("b.txt", b"x\n", "c3");
    check_invariants(repo.path(), "orphan/after-commit").unwrap();
}

#[test]
fn amend_recovery_log_boundary_is_consistent() {
    // amend supersedes a commit and records the old tip in the recovery log so
    // it stays recoverable. Whatever mkit's retention decision, the repo must be
    // consistent and every retained (live) object present — even after an
    // aggressive gc.
    let repo = Repo::new();
    repo.commit_file("a.txt", b"v1\n", "c1");
    repo.commit_file("a.txt", b"v2\n", "c2");
    let amend = repo.run(&["commit", "--amend", "-m", "c2-amended"]);
    check_exit(&amend, "amend").unwrap();
    if amend.status.success() {
        check_invariants(repo.path(), "amend/after").unwrap();
        repo.ok(&["gc", "--grace-secs", "0"]);
        check_invariants(repo.path(), "amend/after-gc").unwrap();
    }
}
