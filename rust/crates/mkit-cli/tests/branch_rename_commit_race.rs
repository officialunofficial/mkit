//! Issue #658 — "Race 1" from the immutable/mutable-log perf analysis:
//! `branch -m` (Fix A: CAS-guarded delete, `refs::delete_ref_if_matches`)
//! racing `commit` (Fix B: `Match`-conditioned ref advance,
//! `commit::advance_head`) on the SAME branch, driven through real
//! `mkit` subprocesses.
//!
//! Before the fix: `commit`'s ref advance used
//! `RefWriteCondition::Any` and `branch -m`'s delete of the source ref
//! was unconditional. The interleaving "rename reads tip T, commit's
//! CAS lands T→C, rename deletes the ref anyway" silently lost the
//! just-landed commit `C` — with BOTH commands reporting success and no
//! error to either caller.
//!
//! After the fix, for every round: the landed commit (if any) is
//! reachable from exactly one of {old branch name, new branch name},
//! never both and never neither while `commit` claims success. This is
//! #658's strongest proof — it drives the real CLI, not a
//! `mkit-core`-internal simulation of it.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::process::Output;
use std::thread;
use std::time::Instant;

use common::{Repo, check_exit};
use mkit_core::hash::Hash;
use mkit_core::layout::RepoLayout;
use mkit_core::object::Object;
use mkit_core::ops::merge::is_ancestor;
use mkit_core::refs;
use mkit_core::store::ObjectStore;

/// Padding files widen `commit`'s critical section (tree-build + sign +
/// durable object write, all between its `resolve_head` parent read and
/// its final `advance_head` CAS) relative to `branch -m`'s much smaller
/// one (read + two ref writes) — without this, the two commands'
/// wall-clock windows rarely overlap at all (in manual verification, a
/// same-size unpadded race did not reproduce the loss even once in 80
/// rounds). This does not change WHAT is being tested, only the odds of
/// a real OS scheduler landing the interleaving on any given attempt.
const PADDING_FILES: u32 = 50;

/// Find the (single) commit in the store whose message is exactly
/// `msg`, if any landed durably. Presence here does NOT imply it's
/// reachable from any ref — Fix B's whole point is that a refused
/// advance still leaves the commit object durable-but-unreferenced
/// ("GC-recoverable", never corrupted).
fn find_commit_with_message(store: &ObjectStore, msg: &str) -> Option<Hash> {
    for h in store.iter_object_hashes().ok()? {
        if let Ok(Object::Commit(c)) = store.read_object(&h)
            && c.message == msg.as_bytes()
        {
            return Some(h);
        }
    }
    None
}

/// Whether `target` is reachable (as itself or an ancestor) from
/// branch `name`'s current tip, if that branch currently exists.
fn reachable_from_branch(
    store: &ObjectStore,
    layout: &RepoLayout,
    name: &str,
    target: Hash,
) -> bool {
    match refs::read_ref(layout, name) {
        Ok(Some(tip)) => is_ancestor(store, target, tip).unwrap_or(false),
        _ => false,
    }
}

/// Core correctness check for one round: the landed commit (if any) is
/// reachable from exactly one of {`"main"`, `new_name`}, never both and
/// never neither while `commit` claims success. Returns whether this
/// round actually raced to a durable-but-unreachable landing (a
/// diagnostic, not itself a failure — see the caller).
fn assert_round_outcome(
    store: &ObjectStore,
    layout: &RepoLayout,
    i: u32,
    msg: &str,
    new_name: &str,
    rename_out: &Output,
    commit_out: &Output,
) -> bool {
    let commit_reported_ok = commit_out.status.success();
    let Some(hash) = find_commit_with_message(store, msg) else {
        // The commit object was never even written — only possible if
        // `commit` failed before reaching the object-write step. It
        // must not claim success.
        assert!(
            !commit_reported_ok,
            "iteration {i}: commit reported success but its object was never written to the \
             store; stderr: {}",
            String::from_utf8_lossy(&commit_out.stderr)
        );
        return false;
    };

    let on_old = reachable_from_branch(store, layout, "main", hash);
    let on_new = reachable_from_branch(store, layout, new_name, hash);
    assert!(
        !(on_old && on_new),
        "iteration {i}: commit {hash:?} reachable from BOTH 'main' and '{new_name}' \
         simultaneously — impossible under correct CAS locking"
    );
    if on_old || on_new {
        assert!(
            commit_reported_ok,
            "iteration {i}: commit {hash:?} is reachable but `commit` reported failure; \
             stderr: {}",
            String::from_utf8_lossy(&commit_out.stderr)
        );
        return false;
    }
    // The commit object exists (durable) but is reachable from NEITHER
    // branch name — acceptable ONLY if `commit` itself reported the
    // failure (Fix B's TEMPFAIL / a lock conflict). A reported success
    // here means the commit was silently lost — exactly the #658 bug
    // this test guards against.
    assert!(
        !commit_reported_ok,
        "iteration {i}: commit {hash:?} is durable but UNREACHABLE from either branch, yet \
         `commit` reported success — the commit was silently lost (issue #658). rename \
         stderr: {} / commit stderr: {}",
        String::from_utf8_lossy(&rename_out.stderr),
        String::from_utf8_lossy(&commit_out.stderr)
    );
    true
}

/// Restore a clean, single-`"main"`-branch state for the next round,
/// regardless of which side "won" this one. Written defensively:
/// pre-fix code's unconditional `Any` advance can "resurrect" a
/// just-deleted `main` (commit's own `read_head` snapshot goes stale
/// mid-flight, same root cause as the bug this test targets), so more
/// than the two tidy end states {main only} / {`new_name` only} can
/// occur here.
fn restore_clean_main(repo: &Repo, layout: &RepoLayout, new_name: &str) {
    if refs::read_ref(layout, "main").unwrap().is_none() {
        // "main" itself is gone: promote whichever branch HEAD (or,
        // failing that, this round's `new_name`) currently names back
        // to "main" so the next round starts clean.
        let current = match refs::read_head(layout).unwrap() {
            refs::Head::Branch(b) => b,
            refs::Head::Detached(_) => new_name.to_owned(),
        };
        repo.ok(&["checkout", "--force", &current]);
        if current != "main" {
            repo.ok(&["branch", "-m", &current, "main"]);
        }
    }
    // HEAD must be on "main" before any stray same-round branch can be
    // force-deleted (deleting the checked-out branch is refused).
    if !matches!(refs::read_head(layout).unwrap(), refs::Head::Branch(ref b) if b == "main") {
        repo.ok(&["checkout", "--force", "main"]);
    }
    if refs::read_ref(layout, new_name).unwrap().is_some() {
        repo.ok(&["branch", "-D", new_name]);
    }
}

/// Races `mkit branch -m main renamed-N` against `mkit commit -m
/// "commit-N"` on the currently checked-out branch, `iterations`
/// rounds, restoring a clean single-`main`-branch state between rounds.
/// Repeats several rounds since the race window is a handful of
/// syscalls wide and is not guaranteed to be hit on any single attempt
/// — the same reasoning `mkit-core`'s
/// `cas_match_race_never_loses_an_update_across_uncoordinated_callers`
/// documents for its own loop.
#[test]
fn branch_rename_racing_commit_never_loses_the_commit() {
    let repo = Repo::new();
    repo.commit_file("base.txt", b"base\n", "base");

    // Calibrate: measure one representative `commit` duration on this
    // machine/repo shape, then sweep `branch -m`'s launch delay across
    // that range across rounds (see `sweep_delay`). A pure "start both
    // at once" race mostly just measures which process the OS
    // dispatches first, not whether the two commands' internal critical
    // sections overlap; sweeping a deliberate delay for the (much
    // faster) rename gives every part of commit's critical section a
    // chance to be "underneath" it on some round.
    for j in 0..PADDING_FILES {
        repo.write(&format!("cal-{j}.txt"), format!("cal {j}\n").as_bytes());
    }
    repo.ok(&["add", "."]);
    let calibration_start = Instant::now();
    repo.ok(&["commit", "-m", "calibration"]);
    let baseline = calibration_start.elapsed();

    let iterations: u32 = 36;
    let sweep_steps: u32 = 12;
    let mut ever_raced_to_an_unreachable_landing = false;

    for i in 0..iterations {
        // Fresh content staged BEFORE racing, so `commit` does no extra
        // `add`/staging I/O inside the race window itself.
        let file = format!("round{i}.txt");
        repo.write(&file, format!("round {i}\n").as_bytes());
        repo.ok(&["add", &file]);
        for j in 0..PADDING_FILES {
            repo.write(
                &format!("pad{i}-{j}.txt"),
                format!("pad {i} {j}\n").as_bytes(),
            );
        }
        repo.ok(&["add", "."]);

        let msg = format!("commit-{i}");
        let new_name = format!("renamed-{i}");

        // Sweep the delay from 0 up to ~1.3x the measured baseline
        // across `sweep_steps` buckets, so across enough rounds every
        // part of `commit`'s critical section gets a turn at being
        // "underneath" `branch -m`'s read-then-delete.
        let step = i % sweep_steps;
        let delay = baseline.mul_f64(1.3 * f64::from(step) / f64::from(sweep_steps - 1));

        let (rename_out, commit_out): (Output, Output) = thread::scope(|scope| {
            let repo_ref = &repo;
            let new_name_ref = new_name.as_str();
            let msg_ref = msg.as_str();
            let commit_handle = scope.spawn(move || repo_ref.run(&["commit", "-m", msg_ref]));
            let rename_handle = scope.spawn(move || {
                thread::sleep(delay);
                repo_ref.run(&["branch", "-m", "main", new_name_ref])
            });
            (
                rename_handle.join().expect("rename thread panicked"),
                commit_handle.join().expect("commit thread panicked"),
            )
        });

        check_exit(&rename_out, "branch -m").unwrap();
        check_exit(&commit_out, "commit").unwrap();

        let layout = RepoLayout::single(repo.path());
        let store = ObjectStore::open(&layout).expect("open store");
        if assert_round_outcome(
            &store,
            &layout,
            i,
            &msg,
            &new_name,
            &rename_out,
            &commit_out,
        ) {
            ever_raced_to_an_unreachable_landing = true;
        }

        restore_clean_main(&repo, &layout, &new_name);
        assert_eq!(
            refs::list_refs(&layout).unwrap().len(),
            1,
            "iteration {i}: expected exactly one branch ('main') after cleanup"
        );
    }

    // Not a hard requirement (the race window is narrow and OS process
    // spawn/schedule timing isn't controlled), but recorded for honesty
    // about this test's actual power on this run — same convention as
    // `delete_ref_with_history_races_update_without_tearing_ref_and_journal`
    // in `mkit-core`, which documents that its own race didn't reliably
    // reproduce in manual verification either.
    eprintln!(
        "branch_rename_racing_commit_never_loses_the_commit: at least one round raced to a \
         durable-but-unreachable commit: {ever_raced_to_an_unreachable_landing}"
    );
}
