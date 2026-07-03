//! Integration tests for the CLI-WIRE commands (9 subcommands).
//!
//! Each command gets at least one happy-path and one error-path test.
//! We spawn the real `mkit` binary so full argv → dispatch → library
//! path is exercised.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::Path;
use std::process::Command;

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run_in(cwd: &Path, args: &[&str]) -> std::process::Output {
    // Empty XDG_CONFIG_HOME per call so the developer's real user
    // config does not bleed into tests.
    let xdg = tempfile::tempdir().expect("xdg tempdir");
    let out = Command::new(mkit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg.path())
        .output()
        .expect("spawn mkit");
    drop(xdg);
    out
}

fn init_repo(td: &Path) {
    assert!(run_in(td, &["init"]).status.success());
    // we removed auto-keygen on `mkit commit`.
    assert!(run_in(td, &["keygen"]).status.success());
}

fn make_commit(td: &Path, file: &str, body: &[u8], msg: &str) {
    fs::write(td.join(file), body).unwrap();
    assert!(run_in(td, &["add", file]).status.success());
    let out = run_in(td, &["commit", "-m", msg]);
    assert!(out.status.success(), "commit failed: {out:?}");
}

fn head_hash(td: &Path) -> String {
    ref_hash(td, "main")
}

fn ref_hash(td: &Path, branch: &str) -> String {
    fs::read_to_string(td.join(".mkit/refs/heads").join(branch))
        .unwrap()
        .trim()
        .to_string()
}

// ---------- clone ---------------------------------------------------------

#[test]
fn clone_errors_on_missing_url() {
    let td = tempfile::tempdir().unwrap();
    let out = run_in(td.path(), &["clone"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.to_lowercase().contains("usage"),
        "expected usage diagnostic on stderr, got: {stderr}"
    );
}

#[test]
fn clone_from_file_url_roundtrips() {
    // FileTransport expects a bare-ish layout with `refs/heads/...` and
    // `packs/...` directly under its root URL — NOT the in-repo `.mkit/`
    // layout. We set up a bare directory, push alice's refs into it,
    // then clone from the bare URL.
    let alice = tempfile::tempdir().unwrap();
    init_repo(alice.path());
    make_commit(alice.path(), "a.txt", b"hi from alice\n", "first");

    let bare = tempfile::tempdir().unwrap();
    let url = format!("mkit+file://{}", bare.path().display());
    // Publish alice's main ref into the bare remote.
    assert!(
        run_in(alice.path(), &["remote", "add", &url])
            .status
            .success()
    );
    let out = run_in(alice.path(), &["push"]);
    assert!(out.status.success(), "push failed: {out:?}");

    let parent = tempfile::tempdir().unwrap();
    let out = Command::new(mkit_bin())
        .args(["clone", &url, "bob"])
        .current_dir(parent.path())
        .output()
        .expect("spawn");
    assert!(out.status.success(), "clone failed: {out:?}");
    let bob = parent.path().join("bob");
    assert!(bob.join(".mkit/refs/heads/main").is_file());
    assert_eq!(
        fs::read_to_string(alice.path().join(".mkit/refs/heads/main"))
            .unwrap()
            .trim(),
        fs::read_to_string(bob.join(".mkit/refs/heads/main"))
            .unwrap()
            .trim(),
    );
}

// ---------- merge ---------------------------------------------------------

#[test]
fn merge_errors_on_missing_branch() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    let out = run_in(td.path(), &["merge", "nope"]);
    assert!(!out.status.success());
}

#[test]
fn merge_fast_forwards_when_current_is_ancestor() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "a.txt", b"1\n", "c1");
    let c1 = head_hash(td.path());
    assert!(run_in(td.path(), &["branch", "feature"]).status.success());
    // Advance feature ahead of main.
    assert!(run_in(td.path(), &["checkout", "feature"]).status.success());
    make_commit(td.path(), "a.txt", b"2\n", "c2");
    // Go back to main — main still at c1 — and merge feature (ff).
    assert!(run_in(td.path(), &["checkout", "main"]).status.success());
    // Only assert merge ran; check it claims fast-forward.
    let out = run_in(td.path(), &["merge", "feature"]);
    assert!(out.status.success(), "merge failed: {out:?}");
    // Confirmation prose now lives on stderr.
    let stderr = String::from_utf8(out.stderr).unwrap();
    let lower = stderr.to_lowercase();
    assert!(
        lower.contains("fast-forward") || lower.contains("up to date"),
        "unexpected merge output: {stderr}"
    );
    // main should have moved off c1.
    assert_ne!(head_hash(td.path()), c1);
}

#[test]
fn merge_preserves_ignored_untracked_files() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "a.txt", b"1\n", "c1");
    assert!(run_in(td.path(), &["branch", "feature"]).status.success());
    assert!(run_in(td.path(), &["checkout", "feature"]).status.success());
    make_commit(td.path(), "a.txt", b"2\n", "c2");
    assert!(run_in(td.path(), &["checkout", "main"]).status.success());

    fs::write(td.path().join(".mkitignore"), "local.txt\n").unwrap();
    fs::write(td.path().join("local.txt"), b"local only\n").unwrap();

    let out = run_in(td.path(), &["merge", "feature"]);
    assert!(out.status.success(), "merge failed: {out:?}");
    assert_eq!(
        fs::read(td.path().join("local.txt")).unwrap(),
        b"local only\n"
    );
    assert_eq!(
        fs::read_to_string(td.path().join(".mkitignore")).unwrap(),
        "local.txt\n"
    );
}

// ---------- cherry-pick ---------------------------------------------------

#[test]
fn cherry_pick_errors_on_bad_hash() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    let out = run_in(td.path(), &["cherry-pick", "not-a-hash"]);
    assert!(!out.status.success());
}

#[test]
fn cherry_pick_restores_worktree_and_advances_ref() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "base.txt", b"base\n", "base");
    assert!(run_in(td.path(), &["branch", "feature"]).status.success());
    assert!(run_in(td.path(), &["checkout", "feature"]).status.success());
    make_commit(td.path(), "picked.txt", b"picked\n", "picked");
    let picked = ref_hash(td.path(), "feature");
    assert!(run_in(td.path(), &["checkout", "main"]).status.success());
    let main_before = head_hash(td.path());

    let out = run_in(td.path(), &["cherry-pick", &picked]);
    assert!(out.status.success(), "cherry-pick failed: {out:?}");
    assert_eq!(fs::read(td.path().join("picked.txt")).unwrap(), b"picked\n");
    assert_ne!(head_hash(td.path()), main_before);
}

// ---------- rebase --------------------------------------------------------

#[test]
fn rebase_errors_when_no_rebase_in_progress() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    let out = run_in(td.path(), &["rebase", "--continue"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("no rebase in progress"));
}

#[test]
fn rebase_onto_same_head_is_noop() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "a.txt", b"1\n", "c1");
    // Create a feature branch at HEAD and rebase onto it — nothing to replay.
    assert!(run_in(td.path(), &["branch", "feature"]).status.success());
    let out = run_in(td.path(), &["rebase", "feature"]);
    assert!(out.status.success(), "rebase failed: {out:?}");
    // Confirmation prose lives on stderr.
    let stderr = String::from_utf8(out.stderr).unwrap();
    let lower = stderr.to_lowercase();
    assert!(
        lower.contains("rebased") || lower.contains("up to date"),
        "unexpected rebase output: {stderr}"
    );
}

#[test]
fn rebase_abort_restores_original_branch_ref_and_worktree() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "a.txt", b"base\n", "base");
    assert!(run_in(td.path(), &["branch", "feature"]).status.success());

    assert!(run_in(td.path(), &["checkout", "feature"]).status.success());
    make_commit(td.path(), "a.txt", b"feature\n", "feature change");
    let feature_before = ref_hash(td.path(), "feature");

    assert!(run_in(td.path(), &["checkout", "main"]).status.success());
    make_commit(td.path(), "a.txt", b"main\n", "main change");

    assert!(run_in(td.path(), &["checkout", "feature"]).status.success());
    let rebase = run_in(td.path(), &["rebase", "main"]);
    assert!(!rebase.status.success(), "rebase should pause on conflict");
    assert!(td.path().join(".mkit/rebase-apply").exists());

    let abort = run_in(td.path(), &["rebase", "--abort"]);
    assert!(abort.status.success(), "abort failed: {abort:?}");
    assert_eq!(ref_hash(td.path(), "feature"), feature_before);
    assert_eq!(fs::read(td.path().join("a.txt")).unwrap(), b"feature\n");
    assert!(!td.path().join(".mkit/rebase-apply").exists());
}

// ---------- bisect --------------------------------------------------------

#[test]
fn bisect_errors_on_unknown_subcommand() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    let out = run_in(td.path(), &["bisect", "wat"]);
    assert!(!out.status.success());
}

#[test]
fn bisect_start_creates_state_file() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "a.txt", b"1\n", "c1");
    let out = run_in(td.path(), &["bisect", "start"]);
    assert!(out.status.success(), "bisect start failed: {out:?}");
    assert!(td.path().join(".mkit/bisect").is_file());
    // Clean up so the repo can be dropped cleanly.
    assert!(run_in(td.path(), &["bisect", "reset"]).status.success());
}

#[test]
fn bisect_run_converges_to_first_bad_commit() {
    // #528: `bisect run <cmd>` drives the loop automatically — it checks
    // out each candidate, runs the command, and maps the exit code (0=good,
    // 1-127≠125=bad) until it prints the first bad commit. Bug is introduced
    // at c3 (marker flips to BAD); the run must converge to c3.
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "marker.txt", b"ok\n", "c1");
    let c1 = head_hash(td.path());
    make_commit(td.path(), "marker.txt", b"ok\n", "c2");
    make_commit(td.path(), "marker.txt", b"BAD\n", "c3");
    let c3 = head_hash(td.path());
    make_commit(td.path(), "marker.txt", b"BAD\n", "c4");
    make_commit(td.path(), "marker.txt", b"BAD\n", "c5");
    let c5 = head_hash(td.path());

    assert!(run_in(td.path(), &["bisect", "start"]).status.success());
    assert!(run_in(td.path(), &["bisect", "good", &c1]).status.success());
    assert!(run_in(td.path(), &["bisect", "bad", &c5]).status.success());

    // `! grep -q BAD marker.txt` exits 0 (good) when marker is "ok",
    // 1 (bad) when it is "BAD".
    let out = run_in(
        td.path(),
        &["bisect", "run", "sh", "-c", "! grep -q BAD marker.txt"],
    );
    assert!(out.status.success(), "bisect run failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        stdout.trim(),
        &c3[..12],
        "bisect run must converge to the first bad commit c3: {stdout:?}"
    );
    let _ = run_in(td.path(), &["bisect", "reset"]);
}

#[test]
fn bisect_run_skips_untestable_candidate_and_still_converges() {
    // #528: exit 125 marks a candidate untestable (skip). The bug is at c3;
    // c4 (above the first-bad) is untestable. Skipping c4 is bypassed as the
    // range narrows below it, so the run still converges to c3. (A skip that
    // STRANDED the answer next to `bad` would instead be ambiguous — see
    // `bisect_run_reports_ambiguity_when_all_candidates_skipped`.)
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "marker.txt", b"ok\n", "c1");
    let c1 = head_hash(td.path());
    make_commit(td.path(), "marker.txt", b"ok\n", "c2");
    make_commit(td.path(), "marker.txt", b"BAD\n", "c3");
    let c3 = head_hash(td.path());
    make_commit(td.path(), "marker.txt", b"SKIP\n", "c4");
    make_commit(td.path(), "marker.txt", b"BAD\n", "c5");
    let c5 = head_hash(td.path());

    assert!(run_in(td.path(), &["bisect", "start"]).status.success());
    assert!(run_in(td.path(), &["bisect", "good", &c1]).status.success());
    assert!(run_in(td.path(), &["bisect", "bad", &c5]).status.success());

    // 125 (skip) when marker is SKIP; 1 (bad) when BAD; 0 (good) otherwise.
    let script = "grep -q SKIP marker.txt && exit 125; grep -q BAD marker.txt && exit 1; exit 0";
    let out = run_in(td.path(), &["bisect", "run", "sh", "-c", script]);
    assert!(out.status.success(), "bisect run failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        stdout.trim(),
        &c3[..12],
        "bisect run must bypass the c4 skip and converge to c3: {stdout:?}"
    );
    let _ = run_in(td.path(), &["bisect", "reset"]);
}

#[test]
fn bisect_run_survives_test_command_dirtying_a_tracked_file() {
    // Review #1: the test command modifies a tracked file each iteration
    // (as `cargo test` refreshing Cargo.lock, or a snapshot writer, would).
    // The per-candidate checkout is forced, discarding the scribbles, so the
    // run still converges instead of aborting on the second candidate.
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "marker.txt", b"ok\n", "c1");
    let c1 = head_hash(td.path());
    make_commit(td.path(), "marker.txt", b"ok\n", "c2");
    make_commit(td.path(), "marker.txt", b"BAD\n", "c3");
    let c3 = head_hash(td.path());
    make_commit(td.path(), "marker.txt", b"BAD\n", "c4");
    make_commit(td.path(), "tracked.txt", b"v0\n", "c5-track");
    let c5 = head_hash(td.path());

    assert!(run_in(td.path(), &["bisect", "start"]).status.success());
    assert!(run_in(td.path(), &["bisect", "good", &c1]).status.success());
    assert!(run_in(td.path(), &["bisect", "bad", &c5]).status.success());

    // The command appends to the tracked file, then classifies from marker.
    let script = "echo scribble >> tracked.txt; ! grep -q BAD marker.txt";
    let out = run_in(td.path(), &["bisect", "run", "sh", "-c", script]);
    assert!(
        out.status.success(),
        "bisect run must survive a tracked-file-dirtying command: {out:?}"
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(stdout.trim(), &c3[..12], "converges to c3: {stdout:?}");
    let _ = run_in(td.path(), &["bisect", "reset"]);
}

#[test]
fn bisect_run_reports_ambiguity_when_all_candidates_skipped() {
    // Review #3: when every remaining candidate is skipped, the run must NOT
    // print `bad` as a definitive first-bad — it reports ambiguity (like
    // git) and exits non-zero.
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "marker.txt", b"ok\n", "c1");
    let c1 = head_hash(td.path());
    for c in ["c2", "c3", "c4"] {
        make_commit(td.path(), "marker.txt", b"BAD\n", c);
    }
    let c4 = head_hash(td.path());

    assert!(run_in(td.path(), &["bisect", "start"]).status.success());
    assert!(run_in(td.path(), &["bisect", "good", &c1]).status.success());
    assert!(run_in(td.path(), &["bisect", "bad", &c4]).status.success());

    // Every candidate is untestable (exit 125).
    let out = run_in(td.path(), &["bisect", "run", "sh", "-c", "exit 125"]);
    assert!(
        !out.status.success(),
        "all-skipped run must exit non-zero: {out:?}"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("only skipped commits left"),
        "must report ambiguity like git: {stderr}"
    );
    let _ = run_in(td.path(), &["bisect", "reset"]);
}

// ---------- stash ---------------------------------------------------------

#[test]
fn stash_list_on_empty_repo_prints_none_marker() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    let out = run_in(td.path(), &["stash", "list"]);
    assert!(out.status.success(), "stash list failed: {out:?}");
    // Empty stash listing → empty stdout; the "(no stash entries)"
    // marker is human-readable diagnostic on stderr.
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.is_empty(),
        "empty stash list must produce empty stdout: {stdout:?}"
    );
    // git prints nothing at all for an empty stash list — match that.
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.is_empty(),
        "empty stash list must be silent (git-shaped): {stderr:?}"
    );
}

#[test]
fn stash_show_on_empty_stash_errors_out_of_range() {
    // `stash show` defaults to entry 0; with no stash entries that
    // index is out of range and must fail with GENERAL_ERROR (1) and a
    // diagnostic naming the bad index — not panic, and not exit 0.
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    let out = run_in(td.path(), &["stash", "show"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "empty-stash `stash show` must exit GENERAL_ERROR: {out:?}"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("stash index 0 is out of range"),
        "expected the out-of-range diagnostic, got: {stderr}"
    );
}

// ---------- blame ---------------------------------------------------------

#[test]
fn blame_errors_on_missing_file() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "real.txt", b"x\n", "r1");
    let out = run_in(td.path(), &["blame", "nope.txt"]);
    assert!(!out.status.success());
}

#[test]
fn blame_on_single_commit_attributes_every_line_to_it() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "f.txt", b"one\ntwo\nthree\n", "first");
    let out = run_in(td.path(), &["blame", "f.txt"]);
    assert!(out.status.success(), "blame failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    // Three lines, each with short_hash \t <line_num> \t <text>.
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 3, "expected 3 blame lines, got {stdout:?}");
    assert!(lines[0].ends_with("\tone"));
    assert!(lines[1].ends_with("\ttwo"));
    assert!(lines[2].ends_with("\tthree"));
    // Short hash is 12 hex chars.
    let first_short: &str = lines[0].split('\t').next().unwrap();
    assert_eq!(first_short.len(), 12);
    assert!(first_short.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn blame_l_range_slices_lines_and_keeps_numbering() {
    // `-L <start>,<end>` restricts output to that inclusive range while
    // preserving the file's own 1-based line numbers, matching git.
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "f.txt", b"a\nb\nc\nd\ne\n", "first");
    let out = run_in(td.path(), &["blame", "-L", "2,4", "f.txt"]);
    assert!(out.status.success(), "blame -L failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 3, "expected lines 2..=4, got {stdout:?}");
    // Line numbers are the file's own (2,3,4), not 1,2,3.
    assert!(lines[0].contains("\t2\t") && lines[0].ends_with("\tb"));
    assert!(lines[1].contains("\t3\t") && lines[1].ends_with("\tc"));
    assert!(lines[2].contains("\t4\t") && lines[2].ends_with("\td"));
}

#[test]
fn blame_l_plus_offset_counts_lines() {
    // `-L <start>,+<n>` is n lines starting at <start>: `2,+1` → line 2.
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "f.txt", b"a\nb\nc\n", "first");
    let out = run_in(td.path(), &["blame", "-L", "2,+1", "f.txt"]);
    assert!(out.status.success(), "blame -L +n failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "expected just line 2, got {stdout:?}");
    assert!(lines[0].contains("\t2\t") && lines[0].ends_with("\tb"));
}

#[test]
fn blame_l_minus_offset_counts_lines_ending_at_start() {
    // `-L <start>,-<n>` is n lines *ending* at <start>: `4,-2` → lines 3,4.
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "f.txt", b"a\nb\nc\nd\ne\n", "first");
    let out = run_in(td.path(), &["blame", "-L", "4,-2", "f.txt"]);
    assert!(out.status.success(), "blame -L -n failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "expected lines 3,4, got {stdout:?}");
    assert!(lines[0].contains("\t3\t") && lines[0].ends_with("\tc"));
    assert!(lines[1].contains("\t4\t") && lines[1].ends_with("\td"));
}

#[test]
fn blame_l_start_past_eof_is_usage_error() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "f.txt", b"a\nb\n", "first");
    let out = run_in(td.path(), &["blame", "-L", "9,10", "f.txt"]);
    assert!(!out.status.success(), "expected failure on out-of-range -L");
    let stderr = String::from_utf8(out.stderr).unwrap();
    // git-faithful, colon-free phrasing: `file f.txt has only 2 lines`.
    assert!(
        stderr.contains("file f.txt has only 2 lines"),
        "expected git-faithful line-count diagnostic, got: {stderr}"
    );
}

#[test]
fn blame_l_zero_line_number_errors_without_panicking() {
    // Regression: `-L ,0` once panicked (exit 101) via an inverted-range
    // swap that produced line 0. It must be a clean usage error instead.
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "f.txt", b"a\nb\nc\n", "first");
    let out = run_in(td.path(), &["blame", "-L", ",0", "f.txt"]);
    assert!(!out.status.success(), "expected failure on -L ,0");
    assert_ne!(
        out.status.code(),
        Some(101),
        "must not panic; got a 101 exit"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("-L invalid line number: 0"),
        "expected git-exact zero-line diagnostic, got: {stderr}"
    );
    // A negative start must reach the parser (allow_hyphen_values), not be
    // intercepted by clap as an unknown flag — git reports it by token.
    let neg = run_in(td.path(), &["blame", "-L", "-3,5", "f.txt"]);
    assert!(!neg.status.success());
    assert!(
        String::from_utf8(neg.stderr)
            .unwrap()
            .contains("-L invalid line number: -3"),
        "negative start should yield the git-exact diagnostic"
    );
}

#[test]
fn blame_at_explicit_revision_uses_that_commit() {
    // `mkit blame <rev> <file>` blames the file as of <rev>, not HEAD.
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "f.txt", b"a\nb\nc\n", "first");
    let first = head_hash(td.path());
    make_commit(td.path(), "f.txt", b"a\nMOD\nc\n", "second");

    // At HEAD, line 2 is attributed to the second commit.
    let head = run_in(td.path(), &["blame", "f.txt"]);
    let head_out = String::from_utf8(head.stdout).unwrap();
    assert!(head_out.lines().nth(1).unwrap().ends_with("\tMOD"));

    // At the first commit, the file is the original three lines, all
    // attributed to `first`.
    let out = run_in(td.path(), &["blame", &first, "f.txt"]);
    assert!(out.status.success(), "blame <rev> failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 3);
    assert!(
        lines[1].ends_with("\tb"),
        "expected pre-MOD content: {stdout:?}"
    );
    let short = &first[..12];
    assert!(
        lines.iter().all(|l| l.starts_with(short)),
        "every line should be attributed to the first commit: {stdout:?}"
    );
}

#[test]
fn blame_unknown_revision_errors() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "f.txt", b"a\n", "first");
    let out = run_in(td.path(), &["blame", "no-such-rev", "f.txt"]);
    assert!(
        !out.status.success(),
        "expected failure on unknown revision"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("unknown revision"),
        "expected unknown-revision diagnostic, got: {stderr}"
    );
}

#[test]
fn blame_w_ignores_whitespace_only_change() {
    // A whitespace-only edit reattributes the line by default, but `-w`
    // keeps the original commit while still printing the current bytes.
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "f.txt", b"foo(a, b)\n", "first");
    let first = head_hash(td.path());
    make_commit(td.path(), "f.txt", b"foo(a,b)\n", "reformat");
    let second = head_hash(td.path());

    // Default: the reformat commit owns the line.
    let plain = run_in(td.path(), &["blame", "f.txt"]);
    let plain_out = String::from_utf8(plain.stdout).unwrap();
    assert!(
        plain_out.starts_with(&second[..12]),
        "default blame should attribute to the reformat commit: {plain_out:?}"
    );

    // -w: the original commit owns it, output shows the current bytes.
    let out = run_in(td.path(), &["blame", "-w", "f.txt"]);
    assert!(out.status.success(), "blame -w failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.starts_with(&first[..12]),
        "-w should keep the original commit: {stdout:?}"
    );
    assert!(
        stdout.trim_end().ends_with("\tfoo(a,b)"),
        "-w output should still show current bytes: {stdout:?}"
    );
}

#[test]
fn blame_m_attributes_within_file_move() {
    // A long line (over the 20-char -M threshold) moved to the end of the
    // file is credited to its original commit under -M.
    let long = "let quick_brown_fox_total = 1;";
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(
        td.path(),
        "f.txt",
        format!("{long}\nB\nC\n").as_bytes(),
        "first",
    );
    let first = head_hash(td.path());
    make_commit(
        td.path(),
        "f.txt",
        format!("B\nC\n{long}\n").as_bytes(),
        "shuffle",
    );
    let second = head_hash(td.path());

    let plain = run_in(td.path(), &["blame", "f.txt"]);
    let plain_out = String::from_utf8(plain.stdout).unwrap();
    let plain_line = plain_out.lines().find(|l| l.ends_with(long)).unwrap();
    assert!(
        plain_line.starts_with(&second[..12]),
        "default: moved line is new: {plain_out:?}"
    );

    let out = run_in(td.path(), &["blame", "-M", "f.txt"]);
    assert!(out.status.success(), "blame -M failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let line = stdout.lines().find(|l| l.ends_with(long)).unwrap();
    assert!(
        line.starts_with(&first[..12]),
        "-M credits the moved line to its origin: {stdout:?}"
    );
}

#[test]
fn blame_m_merge_credits_move_from_second_parent() {
    // A long line lives only on the SECOND merge parent (feature); the merge
    // resolution moves it to the file's end, so neither parent's matcher
    // explains it in place. `git blame -M` credits the moved line to the
    // feature commit, NOT the merge — the detector must run against the
    // second parent. (Pinned against real `git blame -M`, git 2.50.1.)
    let long = "let quick_brown_fox_total = 1;";
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "f.txt", b"HEAD\nX\nY\n", "base");
    assert!(run_in(td.path(), &["branch", "feature"]).status.success());

    // First parent (main): a conflicting edit to line 1, no long line.
    make_commit(td.path(), "f.txt", b"MAIN\nX\nY\n", "p1edit");

    // Second parent (feature): writes the long line at the top.
    assert!(run_in(td.path(), &["checkout", "feature"]).status.success());
    make_commit(
        td.path(),
        "f.txt",
        format!("{long}\nX\nY\n").as_bytes(),
        "feature writes long",
    );
    let feature = ref_hash(td.path(), "feature");

    // Merge conflicts on line 1; resolve by moving the long line to the end.
    assert!(run_in(td.path(), &["checkout", "main"]).status.success());
    let merge = run_in(td.path(), &["merge", "feature"]);
    assert!(!merge.status.success(), "merge should conflict: {merge:?}");
    fs::write(td.path().join("f.txt"), format!("X\nY\n{long}\n")).unwrap();
    assert!(run_in(td.path(), &["add", "f.txt"]).status.success());
    let cont = run_in(td.path(), &["merge", "--continue"]);
    assert!(cont.status.success(), "merge --continue failed: {cont:?}");

    let out = run_in(td.path(), &["blame", "-M", "f.txt"]);
    assert!(out.status.success(), "blame -M failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let line = stdout.lines().find(|l| l.ends_with(long)).unwrap();
    assert!(
        line.starts_with(&feature[..12]),
        "-M credits the move to the 2nd-parent (feature) origin, not the merge: {stdout:?}"
    );
}

#[test]
fn blame_c_merge_conflict_edit_keeps_copy_tie_on_merge() {
    // End-to-end `-C` at a conflicted merge: the SAME copyable block is
    // added as a new file on BOTH merge sides (main's s1.txt, feature's
    // s2.txt) while f.txt itself CONFLICTS (edited on both sides) and is
    // resolved by appending the block. Because f.txt differs on the two
    // parents, BOTH keep their porigins — neither is deduped into the
    // whole-tree search — and s1.txt/s2.txt are unchanged at the merge, so
    // they are invisible to the modified-files channel: the block stays on
    // the MERGE, and the resolved "MAIN" line is credited to main's edit.
    // Pinned against real git 2.50.1 (contrast with mkit-core's
    // `blame_c_merge_copy_tie_prefers_deduped_second_parent`, where the
    // blamed file is UNCHANGED on both sides, the second parent's porigin
    // is deduped, and its whole tree — including the source — is
    // searched). This proves the porigin mechanism end-to-end through
    // `mkit merge --continue` and the real CLI `blame -C -C` path.
    let b1 = "fn handler_alpha() { compute(); }";
    let b2 = "fn handler_bravo() { compute(); }";
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "f.txt", b"TOP\n", "base");
    assert!(run_in(td.path(), &["branch", "feature"]).status.success());

    // First parent (main): conflicting edit to f.txt, plus its OWN copy of
    // the block in s1.txt.
    fs::write(td.path().join("f.txt"), b"MAIN\n").unwrap();
    fs::write(td.path().join("s1.txt"), format!("{b1}\n{b2}\n")).unwrap();
    assert!(
        run_in(td.path(), &["add", "f.txt", "s1.txt"])
            .status
            .success()
    );
    assert!(
        run_in(td.path(), &["commit", "-m", "main edit + s1"])
            .status
            .success()
    );

    // Second parent (feature): a different conflicting edit to f.txt, plus
    // the SAME block duplicated in s2.txt (the tie).
    assert!(run_in(td.path(), &["checkout", "feature"]).status.success());
    fs::write(td.path().join("f.txt"), b"FEAT\n").unwrap();
    fs::write(td.path().join("s2.txt"), format!("{b1}\n{b2}\n")).unwrap();
    assert!(
        run_in(td.path(), &["add", "f.txt", "s2.txt"])
            .status
            .success()
    );
    assert!(
        run_in(td.path(), &["commit", "-m", "feature edit + s2"])
            .status
            .success()
    );
    let feature = ref_hash(td.path(), "feature");

    // Merge conflicts on f.txt; resolve by keeping main's line and
    // appending the block (present verbatim on both sides' new files).
    assert!(run_in(td.path(), &["checkout", "main"]).status.success());
    let merge = run_in(td.path(), &["merge", "feature"]);
    assert!(!merge.status.success(), "merge should conflict: {merge:?}");
    fs::write(td.path().join("f.txt"), format!("MAIN\n{b1}\n{b2}\n")).unwrap();
    assert!(run_in(td.path(), &["add", "f.txt"]).status.success());
    let cont = run_in(td.path(), &["merge", "--continue"]);
    assert!(cont.status.success(), "merge --continue failed: {cont:?}");
    let merge_hash = head_hash(td.path());

    let out = run_in(td.path(), &["blame", "-C", "-C", "f.txt"]);
    assert!(out.status.success(), "blame -C -C failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(
        lines[1].starts_with(&merge_hash[..12]) && lines[2].starts_with(&merge_hash[..12]),
        "both parents keep their porigins (f.txt conflicted), so the \
         unchanged sources are invisible and the block stays on the merge \
         (git parity): {stdout:?}"
    );
    assert!(
        lines.iter().all(|l| !l.starts_with(&feature[..12])),
        "the second parent's unchanged s2.txt must not be credited: {stdout:?}"
    );
}

#[test]
fn blame_ignore_rev_merge_falls_through_to_second_parent() {
    // An ignored merge resolves a modify/delete conflict by keeping a noise
    // version of the feature line. The first parent (main) DELETED that line,
    // so the fall-through must cross to the SECOND parent (feature) that wrote
    // the content. `blame --ignore-rev <merge>` credits feature, not the
    // merge. (Pinned against real `git blame --ignore-rev`, git 2.50.1.)
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "f.txt", b"TOP\nMID\nBOT\n", "base");
    assert!(run_in(td.path(), &["branch", "feature"]).status.success());

    // First parent (main): deletes MID.
    make_commit(td.path(), "f.txt", b"TOP\nBOT\n", "p1 deletes mid");

    // Second parent (feature): rewrites MID to real content.
    assert!(run_in(td.path(), &["checkout", "feature"]).status.success());
    make_commit(
        td.path(),
        "f.txt",
        b"TOP\nREAL_CONTENT_OF_B_LINE\nBOT\n",
        "feature rewrites mid",
    );
    let feature = ref_hash(td.path(), "feature");

    // Merge conflicts (modify/delete); resolve to a noise version of the line.
    assert!(run_in(td.path(), &["checkout", "main"]).status.success());
    let merge = run_in(td.path(), &["merge", "feature"]);
    assert!(!merge.status.success(), "merge should conflict: {merge:?}");
    fs::write(
        td.path().join("f.txt"),
        b"TOP\n  REAL_CONTENT_OF_B_LINE  X\nBOT\n",
    )
    .unwrap();
    assert!(run_in(td.path(), &["add", "f.txt"]).status.success());
    let cont = run_in(td.path(), &["merge", "--continue"]);
    assert!(cont.status.success(), "merge --continue failed: {cont:?}");
    let merge_hash = head_hash(td.path());

    let out = run_in(td.path(), &["blame", "--ignore-rev", &merge_hash, "f.txt"]);
    assert!(out.status.success(), "blame --ignore-rev failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(
        lines[1].starts_with(&feature[..12]),
        "ignored merge falls through across to the 2nd parent (feature): {stdout:?}"
    );
    assert!(
        lines.iter().all(|l| !l.starts_with(&merge_hash[..12])),
        "no line is credited to the ignored merge: {stdout:?}"
    );
}

#[test]
fn blame_ignore_rev_falls_through_to_prior_commit() {
    // `--ignore-rev <reformat>` skips the noise commit: line 2's blame
    // falls through to the commit that previously changed it, while the
    // output still shows the reformatted bytes. Mirrors real
    // `git blame --ignore-rev`.
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "f.txt", b"alpha\nbeta\ngamma\n", "first");
    let first = head_hash(td.path());
    make_commit(td.path(), "f.txt", b"alpha\n  beta  \ngamma\n", "reformat");
    let reformat = head_hash(td.path());

    // Default: the reformat commit owns line 2.
    let plain = run_in(td.path(), &["blame", "f.txt"]);
    let plain_out = String::from_utf8(plain.stdout).unwrap();
    assert!(
        plain_out
            .lines()
            .nth(1)
            .unwrap()
            .starts_with(&reformat[..12])
    );

    let out = run_in(td.path(), &["blame", "--ignore-rev", &reformat, "f.txt"]);
    assert!(out.status.success(), "blame --ignore-rev failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(
        lines[1].starts_with(&first[..12]),
        "ignored reformat falls through to the first commit: {stdout:?}"
    );
    assert!(
        lines[1].ends_with("\t  beta  "),
        "output still shows the reformatted bytes: {stdout:?}"
    );
    assert!(
        lines.iter().all(|l| !l.starts_with(&reformat[..12])),
        "no line is credited to the ignored commit: {stdout:?}"
    );
}

#[test]
fn blame_c_attributes_copy_from_other_file() {
    // A block (over the 40-char -C threshold) is moved from a.txt into a
    // new b.txt; both files change in the commit, so -C (level 1) credits
    // b.txt's lines to the original commit.
    let b1 = "fn handler_alpha() { compute(); }";
    let b2 = "fn handler_bravo() { compute(); }";
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(
        td.path(),
        "a.txt",
        format!("{b1}\n{b2}\nzzz\n").as_bytes(),
        "first",
    );
    let first = head_hash(td.path());

    // Second commit: shrink a.txt and add b.txt with the block.
    fs::write(td.path().join("a.txt"), b"zzz\n").unwrap();
    fs::write(td.path().join("b.txt"), format!("{b1}\n{b2}\n")).unwrap();
    assert!(
        run_in(td.path(), &["add", "a.txt", "b.txt"])
            .status
            .success()
    );
    assert!(
        run_in(td.path(), &["commit", "-m", "split"])
            .status
            .success()
    );
    let second = head_hash(td.path());

    let plain = run_in(td.path(), &["blame", "b.txt"]);
    let plain_out = String::from_utf8(plain.stdout).unwrap();
    assert!(
        plain_out.lines().all(|l| l.starts_with(&second[..12])),
        "default: copied block is new: {plain_out:?}"
    );

    let out = run_in(td.path(), &["blame", "-C", "b.txt"]);
    assert!(out.status.success(), "blame -C failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.lines().all(|l| l.starts_with(&first[..12])),
        "-C credits the copied block to its origin commit: {stdout:?}"
    );
}

#[test]
fn blame_ignore_revs_file_skips_listed_commits() {
    // `--ignore-revs-file` reads full hex object names, skipping blank
    // lines and `#` comments (including inline) — verified against git.
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "f.txt", b"alpha\nbeta\n", "first");
    let first = head_hash(td.path());
    make_commit(td.path(), "f.txt", b"alpha\n  beta  \n", "reformat");
    let reformat = head_hash(td.path());

    let revs = format!("# noise commits\n\n{reformat}  # the reformat\n");
    fs::write(td.path().join("revs.txt"), revs).unwrap();
    let out = run_in(
        td.path(),
        &["blame", "--ignore-revs-file", "revs.txt", "f.txt"],
    );
    assert!(
        out.status.success(),
        "blame --ignore-revs-file failed: {out:?}"
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.lines().nth(1).unwrap().starts_with(&first[..12]),
        "listed reformat is skipped; line 2 falls through: {stdout:?}"
    );
}

#[test]
fn blame_c_c_widens_to_unchanged_source_file() {
    // `-C -C` (level 2) end-to-end: dst.txt copies a block from src.txt,
    // which is NOT modified in the copying commit. Level 1 misses it;
    // level 2 searches every parent file and credits the original commit.
    let b1 = "fn handler_alpha() { compute(); }";
    let b2 = "fn handler_bravo() { compute(); }";
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(
        td.path(),
        "src.txt",
        format!("{b1}\n{b2}\n").as_bytes(),
        "first",
    );
    let first = head_hash(td.path());

    // src.txt unchanged; dst.txt added with the same block.
    fs::write(td.path().join("dst.txt"), format!("{b1}\n{b2}\n")).unwrap();
    assert!(run_in(td.path(), &["add", "dst.txt"]).status.success());
    assert!(
        run_in(td.path(), &["commit", "-m", "copy"])
            .status
            .success()
    );
    let second = head_hash(td.path());

    // -C (level 1) ignores the unchanged source.
    let l1 = run_in(td.path(), &["blame", "-C", "dst.txt"]);
    let l1_out = String::from_utf8(l1.stdout).unwrap();
    assert!(
        l1_out.lines().all(|l| l.starts_with(&second[..12])),
        "-C level 1 misses the unchanged source: {l1_out:?}"
    );

    // -C -C (level 2) finds it.
    let l2 = run_in(td.path(), &["blame", "-C", "-C", "dst.txt"]);
    assert!(l2.status.success(), "blame -C -C failed: {l2:?}");
    let l2_out = String::from_utf8(l2.stdout).unwrap();
    assert!(
        l2_out.lines().all(|l| l.starts_with(&first[..12])),
        "-C -C credits the copied block to its origin: {l2_out:?}"
    );
}

#[test]
fn blame_ignore_rev_unknown_errors_like_git() {
    // git: `fatal: cannot find revision <rev> to ignore`. mkit matches the
    // text (with its own `error:` prefix and sysexits code, not git's 128).
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "f.txt", b"a\n", "first");
    let out = run_in(
        td.path(),
        &["blame", "--ignore-rev", "no-such-rev", "f.txt"],
    );
    assert!(
        !out.status.success(),
        "expected failure on unknown ignore-rev"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("cannot find revision no-such-rev to ignore"),
        "expected git-faithful ignore-rev diagnostic, got: {stderr}"
    );
}

#[test]
fn blame_ignore_revs_file_errors_are_git_faithful() {
    // A missing file and a malformed entry reproduce git's two messages.
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "f.txt", b"a\n", "first");

    let missing = run_in(
        td.path(),
        &["blame", "--ignore-revs-file", "nope.txt", "f.txt"],
    );
    assert!(!missing.status.success());
    assert!(
        String::from_utf8(missing.stderr)
            .unwrap()
            .contains("could not open object name list: nope.txt"),
        "expected git-faithful missing-file diagnostic"
    );

    fs::write(td.path().join("bad.txt"), "zzznothex\n").unwrap();
    let bad = run_in(
        td.path(),
        &["blame", "--ignore-revs-file", "bad.txt", "f.txt"],
    );
    assert!(!bad.status.success());
    assert!(
        String::from_utf8(bad.stderr)
            .unwrap()
            .contains("invalid object name: zzznothex"),
        "expected git-faithful invalid-object-name diagnostic"
    );
}

#[test]
fn blame_reverse_attributes_lines_to_last_surviving_commit() {
    // `--reverse <start>..<end>` blames the start version and attributes
    // each line to the last commit it survived in. Mirrors real
    // `git blame --reverse` (verified field-by-field).
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "f.txt", b"keep\ndoomed\nalso\n", "c1");
    let c1 = head_hash(td.path());
    make_commit(td.path(), "f.txt", b"keep\ndoomed\nalso\nextra\n", "c2");
    let c2 = head_hash(td.path());
    make_commit(
        td.path(),
        "f.txt",
        b"keep\nalso\nextra\n",
        "c3_removes_doomed",
    );
    make_commit(td.path(), "f.txt", b"keep\nalso\nextra2\n", "c4");
    let c4 = head_hash(td.path());

    let out = run_in(
        td.path(),
        &["blame", "--reverse", &format!("{c1}..{c4}"), "f.txt"],
    );
    assert!(out.status.success(), "blame --reverse failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 3, "blames the start (c1) version: {stdout:?}");
    assert!(lines[0].starts_with(&c4[..12]) && lines[0].ends_with("\tkeep"));
    assert!(
        lines[1].starts_with(&c2[..12]) && lines[1].ends_with("\tdoomed"),
        "doomed last existed in c2: {stdout:?}"
    );
    assert!(lines[2].starts_with(&c4[..12]) && lines[2].ends_with("\talso"));
}

#[test]
fn blame_reverse_open_end_defaults_to_head() {
    // `<start>..` defaults <end> to HEAD.
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "f.txt", b"a\nb\n", "c1");
    let c1 = head_hash(td.path());
    make_commit(td.path(), "f.txt", b"a\nB2\n", "c2");
    let c2 = head_hash(td.path());

    let out = run_in(
        td.path(),
        &["blame", "--reverse", &format!("{c1}.."), "f.txt"],
    );
    assert!(out.status.success(), "open-end reverse failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    // `a` survives to HEAD (c2); `b` is changed in c2 → last in c1.
    assert!(
        lines[0].starts_with(&c2[..12]),
        "a survives to HEAD: {stdout:?}"
    );
    assert!(
        lines[1].starts_with(&c1[..12]),
        "b last existed in c1: {stdout:?}"
    );
}

#[test]
fn blame_reverse_requires_a_range() {
    // Clear, non-cryptic errors (a deliberate divergence from git's
    // "dig up from" phrasing) for the three malformed-argument cases.
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "f.txt", b"a\n", "c1");
    let c1 = head_hash(td.path());

    // No range at all.
    let none = run_in(td.path(), &["blame", "--reverse", "f.txt"]);
    assert!(!none.status.success());
    assert!(
        String::from_utf8(none.stderr)
            .unwrap()
            .contains("requires a <start>..<end>"),
        "expected a clear missing-range error"
    );
    // A bare revision (no `..`).
    let bare = run_in(td.path(), &["blame", "--reverse", &c1, "f.txt"]);
    assert!(!bare.status.success());
    assert!(
        String::from_utf8(bare.stderr)
            .unwrap()
            .contains("<start>..<end>"),
        "expected a clear bare-revision error"
    );
    // An open start.
    let open = run_in(
        td.path(),
        &["blame", "--reverse", &format!("..{c1}"), "f.txt"],
    );
    assert!(!open.status.success());
    assert!(
        String::from_utf8(open.stderr)
            .unwrap()
            .contains("explicit <start>"),
        "expected a clear open-start error"
    );
}

#[test]
fn blame_reverse_rejects_malformed_and_empty_ranges() {
    // Review: triple-dot / extra-dot, an omitted file, and an empty range
    // each get a clear error instead of a cryptic revspec failure or a
    // silent success.
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "f.txt", b"a\n", "c1");
    let c1 = head_hash(td.path());
    make_commit(td.path(), "f.txt", b"a\nb\n", "c2");
    let c2 = head_hash(td.path());

    // Triple-dot (git's symmetric range) is not supported.
    let triple = run_in(
        td.path(),
        &["blame", "--reverse", &format!("{c1}...{c2}"), "f.txt"],
    );
    assert!(!triple.status.success());
    assert!(
        String::from_utf8(triple.stderr)
            .unwrap()
            .contains("single <start>..<end>"),
        "expected a clear triple-dot error"
    );
    // Extra `..` (a..b..c).
    let extra = run_in(
        td.path(),
        &["blame", "--reverse", &format!("{c1}..{c2}..{c1}"), "f.txt"],
    );
    assert!(!extra.status.success());
    assert!(
        String::from_utf8(extra.stderr)
            .unwrap()
            .contains("single <start>..<end>"),
        "expected a clear extra-dot error"
    );
    // File omitted: the lone `a..b` positional is swallowed as the filename.
    let no_file = run_in(td.path(), &["blame", "--reverse", &format!("{c1}..{c2}")]);
    assert!(!no_file.status.success());
    assert!(
        String::from_utf8(no_file.stderr)
            .unwrap()
            .contains("missing <file>"),
        "expected a missing-file hint, not a bogus range error"
    );
    // Empty range (start == end) is rejected, matching git.
    let empty = run_in(
        td.path(),
        &["blame", "--reverse", &format!("{c1}..{c1}"), "f.txt"],
    );
    assert!(!empty.status.success());
    assert!(
        String::from_utf8(empty.stderr)
            .unwrap()
            .contains("empty revision range"),
        "expected an empty-range error"
    );
}

#[test]
fn blame_reverse_rejects_detection_flags() {
    // `--reverse` resolves survival via the LCS matcher only, so combining
    // it with -M/-C or --ignore-rev is rejected rather than silently
    // ignored.
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "f.txt", b"a\n", "c1");
    let c1 = head_hash(td.path());
    let range = format!("{c1}..");

    for flag in [vec!["-M"], vec!["-C"], vec!["--ignore-rev", &c1]] {
        let mut args = vec!["blame", "--reverse", &range, "f.txt"];
        args.extend(flag.iter().copied());
        let out = run_in(td.path(), &args);
        assert!(
            !out.status.success(),
            "expected --reverse + {flag:?} to be rejected"
        );
        assert!(
            String::from_utf8(out.stderr)
                .unwrap()
                .contains("--reverse cannot be combined"),
            "expected a clear combination error for {flag:?}"
        );
    }
}

#[test]
fn blame_merge_aware_vs_first_parent() {
    // base → {main adds a top line, feature appends a line} → merge.
    // Default blame credits the appended line to the feature commit
    // (merge-aware); --first-parent credits it to the merge. Verified
    // against real `git blame` / `git blame --first-parent`.
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "f.txt", b"base1\nbase2\n", "base");
    assert!(run_in(td.path(), &["branch", "feature"]).status.success());
    assert!(run_in(td.path(), &["checkout", "feature"]).status.success());
    make_commit(td.path(), "f.txt", b"base1\nbase2\nfeature-line\n", "feat");
    let feat = ref_hash(td.path(), "feature"); // we are on `feature` here
    assert!(run_in(td.path(), &["checkout", "main"]).status.success());
    make_commit(td.path(), "f.txt", b"main-line\nbase1\nbase2\n", "main");
    let merge_out = run_in(td.path(), &["merge", "feature"]);
    assert!(merge_out.status.success(), "merge failed: {merge_out:?}");
    let merge = head_hash(td.path());

    // Default (merge-aware): the feature line traces to the feature commit.
    let def = run_in(td.path(), &["blame", "f.txt"]);
    assert!(def.status.success(), "blame failed: {def:?}");
    let dout = String::from_utf8(def.stdout).unwrap();
    let dlines: Vec<&str> = dout.lines().collect();
    assert_eq!(dlines.len(), 4, "merged file has 4 lines: {dout:?}");
    assert!(
        dlines[3].starts_with(&feat[..12]) && dlines[3].ends_with("\tfeature-line"),
        "default credits the feature line to the feature commit: {dout:?}"
    );
    assert!(
        dlines.iter().all(|l| !l.starts_with(&merge[..12])),
        "no line is credited to the merge under merge-aware blame: {dout:?}"
    );

    // --first-parent: the feature line first appears (to that walk) at the
    // merge, so it is credited there.
    let fp = run_in(td.path(), &["blame", "--first-parent", "f.txt"]);
    assert!(fp.status.success(), "blame --first-parent failed: {fp:?}");
    let fout = String::from_utf8(fp.stdout).unwrap();
    let flines: Vec<&str> = fout.lines().collect();
    assert!(
        flines[3].starts_with(&merge[..12]),
        "--first-parent credits the feature line to the merge: {fout:?}"
    );
}

// ---------- serve ---------------------------------------------------------

#[test]
fn serve_errors_on_missing_path() {
    // `mkit serve` without a path should fail with a usage error.
    // Clap renders "Usage:" (capital U) in its error output; match
    // case-insensitively so the test isn't tied to clap's exact
    // formatting.
    let td = tempfile::tempdir().unwrap();
    let out = run_in(td.path(), &["serve"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.to_lowercase().contains("usage"),
        "expected usage diagnostic on stderr, got: {stderr}"
    );
}

#[test]
fn serve_rejects_bad_handshake_and_exits() {
    use std::io::Write;
    use std::process::Stdio;

    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());

    let mut child = Command::new(mkit_bin())
        .args(["serve", td.path().to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn serve");

    // Send a single frame with the wrong opcode (should be OP_HELLO = 0x00).
    // Frame = [op=0x01][len=0u32].
    let frame = [0x01, 0, 0, 0, 0];
    child.stdin.as_mut().unwrap().write_all(&frame).unwrap();
    drop(child.stdin.take());
    let out = child.wait_with_output().expect("wait serve");
    // The server rejects the bad handshake and exits with the specific
    // PROTOCOL_ERROR code (76) — not a panic (101), not a generic 1.
    assert_eq!(
        out.status.code(),
        Some(76),
        "serve must exit PROTOCOL_ERROR (76) on a bad handshake: {out:?}"
    );
}

// ---------- sparse-checkout ----------------------------------------------

#[test]
fn sparse_checkout_set_without_patterns_errors() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    let out = run_in(td.path(), &["sparse-checkout", "set"]);
    assert!(!out.status.success());
}

#[test]
fn sparse_checkout_roundtrips_patterns() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "a.txt", b"x\n", "c1");
    assert!(
        run_in(td.path(), &["sparse-checkout", "set", "a.txt"])
            .status
            .success()
    );
    let out = run_in(td.path(), &["sparse-checkout", "list"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("a.txt"));
    assert!(
        run_in(td.path(), &["sparse-checkout", "disable"])
            .status
            .success()
    );
}

#[test]
fn sparse_checkout_set_refuses_dirty_tracked_file_inside_sparse_set() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "a.txt", b"v1\n", "c1");

    fs::write(td.path().join("a.txt"), b"local edit\n").unwrap();
    let out = run_in(td.path(), &["sparse-checkout", "set", "a.txt"]);

    assert!(!out.status.success(), "sparse set should fail: {out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("restore would overwrite local changes"));
    assert_eq!(fs::read(td.path().join("a.txt")).unwrap(), b"local edit\n");
    assert!(!td.path().join(".mkit/sparse-checkout").exists());
}

#[test]
fn sparse_checkout_set_allows_dirty_tracked_file_outside_sparse_set() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    fs::write(td.path().join("a.txt"), b"a\n").unwrap();
    fs::write(td.path().join("b.txt"), b"b\n").unwrap();
    assert!(run_in(td.path(), &["add", "."]).status.success());
    assert!(run_in(td.path(), &["commit", "-m", "c1"]).status.success());

    fs::write(td.path().join("b.txt"), b"local b\n").unwrap();
    let out = run_in(td.path(), &["sparse-checkout", "set", "a.txt"]);

    assert!(out.status.success(), "sparse set failed: {out:?}");
    assert_eq!(fs::read(td.path().join("b.txt")).unwrap(), b"local b\n");
    assert_eq!(
        fs::read_to_string(td.path().join(".mkit/sparse-checkout")).unwrap(),
        "a.txt\n"
    );
}

#[test]
fn sparse_checkout_disable_refuses_untracked_file_that_full_restore_would_remove() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "a.txt", b"a\n", "c1");
    assert!(
        run_in(td.path(), &["sparse-checkout", "set", "a.txt"])
            .status
            .success()
    );

    fs::write(td.path().join("notes.txt"), b"local notes\n").unwrap();
    let out = run_in(td.path(), &["sparse-checkout", "disable"]);

    assert!(!out.status.success(), "sparse disable should fail: {out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("restore would remove untracked path"));
    assert_eq!(
        fs::read(td.path().join("notes.txt")).unwrap(),
        b"local notes\n"
    );
    assert_eq!(
        fs::read_to_string(td.path().join(".mkit/sparse-checkout")).unwrap(),
        "a.txt\n"
    );
}

// ---------- diff (revision resolver, #207) -------------------------------

#[test]
fn diff_head_tilde_one_shows_second_commit_change() {
    // PR-B / #207: `mkit diff HEAD~1` must resolve the revision to its
    // tree and emit a real diff against the worktree (which mirrors the
    // tip), NOT silently treat `HEAD~1` as a pathspec and exit empty.
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "a.txt", b"one\n", "c1");
    make_commit(td.path(), "b.txt", b"two\n", "c2");

    let out = run_in(td.path(), &["diff", "HEAD~1"]);
    assert!(out.status.success(), "diff HEAD~1 failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    // The worktree (== HEAD == c2) differs from HEAD~1 (== c1) by b.txt.
    assert!(
        stdout.contains("b.txt"),
        "expected b.txt in diff HEAD~1 output, got: {stdout:?}"
    );
}

#[test]
fn diff_branch_ref_resolves_and_diffs() {
    // `mkit diff <branch>` resolves the branch tip to its tree.
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "a.txt", b"one\n", "c1");
    assert!(run_in(td.path(), &["branch", "base"]).status.success());
    make_commit(td.path(), "b.txt", b"two\n", "c2");

    let out = run_in(td.path(), &["diff", "base"]);
    assert!(out.status.success(), "diff base failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("b.txt"),
        "expected b.txt in diff base output, got: {stdout:?}"
    );
}

#[test]
fn diff_bad_revision_errors_not_silent_empty() {
    // A hash-shaped arg that resolves to nothing is a hard error (#207),
    // not a silent empty diff.
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "a.txt", b"one\n", "c1");

    let bogus = "ab".repeat(32);
    let out = run_in(td.path(), &["diff", &bogus]);
    assert!(!out.status.success(), "bad revision should fail: {out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.to_lowercase().contains("revision"),
        "expected a revision diagnostic, got: {stderr}"
    );
}

#[test]
fn diff_staged_with_revision_is_usage_error() {
    // #223: `--staged` already fixes HEAD vs index; an explicit revision
    // is contradictory.
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "a.txt", b"one\n", "c1");

    let out = run_in(td.path(), &["diff", "--staged", "HEAD"]);
    assert!(!out.status.success(), "--staged HEAD should fail: {out:?}");
}

// ---------- branch / tag ref-write safety (#206) -------------------------

#[test]
fn branch_create_collision_is_rejected() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "a.txt", b"one\n", "c1");
    assert!(run_in(td.path(), &["branch", "feature"]).status.success());

    let out = run_in(td.path(), &["branch", "feature"]);
    assert!(
        !out.status.success(),
        "duplicate branch should fail: {out:?}"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("already exists"),
        "expected collision diagnostic, got: {stderr}"
    );
}

#[test]
fn branch_delete_current_is_rejected() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "a.txt", b"one\n", "c1");
    // HEAD points at `main`; deleting it must be refused.
    let out = run_in(td.path(), &["branch", "-d", "main"]);
    assert!(
        !out.status.success(),
        "deleting current branch should fail: {out:?}"
    );
}

#[test]
fn tag_create_collision_is_rejected() {
    let td = tempfile::tempdir().unwrap();
    init_repo(td.path());
    make_commit(td.path(), "a.txt", b"one\n", "c1");
    assert!(run_in(td.path(), &["tag", "v1"]).status.success());

    let out = run_in(td.path(), &["tag", "v1"]);
    assert!(!out.status.success(), "duplicate tag should fail: {out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("already exists"),
        "expected collision diagnostic, got: {stderr}"
    );
}
