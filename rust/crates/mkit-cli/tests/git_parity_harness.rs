//! Differential git-parity harness (Phase -1, #247 — umbrella #246).
//!
//! Runs the same script under real `git` and under `mkit`, normalizes the
//! output **modulo object-id length** (git's 40-hex SHA-1 vs mkit's 64-hex
//! BLAKE3), and asserts the in-matrix parity contract from `docs/PARITY.md`.
//!
//! Conventions:
//! - Each VCS gets its own repo dir under one canonicalized temp root
//!   (canonicalized so the macOS `/var → /private/var` symlink does not trip
//!   mkit's worktree hashing during signed commits).
//! - All global/system config is neutralized so the host environment cannot
//!   leak in; git identity is pinned via `GIT_*` env vars.
//! - Differential cases early-return (pass) when no real `git` is on PATH, so
//!   the suite stays green in environments without git.
//! - Rows that are not yet implemented are `#[ignore]`d with their phase and
//!   issue. Each phase un-ignores its rows as it ships the feature, so CI
//!   enforces only the currently-passing subset (no `rust.yml` change needed —
//!   `cargo nextest` skips ignored tests by default).

use std::path::PathBuf;
use std::process::{Command, Output};

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

/// Is a real `git` available on PATH? Differential cases skip (pass) when it
/// is not, rather than failing the suite.
fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Two isolated, side-by-side repos (one git, one mkit) sharing a neutralized
/// HOME/config so output differences come from the tools, not the host.
struct Harness {
    _root: tempfile::TempDir,
    home: PathBuf,
    git_repo: PathBuf,
    mkit_repo: PathBuf,
}

impl Harness {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("tempdir");
        let base = root.path().canonicalize().expect("canonicalize temp root");
        let home = base.join("home");
        let git_repo = base.join("git-repo");
        let mkit_repo = base.join("mkit-repo");
        for dir in [&home, &git_repo, &mkit_repo] {
            std::fs::create_dir_all(dir).expect("create repo dir");
        }
        Self {
            _root: root,
            home,
            git_repo,
            mkit_repo,
        }
    }

    fn git(&self, args: &[&str]) -> Output {
        Command::new("git")
            .args(args)
            .current_dir(&self.git_repo)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            // Neutralize global/system config so the host's ~/.gitconfig and
            // /etc/gitconfig cannot influence output.
            .env("GIT_CONFIG_GLOBAL", self.home.join("gitconfig-absent"))
            .env(
                "GIT_CONFIG_SYSTEM",
                self.home.join("gitconfig-system-absent"),
            )
            // Deterministic, isolated identity.
            .env("GIT_AUTHOR_NAME", "parity")
            .env("GIT_AUTHOR_EMAIL", "parity@example.com")
            .env("GIT_COMMITTER_NAME", "parity")
            .env("GIT_COMMITTER_EMAIL", "parity@example.com")
            .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00 +0000")
            .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00 +0000")
            .output()
            .expect("spawn git")
    }

    fn mkit(&self, args: &[&str]) -> Output {
        Command::new(mkit_bin())
            .args(args)
            .current_dir(&self.mkit_repo)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .output()
            .expect("spawn mkit")
    }

    fn init_both(&self) {
        assert!(
            self.git(&["init", "-b", "main"]).status.success(),
            "git init failed"
        );
        assert!(self.mkit(&["init"]).status.success(), "mkit init failed");
        // mkit commits are always signed; generate a key up front.
        assert!(
            self.mkit(&["keygen"]).status.success(),
            "mkit keygen failed"
        );
    }

    fn write_both(&self, rel: &str, content: &[u8]) {
        for repo in [&self.git_repo, &self.mkit_repo] {
            let path = repo.join(rel);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("create parent dir");
            }
            std::fs::write(&path, content).expect("write fixture file");
        }
    }

    fn commit_both(&self, paths: &[&str], message: &str) {
        let mut git_add = vec!["add"];
        git_add.extend_from_slice(paths);
        assert!(self.git(&git_add).status.success(), "git add failed");
        assert!(
            self.git(&["commit", "-m", message]).status.success(),
            "git commit failed"
        );
        let mut mkit_add = vec!["add"];
        mkit_add.extend_from_slice(paths);
        assert!(self.mkit(&mkit_add).status.success(), "mkit add failed");
        assert!(
            self.mkit(&["commit", "-m", message]).status.success(),
            "mkit commit failed"
        );
    }
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Mask any maximal run of lowercase hex that is exactly 40 (git SHA-1) or 64
/// (mkit BLAKE3) chars, so output can be compared modulo object-id length.
fn mask_object_ids(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut run = String::new();
    for ch in line.chars() {
        if ch.is_ascii_digit() || matches!(ch, 'a'..='f') {
            run.push(ch);
        } else {
            flush_run(&mut run, &mut out);
            out.push(ch);
        }
    }
    flush_run(&mut run, &mut out);
    out
}

fn flush_run(run: &mut String, out: &mut String) {
    if run.len() == 40 || run.len() == 64 {
        out.push_str("<oid>");
    } else {
        out.push_str(run);
    }
    run.clear();
}

/// Unordered, object-id-masked **set** of non-empty lines. Use ONLY for
/// output whose contract is a set, not a sequence — i.e. porcelain status,
/// where one line per path appears in either tool regardless of order.
/// Diff / log / plumbing output is order- and blank-line-sensitive; use
/// [`normalize_ordered`] for those.
fn normalize_set(s: &str) -> Vec<String> {
    let mut lines: Vec<String> = s
        .lines()
        .map(mask_object_ids)
        .filter(|l| !l.trim().is_empty())
        .collect();
    lines.sort();
    lines
}

/// Ordered, object-id-masked lines — preserves line order and blank lines.
/// Use for diff / log / plumbing output, where order and blanks are part of
/// the contract.
fn normalize_ordered(s: &str) -> Vec<String> {
    s.lines().map(mask_object_ids).collect()
}

/// Set-equality parity assertion (porcelain status only).
fn assert_parity_set(label: &str, git: &Output, mkit: &Output) {
    assert!(git.status.success(), "{label}: git command failed: {git:?}");
    assert!(
        mkit.status.success(),
        "{label}: mkit command failed: {mkit:?}"
    );
    assert_eq!(
        normalize_set(&stdout(git)),
        normalize_set(&stdout(mkit)),
        "{label}: git/mkit output diverged (modulo hash length)"
    );
}

/// Order- and blank-line-sensitive parity assertion (diff / log / plumbing).
fn assert_parity_ordered(label: &str, git: &Output, mkit: &Output) {
    assert!(git.status.success(), "{label}: git command failed: {git:?}");
    assert!(
        mkit.status.success(),
        "{label}: mkit command failed: {mkit:?}"
    );
    assert_eq!(
        normalize_ordered(&stdout(git)),
        normalize_ordered(&stdout(mkit)),
        "{label}: git/mkit output diverged (modulo hash length, order-sensitive)"
    );
}

/// Mask a **leading** abbreviated-hash token. `--oneline` output is
/// `<abbrev-id> <subject>`, and the abbreviation length differs between
/// git (SHA-1 prefix) and mkit (BLAKE3 prefix) — `mask_object_ids` only
/// catches full 40/64-hex, so the short leading id needs its own mask.
/// Only the first whitespace-delimited token is masked, so subjects are
/// still compared verbatim.
fn mask_leading_short_hash(line: &str) -> String {
    let mut parts = line.splitn(2, ' ');
    let first = parts.next().unwrap_or("");
    let is_short_hash = first.len() >= 4
        && first
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f'));
    match (is_short_hash, parts.next()) {
        (true, Some(rest)) => format!("<oid> {rest}"),
        _ => line.to_owned(),
    }
}

/// Ordered parity assertion for `--oneline`-style output: masks the
/// leading abbreviated id per line, then compares verbatim.
fn assert_parity_oneline(label: &str, git: &Output, mkit: &Output) {
    assert!(git.status.success(), "{label}: git command failed: {git:?}");
    assert!(
        mkit.status.success(),
        "{label}: mkit command failed: {mkit:?}"
    );
    let mask = |s: &str| s.lines().map(mask_leading_short_hash).collect::<Vec<_>>();
    assert_eq!(
        mask(&stdout(git)),
        mask(&stdout(mkit)),
        "{label}: git/mkit oneline output diverged (modulo abbreviated id)"
    );
}

// =====================================================================
// Smoke: the harness itself is isolated and consistent.
// =====================================================================

#[test]
fn clean_repo_status_is_empty_in_both() {
    if !git_available() {
        eprintln!("skipping: real `git` not on PATH");
        return;
    }
    let h = Harness::new();
    h.init_both();
    let g = h.git(&["status", "--porcelain"]);
    let m = h.mkit(&["status", "--porcelain"]);
    assert_parity_set("clean status", &g, &m);
    assert!(
        normalize_set(&stdout(&g)).is_empty(),
        "a clean repo must have empty porcelain status"
    );
}

// =====================================================================
// Passing subset — status --porcelain=v1 (machine-output contract).
// =====================================================================

#[test]
fn status_porcelain_untracked_matches_git() {
    if !git_available() {
        eprintln!("skipping: real `git` not on PATH");
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("untracked.txt", b"hi\n");
    let g = h.git(&["status", "--porcelain"]);
    let m = h.mkit(&["status", "--porcelain"]);
    assert_parity_set("untracked status", &g, &m); // expect `?? untracked.txt`
}

#[cfg(unix)]
#[test]
fn status_porcelain_quotes_special_paths_like_git() {
    if !git_available() {
        eprintln!("skipping: real `git` not on PATH");
        return;
    }
    let h = Harness::new();
    h.init_both();
    // A tab in the name: both git (core.quotePath default) and mkit must
    // emit the same C-style-quoted porcelain line `?? "a\tb.txt"`.
    h.write_both("a\tb.txt", b"x\n");
    let g = h.git(&["status", "--porcelain"]);
    let m = h.mkit(&["status", "--porcelain"]);
    assert_parity_set("quoted special path", &g, &m);
}

/// Parity for `-z` output: split on NUL into an order-independent set of
/// records (status -z carries no object hashes, so no masking needed).
fn assert_parity_nul(label: &str, git: &Output, mkit: &Output) {
    assert!(git.status.success(), "{label}: git failed: {git:?}");
    assert!(mkit.status.success(), "{label}: mkit failed: {mkit:?}");
    let recs = |o: &Output| {
        let s = String::from_utf8_lossy(&o.stdout);
        let mut v: Vec<String> = s
            .split('\0')
            .filter(|r| !r.is_empty())
            .map(str::to_string)
            .collect();
        v.sort();
        v
    };
    assert_eq!(
        recs(git),
        recs(mkit),
        "{label}: -z records diverged (raw NUL-terminated)"
    );
}

#[cfg(unix)]
#[test]
fn status_z_matches_git() {
    if !git_available() {
        eprintln!("skipping: real `git` not on PATH");
        return;
    }
    let h = Harness::new();
    h.init_both();
    // A staged change that is then re-edited in the worktree → one
    // combined `MM` record (not two), matching git porcelain.
    h.write_both("tracked.txt", b"v1\n");
    h.commit_both(&["tracked.txt"], "init");
    h.write_both("tracked.txt", b"v2\n");
    assert!(h.git(&["add", "tracked.txt"]).status.success());
    assert!(h.mkit(&["add", "tracked.txt"]).status.success());
    h.write_both("tracked.txt", b"v3\n");
    // A special-byte untracked path → `-z` emits it raw (unquoted).
    h.write_both("a\tb.txt", b"x\n");

    let g = h.git(&["status", "-z"]);
    let m = h.mkit(&["status", "-z"]);
    assert_parity_nul("status -z", &g, &m);
}

#[test]
fn status_rm_cached_keeps_staged_delete_and_untracked() {
    if !git_available() {
        eprintln!("skipping: real `git` not on PATH");
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("a.txt", b"hello\n");
    h.commit_both(&["a.txt"], "init");
    // Un-track a.txt but leave it on disk. Git porcelain emits TWO records
    // for the same path: `D  a.txt` (staged delete vs HEAD) and `?? a.txt`
    // (the worktree file the index no longer knows). mkit must not collapse
    // them into a lone `?? a.txt`, which would hide the staged deletion.
    assert!(h.git(&["rm", "--cached", "a.txt"]).status.success());
    assert!(h.mkit(&["rm", "--cached", "a.txt"]).status.success());
    let g = h.git(&["status", "--porcelain"]);
    let m = h.mkit(&["status", "--porcelain"]);
    assert_parity_set("rm --cached status", &g, &m); // expect `D  a.txt` + `?? a.txt`
}

#[test]
fn status_porcelain_staged_add_matches_git() {
    if !git_available() {
        eprintln!("skipping: real `git` not on PATH");
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("a.txt", b"hello\n");
    assert!(h.git(&["add", "a.txt"]).status.success());
    assert!(h.mkit(&["add", "a.txt"]).status.success());
    let g = h.git(&["status", "--porcelain"]);
    let m = h.mkit(&["status", "--porcelain"]);
    assert_parity_set("staged-add status", &g, &m); // expect `A  a.txt`
}

#[test]
fn status_porcelain_staged_modification_matches_git() {
    if !git_available() {
        eprintln!("skipping: real `git` not on PATH");
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("a.txt", b"one\n");
    h.commit_both(&["a.txt"], "init");
    h.write_both("a.txt", b"two\n");
    assert!(h.git(&["add", "a.txt"]).status.success());
    assert!(h.mkit(&["add", "a.txt"]).status.success());
    let g = h.git(&["status", "--porcelain"]);
    let m = h.mkit(&["status", "--porcelain"]);
    assert_parity_set("staged-modification status", &g, &m); // expect `M  a.txt`
}

#[test]
fn log_oneline_matches_git() {
    if !git_available() {
        eprintln!("skipping: real `git` not on PATH");
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("a.txt", b"hello\n");
    h.commit_both(&["a.txt"], "only commit");
    let g = h.git(&["log", "--oneline"]);
    let m = h.mkit(&["log", "--oneline"]);
    assert_parity_oneline("log --oneline", &g, &m); // `<abbrev> only commit`
}

// =====================================================================
// Passing subset — diff --name-only / --name-status / -z. Unlike the
// unified patch (whose `diff --mkit` header diverges, Phase 4), these
// formats carry no header or object id, so they match git byte-for-byte.
// =====================================================================

/// Stage one of each change kind against HEAD so a staged diff reports
/// `A`/`D`/`M` for three distinct paths (name-sorted: del, m, new).
fn stage_add_delete_modify(h: &Harness) {
    h.write_both("m.txt", b"one\n");
    h.write_both("del.txt", b"gone\n");
    h.commit_both(&["m.txt", "del.txt"], "init");
    h.write_both("m.txt", b"two\n"); // modify
    h.write_both("new.txt", b"new\n"); // add
    assert!(h.git(&["add", "m.txt", "new.txt"]).status.success());
    assert!(h.git(&["rm", "del.txt"]).status.success());
    assert!(h.mkit(&["add", "m.txt", "new.txt"]).status.success());
    assert!(h.mkit(&["rm", "del.txt"]).status.success());
}

#[test]
fn diff_name_only_matches_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    stage_add_delete_modify(&h);
    let g = h.git(&["diff", "--cached", "--name-only"]);
    let m = h.mkit(&["diff", "--staged", "--name-only"]);
    assert_parity_ordered("diff --name-only", &g, &m); // del.txt, m.txt, new.txt
}

#[test]
fn diff_name_status_matches_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    stage_add_delete_modify(&h);
    let g = h.git(&["diff", "--cached", "--name-status"]);
    let m = h.mkit(&["diff", "--staged", "--name-status"]);
    assert_parity_ordered("diff --name-status", &g, &m); // D del / M m / A new
}

#[cfg(unix)]
#[test]
fn diff_name_status_z_matches_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    stage_add_delete_modify(&h);
    // `-z`: status letter and path are each NUL-terminated, paths raw.
    let g = h.git(&["diff", "--cached", "--name-status", "-z"]);
    let m = h.mkit(&["diff", "--staged", "--name-status", "-z"]);
    assert_parity_nul("diff --name-status -z", &g, &m);
}

#[cfg(unix)]
#[test]
fn diff_name_only_quotes_special_paths_like_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    // A tab in the name: default --name-only C-style quotes it like git's
    // core.quotePath; with -z the same path is emitted raw.
    h.write_both("a\tb.txt", b"x\n");
    assert!(h.git(&["add", "a\tb.txt"]).status.success());
    assert!(h.mkit(&["add", "a\tb.txt"]).status.success());
    let g = h.git(&["diff", "--cached", "--name-only"]);
    let m = h.mkit(&["diff", "--staged", "--name-only"]);
    assert_parity_ordered("diff --name-only quoted", &g, &m); // "a\tb.txt"
    let gz = h.git(&["diff", "--cached", "--name-only", "-z"]);
    let mz = h.mkit(&["diff", "--staged", "--name-only", "-z"]);
    assert_parity_nul("diff --name-only -z raw", &gz, &mz);
}

// =====================================================================
// Pending rows — ignored until the owning phase ships them. Each carries
// the comparison so un-ignoring is a one-line change once implemented.
// =====================================================================

#[test]
#[ignore = "Phase 1 (#249): status --porcelain=v2 not implemented yet"]
fn status_porcelain_v2_matches_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("a.txt", b"hello\n");
    assert!(h.git(&["add", "a.txt"]).status.success());
    assert!(h.mkit(&["add", "a.txt"]).status.success());
    let g = h.git(&["status", "--porcelain=v2"]);
    let m = h.mkit(&["status", "--porcelain=v2"]);
    assert_parity_set("status --porcelain=v2", &g, &m);
}

#[test]
#[ignore = "Phase 4 (#257): diff header is `diff --mkit` not `diff --git`; Myers hunk parity pending"]
fn diff_unified_matches_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("f.txt", b"line1\nline2\nline3\n");
    h.commit_both(&["f.txt"], "init");
    h.write_both("f.txt", b"line1\nCHANGED\nline3\n");
    let g = h.git(&["diff"]);
    let m = h.mkit(&["diff"]);
    assert_parity_ordered("diff (unified)", &g, &m);
}

// =====================================================================
// Unit coverage for the normalizer itself.
// =====================================================================

#[test]
fn mask_object_ids_masks_only_40_and_64_hex() {
    let sha1 = "a".repeat(40);
    let blake3 = "b".repeat(64);
    assert_eq!(mask_object_ids(&format!("commit {sha1}")), "commit <oid>");
    assert_eq!(mask_object_ids(&format!("commit {blake3}")), "commit <oid>");
    // A short abbreviation (7 hex) and an ordinary word are left untouched.
    assert_eq!(mask_object_ids("abc1234 subject"), "abc1234 subject");
    assert_eq!(mask_object_ids("?? untracked.txt"), "?? untracked.txt");
}
