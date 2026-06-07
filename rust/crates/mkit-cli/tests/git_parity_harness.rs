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

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

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

    /// Run `git` with `input` piped to stdin (for `cat-file --batch`).
    fn git_stdin(&self, args: &[&str], input: &[u8]) -> Output {
        let mut child = Command::new("git")
            .args(args)
            .current_dir(&self.git_repo)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("GIT_CONFIG_GLOBAL", self.home.join("gitconfig-absent"))
            .env(
                "GIT_CONFIG_SYSTEM",
                self.home.join("gitconfig-system-absent"),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn git");
        child
            .stdin
            .take()
            .expect("git stdin")
            .write_all(input)
            .expect("write git stdin");
        child.wait_with_output().expect("git output")
    }

    /// Run `mkit` with `input` piped to stdin (for `cat-file --batch`).
    fn mkit_stdin(&self, args: &[&str], input: &[u8]) -> Output {
        let mut child = Command::new(mkit_bin())
            .args(args)
            .current_dir(&self.mkit_repo)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn mkit");
        child
            .stdin
            .take()
            .expect("mkit stdin")
            .write_all(input)
            .expect("write mkit stdin");
        child.wait_with_output().expect("mkit output")
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

/// Byte-exact stdout parity. For output that carries no object ids,
/// order, field pairing, and NUL framing are all part of the contract —
/// so compare the raw bytes directly rather than splitting into a set
/// (which `assert_parity_nul` does, and which would miss a swapped
/// `status\0path` pairing or a reordered record in `--name-status -z`).
fn assert_parity_bytes(label: &str, git: &Output, mkit: &Output) {
    assert!(git.status.success(), "{label}: git failed: {git:?}");
    assert!(mkit.status.success(), "{label}: mkit failed: {mkit:?}");
    assert_eq!(
        git.stdout, mkit.stdout,
        "{label}: stdout bytes diverged (order/pairing/framing sensitive)"
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

#[test]
fn log_revision_and_range_match_git() {
    if !git_available() {
        eprintln!("skipping: real `git` not on PATH");
        return;
    }
    let h = Harness::new();
    h.init_both();
    for (f, m) in [
        ("a.txt", "c1"),
        ("b.txt", "c2"),
        ("c.txt", "c3"),
        ("d.txt", "c4"),
    ] {
        h.write_both(f, b"x\n");
        h.commit_both(&[f], m);
    }
    // A single revision starts the walk there (HEAD~1 and its ancestors).
    assert_parity_oneline(
        "log --oneline HEAD~1",
        &h.git(&["log", "--oneline", "HEAD~1"]),
        &h.mkit(&["log", "--oneline", "HEAD~1"]),
    );
    // `A..B` excludes the left side and its ancestors.
    assert_parity_oneline(
        "log --oneline HEAD~3..HEAD",
        &h.git(&["log", "--oneline", "HEAD~3..HEAD"]),
        &h.mkit(&["log", "--oneline", "HEAD~3..HEAD"]),
    );
    // Open-ended `A..` = `A..HEAD`.
    assert_parity_oneline(
        "log --oneline HEAD~2..",
        &h.git(&["log", "--oneline", "HEAD~2.."]),
        &h.mkit(&["log", "--oneline", "HEAD~2.."]),
    );
}

#[test]
fn log_annotated_tag_range_matches_git() {
    if !git_available() {
        eprintln!("skipping: real `git` not on PATH");
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("a.txt", b"1\n");
    h.commit_both(&["a.txt"], "c1");
    // An annotated tag at c1 in both repos — log must peel it to the commit.
    assert!(h.git(&["tag", "-a", "v1", "-m", "tag c1"]).status.success());
    assert!(
        h.mkit(&["tag", "-a", "v1", "-m", "tag c1"])
            .status
            .success()
    );
    h.write_both("b.txt", b"2\n");
    h.commit_both(&["b.txt"], "c2");
    h.write_both("c.txt", b"3\n");
    h.commit_both(&["c.txt"], "c3");
    // Include side: `log <tag>` walks the tagged commit's history.
    assert_parity_oneline(
        "log --oneline v1 (annotated)",
        &h.git(&["log", "--oneline", "v1"]),
        &h.mkit(&["log", "--oneline", "v1"]),
    );
    // Exclude side: `<tag>..HEAD` excludes the tagged commit + ancestors.
    assert_parity_oneline(
        "log --oneline v1..HEAD (annotated)",
        &h.git(&["log", "--oneline", "v1..HEAD"]),
        &h.mkit(&["log", "--oneline", "v1..HEAD"]),
    );
}

#[test]
fn log_and_diff_symmetric_range_match_git() {
    if !git_available() {
        eprintln!("skipping: real `git` not on PATH");
        return;
    }
    let h = Harness::new();
    h.init_both();
    // Common ancestor c1, then c2 on `main` and c3 on `feat`.
    h.write_both("a.txt", b"base\n");
    h.commit_both(&["a.txt"], "c1");
    assert!(h.git(&["branch", "feat"]).status.success());
    assert!(h.mkit(&["branch", "feat"]).status.success());
    h.write_both("m.txt", b"m\n");
    h.commit_both(&["m.txt"], "c2");
    assert!(h.git(&["checkout", "feat"]).status.success());
    assert!(h.mkit(&["checkout", "feat"]).status.success());
    h.write_both("f.txt", b"f\n");
    h.commit_both(&["f.txt"], "c3");

    // `log main...feat`: the symmetric difference is a *set* {c2, c3}; the
    // order tie-breaks on commit date, which the harness pins to one value
    // for git but not mkit — so compare the masked subject sets.
    let g = h.git(&["log", "--oneline", "main...feat"]);
    let m = h.mkit(&["log", "--oneline", "main...feat"]);
    assert!(g.status.success() && m.status.success(), "log failed");
    let subjects = |o: &Output| {
        let mut v: Vec<String> = stdout(o)
            .lines()
            .filter_map(|l| l.split_once(' ').map(|(_, s)| s.to_string()))
            .collect();
        v.sort();
        v
    };
    assert_eq!(
        subjects(&g),
        subjects(&m),
        "log main...feat commit set diverged"
    );

    // `diff main...feat` = merge-base(c1) vs feat(c3) — a deterministic
    // tree diff, so byte-match it.
    assert_parity_diff(
        "diff main...feat",
        &h.git(&["diff", "main...feat"]),
        &h.mkit(&["diff", "main...feat"]),
    );
}

// =====================================================================
// Passing subset — diff --name-only / --name-status / -z. These carry no
// header or object id, so they match git byte-for-byte. (The unified patch
// also matches now, modulo the abbreviated `index` ids — see the
// `diff_unified_*` tests with `assert_parity_diff`.)
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
    // Byte-exact so a swapped `letter\0path` pairing or reordered record
    // would be caught (the set-based assert_parity_nul would not).
    let g = h.git(&["diff", "--cached", "--name-status", "-z"]);
    let m = h.mkit(&["diff", "--staged", "--name-status", "-z"]);
    assert_parity_bytes("diff --name-status -z", &g, &m);
}

#[test]
fn diff_staged_rejects_bad_rev_like_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("a.txt", b"x\n");
    h.commit_both(&["a.txt"], "init");
    // A hash-shaped leading arg that resolves to nothing must fail closed
    // in staged mode, like `git diff --cached <bad-rev>` (which errors
    // rather than treating it as a no-match pathspec and empty-succeeding).
    let g = h.git(&["diff", "--cached", "--name-only", "deadbeefdeadbeef"]);
    let m = h.mkit(&["diff", "--staged", "--name-only", "deadbeefdeadbeef"]);
    assert!(
        !g.status.success(),
        "git should reject bad staged rev: {g:?}"
    );
    assert!(
        !m.status.success(),
        "mkit must not empty-succeed on a bad staged rev: {m:?}"
    );
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
    assert_parity_bytes("diff --name-only -z raw", &gz, &mz);
}

#[test]
fn diff_stat_matches_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    stage_add_delete_modify(&h);
    // Unscaled multi-file diffstat: per-file `<name> | <count> <graph>`
    // rows (name-sorted: del, m, new) + the `N files changed, …` summary.
    // Byte-exact: --stat carries no object ids, so order, column padding,
    // and (the absence of) trailing whitespace are all part of the contract.
    let g = h.git(&["diff", "--cached", "--stat"]);
    let m = h.mkit(&["diff", "--staged", "--stat"]);
    assert_parity_bytes("diff --stat", &g, &m);
}

#[test]
fn diff_stat_single_insertion_summary_matches_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("f.txt", b"x\n");
    h.commit_both(&["f.txt"], "init");
    h.write_both("f.txt", b"x\ny\n"); // exactly one inserted line
    assert!(h.git(&["add", "f.txt"]).status.success());
    assert!(h.mkit(&["add", "f.txt"]).status.success());
    // Pluralization: "1 file changed, 1 insertion(+)" (singular, no
    // deletions clause since there are none).
    let g = h.git(&["diff", "--cached", "--stat"]);
    let m = h.mkit(&["diff", "--staged", "--stat"]);
    assert_parity_bytes("diff --stat singular summary", &g, &m);
}

#[test]
fn diff_stat_empty_file_zero_change_matches_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("seed.txt", b"x\n");
    h.commit_both(&["seed.txt"], "init");
    // Adding an empty file is a zero-change row: git prints `<name> | 0`
    // with NO trailing space, and the summary still shows BOTH zero
    // clauses (` 1 file changed, 0 insertions(+), 0 deletions(-)`).
    h.write_both("empty.txt", b"");
    assert!(h.git(&["add", "empty.txt"]).status.success());
    assert!(h.mkit(&["add", "empty.txt"]).status.success());
    let g = h.git(&["diff", "--cached", "--stat"]);
    let m = h.mkit(&["diff", "--staged", "--stat"]);
    assert_parity_bytes("diff --stat zero-change row", &g, &m);
}

#[test]
fn diff_stat_nul_file_is_binary_like_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    // A blob containing a NUL byte is valid UTF-8 but Git (and now mkit)
    // classify it as binary by the NUL heuristic, so --stat shows
    // `Bin <old> -> <new> bytes`, not line counts. (Filename avoids
    // Windows reserved device names like `nul`, which mkit's tree guard
    // refuses cross-platform.)
    h.write_both("payload.dat", b"hello\x00world\n");
    h.commit_both(&["payload.dat"], "init");
    h.write_both("payload.dat", b"HELLO\x00WORLD\nmore\n");
    assert!(h.git(&["add", "payload.dat"]).status.success());
    assert!(h.mkit(&["add", "payload.dat"]).status.success());
    let g = h.git(&["diff", "--cached", "--stat"]);
    let m = h.mkit(&["diff", "--staged", "--stat"]);
    assert_parity_bytes("diff --stat NUL=binary", &g, &m);
}

#[test]
fn diff_stat_scaled_graph_matches_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("small.txt", b"x\n");
    h.write_both("really-long-filename.txt", b"x\n");
    h.commit_both(&["small.txt", "really-long-filename.txt"], "init");
    // A small change beside a 200-line rewrite: the big file overflows the
    // ~80-col graph, so git scales both files' graphs via scale_linear.
    // This exercises the scaling + column-width math, not just the literal
    // path. Both tools read COLUMNS identically (default 80 when unset).
    h.write_both("small.txt", b"a\nb\nc\n");
    let mut big = String::new();
    for i in 0..200 {
        use std::fmt::Write as _;
        let _ = writeln!(big, "line{i}");
    }
    h.write_both("really-long-filename.txt", big.as_bytes());
    assert!(
        h.git(&["add", "small.txt", "really-long-filename.txt"])
            .status
            .success()
    );
    assert!(
        h.mkit(&["add", "small.txt", "really-long-filename.txt"])
            .status
            .success()
    );
    let g = h.git(&["diff", "--cached", "--stat"]);
    let m = h.mkit(&["diff", "--staged", "--stat"]);
    assert_parity_bytes("diff --stat (scaled)", &g, &m);
}

// =====================================================================
// Passing subset — clean dry-run parity (#250). `git clean -n` and
// `mkit clean -n` print identical `Would remove <path>` lines (no object
// ids); reset --hard isn't compared (git discards silently, mkit guards).
// =====================================================================

#[test]
fn clean_dry_run_matches_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("tracked.txt", b"t\n");
    h.commit_both(&["tracked.txt"], "init");
    // Untracked files (no ignore involved → identical in both).
    h.write_both("a-untracked.txt", b"u\n");
    h.write_both("z-untracked.txt", b"u\n");
    let g = h.git(&["clean", "-n"]);
    let m = h.mkit(&["clean", "-n"]);
    assert_parity_ordered("clean -n", &g, &m);
}

#[test]
fn clean_dry_run_d_lists_untracked_dirs_like_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("tracked.txt", b"t\n");
    h.commit_both(&["tracked.txt"], "init");
    h.write_both("top.txt", b"u\n");
    h.write_both("untrackeddir/inner.txt", b"d\n");
    // `-d` lists the untracked directory as `untrackeddir/` in both tools.
    let g = h.git(&["clean", "-n", "-d"]);
    let m = h.mkit(&["clean", "-n", "-d"]);
    assert_parity_ordered("clean -n -d", &g, &m);
}

#[test]
fn clean_without_force_refused_like_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("tracked.txt", b"t\n");
    h.commit_both(&["tracked.txt"], "init");
    h.write_both("untracked.txt", b"u\n");
    // Both refuse to delete without -f (git's clean.requireForce default).
    let g = h.git(&["clean"]);
    let m = h.mkit(&["clean"]);
    assert!(
        !g.status.success(),
        "git clean must refuse without -f: {g:?}"
    );
    assert!(
        !m.status.success(),
        "mkit clean must refuse without -f: {m:?}"
    );
}

// =====================================================================
// Passing subset — mv guard parity (#250). The happy-path move shows as
// `R` under git (rename detection) but delete+add under mkit, so only the
// guard/error behavior is compared differentially (both must fail).
// =====================================================================

#[test]
fn mv_existing_dest_refused_like_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("a.txt", b"aaa\n");
    h.write_both("b.txt", b"bbb\n");
    h.commit_both(&["a.txt", "b.txt"], "init");
    // Moving onto an existing path is refused without -f in both tools.
    let g = h.git(&["mv", "a.txt", "b.txt"]);
    let m = h.mkit(&["mv", "a.txt", "b.txt"]);
    assert!(!g.status.success(), "git mv should refuse clobber: {g:?}");
    assert!(!m.status.success(), "mkit mv should refuse clobber: {m:?}");
}

#[test]
fn mv_untracked_source_fails_like_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("tracked.txt", b"t\n");
    h.commit_both(&["tracked.txt"], "init");
    h.write_both("untracked.txt", b"u\n");
    let g = h.git(&["mv", "untracked.txt", "dest.txt"]);
    let m = h.mkit(&["mv", "untracked.txt", "dest.txt"]);
    assert!(
        !g.status.success(),
        "git mv should reject untracked source: {g:?}"
    );
    assert!(
        !m.status.success(),
        "mkit mv should reject untracked source: {m:?}"
    );
}

#[test]
fn config_user_name_round_trips_like_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    // `git config user.name X` then `git config user.name` echoes X; mkit's
    // git-compat alias does the same (it stays non-authoritative — mkit's
    // signed author is the key/`user.identity`, not this value).
    assert!(
        h.git(&["config", "user.name", "Alice Example"])
            .status
            .success()
    );
    assert!(
        h.mkit(&["config", "user.name", "Alice Example"])
            .status
            .success()
    );
    let g = h.git(&["config", "user.name"]);
    let m = h.mkit(&["config", "user.name"]);
    assert_parity_bytes("config user.name round-trip", &g, &m);
}

// =====================================================================
// Passing subset — branch list / delete reconciliation (#249).
// =====================================================================

#[test]
fn branch_default_list_matches_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("a.txt", b"x\n");
    h.commit_both(&["a.txt"], "init");
    assert!(h.git(&["branch", "feature"]).status.success());
    assert!(h.mkit(&["branch", "feature"]).status.success());
    // Default `branch` lists `<marker> <name>` with no commit id, sorted
    // by name (`  feature`, `* main`). No object id, so compare ordered.
    let g = h.git(&["branch"]);
    let m = h.mkit(&["branch"]);
    assert_parity_ordered("branch (default list)", &g, &m);
}

#[test]
fn branch_delete_missing_fails_like_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("a.txt", b"x\n");
    h.commit_both(&["a.txt"], "init");
    // `branch -D <missing>` errors in git; mkit must too (no silent no-op).
    let g = h.git(&["branch", "-D", "ghost"]);
    let m = h.mkit(&["branch", "-D", "ghost"]);
    assert!(
        !g.status.success(),
        "git should reject -D of missing: {g:?}"
    );
    assert!(
        !m.status.success(),
        "mkit -D of a missing branch must fail like git: {m:?}"
    );
}

// =====================================================================
// Passing subset — read-only plumbing (#251, Phase 3). rev-parse /
// show-ref / ls-tree output is parity-able modulo hash length; cat-file
// on a blob is byte-exact (type / size / content carry no object id).
// =====================================================================

#[test]
fn rev_parse_head_matches_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("a.txt", b"x\n");
    h.commit_both(&["a.txt"], "init");
    // Full HEAD id (masked) and the symbolic branch name both match.
    assert_parity_ordered(
        "rev-parse HEAD",
        &h.git(&["rev-parse", "HEAD"]),
        &h.mkit(&["rev-parse", "HEAD"]),
    );
    assert_parity_bytes(
        "rev-parse --abbrev-ref HEAD",
        &h.git(&["rev-parse", "--abbrev-ref", "HEAD"]),
        &h.mkit(&["rev-parse", "--abbrev-ref", "HEAD"]),
    );
}

#[test]
fn show_ref_matches_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("a.txt", b"x\n");
    h.commit_both(&["a.txt"], "init");
    assert!(h.git(&["tag", "v1"]).status.success());
    assert!(h.mkit(&["tag", "v1"]).status.success());
    // `<oid> refs/heads/main` + `<oid> refs/tags/v1`, sorted by refname.
    assert_parity_ordered("show-ref", &h.git(&["show-ref"]), &h.mkit(&["show-ref"]));
    assert_parity_ordered(
        "show-ref --heads",
        &h.git(&["show-ref", "--heads"]),
        &h.mkit(&["show-ref", "--heads"]),
    );
}

#[test]
fn ls_tree_matches_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("file.txt", b"hello\n");
    h.write_both("sub/inner.txt", b"nested\n");
    h.commit_both(&["file.txt", "sub/inner.txt"], "init");
    // Non-recursive: file + `sub` as a tree line. Recursive: leaf blobs
    // with full paths, no tree lines. Both modulo hash length.
    assert_parity_ordered(
        "ls-tree HEAD",
        &h.git(&["ls-tree", "HEAD"]),
        &h.mkit(&["ls-tree", "HEAD"]),
    );
    assert_parity_ordered(
        "ls-tree -r HEAD",
        &h.git(&["ls-tree", "-r", "HEAD"]),
        &h.mkit(&["ls-tree", "-r", "HEAD"]),
    );
}

#[test]
fn cat_file_blob_matches_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("file.txt", b"hello\n");
    h.commit_both(&["file.txt"], "init");
    // Extract each tool's blob hash for file.txt from its own ls-tree
    // (`<mode> blob <hash>\tfile.txt`).
    let git_blob = blob_hash_from_ls_tree(&stdout(&h.git(&["ls-tree", "HEAD"])), "file.txt");
    let mkit_blob = blob_hash_from_ls_tree(&stdout(&h.mkit(&["ls-tree", "HEAD"])), "file.txt");
    // type / size / content are object-id-free → byte-exact parity.
    assert_parity_bytes(
        "cat-file -t blob",
        &h.git(&["cat-file", "-t", &git_blob]),
        &h.mkit(&["cat-file", "-t", &mkit_blob]),
    );
    assert_parity_bytes(
        "cat-file -s blob",
        &h.git(&["cat-file", "-s", &git_blob]),
        &h.mkit(&["cat-file", "-s", &mkit_blob]),
    );
    assert_parity_bytes(
        "cat-file -p blob",
        &h.git(&["cat-file", "-p", &git_blob]),
        &h.mkit(&["cat-file", "-p", &mkit_blob]),
    );
}

/// Pull the `<hash>` field for `name` out of `ls-tree` output
/// (`<mode> <type> <hash>\t<name>`).
fn blob_hash_from_ls_tree(out: &str, name: &str) -> String {
    for line in out.lines() {
        let Some((meta, path)) = line.split_once('\t') else {
            continue;
        };
        if path == name {
            return meta.split_whitespace().nth(2).unwrap_or("").to_string();
        }
    }
    panic!("no ls-tree entry for {name} in: {out:?}");
}

#[test]
fn cat_file_batch_blob_matches_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("file.txt", b"hello\n");
    h.commit_both(&["file.txt"], "init");
    // Feed each tool its own blob id; the `<oid> blob <size>` header masks to
    // parity and `hello` content is byte-identical. A trailing `missing`
    // record exercises the unknown-object path in both tools.
    let git_blob = blob_hash_from_ls_tree(&stdout(&h.git(&["ls-tree", "HEAD"])), "file.txt");
    let mkit_blob = blob_hash_from_ls_tree(&stdout(&h.mkit(&["ls-tree", "HEAD"])), "file.txt");
    let g = h.git_stdin(&["cat-file", "--batch"], format!("{git_blob}\n").as_bytes());
    let m = h.mkit_stdin(
        &["cat-file", "--batch"],
        format!("{mkit_blob}\n").as_bytes(),
    );
    assert_parity_ordered("cat-file --batch blob", &g, &m);
}

#[test]
fn ls_files_matches_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("file.txt", b"hello\n");
    h.write_both("sub/inner.txt", b"nested\n");
    h.commit_both(&["file.txt", "sub/inner.txt"], "init");
    // Default tracked listing (object-id-free → byte-exact, sorted).
    assert_parity_bytes("ls-files", &h.git(&["ls-files"]), &h.mkit(&["ls-files"]));
    // `-s` carries the blob hash → mask modulo length, order-sensitive.
    assert_parity_ordered(
        "ls-files -s",
        &h.git(&["ls-files", "-s"]),
        &h.mkit(&["ls-files", "-s"]),
    );
    // Untracked listing (object-id-free → byte-exact).
    h.write_both("other.txt", b"x\n");
    assert_parity_bytes(
        "ls-files --others",
        &h.git(&["ls-files", "--others"]),
        &h.mkit(&["ls-files", "--others"]),
    );
}

#[test]
fn ls_files_exclude_standard_matches_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    // git reads .gitignore, mkit reads .mkitignore — write the matching
    // ignore file into each repo so both exclude `secret.log`. The ignore
    // file also ignores itself, so the differently-named control files
    // (.gitignore vs .mkitignore) don't show up and skew the comparison.
    std::fs::write(h.git_repo.join(".gitignore"), b"*.log\n.gitignore\n")
        .expect("write .gitignore");
    std::fs::write(h.mkit_repo.join(".mkitignore"), b"*.log\n.mkitignore\n")
        .expect("write .mkitignore");
    h.write_both("keep.txt", b"k\n");
    h.write_both("secret.log", b"s\n");
    // `--others --exclude-standard` drops the ignored `secret.log` and the
    // self-ignored control file, leaving only `keep.txt`. Object-id-free →
    // byte-exact.
    assert_parity_bytes(
        "ls-files --others --exclude-standard",
        &h.git(&["ls-files", "--others", "--exclude-standard"]),
        &h.mkit(&["ls-files", "--others", "--exclude-standard"]),
    );
}

#[test]
fn for_each_ref_matches_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("a.txt", b"x\n");
    h.commit_both(&["a.txt"], "init");
    assert!(h.git(&["tag", "v1"]).status.success());
    assert!(h.mkit(&["tag", "v1"]).status.success());
    // Default `<oid> <objecttype>\t<refname>`, sorted by refname → masked.
    assert_parity_ordered(
        "for-each-ref",
        &h.git(&["for-each-ref"]),
        &h.mkit(&["for-each-ref"]),
    );
    // Object-id-free format → byte-exact parity.
    assert_parity_bytes(
        "for-each-ref --format refname/objecttype",
        &h.git(&["for-each-ref", "--format=%(refname) %(objecttype)"]),
        &h.mkit(&["for-each-ref", "--format=%(refname) %(objecttype)"]),
    );
    // `refname:short` strips the `refs/heads/` + `refs/tags/` prefixes.
    assert_parity_bytes(
        "for-each-ref --format refname:short",
        &h.git(&["for-each-ref", "--format=%(refname:short)"]),
        &h.mkit(&["for-each-ref", "--format=%(refname:short)"]),
    );
}

#[test]
fn symbolic_ref_head_matches_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("a.txt", b"x\n");
    h.commit_both(&["a.txt"], "init");
    // `refs/heads/main` and (with --short) `main` — object-id-free, byte-exact.
    assert_parity_bytes(
        "symbolic-ref HEAD",
        &h.git(&["symbolic-ref", "HEAD"]),
        &h.mkit(&["symbolic-ref", "HEAD"]),
    );
    assert_parity_bytes(
        "symbolic-ref --short HEAD",
        &h.git(&["symbolic-ref", "--short", "HEAD"]),
        &h.mkit(&["symbolic-ref", "--short", "HEAD"]),
    );
}

#[test]
fn update_ref_create_matches_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("a.txt", b"x\n");
    h.commit_both(&["a.txt"], "init");
    // Create refs/heads/feature at HEAD in both, then the ref listing
    // matches modulo hash length.
    assert!(
        h.git(&["update-ref", "refs/heads/feature", "HEAD"])
            .status
            .success()
    );
    assert!(
        h.mkit(&["update-ref", "refs/heads/feature", "HEAD"])
            .status
            .success()
    );
    assert_parity_ordered(
        "show-ref after update-ref create",
        &h.git(&["show-ref", "--heads"]),
        &h.mkit(&["show-ref", "--heads"]),
    );
}

#[test]
fn symbolic_ref_write_matches_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("a.txt", b"x\n");
    h.commit_both(&["a.txt"], "init");
    assert!(h.git(&["branch", "feature"]).status.success());
    assert!(h.mkit(&["branch", "feature"]).status.success());
    // Repoint HEAD at the branch, then read it back — byte-identical.
    assert!(
        h.git(&["symbolic-ref", "HEAD", "refs/heads/feature"])
            .status
            .success()
    );
    assert!(
        h.mkit(&["symbolic-ref", "HEAD", "refs/heads/feature"])
            .status
            .success()
    );
    assert_parity_bytes(
        "symbolic-ref HEAD after write",
        &h.git(&["symbolic-ref", "HEAD"]),
        &h.mkit(&["symbolic-ref", "HEAD"]),
    );
}

#[test]
fn config_core_inert_key_matches_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    assert!(h.git(&["config", "core.autocrlf", "true"]).status.success());
    assert!(
        h.mkit(&["config", "core.autocrlf", "true"])
            .status
            .success()
    );
    assert_parity_bytes(
        "config core.autocrlf round-trip",
        &h.git(&["config", "core.autocrlf"]),
        &h.mkit(&["config", "core.autocrlf"]),
    );
}

// =====================================================================
// Pending rows — ignored until the owning phase ships them. Each carries
// the comparison so un-ignoring is a one-line change once implemented.
// =====================================================================

#[test]
fn status_porcelain_v2_matches_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    // Baseline commit, then a mix of change kinds: staged add, unstaged
    // modify of a tracked file, staged delete, and an untracked file.
    h.write_both("tracked.txt", b"v1\n");
    h.write_both("doomed.txt", b"bye\n");
    h.commit_both(&["tracked.txt", "doomed.txt"], "init");
    h.write_both("added.txt", b"new\n");
    assert!(h.git(&["add", "added.txt"]).status.success());
    assert!(h.mkit(&["add", "added.txt"]).status.success());
    assert!(h.git(&["rm", "doomed.txt"]).status.success());
    assert!(h.mkit(&["rm", "doomed.txt"]).status.success());
    h.write_both("tracked.txt", b"v2\n"); // unstaged modify
    h.write_both("untracked.txt", b"u\n");
    // Each `1 …` line carries object ids (masked) + octal modes; `?` lines
    // for untracked. Order-independent, hash-masked set comparison.
    let g = h.git(&["status", "--porcelain=v2"]);
    let m = h.mkit(&["status", "--porcelain=v2"]);
    assert_parity_set("status --porcelain=v2 (mixed)", &g, &m);
}

/// A tracked file replaced on disk by a directory is **not** a valid
/// worktree side for that path: git (and mkit) report the tracked file as
/// deleted in the worktree (`mW = 000000`). The worktree mode must never be
/// reported as `040000` for the tracked path. Uses an empty replacement
/// directory so the comparison is exactly the tracked-side `1 .D … f`
/// record — git suppresses untracked entries that collide with a tracked
/// path, a shared untracked-walk divergence orthogonal to the v2 mode
/// columns, tracked separately in #288.
#[test]
fn status_porcelain_v2_file_replaced_by_dir_matches_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("f", b"file contents\n");
    h.commit_both(&["f"], "init");
    // Replace the tracked file `f` with a directory.
    for repo in [&h.git_repo, &h.mkit_repo] {
        std::fs::remove_file(repo.join("f")).expect("remove tracked file");
        std::fs::create_dir(repo.join("f")).expect("create dir at path");
    }
    let g = h.git(&["status", "--porcelain=v2"]);
    let m = h.mkit(&["status", "--porcelain=v2"]);
    assert_parity_set("status --porcelain=v2 (file→dir)", &g, &m);
    // Belt-and-suspenders: the tracked record must carry mW = 000000, never
    // the `040000` a raw directory stat would yield.
    let out = String::from_utf8(m.stdout).expect("utf-8");
    let rec = out
        .lines()
        .find(|l| l.ends_with(" f"))
        .expect("tracked `f` record present");
    let mw = rec.split(' ').nth(5).expect("mW field");
    assert_eq!(
        mw, "000000",
        "worktree mode for dir-replaced file must be 000000"
    );
}

/// Mask the abbreviated blob ids on a `diff --git` `index` line — git's
/// SHA-1 prefixes and mkit's BLAKE3 prefixes can't match, but everything
/// else on the line (and every other line) must. Non-`index` lines fall back
/// to the full-hash masker.
fn mask_diff_line(line: &str) -> String {
    if let Some(rest) = line.strip_prefix("index ") {
        let mut parts = rest.splitn(2, ' ');
        let _hashes = parts.next();
        match parts.next() {
            Some(mode) => format!("index <oid>..<oid> {mode}"),
            None => "index <oid>..<oid>".to_string(),
        }
    } else {
        mask_object_ids(line)
    }
}

/// Order-sensitive unified-diff parity: like [`assert_parity_ordered`] but
/// also masks `index` abbreviated ids, so the full `git diff` shape (header,
/// `index`, `--- a/p`/`+++ b/p`, `@@` hunks, `+`/`-` lines) is compared.
fn assert_parity_diff(label: &str, git: &Output, mkit: &Output) {
    assert!(git.status.success(), "{label}: git failed: {git:?}");
    assert!(mkit.status.success(), "{label}: mkit failed: {mkit:?}");
    let norm = |o: &Output| stdout(o).lines().map(mask_diff_line).collect::<Vec<_>>();
    assert_eq!(
        norm(git),
        norm(mkit),
        "{label}: git/mkit unified diff diverged (modulo abbreviated ids)"
    );
}

#[test]
fn diff_unified_modify_matches_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("f.txt", b"line1\nline2\nline3\n");
    h.commit_both(&["f.txt"], "init");
    h.write_both("f.txt", b"line1\nCHANGED\nline3\n");
    assert_parity_diff("diff (modify)", &h.git(&["diff"]), &h.mkit(&["diff"]));
}

#[test]
fn diff_unified_multi_hunk_matches_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    // Ten lines; change line 2 and line 9 → two separate hunks.
    let mut base = String::new();
    for n in 1..=10 {
        use std::fmt::Write as _;
        let _ = writeln!(base, "line{n}");
    }
    h.write_both("f.txt", base.as_bytes());
    h.commit_both(&["f.txt"], "init");
    let edited = base
        .replace("line2\n", "TWO\n")
        .replace("line9\n", "NINE\n");
    h.write_both("f.txt", edited.as_bytes());
    assert_parity_diff("diff (multi-hunk)", &h.git(&["diff"]), &h.mkit(&["diff"]));
}

#[test]
fn diff_unified_add_delete_matches_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("keep.txt", b"keep\n");
    h.write_both("gone.txt", b"a\nb\nc\n");
    h.commit_both(&["keep.txt", "gone.txt"], "init");
    // Stage a brand-new file and a deletion — `diff --staged` shows both with
    // `new file mode` / `deleted file mode` + `/dev/null` headers.
    h.write_both("new.txt", b"hello\nworld\n");
    assert!(h.git(&["add", "new.txt"]).status.success());
    assert!(h.mkit(&["add", "new.txt"]).status.success());
    assert!(h.git(&["rm", "gone.txt"]).status.success());
    assert!(h.mkit(&["rm", "gone.txt"]).status.success());
    assert_parity_diff(
        "diff --staged (add+delete)",
        &h.git(&["diff", "--staged"]),
        &h.mkit(&["diff", "--staged"]),
    );
}

#[test]
fn diff_unified_no_newline_at_eof_matches_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("f.txt", b"a\nb\nc\n");
    h.commit_both(&["f.txt"], "init");
    // Drop the trailing newline → `\ No newline at end of file`.
    h.write_both("f.txt", b"a\nb\nc");
    assert_parity_diff(
        "diff (no newline at eof)",
        &h.git(&["diff"]),
        &h.mkit(&["diff"]),
    );
}

#[test]
fn diff_unified_single_line_hunk_matches_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    h.write_both("f.txt", b"old\n");
    h.commit_both(&["f.txt"], "init");
    // A one-line-each change → `@@ -1 +1 @@` (no `,1`).
    h.write_both("f.txt", b"new\n");
    assert_parity_diff(
        "diff (single-line hunk header)",
        &h.git(&["diff"]),
        &h.mkit(&["diff"]),
    );
}

#[test]
fn diff_unified_nul_blob_is_binary_like_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    // A NUL byte makes the blob binary by git's heuristic → `Binary files …`
    // rather than a textual hunk with an embedded NUL.
    h.write_both("b.dat", b"a\0b\n");
    h.commit_both(&["b.dat"], "init");
    h.write_both("b.dat", b"a\0c\n");
    assert_parity_diff(
        "diff (NUL blob is binary)",
        &h.git(&["diff"]),
        &h.mkit(&["diff"]),
    );
}

#[cfg(unix)]
#[test]
fn diff_unified_quotes_special_path_header_like_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    // A tab in the name → git C-quotes the whole `a/…`/`b/…` header token.
    h.write_both("a\tb.txt", b"one\n");
    h.commit_both(&["a\tb.txt"], "init");
    h.write_both("a\tb.txt", b"two\n");
    assert_parity_diff(
        "diff (quoted special path header)",
        &h.git(&["diff"]),
        &h.mkit(&["diff"]),
    );
}

#[test]
fn diff_dir_replaced_by_file_matches_git() {
    if !git_available() {
        return;
    }
    let h = Harness::new();
    h.init_both();
    // c1: `d` is a directory holding a file.
    h.write_both("d/x.txt", b"hi\n");
    h.commit_both(&["d/x.txt"], "c1");
    // c2: replace the directory with a regular file named `d`.
    for repo in [&h.git_repo, &h.mkit_repo] {
        std::fs::remove_dir_all(repo.join("d")).expect("rm dir");
        std::fs::write(repo.join("d"), b"now a file\n").expect("write file d");
    }
    assert!(h.git(&["add", "-A"]).status.success());
    assert!(h.git(&["commit", "-m", "c2"]).status.success());
    assert!(h.mkit(&["add", "-A"]).status.success());
    assert!(h.mkit(&["commit", "-m", "c2"]).status.success());
    // The tree-to-tree diff: `d/x.txt` deleted + `d` added — never a blob
    // read of a tree object.
    assert_parity_diff(
        "diff (dir replaced by file)",
        &h.git(&["diff", "HEAD~1", "HEAD"]),
        &h.mkit(&["diff", "HEAD~1", "HEAD"]),
    );
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
