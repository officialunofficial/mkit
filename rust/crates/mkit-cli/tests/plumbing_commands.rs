//! Read-only plumbing — `rev-parse` / `cat-file` / `ls-tree` / `ls-files` /
//! `show-ref` / `for-each-ref` / `symbolic-ref` (#251, Phase 3). Covers the
//! mkit-specific paths the differential harness can't compare (abbreviated
//! BLAKE3 ids, repo-root path, `-z`, detached HEAD, unsupported format atoms).

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Output, Stdio};

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run_in(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    std::process::Command::new(mkit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .output()
        .expect("spawn mkit")
}

fn run_in_stdin(cwd: &Path, xdg: &Path, args: &[&str], input: &[u8]) -> Output {
    let mut child = std::process::Command::new(mkit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mkit");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input)
        .expect("write stdin");
    child.wait_with_output().expect("output")
}

fn repo() -> (tempfile::TempDir, tempfile::TempDir) {
    let td = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let (root, x) = (td.path(), xdg.path());
    assert!(run_in(root, x, &["init"]).status.success());
    assert!(run_in(root, x, &["keygen"]).status.success());
    fs::write(root.join("file.txt"), b"hello\n").unwrap();
    fs::create_dir(root.join("sub")).unwrap();
    fs::write(root.join("sub/inner.txt"), b"nested\n").unwrap();
    assert!(run_in(root, x, &["add", "."]).status.success());
    assert!(run_in(root, x, &["commit", "-m", "init"]).status.success());
    (td, xdg)
}

fn out_str(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

#[test]
fn rev_parse_full_short_and_abbrev_ref() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());

    let full = out_str(&run_in(root, x, &["rev-parse", "HEAD"]));
    assert_eq!(full.len(), 64, "full id is 64-hex: {full:?}");
    assert!(full.chars().all(|c| c.is_ascii_hexdigit()));

    let short = out_str(&run_in(root, x, &["rev-parse", "--short", "HEAD"]));
    assert_eq!(short.len(), 7, "default --short is 7 chars: {short:?}");
    assert!(full.starts_with(&short), "short is a prefix of full");

    let short10 = out_str(&run_in(root, x, &["rev-parse", "--short=10", "HEAD"]));
    assert_eq!(short10.len(), 10);

    assert_eq!(
        out_str(&run_in(root, x, &["rev-parse", "--abbrev-ref", "HEAD"])),
        "main"
    );
}

#[test]
fn rev_parse_show_toplevel_is_repo_root() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    // Run from a subdirectory; --show-toplevel still finds the root.
    let out = run_in(&root.join("sub"), x, &["rev-parse", "--show-toplevel"]);
    assert!(out.status.success(), "show-toplevel failed: {out:?}");
    let printed = out_str(&out);
    let canon = fs::canonicalize(root).unwrap();
    assert_eq!(
        fs::canonicalize(&printed).unwrap(),
        canon,
        "show-toplevel should print the repo root"
    );
}

#[test]
fn rev_parse_bad_revision_errors() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    let out = run_in(root, x, &["rev-parse", "no-such-ref"]);
    assert!(!out.status.success(), "bad rev must error: {out:?}");
}

#[test]
fn cat_file_type_of_commit_and_tree() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    assert_eq!(
        out_str(&run_in(root, x, &["cat-file", "-t", "HEAD"])),
        "commit"
    );
    // A blob's type via its hash extracted from ls-tree.
    let ls = out_str(&run_in(root, x, &["ls-tree", "HEAD"]));
    let blob = ls
        .lines()
        .find(|l| l.ends_with("file.txt"))
        .and_then(|l| l.split_whitespace().nth(2))
        .unwrap()
        .to_string();
    assert_eq!(
        out_str(&run_in(root, x, &["cat-file", "-t", &blob])),
        "blob"
    );
    assert_eq!(out_str(&run_in(root, x, &["cat-file", "-s", &blob])), "6");
}

#[test]
fn cat_file_requires_a_flag() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    let out = run_in(root, x, &["cat-file", "HEAD"]);
    assert!(
        !out.status.success(),
        "cat-file without -t/-s/-p must error: {out:?}"
    );
}

#[test]
fn ls_tree_z_is_nul_terminated_and_recurses() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    let out = run_in(root, x, &["ls-tree", "-r", "-z", "HEAD"]);
    assert!(out.status.success(), "ls-tree -rz failed: {out:?}");
    let raw = String::from_utf8_lossy(&out.stdout);
    assert!(raw.ends_with('\0'), "records are NUL-terminated: {raw:?}");
    assert!(!raw.contains('\n'), "no newlines in -z output: {raw:?}");
    assert!(
        raw.contains("sub/inner.txt\0"),
        "recursed path present: {raw:?}"
    );
}

#[test]
fn ls_tree_pathspec_descends_into_subtree() {
    // A pathspec naming a file inside a sub-tree must resolve to that blob,
    // like git (the non-recursive walk has to descend the named path).
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());

    let file = out_str(&run_in(root, x, &["ls-tree", "HEAD", "sub/inner.txt"]));
    assert!(
        file.ends_with("\tsub/inner.txt") && file.contains(" blob "),
        "expected the blob for sub/inner.txt, got: {file:?}"
    );
    // The directory name alone prints the tree line.
    let dir = out_str(&run_in(root, x, &["ls-tree", "HEAD", "sub"]));
    assert!(
        dir.contains(" tree ") && dir.ends_with("\tsub"),
        "expected tree line: {dir:?}"
    );
    // A trailing slash lists the directory's contents.
    let contents = out_str(&run_in(root, x, &["ls-tree", "HEAD", "sub/"]));
    assert!(
        contents.ends_with("\tsub/inner.txt"),
        "expected contents listing: {contents:?}"
    );
}

#[test]
fn show_ref_exits_nonzero_when_namespace_empty() {
    // git returns exit 1 when nothing matches; a repo with a commit (so a
    // branch) but no tags must make `show-ref --tags` fail.
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    let out = run_in(root, x, &["show-ref", "--tags"]);
    assert!(
        !out.status.success(),
        "show-ref --tags with no tags must exit non-zero: {out:?}"
    );
    assert!(out.stdout.is_empty(), "no output expected: {out:?}");
    // --heads still succeeds (the default branch exists).
    assert!(run_in(root, x, &["show-ref", "--heads"]).status.success());
}

#[test]
fn show_ref_heads_and_tags_filter() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    assert!(run_in(root, x, &["tag", "v1"]).status.success());

    let all = out_str(&run_in(root, x, &["show-ref"]));
    assert!(all.contains("refs/heads/main"), "all: {all:?}");
    assert!(all.contains("refs/tags/v1"), "all: {all:?}");

    let heads = out_str(&run_in(root, x, &["show-ref", "--heads"]));
    assert!(
        heads.contains("refs/heads/main") && !heads.contains("refs/tags/"),
        "heads: {heads:?}"
    );

    let tags = out_str(&run_in(root, x, &["show-ref", "--tags"]));
    assert!(
        tags.contains("refs/tags/v1") && !tags.contains("refs/heads/"),
        "tags: {tags:?}"
    );
}

#[test]
fn cat_file_batch_emits_header_and_content() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    let full = out_str(&run_in(root, x, &["rev-parse", "HEAD"]));
    // One known commit + one unknown id → `<hash> commit <size>` + content,
    // then `<name> missing` for the bad id.
    let bad = "f".repeat(64);
    let input = format!("{full}\n{bad}\n");
    let out = run_in_stdin(root, x, &["cat-file", "--batch"], input.as_bytes());
    assert!(out.status.success(), "batch failed: {out:?}");
    let text = String::from_utf8_lossy(&out.stdout);
    let header = text.lines().next().unwrap_or("");
    let mut fields = header.split_whitespace();
    assert_eq!(
        fields.next(),
        Some(full.as_str()),
        "header hash: {header:?}"
    );
    assert_eq!(fields.next(), Some("commit"), "header type: {header:?}");
    let size: usize = fields.next().unwrap().parse().expect("size is a number");
    assert!(size > 0, "commit content is non-empty: {header:?}");
    assert!(
        text.contains(&format!("{bad} missing")),
        "unknown id reported missing: {text:?}"
    );
}

#[test]
fn cat_file_batch_one_record_per_line_no_trim() {
    // git emits one record per input line without trimming: a blank line is
    // an empty (unresolvable) name → ` missing`, and a name padded with
    // spaces stays unresolved (no sneaky `HEAD` lookup). mkit must match.
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    // Three input lines: blank, " HEAD " (padded), and a real id.
    let full = out_str(&run_in(root, x, &["rev-parse", "HEAD"]));
    let input = format!("\n HEAD \n{full}\n");
    let out = run_in_stdin(root, x, &["cat-file", "--batch"], input.as_bytes());
    assert!(out.status.success(), "batch failed: {out:?}");
    let text = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = text.lines().collect();
    // Line 1: blank name → ` missing` (leading space, name is empty).
    assert_eq!(lines[0], " missing", "blank line → ` missing`: {text:?}");
    // Line 2: padded ` HEAD ` is not trimmed → unresolved missing record.
    assert_eq!(
        lines[1], " HEAD  missing",
        "padded HEAD stays missing: {text:?}"
    );
    // The real id still resolves to a `commit` header afterwards.
    assert!(lines[2].contains(" commit "), "real id resolves: {text:?}");
}

#[test]
fn ls_files_lists_tracked_with_stage_info() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    // Default: tracked paths, sorted, one per line.
    let plain = out_str(&run_in(root, x, &["ls-files"]));
    assert_eq!(
        plain, "file.txt\nsub/inner.txt",
        "tracked listing: {plain:?}"
    );
    // `-s` prepends `<mode> <hash> 0` with a 64-hex BLAKE3 id, stage 0.
    let staged = out_str(&run_in(root, x, &["ls-files", "-s"]));
    let first = staged.lines().next().unwrap_or("");
    let mut f = first.split_whitespace();
    assert_eq!(f.next(), Some("100644"), "git mode: {first:?}");
    assert_eq!(f.next().map(str::len), Some(64), "64-hex hash: {first:?}");
    assert_eq!(f.next(), Some("0"), "stage is 0: {first:?}");
    assert!(first.ends_with("\tfile.txt"), "tab + path: {first:?}");
}

#[test]
fn ls_files_others_and_ignored_filters() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    fs::write(root.join(".mkitignore"), b"*.log\n").unwrap();
    fs::write(root.join("new.txt"), b"n\n").unwrap();
    fs::write(root.join("debug.log"), b"d\n").unwrap();
    // --others lists every untracked file (ignored ones included).
    let others = out_str(&run_in(root, x, &["ls-files", "--others"]));
    assert!(others.contains("new.txt"), "others: {others:?}");
    assert!(
        others.contains("debug.log"),
        "others includes ignored: {others:?}"
    );
    // --exclude-standard drops the ignored `debug.log`.
    let excl = out_str(&run_in(
        root,
        x,
        &["ls-files", "--others", "--exclude-standard"],
    ));
    assert!(excl.contains("new.txt"), "excl keeps new.txt: {excl:?}");
    assert!(!excl.contains("debug.log"), "excl drops ignored: {excl:?}");
    // --ignored shows only the ignored file.
    let ign = out_str(&run_in(root, x, &["ls-files", "--others", "--ignored"]));
    assert!(ign.contains("debug.log"), "ignored shows it: {ign:?}");
    assert!(!ign.contains("new.txt"), "ignored excludes others: {ign:?}");
}

#[test]
fn ls_files_ignored_without_others_errors() {
    // `--ignored` only filters the `--others` walk; alone it must fail
    // closed (git rejects `-i` outside an `-o`/`-c` selection) rather than
    // silently printing the tracked listing.
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    let out = run_in(root, x, &["ls-files", "--ignored"]);
    assert!(
        !out.status.success(),
        "ls-files --ignored without --others must error: {out:?}"
    );
    assert!(out.stdout.is_empty(), "no tracked listing leaked: {out:?}");
}

#[cfg(unix)]
#[test]
fn ls_files_stage_quotes_special_paths() {
    // `-s` (no `-z`) must C-quote special-byte pathnames like the default
    // listing does — git's `core.quotePath` default.
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    fs::write(root.join("a\tb.txt"), b"x\n").unwrap();
    assert!(run_in(root, x, &["add", "a\tb.txt"]).status.success());
    let staged = out_str(&run_in(root, x, &["ls-files", "-s"]));
    assert!(
        staged.contains("\t\"a\\tb.txt\""),
        "tab path C-quoted in -s output: {staged:?}"
    );
    // `-z` keeps the raw byte (no quoting, NUL-terminated).
    let z = run_in(root, x, &["ls-files", "-s", "-z"]);
    let raw = String::from_utf8_lossy(&z.stdout);
    assert!(
        raw.contains("\ta\tb.txt\0"),
        "raw tab path under -z: {raw:?}"
    );
}

#[test]
fn cat_file_batch_rejects_object_argument() {
    // git: "batch modes take no arguments". A stray object arg must error,
    // not silently ignore it.
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    let out = run_in(root, x, &["cat-file", "--batch", "HEAD"]);
    assert!(
        !out.status.success(),
        "cat-file --batch with an object arg must error: {out:?}"
    );
}

#[test]
fn for_each_ref_pattern_with_trailing_slash_matches() {
    // Both `refs/heads` and `refs/heads/` must select branch refs (the
    // trailing slash must not turn into an empty `refs/heads//` component).
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    assert!(run_in(root, x, &["tag", "v1"]).status.success());
    for pattern in ["refs/heads", "refs/heads/"] {
        let out = out_str(&run_in(root, x, &["for-each-ref", pattern]));
        assert!(
            out.contains("\trefs/heads/main") && !out.contains("refs/tags/"),
            "pattern {pattern:?} should list only branch refs: {out:?}"
        );
    }
}

#[test]
fn for_each_ref_default_and_format() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    assert!(run_in(root, x, &["tag", "v1"]).status.success());
    // Default `<oid> <objecttype>\t<refname>`, sorted (heads before tags).
    let def = out_str(&run_in(root, x, &["for-each-ref"]));
    let lines: Vec<&str> = def.lines().collect();
    assert!(lines[0].ends_with("\trefs/heads/main"), "head row: {def:?}");
    assert!(lines[0].contains(" commit\t"), "head is a commit: {def:?}");
    assert!(
        lines.iter().any(|l| l.ends_with("\trefs/tags/v1")),
        "tag row present: {def:?}"
    );
    // A custom format with the short-name atom.
    let fmt = out_str(&run_in(
        root,
        x,
        &["for-each-ref", "--format=%(refname:short)"],
    ));
    assert!(
        fmt.lines().any(|l| l == "main") && fmt.lines().any(|l| l == "v1"),
        "short refnames: {fmt:?}"
    );
}

#[test]
fn for_each_ref_rejects_unknown_atom() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    let out = run_in(root, x, &["for-each-ref", "--format=%(bogus)"]);
    assert!(!out.status.success(), "unknown %(atom) must error: {out:?}");
}

#[test]
fn symbolic_ref_reads_head() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    assert_eq!(
        out_str(&run_in(root, x, &["symbolic-ref", "HEAD"])),
        "refs/heads/main"
    );
    assert_eq!(
        out_str(&run_in(root, x, &["symbolic-ref", "--short", "HEAD"])),
        "main"
    );
}

#[test]
fn symbolic_ref_errors_on_detached_and_non_head() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    // A non-HEAD name is unsupported (mkit reads only HEAD).
    assert!(
        !run_in(root, x, &["symbolic-ref", "refs/heads/main"])
            .status
            .success(),
        "non-HEAD symbolic-ref must error"
    );
    // Detached HEAD is not a symbolic ref → error, like git.
    let full = out_str(&run_in(root, x, &["rev-parse", "HEAD"]));
    assert!(run_in(root, x, &["checkout", &full]).status.success());
    let out = run_in(root, x, &["symbolic-ref", "HEAD"]);
    assert!(!out.status.success(), "detached HEAD must error: {out:?}");
}

#[test]
fn update_ref_create_update_and_cas() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    let head = out_str(&run_in(root, x, &["rev-parse", "HEAD"]));
    // Create refs/heads/feature at HEAD.
    assert!(
        run_in(root, x, &["update-ref", "refs/heads/feature", "HEAD"])
            .status
            .success()
    );
    assert_eq!(out_str(&run_in(root, x, &["rev-parse", "feature"])), head);

    // Second commit so the branch can move to a new value.
    fs::write(root.join("z.txt"), b"z\n").unwrap();
    assert!(run_in(root, x, &["add", "z.txt"]).status.success());
    assert!(run_in(root, x, &["commit", "-m", "c2"]).status.success());
    let head2 = out_str(&run_in(root, x, &["rev-parse", "HEAD"]));

    // CAS with the correct old value succeeds.
    assert!(
        run_in(
            root,
            x,
            &["update-ref", "refs/heads/feature", &head2, &head]
        )
        .status
        .success()
    );
    assert_eq!(out_str(&run_in(root, x, &["rev-parse", "feature"])), head2);
    // CAS with the wrong old value fails (current is head2, not head).
    assert!(
        !run_in(root, x, &["update-ref", "refs/heads/feature", &head, &head])
            .status
            .success(),
        "stale CAS must fail"
    );
    // All-zero old = "must be absent": fails for an existing ref...
    let zero = "0".repeat(64);
    assert!(
        !run_in(
            root,
            x,
            &["update-ref", "refs/heads/feature", &head2, &zero]
        )
        .status
        .success(),
        "create-only on an existing ref must fail"
    );
    // ...but succeeds for a brand-new ref.
    assert!(
        run_in(root, x, &["update-ref", "refs/heads/fresh", &head2, &zero])
            .status
            .success()
    );
}

#[test]
fn update_ref_delete_and_guards() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    // Create then delete a tag ref.
    assert!(
        run_in(root, x, &["update-ref", "refs/tags/v9", "HEAD"])
            .status
            .success()
    );
    assert!(out_str(&run_in(root, x, &["show-ref", "--tags"])).contains("refs/tags/v9"));
    assert!(
        run_in(root, x, &["update-ref", "-d", "refs/tags/v9"])
            .status
            .success()
    );
    assert!(
        !run_in(root, x, &["show-ref", "--tags"]).status.success(),
        "tag namespace empty after delete"
    );
    // Deleting the current branch is refused (mkit safety divergence).
    assert!(
        !run_in(root, x, &["update-ref", "-d", "refs/heads/main"])
            .status
            .success(),
        "delete of current branch must be refused"
    );
    // Unsupported namespace is rejected.
    assert!(
        !run_in(root, x, &["update-ref", "refs/remotes/origin/main", "HEAD"])
            .status
            .success(),
        "unsupported ref namespace must error"
    );
}

#[test]
fn symbolic_ref_write_repoints_head() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    assert!(
        run_in(root, x, &["update-ref", "refs/heads/feature", "HEAD"])
            .status
            .success()
    );
    // Repoint HEAD at the branch (plumbing form).
    assert!(
        run_in(root, x, &["symbolic-ref", "HEAD", "refs/heads/feature"])
            .status
            .success()
    );
    assert_eq!(
        out_str(&run_in(root, x, &["symbolic-ref", "HEAD"])),
        "refs/heads/feature"
    );
    // A non-refs/heads target is rejected.
    assert!(
        !run_in(root, x, &["symbolic-ref", "HEAD", "refs/tags/v1"])
            .status
            .success(),
        "HEAD can only point at a branch"
    );
}

#[test]
fn config_core_allowlist_and_rejects_dangerous() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    // An allowlisted inert key round-trips...
    assert!(
        run_in(root, x, &["config", "core.autocrlf", "true"])
            .status
            .success()
    );
    assert_eq!(
        out_str(&run_in(root, x, &["config", "core.autocrlf"])),
        "true"
    );
    // ...and matches case-insensitively on BOTH the variable name and the
    // section (git lowercases both).
    assert_eq!(
        out_str(&run_in(root, x, &["config", "core.AutoCRLF"])),
        "true"
    );
    assert_eq!(
        out_str(&run_in(root, x, &["config", "Core.autocrlf"])),
        "true"
    );
    // Setting via a mixed-case section also works (canonicalizes to lower).
    assert!(
        run_in(root, x, &["config", "CORE.IgnoreCase", "false"])
            .status
            .success()
    );
    assert_eq!(
        out_str(&run_in(root, x, &["config", "core.ignorecase"])),
        "false"
    );
    // A dangerous key is rejected, not stored.
    assert!(
        !run_in(root, x, &["config", "core.sshCommand", "evil"])
            .status
            .success(),
        "core.sshCommand must be rejected"
    );
    // An unknown core key is rejected too.
    assert!(
        !run_in(root, x, &["config", "core.bogus", "x"])
            .status
            .success(),
        "unknown core key must be rejected"
    );
}
