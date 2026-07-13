//! `--format=json` on the mutating commands unified by issue #710:
//! `commit`, `push`, `pull`, `fetch`, `merge`, `cherry-pick`, `revert`,
//! `rebase`, `stash`, `tag`, and `verify-attest`.
//!
//! One success-case test per command, plus the documented structured
//! failure shapes: CAS rejection for `push`, a conflict for
//! `merge`/`cherry-pick`/`revert`, and a bad signature for
//! `verify-attest`. Parsing is intentionally naive (`contains()` on the
//! known-deterministic key/value substrings) to match the existing
//! `tests/json_outputs.rs` / `tests/log_json.rs` convention, which
//! avoids pulling `serde_json` into the dev-dependency graph.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run_in(cwd: &Path, args: &[&str]) -> Output {
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

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn init_with_commit(content: &[u8]) -> tempfile::TempDir {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    assert!(run_in(td.path(), &["keygen"]).status.success());
    fs::write(td.path().join("a.txt"), content).unwrap();
    assert!(run_in(td.path(), &["add", "a.txt"]).status.success());
    assert!(
        run_in(td.path(), &["commit", "-m", "initial"])
            .status
            .success()
    );
    td
}

fn file_url(dir: &Path) -> String {
    format!("mkit+file://{}", dir.display())
}

// -----------------------------------------------------------------------
// commit
// -----------------------------------------------------------------------

#[test]
fn commit_json_emits_hash_and_parents_on_success() {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    assert!(run_in(td.path(), &["keygen"]).status.success());
    fs::write(td.path().join("a.txt"), b"hello").unwrap();
    assert!(run_in(td.path(), &["add", "a.txt"]).status.success());
    let out = run_in(td.path(), &["commit", "-m", "first", "--format=json"]);
    assert!(out.status.success(), "commit failed: {out:?}");
    let stdout = stdout_of(&out);
    assert!(stdout.contains("\"ok\":true"), "{stdout}");
    assert!(stdout.contains("\"parents\":[]"), "root commit: {stdout}");
    assert!(stdout.contains("\"is_root\":true"), "{stdout}");
    assert!(stdout.contains("\"subject\":\"first\""), "{stdout}");
}

// -----------------------------------------------------------------------
// push
// -----------------------------------------------------------------------

#[test]
fn push_json_emits_ref_update_on_success() {
    let td = init_with_commit(b"hi");
    let remote = tempfile::tempdir().unwrap();
    let url = file_url(remote.path());
    assert!(
        run_in(td.path(), &["remote", "add", "origin", &url])
            .status
            .success()
    );
    let out = run_in(td.path(), &["push", "origin", "--format=json"]);
    assert!(out.status.success(), "push failed: {out:?}");
    let stdout = stdout_of(&out);
    assert!(stdout.contains("\"ok\":true"), "{stdout}");
    assert!(stdout.contains("\"remote\":\"origin\""), "{stdout}");
    assert!(stdout.contains("\"up_to_date\":false"), "{stdout}");
}

#[test]
fn push_json_reports_non_fast_forward_rejection() {
    let td = init_with_commit(b"hi");
    let remote = tempfile::tempdir().unwrap();
    let url = file_url(remote.path());
    assert!(
        run_in(td.path(), &["remote", "add", "origin", &url])
            .status
            .success()
    );
    assert!(run_in(td.path(), &["push", "origin"]).status.success());

    // Simulate the remote moving forward independently so our cached
    // tracking ref no longer matches (same recipe as
    // push_named_remote.rs's non_fast_forward_push_is_rejected_without_force).
    let other = "0".repeat(64);
    fs::write(remote.path().join("refs/heads/main"), format!("{other}\n")).unwrap();

    fs::write(td.path().join("a.txt"), b"hi2").unwrap();
    assert!(run_in(td.path(), &["add", "a.txt"]).status.success());
    assert!(run_in(td.path(), &["commit", "-m", "c2"]).status.success());

    let out = run_in(td.path(), &["push", "--format=json"]);
    assert!(!out.status.success(), "non-ff push must be rejected");
    let stdout = stdout_of(&out);
    assert!(stdout.contains("\"ok\":false"), "{stdout}");
    assert!(stdout.contains("\"rejected\":true"), "{stdout}");
}

// -----------------------------------------------------------------------
// pull / fetch
// -----------------------------------------------------------------------

#[test]
fn pull_json_reports_fast_forward() {
    let td = init_with_commit(b"hi");
    let remote = tempfile::tempdir().unwrap();
    let url = file_url(remote.path());
    assert!(run_in(td.path(), &["remote", "add", &url]).status.success());
    assert!(run_in(td.path(), &["push"]).status.success());

    let clone = tempfile::tempdir().unwrap();
    assert!(run_in(clone.path(), &["init"]).status.success());
    assert!(run_in(clone.path(), &["keygen"]).status.success());
    assert!(
        run_in(clone.path(), &["remote", "add", &url])
            .status
            .success()
    );
    assert!(run_in(clone.path(), &["pull"]).status.success());

    // Advance the origin repo and push again, then pull with --format=json
    // in the clone to observe a real (non-no-op) fast-forward.
    fs::write(td.path().join("a.txt"), b"hi2").unwrap();
    assert!(run_in(td.path(), &["add", "a.txt"]).status.success());
    assert!(run_in(td.path(), &["commit", "-m", "c2"]).status.success());
    assert!(run_in(td.path(), &["push"]).status.success());

    let out = run_in(clone.path(), &["pull", "--format=json"]);
    assert!(out.status.success(), "pull failed: {out:?}");
    let stdout = stdout_of(&out);
    assert!(stdout.contains("\"ok\":true"), "{stdout}");
    assert!(stdout.contains("\"up_to_date\":false"), "{stdout}");
}

#[test]
fn fetch_json_lists_updated_tracking_refs() {
    let td = init_with_commit(b"hi");
    let remote = tempfile::tempdir().unwrap();
    let url = file_url(remote.path());
    assert!(run_in(td.path(), &["remote", "add", &url]).status.success());
    assert!(run_in(td.path(), &["push"]).status.success());

    let clone = tempfile::tempdir().unwrap();
    assert!(run_in(clone.path(), &["init"]).status.success());
    assert!(run_in(clone.path(), &["keygen"]).status.success());
    assert!(
        run_in(clone.path(), &["remote", "add", &url])
            .status
            .success()
    );
    let out = run_in(clone.path(), &["fetch", "--format=json"]);
    assert!(out.status.success(), "fetch failed: {out:?}");
    let stdout = stdout_of(&out);
    assert!(stdout.contains("\"ok\":true"), "{stdout}");
    assert!(stdout.contains("\"updated\":["), "{stdout}");
}

// -----------------------------------------------------------------------
// merge
// -----------------------------------------------------------------------

fn init_two_branches_with_conflict(td: &Path) {
    assert!(run_in(td, &["init"]).status.success());
    assert!(run_in(td, &["keygen"]).status.success());
    fs::write(td.join("a.txt"), b"base\n").unwrap();
    assert!(run_in(td, &["add", "a.txt"]).status.success());
    assert!(run_in(td, &["commit", "-m", "base"]).status.success());
    assert!(run_in(td, &["branch", "feature"]).status.success());

    fs::write(td.join("a.txt"), b"main change\n").unwrap();
    assert!(run_in(td, &["add", "a.txt"]).status.success());
    assert!(
        run_in(td, &["commit", "-m", "main change"])
            .status
            .success()
    );

    assert!(run_in(td, &["checkout", "feature"]).status.success());
    fs::write(td.join("a.txt"), b"feature change\n").unwrap();
    assert!(run_in(td, &["add", "a.txt"]).status.success());
    assert!(
        run_in(td, &["commit", "-m", "feature change"])
            .status
            .success()
    );
    assert!(run_in(td, &["checkout", "main"]).status.success());
}

#[test]
fn merge_json_fast_forward_success() {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    assert!(run_in(td.path(), &["keygen"]).status.success());
    fs::write(td.path().join("a.txt"), b"base").unwrap();
    assert!(run_in(td.path(), &["add", "a.txt"]).status.success());
    assert!(
        run_in(td.path(), &["commit", "-m", "base"])
            .status
            .success()
    );
    assert!(run_in(td.path(), &["branch", "feature"]).status.success());
    assert!(run_in(td.path(), &["checkout", "feature"]).status.success());
    fs::write(td.path().join("a.txt"), b"feature").unwrap();
    assert!(run_in(td.path(), &["add", "a.txt"]).status.success());
    assert!(
        run_in(td.path(), &["commit", "-m", "feature"])
            .status
            .success()
    );
    assert!(run_in(td.path(), &["checkout", "main"]).status.success());

    let out = run_in(td.path(), &["merge", "feature", "--format=json"]);
    assert!(out.status.success(), "merge failed: {out:?}");
    let stdout = stdout_of(&out);
    assert!(stdout.contains("\"ok\":true"), "{stdout}");
    assert!(stdout.contains("\"kind\":\"fast-forward\""), "{stdout}");
}

#[test]
fn merge_json_reports_conflict() {
    let td = tempfile::tempdir().unwrap();
    init_two_branches_with_conflict(td.path());

    let out = run_in(td.path(), &["merge", "feature", "--format=json"]);
    assert!(!out.status.success(), "conflicting merge must fail");
    let stdout = stdout_of(&out);
    assert!(stdout.contains("\"ok\":false"), "{stdout}");
    assert!(stdout.contains("\"kind\":\"conflict\""), "{stdout}");
    assert!(stdout.contains("\"conflicts\":[\"a.txt\"]"), "{stdout}");
}

// -----------------------------------------------------------------------
// cherry-pick
// -----------------------------------------------------------------------

#[test]
fn cherry_pick_json_success() {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    assert!(run_in(td.path(), &["keygen"]).status.success());
    fs::write(td.path().join("a.txt"), b"base").unwrap();
    assert!(run_in(td.path(), &["add", "a.txt"]).status.success());
    assert!(
        run_in(td.path(), &["commit", "-m", "base"])
            .status
            .success()
    );
    assert!(run_in(td.path(), &["branch", "feature"]).status.success());
    assert!(run_in(td.path(), &["checkout", "feature"]).status.success());
    fs::write(td.path().join("b.txt"), b"new file").unwrap();
    assert!(run_in(td.path(), &["add", "b.txt"]).status.success());
    assert!(
        run_in(td.path(), &["commit", "-m", "add b"])
            .status
            .success()
    );
    let picked = fs::read_to_string(td.path().join(".mkit/refs/heads/feature"))
        .unwrap()
        .trim()
        .to_string();
    assert!(run_in(td.path(), &["checkout", "main"]).status.success());

    let out = run_in(td.path(), &["cherry-pick", &picked, "--format=json"]);
    assert!(out.status.success(), "cherry-pick failed: {out:?}");
    let stdout = stdout_of(&out);
    assert!(stdout.contains("\"ok\":true"), "{stdout}");
    assert!(stdout.contains("\"kind\":\"commit\""), "{stdout}");
    assert!(
        stdout.contains(&format!("\"picked\":\"{picked}\"")),
        "{stdout}"
    );
}

#[test]
fn cherry_pick_json_reports_conflict() {
    let td = tempfile::tempdir().unwrap();
    init_two_branches_with_conflict(td.path());
    let picked = fs::read_to_string(td.path().join(".mkit/refs/heads/feature"))
        .unwrap()
        .trim()
        .to_string();

    let out = run_in(td.path(), &["cherry-pick", &picked, "--format=json"]);
    assert!(!out.status.success(), "conflicting pick must fail");
    let stdout = stdout_of(&out);
    assert!(stdout.contains("\"ok\":false"), "{stdout}");
    assert!(stdout.contains("\"kind\":\"conflict\""), "{stdout}");
    assert!(stdout.contains("\"conflicts\":[\"a.txt\"]"), "{stdout}");
}

// -----------------------------------------------------------------------
// revert
// -----------------------------------------------------------------------

#[test]
fn revert_json_success() {
    let td = init_with_commit(b"hi");
    let head = fs::read_to_string(td.path().join(".mkit/refs/heads/main"))
        .unwrap()
        .trim()
        .to_string();
    let out = run_in(td.path(), &["revert", &head, "--format=json"]);
    assert!(out.status.success(), "revert failed: {out:?}");
    let stdout = stdout_of(&out);
    assert!(stdout.contains("\"ok\":true"), "{stdout}");
    assert!(stdout.contains("\"kind\":\"commit\""), "{stdout}");
    assert!(
        stdout.contains(&format!("\"reverted\":\"{head}\"")),
        "{stdout}"
    );
}

// -----------------------------------------------------------------------
// stash
// -----------------------------------------------------------------------

#[test]
fn stash_json_save_list_pop_roundtrip() {
    let td = init_with_commit(b"hi");
    fs::write(td.path().join("a.txt"), b"dirty").unwrap();

    let save = run_in(td.path(), &["stash", "save", "-m", "wip", "--format=json"]);
    assert!(save.status.success(), "stash save failed: {save:?}");
    let save_out = stdout_of(&save);
    assert!(save_out.contains("\"ok\":true"), "{save_out}");
    assert!(save_out.contains("\"kind\":\"save\""), "{save_out}");

    let list = run_in(td.path(), &["stash", "list", "--format=json"]);
    assert!(list.status.success());
    let list_out = stdout_of(&list);
    assert!(list_out.contains("\"index\":0"), "{list_out}");
    assert!(
        list_out.contains("\"message\":\"On main: wip\""),
        "{list_out}"
    );

    let pop = run_in(td.path(), &["stash", "pop", "--format=json"]);
    assert!(pop.status.success(), "stash pop failed: {pop:?}");
    let pop_out = stdout_of(&pop);
    assert!(pop_out.contains("\"ok\":true"), "{pop_out}");
    assert!(pop_out.contains("\"kind\":\"pop\""), "{pop_out}");
}

// -----------------------------------------------------------------------
// tag
// -----------------------------------------------------------------------

#[test]
fn tag_json_lightweight_create_and_list() {
    let td = init_with_commit(b"hi");
    let create = run_in(td.path(), &["tag", "v1", "--format=json"]);
    assert!(create.status.success(), "tag create failed: {create:?}");
    let create_out = stdout_of(&create);
    assert!(create_out.contains("\"ok\":true"), "{create_out}");
    assert!(
        create_out.contains("\"kind\":\"lightweight\""),
        "{create_out}"
    );
    assert!(create_out.contains("\"name\":\"v1\""), "{create_out}");

    let list = run_in(td.path(), &["tag", "--format=json"]);
    assert!(list.status.success());
    let list_out = stdout_of(&list);
    assert!(list_out.contains("\"name\":\"v1\""), "{list_out}");
    assert!(list_out.contains("\"annotated\":false"), "{list_out}");
}

// -----------------------------------------------------------------------
// verify-attest
// -----------------------------------------------------------------------

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn verify_attest_json_reports_verified_signature() {
    let td = init_with_commit(b"hi");
    let pubkey = run_in(td.path(), &["keygen", "--print-pubkey"]);
    // `keygen` already ran once via `init_with_commit`; re-running with
    // `--print-pubkey` on an existing key just prints it back out
    // (idempotent read path), so this does not rotate the key.
    assert!(pubkey.status.success(), "keygen --print-pubkey: {pubkey:?}");
    let printed = stdout_of(&pubkey).trim().to_string();
    let hex = printed.strip_prefix("ed25519:").unwrap().to_string();

    let attest = run_in(td.path(), &["attest", "--algorithm", "ed25519"]);
    assert!(attest.status.success(), "attest failed: {attest:?}");

    // The repo-key signer's DSSE signature carries a `blake3:<digest>`
    // keyid (digest of the raw pubkey bytes), not `ed25519:<hex>` — see
    // `keyid_matches_pubkey` in `commands/verify_attest.rs`.
    let pk_bytes = hex_decode(&hex);
    let digest = mkit_core::hash::hash(&pk_bytes);
    let keyid = format!("blake3:{}", mkit_core::hash::to_hex(&digest));

    let trust_roots = td.path().join("trust-roots.toml");
    fs::write(
        &trust_roots,
        format!(
            "[[trust_root]]\nkeyid = \"{keyid}\"\nkind = \"ed25519\"\npubkey_hex = \"{hex}\"\n"
        ),
    )
    .unwrap();

    let out = run_in(
        td.path(),
        &[
            "verify-attest",
            "--trust-roots",
            trust_roots.to_str().unwrap(),
            "--format=json",
        ],
    );
    assert!(out.status.success(), "verify-attest failed: {out:?}");
    let stdout = stdout_of(&out);
    assert!(stdout.contains("\"ok\":true"), "{stdout}");
    assert!(stdout.contains("\"verified\":true"), "{stdout}");
}

#[test]
fn verify_attest_json_reports_unverified_signature_for_unknown_keyid() {
    let td = init_with_commit(b"hi");
    let attest = run_in(td.path(), &["attest", "--algorithm", "ed25519"]);
    assert!(attest.status.success(), "attest failed: {attest:?}");

    // Trust-roots naming a DIFFERENT (fabricated) key: the real
    // signature's keyid won't resolve, so it reports UnknownKeyid /
    // verified:false rather than "ok".
    let bogus_hex = "ab".repeat(32);
    let trust_roots = td.path().join("trust-roots.toml");
    fs::write(
        &trust_roots,
        format!(
            "[[trust_root]]\nkeyid = \"ed25519:{bogus_hex}\"\nkind = \"ed25519\"\npubkey_hex = \"{bogus_hex}\"\n"
        ),
    )
    .unwrap();

    let out = run_in(
        td.path(),
        &[
            "verify-attest",
            "--trust-roots",
            trust_roots.to_str().unwrap(),
            "--format=json",
        ],
    );
    assert!(
        !out.status.success(),
        "unverifiable attestation must not exit 0"
    );
    let stdout = stdout_of(&out);
    assert!(stdout.contains("\"ok\":false"), "{stdout}");
    assert!(stdout.contains("\"verified\":false"), "{stdout}");
}

// -----------------------------------------------------------------------
// rebase
// -----------------------------------------------------------------------

#[test]
fn rebase_json_reports_up_to_date() {
    let td = init_with_commit(b"hi");
    assert!(run_in(td.path(), &["branch", "feature"]).status.success());
    let out = run_in(td.path(), &["rebase", "feature", "--format=json"]);
    assert!(out.status.success(), "rebase failed: {out:?}");
    let stdout = stdout_of(&out);
    assert!(stdout.contains("\"ok\":true"), "{stdout}");
    assert!(stdout.contains("\"kind\":\"up-to-date\""), "{stdout}");
}

#[test]
fn rebase_json_reports_conflict() {
    let td = tempfile::tempdir().unwrap();
    init_two_branches_with_conflict(td.path());
    // On `main`, rebase onto `feature` — replays main's own commit
    // (the divergent `a.txt` change) on top of feature's tip, conflicting.
    let out = run_in(td.path(), &["rebase", "feature", "--format=json"]);
    assert!(!out.status.success(), "conflicting rebase must fail");
    let stdout = stdout_of(&out);
    assert!(stdout.contains("\"ok\":false"), "{stdout}");
    assert!(stdout.contains("\"kind\":\"conflict\""), "{stdout}");
}
