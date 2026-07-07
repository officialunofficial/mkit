//! End-to-end coverage for the `mkit+ssh://` transport and the issue
//! #389 trust-pinning wiring.
//!
//! ## What this proves
//!
//! 1. A full `mkit clone mkit+ssh://…` moves real data through the SSH
//!    transport: the `Hello` handshake, ref negotiation, and upload-pack
//!    all run against a real `mkit serve` on the far side. The cloned
//!    repo's HEAD ref and object content MATCH the source.
//!
//! 2. The per-repo `ssh.*` trust-pinning config keys
//!    (`ssh.strict_host_key_checking`, `ssh.user_known_hosts_file`,
//!    `ssh.identity_file`) actually reach the spawned `ssh` program as
//!    `-o StrictHostKeyChecking=…`, `-o UserKnownHostsFile=…`, and
//!    `-i …`. Before the #389 fix these keys were parsed into `Config`
//!    but never threaded into `SshOptions`, so the recorded argv would
//!    lack them — this test FAILS on the pre-fix code and PASSES after.
//!
//! ## How it stays hermetic
//!
//! `build_ssh_command` honours `MKIT_SSH_PROGRAM` (the testability seam
//! added for #389). We point it at a generated `/bin/sh` wrapper that:
//!
//!   (a) appends its entire argv to `$MKIT_SSH_ARGV_LOG`, then
//!   (b) finds the `mkit` token in that argv and `exec`s
//!       `$MKIT_SSH_TARGET_BIN serve <path>` locally with inherited
//!       stdin/stdout — i.e. it replaces the network hop with a local
//!       `mkit serve`, while still exercising the real wire protocol.
//!
//! Both env vars are set on the `mkit clone` process and inherited by the
//! spawned wrapper, so the script body stays fully static (no path is
//! interpolated into shell source).
//!
//! No sshd, no network, no `ssh` binary required. The higher-fidelity
//! real-`ssh(1)` variant lives in `ssh_e2e_real.rs` and is `#[ignore]`d.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use mkit_core::layout::RepoLayout;
use mkit_core::ops::reachable_objects;
use mkit_core::refs;
use mkit_core::store::ObjectStore;

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

/// Drive the real `mkit` binary, fully isolated from the developer's
/// environment. `extra_env` lets a test add the `MKIT_SSH_*` vars.
fn run_in(cwd: &Path, xdg: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(mkit_bin());
    cmd.args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .env("HOME", xdg)
        .env("EDITOR", "true")
        .env("VISUAL", "true")
        .stdin(Stdio::null());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output().expect("spawn mkit")
}

/// Write the hermetic ssh-wrapper script and `chmod +x` it. The script
/// records its argv and execs `$MKIT_SSH_TARGET_BIN serve <path>`.
///
/// All dynamic inputs (the argv log path, the target binary) arrive via
/// the environment, so the script body is fully static — no path is
/// interpolated into shell source, leaving no injection surface. The
/// caller sets `MKIT_SSH_ARGV_LOG` and `MKIT_SSH_TARGET_BIN` on the
/// `mkit clone` process; `build_ssh_command` spawns this wrapper without
/// clearing the environment, so both vars reach it.
fn write_ssh_wrapper(dir: &Path) -> std::path::PathBuf {
    let wrapper = dir.join("fake_ssh.sh");
    // `set -eu`: fail loud on any error and on a missing MKIT_SSH_* var
    // rather than silently logging to nowhere or exec'ing an empty path.
    let script = r#"#!/bin/sh
set -eu

# Record the full argv this wrapper was invoked with, one token per line,
# framed by a record separator so the test can scan a single invocation.
{
  echo "=== ssh invocation ==="
  for a in "$@"; do
    printf '%s\n' "$a"
  done
} >> "$MKIT_SSH_ARGV_LOG"

# Find the `mkit serve <path>` triple at the tail of the argv and exec it
# locally. We walk forward to the literal `mkit` token; everything after
# `mkit serve` is the path.
found=0
path=""
for a in "$@"; do
  if [ "$found" = 2 ]; then
    path="$a"
    break
  fi
  if [ "$found" = 1 ] && [ "$a" = serve ]; then
    found=2
    continue
  fi
  if [ "$a" = mkit ]; then
    found=1
  fi
done

if [ -z "$path" ]; then
  echo "fake_ssh: could not locate 'mkit serve <path>' in argv" >&2
  exit 64
fi

exec "$MKIT_SSH_TARGET_BIN" serve "$path"
"#;
    fs::write(&wrapper, script).expect("write wrapper");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&wrapper).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&wrapper, perms).unwrap();
    }
    wrapper
}

/// Build a source repo with real committed content, then push it to a
/// freshly-initialised `remote` repo so the remote carries the packmap
/// refs that `clone` reconstructs from. Returns the served `remote`
/// repo path.
///
/// mkit's transfer dialect is packmap-only: a branch tip is only
/// fetchable once a push has advertised `refs/mkit/packmap/<branch>`. A
/// repo that was merely committed-to (never pushed) advertises no
/// packmap, so cloning it yields zero refs. We therefore serve a
/// push-populated remote, exactly as a real deployment would.
fn build_and_push_source(root: &Path, xdg: &Path) -> std::path::PathBuf {
    let source = root.join("source");
    fs::create_dir_all(&source).unwrap();
    assert!(
        run_in(&source, xdg, &["init"], &[]).status.success(),
        "init source"
    );
    assert!(
        run_in(&source, xdg, &["keygen"], &[]).status.success(),
        "keygen source"
    );
    fs::write(source.join("README.md"), b"# e2e ssh project\n").unwrap();
    fs::create_dir_all(source.join("src")).unwrap();
    fs::write(
        source.join("src/main.rs"),
        b"fn main() { println!(\"hi\"); }\n",
    )
    .unwrap();
    assert!(
        run_in(&source, xdg, &["add", "."], &[]).status.success(),
        "add source"
    );
    let commit = run_in(&source, xdg, &["commit", "-m", "e2e-1"], &[]);
    assert!(
        commit.status.success(),
        "commit source: {}",
        String::from_utf8_lossy(&commit.stderr)
    );

    let remote = root.join("remote");
    fs::create_dir_all(&remote).unwrap();
    assert!(
        run_in(&remote, xdg, &["init"], &[]).status.success(),
        "init remote"
    );
    let remote_url = format!("mkit+file://{}", remote.display());
    assert!(
        run_in(&source, xdg, &["remote", "add", "origin", &remote_url], &[])
            .status
            .success(),
        "remote add"
    );
    let push = run_in(&source, xdg, &["push", "origin"], &[]);
    assert!(
        push.status.success(),
        "push source -> remote: {}",
        String::from_utf8_lossy(&push.stderr)
    );
    remote
}

#[test]
fn ssh_clone_moves_data_and_delivers_pinned_options() {
    // Skip cleanly on non-unix where the /bin/sh wrapper can't run.
    if cfg!(not(unix)) {
        eprintln!("ssh_e2e: skipped (requires a POSIX shell)");
        return;
    }

    let work = tempfile::tempdir().expect("work tempdir");
    let xdg = tempfile::tempdir().expect("xdg tempdir");
    let root = work.path();

    // --- Source repo with real content, pushed to a served remote -------
    let remote = build_and_push_source(root, xdg.path());
    let source = root.join("source");
    let source_tip = refs::read_ref(&RepoLayout::single(&source), "main")
        .unwrap()
        .expect("source has refs/heads/main");

    // --- Pinned trust options: real files on disk -----------------------
    let known_hosts = root.join("project.known_hosts");
    fs::write(&known_hosts, b"# pinned known hosts for e2e\n").unwrap();
    let identity = root.join("id_ed25519_e2e");
    fs::write(&identity, b"-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n").unwrap();
    // Must NOT be "accept-new": `build_ssh_command` emits
    // `StrictHostKeyChecking=accept-new` as its default baseline whenever
    // the configured value is empty, so an `accept-new` pin would pass the
    // assertion below even on pre-fix code. "yes" is only ever produced by
    // the live Config→SshOptions wiring, making the assertion discriminating.
    // The hermetic `fake_ssh.sh` shim ignores all `-o` options, so the
    // clone still succeeds regardless of the value.
    let strict_value = "yes";

    // Set the three ssh.* keys in the USER-scoped config (they are
    // REPO_FORBIDDEN_KEYS, so only user scope may set them). `mkit
    // config <key> <val>` writes to $XDG_CONFIG_HOME/mkit/config.
    for (key, val) in [
        ("ssh.strict_host_key_checking", strict_value),
        ("ssh.user_known_hosts_file", known_hosts.to_str().unwrap()),
        ("ssh.identity_file", identity.to_str().unwrap()),
    ] {
        let out = run_in(root, xdg.path(), &["config", key, val], &[]);
        assert!(
            out.status.success(),
            "set {key}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // --- Hermetic ssh wrapper -------------------------------------------
    let argv_log = root.join("ssh_argv.log");
    let wrapper = write_ssh_wrapper(root);

    // --- Clone over mkit+ssh:// -----------------------------------------
    // We serve the push-populated `remote` repo (it carries the packmap
    // refs `clone` reconstructs from). The path must satisfy the strict
    // ssh-path charset (`[A-Za-z0-9._-/]`); tempdir paths qualify.
    let remote_path = remote.to_str().unwrap();
    let url = format!("mkit+ssh://e2euser@localhost{remote_path}");
    let dest = root.join("dest");
    let dest_str = dest.to_str().unwrap();

    let clone = run_in(
        root,
        xdg.path(),
        &["clone", &url, dest_str],
        &[
            ("MKIT_SSH_PROGRAM", wrapper.to_str().unwrap()),
            ("MKIT_SSH_ARGV_LOG", argv_log.to_str().unwrap()),
            ("MKIT_SSH_TARGET_BIN", mkit_bin()),
        ],
    );
    assert!(
        clone.status.success(),
        "clone over ssh must succeed; stderr:\n{}",
        String::from_utf8_lossy(&clone.stderr)
    );

    // --- (b) HEAD ref + object closure MATCH the source -----------------
    let dest_tip = refs::read_ref(&RepoLayout::single(&dest), "main")
        .unwrap()
        .expect("cloned repo has refs/heads/main");
    assert_eq!(
        source_tip, dest_tip,
        "cloned HEAD must equal source HEAD (real ref negotiation)"
    );

    let source_store = ObjectStore::open(&RepoLayout::single(&source)).unwrap();
    let dest_store = ObjectStore::open(&RepoLayout::single(&dest)).unwrap();
    let source_set: HashSet<_> = reachable_objects(&source_store, &source_tip)
        .unwrap()
        .into_iter()
        .collect();
    let dest_set: HashSet<_> = reachable_objects(&dest_store, &dest_tip)
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(
        source_set, dest_set,
        "object closures must match — proves real data moved through the transport"
    );
    assert!(
        source_set.len() >= 4,
        "closure must include >= commit + tree + 2 blobs"
    );

    // --- (c) The pinned options reached the spawned program -------------
    let log = fs::read_to_string(&argv_log).expect("argv log written by wrapper");
    // argv is logged one token per line; assert the consecutive
    // `-o <val>` / `-i <val>` pairs are present.
    let lines: Vec<&str> = log.lines().collect();
    assert!(
        has_pair(
            &lines,
            "-o",
            &format!("StrictHostKeyChecking={strict_value}")
        ),
        "ssh argv missing StrictHostKeyChecking; log:\n{log}"
    );
    assert!(
        has_pair(
            &lines,
            "-o",
            &format!("UserKnownHostsFile={}", known_hosts.display())
        ),
        "ssh argv missing UserKnownHostsFile; log:\n{log}"
    );
    assert!(
        has_pair(&lines, "-i", &identity.display().to_string()),
        "ssh argv missing identity file; log:\n{log}"
    );
}

/// True when `lines` contains `flag` immediately followed by `value`.
fn has_pair(lines: &[&str], flag: &str, value: &str) -> bool {
    lines.windows(2).any(|w| w[0] == flag && w[1] == value)
}
