//! Regression test for mkit#703: `SshTransport` retries a verb call
//! that observes `ConnectionFailed` by transparently reconnecting
//! (spawning a fresh `ssh` child and redoing the `Hello` handshake)
//! and re-issuing the verb, instead of failing the whole command on a
//! single dropped connection (SPEC-TRANSPORT §7).
//!
//! Reuses the `MKIT_SSH_PROGRAM` seam from `ssh_e2e.rs`, but the fake
//! `ssh` wrapper here tracks how many times it has been invoked (via a
//! counter file — each retry attempt spawns an entirely new `ssh`
//! child process, so in-memory state doesn't survive between attempts)
//! and sets `MKIT_SERVE_TEST_DIE_AFTER_HELLO=1` — a test-only hook in
//! `mkit serve` (see `src/commands/serve/mod.rs`) — on ONLY the first
//! invocation. That server exits immediately after replying to
//! `Hello`, before answering any verb, so the client observes
//! `ConnectionFailed` on its first `list_refs` call. The second
//! invocation (the client's automatic reconnect) serves normally.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use mkit_core::layout::RepoLayout;
use mkit_core::refs;

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

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

fn write_flaky_ssh_wrapper(dir: &Path) -> std::path::PathBuf {
    let wrapper = dir.join("flaky_ssh.sh");
    let script = r#"#!/bin/sh
set -eu

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
  echo "flaky_ssh: could not locate 'mkit serve <path>' in argv" >&2
  exit 64
fi

count=0
if [ -f "$MKIT_SSH_ATTEMPT_COUNTER" ]; then
  count=$(cat "$MKIT_SSH_ATTEMPT_COUNTER")
fi
count=$((count + 1))
echo "$count" > "$MKIT_SSH_ATTEMPT_COUNTER"

if [ "$count" -eq 1 ]; then
  MKIT_SERVE_TEST_DIE_AFTER_HELLO=1 exec "$MKIT_SSH_TARGET_BIN" serve "$path"
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

fn build_and_push_source(root: &Path, xdg: &Path) -> std::path::PathBuf {
    let source = root.join("source");
    fs::create_dir_all(&source).unwrap();
    assert!(run_in(&source, xdg, &["init"], &[]).status.success());
    assert!(run_in(&source, xdg, &["keygen"], &[]).status.success());
    fs::write(source.join("README.md"), b"# ssh retry e2e\n").unwrap();
    assert!(run_in(&source, xdg, &["add", "."], &[]).status.success());
    let commit = run_in(&source, xdg, &["commit", "-m", "e2e-1"], &[]);
    assert!(
        commit.status.success(),
        "commit source: {}",
        String::from_utf8_lossy(&commit.stderr)
    );

    let remote = root.join("remote");
    fs::create_dir_all(&remote).unwrap();
    assert!(run_in(&remote, xdg, &["init"], &[]).status.success());
    let remote_url = format!("mkit+file://{}", remote.display());
    assert!(
        run_in(&source, xdg, &["remote", "add", "origin", &remote_url], &[])
            .status
            .success()
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
#[ignore = "waits out the real (1s+) production backoff ladder; run via the serial --ignored CI lane"]
fn ssh_clone_retries_past_a_dropped_first_connection() {
    if cfg!(not(unix)) {
        eprintln!("ssh_retry_e2e: skipped (requires a POSIX shell)");
        return;
    }

    let work = tempfile::tempdir().expect("work tempdir");
    let xdg = tempfile::tempdir().expect("xdg tempdir");
    let root = work.path();

    let remote = build_and_push_source(root, xdg.path());
    let source = root.join("source");
    let source_tip = refs::read_ref(&RepoLayout::single(&source), "main")
        .unwrap()
        .expect("source has refs/heads/main");

    let wrapper = write_flaky_ssh_wrapper(root);
    let attempt_counter = root.join("ssh_attempts");

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
            ("MKIT_SSH_TARGET_BIN", mkit_bin()),
            (
                "MKIT_SSH_ATTEMPT_COUNTER",
                attempt_counter.to_str().unwrap(),
            ),
        ],
    );
    assert!(
        clone.status.success(),
        "clone must succeed by retrying past the dropped first ssh connection; stderr:\n{}",
        String::from_utf8_lossy(&clone.stderr)
    );

    let dest_tip = refs::read_ref(&RepoLayout::single(&dest), "main")
        .unwrap()
        .expect("cloned repo has refs/heads/main");
    assert_eq!(
        source_tip, dest_tip,
        "cloned HEAD must equal source HEAD — retried clone must move the real data"
    );

    let attempts: u32 = fs::read_to_string(&attempt_counter)
        .expect("attempt counter written by wrapper")
        .trim()
        .parse()
        .expect("attempt counter is a number");
    assert!(
        attempts >= 2,
        "expected at least 2 ssh connection attempts (initial drop + reconnect), got {attempts}"
    );
}
