//! Shared test harness for the end-to-end CLI suites.
//!
//! The state-machine suite (`state_machine.rs`) and the fault-injection suites
//! (`crash_recovery.rs`, `corruption_rejection.rs`, `lock_contention.rs`) all
//! drive the real `mkit` binary and assert the same repo-invariant battery, so
//! that machinery lives here.
//!
//! Each integration-test binary compiles its own copy of this module, so not
//! every binary uses every helper — hence the crate-wide `allow(dead_code)`.

#![allow(dead_code)]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use mkit_core::Hash;
use mkit_core::index::read_index;
use mkit_core::layout::RepoLayout;
use mkit_core::object::Object;
use mkit_core::ops::live_objects;
use mkit_core::refs;
use mkit_core::sign::{KeyPair, save_key, verify_commit, verify_remix, verify_tag};
use mkit_core::store::ObjectStore;
use mkit_core::to_hex;

/// Deterministic seed for the prewritten signing key, so commits don't depend
/// on `keygen` randomness (faster + reproducible across runs).
pub(crate) const KEY_SEED: [u8; 32] = [0x11; 32];

// ---------------------------------------------------------------------------
// Loud skips (#505 PR 2/5)
// ---------------------------------------------------------------------------
//
// Tests that depend on an external tool or an opt-in environment flag used
// to `return` quietly (green) when the dependency was missing — a
// tool-less CI reported green while validating nothing. These helpers make
// that loud instead: under `MKIT_TEST_STRICT=1` (set in CI jobs that are
// expected to have the dependency) a missing tool/flag panics the test
// rather than silently skipping it.

// Not every integration-test binary that compiles this module calls these
// (see the file-level `allow(dead_code)` rationale above) — allow the
// re-export to go unused in binaries that only need `require_env_flag`.
#[allow(unused_imports)]
pub(crate) use mkit_test_util::{require_tool, tool_available};

/// Returns `true` if the opt-in environment flag `var` is set to `"1"`
/// (e.g. `MKIT_SSH_E2E_REAL`). If it is not: panic when `MKIT_TEST_STRICT`
/// is set, otherwise print a loud `SKIP:` line and return `false`.
///
/// Unlike `require_tool`, this doesn't test for a missing dependency — it
/// gates an opt-in, environment-fragile e2e suite. `MKIT_TEST_STRICT`
/// should therefore only be set alongside the flag itself in a CI job that
/// actually provisions the real e2e environment.
pub(crate) fn require_env_flag(var: &str) -> bool {
    if std::env::var(var).as_deref() == Ok("1") {
        return true;
    }
    assert!(
        std::env::var_os("MKIT_TEST_STRICT").is_none(),
        "{var}=1 required (MKIT_TEST_STRICT set) but not set"
    );
    eprintln!("SKIP: {var} not set to 1");
    false
}

// ---------------------------------------------------------------------------
// Driving the real binary
// ---------------------------------------------------------------------------

/// Spawn the real `mkit` binary, fully isolated from the developer's
/// environment, with a non-interactive editor so nothing ever blocks.
pub(crate) fn mkit(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mkit"))
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .env("HOME", xdg)
        .env("EDITOR", "true")
        .env("VISUAL", "true")
        .env("GIT_EDITOR", "true")
        .stdin(Stdio::null())
        .output()
        .expect("spawn mkit")
}

/// Prewrite a deterministic Ed25519 signing key at the default path.
pub(crate) fn install_fixed_key(root: &Path) -> Result<(), String> {
    let keys = root.join(".mkit").join("keys");
    std::fs::create_dir_all(&keys).map_err(|e| format!("mkdir keys: {e}"))?;
    let kp = KeyPair::from_seed(KEY_SEED);
    save_key(&keys.join("default.key"), &kp).map_err(|e| format!("save_key: {e}"))?;
    Ok(())
}

/// Exit codes a well-behaved `mkit` command may return — `OK` plus the
/// documented sysexits-style errors from `mkit-cli/src/exit.rs`. Anything else
/// (notably 101 from a Rust panic, or `None` from a signal) is a violation.
pub(crate) const ALLOWED_EXIT: &[i32] = &[0, 1, 64, 65, 66, 69, 73, 75, 76, 77, 78];

/// Assert a command exited with an allowlisted code and did not panic.
pub(crate) fn check_exit(out: &Output, label: &str) -> Result<(), String> {
    let stderr = String::from_utf8_lossy(&out.stderr);
    match out.status.code() {
        Some(c) if ALLOWED_EXIT.contains(&c) => {}
        Some(c) => {
            return Err(format!(
                "[{label}] disallowed exit code {c}; stderr: {stderr}"
            ));
        }
        None => return Err(format!("[{label}] killed by signal; stderr: {stderr}")),
    }
    for marker in ["panicked at", "thread 'main' panicked", "RUST_BACKTRACE"] {
        if stderr.contains(marker) {
            return Err(format!("[{label}] panic in stderr: {stderr}"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Invariant battery (test-local validator over mkit-core primitives)
// ---------------------------------------------------------------------------

/// The "no corruption" subset of the invariant battery that does NOT read
/// operation-state roots: content-addressing integrity over every loose
/// object, a well-formed HEAD, and a parseable index.
///
/// This is the right oracle after a *deliberately garbled* operation-state
/// image (a malformed `MERGE_HEAD` / `rebase-apply/todo`, …), where the full
/// [`check_invariants`] would correctly fail-closed: `live_objects()` →
/// `collect_roots()` reads those sidecar files and errors on malformed roots,
/// which is expected for a garbled state, not a sign of repo corruption.
pub(crate) fn check_store_intact(root: &Path, label: &str) -> Result<(), String> {
    let layout = RepoLayout::single(root);
    let store = ObjectStore::open(&layout).map_err(|e| format!("[{label}] open store: {e}"))?;

    // Content-addressing integrity: every loose object's bytes re-hash to its
    // path. `read` recomputes BLAKE3 and rejects on mismatch.
    let present = store
        .iter_object_hashes()
        .map_err(|e| format!("[{label}] enumerate objects: {e}"))?;
    for h in &present {
        store
            .read(h)
            .map_err(|e| format!("[{label}] object {} failed integrity: {e}", to_hex(h)))?;
    }

    // HEAD is well-formed (symbolic-to-branch or a 64-hex detached hash).
    refs::read_head(&layout).map_err(|e| format!("[{label}] HEAD malformed: {e}"))?;

    // Index parses.
    read_index(&layout).map_err(|e| format!("[{label}] index unparseable: {e}"))?;
    Ok(())
}

/// The full repo-invariant battery. Builds on [`check_store_intact`] and adds:
/// signed-root reachability + signature validity, gc-safety over mkit's own
/// retention live-set, and no leaked lock files. Only valid on a *parseable*
/// repo state (post-recovery / non-garbled).
pub(crate) fn check_invariants(root: &Path, label: &str) -> Result<(), String> {
    check_store_intact(root, label)?;
    let layout = RepoLayout::single(root);
    let mkit_dir = layout.common_dir().to_path_buf();
    let store = ObjectStore::open(&layout).map_err(|e| format!("[{label}] open store: {e}"))?;

    // Collect *signed* roots: HEAD, every head ref, every tag ref. A listed ref
    // whose on-disk bytes are malformed (hash == None) is corruption.
    let mut roots: Vec<Hash> = Vec::new();
    if let Some(h) =
        refs::resolve_head(&layout).map_err(|e| format!("[{label}] resolve HEAD: {e}"))?
    {
        roots.push(h);
    }
    for r in refs::list_refs(&layout).map_err(|e| format!("[{label}] list heads: {e}"))? {
        match r.hash {
            Some(h) => roots.push(h),
            None => {
                return Err(format!(
                    "[{label}] head ref '{}' has malformed bytes",
                    r.name
                ));
            }
        }
    }
    for r in refs::list_tags(&layout).map_err(|e| format!("[{label}] list tags: {e}"))? {
        match r.hash {
            Some(h) => roots.push(h),
            None => {
                return Err(format!(
                    "[{label}] tag ref '{}' has malformed bytes",
                    r.name
                ));
            }
        }
    }

    // Signature validity over the signed reachable set. Stash roots (unannotated
    // zero-sig commits) are NOT walked here — broad presence (incl. stash) is
    // covered by the gc live-set check below.
    let mut visited: HashSet<String> = HashSet::new();
    let mut work = roots;
    while let Some(h) = work.pop() {
        if !visited.insert(to_hex(&h)) {
            continue;
        }
        let obj = store
            .read_object(&h)
            .map_err(|e| format!("[{label}] reachable object {} unreadable: {e}", to_hex(&h)))?;
        match obj {
            Object::Commit(c) => {
                verify_commit(&c)
                    .map_err(|e| format!("[{label}] commit {} bad signature: {e}", to_hex(&h)))?;
                work.push(c.tree_hash);
                work.extend(c.parents);
            }
            Object::Remix(r) => {
                verify_remix(&r)
                    .map_err(|e| format!("[{label}] remix {} bad signature: {e}", to_hex(&h)))?;
                work.push(r.tree_hash);
                work.extend(r.parents);
            }
            Object::Tag(t) => {
                // `tag -a` creates an UNSIGNED annotated tag (zero signature);
                // only `tag -s` signs. Verify only when a signature is present,
                // mirroring the stash / unannotated-commit exemption.
                if t.signature != [0u8; 64] {
                    verify_tag(&t)
                        .map_err(|e| format!("[{label}] tag {} bad signature: {e}", to_hex(&h)))?;
                }
                work.push(t.target);
            }
            Object::Tree(t) => {
                work.extend(t.entries.into_iter().map(|e| e.object_hash));
            }
            Object::ChunkedBlob(cb) => work.extend(cb.chunks),
            Object::Blob(_) | Object::Delta(_) => {}
        }
    }

    // gc-safety: every object mkit would retain (its own live-set — refs, stash,
    // ORIG_HEAD, in-progress state, conflict sidecars, attestations, recovery
    // roots, and their closure incl. chunked-blob chunks) must be present.
    let live =
        live_objects(&store, &layout).map_err(|e| format!("[{label}] collect gc live-set: {e}"))?;
    for h in &live {
        store
            .read(h)
            .map_err(|e| format!("[{label}] live object {} missing/corrupt: {e}", to_hex(h)))?;
    }

    // No leaked lock files: every `.mkit/*.lock` is acquired and released within
    // a single command, so none must survive a returned command.
    if let Ok(rd) = std::fs::read_dir(&mkit_dir) {
        for ent in rd.flatten() {
            let name = ent.file_name();
            let name = name.to_string_lossy();
            if name.ends_with(".lock") {
                return Err(format!("[{label}] leaked lock file: .mkit/{name}"));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Operation-state inspection
// ---------------------------------------------------------------------------

/// Which resumable operation, if any, is in progress (by sidecar presence).
pub(crate) fn in_progress(mkit_dir: &Path) -> Option<&'static str> {
    if mkit_dir.join("rebase-apply").exists() || mkit_dir.join("rebase-merge").exists() {
        Some("rebase")
    } else if mkit_dir.join("CHERRY_PICK_HEAD").exists() {
        Some("cherry-pick")
    } else if mkit_dir.join("REVERT_HEAD").exists() {
        Some("revert")
    } else if mkit_dir.join("MERGE_HEAD").exists() {
        Some("merge")
    } else {
        None
    }
}

/// If `verb` left any on-disk residue after concluding, return a description of
/// the first piece found — else `None`. Residue is the in-progress marker, the
/// shared `mkit-conflicts` sidecar, or the op-specific message file
/// (`MERGE_MSG`/`CHERRY_PICK_MSG`/`REVERT_MSG`) — all of which the core
/// `clear_*_state` helpers remove. `ORIG_HEAD` is deliberately NOT checked: a
/// `reset` legitimately leaves it. Rebase keeps its sidecar/message *inside*
/// `rebase-apply/`, which the directory check already covers.
pub(crate) fn operation_residue(mkit_dir: &Path, verb: &str) -> Option<String> {
    let (head, msg) = match verb {
        "merge" => ("MERGE_HEAD", "MERGE_MSG"),
        "cherry-pick" => ("CHERRY_PICK_HEAD", "CHERRY_PICK_MSG"),
        "revert" => ("REVERT_HEAD", "REVERT_MSG"),
        "rebase" => {
            return (mkit_dir.join("rebase-apply").exists()
                || mkit_dir.join("rebase-merge").exists())
            .then(|| "rebase-apply/".to_owned());
        }
        _ => return None,
    };
    for residue in [head, "mkit-conflicts", msg] {
        if mkit_dir.join(residue).exists() {
            return Some(residue.to_owned());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Repo fixture + conflict builders (used by the fault-injection suites)
// ---------------------------------------------------------------------------

/// A throwaway repo on a fresh temp dir, initialised with the fixed signing key
/// (no `keygen`), plus an isolated XDG/HOME dir.
pub(crate) struct Repo {
    pub dir: tempfile::TempDir,
    pub xdg: tempfile::TempDir,
}

impl Repo {
    /// `init` + install the fixed key.
    pub(crate) fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let xdg = tempfile::tempdir().expect("xdg tempdir");
        let r = Repo { dir, xdg };
        r.ok(&["init"]);
        install_fixed_key(r.path()).expect("install key");
        r
    }

    pub(crate) fn path(&self) -> &Path {
        self.dir.path()
    }
    pub(crate) fn xdg(&self) -> &Path {
        self.xdg.path()
    }
    pub(crate) fn mkit_dir(&self) -> PathBuf {
        self.path().join(".mkit")
    }

    pub(crate) fn run(&self, args: &[&str]) -> Output {
        mkit(self.path(), self.xdg(), args)
    }

    /// Run and assert success.
    pub(crate) fn ok(&self, args: &[&str]) -> Output {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "expected `mkit {}` to succeed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }

    pub(crate) fn write(&self, rel: &str, body: &[u8]) {
        let p = self.path().join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(p, body).unwrap();
    }

    /// write + `add` + `commit -m`.
    pub(crate) fn commit_file(&self, rel: &str, body: &[u8], msg: &str) {
        self.write(rel, body);
        self.ok(&["add", rel]);
        self.ok(&["commit", "-m", msg]);
    }
}

impl Default for Repo {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a base commit then a `feature` branch and `main` that edit the same
/// file divergently, leaving the repo checked out on `main` — so the next
/// `merge`/`cherry-pick`/`revert feature` conflicts. Returns the `feature`
/// branch name.
pub(crate) fn diverge_on(repo: &Repo, path: &str) -> &'static str {
    repo.commit_file(path, b"base\n", "base");
    repo.ok(&["branch", "feature"]);
    repo.ok(&["checkout", "feature"]);
    repo.commit_file(path, b"theirs\n", "theirs");
    repo.ok(&["checkout", "main"]);
    repo.commit_file(path, b"ours\n", "ours");
    "feature"
}

/// Drive `verb` into a conflicted, in-progress state on a freshly diverged
/// repo. `verb` ∈ {"merge","cherry-pick","revert","rebase"}. Returns the repo
/// with the operation paused (its sidecars on disk). Panics if the op does not
/// actually conflict (keeps the builders honest).
pub(crate) fn conflicted(verb: &str) -> Repo {
    let repo = Repo::new();
    let feature = diverge_on(&repo, "a.txt");
    let args: Vec<&str> = match verb {
        "merge" => vec!["merge", feature],
        "cherry-pick" => vec!["cherry-pick", feature],
        "revert" => {
            // Revert conflicts against a *divergent* HEAD: revert the base-era
            // change of `feature`'s tip after `main` moved the same file.
            vec!["revert", feature]
        }
        "rebase" => vec!["rebase", feature],
        other => panic!("unknown verb {other}"),
    };
    let out = repo.run(&args);
    assert!(
        !out.status.success(),
        "expected `mkit {}` to conflict, but it succeeded",
        args.join(" ")
    );
    assert!(
        in_progress(&repo.mkit_dir()) == Some(verb),
        "expected {verb} in progress, got {:?}; stderr: {}",
        in_progress(&repo.mkit_dir()),
        String::from_utf8_lossy(&out.stderr)
    );
    repo
}
