//! Stateful end-to-end invariant suite.
//!
//! `proptest` generates a random `Vec<Op>` over mkit's local DAG/worktree
//! command surface, drives each op through the **real `mkit` binary**, and
//! after every op asserts a battery of repo invariants that no amount of
//! per-operation unit testing can reach: emergent state corruption from
//! arbitrary op *composition* (commit → branch → merge → reset → rebase →
//! cherry-pick → gc → …).
//!
//! Design (see `docs`/the plan for the full rationale):
//!   * **Oracle = invariant battery** (metamorphic), not a reference model.
//!     After every op the repo must still satisfy: content-addressing
//!     integrity, resolvable head/tag refs, well-formed HEAD, parseable index,
//!     gc-safety (every object in mkit's own retention live-set — refs, stash,
//!     `ORIG_HEAD`, in-progress op state, conflict sidecars, attestations,
//!     recovery roots, and their closure — is present), valid signatures over
//!     signed refs, operation-state coherence (a successful `--abort`/
//!     `--continue` leaves no in-progress marker or `mkit-conflicts` residue),
//!     no leaked lock files, and clean process-exit hygiene.
//!   * **Drive level = CLI subprocess** — the corruption-prone orchestration
//!     (merge/rebase/reset/`--continue`/`--abort` + conflict sidecars + locks)
//!     lives only in the CLI layer, so the suite spawns the binary.
//!   * **Determinism** = a prewritten fixed signing key (no production time
//!     hook). Wall-clock timestamps make object hashes differ between runs,
//!     but the invariant battery is hash-agnostic and proptest reproduces the
//!     failing `Vec<Op>` from its seed regardless.
//!   * **Bounded by default** (32 cases) so the workspace `nextest` run stays
//!     fast; the nightly job raises `PROPTEST_CASES` under the `state-machine`
//!     nextest profile (longer slow-timeout). Sequence length is a FIXED
//!     constant in every mode so persisted regressions always replay.
//!
//! Fault injection (crash recovery, corrupted-object rejection, multi-process
//! lock contention) is intentionally **out of scope here** — it needs a
//! different technique and is tracked as the follow-up in issue #307.

use std::fmt;
use std::fs;
use std::path::Path;
use std::process::Output;

use mkit_core::refs;

use proptest::prelude::*;
use proptest::test_runner::{FileFailurePersistence, TestCaseError};

mod common;
use common::{
    check_exit, check_invariants, in_progress, install_fixed_key, mkit, operation_residue,
};

/// Number of distinct worktree files the generator draws from. Small so that
/// edits collide and real merges/conflicts arise instead of almost never.
const FILES: usize = 5;
/// Number of distinct branch/tag names the generator draws from.
const NAMES: usize = 4;
/// Maximum generated sequence length. **Fixed across all modes** — only the
/// case *count* varies (PR vs nightly) — so a regression minimized by the
/// nightly run still replays under the default config.
const MAX_OPS: usize = 50;

// ---------------------------------------------------------------------------
// Operation alphabet
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum ResetMode {
    Soft,
    Mixed,
    Hard,
}

impl ResetMode {
    fn flag(&self) -> &'static str {
        match self {
            ResetMode::Soft => "--soft",
            ResetMode::Mixed => "--mixed",
            ResetMode::Hard => "--hard",
        }
    }
    fn word(&self) -> &'static str {
        match self {
            ResetMode::Soft => "soft",
            ResetMode::Mixed => "mixed",
            ResetMode::Hard => "hard",
        }
    }
}

/// Local DAG/worktree mutators. Selectors are small integers resolved modulo
/// the live repo state at *apply* time, so most ops are valid by construction
/// while still occasionally exercising clean error paths.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Op {
    Write(u8, u8),
    Delete(u8),
    Add(u8),
    AddAll,
    Rm(u8),
    Restore(u8),
    Commit,
    Branch(u8),
    DelBranch(u8),
    Checkout(u8),
    CheckoutNew(u8),
    Tag(u8),
    DelTag(u8),
    Merge(u8),
    Reset(ResetMode),
    CherryPick(u8),
    Revert,
    Rebase(u8),
    Continue,
    Abort,
    Skip,
    Stash,
    StashPop,
    Gc,
    Mv(u8, u8),
    Clean,
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Op::Write(a, b) => write!(f, "w {a} {b}"),
            Op::Delete(a) => write!(f, "del {a}"),
            Op::Add(a) => write!(f, "add {a}"),
            Op::AddAll => write!(f, "addall"),
            Op::Rm(a) => write!(f, "rm {a}"),
            Op::Restore(a) => write!(f, "restore {a}"),
            Op::Commit => write!(f, "commit"),
            Op::Branch(a) => write!(f, "branch {a}"),
            Op::DelBranch(a) => write!(f, "delbranch {a}"),
            Op::Checkout(a) => write!(f, "checkout {a}"),
            Op::CheckoutNew(a) => write!(f, "checkoutnew {a}"),
            Op::Tag(a) => write!(f, "tag {a}"),
            Op::DelTag(a) => write!(f, "deltag {a}"),
            Op::Merge(a) => write!(f, "merge {a}"),
            Op::Reset(m) => write!(f, "reset {}", m.word()),
            Op::CherryPick(a) => write!(f, "cherrypick {a}"),
            Op::Revert => write!(f, "revert"),
            Op::Rebase(a) => write!(f, "rebase {a}"),
            Op::Continue => write!(f, "continue"),
            Op::Abort => write!(f, "abort"),
            Op::Skip => write!(f, "skip"),
            Op::Stash => write!(f, "stash"),
            Op::StashPop => write!(f, "stashpop"),
            Op::Gc => write!(f, "gc"),
            Op::Mv(a, b) => write!(f, "mv {a} {b}"),
            Op::Clean => write!(f, "clean"),
        }
    }
}

/// Parse one transcript line into an `Op`. Mirror of `Display`.
fn parse_op(line: &str) -> Result<Op, String> {
    let mut t = line.split_whitespace();
    let head = t.next().ok_or_else(|| "empty op".to_owned())?;
    let num = |t: &mut std::str::SplitWhitespace<'_>| -> Result<u8, String> {
        t.next()
            .ok_or_else(|| format!("op `{head}` missing argument"))?
            .parse::<u8>()
            .map_err(|e| format!("op `{head}` bad number: {e}"))
    };
    let op = match head {
        "w" => {
            let a = num(&mut t)?;
            Op::Write(a, num(&mut t)?)
        }
        "del" => Op::Delete(num(&mut t)?),
        "add" => Op::Add(num(&mut t)?),
        "addall" => Op::AddAll,
        "rm" => Op::Rm(num(&mut t)?),
        "restore" => Op::Restore(num(&mut t)?),
        "commit" => Op::Commit,
        "branch" => Op::Branch(num(&mut t)?),
        "delbranch" => Op::DelBranch(num(&mut t)?),
        "checkout" => Op::Checkout(num(&mut t)?),
        "checkoutnew" => Op::CheckoutNew(num(&mut t)?),
        "tag" => Op::Tag(num(&mut t)?),
        "deltag" => Op::DelTag(num(&mut t)?),
        "merge" => Op::Merge(num(&mut t)?),
        "reset" => match t.next() {
            Some("soft") => Op::Reset(ResetMode::Soft),
            Some("mixed") => Op::Reset(ResetMode::Mixed),
            Some("hard") => Op::Reset(ResetMode::Hard),
            other => return Err(format!("reset bad mode: {other:?}")),
        },
        "cherrypick" => Op::CherryPick(num(&mut t)?),
        "revert" => Op::Revert,
        "rebase" => Op::Rebase(num(&mut t)?),
        "continue" => Op::Continue,
        "abort" => Op::Abort,
        "skip" => Op::Skip,
        "stash" => Op::Stash,
        "stashpop" => Op::StashPop,
        "gc" => Op::Gc,
        "mv" => {
            let a = num(&mut t)?;
            Op::Mv(a, num(&mut t)?)
        }
        "clean" => Op::Clean,
        other => return Err(format!("unknown op `{other}`")),
    };
    Ok(op)
}

fn parse_transcript(text: &str) -> Result<Vec<Op>, String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(parse_op)
        .collect()
}

// ---------------------------------------------------------------------------
// Strategy
// ---------------------------------------------------------------------------

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (any::<u8>(), any::<u8>()).prop_map(|(a, b)| Op::Write(a, b)),
        1 => any::<u8>().prop_map(Op::Delete),
        3 => any::<u8>().prop_map(Op::Add),
        2 => Just(Op::AddAll),
        1 => any::<u8>().prop_map(Op::Rm),
        1 => any::<u8>().prop_map(Op::Restore),
        4 => Just(Op::Commit),
        2 => any::<u8>().prop_map(Op::Branch),
        1 => any::<u8>().prop_map(Op::DelBranch),
        2 => any::<u8>().prop_map(Op::Checkout),
        2 => any::<u8>().prop_map(Op::CheckoutNew),
        1 => any::<u8>().prop_map(Op::Tag),
        1 => any::<u8>().prop_map(Op::DelTag),
        3 => any::<u8>().prop_map(Op::Merge),
        2 => prop_oneof![
            Just(ResetMode::Soft),
            Just(ResetMode::Mixed),
            Just(ResetMode::Hard),
        ].prop_map(Op::Reset),
        2 => any::<u8>().prop_map(Op::CherryPick),
        1 => Just(Op::Revert),
        2 => any::<u8>().prop_map(Op::Rebase),
        2 => Just(Op::Continue),
        1 => Just(Op::Abort),
        1 => Just(Op::Skip),
        1 => Just(Op::Stash),
        1 => Just(Op::StashPop),
        1 => Just(Op::Gc),
        1 => (any::<u8>(), any::<u8>()).prop_map(|(a, b)| Op::Mv(a, b)),
        1 => Just(Op::Clean),
    ]
}

// ---------------------------------------------------------------------------
// Op-model naming helpers
// ---------------------------------------------------------------------------

fn file_name(a: u8) -> String {
    format!("f{}.txt", (a as usize) % FILES)
}
fn branch_name(a: u8) -> String {
    format!("topic{}", (a as usize) % NAMES)
}
fn tag_name(a: u8) -> String {
    format!("tag{}", (a as usize) % NAMES)
}

/// Names of head refs that currently exist (have valid on-disk bytes).
fn existing_branches(mkit_dir: &Path) -> Vec<String> {
    refs::list_refs(mkit_dir)
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.hash.is_some())
        .map(|r| r.name)
        .collect()
}

/// Resolve a selector to an existing branch name, or `main` when none exist
/// yet (so e.g. `checkout`/`merge` exercise the unborn-branch path cleanly).
fn pick_branch(mkit_dir: &Path, a: u8) -> String {
    let names = existing_branches(mkit_dir);
    if names.is_empty() {
        "main".to_owned()
    } else {
        names[(a as usize) % names.len()].clone()
    }
}

/// Apply one op. Returns **every** `mkit` invocation it made (composite ops
/// like `CheckoutNew` make two), so the caller can run exit hygiene on each.
/// Pure-filesystem ops return an empty vec.
fn apply(op: &Op, root: &Path, xdg: &Path, ctr: &mut u32) -> Vec<Output> {
    let mkit_dir = root.join(".mkit");
    match op {
        Op::Write(a, b) => {
            let byte = b'A' + (b % 26);
            let _ = fs::write(root.join(file_name(*a)), [byte, b'\n']);
            vec![]
        }
        Op::Delete(a) => {
            let _ = fs::remove_file(root.join(file_name(*a)));
            vec![]
        }
        Op::Add(a) => vec![mkit(root, xdg, &["add", &file_name(*a)])],
        Op::AddAll => vec![mkit(root, xdg, &["add", "-A"])],
        Op::Rm(a) => vec![mkit(root, xdg, &["rm", "-f", &file_name(*a)])],
        Op::Restore(a) => vec![mkit(root, xdg, &["restore", &file_name(*a)])],
        Op::Commit => {
            *ctr += 1;
            vec![mkit(root, xdg, &["commit", "-m", &format!("c{ctr}")])]
        }
        Op::Branch(a) => vec![mkit(root, xdg, &["branch", &branch_name(*a)])],
        Op::DelBranch(a) => vec![mkit(root, xdg, &["branch", "-d", &branch_name(*a)])],
        Op::Checkout(a) => vec![mkit(root, xdg, &["checkout", &pick_branch(&mkit_dir, *a)])],
        Op::CheckoutNew(a) => {
            // mkit has no `checkout -b`: compose branch-create then switch. Both
            // invocations are returned so neither escapes exit hygiene.
            let n = branch_name(*a);
            vec![
                mkit(root, xdg, &["branch", &n]),
                mkit(root, xdg, &["checkout", &n]),
            ]
        }
        Op::Tag(a) => vec![mkit(root, xdg, &["tag", &tag_name(*a)])],
        Op::DelTag(a) => vec![mkit(root, xdg, &["tag", "-d", &tag_name(*a)])],
        Op::Merge(a) => vec![mkit(root, xdg, &["merge", &pick_branch(&mkit_dir, *a)])],
        Op::Reset(m) => vec![mkit(root, xdg, &["reset", m.flag()])],
        Op::CherryPick(a) => {
            let names = existing_branches(&mkit_dir);
            if names.is_empty() {
                vec![]
            } else {
                let b = &names[(*a as usize) % names.len()];
                vec![mkit(root, xdg, &["cherry-pick", b])]
            }
        }
        Op::Revert => vec![mkit(root, xdg, &["revert", "HEAD"])],
        Op::Rebase(a) => vec![mkit(root, xdg, &["rebase", &pick_branch(&mkit_dir, *a)])],
        // Continuations dispatch to whatever op is in progress; when none is,
        // we still fire the representative verb so the "nothing in progress ->
        // clean error" path is exercised (and validated by exit hygiene).
        Op::Continue => {
            let verb = in_progress(&mkit_dir).unwrap_or("merge");
            vec![mkit(root, xdg, &[verb, "--continue"])]
        }
        Op::Abort => {
            let verb = in_progress(&mkit_dir).unwrap_or("merge");
            vec![mkit(root, xdg, &[verb, "--abort"])]
        }
        Op::Skip => vec![mkit(root, xdg, &["rebase", "--skip"])],
        Op::Stash => vec![mkit(root, xdg, &["stash"])],
        Op::StashPop => vec![mkit(root, xdg, &["stash", "pop"])],
        // `--grace-secs 0` actually prunes unreachable objects on a fresh repo;
        // the default 14-day window would retain everything and make the
        // post-gc reachability invariant toothless.
        Op::Gc => vec![mkit(root, xdg, &["gc", "--grace-secs", "0"])],
        Op::Mv(a, b) => vec![mkit(root, xdg, &["mv", &file_name(*a), &file_name(*b)])],
        Op::Clean => vec![mkit(root, xdg, &["clean", "-f", "-d"])],
    }
}

/// Operation-state-coherence invariant (the conflict-sidecar half of the
/// oracle). A successful `--abort` or `--continue` *concludes* the operation
/// and must leave no residue — no in-progress marker AND no `mkit-conflicts`
/// sidecar. This holds for rebase too: `rebase --continue`/`--abort` returns
/// exit 0 only on full completion (a re-pause returns non-zero), so a 0 exit
/// means the rebase state must be gone. This is exactly the class of bug —
/// "abort returns success but forgets to delete `MERGE_HEAD`/`mkit-conflicts`"
/// — that pure reachability/signature checks miss.
fn check_op_state(
    op: &Op,
    pre_verb: Option<&'static str>,
    outputs: &[Output],
    mkit_dir: &Path,
    label: &str,
) -> Result<(), String> {
    if !matches!(op, Op::Abort | Op::Continue) {
        return Ok(());
    }
    let last_ok = outputs.last().is_some_and(|o| o.status.code() == Some(0));
    let Some(verb) = pre_verb else {
        return Ok(());
    };
    let residue = if last_ok {
        operation_residue(mkit_dir, verb)
    } else {
        None
    };
    if let Some(residue) = residue {
        let flag = if matches!(op, Op::Abort) {
            "--abort"
        } else {
            "--continue"
        };
        return Err(format!(
            "[{label}] `{verb} {flag}` reported success but left residue: {residue}"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Scenario driver
// ---------------------------------------------------------------------------

/// Initialise a fresh repo, install the fixed key, then apply every op,
/// checking exit hygiene + the full invariant battery after each.
fn run_scenario(ops: &[Op]) -> Result<(), String> {
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let xdg = tempfile::tempdir().map_err(|e| e.to_string())?;
    let root = dir.path();
    let xdgp = xdg.path();

    check_exit(&mkit(root, xdgp, &["init"]), "init")?;
    install_fixed_key(root)?;
    check_invariants(root, "after-init")?;

    let mut ctr = 0u32;
    for (i, op) in ops.iter().enumerate() {
        let label = format!("op{i} `{op}`");
        let mkit_dir = root.join(".mkit");
        let pre_verb = in_progress(&mkit_dir);
        let outputs = apply(op, root, xdgp, &mut ctr);
        for out in &outputs {
            check_exit(out, &label)?;
        }
        check_op_state(op, pre_verb, &outputs, &mkit_dir, &label)?;
        check_invariants(root, &label)?;
    }
    Ok(())
}

/// Read the case count from proptest's own env var so the nightly job can scale
/// up. We must read it manually because an explicit `cases:` field in
/// `ProptestConfig` otherwise bypasses the env override.
fn sm_cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(32)
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: sm_cases(),
        // Persist failures next to the source as `proptest-regressions/state_machine.txt`.
        failure_persistence: Some(Box::new(FileFailurePersistence::SourceParallel(
            "proptest-regressions",
        ))),
        ..ProptestConfig::default()
    })]

    /// The core stateful property: no random local op sequence corrupts the
    /// repo. On failure, the printed transcript can be dropped verbatim into
    /// `tests/regressions/` (see `replay_checked_in_regressions`).
    #[test]
    fn stateful_invariants(ops in prop::collection::vec(op_strategy(), 0..=MAX_OPS)) {
        if let Err(e) = run_scenario(&ops) {
            let transcript = ops
                .iter()
                .map(Op::to_string)
                .collect::<Vec<_>>()
                .join("\n");
            return Err(TestCaseError::fail(format!(
                "invariant failure: {e}\n--- transcript ---\n{transcript}"
            )));
        }
    }
}

/// Replay every checked-in regression transcript directly (independent of the
/// proptest generator/seed format) and assert the invariants now hold.
#[test]
fn replay_checked_in_regressions() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("regressions");
    let Ok(entries) = fs::read_dir(&dir) else {
        return; // no regressions directory yet
    };
    for ent in entries.flatten() {
        let path = ent.path();
        if path.extension().and_then(|s| s.to_str()) != Some("txt") {
            continue; // skip README.md and friends
        }
        let text = fs::read_to_string(&path).expect("read regression transcript");
        let ops =
            parse_transcript(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
        run_scenario(&ops)
            .unwrap_or_else(|e| panic!("regression {} reproduced a failure: {e}", path.display()));
    }
}

#[cfg(test)]
mod unit {
    use super::*;

    /// Fabricate a successful `Output` so tests don't depend on a real process.
    fn ok_output() -> Output {
        use std::os::unix::process::ExitStatusExt;
        Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }

    /// The operation-state invariant must bite: if `--abort` reports success
    /// but the in-progress marker is still on disk, `check_op_state` flags it.
    #[test]
    fn op_state_invariant_detects_stale_marker() {
        let dir = tempfile::tempdir().unwrap();
        let mkit_dir = dir.path().join(".mkit");
        fs::create_dir_all(&mkit_dir).unwrap();
        let merge_head = mkit_dir.join("MERGE_HEAD");

        // Healthy: a successful abort left no marker → no complaint.
        check_op_state(
            &Op::Abort,
            Some("merge"),
            &[ok_output()],
            &mkit_dir,
            "clean",
        )
        .unwrap();

        // Buggy: marker survived a successful abort → flagged.
        fs::write(&merge_head, b"deadbeef").unwrap();
        assert!(
            check_op_state(
                &Op::Abort,
                Some("merge"),
                &[ok_output()],
                &mkit_dir,
                "stale"
            )
            .is_err(),
            "stale MERGE_HEAD after a successful abort must be flagged"
        );
    }

    #[test]
    fn op_display_roundtrips_through_parse() {
        let ops = [
            Op::Write(2, 65),
            Op::Delete(1),
            Op::AddAll,
            Op::Reset(ResetMode::Hard),
            Op::Mv(0, 3),
            Op::CheckoutNew(2),
            Op::Continue,
            Op::Clean,
        ];
        for op in ops {
            let s = op.to_string();
            assert_eq!(parse_op(&s).unwrap(), op, "roundtrip failed for `{s}`");
        }
    }

    /// Walk `.mkit/objects/<2>/<62>` and return the first loose object file.
    fn first_object_file(root: &Path) -> std::path::PathBuf {
        let objects = root.join(".mkit").join("objects");
        for shard in fs::read_dir(&objects).unwrap().flatten() {
            if !shard.path().is_dir() {
                continue;
            }
            if let Some(obj) = fs::read_dir(shard.path()).unwrap().flatten().next() {
                return obj.path();
            }
        }
        panic!("no loose object found under {}", objects.display());
    }

    /// The oracle must *bite*: a single tampered byte in a stored object breaks
    /// content-addressing integrity and `check_invariants` must reject it. This
    /// is the standing proof that a passing battery means something.
    #[test]
    fn validator_detects_tampered_object() {
        let dir = tempfile::tempdir().unwrap();
        let xdg = tempfile::tempdir().unwrap();
        let root = dir.path();
        assert!(mkit(root, xdg.path(), &["init"]).status.success());
        install_fixed_key(root).unwrap();
        fs::write(root.join("f0.txt"), b"hi\n").unwrap();
        assert!(mkit(root, xdg.path(), &["add", "f0.txt"]).status.success());
        assert!(
            mkit(root, xdg.path(), &["commit", "-m", "first"])
                .status
                .success()
        );

        // Healthy repo passes.
        check_invariants(root, "pre-tamper").unwrap();

        // Flip a byte in a stored object → BLAKE3 no longer matches the path.
        let obj = first_object_file(root);
        let mut bytes = fs::read(&obj).unwrap();
        bytes[0] ^= 0xff;
        fs::write(&obj, &bytes).unwrap();

        assert!(
            check_invariants(root, "post-tamper").is_err(),
            "validator failed to detect a tampered object"
        );
    }

    #[test]
    fn fixed_key_commit_verifies() {
        // The prewritten key must let the binary make a verifiable commit.
        let dir = tempfile::tempdir().unwrap();
        let xdg = tempfile::tempdir().unwrap();
        let root = dir.path();
        assert!(mkit(root, xdg.path(), &["init"]).status.success());
        install_fixed_key(root).unwrap();
        fs::write(root.join("f0.txt"), b"hi\n").unwrap();
        assert!(mkit(root, xdg.path(), &["add", "f0.txt"]).status.success());
        let c = mkit(root, xdg.path(), &["commit", "-m", "first"]);
        assert!(
            c.status.success(),
            "commit failed: {}",
            String::from_utf8_lossy(&c.stderr)
        );
        // The invariant battery (which verifies the commit signature) holds.
        check_invariants(root, "fixed-key-commit").unwrap();
    }
}
