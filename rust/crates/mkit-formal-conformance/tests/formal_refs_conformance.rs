//! Model-based conformance for the refs model (Linear MKIT-22, epic
//! MKIT-17).
//!
//! Replays every step of the ITF traces under
//! `tests/fixtures/formal_refs/` (drawn from `formal/quint/refs/refs_mbt.qnt`
//! by `formal/scripts/gen-refs-traces.sh`) against the real code on a temp
//! repository, and compares the observable state after every step:
//!
//! - the on-disk refs `refs/heads/a` (model ref 0) and `refs/heads/b`
//!   (model ref 1), read through BOTH `mkit_core::refs::read_ref` and
//!   `FileTransport` (they are the same files, SPEC-CONCURRENCY §3.1);
//! - the memory transport's refs;
//! - the recovery log's entries (SPEC-CONCURRENCY §3.2);
//! - on every `commitRef`, the outcome: `ok`, `conflict` (CAS failed,
//!   `RefError::Conflict` / `TransportError::RefConflict`) or `notfound`
//!   (`delete_ref` of an absent ref, `RefError::NotFound`).
//!
//! How each model op maps to the code (SPEC-REFS §5, §5.1):
//!
//! | model `kind`                                  | real call |
//! |-----------------------------------------------|-----------|
//! | `commit`, `amend`, `updateRef`, `checkout`    | `refs::update_ref` with the op's condition |
//! | `branch` (write)                              | `refs::update_ref` |
//! | `branch`, `del`, condition `Any`              | `refs::delete_ref` |
//! | `branch`, `del`, condition `Match(e)`         | `refs::delete_ref_if_matches` |
//! | `file`                                        | `Transport::update_ref` on a `FileTransport` rooted at the repo's common dir |
//! | `mem`                                         | `Transport::update_ref` on a `MemoryTransport` |
//! | `record` (amend)                              | `ops::recovery::record` |
//! | `expireWrite` (gc)                            | `ops::recovery::expire` (default retention) |
//!
//! Abstractions, stated so the reader knows what is NOT compared:
//!
//! - Lock steps (`begin`, `acquire`, `release`) are not replayed: each real
//!   call takes its own locks internally, and the model's lock-order and
//!   deadlock properties are checked by the model checkers, not here.
//! - The real calls are atomic, so a trace must be linearizable at the ref
//!   level. `refs_mbt.qnt`'s `stepLin` guarantees that (it removes only the
//!   documented cross-domain gap), and the harness re-checks it: a
//!   `commitRef` whose ref changed since that process's `readRef` fails the
//!   test as a non-linearizable trace instead of being compared.
//! - `commit` goes through `update_ref`, not the `history-mmr` ancestry path
//!   (its CAS is the same `RefMutation`; the ancestry journal needs real
//!   commit objects and is out of this model's scope).
//! - Model values 1 and 2 are two fixed hashes; recovery entry `n` is a
//!   fixed hash too. Every entry is recorded "now", so default retention
//!   keeps all of them, which is the model's expire (it keeps its snapshot).
//!
//! `harness_detects_adapter_faults` and `harness_detects_a_tampered_trace`
//! show the comparison is not vacuous.
#![allow(clippy::panic, clippy::expect_used)] // panics are the assertions here

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use mkit_core::hash::{self, Hash};
use mkit_core::layout::RepoLayout;
use mkit_core::ops::recovery::{self, RecoveryEntry, RetentionPolicy};
use mkit_core::protocol::{Transport, TransportError};
use mkit_core::refs::{self, RefError, RefWriteCondition};
use mkit_transport_file::FileTransport;
use mkit_transport_memory::MemoryTransport;
use serde_json::Value;

/// Unix time used for every recovery entry and for `expire`'s `now`.
const NOW: u64 = 1_700_000_000;
/// The model's `ABSENT` value.
const ABSENT: i64 = 0;
/// Largest model value / recovery entry id the harness can map back.
const MAX_ID: i64 = 64;
/// Prefix of every model-vs-implementation disagreement, so the
/// non-vacuity tests can tell one from a harness or I/O error.
const MISMATCH: &str = "model/implementation mismatch: ";

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/formal_refs")
}

fn fixtures() -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = fs::read_dir(fixtures_dir())
        .expect("fixtures dir: run formal/scripts/gen-refs-traces.sh")
        .map(|e| e.expect("fixtures dir entry").path())
        .filter(|p| p.to_string_lossy().ends_with(".itf.json"))
        .collect();
    paths.sort();
    assert!(
        !paths.is_empty(),
        "no ITF fixtures in {}",
        fixtures_dir().display()
    );
    paths
}

// ---------------------------------------------------------------- ITF input

fn int(v: &Value) -> i64 {
    v.get("#bigint")
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("not an ITF #bigint: {v}"))
}

fn field<'a>(v: &'a Value, k: &str) -> &'a Value {
    v.get(k)
        .unwrap_or_else(|| panic!("ITF value has no field {k:?}: {v}"))
}

fn text(v: &Value, k: &str) -> String {
    field(v, k)
        .as_str()
        .unwrap_or_else(|| panic!("field {k:?} is not a string"))
        .to_owned()
}

fn int_map(v: &Value) -> BTreeMap<i64, i64> {
    field(v, "#map")
        .as_array()
        .expect("#map array")
        .iter()
        .map(|kv| (int(&kv[0]), int(&kv[1])))
        .collect()
}

fn int_set(v: &Value) -> BTreeSet<i64> {
    field(v, "#set")
        .as_array()
        .expect("#set array")
        .iter()
        .map(int)
        .collect()
}

/// SPEC-REFS §5 condition, as the model spells it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cond {
    Any,
    Missing,
    Match(i64),
}

#[derive(Clone, Debug)]
struct Op {
    kind: String,
    reference: i64,
    cond: Cond,
    value: i64,
    del: bool,
}

/// One ITF state: the action that produced it and the variables compared.
#[derive(Clone, Debug)]
struct State {
    index: usize,
    action: String,
    proc_name: String,
    op: Op,
    outcome: String,
    disk: BTreeMap<i64, i64>,
    mem: BTreeMap<i64, i64>,
    rec_log: BTreeSet<i64>,
    next_entry: i64,
    violations: usize,
}

fn parse_state(index: usize, s: &Value) -> State {
    let last = field(s, "lastAction");
    let op = field(last, "op");
    let cond = field(op, "cond");
    let cond = match text(cond, "tag").as_str() {
        "Any" => Cond::Any,
        "Missing" => Cond::Missing,
        "Match" => Cond::Match(int(field(cond, "value"))),
        other => panic!("unknown condition tag {other}"),
    };
    State {
        index,
        action: text(last, "name"),
        proc_name: text(last, "proc"),
        op: Op {
            kind: text(op, "kind"),
            reference: int(field(op, "ref")),
            cond,
            value: int(field(op, "value")),
            del: field(op, "del").as_bool().expect("del is a bool"),
        },
        outcome: text(last, "outcome"),
        disk: int_map(field(s, "disk")),
        mem: int_map(field(s, "mem")),
        rec_log: int_set(field(s, "recLog")),
        next_entry: int(field(s, "nextEntry")),
        violations: field(field(s, "violations"), "#set")
            .as_array()
            .expect("#set array")
            .len(),
    }
}

fn load_trace(path: &Path) -> Vec<State> {
    let raw = fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let itf: Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    field(&itf, "states")
        .as_array()
        .expect("states array")
        .iter()
        .enumerate()
        .map(|(i, s)| parse_state(i, s))
        .collect()
}

// ------------------------------------------------------------ the adapter

/// Deliberate adapter bugs, used ONLY by `harness_detects_adapter_faults`
/// to show that a wrong implementation of each lock domain is caught.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    None,
    /// Local writes ignore `Missing` (write unconditionally).
    LocalMissingAsAny,
    /// File-transport writes ignore `Match` (write unconditionally).
    FileMatchAsAny,
    /// Memory-transport writes ignore `Match`.
    MemMatchAsAny,
    /// `delete_ref_if_matches` replaced by the unconditional `delete_ref`.
    ConditionalDeleteUnconditional,
    /// `recovery::record` skipped.
    RecordDropped,
}

fn value_hash(v: i64) -> Hash {
    hash::hash(format!("mkit-formal-refs value {v}").as_bytes())
}

fn entry_hash(id: i64) -> Hash {
    hash::hash(format!("mkit-formal-refs recovery entry {id}").as_bytes())
}

fn model_value(h: Option<Hash>) -> Result<i64, String> {
    match h {
        None => Ok(ABSENT),
        Some(h) => (1..=MAX_ID).find(|v| value_hash(*v) == h).ok_or_else(|| {
            format!(
                "ref holds a hash no model value maps to: {}",
                hash::to_hex(&h)
            )
        }),
    }
}

fn branch(reference: i64) -> &'static str {
    match reference {
        0 => "a",
        1 => "b",
        other => panic!("model ref {other} out of bounds"),
    }
}

fn transport_name(reference: i64) -> String {
    format!("refs/heads/{}", branch(reference))
}

fn condition(c: Cond) -> RefWriteCondition {
    match c {
        Cond::Any => RefWriteCondition::Any,
        Cond::Missing => RefWriteCondition::Missing,
        Cond::Match(e) => RefWriteCondition::Match(value_hash(e)),
    }
}

fn local_outcome(r: Result<(), RefError>) -> Result<&'static str, String> {
    match r {
        Ok(()) => Ok("ok"),
        Err(RefError::Conflict(_)) => Ok("conflict"),
        Err(RefError::NotFound(_)) => Ok("notfound"),
        Err(e) => Err(format!("unexpected local ref error: {e}")),
    }
}

fn transport_outcome(r: Result<(), TransportError>) -> Result<&'static str, String> {
    match r {
        Ok(()) => Ok("ok"),
        Err(TransportError::RefConflict) => Ok("conflict"),
        Err(e) => Err(format!("unexpected transport error: {e}")),
    }
}

/// The system under test: one temp repository, a `FileTransport` over its
/// common dir (the root a `mkit serve` / `mkit-server --meta fs-layout` of
/// the same `.mkit` would use), and one `MemoryTransport`.
struct Sut {
    _dir: tempfile::TempDir,
    layout: RepoLayout,
    file: FileTransport,
    mem: MemoryTransport,
    fault: Fault,
    /// Per process: the value its last `readRef` saw (linearizability check).
    read: BTreeMap<String, i64>,
}

impl Sut {
    fn new(init: &State, fault: Fault) -> Result<Self, String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let layout = RepoLayout::single(dir.path());
        refs::init(&layout).map_err(|e| e.to_string())?;
        let file = FileTransport::new(layout.common_dir());
        let sut = Self {
            _dir: dir,
            layout,
            file,
            mem: MemoryTransport::new(),
            fault,
            read: BTreeMap::new(),
        };
        for (r, v) in &init.disk {
            if *v != ABSENT {
                refs::write_ref(&sut.layout, branch(*r), &value_hash(*v))
                    .map_err(|e| e.to_string())?;
            }
        }
        for (r, v) in &init.mem {
            if *v != ABSENT {
                sut.mem
                    .update_ref(&transport_name(*r), RefWriteCondition::Any, &value_hash(*v))
                    .map_err(|e| e.to_string())?;
            }
        }
        Ok(sut)
    }

    /// The current value of `op`'s ref in `op`'s store.
    fn read_store(&self, op: &Op) -> Result<i64, String> {
        let h = if op.kind == "mem" {
            self.mem
                .read_ref(&transport_name(op.reference))
                .map_err(|e| e.to_string())?
        } else if op.kind == "file" {
            self.file
                .read_ref(&transport_name(op.reference))
                .map_err(|e| e.to_string())?
        } else {
            refs::read_ref(&self.layout, branch(op.reference)).map_err(|e| e.to_string())?
        };
        model_value(h)
    }

    /// The real call for a `commitRef` of `op`; returns its outcome.
    fn commit(&self, op: &Op) -> Result<&'static str, String> {
        let h = value_hash(op.value);
        let cond = condition(op.cond);
        match op.kind.as_str() {
            "commit" | "amend" | "updateRef" | "checkout" | "branch" if !op.del => {
                let cond = if self.fault == Fault::LocalMissingAsAny && op.cond == Cond::Missing {
                    RefWriteCondition::Any
                } else {
                    cond
                };
                local_outcome(refs::update_ref(
                    &self.layout,
                    branch(op.reference),
                    cond,
                    &h,
                ))
            }
            "branch" => match op.cond {
                Cond::Any => local_outcome(refs::delete_ref(&self.layout, branch(op.reference))),
                Cond::Match(_) if self.fault == Fault::ConditionalDeleteUnconditional => {
                    local_outcome(refs::delete_ref(&self.layout, branch(op.reference)))
                }
                Cond::Match(e) => local_outcome(refs::delete_ref_if_matches(
                    &self.layout,
                    branch(op.reference),
                    value_hash(e),
                )),
                Cond::Missing => Err("the model never deletes with Missing".into()),
            },
            "file" => {
                let cond = match op.cond {
                    Cond::Match(_) if self.fault == Fault::FileMatchAsAny => RefWriteCondition::Any,
                    _ => cond,
                };
                transport_outcome(
                    self.file
                        .update_ref(&transport_name(op.reference), cond, &h),
                )
            }
            "mem" => {
                let cond = match op.cond {
                    Cond::Match(_) if self.fault == Fault::MemMatchAsAny => RefWriteCondition::Any,
                    _ => cond,
                };
                transport_outcome(self.mem.update_ref(&transport_name(op.reference), cond, &h))
            }
            other => Err(format!("commitRef of unexpected op kind {other}")),
        }
    }

    /// Replay the step that produced `state` from `prev`. Returns the real
    /// outcome for a `commitRef`, `None` otherwise.
    fn apply(&mut self, prev: &State, state: &State) -> Result<Option<&'static str>, String> {
        let op = &state.op;
        match state.action.as_str() {
            // Locks: taken inside each real call (see the module docs).
            "begin" | "acquire" | "release" | "expireRead" => Ok(None),
            "record" => {
                if self.fault != Fault::RecordDropped {
                    let entry = RecoveryEntry {
                        timestamp: NOW,
                        op: "amend".into(),
                        superseded: entry_hash(prev.next_entry),
                        branch: branch(op.reference).into(),
                    };
                    recovery::record(&self.layout, &entry).map_err(|e| e.to_string())?;
                }
                Ok(None)
            }
            "readRef" => {
                let v = self.read_store(op)?;
                self.read.insert(state.proc_name.clone(), v);
                Ok(None)
            }
            "commitRef" => {
                let now = self.read_store(op)?;
                match self.read.remove(&state.proc_name) {
                    Some(seen) if seen != now => {
                        return Err(format!(
                            "non-linearizable trace: {} read {seen} but the ref is {now} at its commit \
                             (the cross-domain gap stepLin excludes)",
                            state.proc_name
                        ));
                    }
                    Some(_) => {}
                    None => return Err(format!("{} commits without a readRef", state.proc_name)),
                }
                self.commit(op).map(Some)
            }
            "expireWrite" => {
                recovery::expire(&self.layout, NOW, &RetentionPolicy::default())
                    .map_err(|e| e.to_string())?;
                Ok(None)
            }
            other => Err(format!("unknown model action {other}")),
        }
    }

    /// Compare the real observable state with the model's.
    fn compare(&self, state: &State) -> Result<(), String> {
        for (r, want) in &state.disk {
            let local =
                model_value(refs::read_ref(&self.layout, branch(*r)).map_err(|e| e.to_string())?)?;
            let via_file = model_value(
                self.file
                    .read_ref(&transport_name(*r))
                    .map_err(|e| e.to_string())?,
            )?;
            if local != *want || via_file != *want {
                return Err(format!(
                    "{MISMATCH}disk ref {}: model {want}, refs::read_ref {local}, FileTransport {via_file}",
                    transport_name(*r)
                ));
            }
        }
        for (r, want) in &state.mem {
            let got = model_value(
                self.mem
                    .read_ref(&transport_name(*r))
                    .map_err(|e| e.to_string())?,
            )?;
            if got != *want {
                return Err(format!(
                    "{MISMATCH}memory ref {}: model {want}, real {got}",
                    transport_name(*r)
                ));
            }
        }
        let roots = recovery::roots(&self.layout).map_err(|e| e.to_string())?;
        let want: BTreeSet<Hash> = state.rec_log.iter().map(|id| entry_hash(*id)).collect();
        if roots != want {
            return Err(format!(
                "{MISMATCH}recovery log: model entries {:?}, real log holds {} entries matching {:?}",
                state.rec_log,
                roots.len(),
                (1..=MAX_ID)
                    .filter(|id| roots.contains(&entry_hash(*id)))
                    .collect::<Vec<_>>()
            ));
        }
        Ok(())
    }
}

// --------------------------------------------------------------- replay

/// What one replay exercised (commitRef outcomes by domain and shape).
#[derive(Debug, Default)]
struct Coverage {
    steps: usize,
    commits: BTreeMap<String, usize>,
    records: usize,
    expires_of_nonempty_log: usize,
}

impl Coverage {
    fn merge(&mut self, other: Coverage) {
        self.steps += other.steps;
        for (k, n) in other.commits {
            *self.commits.entry(k).or_default() += n;
        }
        self.records += other.records;
        self.expires_of_nonempty_log += other.expires_of_nonempty_log;
    }

    fn has(&self, key: &str) -> bool {
        self.commits.get(key).is_some_and(|n| *n > 0)
    }
}

fn commit_key(op: &Op, outcome: &str) -> String {
    let shape = match (op.del, op.cond) {
        (true, Cond::Any) => "delete",
        (true, _) => "delete-if-matches",
        (false, Cond::Any) => "any",
        (false, Cond::Missing) => "missing",
        (false, Cond::Match(_)) => "match",
    };
    format!("{}/{shape}/{outcome}", op.kind)
}

/// Replay one trace; `Err` names the fixture, state and discrepancy.
fn replay(name: &str, trace: &[State], fault: Fault) -> Result<Coverage, String> {
    let at = |s: &State, msg: String| {
        format!(
            "{name} state {} ({} {}): {msg}",
            s.index, s.action, s.proc_name
        )
    };
    let first = trace
        .first()
        .ok_or_else(|| format!("{name}: empty trace"))?;
    if first.action != "init" {
        return Err(format!("{name}: first state is not init"));
    }
    let mut sut = Sut::new(first, fault).map_err(|e| at(first, e))?;
    sut.compare(first).map_err(|e| at(first, e))?;
    let mut cov = Coverage::default();
    for pair in trace.windows(2) {
        let (prev, state) = (&pair[0], &pair[1]);
        if state.violations != 0 {
            return Err(at(
                state,
                "model recorded a lost update (trace not from stepLin?)".into(),
            ));
        }
        let real = sut.apply(prev, state).map_err(|e| at(state, e))?;
        if let Some(real) = real {
            if real != state.outcome {
                return Err(at(
                    state,
                    format!(
                        "{MISMATCH}{:?}: model outcome {:?}, real outcome {real:?}",
                        state.op, state.outcome
                    ),
                ));
            }
            *cov.commits.entry(commit_key(&state.op, real)).or_default() += 1;
        }
        match state.action.as_str() {
            "record" => cov.records += 1,
            "expireWrite" if !prev.rec_log.is_empty() => cov.expires_of_nonempty_log += 1,
            _ => {}
        }
        sut.compare(state).map_err(|e| at(state, e))?;
        cov.steps += 1;
    }
    Ok(cov)
}

fn fixture_name(p: &Path) -> String {
    p.file_name()
        .expect("file name")
        .to_string_lossy()
        .into_owned()
}

#[test]
fn refs_traces_replay_against_the_implementation() {
    let mut total = Coverage::default();
    for path in fixtures() {
        let name = fixture_name(&path);
        let cov = replay(&name, &load_trace(&path), Fault::None).unwrap_or_else(|e| panic!("{e}"));
        total.merge(cov);
    }
    // Non-vacuity of the fixture set: together the traces must reach every
    // op kind's commit and each CAS outcome in each lock domain.
    let required = [
        "commit/match/ok",
        "commit/match/conflict",
        "updateRef/missing/ok",
        "updateRef/missing/conflict",
        "branch/delete/notfound",
        "branch/delete-if-matches/ok",
        "branch/delete-if-matches/conflict",
        "file/match/ok",
        "file/match/conflict",
        "file/missing/conflict",
        "mem/match/ok",
        "mem/match/conflict",
        "mem/missing/conflict",
    ];
    let missing: Vec<&str> = required.iter().copied().filter(|k| !total.has(k)).collect();
    assert!(
        missing.is_empty(),
        "fixtures no longer cover {missing:?} (coverage: {:?}); regenerate with other seeds",
        total.commits
    );
    for kind in [
        "commit",
        "amend",
        "updateRef",
        "branch",
        "checkout",
        "file",
        "mem",
    ] {
        assert!(
            total
                .commits
                .keys()
                .any(|k| k.starts_with(&format!("{kind}/"))),
            "no {kind} commit replayed"
        );
    }
    assert!(total.records > 0, "no recovery record replayed");
    assert!(
        total.expires_of_nonempty_log > 0,
        "no expire of a non-empty log replayed"
    );
}

#[test]
fn harness_detects_adapter_faults() {
    let traces: Vec<(String, Vec<State>)> = fixtures()
        .iter()
        .map(|p| (fixture_name(p), load_trace(p)))
        .collect();
    for fault in [
        Fault::LocalMissingAsAny,
        Fault::FileMatchAsAny,
        Fault::MemMatchAsAny,
        Fault::ConditionalDeleteUnconditional,
        Fault::RecordDropped,
    ] {
        let caught = traces
            .iter()
            .find_map(|(name, t)| replay(name, t, fault).err())
            .unwrap_or_else(|| panic!("adapter fault {fault:?} went undetected by every trace"));
        // Caught as a model/implementation disagreement, not a harness error.
        assert!(caught.contains(MISMATCH), "{fault:?}: {caught}");
    }
}

#[test]
fn harness_detects_a_tampered_trace() {
    let path = &fixtures()[0];
    let mut trace = load_trace(path);
    // Flip the first commit outcome the model recorded.
    let i = trace
        .iter()
        .position(|s| s.action == "commitRef")
        .expect("trace has a commitRef");
    trace[i].outcome = if trace[i].outcome == "ok" {
        "conflict"
    } else {
        "ok"
    }
    .into();
    let err =
        replay(&fixture_name(path), &trace, Fault::None).expect_err("tampered outcome caught");
    assert!(
        err.contains(&format!("state {i} ")) && err.contains(MISMATCH),
        "{err}"
    );

    // Change a ref value the model reports after a successful write.
    let mut trace = load_trace(path);
    let i = trace
        .iter()
        .position(|s| s.action == "commitRef" && s.outcome == "ok" && !s.op.del)
        .expect("trace has a successful write");
    let r = trace[i].op.reference;
    let store = if trace[i].op.kind == "mem" {
        &mut trace[i].mem
    } else {
        &mut trace[i].disk
    };
    let v = store.get_mut(&r).expect("ref in store");
    *v = if *v == 1 { 2 } else { 1 };
    let err = replay(&fixture_name(path), &trace, Fault::None).expect_err("tampered value caught");
    assert!(
        err.contains(&format!("state {i} ")) && err.contains(MISMATCH),
        "{err}"
    );
}
