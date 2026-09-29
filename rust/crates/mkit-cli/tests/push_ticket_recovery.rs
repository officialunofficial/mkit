//! The CLI's typed ticket recovery and its pre-admission pack cap.
#![allow(clippy::unwrap_used)]

mod common;

use std::path::PathBuf;
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

use common::Repo;
use mkit_cli::remote_dispatch::{
    DispatchError, PushControl, RetryReason, StepAuthority, plan_push_steps, push_all_with,
    push_branch_steps, push_branch_with_limits,
};
use mkit_core::hash::Hash;
use mkit_core::layout::RepoLayout;
use mkit_core::object::Object;
use mkit_core::ops::graph::reachable_objects;
use mkit_core::protocol::{
    CommitOutcome, PackKey, RefWriteCondition, Transport, TransportError, TransportResult,
    UploadLimits,
};
use mkit_core::refs::{self, Ref};
use mkit_core::store::ObjectStore;
use mkit_transport_memory::MemoryTransport;

#[derive(Clone, Copy)]
enum Fault {
    None,
    Rejected,
    Packlist,
    Delta,
    RejectedTwice,
    LandedThenRejected,
    /// Every advance attempt from this one on fails: the connection is lost.
    LostFrom(usize),
    /// Another pusher moves the branch just before this attempt.
    Interleave(usize),
}

/// One advance attempt as the server saw it.
#[derive(Debug)]
struct Advance {
    head_condition: RefWriteCondition,
    head_value: Hash,
    tickets: usize,
    /// Packs uploaded before this attempt.
    uploads_at: usize,
}

struct TicketTransport {
    inner: MemoryTransport,
    fault: Fault,
    /// The advance attempt (0-based) the one-shot faults strike.
    fault_attempt: usize,
    advance_log: Mutex<Vec<Advance>>,
    upload_keys: Mutex<Vec<PackKey>>,
    /// A scratch repo fetched from after every landed advance: each published
    /// intermediate state must reconstruct.
    verify_into: Option<PathBuf>,
    verified: Mutex<Vec<Hash>>,
    advances: AtomicUsize,
    uploads: AtomicUsize,
    largest_upload: AtomicUsize,
    upload_lengths: Mutex<Vec<usize>>,
    max_pack_bytes: Option<u64>,
    ticket_threshold_bytes: Option<u64>,
    tickets_per_advance: Option<usize>,
}

impl TicketTransport {
    fn new(fault: Fault) -> Self {
        Self {
            inner: MemoryTransport::new(),
            fault,
            fault_attempt: 0,
            advance_log: Mutex::new(Vec::new()),
            upload_keys: Mutex::new(Vec::new()),
            verify_into: None,
            verified: Mutex::new(Vec::new()),
            advances: AtomicUsize::new(0),
            uploads: AtomicUsize::new(0),
            largest_upload: AtomicUsize::new(0),
            upload_lengths: Mutex::new(Vec::new()),
            max_pack_bytes: None,
            ticket_threshold_bytes: Some(0),
            tickets_per_advance: Some(7),
        }
    }
}

impl Transport for TicketTransport {
    fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        self.uploads.fetch_add(1, Ordering::SeqCst);
        self.largest_upload.fetch_max(bytes.len(), Ordering::SeqCst);
        self.upload_lengths.lock().unwrap().push(bytes.len());
        self.upload_keys.lock().unwrap().push(*key);
        self.inner.upload_pack(bytes, key)
    }
    fn download_pack(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        self.inner.download_pack(key)
    }
    fn pack_exists(&self, key: &PackKey) -> TransportResult<bool> {
        self.inner.pack_exists(key)
    }
    fn upload_blob(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        self.inner.upload_blob(bytes, key)
    }
    fn download_blob(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        self.inner.download_blob(key)
    }
    fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        hash: &Hash,
    ) -> TransportResult<()> {
        self.inner.update_ref(name, condition, hash)
    }
    fn read_ref(&self, name: &str) -> TransportResult<Option<Hash>> {
        self.inner.read_ref(name)
    }
    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<Ref>> {
        self.inner.list_refs(prefix)
    }
    fn upload_limits(&self) -> UploadLimits {
        UploadLimits {
            max_pack_bytes: self.max_pack_bytes,
            tickets_per_advance: self.tickets_per_advance,
            ticket_threshold_bytes: self.ticket_threshold_bytes,
        }
    }
    fn supports_atomic_advance(&self) -> bool {
        true
    }
    fn advance_refs_committing(
        &self,
        head_ref: &str,
        head_condition: RefWriteCondition,
        head_value: &Hash,
        packmap_ref: &str,
        packmap_condition: RefWriteCondition,
        packmap_value: &Hash,
        commit: &[PackKey],
    ) -> TransportResult<CommitOutcome> {
        let attempt = self.advances.fetch_add(1, Ordering::SeqCst);
        self.advance_log.lock().unwrap().push(Advance {
            head_condition,
            head_value: *head_value,
            tickets: commit.len(),
            uploads_at: self.upload_keys.lock().unwrap().len(),
        });
        let relative = attempt.checked_sub(self.fault_attempt);
        let fault = match (self.fault, relative) {
            (Fault::Rejected, Some(0)) | (Fault::RejectedTwice, Some(0..=1)) => {
                Some(CommitOutcome::TicketRejected)
            }
            (Fault::Packlist, Some(0)) => Some(CommitOutcome::PacklistNotInRepository),
            (Fault::Delta, Some(0)) => Some(CommitOutcome::DeltaBaseUnavailable),
            (Fault::LandedThenRejected, Some(0)) => {
                self.inner.advance_refs(
                    head_ref,
                    head_condition,
                    head_value,
                    packmap_ref,
                    packmap_condition,
                    packmap_value,
                )?;
                Some(CommitOutcome::TicketRejected)
            }
            (Fault::LostFrom(from), _) if attempt >= from => {
                return Err(TransportError::RemoteError("connection lost".to_owned()));
            }
            (Fault::Interleave(at), _) if attempt == at => {
                // A concurrent pusher wins the branch first.
                self.inner
                    .update_ref(head_ref, RefWriteCondition::Any, &[0xee; 32])?;
                None
            }
            _ => None,
        };
        if let Some(fault) = fault {
            return Ok(fault);
        }
        let outcome = self.inner.advance_refs(
            head_ref,
            head_condition,
            head_value,
            packmap_ref,
            packmap_condition,
            packmap_value,
        )?;
        if let Some(path) = &self.verify_into
            && matches!(outcome, mkit_core::protocol::AdvanceOutcome::Committed)
        {
            mkit_cli::remote_dispatch::fetch_all(path, &self.inner, "origin").unwrap();
            let layout = RepoLayout::single(path);
            let fetched = refs::read_remote_ref(&layout, "origin", "main")
                .unwrap()
                .unwrap();
            assert_eq!(fetched, *head_value, "the published head reconstructs");
            self.verified.lock().unwrap().push(fetched);
        }
        Ok(CommitOutcome::Advanced(outcome))
    }
}

fn tip(repo: &Repo) -> Hash {
    refs::read_ref(&RepoLayout::single(repo.path()), "main")
        .unwrap()
        .unwrap()
}

fn push(repo: &Repo, tx: &TicketTransport, cap: u64) -> Result<(), DispatchError> {
    let store = ObjectStore::open(&RepoLayout::single(repo.path())).unwrap();
    push_branch_with_limits(
        tx,
        &store,
        "main",
        tip(repo),
        RefWriteCondition::Missing,
        0,
        cap,
    )
}

fn filler(seed: u64, len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    let mut state = seed | 1;
    for chunk in bytes.chunks_mut(8) {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
    }
    bytes
}

#[test]
fn typed_ticket_failures_restart_once_and_landed_write_succeeds() {
    for (fault, expected_attempts) in [
        (Fault::Rejected, 2),
        (Fault::Packlist, 2),
        (Fault::Delta, 2),
        (Fault::LandedThenRejected, 1),
    ] {
        let repo = Repo::new();
        repo.commit_file("a", b"content", "one");
        let tx = TicketTransport::new(fault);
        push(&repo, &tx, 4096).unwrap();
        assert_eq!(tx.advances.load(Ordering::SeqCst), expected_attempts);
        assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(tip(&repo)));
    }

    let repo = Repo::new();
    repo.commit_file("a", b"content", "one");
    let tx = TicketTransport::new(Fault::RejectedTwice);
    assert!(matches!(
        push(&repo, &tx, 4096),
        Err(DispatchError::TicketRejected)
    ));
    assert_eq!(tx.advances.load(Ordering::SeqCst), 2);
}

#[test]
fn seventh_data_pack_is_refused_before_its_begin_upload() {
    let repo = Repo::new();
    for i in 0_u64..18 {
        let bytes = filler(i * 2 + 1, 2048);
        repo.write(&format!("f{i}.bin"), &bytes);
    }
    repo.ok(&["add", "."]);
    repo.ok(&["commit", "-m", "many files"]);
    let tx = TicketTransport::new(Fault::None);
    let err = push(&repo, &tx, 4096).unwrap_err();
    // One commit cannot be split, so the exact local dry seal refuses it
    // before any pack goes up (WP-1.17b); it names the commit.
    match &err {
        DispatchError::PushTooLarge {
            packs: 7,
            limit: 6,
            commit: Some(commit),
            ..
        } => assert!(
            commit.contains(&mkit_core::hash::to_hex(&tip(&repo))),
            "{err}"
        ),
        other => panic!("{other:?}"),
    }
    assert_eq!(tx.uploads.load(Ordering::SeqCst), 0);
    assert_eq!(tx.advances.load(Ordering::SeqCst), 0);
}

#[test]
fn ticketless_multi_pack_push_is_not_subject_to_ticket_cap() {
    let repo = Repo::new();
    for i in 0_u64..18 {
        let bytes = filler(i * 2 + 1, 2048);
        repo.write(&format!("f{i}.bin"), &bytes);
    }
    repo.ok(&["add", "."]);
    repo.ok(&["commit", "-m", "many files"]);
    // A V2 server whose threshold no pack reaches, and one reached without a
    // signer (tickets_per_advance None): neither is subject to the cap.
    for signer in [true, false] {
        let mut tx = TicketTransport::new(Fault::None);
        if signer {
            tx.ticket_threshold_bytes = Some(u64::MAX);
        } else {
            tx.tickets_per_advance = None;
        }
        tx.max_pack_bytes = Some(4096);
        push(&repo, &tx, 4096).unwrap();
        assert!(tx.uploads.load(Ordering::SeqCst) > 6);
        assert!(tx.largest_upload.load(Ordering::SeqCst) <= 4096);
    }
}

#[test]
fn compressible_push_is_not_refused_by_an_uncompressed_estimate() {
    let repo = Repo::new();
    // Highly compressible: about 60 KiB raw, far fewer bytes once packed.
    for i in 0_u64..30 {
        repo.write(&format!("c{i}.txt"), &vec![b'a' + (i % 26) as u8; 2048]);
    }
    repo.ok(&["add", "."]);
    repo.ok(&["commit", "-m", "compressible"]);
    let mut tx = TicketTransport::new(Fault::None);
    tx.max_pack_bytes = Some(8192);
    push(&repo, &tx, 8192).unwrap();
    assert!(tx.uploads.load(Ordering::SeqCst) <= 6);
}

#[test]
fn rebaseline_over_six_packs_keeps_the_append_plan() {
    for (threshold, should_append) in [(0, true), (u64::MAX, false)] {
        let repo = Repo::new();
        for i in 0_u64..16 {
            repo.write(&format!("f{i}.bin"), &filler(i * 2 + 1, 2048));
        }
        repo.ok(&["add", "."]);
        repo.ok(&["commit", "-m", "large base"]);
        let base = tip(&repo);
        let mut tx = TicketTransport::new(Fault::None);
        tx.ticket_threshold_bytes = Some(u64::MAX);
        let store = ObjectStore::open(&RepoLayout::single(repo.path())).unwrap();
        push_branch_with_limits(
            &tx,
            &store,
            "main",
            base,
            RefWriteCondition::Missing,
            0,
            4096,
        )
        .unwrap();

        tx.ticket_threshold_bytes = Some(threshold);
        repo.commit_file("next", b"small update", "next");
        let store = ObjectStore::open(&RepoLayout::single(repo.path())).unwrap();
        push_branch_with_limits(
            &tx,
            &store,
            "main",
            tip(&repo),
            RefWriteCondition::Match(base),
            1,
            4096,
        )
        .unwrap();
        assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(tip(&repo)));
        let newest = tx.read_ref("refs/mkit/packmap/main").unwrap().unwrap();
        let node =
            mkit_core::transfer::decode_packlist(&tx.download_blob(&PackKey::new(newest)).unwrap())
                .unwrap();
        assert_eq!(node.prev.is_some(), should_append);
    }
}

#[test]
fn many_small_entries_split_before_serialized_pack_limit() {
    let repo = Repo::new();
    for i in 0_u64..100 {
        repo.write(&format!("d{}/f{i}.bin", i / 10), &filler(i + 1, 8));
    }
    repo.ok(&["add", "."]);
    repo.ok(&["commit", "-m", "many small files"]);
    let mut tx = TicketTransport::new(Fault::None);
    tx.ticket_threshold_bytes = Some(u64::MAX);
    tx.max_pack_bytes = Some(1024);
    push(&repo, &tx, 1024).unwrap();
    let sizes = tx.upload_lengths.lock().unwrap();
    assert!(sizes.len() > 1);
    assert!(sizes.iter().all(|&size| size <= 1024), "{sizes:?}");
}

#[test]
fn missing_delta_base_restarts_with_self_contained_bytes() {
    let repo = Repo::new();
    let mut bytes = filler(17, 1_200_000);
    repo.write("big.bin", &bytes);
    repo.ok(&["add", "."]);
    repo.ok(&["commit", "-m", "base"]);
    let base = tip(&repo);
    let mut tx = TicketTransport::new(Fault::None);
    let store = ObjectStore::open(&RepoLayout::single(repo.path())).unwrap();
    push_branch_with_limits(
        &tx,
        &store,
        "main",
        base,
        RefWriteCondition::Missing,
        0,
        2 << 20,
    )
    .unwrap();

    for byte in &mut bytes[600_000..600_016] {
        *byte ^= 0xff;
    }
    repo.write("big.bin", &bytes);
    repo.ok(&["add", "."]);
    repo.ok(&["commit", "-m", "edit"]);
    tx.fault = Fault::Delta;
    tx.advances.store(0, Ordering::SeqCst);
    tx.upload_lengths.lock().unwrap().clear();
    let store = ObjectStore::open(&RepoLayout::single(repo.path())).unwrap();
    push_branch_with_limits(
        &tx,
        &store,
        "main",
        tip(&repo),
        RefWriteCondition::Match(base),
        0,
        2 << 20,
    )
    .unwrap();
    let lengths = tx.upload_lengths.lock().unwrap();
    assert_eq!(tx.advances.load(Ordering::SeqCst), 2);
    assert!(lengths.len() >= 2, "one pack was uploaded for each plan");
    assert!(lengths[0] < 16 * 1024, "incremental delta: {lengths:?}");
    assert!(lengths[1] > 1_000_000, "self-contained retry: {lengths:?}");
}

// ---------------------------------------------------------------------------
// Splitting an oversized push along first-parent history (WP-1.17b, R-164)
// ---------------------------------------------------------------------------

const CAP: u64 = 4096;

/// `n` commits on main, each adding one incompressible file of `len` bytes.
fn long_history(repo: &Repo, n: u64, len: usize) {
    for i in 0..n {
        repo.commit_file(
            &format!("f{i}.bin"),
            &filler(i * 2 + 1, len),
            &format!("c{i}"),
        );
    }
}

fn store(repo: &Repo) -> ObjectStore {
    ObjectStore::open(&RepoLayout::single(repo.path())).unwrap()
}

/// `from` and its first parents, newest first.
fn first_parents(repo: &Repo, from: Hash) -> Vec<Hash> {
    let store = store(repo);
    let mut chain = vec![from];
    while let Object::Commit(commit) = store.read_object(chain.last().unwrap()).unwrap() {
        let Some(parent) = commit.parents.first() else {
            break;
        };
        chain.push(*parent);
    }
    chain
}

fn split_transport() -> TicketTransport {
    let mut tx = TicketTransport::new(Fault::None);
    tx.max_pack_bytes = Some(8192);
    tx
}

/// Push main's tip with the split machinery; the heads reported per advance.
fn push_steps(
    repo: &Repo,
    tx: &TicketTransport,
    condition: RefWriteCondition,
    control: &PushControl<'_>,
) -> (Result<usize, DispatchError>, Vec<Hash>) {
    let mut heads = Vec::new();
    let result = push_branch_steps(
        tx,
        &store(repo),
        "main",
        tip(repo),
        condition,
        0,
        CAP,
        control,
        &mut |head| {
            heads.push(head);
            Ok(())
        },
    );
    (result, heads)
}

fn planned_steps(repo: &Repo, tx: &TicketTransport, remote: Option<Hash>) -> Vec<Hash> {
    plan_push_steps(
        &store(repo),
        tip(repo),
        remote,
        tx.upload_limits(),
        CAP,
        &PushControl::default(),
        RefWriteCondition::Missing,
        "main",
    )
    .unwrap()
}

fn assert_split(repo: &Repo, tx: &TicketTransport, heads: &[Hash]) {
    let chain = first_parents(repo, tip(repo));
    let positions: Vec<usize> = heads
        .iter()
        .map(|head| {
            chain
                .iter()
                .position(|c| c == head)
                .expect("first-parent ancestor")
        })
        .collect();
    assert!(positions.windows(2).all(|w| w[0] > w[1]), "{positions:?}");
    assert_eq!(heads.last(), Some(&tip(repo)));
    assert!(
        tx.advance_log
            .lock()
            .unwrap()
            .iter()
            .all(|a| a.tickets <= 7)
    );
}

#[test]
fn oversized_push_is_split_along_first_parent_history() {
    let repo = Repo::new();
    long_history(&repo, 14, 3000);
    let scratch = Repo::new();
    let mut tx = split_transport();
    tx.verify_into = Some(scratch.path().to_path_buf());
    let (result, heads) = push_steps(
        &repo,
        &tx,
        RefWriteCondition::Missing,
        &PushControl::default(),
    );
    let steps = result.unwrap();
    assert!(steps >= 2, "{steps}");
    assert_eq!(heads.len(), steps);
    assert_split(&repo, &tx, &heads);
    // Every published intermediate state reconstructed on a fetch, and the
    // last one is the whole closure.
    assert_eq!(*tx.verified.lock().unwrap(), heads);
    let closure = reachable_objects(&store(&scratch), &tip(&repo)).unwrap();
    assert_eq!(
        closure,
        reachable_objects(&store(&repo), &tip(&repo)).unwrap()
    );
    // The first advance uses the caller's condition, every later one is a
    // Match on the previous advance.
    let log = tx.advance_log.lock().unwrap();
    assert_eq!(log.len(), steps);
    assert_eq!(log[0].head_condition, RefWriteCondition::Missing);
    for k in 1..steps {
        assert_eq!(
            log[k].head_condition,
            RefWriteCondition::Match(heads[k - 1])
        );
        assert_eq!(log[k].head_value, heads[k]);
    }
}

#[test]
fn later_steps_stay_conditional_under_force() {
    let repo = Repo::new();
    long_history(&repo, 14, 3000);
    let tx = split_transport();
    let (result, heads) = push_steps(&repo, &tx, RefWriteCondition::Any, &PushControl::default());
    result.unwrap();
    let log = tx.advance_log.lock().unwrap();
    assert_eq!(log[0].head_condition, RefWriteCondition::Any);
    for k in 1..heads.len() {
        assert_eq!(
            log[k].head_condition,
            RefWriteCondition::Match(heads[k - 1])
        );
    }
}

#[test]
fn pushes_within_the_budget_are_not_split() {
    let repo = Repo::new();
    long_history(&repo, 2, 200);
    let tx = split_transport();
    let (result, heads) = push_steps(
        &repo,
        &tx,
        RefWriteCondition::Missing,
        &PushControl::default(),
    );
    assert_eq!(result.unwrap(), 1);
    assert_eq!(heads, [tip(&repo)]);
    assert_eq!(tx.advances.load(Ordering::SeqCst), 1);

    // Without tickets there is no per-advance budget to split for.
    let big = Repo::new();
    long_history(&big, 14, 3000);
    let mut tx = split_transport();
    tx.tickets_per_advance = None;
    let (result, _) = push_steps(
        &big,
        &tx,
        RefWriteCondition::Missing,
        &PushControl::default(),
    );
    assert_eq!(result.unwrap(), 1);
    assert_eq!(tx.advances.load(Ordering::SeqCst), 1);
}

/// A remote holding main's first commit, and the transport for it.
fn seeded(repo: &Repo) -> (TicketTransport, Hash) {
    repo.commit_file("base.txt", b"base", "base");
    let tx = split_transport();
    push(repo, &tx, CAP).unwrap();
    let base = tip(repo);
    tx.advances.store(0, Ordering::SeqCst);
    tx.advance_log.lock().unwrap().clear();
    tx.uploads.store(0, Ordering::SeqCst);
    (tx, base)
}

/// A merge of `side_files` incompressible files into main, after main took
/// `main_commits` commits of its own.
fn merge_repo(repo: &Repo, main_commits: u64, side_files: u64) {
    repo.ok(&["branch", "side"]);
    repo.ok(&["checkout", "side"]);
    for i in 0..side_files {
        repo.write(&format!("side{i}.bin"), &filler(i * 2 + 101, 2048));
    }
    repo.ok(&["add", "."]);
    repo.ok(&["commit", "-m", "side"]);
    repo.ok(&["checkout", "main"]);
    long_history(repo, main_commits, 3000);
    repo.ok(&["merge", "side"]);
}

#[test]
fn oversize_merge_fails_before_anything_is_published() {
    let repo = Repo::new();
    let (tx, base) = seeded(&repo);
    merge_repo(&repo, 1, 20);
    let store = store(&repo);
    let err = push_branch_with_limits(
        &tx,
        &store,
        "main",
        tip(&repo),
        RefWriteCondition::Match(base),
        0,
        CAP,
    )
    .unwrap_err();
    let DispatchError::PushTooLarge {
        commit: Some(commit),
        ..
    } = &err
    else {
        panic!("{err:?}");
    };
    let Object::Commit(merge) = store.read_object(&tip(&repo)).unwrap() else {
        panic!("tip is a commit");
    };
    assert!(commit.contains("merge commit"), "{commit}");
    assert!(
        commit.contains(&mkit_core::hash::to_hex(&merge.parents[1])),
        "{commit}"
    );
    assert_eq!(tx.uploads.load(Ordering::SeqCst), 0);
    assert_eq!(tx.advances.load(Ordering::SeqCst), 0);
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(base));
}

#[test]
fn small_merge_rides_inside_a_step() {
    let repo = Repo::new();
    let (tx, base) = seeded(&repo);
    merge_repo(&repo, 10, 1);
    let (result, heads) = push_steps(
        &repo,
        &tx,
        RefWriteCondition::Match(base),
        &PushControl::default(),
    );
    assert!(result.unwrap() >= 2);
    assert_split(&repo, &tx, &heads);
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(tip(&repo)));
}

#[test]
fn interrupted_split_resumes_from_the_published_prefix() {
    let repo = Repo::new();
    long_history(&repo, 14, 3000);
    let mut tx = split_transport();
    let total = planned_steps(&repo, &tx, None).len();
    assert!(total >= 3, "{total}");

    tx.fault = Fault::LostFrom(2);
    let (result, heads) = push_steps(
        &repo,
        &tx,
        RefWriteCondition::Missing,
        &PushControl::default(),
    );
    let error = result.unwrap_err();
    let DispatchError::SplitInterrupted {
        published,
        total: reported,
        head,
        cause,
        ..
    } = &error
    else {
        panic!("{error:?}");
    };
    assert_eq!((*published, *reported), (2, total));
    assert_eq!(*head, mkit_core::hash::to_hex(&heads[1]));
    assert!(matches!(**cause, DispatchError::Transport(_)), "{cause:?}");
    let text = error.to_string();
    assert!(text.contains("re-run the push to resume"), "{text}");
    assert!(text.contains("the last published advance was"), "{text}");
    assert_eq!(heads.len(), 2);
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(heads[1]));
    let (interrupted, prefix) = error.into_published_prefix();
    assert!(matches!(interrupted, DispatchError::Transport(_)));
    assert_eq!(prefix.unwrap().published, 2);

    // The interrupted step's packs, and the advance that never landed.
    let (failed_keys, uploads_before_rerun) = {
        let log = tx.advance_log.lock().unwrap();
        let keys = tx.upload_keys.lock().unwrap();
        (
            keys[log[1].uploads_at..log[2].uploads_at].to_vec(),
            keys.len(),
        )
    };
    assert!(!failed_keys.is_empty());

    // Re-running from the tracking ref (the last published head) finishes
    // with the same total, regenerating the interrupted step's packs.
    tx.fault = Fault::None;
    let (result, resumed) = push_steps(
        &repo,
        &tx,
        RefWriteCondition::Match(heads[1]),
        &PushControl::default(),
    );
    assert_eq!(2 + result.unwrap(), total);
    assert_eq!(resumed.last(), Some(&tip(&repo)));
    let keys = tx.upload_keys.lock().unwrap();
    assert_eq!(
        keys[uploads_before_rerun..][..failed_keys.len()],
        failed_keys[..]
    );
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(tip(&repo)));
}

#[test]
fn concurrent_push_between_steps_reports_the_published_prefix() {
    let repo = Repo::new();
    long_history(&repo, 14, 3000);
    let mut tx = split_transport();
    tx.fault = Fault::Interleave(1);
    let (result, heads) = push_steps(
        &repo,
        &tx,
        RefWriteCondition::Missing,
        &PushControl::default(),
    );
    let error = result.unwrap_err();
    let DispatchError::SplitInterrupted {
        published, cause, ..
    } = &error
    else {
        panic!("{error:?}");
    };
    assert_eq!(*published, 1);
    assert!(
        matches!(**cause, DispatchError::NonFastForwardPush { .. }),
        "{cause:?}"
    );
    assert_eq!(heads.len(), 1);
    // The branch moved, so the advice is not to simply re-run.
    let text = error.to_string();
    assert!(!text.contains("re-run the push to resume"), "{text}");
    assert!(text.contains("moved by another push"), "{text}");
    let (_, prefix) = error.into_published_prefix();
    let note = prefix.unwrap().note();
    assert!(!note.contains("re-run"), "{note}");
    // The concurrent pusher's head was not overwritten.
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some([0xee; 32]));
}

#[test]
fn each_step_recovers_on_its_own() {
    let repo = Repo::new();
    long_history(&repo, 14, 3000);
    let total = planned_steps(&repo, &split_transport(), None).len();
    for (fault, extra_attempts) in [
        (Fault::Rejected, 1),
        (Fault::Packlist, 1),
        (Fault::LandedThenRejected, 0),
    ] {
        let mut tx = split_transport();
        tx.fault = fault;
        tx.fault_attempt = 1;
        let (result, heads) = push_steps(
            &repo,
            &tx,
            RefWriteCondition::Missing,
            &PushControl::default(),
        );
        assert_eq!(result.unwrap(), total);
        assert_eq!(heads.len(), total);
        assert_eq!(tx.advances.load(Ordering::SeqCst), total + extra_attempts);
    }

    // A second rejection in one step is final, and names the prefix.
    let mut tx = split_transport();
    tx.fault = Fault::RejectedTwice;
    tx.fault_attempt = 1;
    let error = push_steps(
        &repo,
        &tx,
        RefWriteCondition::Missing,
        &PushControl::default(),
    )
    .0
    .unwrap_err();
    let (cause, prefix) = error.into_published_prefix();
    assert!(matches!(cause, DispatchError::TicketRejected), "{cause:?}");
    assert_eq!(prefix.unwrap().published, 1);

    // A missing delta base re-plans the step as its full closure; that no
    // longer fits one advance. The dry seal refuses it before anything is
    // uploaded for the retry, with an error that names the lost base, and the
    // error says what was published.
    let mut tx = split_transport();
    tx.fault = Fault::Delta;
    tx.fault_attempt = 1;
    let error = push_steps(
        &repo,
        &tx,
        RefWriteCondition::Missing,
        &PushControl::default(),
    )
    .0
    .unwrap_err();
    let (cause, prefix) = error.into_published_prefix();
    assert!(
        matches!(
            cause,
            DispatchError::RetryTooLarge {
                reason: RetryReason::LostDeltaBase,
                ..
            }
        ),
        "{cause:?}"
    );
    assert!(cause.to_string().contains("delta base"), "{cause}");
    assert_eq!(prefix.unwrap().published, 1);
    let log = tx.advance_log.lock().unwrap();
    assert_eq!(log.len(), 2, "no advance was attempted for the retry");
    assert_eq!(
        tx.uploads.load(Ordering::SeqCst),
        log[1].uploads_at,
        "nothing was uploaded for the retry"
    );
}

#[test]
fn a_heavy_but_compressible_commit_rides_a_multi_step_split() {
    let repo = Repo::new();
    long_history(&repo, 8, 3000);
    for i in 0_u8..12 {
        repo.write(&format!("z{i}.bin"), &vec![i + 1; 3000]);
    }
    repo.ok(&["add", "."]);
    repo.ok(&["commit", "-m", "compressible"]);
    let heavy = tip(&repo);
    for i in 0..4 {
        repo.commit_file(&format!("g{i}.bin"), &filler(i * 2 + 501, 3000), "after");
    }
    let tx = split_transport();
    let (result, heads) = push_steps(
        &repo,
        &tx,
        RefWriteCondition::Missing,
        &PushControl::default(),
    );
    assert!(result.unwrap() >= 3);
    assert_split(&repo, &tx, &heads);
    // Its uncompressed estimate is over budget: the step is verified by an
    // exact dry seal, which passes, and the commit is published on its own.
    assert!(heads.contains(&heavy));
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(tip(&repo)));
}

struct Authority {
    refuse: bool,
    calls: Mutex<Vec<(RefWriteCondition, bool)>>,
}

impl StepAuthority for Authority {
    fn authorize(
        &self,
        _branch: &str,
        first: RefWriteCondition,
        later_steps: bool,
    ) -> Result<(), String> {
        self.calls.lock().unwrap().push((first, later_steps));
        if self.refuse {
            Err("no grant".to_owned())
        } else {
            Ok(())
        }
    }
}

#[test]
fn authority_is_checked_before_any_upload() {
    let repo = Repo::new();
    long_history(&repo, 14, 3000);
    let tx = split_transport();
    let refusing = Authority {
        refuse: true,
        calls: Mutex::new(Vec::new()),
    };
    let control = PushControl {
        authority: Some(&refusing),
        ..PushControl::default()
    };
    let error = push_steps(&repo, &tx, RefWriteCondition::Missing, &control)
        .0
        .unwrap_err();
    assert!(
        matches!(&error, DispatchError::PushNotAuthorized(m) if m == "no grant"),
        "{error:?}"
    );
    assert_eq!(tx.uploads.load(Ordering::SeqCst), 0);
    assert_eq!(tx.advances.load(Ordering::SeqCst), 0);
    assert_eq!(
        *refusing.calls.lock().unwrap(),
        [(RefWriteCondition::Missing, true)]
    );

    let allowing = Authority {
        refuse: false,
        calls: Mutex::new(Vec::new()),
    };
    let control = PushControl {
        authority: Some(&allowing),
        ..PushControl::default()
    };
    push_steps(&repo, &tx, RefWriteCondition::Missing, &control)
        .0
        .unwrap();

    // A push that is not split never consults it.
    let small = Repo::new();
    long_history(&small, 1, 100);
    let unused = Authority {
        refuse: true,
        calls: Mutex::new(Vec::new()),
    };
    let control = PushControl {
        authority: Some(&unused),
        ..PushControl::default()
    };
    push_steps(
        &small,
        &split_transport(),
        RefWriteCondition::Missing,
        &control,
    )
    .0
    .unwrap();
    assert!(unused.calls.lock().unwrap().is_empty());
}

#[test]
fn cuts_and_packs_are_deterministic() {
    let repo = Repo::new();
    long_history(&repo, 14, 3000);
    let first = split_transport();
    assert_eq!(
        planned_steps(&repo, &first, None),
        planned_steps(&repo, &first, None)
    );
    let second = split_transport();
    push_steps(
        &repo,
        &first,
        RefWriteCondition::Missing,
        &PushControl::default(),
    )
    .0
    .unwrap();
    push_steps(
        &repo,
        &second,
        RefWriteCondition::Missing,
        &PushControl::default(),
    )
    .0
    .unwrap();
    let keys = |tx: &TicketTransport| tx.upload_keys.lock().unwrap().clone();
    assert_eq!(keys(&first), keys(&second));
}

#[test]
fn step_and_chain_bounds_refuse_before_any_advance() {
    let repo = Repo::new();
    long_history(&repo, 14, 3000);
    for control in [
        PushControl {
            max_steps: 1,
            ..PushControl::default()
        },
        PushControl {
            max_chain: 3,
            ..PushControl::default()
        },
    ] {
        let tx = split_transport();
        let error = push_steps(&repo, &tx, RefWriteCondition::Missing, &control)
            .0
            .unwrap_err();
        assert!(
            matches!(error, DispatchError::PushSplitLimit(_)),
            "{error:?}"
        );
        assert_eq!(tx.uploads.load(Ordering::SeqCst), 0);
        assert_eq!(tx.advances.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn push_all_writes_the_tracking_ref_after_every_step() {
    let repo = Repo::new();
    long_history(&repo, 14, 3000);
    let layout = RepoLayout::single(repo.path());
    let tracked = || refs::read_remote_ref(&layout, "origin", "main").unwrap();

    let mut tx = split_transport();
    tx.fault = Fault::LostFrom(1);
    let error = push_all_with(repo.path(), &tx, Some("origin"), false, None).unwrap_err();
    let (_, prefix) = error.into_published_prefix();
    assert_eq!(prefix.unwrap().published, 1);
    let head = tx.read_ref("refs/heads/main").unwrap();
    assert!(head.is_some());
    assert_eq!(tracked(), head);

    tx.fault = Fault::None;
    let pushed = push_all_with(repo.path(), &tx, Some("origin"), false, None).unwrap();
    assert_eq!(pushed.refs, 1);
    assert!(pushed.steps >= 1);
    assert_eq!(tracked(), Some(tip(&repo)));

    // A second branch, pushed whole, gets its own tracking ref.
    repo.ok(&["branch", "extra"]);
    let tx = split_transport();
    let pushed = push_all_with(repo.path(), &tx, Some("mirror"), false, None).unwrap();
    assert_eq!(pushed.refs, 2);
    assert!(pushed.steps >= 2);
    for branch in ["main", "extra"] {
        assert_eq!(
            refs::read_remote_ref(&layout, "mirror", branch).unwrap(),
            Some(tip(&repo))
        );
    }
}

#[test]
fn every_published_head_contains_the_remote_head_it_replaced() {
    let repo = Repo::new();
    let (tx, base) = seeded(&repo);
    // Someone else advanced the remote branch.
    repo.ok(&["branch", "theirs"]);
    repo.ok(&["checkout", "theirs"]);
    repo.commit_file("theirs.txt", b"theirs", "theirs");
    let theirs = refs::read_ref(&RepoLayout::single(repo.path()), "theirs")
        .unwrap()
        .unwrap();
    push_branch_with_limits(
        &tx,
        &store(&repo),
        "main",
        theirs,
        RefWriteCondition::Match(base),
        0,
        CAP,
    )
    .unwrap();
    // Local work that then merges it: the remote head is reachable only
    // through the merge's second parent.
    repo.ok(&["checkout", "main"]);
    long_history(&repo, 10, 3000);
    repo.ok(&["merge", "theirs"]);
    // The first advance must already contain their commit, so the whole
    // prefix is one step; too big for one advance, it is refused up front
    // rather than published as a branch that drops their work.
    let advances_before = tx.advances.load(Ordering::SeqCst);
    let (result, heads) = push_steps(
        &repo,
        &tx,
        RefWriteCondition::Match(theirs),
        &PushControl::default(),
    );
    assert!(
        matches!(result, Err(DispatchError::PushTooLarge { .. })),
        "{result:?}"
    );
    assert!(heads.is_empty());
    assert_eq!(tx.advances.load(Ordering::SeqCst), advances_before);
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(theirs));
}
