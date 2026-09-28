//! The CLI's typed ticket recovery and its pre-admission pack cap.
#![allow(clippy::unwrap_used)]

mod common;

use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

use common::Repo;
use mkit_cli::remote_dispatch::{DispatchError, push_branch_with_limits};
use mkit_core::hash::Hash;
use mkit_core::layout::RepoLayout;
use mkit_core::protocol::{
    CommitOutcome, PackKey, RefWriteCondition, Transport, TransportResult, UploadLimits,
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
}

struct TicketTransport {
    inner: MemoryTransport,
    fault: Fault,
    advances: AtomicUsize,
    uploads: AtomicUsize,
    largest_upload: AtomicUsize,
    upload_lengths: Mutex<Vec<usize>>,
    max_pack_bytes: Option<u64>,
    ticket_threshold_bytes: Option<u64>,
}

impl TicketTransport {
    fn new(fault: Fault) -> Self {
        Self {
            inner: MemoryTransport::new(),
            fault,
            advances: AtomicUsize::new(0),
            uploads: AtomicUsize::new(0),
            largest_upload: AtomicUsize::new(0),
            upload_lengths: Mutex::new(Vec::new()),
            max_pack_bytes: None,
            ticket_threshold_bytes: Some(0),
        }
    }
}

impl Transport for TicketTransport {
    fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        self.uploads.fetch_add(1, Ordering::SeqCst);
        self.largest_upload.fetch_max(bytes.len(), Ordering::SeqCst);
        self.upload_lengths.lock().unwrap().push(bytes.len());
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
            tickets_per_advance: Some(7),
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
        _commit: &[PackKey],
    ) -> TransportResult<CommitOutcome> {
        let attempt = self.advances.fetch_add(1, Ordering::SeqCst);
        let fault = match (self.fault, attempt) {
            (Fault::Rejected, 0) | (Fault::RejectedTwice, 0..=1) => {
                Some(CommitOutcome::TicketRejected)
            }
            (Fault::Packlist, 0) => Some(CommitOutcome::PacklistNotInRepository),
            (Fault::Delta, 0) => Some(CommitOutcome::DeltaBaseUnavailable),
            (Fault::LandedThenRejected, 0) => {
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
            _ => None,
        };
        if let Some(fault) = fault {
            return Ok(fault);
        }
        self.inner
            .advance_refs(
                head_ref,
                head_condition,
                head_value,
                packmap_ref,
                packmap_condition,
                packmap_value,
            )
            .map(CommitOutcome::Advanced)
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
fn seventh_data_pack_is_refused_before_upload() {
    let repo = Repo::new();
    for i in 0..18 {
        let bytes = filler(i as u64 * 2 + 1, 2048);
        repo.write(&format!("f{i}.bin"), &bytes);
    }
    repo.ok(&["add", "."]);
    repo.ok(&["commit", "-m", "many files"]);
    let tx = TicketTransport::new(Fault::None);
    let err = push(&repo, &tx, 4096).unwrap_err();
    assert!(
        matches!(err, DispatchError::PushTooLarge { limit: 6, .. }),
        "{err:?}"
    );
    assert_eq!(tx.uploads.load(Ordering::SeqCst), 6);
    assert_eq!(tx.advances.load(Ordering::SeqCst), 0);
}

#[test]
fn ticketless_multi_pack_push_is_not_subject_to_ticket_cap() {
    let repo = Repo::new();
    for i in 0..18 {
        let bytes = filler(i as u64 * 2 + 1, 2048);
        repo.write(&format!("f{i}.bin"), &bytes);
    }
    repo.ok(&["add", "."]);
    repo.ok(&["commit", "-m", "many files"]);
    let mut tx = TicketTransport::new(Fault::None);
    tx.ticket_threshold_bytes = Some(u64::MAX);
    tx.max_pack_bytes = Some(4096);
    push(&repo, &tx, 4096).unwrap();
    assert!(tx.uploads.load(Ordering::SeqCst) > 6);
    assert!(tx.largest_upload.load(Ordering::SeqCst) <= 4096);
}

#[test]
fn rebaseline_over_six_packs_keeps_the_append_plan() {
    let repo = Repo::new();
    for i in 0..16 {
        repo.write(&format!("f{i}.bin"), &filler(i as u64 * 2 + 1, 2048));
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

    tx.ticket_threshold_bytes = Some(0);
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
    assert!(
        node.prev.is_some(),
        "the new plan appended to the base chain"
    );
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
