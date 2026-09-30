//! In-process indexed verification against real pack bytes and metadata rows.
#![allow(clippy::unwrap_used)] // Fixtures and assertions fail the test on invalid setup.

use bytes::Bytes;
use futures_executor::block_on;
use mkit_core::hash::{Hash, hash};
use mkit_core::object::{Commit, Identity, Object, Tree};
use mkit_core::pack::{DecodeLimits, NoExternalBases, PackWriter, decode_entries_with};
use mkit_core::serialize::serialize;
use mkit_core::sign::{KeyPair, sign_commit};
use mkit_core::transfer::encode_packlist;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use super::{
    IndexedConfig,
    verify::{StagedCommits, verify_ticketed},
};
use crate::Clock;
use crate::memory::{MemoryBlobStore, MemoryKv};
use crate::pipeline::{ShardMap, SinglePartition};
use crate::repo::{NamespaceKey, RepoId, RepoName};
use crate::rt::ManualClock;
use crate::store::{
    Batch, BatchOutcome, BlobKey, BlobStore, Cursor, Key, NamespaceStore, PackSink, Partition,
    PartitionStats, Precondition, ScanPage, StoreCapabilities, StoreError, Value, Write,
    codec::TicketV1, keys,
};
use crate::telemetry::NoopMetrics;

pub(super) const NOW: i64 = 1_700_000_000_000;

pub(super) fn repo(name: &str) -> RepoId {
    RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new(name).unwrap(),
    }
}

pub(super) fn ticket(repo: &RepoId, bytes: &[u8], created_at_ms: u64) -> TicketV1 {
    TicketV1 {
        authority_generation: None,
        repo: repo.name.clone(),
        ref_name: "refs/heads/main".into(),
        signer: [3; 32],
        pack_id: hash(bytes),
        bytes: bytes.len() as u64,
        part_size: 1 << 20,
        expires_at_ms: NOW as u64 + 300_000,
        created_at_ms,
        reservation_id: "s:test".into(),
        upload_session: None,
    }
}

/// A stand-in id per consumed ticket: the pack id, unique per ticket.
fn ticket_ids(tickets: &[TicketV1]) -> Vec<Hash> {
    tickets.iter().map(|t| hash(&t.pack_id)).collect()
}

pub(super) fn upload(blobs: &MemoryBlobStore, bytes: &[u8]) {
    block_on(async {
        let mut sink = blobs
            .begin(BlobKey::pack(hash(bytes)), bytes.len() as u64)
            .await
            .unwrap();
        sink.write(Bytes::copy_from_slice(bytes)).await.unwrap();
        sink.commit().await.unwrap();
    });
}

pub(super) fn source(repo: &RepoId) -> Partition {
    SinglePartition.ref_shard(repo, "refs/heads/main")
}

fn verify_store<S: NamespaceStore>(
    blobs: &MemoryBlobStore,
    store: &S,
    repo: &RepoId,
    tickets: &[TicketV1],
    head: Hash,
    cfg: IndexedConfig,
    clock: &ManualClock,
) -> Result<StagedCommits, crate::ServerError> {
    block_on(verify_ticketed(
        blobs,
        store,
        &SinglePartition,
        repo,
        &source(repo),
        tickets,
        &ticket_ids(tickets),
        head,
        cfg,
        clock,
        &NoopMetrics,
    ))
}

fn verify(
    blobs: &MemoryBlobStore,
    store: &MemoryKv,
    repo: &RepoId,
    tickets: &[TicketV1],
    head: Hash,
    cfg: IndexedConfig,
    clock: &ManualClock,
) -> Result<StagedCommits, crate::ServerError> {
    verify_store(blobs, store, repo, tickets, head, cfg, clock)
}

enum RenewHook {
    None,
    Retry(Box<RetryProbe>),
    Lose { target: Key },
}

struct RetryProbe {
    target: Key,
    blobs: Arc<MemoryBlobStore>,
    repo: RepoId,
    ticket: TicketV1,
    head: Hash,
    observed: Arc<Mutex<Option<(String, usize)>>>,
}

/// Advances the backend clock after each committed index batch. The renewal
/// hook runs at the state CAS boundary, with no wall-clock sleeps or threads.
struct TimedKv {
    inner: MemoryKv,
    clock: Arc<ManualClock>,
    index_step_ms: i64,
    index_batches: AtomicUsize,
    hook: Mutex<RenewHook>,
}

impl TimedKv {
    fn new(clock: Arc<ManualClock>, index_step_ms: i64, hook: RenewHook) -> Self {
        Self {
            inner: MemoryKv::with_clock(clock.clone()),
            clock,
            index_step_ms,
            index_batches: AtomicUsize::new(0),
            hook: Mutex::new(hook),
        }
    }
}

impl NamespaceStore for TimedKv {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }

    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.inner.get(p, key).await
    }

    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.inner.scan(p, start, end, after, limit).await
    }

    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        let is_index = batch
            .writes
            .iter()
            .any(|write| matches!(write, Write::Put(key, _) if key.as_bytes().starts_with(b"i\0")));
        let renewing = batch.writes.iter().find_map(|write| {
            let Write::Put(key, value) = write else {
                return None;
            };
            (matches!(
                super::state::decode(value),
                Ok(super::state::VerificationV1::Pending { .. })
            ) && batch
                .preconditions
                .iter()
                .any(|pre| matches!(pre, Precondition::Equals(guarded, _) if guarded == key)))
            .then(|| key.clone())
        });
        let hook = {
            let mut pending = self.hook.lock().unwrap();
            match (&*pending, &renewing) {
                (RenewHook::Retry(probe), Some(key)) if probe.target == *key => {
                    std::mem::replace(&mut *pending, RenewHook::None)
                }
                (RenewHook::Lose { target }, Some(key)) if target == key => {
                    std::mem::replace(&mut *pending, RenewHook::None)
                }
                _ => RenewHook::None,
            }
        };
        if let RenewHook::Lose { target } = &hook {
            let rival = super::state::VerificationV1::Pending {
                lease_until_ms: u64::try_from(crate::Clock::now_ms(self.clock.as_ref()))
                    .unwrap()
                    .saturating_add(super::state::VERIFICATION_LEASE_MS + 1),
            };
            self.inner
                .apply(
                    p,
                    Batch::new().put(target.clone(), super::state::encode(&rival)),
                )
                .await?;
        }
        let outcome = self.inner.apply(p, batch).await?;
        if is_index && matches!(&outcome, BatchOutcome::Committed) {
            self.index_batches.fetch_add(1, Ordering::SeqCst);
            self.clock.advance(self.index_step_ms);
        }
        if let RenewHook::Retry(probe) = hook {
            let RetryProbe {
                blobs,
                repo,
                ticket,
                head,
                observed,
                ..
            } = *probe;
            assert_eq!(outcome, BatchOutcome::Committed);
            // Cross the original lease's 30-second boundary while staying
            // inside the new lease written by this CAS.
            self.clock.advance(9_001);
            let retry_source = source(&repo);
            let error = verify_ticketed(
                blobs.as_ref(),
                &self.inner,
                &SinglePartition,
                &repo,
                &retry_source,
                std::slice::from_ref(&ticket),
                &ticket_ids(std::slice::from_ref(&ticket)),
                head,
                IndexedConfig::default(),
                self.clock.as_ref(),
                &NoopMetrics,
            )
            .await
            .unwrap_err();
            *observed.lock().unwrap() =
                Some((error.public_message().to_owned(), error.details().len()));
        }
        Ok(outcome)
    }

    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.inner.stats(p).await
    }

    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

fn good_pack() -> (Vec<u8>, Hash) {
    let tree = Object::Tree(Tree {
        entries: Vec::new(),
    });
    let tree_id = tree.id().unwrap();
    let tree_bytes = serialize(&tree).unwrap();
    let key = KeyPair::from_seed([7; 32]);
    let mut commit = Commit::new_unannotated(
        tree_id,
        Vec::new(),
        Identity::ed25519(key.public.0),
        key.public.0,
        b"good".to_vec(),
        42,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &key).unwrap().0;
    let commit = Object::Commit(commit);
    let head = commit.id().unwrap();
    let mut writer = PackWriter::new_raw_only();
    writer.push_raw(tree_id, &tree_bytes).unwrap();
    writer.push_raw(head, &serialize(&commit).unwrap()).unwrap();
    (writer.finish().unwrap(), head)
}

fn several_index_batches(blobs: &MemoryBlobStore, repo: &RepoId) -> (Vec<TicketV1>, Hash) {
    let (good, head) = good_pack();
    upload(blobs, &good);
    let mut tickets = vec![ticket(repo, &good, NOW as u64)];
    for n in 0..3u8 {
        let (id, raw) = blob(&[n]);
        let mut writer = PackWriter::new_raw_only();
        writer.push_raw(id, &raw).unwrap();
        let pack = writer.finish().unwrap();
        upload(blobs, &pack);
        tickets.push(ticket(repo, &pack, NOW as u64));
    }
    (tickets, head)
}

#[test]
fn good_push_indexes_before_membership_and_reuses_verified_state() {
    let (pack, head) = good_pack();
    let blobs = MemoryBlobStore::default();
    let repo = repo("one");
    let clock = Arc::new(ManualClock::new(NOW));
    let store = MemoryKv::with_clock(clock.clone());
    upload(&blobs, &pack);
    let ticket = ticket(&repo, &pack, NOW as u64);
    let staged = verify(
        &blobs,
        &store,
        &repo,
        std::slice::from_ref(&ticket),
        head,
        IndexedConfig::default(),
        &clock,
    )
    .unwrap();
    // Only history objects are kept: the commit, with its parents.
    assert_eq!(staged.parents.keys().copied().collect::<Vec<_>>(), [head]);
    assert!(staged.bytes > 0);
    let index = keys::object_index(&repo.name, &head, &ticket.pack_id);
    assert!(
        block_on(store.get(&source(&repo), &index))
            .unwrap()
            .is_some()
    );
    assert!(
        block_on(store.get(
            &source(&repo),
            &keys::membership(&repo.name, &ticket.pack_id)
        ))
        .unwrap()
        .is_none()
    );
    // A previously verified pack still contributes its objects to this
    // advance's signature and closure checks.
    assert_eq!(
        verify(
            &blobs,
            &store,
            &repo,
            &[ticket],
            head,
            IndexedConfig::default(),
            &clock
        )
        .unwrap()
        .objects,
        2
    );
}

#[test]
fn bad_signature_and_dangling_object_are_rejected() {
    let (pack, head) = good_pack();
    let mut bad = pack.clone();
    // The commit's signature occupies the last 64 bytes of its payload;
    // mutate it, then repair the pack trailer so identity is checked first.
    let trailer = bad.len() - 32;
    bad[trailer - 1] ^= 1;
    let digest = hash(&bad[..trailer]);
    bad[trailer..].copy_from_slice(&digest);
    let blobs = MemoryBlobStore::default();
    let repo = repo("one");
    let clock = Arc::new(ManualClock::new(NOW));
    let store = MemoryKv::with_clock(clock.clone());
    upload(&blobs, &bad);
    let error = verify(
        &blobs,
        &store,
        &repo,
        &[ticket(&repo, &bad, NOW as u64)],
        head,
        IndexedConfig::default(),
        &clock,
    )
    .unwrap_err();
    assert_eq!(error.public_message(), "bad signature");

    let (good, head) = good_pack();
    let mut writer = PackWriter::new_raw_only();
    // A tree referring to an absent blob is unreachable from the head, but
    // it is still a consumed object and must pass closure verification.
    let orphan = Object::Tree(Tree {
        entries: vec![mkit_core::object::TreeEntry {
            name: b"missing".to_vec(),
            mode: mkit_core::object::EntryMode::Blob,
            object_hash: [9; 32],
        }],
    });
    writer
        .push_raw(orphan.id().unwrap(), &serialize(&orphan).unwrap())
        .unwrap();
    let orphan_pack = writer.finish().unwrap();
    let blobs = MemoryBlobStore::default();
    let store = MemoryKv::with_clock(clock.clone());
    upload(&blobs, &good);
    upload(&blobs, &orphan_pack);
    let tickets = [
        ticket(&repo, &good, NOW as u64 - 60_000),
        ticket(&repo, &orphan_pack, NOW as u64 - 60_000),
    ];
    let error = verify(
        &blobs,
        &store,
        &repo,
        &tickets,
        head,
        IndexedConfig::default(),
        &clock,
    )
    .unwrap_err();
    assert_eq!(error.public_message(), "open closure");
}

#[test]
fn corrupt_pack_identity_is_rejected() {
    let repo = repo("one");
    let clock = Arc::new(ManualClock::new(NOW));
    let store = MemoryKv::with_clock(clock.clone());
    let blobs = MemoryBlobStore::default();
    let (mut pack, head) = good_pack();
    let last = pack.len() - 1;
    pack[last] ^= 1; // Valid content-addressed upload, invalid pack trailer.
    upload(&blobs, &pack);
    let error = verify(
        &blobs,
        &store,
        &repo,
        &[ticket(&repo, &pack, NOW as u64)],
        head,
        IndexedConfig::default(),
        &clock,
    )
    .unwrap_err();
    assert_eq!(error.public_message(), "object hash mismatch");
}

#[test]
fn unknown_type_and_foreign_packlist_follow_exact_errors() {
    let blobs = MemoryBlobStore::default();
    let repo = repo("one");
    let clock = Arc::new(ManualClock::new(NOW));
    let store = MemoryKv::with_clock(clock.clone());
    let unknown = b"NOPE".to_vec();
    upload(&blobs, &unknown);
    let error = verify(
        &blobs,
        &store,
        &repo,
        &[ticket(&repo, &unknown, NOW as u64)],
        [0; 32],
        IndexedConfig::default(),
        &clock,
    )
    .unwrap_err();
    assert_eq!(error.public_message(), "unknown upload type");

    let (good, head) = good_pack();
    upload(&blobs, &good);
    let foreign = [8; 32];
    let list = encode_packlist(None, &[foreign]).unwrap();
    upload(&blobs, &list);
    let tickets = [
        ticket(&repo, &good, NOW as u64),
        ticket(&repo, &list, NOW as u64),
    ];
    let retry_store = MemoryKv::with_clock(clock.clone());
    let error = verify(
        &blobs,
        &retry_store,
        &repo,
        &tickets,
        head,
        IndexedConfig::default(),
        &clock,
    )
    .unwrap_err();
    assert_eq!(
        error.public_message(),
        "repository membership not yet visible"
    );
    // The unavailable attempt releases its lease. The same ticket reaches
    // the permanent answer exactly at the lag boundary.
    clock.advance(i64::try_from(IndexedConfig::default().relay_lag_bound_ms).unwrap());
    let error = verify(
        &blobs,
        &retry_store,
        &repo,
        &tickets,
        head,
        IndexedConfig::default(),
        &clock,
    )
    .unwrap_err();
    assert_eq!(
        error.public_message(),
        "packlist lists a pack that is not in this repository"
    );
}

#[test]
fn concurrent_lease_is_pending_without_replay_then_retry_succeeds() {
    let (pack, head) = good_pack();
    let repo = repo("one");
    let clock = Arc::new(ManualClock::new(NOW));
    let store = MemoryKv::with_clock(clock.clone());
    let blobs = MemoryBlobStore::default();
    upload(&blobs, &pack);
    let ticket = ticket(&repo, &pack, NOW as u64);
    let pending = super::state::VerificationV1::Pending {
        lease_until_ms: NOW as u64 + 30_000,
    };
    block_on(store.apply(
        &source(&repo),
        Batch::new().put(
            keys::verification(&repo.name, &ticket.pack_id),
            super::state::encode(&pending),
        ),
    ))
    .unwrap();
    let error = verify(
        &blobs,
        &store,
        &repo,
        std::slice::from_ref(&ticket),
        head,
        IndexedConfig::default(),
        &clock,
    )
    .unwrap_err();
    assert_eq!(error.code(), crate::Code::Unavailable);
    assert_eq!(error.public_message(), "pack verification pending");
    assert_eq!(error.details().len(), 1);
    assert_eq!(error.http_status(), Some(503));
    clock.advance(30_001);
    assert_eq!(
        verify(
            &blobs,
            &store,
            &repo,
            &[ticket],
            head,
            IndexedConfig::default(),
            &clock
        )
        .unwrap()
        .objects,
        2
    );
}

#[test]
fn fresh_batch_deadlines_and_renewed_leases_finish_after_thirty_seconds() {
    let repo = repo("one");
    let clock = Arc::new(ManualClock::new(NOW));
    let blobs = MemoryBlobStore::default();
    let (tickets, head) = several_index_batches(&blobs, &repo);
    let store = TimedKv::new(clock.clone(), 11_000, RenewHook::None);
    let ids = verify_store(
        &blobs,
        &store,
        &repo,
        &tickets,
        head,
        IndexedConfig::default(),
        &clock,
    )
    .unwrap();
    assert_eq!(ids.objects, 5);
    assert_eq!(store.index_batches.load(Ordering::SeqCst), 4);
    assert!(clock.now_ms() - NOW > 30_000);
    for ticket in &tickets {
        let state = block_on(super::state::read(
            &store,
            &source(&repo),
            &repo.name,
            &ticket.pack_id,
        ))
        .unwrap()
        .unwrap()
        .0;
        assert!(matches!(
            state,
            super::state::VerificationV1::Verified { .. }
        ));
    }
}

#[test]
fn retry_during_renewed_lease_cannot_steal_it() {
    let repo = repo("one");
    let clock = Arc::new(ManualClock::new(NOW));
    let blobs = Arc::new(MemoryBlobStore::default());
    let (tickets, head) = several_index_batches(&blobs, &repo);
    let observed = Arc::new(Mutex::new(None));
    let store = TimedKv::new(
        clock.clone(),
        11_000,
        RenewHook::Retry(Box::new(RetryProbe {
            target: keys::verification(&repo.name, &tickets[1].pack_id),
            blobs: blobs.clone(),
            repo: repo.clone(),
            ticket: tickets[1].clone(),
            head,
            observed: observed.clone(),
        })),
    );
    verify_store(
        &blobs,
        &store,
        &repo,
        &tickets,
        head,
        IndexedConfig::default(),
        &clock,
    )
    .unwrap();
    assert_eq!(
        *observed.lock().unwrap(),
        Some(("pack verification pending".to_owned(), 1))
    );
    let state = block_on(super::state::read(
        &store,
        &source(&repo),
        &repo.name,
        &tickets[1].pack_id,
    ))
    .unwrap()
    .unwrap()
    .0;
    assert!(matches!(
        state,
        super::state::VerificationV1::Verified { .. }
    ));
    assert!(clock.now_ms() - NOW > 30_000);
}

#[test]
fn later_pack_lease_is_renewed_while_earlier_packs_are_indexed() {
    let repo = repo("one");
    let clock = Arc::new(ManualClock::new(NOW));
    let blobs = Arc::new(MemoryBlobStore::default());
    let (tickets, head) = several_index_batches(&blobs, &repo);
    let observed = Arc::new(Mutex::new(None));
    let target = tickets[3].clone();
    let store = TimedKv::new(
        clock.clone(),
        11_000,
        RenewHook::Retry(Box::new(RetryProbe {
            target: keys::verification(&repo.name, &target.pack_id),
            blobs: blobs.clone(),
            repo: repo.clone(),
            ticket: target.clone(),
            head,
            observed: observed.clone(),
        })),
    );
    verify_store(
        &blobs,
        &store,
        &repo,
        &tickets,
        head,
        IndexedConfig::default(),
        &clock,
    )
    .unwrap();
    assert_eq!(
        *observed.lock().unwrap(),
        Some(("pack verification pending".to_owned(), 1))
    );
    let state = block_on(super::state::read(
        &store,
        &source(&repo),
        &repo.name,
        &target.pack_id,
    ))
    .unwrap()
    .unwrap()
    .0;
    assert!(matches!(
        state,
        super::state::VerificationV1::Verified { .. }
    ));
}

#[test]
fn lost_renewal_writes_no_verified_state() {
    let repo = repo("one");
    let clock = Arc::new(ManualClock::new(NOW));
    let blobs = MemoryBlobStore::default();
    let (tickets, head) = several_index_batches(&blobs, &repo);
    let store = TimedKv::new(
        clock.clone(),
        11_000,
        RenewHook::Lose {
            target: keys::verification(&repo.name, &tickets[1].pack_id),
        },
    );
    let error = verify_store(
        &blobs,
        &store,
        &repo,
        &tickets,
        head,
        IndexedConfig::default(),
        &clock,
    )
    .unwrap_err();
    assert_eq!(error.public_message(), "pack verification pending");
    let state = block_on(super::state::read(
        &store,
        &source(&repo),
        &repo.name,
        &tickets[1].pack_id,
    ))
    .unwrap()
    .unwrap()
    .0;
    assert!(matches!(
        state,
        super::state::VerificationV1::Pending { .. }
    ));
}

fn blob(data: &[u8]) -> (Hash, Vec<u8>) {
    let object = Object::Blob(mkit_core::object::Blob {
        data: data.to_vec(),
    });
    (object.id().unwrap(), serialize(&object).unwrap())
}

fn thin_pack(base: Hash, base_bytes: &[u8], target_bytes: &[u8]) -> Vec<u8> {
    let mut writer = PackWriter::new();
    writer
        .push_delta(
            &base,
            &mkit_core::delta::encode(base_bytes, target_bytes).unwrap(),
        )
        .unwrap();
    writer.finish().unwrap()
}

pub(super) fn seed_member_raw(
    blobs: &MemoryBlobStore,
    store: &MemoryKv,
    repo: &RepoId,
    object: Hash,
    raw: &[u8],
) {
    let mut writer = PackWriter::new_raw_only();
    writer.push_raw(object, raw).unwrap();
    let pack = writer.finish().unwrap();
    let pack_id = hash(&pack);
    upload(blobs, &pack);
    let mut frame = None;
    decode_entries_with(
        &pack,
        &mut NoExternalBases,
        DecodeLimits::default(),
        |entry| {
            frame = Some((
                entry.frame_offset,
                entry.frame_length,
                entry.wire_type,
                entry.bytes.len() as u64,
            ));
            Ok(())
        },
    )
    .unwrap();
    let (frame_offset, frame_length, wire_type, decoded_size) = frame.unwrap();
    let value = crate::store::index::IndexValue {
        frame_offset,
        frame_length,
        wire_type,
        decoded_size,
        chain_depth: 0,
        delta_base: None,
    };
    let index = keys::object_index(&repo.name, &object, &pack_id);
    let membership = keys::membership(&repo.name, &pack_id);
    block_on(
        store.apply(
            &source(repo),
            Batch::new()
                .put(
                    index,
                    crate::store::codec::encode_object_index(&object, &value).unwrap(),
                )
                .put(membership, crate::Value::default()),
        ),
    )
    .unwrap();
}

pub(super) fn seed_capped_index(store: &MemoryKv, repo: &RepoId, object: Hash) {
    let value = crate::store::codec::encode_object_index(
        &object,
        &crate::store::index::IndexValue {
            frame_offset: 12,
            frame_length: 20,
            wire_type: 0,
            decoded_size: 5,
            chain_depth: 0,
            delta_base: None,
        },
    )
    .unwrap();
    for chunk in (0..=u32::try_from(crate::store::index::MAX_LOOKUP_ROWS).unwrap())
        .collect::<Vec<_>>()
        .chunks(90)
    {
        let mut batch = Batch::new();
        for n in chunk {
            let mut pack = [0; 32];
            pack[28..].copy_from_slice(&n.to_be_bytes());
            batch = batch.put(
                keys::object_index(&repo.name, &object, &pack),
                value.clone(),
            );
        }
        block_on(store.apply(&source(repo), batch)).unwrap();
    }
}

#[test]
fn thin_base_in_another_repository_is_indistinguishable_from_absent() {
    let (base, base_bytes) = blob(b"base");
    let (_, target_bytes) = blob(b"target");
    let thin = thin_pack(base, &base_bytes, &target_bytes);
    let a = repo("a");
    let b = repo("b");
    let blobs = MemoryBlobStore::default();
    upload(&blobs, &thin);
    let clock = Arc::new(ManualClock::new(NOW));
    for age in [0, 60_000] {
        let foreign = MemoryKv::with_clock(clock.clone());
        seed_member_raw(&blobs, &foreign, &a, base, &base_bytes);
        let absent = MemoryKv::with_clock(clock.clone());
        let t = ticket(&b, &thin, NOW as u64 - age);
        let left = verify(
            &blobs,
            &foreign,
            &b,
            std::slice::from_ref(&t),
            [0; 32],
            IndexedConfig::default(),
            &clock,
        )
        .unwrap_err();
        let right = verify(
            &blobs,
            &absent,
            &b,
            &[t],
            [0; 32],
            IndexedConfig::default(),
            &clock,
        )
        .unwrap_err();
        assert_eq!(
            (left.code(), left.public_message(), left.details()),
            (right.code(), right.public_message(), right.details())
        );
        let expected = if age == 0 {
            "repository membership not yet visible"
        } else {
            "delta base not available in this repository"
        };
        assert_eq!(left.public_message(), expected);
    }
}

#[test]
fn capped_delta_base_is_permanent_failed_precondition() {
    let repo = repo("one");
    let clock = Arc::new(ManualClock::new(NOW));
    let store = MemoryKv::with_clock(clock.clone());
    let blobs = MemoryBlobStore::default();
    let (base, raw_base) = blob(b"base");
    let (_, raw_target) = blob(b"target");
    let thin = thin_pack(base, &raw_base, &raw_target);
    upload(&blobs, &thin);
    seed_capped_index(&store, &repo, base);
    let error = verify(
        &blobs,
        &store,
        &repo,
        &[ticket(&repo, &thin, NOW as u64)],
        [0; 32],
        IndexedConfig::default(),
        &clock,
    )
    .unwrap_err();
    assert_eq!(error.code(), crate::Code::FailedPrecondition);
    assert_eq!(
        error.public_message(),
        "delta base not available in this repository"
    );
    assert!(
        block_on(super::state::read(
            &store,
            &source(&repo),
            &repo.name,
            &hash(&thin),
        ))
        .unwrap()
        .is_none()
    );
}

#[test]
fn external_depth_is_not_rejected_and_self_contained_retry_succeeds() {
    let repo = repo("one");
    let clock = Arc::new(ManualClock::new(NOW));
    let store = MemoryKv::with_clock(clock.clone());
    let blobs = MemoryBlobStore::default();
    let (a, raw_a) = blob(b"base");
    let (b, raw_b) = blob(b"middle");
    let (_, raw_c) = blob(b"target");
    seed_member_raw(&blobs, &store, &repo, a, &raw_a);
    let member = thin_pack(a, &raw_a, &raw_b);
    let (good, head) = good_pack();
    upload(&blobs, &member);
    upload(&blobs, &good);
    verify(
        &blobs,
        &store,
        &repo,
        &[
            ticket(&repo, &good, NOW as u64),
            ticket(&repo, &member, NOW as u64),
        ],
        head,
        IndexedConfig::default(),
        &clock,
    )
    .unwrap();
    block_on(store.apply(
        &source(&repo),
        Batch::new().put(
            keys::membership(&repo.name, &hash(&member)),
            Value::default(),
        ),
    ))
    .unwrap();

    let thin = thin_pack(b, &raw_b, &raw_c);
    upload(&blobs, &thin);
    let cfg = IndexedConfig {
        max_delta_chain_depth: 1,
        ..IndexedConfig::default()
    };
    let error = verify(
        &blobs,
        &store,
        &repo,
        &[
            ticket(&repo, &good, NOW as u64),
            ticket(&repo, &thin, NOW as u64),
        ],
        head,
        cfg,
        &clock,
    )
    .unwrap_err();
    assert_eq!(error.public_message(), "delta chain too deep");
    assert!(
        block_on(super::state::read(
            &store,
            &source(&repo),
            &repo.name,
            &hash(&thin),
        ))
        .unwrap()
        .is_none()
    );

    let mut writer = PackWriter::new();
    writer.push_raw(b, &raw_b).unwrap();
    writer
        .push_delta(&b, &mkit_core::delta::encode(&raw_b, &raw_c).unwrap())
        .unwrap();
    let self_contained = writer.finish().unwrap();
    upload(&blobs, &self_contained);
    verify(
        &blobs,
        &store,
        &repo,
        &[
            ticket(&repo, &good, NOW as u64),
            ticket(&repo, &self_contained, NOW as u64),
        ],
        head,
        cfg,
        &clock,
    )
    .unwrap();
}

#[test]
fn retained_external_bases_share_the_pack_decode_budget() {
    let repo = repo("one");
    let clock = Arc::new(ManualClock::new(NOW));
    let store = MemoryKv::with_clock(clock.clone());
    let blobs = MemoryBlobStore::default();
    let (good, head) = good_pack();
    upload(&blobs, &good);
    let mut writer = PackWriter::new();
    for n in 0..3u8 {
        let (base, raw_base) = blob(&vec![n; 16 * 1024]);
        let (_, raw_target) = blob(&[n]);
        seed_member_raw(&blobs, &store, &repo, base, &raw_base);
        writer
            .push_delta(
                &base,
                &mkit_core::delta::encode(&raw_base, &raw_target).unwrap(),
            )
            .unwrap();
    }
    let thin = writer.finish().unwrap();
    upload(&blobs, &thin);
    let cfg = IndexedConfig {
        decode_budget: 24_000,
        ..IndexedConfig::default()
    };
    let error = verify(
        &blobs,
        &store,
        &repo,
        &[
            ticket(&repo, &good, NOW as u64),
            ticket(&repo, &thin, NOW as u64),
        ],
        head,
        cfg,
        &clock,
    )
    .unwrap_err();
    assert_eq!(error.public_message(), "pack exceeds indexed decode budget");
    assert!(
        block_on(super::state::read(
            &store,
            &source(&repo),
            &repo.name,
            &hash(&thin),
        ))
        .unwrap()
        .is_none()
    );
}

#[test]
#[allow(clippy::too_many_lines)] // One fixture proves recursion, memoization and the cap.
fn member_frame_resolver_recurses_memoizes_and_caps_total_depth() {
    let repo = repo("one");
    let clock = Arc::new(ManualClock::new(NOW));
    let store = MemoryKv::with_clock(clock);
    let blobs = MemoryBlobStore::default();
    let (a, raw_a) = blob(b"base");
    let (b, raw_b) = blob(b"base2");
    let (c, raw_c) = blob(b"base3");
    let mut writer = PackWriter::new();
    writer.push_raw(a, &raw_a).unwrap();
    writer
        .push_delta(&a, &mkit_core::delta::encode(&raw_a, &raw_b).unwrap())
        .unwrap();
    writer
        .push_delta(&b, &mkit_core::delta::encode(&raw_b, &raw_c).unwrap())
        .unwrap();
    let pack = writer.finish().unwrap();
    let pack_id = hash(&pack);
    upload(&blobs, &pack);
    let mut frames = Vec::new();
    decode_entries_with(
        &pack,
        &mut NoExternalBases,
        DecodeLimits::default(),
        |entry| {
            frames.push(super::entries::FrameMeta {
                id: entry.id,
                frame_offset: entry.frame_offset,
                frame_length: entry.frame_length,
                wire_type: entry.wire_type,
                delta_base: entry.delta_base,
                decoded_size: entry.bytes.len() as u64,
            });
            Ok(())
        },
    )
    .unwrap();
    let entries = super::entries::index_entries(&frames, 50).unwrap();
    let located = crate::store::index::LocatedObject {
        pack: pack_id,
        value: entries[2].value,
    };
    let plan = crate::store::index::plan_index_rows_direct(
        &SinglePartition,
        &repo,
        &source(&repo),
        &pack_id,
        &entries,
        NOW as u64,
    )
    .unwrap();
    for direct in plan.direct {
        let batch = direct
            .puts
            .into_iter()
            .fold(Batch::new(), |batch, (key, value)| batch.put(key, value));
        block_on(store.apply(&direct.target, batch)).unwrap();
    }
    block_on(store.apply(
        &source(&repo),
        Batch::new().put(
            keys::membership(&repo.name, &pack_id),
            crate::Value::default(),
        ),
    ))
    .unwrap();
    let mut memo = super::resolve::MemberCache::default();
    let mut visiting = BTreeSet::new();
    let (bytes, depth) = block_on(super::resolve::member_object(
        &blobs,
        &store,
        &SinglePartition,
        &repo,
        c,
        located,
        50,
        1 << 20,
        &mut memo,
        &mut visiting,
        &NoopMetrics,
    ))
    .unwrap();
    assert_eq!(bytes.as_ref(), raw_c.as_slice());
    assert_eq!(depth, 2);
    assert_eq!(memo.len(), 3);
    assert_eq!(
        memo.retained_bytes(),
        (raw_a.len() + raw_b.len() + raw_c.len()) as u64
    );
    let before = memo.clone();
    assert_eq!(
        block_on(super::resolve::member_object(
            &blobs,
            &store,
            &SinglePartition,
            &repo,
            c,
            located,
            50,
            1 << 20,
            &mut memo,
            &mut visiting,
            &NoopMetrics
        ))
        .unwrap()
        .1,
        2
    );
    assert_eq!(memo, before);
    let mut limited = super::resolve::MemberCache::default();
    let error = block_on(super::resolve::member_object(
        &blobs,
        &store,
        &SinglePartition,
        &repo,
        b,
        crate::store::index::LocatedObject {
            pack: pack_id,
            value: entries[1].value,
        },
        50,
        (raw_a.len() + raw_b.len() - 1) as u64,
        &mut limited,
        &mut BTreeSet::new(),
        &NoopMetrics,
    ))
    .unwrap_err();
    assert_eq!(
        error
            .public_error(NOW as u64, NOW as u64, 0)
            .public_message(),
        "pack exceeds indexed decode budget"
    );
    let error = block_on(super::resolve::member_object(
        &blobs,
        &store,
        &SinglePartition,
        &repo,
        c,
        located,
        1,
        1 << 20,
        &mut super::resolve::MemberCache::default(),
        &mut BTreeSet::new(),
        &NoopMetrics,
    ))
    .unwrap_err();
    assert_eq!(
        error
            .public_error(NOW as u64, NOW as u64, 0)
            .public_message(),
        "delta chain too deep"
    );
}

#[test]
fn member_blob_cannot_be_an_advanced_head() {
    let repo = repo("one");
    let clock = Arc::new(ManualClock::new(NOW));
    let store = MemoryKv::with_clock(clock.clone());
    let blobs = MemoryBlobStore::default();
    let (member_id, member_bytes) = blob(b"member blob");
    seed_member_raw(&blobs, &store, &repo, member_id, &member_bytes);
    let (pack, _) = good_pack();
    upload(&blobs, &pack);
    let error = verify(
        &blobs,
        &store,
        &repo,
        &[ticket(&repo, &pack, NOW as u64)],
        member_id,
        IndexedConfig::default(),
        &clock,
    )
    .unwrap_err();
    assert_eq!(error.public_message(), "open closure");
}

#[test]
fn capped_closure_lookup_has_distinct_permanent_error() {
    let repo = repo("one");
    let clock = Arc::new(ManualClock::new(NOW));
    let store = MemoryKv::with_clock(clock.clone());
    let blobs = MemoryBlobStore::default();
    let (good, head) = good_pack();
    upload(&blobs, &good);
    let missing = [9; 32];
    let orphan = Object::Tree(Tree {
        entries: vec![mkit_core::object::TreeEntry {
            name: b"missing".to_vec(),
            mode: mkit_core::object::EntryMode::Blob,
            object_hash: missing,
        }],
    });
    let mut writer = PackWriter::new_raw_only();
    writer
        .push_raw(orphan.id().unwrap(), &serialize(&orphan).unwrap())
        .unwrap();
    let orphan_pack = writer.finish().unwrap();
    upload(&blobs, &orphan_pack);
    seed_capped_index(&store, &repo, missing);
    let tickets = [
        ticket(&repo, &good, NOW as u64 - 60_000),
        ticket(&repo, &orphan_pack, NOW as u64 - 60_000),
    ];
    let error = verify(
        &blobs,
        &store,
        &repo,
        &tickets,
        head,
        IndexedConfig::default(),
        &clock,
    )
    .unwrap_err();
    assert_eq!(error.public_message(), "object index limit exceeded");
}

#[test]
fn in_pack_delta_chain_above_cap_is_rejected_before_tip() {
    let repo = repo("one");
    let clock = Arc::new(ManualClock::new(NOW));
    let store = MemoryKv::with_clock(clock.clone());
    let blobs = MemoryBlobStore::default();
    let (a, raw_a) = blob(b"base");
    let (b, raw_b) = blob(b"base2");
    let (_, raw_c) = blob(b"base3");
    let mut writer = PackWriter::new();
    writer.push_raw(a, &raw_a).unwrap();
    writer
        .push_delta(&a, &mkit_core::delta::encode(&raw_a, &raw_b).unwrap())
        .unwrap();
    writer
        .push_delta(&b, &mkit_core::delta::encode(&raw_b, &raw_c).unwrap())
        .unwrap();
    // The over-cap in-pack hop must win over this later missing member base.
    writer
        .push_delta(
            &[0x99; 32],
            &mkit_core::delta::encode(&raw_a, &raw_b).unwrap(),
        )
        .unwrap();
    let pack = writer.finish().unwrap();
    upload(&blobs, &pack);
    let cfg = IndexedConfig {
        max_delta_chain_depth: 1,
        ..IndexedConfig::default()
    };
    let error = verify(
        &blobs,
        &store,
        &repo,
        &[ticket(&repo, &pack, NOW as u64)],
        [0; 32],
        cfg,
        &clock,
    )
    .unwrap_err();
    assert_eq!(error.code(), crate::Code::InvalidArgument);
    assert_eq!(error.public_message(), "delta chain too deep");
}

#[test]
fn unstaged_head_lag_window_uses_earliest_consumed_ticket_in_either_order() {
    let (good, _) = good_pack();
    let extra = encode_packlist(None, &[]).unwrap();
    let blobs = MemoryBlobStore::default();
    upload(&blobs, &good);
    upload(&blobs, &extra);
    let repo = repo("one");
    let clock = Arc::new(ManualClock::new(NOW));
    for oldest_first in [false, true] {
        let store = MemoryKv::with_clock(clock.clone());
        let mut tickets = [
            ticket(&repo, &good, NOW as u64),
            ticket(
                &repo,
                &extra,
                NOW as u64 - IndexedConfig::default().relay_lag_bound_ms,
            ),
        ];
        if oldest_first {
            tickets.reverse();
        }
        let error = verify(
            &blobs,
            &store,
            &repo,
            &tickets,
            [99; 32],
            IndexedConfig::default(),
            &clock,
        )
        .unwrap_err();
        assert_eq!(error.code(), crate::Code::InvalidArgument);
        assert_eq!(error.public_message(), "open closure");
    }
}
