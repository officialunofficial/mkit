//! Durable local-selection callbacks keep bounded work and resumable checkpoints.
use super::*;
use crate::Precondition;

struct Checkpoints {
    inner: Arc<MemoryKv>,
    commits: AtomicU32,
    fail_at: u32,
    lose_reply: bool,
}

impl NamespaceStore for Checkpoints {
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
        batch.validate(&self.capabilities()).unwrap();
        let checkpoint = batch.preconditions.iter().any(|guard| matches!(guard,
            Precondition::Equals(key, _) if matches!(keys::parse(key), Some(keys::ParsedKey::Timer { .. }))))
            && batch.writes.iter().any(|write| match write {
                crate::store::Write::Put(key, raw)
                    if matches!(keys::parse(key), Some(keys::ParsedKey::VerifyCursor { sub: keys::VC_JOB, .. })) =>
                {
                    decode_job(raw).unwrap().phase == Phase::Extract
                }
                _ => false,
            });
        let fail = checkpoint && self.commits.fetch_add(1, Ordering::SeqCst) + 1 == self.fail_at;
        if fail && !self.lose_reply {
            return Err(StoreError::unavailable("interrupted selection checkpoint"));
        }
        let result = self.inner.apply(p, batch).await?;
        if fail {
            assert_eq!(result, BatchOutcome::Committed);
            return Err(StoreError::unavailable("lost selection checkpoint reply"));
        }
        Ok(result)
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

struct Selection {
    rig: Rig,
    extension: TestExtraction,
    ticket: TicketV1,
    ticket_id: Hash,
    head: Hash,
}

fn selection(slices: u32) -> Selection {
    selection_with_member(slices, false)
}

fn selection_with_member(slices: u32, external: bool) -> Selection {
    let mut rig = Rig::new();
    rig.limits.extract_chain_slices = slices;
    let (bytes, head) = if external {
        rig.limits.extract_chain_steps = 16;
        let (id, raw) = blob(999, 19);
        seed_member(&rig, id, &raw);
        external_children_pack(32, &[id])
    } else {
        tree_pack(64, 19)
    };
    let (ticket, ticket_id) = rig.add(&bytes);
    assert!(rig.check(&[(&ticket, ticket_id)], head).is_err());
    let extension = TestExtraction::new(&rig);
    for _ in 0..500 {
        if rig.job(&ticket.pack_id).unwrap().phase == Phase::Extract {
            assert!(!rig.job(&ticket.pack_id).unwrap().usable());
            return Selection {
                rig,
                extension,
                ticket,
                ticket_id,
                head,
            };
        }
        tick(&rig, &extension, rig.store.as_ref(), true);
        rig.clock.advance(1_000);
    }
    panic!("fixture did not enter selection");
}

fn callback(f: &Selection, store: &impl NamespaceStore) -> usize {
    let before = f.rig.recorder.slices.lock().unwrap().len();
    let now = f.rig.clock.now_ms();
    tick(&f.rig, &f.extension, store, true);
    assert_eq!(f.rig.clock.now_ms(), now, "callback uses a frozen clock");
    f.rig.recorder.slices.lock().unwrap().len() - before
}

#[test]
fn extract_callback_slice_ceiling_holds_with_a_frozen_clock() {
    for cap in [2, 4, 8, u32::MAX] {
        let f = selection(cap);
        let before = f.rig.recorder.slices.lock().unwrap().len();
        let count = callback(&f, f.rig.store.as_ref());
        assert!(count > 1, "selection chains durable slices: {count}");
        assert!(count <= cap.min(8) as usize, "cap {cap}: {count}");
        assert_eq!(f.rig.job(&f.ticket.pack_id).unwrap().phase, Phase::Extract);
        f.rig.verification_timer(&f.ticket.pack_id);
        assert!(
            f.rig.recorder.slices.lock().unwrap()[before..]
                .iter()
                .sum::<f64>()
                <= 256.0
        );
    }
}

#[test]
fn extract_callback_replays_each_committed_slice_after_failure_or_lost_reply() {
    let reference = selection(8);
    let store = Checkpoints {
        inner: reference.rig.store.clone(),
        commits: AtomicU32::new(0),
        fail_at: 0,
        lose_reply: false,
    };
    assert!(callback(&reference, &store) > 1);
    let boundaries = store.commits.load(Ordering::SeqCst);
    assert!(boundaries > 1);
    drive(
        &reference.rig,
        &reference.extension,
        &[reference.ticket.pack_id],
    );
    let expected = snapshot(&reference.rig, &reference.ticket.pack_id);
    for lose_reply in [false, true] {
        for fail_at in 1..=boundaries {
            let f = selection(8);
            let before = f.rig.job(&f.ticket.pack_id).unwrap();
            let store = Checkpoints {
                inner: f.rig.store.clone(),
                commits: AtomicU32::new(0),
                fail_at,
                lose_reply,
            };
            callback(&f, &store);
            assert_eq!(store.commits.load(Ordering::SeqCst), fail_at);
            f.rig.verification_timer(&f.ticket.pack_id);
            if lose_reply || fail_at > 1 {
                assert_ne!(f.rig.job(&f.ticket.pack_id).unwrap(), before);
            }
            drive(&f.rig, &f.extension, &[f.ticket.pack_id]);
            assert_eq!(
                snapshot(&f.rig, &f.ticket.pack_id),
                expected,
                "checkpoint {fail_at}, lost reply {lose_reply}"
            );
            assert!(f.rig.job(&f.ticket.pack_id).unwrap().usable());
            assert!(f.extension.sessions.lock().unwrap().is_empty());
        }
    }
}

#[test]
fn extract_callback_spends_one_allowance_and_rearms_after_partial_progress() {
    let full = selection_with_member(8, true);
    let full_count = callback(&full, full.rig.store.as_ref());
    let mut limited = selection_with_member(8, true);
    limited.rig.limits.max_subrequests = 128;
    let calls_before = limited.rig.recorder.slices.lock().unwrap().len();
    let before = limited.rig.job(&limited.ticket.pack_id).unwrap();
    let count = callback(&limited, limited.rig.store.as_ref());
    assert!(
        count > 1 && count < full_count,
        "limited {count}, full {full_count}"
    );
    let spent = limited.rig.recorder.slices.lock().unwrap()[calls_before..]
        .iter()
        .sum::<f64>();
    assert!(spent > 0.0 && spent <= 128.0, "charged calls: {spent}");
    assert_ne!(limited.rig.job(&limited.ticket.pack_id).unwrap(), before);
    limited.rig.verification_timer(&limited.ticket.pack_id);
    assert_eq!(
        limited.rig.job(&limited.ticket.pack_id).unwrap().phase,
        Phase::Extract
    );
    drive(&limited.rig, &limited.extension, &[limited.ticket.pack_id]);
    assert!(limited.rig.job(&limited.ticket.pack_id).unwrap().usable());
}

#[test]
fn extract_callback_no_candidates_preserves_the_usable_result() {
    let mut results = Vec::new();
    for slices in [1, 8] {
        let f = selection(slices);
        drive(&f.rig, &f.extension, &[f.ticket.pack_id]);
        assert!(f.rig.job(&f.ticket.pack_id).unwrap().usable());
        assert!(f.extension.sessions.lock().unwrap().is_empty());
        results.push((
            snapshot(&f.rig, &f.ticket.pack_id),
            f.rig.check(&[(&f.ticket, f.ticket_id)], f.head).unwrap(),
        ));
    }
    assert_eq!(results[0], results[1]);
}

#[test]
fn extract_callback_real_extraction_preserves_content_and_offsets_bytes() {
    let (bytes, head) = tree_pack(3, 70_000);
    let mut results = Vec::new();
    for slices in [1, 8] {
        let mut rig = Rig::new();
        rig.limits.extract_chain_slices = slices;
        let (ticket, ticket_id) = rig.add(&bytes);
        assert!(rig.check(&[(&ticket, ticket_id)], head).is_err());
        let extension = TestExtraction::new(&rig);
        drive(&rig, &extension, &[ticket.pack_id]);
        let mut output = Vec::new();
        for n in 0..3 {
            let (id, _) = blob(n, 70_000);
            assert_holder(&rig, id);
            let content = read_blob(&rig.blobs, &BlobKey::object(id)).unwrap();
            let offsets = read_blob(&rig.blobs, &BlobKey::object_offsets(id));
            output.push((content, offsets));
        }
        results.push((rig.check(&[(&ticket, ticket_id)], head).unwrap(), output));
    }
    assert_eq!(results[0], results[1]);
}

#[test]
fn extract_callback_chunked_control_preserves_expected_content_and_offsets_bytes() {
    let data = [vec![3; 70_000], vec![5; 9_000], vec![7; 1_500]];
    let mut objects = data
        .iter()
        .map(|data| Object::Blob(Blob { data: data.clone() }))
        .collect::<Vec<_>>();
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: 80_500,
        chunk_size: 0,
        chunks: objects.iter().map(|object| object.id().unwrap()).collect(),
    });
    let id = manifest.id().unwrap();
    let (tree, commit, head) = tree_head(&[id]);
    objects.extend([manifest, tree, commit]);
    let bytes = pack(&objects);
    let expected_offsets = crate::indexed::extract::encode_offsets(&[0, 70_000, 79_000, 80_500]);
    let mut results = Vec::new();
    for slices in [1, 8] {
        let mut rig = Rig::new();
        rig.limits.extract_chain_slices = slices;
        let (ticket, ticket_id) = rig.add(&bytes);
        assert!(rig.check(&[(&ticket, ticket_id)], head).is_err());
        let extension = TestExtraction::new(&rig);
        let mut max_selection_slices = 0;
        for _ in 0..3_000 {
            if rig.finished(&ticket.pack_id) {
                break;
            }
            let job = rig.job(&ticket.pack_id).unwrap();
            let selection = job.phase == Phase::Extract && !job.tiny();
            let before = rig.recorder.slices.lock().unwrap().len();
            tick(&rig, &extension, rig.store.as_ref(), true);
            if selection {
                max_selection_slices =
                    max_selection_slices.max(rig.recorder.slices.lock().unwrap().len() - before);
            }
            rig.clock.advance(1_000);
        }
        assert!(rig.finished(&ticket.pack_id));
        assert_eq!(max_selection_slices > 1, slices > 1);
        assert_holder(&rig, id);
        let content = read_blob(&rig.blobs, &BlobKey::object(id)).unwrap();
        let offsets = read_blob(&rig.blobs, &BlobKey::object_offsets(id)).unwrap();
        assert_eq!(content, data.concat());
        assert_eq!(offsets, expected_offsets);
        results.push((
            rig.check(&[(&ticket, ticket_id)], head).unwrap(),
            content,
            offsets,
        ));
    }
    assert_eq!(results[0], results[1]);
}

struct RestartAfterCommit {
    inner: Checkpoints,
    repo: RepoName,
    pack: Hash,
    restarted: Mutex<Option<VerifyJobV1>>,
}

impl NamespaceStore for RestartAfterCommit {
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
        let result = self.inner.apply(p, batch).await?;
        if result == BatchOutcome::Committed
            && self.inner.commits.load(Ordering::SeqCst) == 1
            && self.restarted.lock().unwrap().is_none()
        {
            let key = keys::verify_job(&self.repo, &self.pack);
            let raw = self.inner.get(p, &key).await?.unwrap();
            let mut job = decode_job(&raw)?;
            assert_eq!(job.phase, Phase::Extract);
            job.restart();
            let batch = checkpoint::write_job(
                Batch::new().require(Precondition::Equals(key, raw.clone())),
                &mut job,
                Some(&raw),
                &self.repo,
                &self.pack,
            )?;
            assert_eq!(
                self.inner.inner.apply(p, batch).await?,
                BatchOutcome::Committed
            );
            *self.restarted.lock().unwrap() = Some(job);
        }
        Ok(result)
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

#[test]
fn extract_callback_rechecks_the_phase_after_a_concurrent_restart() {
    let f = selection(8);
    let store = RestartAfterCommit {
        inner: Checkpoints {
            inner: f.rig.store.clone(),
            commits: AtomicU32::new(0),
            fail_at: 0,
            lose_reply: false,
        },
        repo: f.rig.repo.name.clone(),
        pack: f.ticket.pack_id,
        restarted: Mutex::new(None),
    };
    let reads_before = f.rig.windows.reads.load(Ordering::SeqCst);
    callback(&f, &store);
    let expected = store.restarted.lock().unwrap().clone().unwrap();
    assert_eq!(expected.phase, Phase::Decode);
    assert_eq!(f.rig.job(&f.ticket.pack_id).unwrap(), expected);
    assert_eq!(
        f.rig.windows.reads.load(Ordering::SeqCst),
        reads_before,
        "the selection continuation cannot begin the restarted Decode"
    );
    assert_eq!(store.inner.commits.load(Ordering::SeqCst), 1);
    f.rig.verification_timer(&f.ticket.pack_id);
    drive(&f.rig, &f.extension, &[f.ticket.pack_id]);
    assert!(f.rig.job(&f.ticket.pack_id).unwrap().usable());
    f.rig.check(&[(&f.ticket, f.ticket_id)], f.head).unwrap();
}
