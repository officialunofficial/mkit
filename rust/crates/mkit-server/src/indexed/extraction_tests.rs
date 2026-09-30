//! Scheduled extraction acceptance, using the same native verifier as the oracle.
#[path = "extraction_count_tests.rs"]
mod extraction_count_tests;
#[path = "member_lookup_tests.rs"]
mod member_lookup_tests;
use super::*;
use crate::indexed::budget::SliceBudget;
use crate::indexed::job::SliceExtension;
use crate::store::{
    BlobBody, CommitOutcome, ContentIndex, MultipartBlobStore, PartRef, PartSink, content_shard,
};
use mkit_core::object::ChunkedBlob;
use mkit_core::upload_parts::{PartPlan, merge_to_root};
use std::collections::BTreeMap;

type UploadSession = (Vec<u8>, Hash, Vec<Hash>);

#[derive(Clone)]
struct TestExtraction {
    blobs: Arc<MemoryBlobStore>,
    sessions: Arc<Mutex<BTreeMap<Hash, UploadSession>>>,
    fail: Arc<Mutex<Option<&'static str>>>,
    completed: Arc<AtomicU32>,
}

impl TestExtraction {
    fn new(rig: &Rig) -> Self {
        Self {
            blobs: rig.blobs.clone(),
            sessions: Arc::default(),
            fail: Arc::default(),
            completed: Arc::default(),
        }
    }

    fn lost_reply(&self, boundary: &'static str) -> Result<(), StoreError> {
        let mut fail = self.fail.lock().unwrap();
        if *fail == Some(boundary) {
            *fail = None;
            return Err(StoreError::Unavailable(
                "lost extraction callback reply".into(),
            ));
        }
        Ok(())
    }
}

impl SliceExtension for TestExtraction {
    fn needs_extraction(&self, object: &Object, cfg: &IndexedConfig) -> bool {
        FailClosedExtraction.needs_extraction(object, cfg)
    }

    fn extraction_enabled(&self) -> bool {
        true
    }

    fn begin_object<'a>(
        &'a self,
        key: BlobKey,
        plan: &'a PartPlan,
        root: Hash,
        cvs: &'a [Hash],
        operation: Hash,
        budget: &'a SliceBudget,
    ) -> BoxFuture<'a, Result<Option<Vec<u8>>, StoreError>> {
        Box::pin(async move {
            assert_eq!(merge_to_root(plan, cvs).unwrap(), root);
            budget.charge()?;
            let prior = self.sessions.lock().unwrap().get(&operation).cloned();
            if let Some((session, expected, parts)) = prior {
                assert_eq!(expected, root);
                assert_eq!(parts, cvs);
                return Ok(Some(session));
            }
            let session = self
                .blobs
                .begin_multipart(key, plan.total(), plan.part_size())
                .await?;
            self.sessions
                .lock()
                .unwrap()
                .insert(operation, (session.clone(), root, cvs.to_vec()));
            self.lost_reply("begin")?;
            Ok(Some(session))
        })
    }

    fn put_object_part<'a>(
        &'a self,
        key: BlobKey,
        session: &'a [u8],
        plan: &'a PartPlan,
        index: u32,
        cv: Hash,
        bytes: Vec<u8>,
        budget: &'a SliceBudget,
    ) -> BoxFuture<'a, Result<Option<Vec<u8>>, StoreError>> {
        Box::pin(async move {
            budget.charge()?;
            let mut sink = self.blobs.begin_part(key, session, plan, index, cv).await?;
            budget.charge()?;
            sink.write(Bytes::from(bytes)).await?;
            budget.charge()?;
            let tag = sink.commit().await?;
            self.lost_reply("part")?;
            Ok(Some(tag))
        })
    }

    fn complete_object<'a>(
        &'a self,
        key: BlobKey,
        session: &'a [u8],
        plan: &'a PartPlan,
        parts: Vec<PartRef>,
        root: Hash,
        budget: &'a SliceBudget,
    ) -> BoxFuture<'a, Result<Option<CommitOutcome>, StoreError>> {
        Box::pin(async move {
            budget.charge()?;
            let outcome = match self
                .blobs
                .complete_with_root(key, session, plan, &parts, root)
                .await
            {
                Err(StoreError::SessionGone) => {
                    budget.charge()?;
                    let mut bytes = Vec::new();
                    match self.blobs.get(&key, None).await? {
                        Some(BlobBody::Bytes(piece)) => bytes.extend_from_slice(&piece),
                        Some(BlobBody::Stream { mut stream, .. }) => {
                            use futures::StreamExt as _;
                            while let Some(piece) = stream.next().await {
                                bytes.extend_from_slice(&piece?);
                            }
                        }
                        None => return Err(StoreError::SessionGone),
                    }
                    assert_eq!(hash(&bytes), root);
                    CommitOutcome::AlreadyPresent
                }
                other => other?,
            };
            self.completed.fetch_add(1, Ordering::SeqCst);
            self.lost_reply("complete")?;
            Ok(Some(outcome))
        })
    }

    fn abort_object<'a>(
        &'a self,
        key: BlobKey,
        session: &'a [u8],
        _: &'a PartPlan,
        budget: &'a SliceBudget,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            budget.charge()?;
            self.blobs.abort(key, session).await
        })
    }
}

fn extraction_handler(
    rig: &Rig,
    extension: TestExtraction,
) -> VerifyTimer<Shared<MemoryKv>, Shared<MemoryBlobStore>, Arc<Windows>, TestExtraction> {
    let h = rig.handler();
    VerifyTimer {
        remote: h.remote,
        blobs: h.blobs,
        windows: h.windows,
        shards: h.shards,
        cfg: h.cfg,
        limits: h.limits,
        lease: h.lease,
        clock: h.clock,
        metrics: h.metrics,
        extension,
    }
}

fn tick<S: NamespaceStore>(rig: &Rig, extension: &TestExtraction, local: &S, relay: bool) {
    let registry = TimerRegistry::new().register(extraction_handler(rig, extension.clone()));
    let registry = if relay {
        registry.register(crate::relay::RelayHandler {
            target: Shared(rig.store.clone()),
            hook: crate::relay::HolderRelayHook {
                clock: rig.clock.clone(),
            },
            budget: crate::relay::RelayBudget::default(),
        })
    } else {
        registry
    };
    block_on(run_due(
        local,
        &rig.source(),
        &registry,
        rig.clock.as_ref(),
        u64::try_from(rig.clock.now_ms()).unwrap(),
        &TickBudget::default(),
    ))
    .unwrap();
}

fn drive(rig: &Rig, extension: &TestExtraction, packs: &[Hash]) {
    for _ in 0..3_000 {
        if packs
            .iter()
            .all(|id| rig.finished(id) && !rig.job(id).unwrap().closure_retry())
        {
            for pack in packs {
                assert_eq!(rig.job(pack).unwrap().outcome, None);
            }
            return;
        }
        tick(rig, extension, rig.store.as_ref(), true);
        rig.clock.advance(1_000);
    }
    panic!(
        "extraction did not finish: {:?}",
        packs.iter().map(|id| rig.job(id)).collect::<Vec<_>>()
    );
}

fn read_blob(blobs: &MemoryBlobStore, key: &BlobKey) -> Option<Vec<u8>> {
    let body = block_on(blobs.get(key, None)).unwrap()?;
    Some(match body {
        BlobBody::Bytes(bytes) => bytes.to_vec(),
        BlobBody::Stream { mut stream, .. } => {
            use futures::StreamExt as _;
            let mut bytes = Vec::new();
            while let Some(piece) = block_on(stream.next()) {
                bytes.extend(piece.unwrap());
            }
            bytes
        }
    })
}

fn pack(objects: &[Object]) -> Vec<u8> {
    let mut writer = PackWriter::new_raw_only();
    for object in objects {
        writer
            .push_raw(object.id().unwrap(), &serialize(object).unwrap())
            .unwrap();
    }
    writer.finish().unwrap()
}

fn tree_head(files: &[Hash]) -> (Object, Object, Hash) {
    let tree = Object::Tree(Tree {
        entries: files
            .iter()
            .enumerate()
            .map(|(i, id)| TreeEntry {
                name: format!("f{i}").into_bytes(),
                mode: EntryMode::Blob,
                object_hash: *id,
            })
            .collect(),
    });
    let (commit, head) = signed_commit(tree.id().unwrap(), Vec::new(), 7, b"extraction");
    (tree, commit, head)
}

fn closure_ticks(rig: &Rig, extension: &TestExtraction, count: usize) {
    for _ in 0..count {
        tick(rig, extension, rig.store.as_ref(), true);
        rig.clock.advance(1_000);
    }
}

fn assert_no_extraction_effects(rig: &Rig, extension: &TestExtraction, id: Hash) {
    assert!(extension.sessions.lock().unwrap().is_empty());
    assert_eq!(extension.completed.load(Ordering::SeqCst), 0);
    assert!(read_blob(&rig.blobs, &BlobKey::object(id)).is_none());
    for (start, end) in [keys::holds_of(&id), keys::pending_holders_of(&id)] {
        assert!(
            block_on(rig.store.scan(&content_shard(&id), &start, &end, None, 1))
                .unwrap()
                .entries
                .is_empty()
        );
    }
}

#[test]
fn missing_unstaged_chunk_closes_after_lag_without_starting_extraction() {
    let rig = Rig::new();
    let chunk = Object::Blob(Blob {
        data: vec![91; 70_000],
    });
    let chunk_id = chunk.id().unwrap();
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: 70_000,
        chunk_size: 0,
        chunks: vec![chunk_id],
    });
    let id = manifest.id().unwrap();
    let (tree, commit, head) = tree_head(&[id]);
    let (ticket, ticket_id) = rig.add(&pack(&[manifest, tree, commit]));
    assert!(rig.check(&[(&ticket, ticket_id)], head).is_err());
    let extension = TestExtraction::new(&rig);
    closure_ticks(&rig, &extension, 100);
    assert_no_extraction_effects(&rig, &extension, id);
    rig.clock
        .advance(i64::try_from(rig.cfg.relay_lag_bound_ms).unwrap());
    closure_ticks(&rig, &extension, 20);
    assert_eq!(
        rig.check(&[(&ticket, ticket_id)], head)
            .unwrap_err()
            .public_message(),
        "open closure"
    );
    assert!(rig.job(&ticket.pack_id).unwrap().outcome.is_some());
    assert_no_extraction_effects(&rig, &extension, id);
    for _ in 0..8 {
        closure_ticks(&rig, &extension, 1);
        assert_eq!(
            rig.job(&ticket.pack_id).unwrap().outcome,
            Some(checkpoint::Outcome::ClosureMissing)
        );
        assert_eq!(
            rig.check(&[(&ticket, ticket_id)], head)
                .unwrap_err()
                .public_message(),
            "open closure"
        );
        assert_no_extraction_effects(&rig, &extension, id);
    }
    seed_member(&rig, chunk_id, &serialize(&chunk).unwrap());
    drive(&rig, &extension, &[ticket.pack_id]);
    rig.check(&[(&ticket, ticket_id)], head).unwrap();
    assert_holder(&rig, id);
}

#[test]
fn unrelated_open_closure_blocks_an_otherwise_extractable_object() {
    let rig = Rig::new();
    let object = Object::Blob(Blob {
        data: vec![71; 70_000],
    });
    let id = object.id().unwrap();
    let (tree, commit, head) = tree_head(&[id]);
    let (open_commit, _) = signed_commit([92; 32], vec![], 7, b"open");
    let (ticket, ticket_id) = rig.add(&pack(&[object, tree, commit, open_commit]));
    assert!(rig.check(&[(&ticket, ticket_id)], head).is_err());
    let extension = TestExtraction::new(&rig);
    closure_ticks(&rig, &extension, 100);
    assert_no_extraction_effects(&rig, &extension, id);
}

#[test]
fn invalid_head_or_packlist_blocks_multipart_before_effects() {
    for invalid_head in [true, false] {
        let rig = Rig::new();
        let object = Object::Blob(Blob {
            data: vec![72; 70_000],
        });
        let id = object.id().unwrap();
        let (tree, commit, valid_head) = tree_head(&[id]);
        let head = if invalid_head {
            tree.id().unwrap()
        } else {
            valid_head
        };
        let first = rig.add(&pack(&[object, tree, commit]));
        let second = (!invalid_head).then(|| {
            rig.add(
                &mkit_core::transfer::encode_packlist(None, &[first.0.pack_id, [93; 32]]).unwrap(),
            )
        });
        let mut tickets = vec![(&first.0, first.1)];
        if let Some(second) = &second {
            tickets.push((&second.0, second.1));
        }
        assert!(rig.check(&tickets, head).is_err());
        let extension = TestExtraction::new(&rig);
        closure_ticks(&rig, &extension, 100);
        assert_no_extraction_effects(&rig, &extension, id);
    }
}

#[test]
fn an_invalid_head_can_retry_the_same_live_ticket_before_any_effects() {
    let rig = Rig::new();
    let object = Object::Blob(Blob {
        data: vec![75; 70_000],
    });
    let id = object.id().unwrap();
    let (tree, commit, head) = tree_head(&[id]);
    let wrong_head = tree.id().unwrap();
    let (ticket, ticket_id) = rig.add(&pack(&[object, tree, commit]));
    assert!(rig.check(&[(&ticket, ticket_id)], wrong_head).is_err());
    let extension = TestExtraction::new(&rig);
    closure_ticks(&rig, &extension, 100);
    assert_eq!(
        rig.check(&[(&ticket, ticket_id)], wrong_head)
            .unwrap_err()
            .public_message(),
        "open closure"
    );
    assert_no_extraction_effects(&rig, &extension, id);
    assert!(rig.check(&[(&ticket, ticket_id)], head).is_err());
    drive(&rig, &extension, &[ticket.pack_id]);
    rig.check(&[(&ticket, ticket_id)], head).unwrap();
    assert_holder(&rig, id);
}

#[test]
fn a_terminal_block_retains_progress_that_prevents_preeffect_reclaim() {
    let rig = Rig::new();
    let object = Object::Blob(Blob {
        data: vec![76; 70_000],
    });
    let id = object.id().unwrap();
    let (tree, commit, head) = tree_head(&[id]);
    let (ticket, ticket_id) = rig.add(&pack(&[object, tree, commit]));
    assert!(rig.check(&[(&ticket, ticket_id)], head).is_err());
    let extension = TestExtraction::new(&rig);
    for _ in 0..100 {
        if rig
            .job(&ticket.pack_id)
            .is_some_and(|j| j.extraction.as_ref().is_some_and(|x| x.stage == 8))
        {
            break;
        }
        fire_pack(&rig, &extension, ticket.pack_id);
    }
    assert_eq!(
        rig.job(&ticket.pack_id).unwrap().extraction.unwrap().stage,
        8
    );
    assert!(read_blob(&rig.blobs, &BlobKey::object(id)).is_some());
    block_on(
        ContentIndex::new(crate::store::BorrowedStore(rig.store.as_ref())).block(
            &id,
            &crate::store::BlockEntry::new("dmca", 1),
            u64::try_from(rig.clock.now_ms()).unwrap(),
        ),
    )
    .unwrap();
    fire_pack(&rig, &extension, ticket.pack_id);
    let job = rig.job(&ticket.pack_id).unwrap();
    assert_eq!(
        job.outcome,
        Some(crate::indexed::checkpoint::Outcome::ObjectBlocked)
    );
    let progress = job
        .extraction
        .expect("terminal errors retain durable extraction progress");
    assert_eq!(progress.object, Some(id));
    assert_eq!(progress.stage, 8);
}

#[test]
fn a_missing_delta_dependency_uses_its_older_owner_lag() {
    let rig = Rig::new();
    let (base, base_raw) = blob(77, 400);
    let (_, target_raw) = blob(78, 70_000);
    seed_member(&rig, base, &base_raw);
    let first = rig.add(&thin(base, &base_raw, &target_raw));
    rig.clock.advance(50_000);
    let (bytes, head) = tree_pack(1, 70_000);
    let second = rig.add(&bytes);
    let tickets = [(&first.0, first.1), (&second.0, second.1)];
    assert!(rig.check(&tickets, head).is_err());
    let extension = TestExtraction::new(&rig);
    for _ in 0..40 {
        fire_pack(&rig, &extension, first.0.pack_id);
    }
    for _ in 0..100 {
        if rig
            .job(&second.0.pack_id)
            .is_some_and(|j| j.extraction.as_ref().is_some_and(|x| x.stage == 10))
        {
            break;
        }
        fire_pack(&rig, &extension, second.0.pack_id);
    }
    assert_eq!(
        rig.job(&second.0.pack_id)
            .unwrap()
            .extraction
            .unwrap()
            .stage,
        10
    );
    let (start, end) =
        keys::verify_range(&rig.repo.name, &first.0.pack_id, Some(keys::VC_DEPENDENCY));
    let page = block_on(rig.store.scan(&rig.source(), &start, &end, None, 1)).unwrap();
    let Some(keys::ParsedKey::VerifyCursor {
        id: Some(member), ..
    }) = keys::parse(&page.entries[0].0)
    else {
        panic!("decoded thin pack must retain its dependency");
    };
    block_on(rig.store.apply(
        &rig.source(),
        Batch::new().delete(keys::membership(&rig.repo.name, &member)),
    ))
    .unwrap();
    rig.clock
        .set(i64::try_from(first.0.created_at_ms + rig.cfg.relay_lag_bound_ms + 1).unwrap());
    for _ in 0..30 {
        fire_pack(&rig, &extension, second.0.pack_id);
    }
    assert_eq!(
        rig.job(&second.0.pack_id).unwrap().outcome,
        Some(crate::indexed::checkpoint::Outcome::BaseCapped)
    );
    assert_eq!(
        rig.check(&tickets, head).unwrap_err().public_message(),
        "delta base not available in this repository"
    );
}

#[test]
fn missing_member_source_can_arrive_before_lag_and_then_extract() {
    let mut rig = Rig::new();
    rig.cfg.relay_lag_bound_ms = 200_000;
    let chunk = Object::Blob(Blob {
        data: vec![73; 70_000],
    });
    let chunk_id = chunk.id().unwrap();
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: 70_000,
        chunk_size: 0,
        chunks: vec![chunk_id],
    });
    let id = manifest.id().unwrap();
    let (tree, commit, head) = tree_head(&[id]);
    let (ticket, ticket_id) = rig.add(&pack(&[manifest, tree, commit]));
    assert!(rig.check(&[(&ticket, ticket_id)], head).is_err());
    let extension = TestExtraction::new(&rig);
    closure_ticks(&rig, &extension, 100);
    assert_no_extraction_effects(&rig, &extension, id);
    seed_member(&rig, chunk_id, &serialize(&chunk).unwrap());
    drive(&rig, &extension, &[ticket.pack_id]);
    rig.check(&[(&ticket, ticket_id)], head).unwrap();
    assert_holder(&rig, id);
}

#[test]
fn a_peer_stale_closure_error_does_not_block_a_revalidated_group_owner() {
    let rig = Rig::new();
    let native_rig = Rig::new();
    let chunk = Object::Blob(Blob {
        data: vec![76; 70_000],
    });
    let chunk_id = chunk.id().unwrap();
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: 70_000,
        chunk_size: 0,
        chunks: vec![chunk_id],
    });
    let id = manifest.id().unwrap();
    let (tree, commit, head) = tree_head(&[id]);
    let packs = [pack(&[manifest]), pack(&[tree, commit])];
    let tickets = packs.iter().map(|pack| rig.add(pack)).collect::<Vec<_>>();
    let native_tickets = packs
        .iter()
        .map(|pack| native_rig.add(pack))
        .collect::<Vec<_>>();
    let items = tickets
        .iter()
        .map(|(ticket, id)| (ticket, *id))
        .collect::<Vec<_>>();
    assert!(rig.check(&items, head).is_err());
    let extension = TestExtraction::new(&rig);
    rig.clock
        .advance(i64::try_from(rig.cfg.relay_lag_bound_ms).unwrap() + 1);
    for _ in 0..100 {
        for (ticket, _) in &tickets {
            fire_pack(&rig, &extension, ticket.pack_id);
        }
        if tickets.iter().all(|(ticket, _)| {
            rig.job(&ticket.pack_id).unwrap().outcome == Some(checkpoint::Outcome::ClosureMissing)
        }) {
            break;
        }
    }
    for (ticket, _) in &tickets {
        assert_eq!(
            rig.job(&ticket.pack_id).unwrap().outcome,
            Some(checkpoint::Outcome::ClosureMissing)
        );
    }
    assert_no_extraction_effects(&rig, &extension, id);
    seed_member(&rig, chunk_id, &serialize(&chunk).unwrap());
    // Only the first owner runs. The peer's durable error remains stale while
    // this owner validates the complete current group and starts its object.
    for _ in 0..100 {
        fire_pack(&rig, &extension, tickets[0].0.pack_id);
        let job = rig.job(&tickets[0].0.pack_id).unwrap();
        if job
            .extraction
            .as_ref()
            .is_some_and(|x| x.object == Some(id) && x.stage == 4)
        {
            assert_eq!(job.outcome, None);
            break;
        }
    }
    let first = rig.job(&tickets[0].0.pack_id).unwrap();
    assert_eq!(first.outcome, None);
    assert_eq!(first.extraction.as_ref().unwrap().stage, 4);
    assert_eq!(
        rig.job(&tickets[1].0.pack_id).unwrap().outcome,
        Some(checkpoint::Outcome::ClosureMissing)
    );
    fire_pack(&rig, &extension, tickets[0].0.pack_id);
    assert_eq!(rig.job(&tickets[0].0.pack_id).unwrap().outcome, None);
    assert!(
        rig.job(&tickets[0].0.pack_id)
            .unwrap()
            .extraction
            .as_ref()
            .unwrap()
            .stage
            > 4
    );
    drive(
        &rig,
        &extension,
        &tickets
            .iter()
            .map(|(ticket, _)| ticket.pack_id)
            .collect::<Vec<_>>(),
    );
    seed_member(&native_rig, chunk_id, &serialize(&chunk).unwrap());
    assert_eq!(
        rig.check(&items, head).unwrap(),
        native(&native_rig, &native_tickets, head)
    );
    assert_holder(&rig, id);
}

#[test]
fn a_consumed_chunk_decoding_after_lag_still_satisfies_the_barrier() {
    let rig = Rig::new();
    let chunk = Object::Blob(Blob {
        data: vec![74; 70_000],
    });
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: 70_000,
        chunk_size: 0,
        chunks: vec![chunk.id().unwrap()],
    });
    let id = manifest.id().unwrap();
    let (tree, commit, head) = tree_head(&[id]);
    let first = rig.add(&pack(&[manifest, tree, commit]));
    let second = rig.add(&pack(&[chunk]));
    assert!(
        rig.check(&[(&first.0, first.1), (&second.0, second.1)], head)
            .is_err()
    );
    let extension = TestExtraction::new(&rig);
    for _ in 0..40 {
        fire_pack(&rig, &extension, first.0.pack_id);
    }
    assert_no_extraction_effects(&rig, &extension, id);
    rig.clock
        .advance(i64::try_from(rig.cfg.relay_lag_bound_ms).unwrap() + 1);
    drive(&rig, &extension, &[first.0.pack_id, second.0.pack_id]);
    rig.check(&[(&first.0, first.1), (&second.0, second.1)], head)
        .unwrap();
    assert_holder(&rig, id);
}

fn assert_holder(rig: &Rig, id: Hash) {
    let holder = block_on(rig.store.get(
        &content_shard(&id),
        &keys::holder(&id, &rig.repo.namespace, &rig.repo.name).unwrap(),
    ))
    .unwrap();
    assert!(holder.is_some(), "Verified content has no durable holder");
    let (start, end) = keys::pending_holders_of(&id);
    assert!(
        block_on(rig.store.scan(&content_shard(&id), &start, &end, None, 100))
            .unwrap()
            .entries
            .is_empty()
    );
    let (start, end) = keys::holds_of(&id);
    assert!(
        block_on(rig.store.scan(&content_shard(&id), &start, &end, None, 100))
            .unwrap()
            .entries
            .is_empty()
    );
}

fn native(
    rig: &Rig,
    tickets: &[(TicketV1, Hash)],
    head: Hash,
) -> crate::indexed::verify::StagedCommits {
    let values = tickets
        .iter()
        .map(|(ticket, _)| ticket.clone())
        .collect::<Vec<_>>();
    let ids = tickets.iter().map(|(_, id)| *id).collect::<Vec<_>>();
    block_on(crate::indexed::verify::verify_ticketed(
        rig.blobs.as_ref(),
        rig.store.as_ref(),
        rig.shards.as_ref(),
        &rig.repo,
        &rig.source(),
        &values,
        &ids,
        head,
        rig.cfg,
        rig.clock.as_ref(),
        rig.recorder.as_ref(),
    ))
    .unwrap()
}

#[test]
fn scheduled_union_matches_native_for_blob_manifest_and_tree_in_separate_packs() {
    for direct_blob in [false, true] {
        let chunk = Object::Blob(Blob {
            data: vec![41; 70_000],
        });
        let chunk_id = chunk.id().unwrap();
        let manifest = Object::ChunkedBlob(ChunkedBlob {
            total_size: 70_000,
            chunk_size: 0,
            chunks: vec![chunk_id],
        });
        let manifest_id = manifest.id().unwrap();
        let files = if direct_blob {
            vec![chunk_id, manifest_id]
        } else {
            vec![manifest_id]
        };
        let (tree, commit, head) = tree_head(&files);
        let packs = [pack(&[chunk]), pack(&[manifest]), pack(&[tree, commit])];
        let scheduled_rig = Rig::new();
        let native_rig = Rig::new();
        let tickets = packs
            .iter()
            .map(|p| scheduled_rig.add(p))
            .collect::<Vec<_>>();
        let native_tickets = packs.iter().map(|p| native_rig.add(p)).collect::<Vec<_>>();
        let expected = native(&native_rig, &native_tickets, head);
        let items = tickets.iter().map(|(t, id)| (t, *id)).collect::<Vec<_>>();
        assert!(scheduled_rig.check(&items, head).is_err());
        let extension = TestExtraction::new(&scheduled_rig);
        drive(
            &scheduled_rig,
            &extension,
            &tickets.iter().map(|(t, _)| t.pack_id).collect::<Vec<_>>(),
        );
        assert_eq!(scheduled_rig.check(&items, head).unwrap(), expected);
        for id in [chunk_id, manifest_id] {
            assert_eq!(
                read_blob(&scheduled_rig.blobs, &BlobKey::object(id)),
                read_blob(&native_rig.blobs, &BlobKey::object(id))
            );
        }
        assert_holder(&scheduled_rig, manifest_id);
        if direct_blob {
            assert_holder(&scheduled_rig, chunk_id);
        }
        assert!(
            scheduled_rig
                .recorder
                .slices
                .lock()
                .unwrap()
                .iter()
                .all(|calls| *calls <= 256.0)
        );
    }
}

#[test]
fn scheduled_staged_member_and_mixed_chunks_reassemble_exact_content_and_offsets() {
    let data = [vec![3; 4_000], vec![5; 9_000], vec![7; 1_500], vec![9; 2]];
    let chunks = data
        .iter()
        .map(|data| Object::Blob(Blob { data: data.clone() }))
        .collect::<Vec<_>>();
    let ids = chunks
        .iter()
        .map(|object| object.id().unwrap())
        .collect::<Vec<_>>();
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: 14_502,
        chunk_size: 0,
        chunks: ids.clone(),
    });
    let id = manifest.id().unwrap();
    let (tree, commit, head) = tree_head(&[id]);
    for member in [vec![], vec![0, 1, 2, 3], vec![1, 3]] {
        let scheduled_rig = Rig::new();
        let native_rig = Rig::new();
        let mut objects = vec![manifest.clone(), tree.clone(), commit.clone()];
        for (i, object) in chunks.iter().enumerate() {
            if member.contains(&i) {
                let raw = serialize(object).unwrap();
                seed_member(&scheduled_rig, ids[i], &raw);
                seed_member(&native_rig, ids[i], &raw);
            } else {
                objects.push(object.clone());
            }
        }
        let bytes = pack(&objects);
        let ticket = scheduled_rig.add(&bytes);
        let native_ticket = native_rig.add(&bytes);
        let expected = native(&native_rig, &[native_ticket], head);
        assert!(scheduled_rig.check(&[(&ticket.0, ticket.1)], head).is_err());
        let extension = TestExtraction::new(&scheduled_rig);
        drive(&scheduled_rig, &extension, &[ticket.0.pack_id]);
        assert_eq!(
            scheduled_rig.check(&[(&ticket.0, ticket.1)], head).unwrap(),
            expected
        );
        assert_eq!(
            read_blob(&scheduled_rig.blobs, &BlobKey::object(id)),
            Some(data.concat())
        );
        assert_eq!(
            read_blob(&scheduled_rig.blobs, &BlobKey::object_offsets(id)),
            Some(crate::indexed::extract::encode_offsets(&[
                0, 4_000, 13_000, 14_500, 14_502
            ]))
        );
        for chunk in &ids {
            assert!(read_blob(&scheduled_rig.blobs, &BlobKey::object(*chunk)).is_none());
        }
        assert_holder(&scheduled_rig, id);
    }
}

#[test]
fn scheduled_duplicate_objects_keep_first_pack_owner_and_advance_counts() {
    let blob = Object::Blob(Blob {
        data: vec![61; 70_000],
    });
    let id = blob.id().unwrap();
    let (tree, commit, head) = tree_head(&[id]);
    let packs = [
        pack(std::slice::from_ref(&blob)),
        pack(&[blob, tree, commit]),
    ];
    let rig = Rig::new();
    let native_rig = Rig::new();
    let native_tickets = packs.iter().map(|p| native_rig.add(p)).collect::<Vec<_>>();
    let expected = native(&native_rig, &native_tickets, head);
    let tickets = packs.iter().map(|p| rig.add(p)).collect::<Vec<_>>();
    let items = tickets.iter().map(|(t, id)| (t, *id)).collect::<Vec<_>>();
    assert!(rig.check(&items, head).is_err());
    drive(
        &rig,
        &TestExtraction::new(&rig),
        &tickets.iter().map(|(t, _)| t.pack_id).collect::<Vec<_>>(),
    );
    let facts = rig.check(&items, head).unwrap();
    assert_eq!(facts.objects, 3, "duplicate canonical objects count once");
    assert_eq!(
        facts, expected,
        "canonical byte and object counts match native"
    );
    let raw = block_on(rig.store.get(
        &content_shard(&id),
        &keys::holder(&id, &rig.repo.namespace, &rig.repo.name).unwrap(),
    ))
    .unwrap()
    .unwrap();
    assert_eq!(codec::decode_holder(&raw).unwrap().op_id, tickets[0].1);
    assert_holder(&rig, id);
}

#[test]
fn verified_reuse_keeps_selection_facts_without_recording_the_first_owner_again() {
    let blob = Object::Blob(Blob {
        data: vec![71; 70_000],
    });
    let blob_id = blob.id().unwrap();
    let (first_tree, first_commit, first_head) = tree_head(&[blob_id]);
    let first_pack = pack(&[blob, first_tree, first_commit]);
    let rig = Rig::new();
    let first = rig.add(&first_pack);
    assert!(rig.check(&[(&first.0, first.1)], first_head).is_err());
    let extension = TestExtraction::new(&rig);
    drive(&rig, &extension, &[first.0.pack_id]);
    let holder_key = keys::holder(&blob_id, &rig.repo.namespace, &rig.repo.name).unwrap();
    let holder_before = block_on(rig.store.get(&content_shard(&blob_id), &holder_key)).unwrap();
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: 70_000,
        chunk_size: 0,
        chunks: vec![blob_id],
    });
    let id = manifest.id().unwrap();
    let (tree, commit, head) = tree_head(&[id]);
    let second = rig.add(&pack(&[manifest, tree, commit]));
    let items = [(&first.0, first.1), (&second.0, second.1)];
    assert!(rig.check(&items, head).is_err());
    drive(&rig, &extension, &[second.0.pack_id]);
    rig.check(&items, head).unwrap();
    assert_eq!(
        read_blob(&rig.blobs, &BlobKey::object(id)),
        Some(vec![71; 70_000])
    );
    assert_eq!(
        block_on(rig.store.get(&content_shard(&blob_id), &holder_key)).unwrap(),
        holder_before
    );
    assert_holder(&rig, id);
}

#[test]
fn queued_holder_is_renewed_beyond_ticket_expiry_and_one_day() {
    let rig = Rig::new();
    let (bytes, head) = tree_pack(1, 70_000);
    let (ticket, ticket_id) = rig.add(&bytes);
    assert!(rig.check(&[(&ticket, ticket_id)], head).is_err());
    let extension = TestExtraction::new(&rig);
    for _ in 0..300 {
        if rig
            .job(&ticket.pack_id)
            .unwrap()
            .extraction
            .as_ref()
            .is_some_and(|x| x.stage == 9)
        {
            break;
        }
        tick(&rig, &extension, rig.store.as_ref(), true);
        rig.clock.advance(1_000);
    }
    let job = rig.job(&ticket.pack_id).unwrap();
    let x = job.extraction.as_ref().unwrap();
    assert_eq!(x.stage, 9);
    let id = x.object.unwrap();
    let content = ContentIndex::new(crate::store::BorrowedStore(rig.store.as_ref()));
    let hold = crate::indexed::extract::hold_id(&rig.repo, &ticket_id, &id);
    rig.clock
        .advance(i64::try_from(crate::store::MAX_HOLD_TTL_MS).unwrap() + 1_000);
    block_on(
        rig.store
            .apply(&rig.source(), Batch::new().delete(keys::ticket(&ticket_id))),
    )
    .unwrap();
    assert!(
        block_on(content.collectable(&id, u64::try_from(rig.clock.now_ms()).unwrap(), 0))
            .unwrap()
            .is_none()
    );
    tick(&rig, &extension, rig.store.as_ref(), false);
    let raw = block_on(rig.store.get(&content_shard(&id), &keys::hold(&id, &hold)))
        .unwrap()
        .unwrap();
    assert!(codec::decode_hold(&raw).unwrap() > u64::try_from(rig.clock.now_ms()).unwrap());
    for _ in 0..20 {
        tick(&rig, &extension, rig.store.as_ref(), true);
        rig.clock.advance(1_000);
        if block_on(rig.store.get(
            &content_shard(&id),
            &keys::holder(&id, &rig.repo.namespace, &rig.repo.name).unwrap(),
        ))
        .unwrap()
        .is_some()
        {
            break;
        }
    }
    assert_holder(&rig, id);
}

#[test]
fn near_one_mib_fragment_payload_is_split_with_checkpoint_guard_headroom() {
    let rig = Rig::new();
    let chunk = Object::Blob(Blob {
        data: vec![81; (1 << 20) - 10],
    });
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: (1 << 20) - 10,
        chunk_size: 0,
        chunks: vec![chunk.id().unwrap()],
    });
    let id = manifest.id().unwrap();
    let (tree, commit, head) = tree_head(&[id]);
    let (ticket, ticket_id) = rig.add(&pack(&[chunk, manifest, tree, commit]));
    assert!(rig.check(&[(&ticket, ticket_id)], head).is_err());
    drive(&rig, &TestExtraction::new(&rig), &[ticket.pack_id]);
    assert_eq!(
        read_blob(&rig.blobs, &BlobKey::object(id)),
        Some(vec![81; (1 << 20) - 10])
    );
    assert_holder(&rig, id);
}

#[test]
fn empty_chunks_and_empty_manifests_match_native_content_and_offsets() {
    for chunks in [
        vec![],
        vec![vec![]],
        vec![vec![], vec![2; 100], vec![], vec![4; 50]],
    ] {
        let objects = chunks
            .iter()
            .map(|bytes| {
                Object::Blob(Blob {
                    data: bytes.clone(),
                })
            })
            .collect::<Vec<_>>();
        let manifest = Object::ChunkedBlob(ChunkedBlob {
            total_size: chunks.iter().map(|x| x.len() as u64).sum(),
            chunk_size: 0,
            chunks: objects.iter().map(|x| x.id().unwrap()).collect(),
        });
        let id = manifest.id().unwrap();
        let (tree, commit, head) = tree_head(&[id]);
        // Packs cannot repeat the same canonical empty Blob.
        let mut all = BTreeMap::new();
        for object in objects.into_iter().chain([manifest, tree, commit]) {
            all.insert(object.id().unwrap(), object);
        }
        let bytes = pack(&all.into_values().collect::<Vec<_>>());
        let rig = Rig::new();
        let native_rig = Rig::new();
        let ticket = rig.add(&bytes);
        let native_ticket = native_rig.add(&bytes);
        let expected = native(&native_rig, &[native_ticket], head);
        assert!(rig.check(&[(&ticket.0, ticket.1)], head).is_err());
        drive(&rig, &TestExtraction::new(&rig), &[ticket.0.pack_id]);
        assert_eq!(rig.check(&[(&ticket.0, ticket.1)], head).unwrap(), expected);
        assert_eq!(
            read_blob(&rig.blobs, &BlobKey::object(id)),
            Some(chunks.concat())
        );
        assert_eq!(
            read_blob(&rig.blobs, &BlobKey::object_offsets(id)),
            read_blob(&native_rig.blobs, &BlobKey::object_offsets(id))
        );
        assert_holder(&rig, id);
    }
}

#[test]
fn every_extraction_checkpoint_boundary_replays_without_losing_protection() {
    for stage in (0..=13).filter(|stage| *stage != 5) {
        let mut rig = Rig::new();
        let chunk = Object::Blob(Blob {
            data: vec![92; 500],
        });
        let manifest = Object::ChunkedBlob(ChunkedBlob {
            total_size: 500,
            chunk_size: 0,
            chunks: vec![chunk.id().unwrap()],
        });
        let id = manifest.id().unwrap();
        let (tree, commit, head) = tree_head(&[id]);
        let canonical = serialize(&chunk).unwrap();
        seed_member(&rig, chunk.id().unwrap(), &canonical);
        let objects = [manifest, tree, commit];
        rig.cfg.decode_budget = objects
            .iter()
            .map(|object| serialize(object).unwrap().len() as u64)
            .sum::<u64>()
            + canonical.len() as u64;
        let (ticket, ticket_id) = rig.add(&pack(&objects));
        assert!(rig.check(&[(&ticket, ticket_id)], head).is_err());
        let extension = TestExtraction::new(&rig);
        for _ in 0..300 {
            if rig
                .job(&ticket.pack_id)
                .unwrap()
                .extraction
                .as_ref()
                .is_some_and(|x| x.stage == stage)
            {
                break;
            }
            tick(&rig, &extension, rig.store.as_ref(), true);
            rig.clock.advance(1_000);
        }
        assert_eq!(
            rig.job(&ticket.pack_id)
                .unwrap()
                .extraction
                .as_ref()
                .unwrap()
                .stage,
            stage
        );
        let faulty = Faulty {
            inner: rig.store.clone(),
            applies: AtomicU32::new(0),
            fail_at: AtomicU32::new(1),
            inventory_guard: None,
        };
        tick(&rig, &extension, &faulty, false);
        assert!(faulty.applies.load(Ordering::SeqCst) >= 1);
        if read_blob(&rig.blobs, &BlobKey::object(id)).is_some() {
            let index = ContentIndex::new(crate::store::BorrowedStore(rig.store.as_ref()));
            assert!(
                block_on(index.collectable(&id, u64::try_from(rig.clock.now_ms()).unwrap(), 0))
                    .unwrap()
                    .is_none(),
                "stage {stage} lost protection"
            );
        }
        rig.clock.advance(1_000);
        drive(&rig, &extension, &[ticket.pack_id]);
        assert_eq!(
            read_blob(&rig.blobs, &BlobKey::object(id)),
            Some(vec![92; 500])
        );
        assert_eq!(
            read_blob(&rig.blobs, &BlobKey::object_offsets(id)),
            Some(crate::indexed::extract::encode_offsets(&[0, 500]))
        );
        assert_holder(&rig, id);
    }
}

#[test]
fn multipart_lost_replies_at_begin_part_and_completion_resume_same_session() {
    for boundary in ["begin", "part", "complete"] {
        let mut rig = Rig::new();
        rig.limits.window_bytes = 16 << 20;
        let mut data = vec![Vec::new()];
        data.extend((0..8).map(|i| vec![102 + i; (1 << 20) - 10]));
        data.extend([vec![110; 80], Vec::new(), vec![111; 99]]);
        let chunks = data
            .iter()
            .map(|data| Object::Blob(Blob { data: data.clone() }))
            .collect::<Vec<_>>();
        let manifest = Object::ChunkedBlob(ChunkedBlob {
            total_size: (8 << 20) + 99,
            chunk_size: 0,
            chunks: chunks.iter().map(|chunk| chunk.id().unwrap()).collect(),
        });
        let id = manifest.id().unwrap();
        let (tree, commit, head) = tree_head(&[id]);
        let mut objects = BTreeMap::new();
        for object in chunks.into_iter().chain([manifest, tree, commit]) {
            objects.insert(object.id().unwrap(), object);
        }
        let (ticket, ticket_id) = rig.add(&pack(&objects.into_values().collect::<Vec<_>>()));
        assert!(rig.check(&[(&ticket, ticket_id)], head).is_err());
        let extension = TestExtraction::new(&rig);
        *extension.fail.lock().unwrap() = Some(boundary);
        drive(&rig, &extension, &[ticket.pack_id]);
        assert!(
            extension.fail.lock().unwrap().is_none(),
            "{boundary} fault was not reached"
        );
        assert_eq!(
            extension.sessions.lock().unwrap().len(),
            1,
            "{boundary} started another immutable session"
        );
        assert_eq!(
            read_blob(&rig.blobs, &BlobKey::object(id)),
            Some(data.concat())
        );
        assert!(extension.completed.load(Ordering::SeqCst) >= 1);
        assert_holder(&rig, id);
        assert!(
            rig.recorder
                .slices
                .lock()
                .unwrap()
                .iter()
                .all(|calls| *calls <= 256.0)
        );
    }
}

#[test]
fn repository_local_source_budget_fails_identically_on_dedup_and_miss() {
    for present in [false, true] {
        let mut rig = Rig::new();
        let chunk = Object::Blob(Blob {
            data: vec![121; 4_000],
        });
        let canonical = serialize(&chunk).unwrap();
        seed_member(&rig, chunk.id().unwrap(), &canonical);
        let manifest = Object::ChunkedBlob(ChunkedBlob {
            total_size: 4_000,
            chunk_size: 0,
            chunks: vec![chunk.id().unwrap()],
        });
        let id = manifest.id().unwrap();
        let (tree, commit, head) = tree_head(&[id]);
        let objects = [manifest, tree, commit];
        rig.cfg.decode_budget = objects
            .iter()
            .map(|object| serialize(object).unwrap().len() as u64)
            .sum::<u64>()
            + canonical.len() as u64
            - 1;
        if present {
            block_on(async {
                let data = vec![121; 4_000];
                let root = hash(&data);
                let mut sink = rig.blobs.begin(BlobKey::object(id), 4_000).await.unwrap();
                sink.write(Bytes::from(data)).await.unwrap();
                sink.commit_with_root(root).await.unwrap();
            });
        }
        let (ticket, ticket_id) = rig.add(&pack(&objects));
        assert!(rig.check(&[(&ticket, ticket_id)], head).is_err());
        let extension = TestExtraction::new(&rig);
        for _ in 0..300 {
            if rig.finished(&ticket.pack_id) {
                break;
            }
            tick(&rig, &extension, rig.store.as_ref(), true);
            rig.clock.advance(1_000);
        }
        assert_eq!(
            rig.job(&ticket.pack_id).unwrap().outcome,
            Some(crate::indexed::checkpoint::Outcome::DecodeBudget)
        );
        assert_eq!(
            read_blob(&rig.blobs, &BlobKey::object(id)).is_some(),
            present
        );
        assert!(
            block_on(rig.store.get(
                &content_shard(&id),
                &keys::holder(&id, &rig.repo.namespace, &rig.repo.name).unwrap()
            ))
            .unwrap()
            .is_none()
        );
    }
}

#[test]
fn extraction_holder_enqueue_cannot_commit_under_a_lost_source_lease() {
    let rig = Rig::named("one", Arc::new(D34Shards));
    let (bytes, head) = tree_pack(1, 70_000);
    let (ticket, ticket_id) = rig.add(&bytes);
    assert!(rig.check(&[(&ticket, ticket_id)], head).is_err());
    let extension = TestExtraction::new(&rig);
    for _ in 0..300 {
        if rig
            .job(&ticket.pack_id)
            .unwrap()
            .extraction
            .as_ref()
            .is_some_and(|x| x.stage == 8)
        {
            break;
        }
        tick(&rig, &extension, rig.store.as_ref(), true);
        rig.clock.advance(1_000);
    }
    assert_eq!(
        rig.job(&ticket.pack_id)
            .unwrap()
            .extraction
            .as_ref()
            .unwrap()
            .stage,
        8
    );
    let id = rig
        .job(&ticket.pack_id)
        .unwrap()
        .extraction
        .unwrap()
        .object
        .unwrap();
    let rival = Rival {
        inner: rig.store.clone(),
        armed: std::sync::atomic::AtomicBool::new(true),
        relay_rows_seen: AtomicU32::new(0),
    };
    tick(&rig, &extension, &rival, false);
    assert_eq!(rival.relay_rows_seen.load(Ordering::SeqCst), 0);
    assert_eq!(
        rig.job(&ticket.pack_id)
            .unwrap()
            .extraction
            .as_ref()
            .unwrap()
            .stage,
        8
    );
    rig.clock.advance(1_000);
    drive(&rig, &extension, &[ticket.pack_id]);
    assert_holder(&rig, id);
}

#[test]
fn a_rejected_group_member_prevents_effects_and_the_survivor_can_retry_alone() {
    let rig = Rig::new();
    let tree = Object::Tree(Tree { entries: vec![] });
    let (mut bad, _) = signed_commit(tree.id().unwrap(), vec![], 7, b"bad signature");
    if let Object::Commit(commit) = &mut bad {
        commit.signature[0] ^= 1;
    }
    let first = rig.add(&pack(&[tree, bad]));
    let (bytes, head) = tree_pack(1, 70_000);
    let second = rig.add(&bytes);
    let mut extracted = None;
    decode_entries_with(
        &bytes,
        &mut NoExternalBases,
        DecodeLimits::default(),
        |entry| {
            if matches!(entry.object, Object::Blob(_)) {
                extracted = Some(entry.id);
            }
            Ok(())
        },
    )
    .unwrap();
    let id = extracted.unwrap();
    assert!(
        rig.check(&[(&first.0, first.1), (&second.0, second.1)], head)
            .is_err()
    );
    let extension = TestExtraction::new(&rig);
    for _ in 0..100 {
        tick(&rig, &extension, rig.store.as_ref(), true);
        rig.clock.advance(1_000);
    }
    assert!(matches!(
        rig.state(&first.0.pack_id),
        Some(VerificationV1::Rejected { .. })
    ));
    assert!(read_blob(&rig.blobs, &BlobKey::object(id)).is_none());
    let (start, end) = keys::pending_holders_of(&id);
    assert!(
        block_on(rig.store.scan(&content_shard(&id), &start, &end, None, 100))
            .unwrap()
            .entries
            .is_empty()
    );
    assert!(rig.check(&[(&second.0, second.1)], head).is_err());
    assert_eq!(
        rig.job(&second.0.pack_id).unwrap().extraction_group.len(),
        1
    );
    drive(&rig, &extension, &[second.0.pack_id]);
    rig.check(&[(&second.0, second.1)], head).unwrap();
    assert_holder(&rig, id);
}

fn fire_pack(rig: &Rig, extension: &TestExtraction, pack: Hash) {
    use crate::timers::{DueTimer, Fired, TimerCtx, TimerHandler};
    let handler = extraction_handler(rig, extension.clone());
    let now = u64::try_from(rig.clock.now_ms()).unwrap();
    let fired = block_on(handler.fire(
        &TimerCtx {
            store: rig.store.as_ref(),
            partition: &rig.source(),
            now_ms: now,
        },
        &DueTimer {
            due_at_ms: now,
            kind: crate::timers::registry::kinds::VERIFY,
            reference: Bytes::from(crate::indexed::checkpoint::timer_reference(
                &rig.repo.name,
                &pack,
            )),
            value: Value::default(),
        },
    ))
    .unwrap();
    let batch = match fired {
        Fired::Done(batch) | Fired::Reschedule { batch, .. } => batch,
        Fired::Retry => return,
    };
    assert_eq!(
        block_on(rig.store.apply(&rig.source(), batch)).unwrap(),
        BatchOutcome::Committed
    );
}

#[test]
fn canceling_the_first_owner_cannot_verify_a_duplicate_without_extraction() {
    let rig = Rig::new();
    let object = Object::Blob(Blob {
        data: vec![141; 70_000],
    });
    let id = object.id().unwrap();
    let (tree, commit, head) = tree_head(&[id]);
    let first = rig.add(&pack(std::slice::from_ref(&object)));
    let second = rig.add(&pack(&[object, tree, commit]));
    assert!(
        rig.check(&[(&first.0, first.1), (&second.0, second.1)], head)
            .is_err()
    );
    let extension = TestExtraction::new(&rig);
    for _ in 0..300 {
        if [first.0.pack_id, second.0.pack_id]
            .iter()
            .all(|pack| rig.job(pack).unwrap().phase == Phase::Extract)
        {
            break;
        }
        tick(&rig, &extension, rig.store.as_ref(), true);
        rig.clock.advance(1_000);
    }
    let job = rig.job(&first.0.pack_id).unwrap();
    assert_eq!(job.phase, Phase::Extract);
    assert!(job.extraction.as_ref().is_none_or(|x| x.object.is_none()));
    block_on(
        rig.store
            .apply(&rig.source(), Batch::new().delete(keys::ticket(&first.1))),
    )
    .unwrap();
    for _ in 0..80 {
        fire_pack(&rig, &extension, second.0.pack_id);
        rig.clock.advance(1_000);
    }
    assert!(
        !rig.job(&second.0.pack_id).unwrap().usable()
            || read_blob(&rig.blobs, &BlobKey::object(id)).is_some(),
        "surviving duplicate became Verified while its canceled first owner never extracted the object"
    );
    let _ = rig.check(&[(&second.0, second.1)], head);
    drive(&rig, &extension, &[second.0.pack_id]);
    rig.check(&[(&second.0, second.1)], head).unwrap();
    assert_holder(&rig, id);
}

#[path = "extraction_budget_tests.rs"]
mod budget_tests;

#[test]
fn extraction_effects_refuse_a_lost_source_lease_before_publication() {
    for stage in [3, 4, 6] {
        let rig = Rig::named("one", Arc::new(D34Shards));
        let (bytes, head) = tree_pack(1, 70_000);
        let (ticket, ticket_id) = rig.add(&bytes);
        assert!(rig.check(&[(&ticket, ticket_id)], head).is_err());
        let extension = TestExtraction::new(&rig);
        for _ in 0..300 {
            if rig
                .job(&ticket.pack_id)
                .unwrap()
                .extraction
                .as_ref()
                .is_some_and(|x| x.stage == stage)
            {
                break;
            }
            tick(&rig, &extension, rig.store.as_ref(), true);
            rig.clock.advance(1_000);
        }
        let before = rig.job(&ticket.pack_id).unwrap().extraction.unwrap();
        assert_eq!(before.stage, stage);
        let object = before.object.unwrap();
        // An unusable persisted lease must close each effect before it starts.
        block_on(rig.store.apply(
            &rig.source(),
            Batch::new().put(keys::epoch_lease(), Value::default()),
        ))
        .unwrap();
        tick(&rig, &extension, rig.store.as_ref(), false);
        assert_eq!(
            rig.job(&ticket.pack_id).unwrap().extraction.unwrap(),
            before
        );
        assert!(read_blob(&rig.blobs, &BlobKey::object(object)).is_none());
    }
}
