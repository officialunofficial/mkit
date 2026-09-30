//! Ownership and failed-group recovery use current ticket bindings.
use super::*;

#[test]
fn another_signer_cannot_steal_an_unfinished_group_member() {
    let rig = Rig::new();
    let (a, _) = tree_pack(1, 10);
    let (b, head) = tree_pack(2, 10);
    let (c, other_head) = tree_pack(3, 10);
    let first = rig.add(&a);
    let second = rig.add(&b);
    let third = rig.add(&c);
    assert!(
        rig.check(&[(&first.0, first.1), (&second.0, second.1)], head)
            .is_err()
    );
    let before = rig.job(&first.0.pack_id).unwrap();
    // BeginUpload's index includes the signer: these two live tickets do not
    // collide, unlike duplicate same-signer bindings in one Advance.
    let mut alternate = first.0.clone();
    alternate.signer = [4; 32];
    alternate.reservation_id = "other-signer".into();
    let alternate_id = tickets::ticket_id(&alternate.reservation_id);
    block_on(rig.store.apply(
        &rig.source(),
        Batch::new().put(
            keys::ticket(&alternate_id),
            codec::encode_ticket(&alternate),
        ),
    ))
    .unwrap();
    assert!(
        rig.check(
            &[(&alternate, alternate_id), (&third.0, third.1)],
            other_head
        )
        .is_err()
    );
    assert_eq!(rig.job(&first.0.pack_id).unwrap(), before);
    assert!(
        rig.job(&third.0.pack_id).is_none(),
        "foreign claim created a partial group"
    );
}

#[test]
fn a_live_ticket_can_reclaim_its_pre_effect_job_after_group_ticket_disappears() {
    let rig = Rig::new();
    let (a, _) = tree_pack(1, 10);
    let (b, head) = tree_pack(2, 10);
    let first = rig.add(&a);
    let second = rig.add(&b);
    assert!(
        rig.check(&[(&first.0, first.1), (&second.0, second.1)], head)
            .is_err()
    );
    block_on(
        rig.store
            .apply(&rig.source(), Batch::new().delete(keys::ticket(&first.1))),
    )
    .unwrap();
    assert!(rig.check(&[(&second.0, second.1)], head).is_err());
    let recovered = rig.job(&second.0.pack_id).unwrap();
    assert_eq!(recovered.ticket_id, second.1);
    assert_eq!(recovered.extraction_group.len(), 1);
    rig.drive(|r| r.finished(&second.0.pack_id));
    assert!(rig.check(&[(&second.0, second.1)], head).is_ok());
}

#[test]
fn a_rejected_peer_allows_pre_effect_reclaim_but_an_active_peer_does_not() {
    for failed in [false, true] {
        let rig = Rig::new();
        let (a, _) = tree_pack(1, 10);
        let (b, head) = tree_pack(2, 10);
        let first = rig.add(&a);
        let second = rig.add(&b);
        assert!(
            rig.check(&[(&first.0, first.1), (&second.0, second.1)], head)
                .is_err()
        );
        if failed {
            block_on(rig.store.apply(
                &rig.source(),
                Batch::new().put(
                    keys::verification(&rig.repo.name, &first.0.pack_id),
                    super::super::state::encode(&VerificationV1::Rejected {
                        code: "invalid_argument".into(),
                        message: "bad signature".into(),
                    }),
                ),
            ))
            .unwrap();
        }
        assert!(rig.check(&[(&second.0, second.1)], head).is_err());
        assert_eq!(
            rig.job(&second.0.pack_id).unwrap().extraction_group.len(),
            if failed { 1 } else { 2 }
        );
    }
}

#[test]
fn a_ready_source_is_pinned_to_its_new_group_without_redecoding() {
    let rig = Rig::new();
    let (a, first_head) = tree_pack(1, 10);
    let (b, head) = tree_pack(2, 10);
    let first = rig.add(&a);
    assert!(rig.check(&[(&first.0, first.1)], first_head).is_err());
    rig.drive(|r| r.finished(&first.0.pack_id));
    let before = rig.job(&first.0.pack_id).unwrap();
    let second = rig.add(&b);
    assert!(
        rig.check(&[(&first.0, first.1), (&second.0, second.1)], head)
            .is_err()
    );
    let retained = rig.job(&first.0.pack_id).unwrap();
    assert_eq!(retained.phase, before.phase);
    assert_eq!(retained.entries, before.entries);
    assert_eq!(retained.etag, before.etag);
    assert_eq!(retained.extraction_group.len(), 2);
    assert_eq!(
        rig.job(&second.0.pack_id).unwrap().extraction_group,
        retained.extraction_group
    );
}

struct RevivedTicket {
    rig: Arc<MemoryKv>,
    key: Key,
    value: Value,
}

struct BatchBytes {
    inner: Arc<MemoryKv>,
    maximum: std::sync::atomic::AtomicUsize,
}

impl NamespaceStore for BatchBytes {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.inner.get(p, key).await
    }
    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        self.inner.get_many(p, keys).await
    }
    async fn scan(
        &self,
        p: &Partition,
        a: &Key,
        b: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.inner.scan(p, a, b, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        let bytes: usize = batch
            .preconditions
            .iter()
            .map(|pre| match pre {
                crate::store::Precondition::Absent(k) | crate::store::Precondition::Present(k) => {
                    k.as_bytes().len()
                }
                crate::store::Precondition::Equals(k, v) => k.as_bytes().len() + v.as_bytes().len(),
                crate::store::Precondition::NotAfter(_) => 0,
            })
            .chain(batch.writes.iter().map(|write| match write {
                crate::store::Write::Put(k, v) => k.as_bytes().len() + v.as_bytes().len(),
                crate::store::Write::Delete(k) => k.as_bytes().len(),
            }))
            .sum();
        self.maximum.fetch_max(bytes, Ordering::SeqCst);
        self.inner.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

impl NamespaceStore for RevivedTicket {
    fn capabilities(&self) -> StoreCapabilities {
        self.rig.capabilities()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.rig.get(p, key).await
    }
    async fn scan(
        &self,
        p: &Partition,
        a: &Key,
        b: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.rig.scan(p, a, b, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.rig
            .apply(p, Batch::new().put(self.key.clone(), self.value.clone()))
            .await?;
        self.rig.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.rig.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.rig.probe().await
    }
}

#[test]
fn a_changed_failed_group_witness_cannot_commit_a_reclaim() {
    let rig = Rig::new();
    let (a, _) = tree_pack(1, 10);
    let (b, head) = tree_pack(2, 10);
    let first = rig.add(&a);
    let second = rig.add(&b);
    assert!(
        rig.check(&[(&first.0, first.1), (&second.0, second.1)], head)
            .is_err()
    );
    block_on(
        rig.store
            .apply(&rig.source(), Batch::new().delete(keys::ticket(&first.1))),
    )
    .unwrap();
    let racing = RevivedTicket {
        rig: rig.store.clone(),
        key: keys::ticket(&first.1),
        value: codec::encode_ticket(&first.0),
    };
    assert!(
        block_on(scheduled::check(
            rig.blobs.as_ref(),
            &racing,
            rig.shards.as_ref(),
            &rig.repo,
            &rig.source(),
            &[second.0.clone()],
            &[second.1],
            head,
            rig.cfg,
            rig.clock.as_ref(),
            rig.recorder.as_ref()
        ))
        .is_err()
    );
    assert_eq!(
        rig.job(&second.0.pack_id).unwrap().extraction_group.len(),
        2
    );
}

#[test]
fn completed_groups_with_full_member_lists_remain_claimable() {
    let rig = Rig::new();
    let mut entries = (0..256)
        .map(|n| {
            let (id, raw) = blob(n, 20);
            seed_member(&rig, id, &raw);
            TreeEntry {
                name: format!("external{n}").into_bytes(),
                mode: EntryMode::Blob,
                object_hash: id,
            }
        })
        .collect::<Vec<_>>();
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let tree = Object::Tree(Tree { entries });
    let tree_id = tree.id().unwrap();
    let mut groups = Vec::new();
    for group in 0..6 {
        let mut members = Vec::new();
        let mut head = [0; 32];
        for member in 0..7 {
            let (commit, id) = signed_commit(
                tree_id,
                Vec::new(),
                7,
                format!("{group}:{member}").as_bytes(),
            );
            let mut writer = PackWriter::new_raw_only();
            writer
                .push_raw(tree_id, &serialize(&tree).unwrap())
                .unwrap();
            writer.push_raw(id, &serialize(&commit).unwrap()).unwrap();
            members.push(rig.add(&writer.finish().unwrap()));
            head = id;
        }
        let items = members.iter().map(|(t, id)| (t, *id)).collect::<Vec<_>>();
        assert!(rig.check(&items, head).is_err());
        groups.push(members);
    }
    let all = groups.iter().flatten().collect::<Vec<_>>();
    for _ in 0..15_000 {
        if all.iter().all(|(t, _)| rig.finished(&t.pack_id)) {
            break;
        }
        rig.tick();
        rig.clock.advance(10);
    }
    assert!(all.iter().all(|(t, _)| rig.finished(&t.pack_id)));
    for (ticket, _) in &all {
        let job = rig.job(&ticket.pack_id).unwrap();
        assert!(job.usable());
        assert_eq!(job.satisfying.len(), 256);
    }
    let guarded_bytes: usize = all
        .iter()
        .map(|(t, _)| {
            block_on(
                rig.store
                    .get(&rig.source(), &keys::verify_job(&rig.repo.name, &t.pack_id)),
            )
            .unwrap()
            .unwrap()
            .as_bytes()
            .len()
        })
        .sum();
    assert!(
        guarded_bytes <= crate::store::MAX_BATCH_BYTES,
        "current producer headers must fit the summed guard cap: {guarded_bytes}"
    );
    let (bytes, head) = tree_pack(1, 10);
    let fresh = rig.add(&bytes);
    let mut items = groups
        .iter()
        .map(|members| (&members[0].0, members[0].1))
        .collect::<Vec<_>>();
    items.push((&fresh.0, fresh.1));
    let counted = BatchBytes {
        inner: rig.store.clone(),
        maximum: std::sync::atomic::AtomicUsize::new(0),
    };
    let values = items.iter().map(|(t, _)| (*t).clone()).collect::<Vec<_>>();
    let ids = items.iter().map(|(_, id)| *id).collect::<Vec<_>>();
    let result = block_on(scheduled::check(
        rig.blobs.as_ref(),
        &counted,
        rig.shards.as_ref(),
        &rig.repo,
        &rig.source(),
        &values,
        &ids,
        head,
        rig.cfg,
        rig.clock.as_ref(),
        rig.recorder.as_ref(),
    ));
    let maximum = counted.maximum.load(Ordering::SeqCst);
    assert!(
        maximum <= crate::store::MAX_BATCH_BYTES,
        "claim used {maximum} bytes"
    );
    eprintln!(
        "current-produced old job values {guarded_bytes} bytes; attempted atomic claim {maximum} bytes"
    );
    assert!(
        rig.job(&fresh.0.pack_id).is_some(),
        "legitimate claim stalled with {guarded_bytes} old raw job bytes: {result:?}"
    );
}

#[test]
fn a_changed_peer_header_or_generation_defeats_the_actual_reuse_claim() {
    for phase_change in [false, true] {
        let rig = Rig::new();
        let (a, first_head) = tree_pack(1, 10);
        let first = rig.add(&a);
        assert!(rig.check(&[(&first.0, first.1)], first_head).is_err());
        rig.drive(|r| r.finished(&first.0.pack_id));
        let key = keys::verify_job(&rig.repo.name, &first.0.pack_id);
        let prior = block_on(rig.store.get(&rig.source(), &key))
            .unwrap()
            .unwrap();
        let mut changed = rig.job(&first.0.pack_id).unwrap();
        if phase_change {
            changed.phase = Phase::Recheck;
        }
        let update = super::super::checkpoint::write_job(
            Batch::new(),
            &mut changed,
            Some(&prior),
            &rig.repo.name,
            &first.0.pack_id,
        )
        .unwrap();
        let crate::store::Write::Put(_, value) = update.writes.last().unwrap() else {
            panic!("writer must end with the bounded header");
        };
        let racing = RevivedTicket {
            rig: rig.store.clone(),
            key,
            value: value.clone(),
        };
        let (b, head) = tree_pack(2, 10);
        let second = rig.add(&b);
        assert!(
            block_on(scheduled::check(
                rig.blobs.as_ref(),
                &racing,
                rig.shards.as_ref(),
                &rig.repo,
                &rig.source(),
                &[first.0.clone(), second.0.clone()],
                &[first.1, second.1],
                head,
                rig.cfg,
                rig.clock.as_ref(),
                rig.recorder.as_ref(),
            ))
            .is_err()
        );
        assert!(
            rig.job(&second.0.pack_id).is_none(),
            "stale peer claim committed"
        );
        assert!(
            rig.job(&first.0.pack_id).unwrap().generation > decode_job(&prior).unwrap().generation
        );
    }
}
