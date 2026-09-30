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
            std::slice::from_ref(&second.0),
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

fn full_member_tree(rig: &Rig) -> (Object, Vec<Hash>, Vec<Key>) {
    let mut member_packs = std::collections::BTreeMap::new();
    let mut lookup_keys = Vec::new();
    let mut entries = (0..256)
        .map(|n| {
            let (id, raw) = blob(n, 20);
            seed_member(rig, id, &raw);
            let mut writer = PackWriter::new_raw_only();
            writer.push_raw(id, &raw).unwrap();
            member_packs.insert(id, hash(&writer.finish().unwrap()));
            lookup_keys.push(keys::object_index_range(&rig.repo.name, &id).0);
            TreeEntry {
                name: format!("external{n}").into_bytes(),
                mode: EntryMode::Blob,
                object_hash: id,
            }
        })
        .collect::<Vec<_>>();
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    (
        Object::Tree(Tree { entries }),
        member_packs.into_values().collect(),
        lookup_keys,
    )
}

fn preseed_known_members(rig: &Rig, pack: Hash, members: &[Hash]) {
    let key = keys::verify_job(&rig.repo.name, &pack);
    let prior = block_on(rig.store.get(&rig.source(), &key))
        .unwrap()
        .unwrap();
    let mut job = decode_job(&prior).unwrap();
    job.members_loaded = true;
    job.satisfying = members.to_vec();
    let batch = super::super::checkpoint::write_job(
        Batch::new()
            .require(crate::Precondition::Equals(key, prior.clone()))
            .require(crate::Precondition::NotAfter(
                u64::try_from(rig.clock.now_ms()).unwrap() + 10_000,
            )),
        &mut job,
        Some(&prior),
        &rig.repo.name,
        &pack,
    )
    .unwrap();
    assert_eq!(
        block_on(rig.store.apply(&rig.source(), batch)).unwrap(),
        BatchOutcome::Committed
    );
}

struct MemberLookups {
    inner: Arc<MemoryKv>,
    counts: Mutex<std::collections::BTreeMap<Key, usize>>,
    untracked: Mutex<std::collections::BTreeSet<Key>>,
}

impl MemberLookups {
    fn observe(&self, start: &Key) {
        if let Some(count) = self.counts.lock().unwrap().get_mut(start) {
            *count += 1;
        } else {
            let mut samples = self.untracked.lock().unwrap();
            if samples.len() < 8 {
                samples.insert(start.clone());
            }
        }
    }
}

impl NamespaceStore for MemberLookups {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, p: &Partition, k: &Key) -> Result<Option<Value>, StoreError> {
        self.inner.get(p, k).await
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
        self.observe(a);
        self.inner.scan(p, a, b, after, limit).await
    }
    async fn scan_many(
        &self,
        p: &Partition,
        ranges: &[RangeScan],
    ) -> Result<Vec<ScanPage>, StoreError> {
        for range in ranges {
            self.observe(&range.start);
        }
        self.inner.scan_many(p, ranges).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.inner.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

struct ObservedVerification {
    inner: VerifyTimer<Shared<MemberLookups>, Shared<MemoryBlobStore>, Arc<Windows>>,
    errors: Arc<Mutex<Vec<String>>>,
}

impl<S: NamespaceStore> crate::timers::TimerHandler<S> for ObservedVerification {
    fn kind(&self) -> crate::timers::TimerKind {
        crate::timers::registry::kinds::VERIFY
    }
    fn max_per_tick(&self) -> Option<u32> {
        Some(1)
    }
    fn fire<'a>(
        &'a self,
        ctx: &'a crate::timers::TimerCtx<'a, S>,
        timer: &'a crate::timers::DueTimer,
    ) -> crate::BoxFuture<'a, Result<crate::timers::Fired, StoreError>> {
        Box::pin(async move {
            let result = crate::timers::TimerHandler::fire(&self.inner, ctx, timer).await;
            if let Err(error) = &result {
                self.errors.lock().unwrap().push(error.to_string());
            }
            result
        })
    }
}

fn tick_counting_members(rig: &Rig, lookups: &Arc<MemberLookups>) {
    let h = rig.handler();
    let handler = VerifyTimer {
        remote: Shared(lookups.clone()),
        blobs: h.blobs,
        windows: h.windows,
        shards: h.shards,
        cfg: h.cfg,
        limits: h.limits,
        lease: h.lease,
        clock: h.clock,
        metrics: h.metrics,
        extension: h.extension,
    };
    let errors = Arc::new(Mutex::new(Vec::new()));
    let registry = TimerRegistry::new()
        .register(ObservedVerification {
            inner: handler,
            errors: errors.clone(),
        })
        .register(crate::relay::RelayHandler {
            target: Shared(rig.store.clone()),
            hook: crate::relay::NoHook,
            budget: crate::relay::RelayBudget::default(),
        });
    let report = block_on(run_due(
        lookups.as_ref(),
        &rig.source(),
        &registry,
        rig.clock.as_ref(),
        u64::try_from(rig.clock.now_ms()).unwrap(),
        &TickBudget::default(),
    ))
    .unwrap();
    assert_eq!(
        report.failed,
        0,
        "verification fixture failed: {report:?}, errors {:?}",
        errors.lock().unwrap()
    );
}

fn finish_full_member_group(
    rig: &Rig,
    lookups: &Arc<MemberLookups>,
    members: &[(TicketV1, Hash)],
    satisfying: &[Hash],
    representative: Option<Hash>,
) -> usize {
    let mut seeded = std::collections::BTreeSet::new();
    let mut finished = std::collections::BTreeSet::new();
    for _ in 0..15_000 {
        for (ticket, _) in members {
            if !finished.contains(&ticket.pack_id)
                && matches!(
                    rig.state(&ticket.pack_id),
                    Some(VerificationV1::Verified { .. })
                )
            {
                finished.insert(ticket.pack_id);
            }
        }
        if finished.len() == members.len() {
            break;
        }
        for (ticket, _) in members {
            // Decode owns clearing provisional vc4 rows. Install cached members
            // only after that producer finished, before its first closure lookup.
            if Some(ticket.pack_id) != representative
                && !seeded.contains(&ticket.pack_id)
                && rig.job(&ticket.pack_id).unwrap().phase == Phase::ClosureResolve
            {
                preseed_known_members(rig, ticket.pack_id, satisfying);
                seeded.insert(ticket.pack_id);
            }
        }
        tick_counting_members(rig, lookups);
        rig.clock.advance(10);
    }
    assert_eq!(finished.len(), 7);
    for (ticket, _) in members {
        let job = rig.job(&ticket.pack_id).unwrap();
        assert!(
            job.usable(),
            "unfinished job phase {:?}, outcome {:?}, entries {}, pending children {}",
            job.phase,
            job.outcome,
            job.entries,
            rig.rows(&ticket.pack_id, keys::VC_CHILD).len()
        );
        assert_eq!(job.satisfying, satisfying);
    }
    seeded.len()
}

fn completed_full_member_groups(rig: &Rig) -> Vec<Vec<(TicketV1, Hash)>> {
    let (tree, satisfying, lookup_keys) = full_member_tree(rig);
    let tree_id = tree.id().unwrap();
    let lookups = Arc::new(MemberLookups {
        inner: rig.store.clone(),
        counts: Mutex::new(lookup_keys.into_iter().map(|key| (key, 0)).collect()),
        untracked: Mutex::default(),
    });
    let mut groups = Vec::new();
    let mut seeded = 0;
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
        // The required claim sees six completed groups. Completing each before
        // creating the next avoids retaining 10,752 redundant pending children.
        seeded += finish_full_member_group(
            rig,
            &lookups,
            &members,
            &satisfying,
            (group == 0).then_some(members[0].0.pack_id),
        );
        groups.push(members);
    }
    assert_eq!(seeded, 41);
    let counts = lookups.counts.lock().unwrap();
    assert_eq!(counts.len(), 256);
    let first = rig.job(&groups[0][0].0.pack_id).unwrap();
    assert!(
        counts.values().all(|count| *count == 42),
        "each job must resolve every member: count range {:?}..{:?}, expected key {:?}, observed starts {:?}, first job {:?}",
        counts.values().min(),
        counts.values().max(),
        counts.keys().next(),
        lookups.untracked.lock().unwrap(),
        (
            first.phase,
            first.entries,
            rig.rows(&groups[0][0].0.pack_id, keys::VC_CHILD).len()
        )
    );
    for (ticket, _) in groups.iter().flatten() {
        let job = rig.job(&ticket.pack_id).unwrap();
        assert!(job.usable());
        assert_eq!(job.satisfying, satisfying);
    }
    groups
}

#[test]
fn completed_groups_with_full_member_lists_remain_claimable() {
    let rig = Rig::new();
    let groups = completed_full_member_groups(&rig);
    assert_eq!(groups.len(), 6);
    assert!(groups.iter().all(|members| members.len() == 7));
    let all = groups.iter().flatten().collect::<Vec<_>>();
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
