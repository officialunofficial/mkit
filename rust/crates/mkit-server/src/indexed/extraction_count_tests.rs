//! Counts and decode charges come from the consumed canonical object union.
use super::*;

struct NoFrameScans {
    inner: Arc<MemoryKv>,
    frames: AtomicU32,
    frame_starts: Vec<Key>,
}

impl NamespaceStore for NoFrameScans {
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
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        if self.frame_starts.contains(start) {
            self.frames.fetch_add(1, Ordering::SeqCst);
            return Err(StoreError::Unavailable(
                "ready facts must not rescan frames".into(),
            ));
        }
        self.inner.scan(p, start, end, after, limit).await
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

#[test]
fn ready_current_producer_union_counts_do_not_rescan_frames_even_with_packlist() {
    let rig = Rig::new();
    let native_rig = Rig::new();
    let blob = Object::Blob(Blob {
        data: vec![81; 100],
    });
    let (tree, commit, head) = tree_head(&[blob.id().unwrap()]);
    let mut packs = vec![pack(&[blob]), pack(&[tree, commit])];
    let list = mkit_core::transfer::encode_packlist(
        None,
        &packs.iter().map(|p| hash(p)).collect::<Vec<_>>(),
    )
    .unwrap();
    packs.push(list);
    let tickets = packs.iter().map(|p| rig.add(p)).collect::<Vec<_>>();
    let native_tickets = packs.iter().map(|p| native_rig.add(p)).collect::<Vec<_>>();
    let expected = native(&native_rig, &native_tickets, head);
    let items = tickets.iter().map(|(t, id)| (t, *id)).collect::<Vec<_>>();
    assert!(rig.check(&items, head).is_err());
    drive(
        &rig,
        &TestExtraction::new(&rig),
        &tickets.iter().map(|(t, _)| t.pack_id).collect::<Vec<_>>(),
    );
    let store = NoFrameScans {
        inner: rig.store.clone(),
        frames: AtomicU32::new(0),
        frame_starts: tickets
            .iter()
            .map(|(ticket, _)| {
                keys::verify_range(&rig.repo.name, &ticket.pack_id, Some(keys::VC_FRAME)).0
            })
            .collect(),
    };
    let values = tickets.iter().map(|(t, _)| t.clone()).collect::<Vec<_>>();
    let ids = tickets.iter().map(|(_, id)| *id).collect::<Vec<_>>();
    let actual = block_on(scheduled::check(
        rig.blobs.as_ref(),
        &store,
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
    assert_eq!(actual.unwrap(), expected);
    assert_eq!(store.frames.load(Ordering::SeqCst), 0);
}

#[test]
fn duplicate_canonical_bytes_fit_the_native_union_decode_budget_boundary() {
    let blob = Object::Blob(Blob {
        data: vec![82; 70_000],
    });
    let (tree, commit, head) = tree_head(&[blob.id().unwrap()]);
    let budget = [&blob, &tree, &commit]
        .iter()
        .map(|object| serialize(object).unwrap().len() as u64)
        .sum::<u64>();
    let packs = [
        pack(std::slice::from_ref(&blob)),
        pack(&[blob, tree, commit]),
    ];
    let mut rig = Rig::new();
    let mut native_rig = Rig::new();
    rig.cfg.decode_budget = budget;
    native_rig.cfg.decode_budget = budget;
    let tickets = packs.iter().map(|p| rig.add(p)).collect::<Vec<_>>();
    let native_tickets = packs.iter().map(|p| native_rig.add(p)).collect::<Vec<_>>();
    let expected = native(&native_rig, &native_tickets, head);
    assert_eq!(expected.bytes, budget);
    let items = tickets.iter().map(|(t, id)| (t, *id)).collect::<Vec<_>>();
    assert!(rig.check(&items, head).is_err());
    drive(
        &rig,
        &TestExtraction::new(&rig),
        &tickets.iter().map(|(t, _)| t.pack_id).collect::<Vec<_>>(),
    );
    assert_eq!(rig.check(&items, head).unwrap(), expected);
}
