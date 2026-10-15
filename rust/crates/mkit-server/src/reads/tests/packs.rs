use super::*;

#[test]
#[allow(clippy::too_many_lines)] // One fixture pins routing, ordering and frame bounds.
fn exact_pack_indexes_route_order_absence_duplicates_and_frame_bounds() {
    for shards in maps() {
        let store = MemoryKv::default();
        let repo = repo();
        let object = [22; 32];
        let reads = ReadAccess::new(&store, shards.as_ref(), RepoVisibility::Public, true);
        let packs = [
            PackRef {
                id: [24; 32],
                len: 37,
            },
            PackRef {
                id: [25; 32],
                len: 37,
            },
            PackRef {
                id: [23; 32],
                len: 47,
            },
            PackRef {
                id: [24; 32],
                len: 37,
            },
        ];
        assert!(
            block_on(reads.object_index_in_packs(&repo, &object, &packs))
                .unwrap()
                .is_empty()
        );
        seed_member(&store, shards.as_ref(), &repo, object, packs[0].id, 20);
        seed_member(&store, shards.as_ref(), &repo, object, packs[2].id, 30);
        // An index is exact evidence even without a membership row.
        block_on(store.apply(
            &shards.membership(&repo, &BlobKey::pack(packs[0].id)),
            Batch::new().delete(keys::membership(&repo.name, &packs[0].id)),
        ))
        .unwrap();
        let found = block_on(reads.object_index_in_packs(&repo, &object, &packs)).unwrap();
        assert_eq!(
            found.iter().map(|(pack, _)| *pack).collect::<Vec<_>>(),
            vec![packs[0].id, packs[2].id, packs[0].id]
        );
        assert_eq!(found[0], found[2]);
        assert_eq!(
            found[0].1.frame_offset + found[0].1.frame_length,
            packs[0].len
        );
        assert_eq!(
            (
                found[0].1.wire_type,
                found[0].1.decoded_size,
                found[0].1.in_pack_delta_depth,
                found[0].1.delta_base
            ),
            (0, 20, 0, None)
        );
        let foreign = RepoId {
            name: RepoName::new("other").unwrap(),
            ..repo.clone()
        };
        assert!(
            block_on(reads.object_index_in_packs(&foreign, &object, &packs))
                .unwrap()
                .is_empty()
        );
        let mut short = packs;
        short[3].len -= 1;
        assert!(block_on(reads.object_index_in_packs(&repo, &object, &short)).is_err());
        let index_partition = shards.object_index(&repo, &object);
        let key = keys::object_index(&repo.name, &object, &packs[2].id);
        put(&store, &index_partition, key.clone(), Value::new(vec![255]));
        assert_eq!(
            code(block_on(
                reads.object_index_in_packs(&repo, &object, &packs)
            )),
            crate::Code::Internal
        );
        // Overflowing frame ends cannot become valid even for a maximal pack.
        let mut raw = codec::encode_object_index(
            &object,
            &index::IndexValue {
                frame_offset: 12,
                frame_length: 5,
                wire_type: 0,
                decoded_size: 1,
                chain_depth: 0,
                delta_base: None,
            },
        )
        .unwrap()
        .as_bytes()
        .to_vec();
        // Encode a valid row, then corrupt its frame offset through the codec's fixed width.
        raw[1..9].copy_from_slice(&u64::MAX.to_be_bytes());
        put(&store, &index_partition, key, Value::new(raw));
        assert_eq!(
            code(block_on(reads.object_index_in_packs(
                &repo,
                &object,
                &[PackRef {
                    id: packs[2].id,
                    len: u64::MAX
                }]
            ))),
            crate::Code::Internal
        );
    }
}

#[test]
fn exact_pack_indexes_batch_caps_and_shared_call_budget() {
    use crate::indexed::budget::{Budgeted, SliceBudget};
    for shards in maps() {
        let store = MemoryKv::default();
        let repo = repo();
        let object = [31; 32];
        let pack = PackRef {
            id: [32; 32],
            len: 37,
        };
        seed_member(&store, shards.as_ref(), &repo, object, pack.id, 20);
        let calls = SliceBudget::new(8);
        let budgeted = Budgeted::new(&store, &calls);
        let reads = ReadAccess::new(&budgeted, shards.as_ref(), RepoVisibility::Public, true);
        assert!(
            block_on(reads.object_index_in_packs(&repo, &object, &[]))
                .unwrap()
                .is_empty()
        );
        assert_eq!(calls.used(), 0);
        assert_eq!(
            block_on(reads.object_index_in_packs(
                &repo,
                &object,
                &vec![pack; MAX_OBJECT_INDEX_PACKS + 1]
            ))
            .unwrap_err()
            .code(),
            crate::Code::InvalidArgument
        );
        assert_eq!(calls.used(), 0);
        let result = block_on(reads.object_index_in_packs(
            &repo,
            &object,
            &vec![pack; MAX_OBJECT_INDEX_PACKS],
        ))
        .unwrap();
        assert_eq!(result.len(), MAX_OBJECT_INDEX_PACKS);
        assert!(result.windows(2).all(|pair| pair[0] == pair[1]));
        assert_eq!(calls.used(), 8);
        assert!(block_on(reads.object_index_in_packs(&repo, &object, &[pack])).is_err());
        let calls = SliceBudget::new(1);
        let budgeted = Budgeted::new(&store, &calls);
        let reads = ReadAccess::new(&budgeted, shards.as_ref(), RepoVisibility::Public, true);
        assert!(
            block_on(reads.object_index_in_packs(
                &repo,
                &object,
                &vec![pack; OBJECT_INDEX_BATCH_SIZE + 1]
            ))
            .is_err()
        );
        assert_eq!(calls.used(), 1);
    }
}

#[test]
#[allow(clippy::too_many_lines)] // One fixture pins witness parity across views.
fn pack_witness_routes_presence_decoding_and_visibility_parity() {
    for shards in maps() {
        for member in [false, true] {
            for published in [false, true] {
                for empty in [false, true] {
                    for held in [false, true] {
                        for cleared in [false, true] {
                            let store = MemoryKv::default();
                            let repo = repo();
                            let pack = [41; 32];
                            let p = shards.membership(&repo, &BlobKey::pack(pack));
                            let internal = publication::Witness {
                                generation: 3,
                                sequence: 9,
                                published: cleared,
                                held,
                                boundary: true,
                            };
                            let raw = if empty {
                                Value::default()
                            } else {
                                internal.encode()
                            };
                            let decoded = publication::Witness::decode(&raw).unwrap();
                            if member {
                                put(&store, &p, keys::membership(&repo.name, &pack), raw.clone());
                            }
                            if published {
                                put(&store, &p, keys::published_member(&repo.name, &pack), raw);
                            }
                            let reads = ReadAccess::new(
                                &store,
                                shards.as_ref(),
                                RepoVisibility::Public,
                                true,
                            );
                            let witness = block_on(reads.pack_witness(&repo, &pack)).unwrap();
                            assert_eq!(
                                witness.member,
                                member.then(|| VisibilityWitness::from_witness(decoded))
                            );
                            assert_eq!(
                                witness.published,
                                published.then(|| VisibilityWitness::from_witness(decoded))
                            );
                            for writer in [false, true] {
                                for generation in [0, 3, 4] {
                                    assert_eq!(
                                        witness.visible(writer, generation),
                                        member && published && decoded.visible(writer, generation)
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        // Validate an invisible or absent partner's corrupt row too; repeat reads are fresh.
        for bad_member in [false, true] {
            let store = MemoryKv::default();
            let repo = repo();
            let pack = [42; 32];
            let p = shards.membership(&repo, &BlobKey::pack(pack));
            let reads = ReadAccess::new(&store, shards.as_ref(), RepoVisibility::Public, true);
            assert!(
                !block_on(reads.pack_witness(&repo, &pack))
                    .unwrap()
                    .visible(true, 0)
            );
            let bad = if bad_member {
                keys::membership(&repo.name, &pack)
            } else {
                keys::published_member(&repo.name, &pack)
            };
            put(&store, &p, bad.clone(), Value::new(vec![255]));
            assert_eq!(
                code(block_on(reads.pack_witness(&repo, &pack))),
                crate::Code::Internal
            );
            put(&store, &p, bad.clone(), Value::default());
            assert!(block_on(reads.pack_witness(&repo, &pack)).is_ok());
            let partner = if bad_member {
                keys::published_member(&repo.name, &pack)
            } else {
                keys::membership(&repo.name, &pack)
            };
            put(
                &store,
                &p,
                partner,
                publication::Witness {
                    generation: 0,
                    sequence: 0,
                    published: true,
                    held: true,
                    boundary: false,
                }
                .encode(),
            );
            put(&store, &p, bad, Value::new(vec![255]));
            assert_eq!(
                code(block_on(reads.pack_witness(&repo, &pack))),
                crate::Code::Internal
            );
        }
    }
}

#[test]
fn pack_witness_shared_budget_charges_one_call_and_refuses_exhaustion() {
    use crate::indexed::budget::{Budgeted, SliceBudget};
    for shards in maps() {
        let store = MemoryKv::default();
        let repo = repo();
        let calls = SliceBudget::new(1);
        let budgeted = Budgeted::new(&store, &calls);
        let reads = ReadAccess::new(&budgeted, shards.as_ref(), RepoVisibility::Public, true);
        assert!(block_on(reads.pack_witness(&repo, &[1; 32])).is_ok());
        assert_eq!(calls.used(), 1);
        assert!(block_on(reads.pack_witness(&repo, &[1; 32])).is_err());
    }
}

struct BatchObserver {
    inner: MemoryKv,
    batches: std::sync::Mutex<Vec<(crate::Partition, usize)>>,
    extra_rows: i8,
}

impl NamespaceStore for BatchObserver {
    fn capabilities(&self) -> crate::store::StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(
        &self,
        p: &crate::Partition,
        key: &crate::Key,
    ) -> Result<Option<Value>, crate::StoreError> {
        self.inner.get(p, key).await
    }
    async fn get_many(
        &self,
        p: &crate::Partition,
        keys: &[crate::Key],
    ) -> Result<Vec<Option<Value>>, crate::StoreError> {
        self.batches.lock().unwrap().push((p.clone(), keys.len()));
        let mut rows = self.inner.get_many(p, keys).await?;
        match self.extra_rows {
            -1 => {
                rows.pop();
            }
            1 => rows.push(None),
            _ => {}
        }
        Ok(rows)
    }
    async fn scan(
        &self,
        p: &crate::Partition,
        start: &crate::Key,
        end: &crate::Key,
        cursor: Option<&crate::store::Cursor>,
        limit: u32,
    ) -> Result<crate::store::ScanPage, crate::StoreError> {
        self.inner.scan(p, start, end, cursor, limit).await
    }
    async fn apply(
        &self,
        p: &crate::Partition,
        batch: Batch,
    ) -> Result<BatchOutcome, crate::StoreError> {
        self.inner.apply(p, batch).await
    }
    async fn stats(
        &self,
        p: &crate::Partition,
    ) -> Result<crate::store::PartitionStats, crate::StoreError> {
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), crate::StoreError> {
        self.inner.probe().await
    }
}

#[test]
fn exact_evidence_batch_geometry_and_malformed_replies() {
    for shards in maps() {
        let repo = repo();
        let object = [51; 32];
        let pack = PackRef {
            id: [52; 32],
            len: 37,
        };
        for extra_rows in [-1, 0, 1] {
            let store = BatchObserver {
                inner: MemoryKv::default(),
                batches: std::sync::Mutex::new(Vec::new()),
                extra_rows,
            };
            let reads = ReadAccess::new(&store, shards.as_ref(), RepoVisibility::Public, true);
            let result = block_on(reads.object_index_in_packs(
                &repo,
                &object,
                &vec![pack; MAX_OBJECT_INDEX_PACKS],
            ));
            assert_eq!(result.is_ok(), extra_rows == 0);
            if extra_rows != 0 {
                assert_eq!(
                    result.map(|_| ()).unwrap_err().code(),
                    crate::Code::Unavailable,
                    "malformed replies stay retryable"
                );
            }
            let batches = store.batches.lock().unwrap().clone();
            assert_eq!(batches.len(), if extra_rows == 0 { 8 } else { 1 });
            assert!(
                batches
                    .iter()
                    .all(|(p, len)| p == &shards.object_index(&repo, &object)
                        && *len == OBJECT_INDEX_BATCH_SIZE)
            );
            store.batches.lock().unwrap().clear();
            let witness = block_on(reads.pack_witness(&repo, &pack.id));
            assert_eq!(witness.is_ok(), extra_rows == 0);
            if extra_rows != 0 {
                assert_eq!(
                    witness.map(|_| ()).unwrap_err().code(),
                    crate::Code::Unavailable,
                    "malformed replies stay retryable"
                );
            }
            assert_eq!(
                *store.batches.lock().unwrap(),
                vec![(shards.membership(&repo, &BlobKey::pack(pack.id)), 2)]
            );
        }
        // A corrupt row in a later batch refuses earlier valid results.
        let store = MemoryKv::default();
        seed_member(&store, shards.as_ref(), &repo, object, pack.id, 20);
        let bad = PackRef {
            id: [53; 32],
            len: 37,
        };
        put(
            &store,
            &shards.object_index(&repo, &object),
            keys::object_index(&repo.name, &object, &bad.id),
            Value::new(vec![255]),
        );
        let mut packs = vec![pack; OBJECT_INDEX_BATCH_SIZE];
        packs.push(bad);
        let reads = ReadAccess::new(&store, shards.as_ref(), RepoVisibility::Public, true);
        assert_eq!(
            code(block_on(
                reads.object_index_in_packs(&repo, &object, &packs)
            )),
            crate::Code::Internal
        );
    }
}

#[test]
fn pack_witness_requires_each_partner_to_clear_independently() {
    for shards in maps() {
        let store = MemoryKv::default();
        let repo = repo();
        let pack = [61; 32];
        let p = shards.membership(&repo, &BlobKey::pack(pack));
        let clear = publication::Witness {
            generation: 0,
            sequence: 7,
            published: true,
            held: false,
            boundary: false,
        };
        let reads = ReadAccess::new(&store, shards.as_ref(), RepoVisibility::Public, true);
        for blocked in [
            publication::Witness {
                held: true,
                ..clear
            },
            publication::Witness {
                generation: 1,
                ..clear
            },
            publication::Witness {
                published: false,
                ..clear
            },
        ] {
            for swap in [false, true] {
                let (member, published) = if swap {
                    (blocked, clear)
                } else {
                    (clear, blocked)
                };
                put(
                    &store,
                    &p,
                    keys::membership(&repo.name, &pack),
                    member.encode(),
                );
                put(
                    &store,
                    &p,
                    keys::published_member(&repo.name, &pack),
                    published.encode(),
                );
                let witness = block_on(reads.pack_witness(&repo, &pack)).unwrap();
                for writer in [false, true] {
                    assert_eq!(
                        witness.visible(writer, 0),
                        member.visible(writer, 0) && published.visible(writer, 0)
                    );
                }
            }
        }
    }
}

#[test]
fn exact_pack_indexes_ignore_other_packs_and_preserve_delta_metadata() {
    for shards in maps() {
        for wire_type in [0, 2, 3, 4] {
            let store = MemoryKv::default();
            let repo = repo();
            let object = [71; 32];
            let pack = PackRef {
                id: [72; 32],
                len: 37,
            };
            let delta = matches!(wire_type, 2 | 4);
            let value = index::IndexValue {
                frame_offset: 24,
                frame_length: 13,
                wire_type,
                decoded_size: 20,
                chain_depth: if delta { 2 } else { 0 },
                delta_base: delta.then_some([73; 32]),
            };
            let p = shards.object_index(&repo, &object);
            put(
                &store,
                &p,
                keys::object_index(&repo.name, &object, &pack.id),
                codec::encode_object_index(&object, &value).unwrap(),
            );
            // An unrelated corrupt duplicate must never be consulted by an exact query.
            put(
                &store,
                &p,
                keys::object_index(&repo.name, &object, &[74; 32]),
                Value::new(vec![255]),
            );
            let reads = ReadAccess::new(&store, shards.as_ref(), RepoVisibility::Public, true);
            assert_eq!(
                block_on(reads.object_index_in_packs(&repo, &object, &[pack])).unwrap(),
                vec![(
                    pack.id,
                    FrameLocation {
                        frame_offset: 24,
                        frame_length: 13,
                        wire_type,
                        decoded_size: 20,
                        in_pack_delta_depth: if delta { 2 } else { 0 },
                        delta_base: delta.then_some([73; 32]),
                    }
                )]
            );
        }
    }
}
