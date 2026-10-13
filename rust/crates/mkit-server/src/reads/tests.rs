use super::*;
use crate::pipeline::{D34Shards, SinglePartition};
use crate::store::{
    Batch, BatchOutcome, BlobKey, BlobStore, PackSink, Value, codec, index, keys, publication,
};
use crate::{MemoryBlobStore, MemoryKv, NamespaceKey, RepoName};
use futures_executor::block_on;
use mkit_core::object::{Blob, Object};
use mkit_core::pack::PackWriter;

fn repo() -> RepoId {
    RepoId {
        namespace: NamespaceKey::from_namespace(&mkit_core::repo_identity::Namespace::Ed25519(
            [1; 32],
        )),
        name: RepoName::new("demo").unwrap(),
    }
}

fn maps() -> [Box<dyn ShardMap>; 2] {
    [Box::new(SinglePartition), Box::new(D34Shards)]
}

fn put(store: &MemoryKv, partition: &crate::Partition, key: crate::Key, value: Value) {
    assert_eq!(
        block_on(store.apply(partition, Batch::new().put(key, value))).unwrap(),
        BatchOutcome::Committed
    );
}

fn visibility(private: bool, time: u64) -> Value {
    codec::encode_repo_visibility(&codec::RepoVisibilityV1 {
        visibility: if private {
            codec::StoredVisibility::Private
        } else {
            codec::StoredVisibility::Public
        },
        last_created_ms: time,
        last_statement_id: None,
        changed_ms: time,
    })
}

#[test]
fn visibility_single_and_d34_absence_defaults_and_corruption() {
    for shards in maps() {
        let store = MemoryKv::with_clock(std::sync::Arc::new(crate::ManualClock::new(1)));
        let repo = repo();
        let reads = ReadAccess::new(&store, shards.as_ref(), RepoVisibility::Private, true);
        assert_eq!(block_on(reads.repository_visibility(&repo)).unwrap(), None);
        let p = shards.coordinator(&repo.namespace);
        put(
            &store,
            &p,
            keys::repo_record(&repo.name),
            codec::encode_repo_record(&codec::RepoRecord { created_at_ms: 1 }),
        );
        assert_eq!(
            block_on(reads.repository_visibility(&repo))
                .unwrap()
                .unwrap()
                .visibility,
            RepoVisibility::Private
        );
        put(
            &store,
            &p,
            keys::repo_visibility(&repo.name),
            visibility(false, 2),
        );
        assert_eq!(
            block_on(reads.repository_visibility(&repo))
                .unwrap()
                .unwrap()
                .visibility,
            RepoVisibility::Public
        );
        put(
            &store,
            &p,
            keys::repo_visibility(&repo.name),
            Value::new(vec![255]),
        );
        assert!(block_on(reads.repository_visibility(&repo)).is_err());
        put(
            &store,
            &p,
            keys::repo_visibility(&repo.name),
            visibility(false, 2),
        );
        put(
            &store,
            &p,
            keys::repo_record(&repo.name),
            Value::new(vec![255]),
        );
        assert!(block_on(reads.repository_visibility(&repo)).is_err());
    }
}

#[test]
fn private_change_during_metadata_read_invalidates_visibility_revision() {
    for shards in maps() {
        let store = MemoryKv::with_clock(std::sync::Arc::new(crate::ManualClock::new(1)));
        let repo = repo();
        let reads = ReadAccess::new(&store, shards.as_ref(), RepoVisibility::Public, true);
        let p = shards.coordinator(&repo.namespace);
        put(
            &store,
            &p,
            keys::repo_record(&repo.name),
            codec::encode_repo_record(&codec::RepoRecord { created_at_ms: 1 }),
        );
        let before = block_on(reads.repository_visibility(&repo))
            .unwrap()
            .unwrap();
        assert_eq!(before.visibility, RepoVisibility::Public);
        // Another writer commits while the caller reads unrelated metadata.
        put(
            &store,
            &p,
            keys::repo_visibility(&repo.name),
            visibility(true, 3),
        );
        let after = block_on(reads.repository_visibility(&repo))
            .unwrap()
            .unwrap();
        assert_ne!(before.revision, after.revision);
        assert_eq!(after.visibility, RepoVisibility::Private);
        assert_eq!(
            after,
            block_on(reads.repository_visibility(&repo))
                .unwrap()
                .unwrap()
        );
        // A newer statement restoring public visibility must not restore the token.
        put(
            &store,
            &p,
            keys::repo_visibility(&repo.name),
            visibility(false, 4),
        );
        assert_ne!(
            before.revision,
            block_on(reads.repository_visibility(&repo))
                .unwrap()
                .unwrap()
                .revision
        );
    }
}

#[test]
fn published_branch_single_and_d34_absence_pair_and_corruption() {
    for shards in maps() {
        let store = MemoryKv::with_clock(std::sync::Arc::new(crate::ManualClock::new(1)));
        let repo = repo();
        let reads = ReadAccess::new(&store, shards.as_ref(), RepoVisibility::Public, true);
        let branch = "refs/heads/main";
        assert_eq!(
            block_on(reads.published_branch(&repo, branch)).unwrap(),
            None
        );
        assert!(block_on(reads.published_branch(&repo, "refs/tags/main")).is_err());
        let p = shards.ref_shard(&repo, branch);
        let key = keys::publication(&repo.name, &publication::sequence_ref(branch));
        let mut row = publication::Publication {
            sequence: 8,
            published: 6,
            boundary: 0,
            generation: 1,
            value: publication::Pair {
                head: Some([1; 32]),
                packmap: Some([2; 32]),
            },
        };
        put(&store, &p, key.clone(), row.encode().unwrap());
        let pair = block_on(reads.published_branch(&repo, branch))
            .unwrap()
            .unwrap();
        assert_eq!(
            (
                pair.head,
                pair.packmap,
                pair.sequence,
                pair.published_sequence,
                pair.generation
            ),
            ([1; 32], [2; 32], 8, 6, 1)
        );
        row.value.packmap = None;
        put(&store, &p, key.clone(), row.encode().unwrap());
        assert_eq!(
            block_on(reads.published_branch(&repo, branch)).unwrap(),
            None
        );
        row.value.head = None;
        row.value.packmap = Some([2; 32]);
        put(&store, &p, key.clone(), row.encode().unwrap());
        assert_eq!(
            block_on(reads.published_branch(&repo, branch)).unwrap(),
            None
        );
        put(&store, &p, key, Value::new(vec![255]));
        assert!(block_on(reads.published_branch(&repo, branch)).is_err());
    }
}

fn seed_member(
    store: &MemoryKv,
    shards: &dyn ShardMap,
    repo: &RepoId,
    id: Hash,
    pack: Hash,
    size: u64,
) {
    let value = index::IndexValue {
        frame_offset: 12,
        frame_length: size + 5,
        wire_type: 0,
        decoded_size: size,
        chain_depth: 0,
        delta_base: None,
    };
    put(
        store,
        &shards.object_index(repo, &id),
        keys::object_index(&repo.name, &id, &pack),
        codec::encode_object_index(&id, &value).unwrap(),
    );
    put(
        store,
        &shards.membership(repo, &BlobKey::pack(pack)),
        keys::membership(&repo.name, &pack),
        Value::default(),
    );
}

#[test]
fn member_location_single_and_d34_absence_fresh_denial_and_corruption() {
    for shards in maps() {
        let store = MemoryKv::with_clock(std::sync::Arc::new(crate::ManualClock::new(1)));
        let repo = repo();
        let reads = ReadAccess::new(&store, shards.as_ref(), RepoVisibility::Public, true);
        let id = [10; 32];
        let pack = [11; 32];
        assert_eq!(block_on(reads.locate_object(&repo, &id)).unwrap(), None);
        seed_member(&store, shards.as_ref(), &repo, id, pack, 20);
        let found = block_on(reads.locate_object(&repo, &id)).unwrap().unwrap();
        assert_eq!(
            (
                found.pack,
                found.frame_offset,
                found.decoded_size,
                found.denied
            ),
            (pack, 12, 20, false)
        );
        let foreign = RepoId {
            name: RepoName::new("other").unwrap(),
            ..repo.clone()
        };
        assert_eq!(block_on(reads.locate_object(&foreign, &id)).unwrap(), None);
        let content = crate::ContentIndex::new(crate::store::BorrowedStore(&store));
        block_on(content.block(
            &crate::takedown::DenialCapability::for_test(),
            &id,
            &crate::store::BlockEntry::new("policy", 1),
            1,
        ))
        .unwrap();
        assert!(
            block_on(reads.locate_object(&repo, &id))
                .unwrap()
                .unwrap()
                .denied
        );
        block_on(content.unblock(&id, 2)).unwrap();
        assert!(
            !block_on(reads.locate_object(&repo, &id))
                .unwrap()
                .unwrap()
                .denied
        );
        block_on(content.block(
            &crate::takedown::DenialCapability::for_test(),
            &pack,
            &crate::store::BlockEntry::new("policy", 3),
            3,
        ))
        .unwrap();
        assert!(
            block_on(reads.locate_object(&repo, &id))
                .unwrap()
                .unwrap()
                .denied
        );
        put(
            &store,
            &crate::store::content_shard(&pack),
            keys::block(&pack),
            Value::new(vec![255]),
        );
        assert!(block_on(reads.locate_object(&repo, &id)).is_err());
        put(
            &store,
            &shards.object_index(&repo, &id),
            keys::object_index(&repo.name, &id, &pack),
            Value::new(vec![255]),
        );
        assert!(block_on(reads.locate_object(&repo, &id)).is_err());
    }
}

fn upload(blobs: &MemoryBlobStore, pack: Hash, pack_bytes: &[u8]) {
    block_on(async {
        let mut sink = blobs
            .begin(BlobKey::pack(pack), pack_bytes.len() as u64)
            .await
            .unwrap();
        sink.write(bytes::Bytes::copy_from_slice(pack_bytes))
            .await
            .unwrap();
        sink.commit().await.unwrap();
    });
}

fn assert_live_canonical_denial(
    reads: &ReadAccess<'_, MemoryKv>,
    blobs: &MemoryBlobStore,
    store: &MemoryKv,
    repo: &RepoId,
    id: Hash,
    limits: MemberReadLimits,
) {
    let content = crate::ContentIndex::new(crate::store::BorrowedStore(store));
    block_on(content.block(
        &crate::takedown::DenialCapability::for_test(),
        &id,
        &crate::store::BlockEntry::new("policy", 2),
        2,
    ))
    .unwrap();
    assert!(block_on(reads.read_member_canonical(blobs, repo, id, limits)).is_err());
    block_on(content.unblock(&id, 3)).unwrap();
    assert!(
        block_on(reads.read_member_canonical(blobs, repo, id, limits))
            .unwrap()
            .is_some()
    );
}

#[test]
fn inventory_and_canonical_single_and_d34_absence_corruption_and_bounds() {
    for shards in maps() {
        let store = MemoryKv::with_clock(std::sync::Arc::new(crate::ManualClock::new(1)));
        let repo = repo();
        let reads = ReadAccess::new(&store, shards.as_ref(), RepoVisibility::Public, true);
        let object = Object::Blob(Blob {
            data: b"example".to_vec(),
        });
        let id = object.id().unwrap();
        let bytes = mkit_core::serialize::serialize(&object).unwrap();
        let mut writer = PackWriter::new_raw_only();
        writer.push_raw(id, &bytes).unwrap();
        let pack_bytes = writer.finish().unwrap();
        let pack = mkit_core::hash::hash(&pack_bytes);
        let blobs = MemoryBlobStore::new("reads");
        let limits = MemberReadLimits {
            max_delta_depth: 32,
            max_decode_bytes: 1024,
        };
        assert!(
            block_on(reads.member_inventory(&repo, &id))
                .unwrap()
                .is_none()
        );
        assert!(
            block_on(reads.read_member_canonical(&blobs, &repo, id, limits))
                .unwrap()
                .is_none()
        );
        upload(&blobs, pack, &pack_bytes);
        seed_member(&store, shards.as_ref(), &repo, id, pack, bytes.len() as u64);
        assert!(
            block_on(reads.member_inventory(&repo, &id))
                .unwrap()
                .is_none()
        );
        block_on(crate::takedown::inventory::stage(
            &store,
            &pack,
            pack_bytes.len() as u64,
            &id,
            &object,
            None,
            1,
        ))
        .unwrap();
        let inventory = block_on(reads.member_inventory(&repo, &id))
            .unwrap()
            .unwrap();
        assert_eq!(inventory.kind, Some(mkit_core::object::ObjectType::Blob));
        let canonical = block_on(reads.read_member_canonical(&blobs, &repo, id, limits))
            .unwrap()
            .unwrap();
        assert_eq!(canonical.bytes.as_ref(), bytes.as_slice());
        assert_eq!(canonical.decoded_bytes, bytes.len() as u64);
        assert_live_canonical_denial(&reads, &blobs, &store, &repo, id, limits);
        assert!(
            block_on(reads.read_member_canonical(
                &blobs,
                &repo,
                id,
                MemberReadLimits {
                    max_decode_bytes: 1,
                    ..limits
                }
            ))
            .is_err()
        );
        put(
            &store,
            &crate::store::content_shard(&pack),
            crate::takedown::inventory::entry_key(&pack, &id),
            Value::new(vec![255]),
        );
        assert!(block_on(reads.member_inventory(&repo, &id)).is_err());
        put(
            &store,
            &shards.object_index(&repo, &id),
            keys::object_index(&repo.name, &id, &pack),
            Value::new(vec![255]),
        );
        assert!(block_on(reads.read_member_canonical(&blobs, &repo, id, limits)).is_err());
    }
}

#[test]
fn batched_locations_route_order_absence_duplicates_bounds_and_corruption() {
    for shards in maps() {
        let store = MemoryKv::with_clock(std::sync::Arc::new(crate::ManualClock::new(1)));
        let repo = repo();
        let reads = ReadAccess::new(&store, shards.as_ref(), RepoVisibility::Public, true);
        let ids = [[12; 32], [14; 32], [13; 32], [12; 32]];
        assert_eq!(
            block_on(reads.locate_objects(&repo, &ids)).unwrap(),
            vec![None; 4]
        );
        seed_member(&store, shards.as_ref(), &repo, ids[0], [15; 32], 20);
        seed_member(&store, shards.as_ref(), &repo, ids[2], [16; 32], 30);
        let found = block_on(reads.locate_objects(&repo, &ids)).unwrap();
        assert_eq!(found[0].unwrap().pack, [15; 32]);
        assert_eq!(found[1], None);
        assert_eq!(found[2].unwrap().pack, [16; 32]);
        assert_eq!(found[0], found[3]);
        let too_many = vec![ids[0]; MAX_OBJECT_LOOKUP_IDS + 1];
        assert_eq!(
            block_on(reads.locate_objects(&repo, &too_many))
                .unwrap_err()
                .code(),
            crate::Code::InvalidArgument
        );
        put(
            &store,
            &shards.object_index(&repo, &ids[2]),
            keys::object_index(&repo.name, &ids[2], &[16; 32]),
            Value::new(vec![255]),
        );
        assert!(block_on(reads.locate_objects(&repo, &ids)).is_err());
    }
}

mod denial_modes {
    use super::*;
    use crate::store::{
        Cursor, Key, Partition, PartitionStats, ScanPage, StoreCapabilities, StoreError,
    };
    use std::sync::Mutex;

    struct Recorded {
        inner: MemoryKv,
        denial_reads: Mutex<usize>,
    }
    impl Recorded {
        fn observe(&self, p: &Partition, key: &Key) {
            let bytes = key.as_bytes();
            if bytes.starts_with(b"b\0")
                && (bytes.len() == 34 || (bytes.len() == 42 && bytes.ends_with(b"\0actions")))
            {
                let id: Hash = bytes[2..34].try_into().unwrap();
                if *p == crate::store::content_shard(&id) {
                    *self.denial_reads.lock().unwrap() += 1;
                }
            }
        }
    }
    impl NamespaceStore for Recorded {
        fn capabilities(&self) -> StoreCapabilities {
            self.inner.capabilities()
        }
        async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
            self.observe(p, key);
            self.inner.get(p, key).await
        }
        async fn get_many(
            &self,
            p: &Partition,
            keys: &[Key],
        ) -> Result<Vec<Option<Value>>, StoreError> {
            for key in keys {
                self.observe(p, key);
            }
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

    struct DeltaFixture {
        store: Recorded,
        blobs: MemoryBlobStore,
        base: Hash,
        base_pack: Hash,
        id: Hash,
        pack: Hash,
        bytes: Vec<u8>,
    }
    fn delta_fixture(shards: &dyn ShardMap) -> DeltaFixture {
        let store = Recorded {
            inner: MemoryKv::with_clock(std::sync::Arc::new(crate::ManualClock::new(1))),
            denial_reads: Mutex::new(0),
        };
        let blobs = MemoryBlobStore::new("typed-reads");
        let base = Object::Blob(Blob {
            data: b"external base".to_vec(),
        });
        let object = Object::Blob(Blob {
            data: b"derived value".to_vec(),
        });
        let base_id = base.id().unwrap();
        let id = object.id().unwrap();
        let base_bytes = mkit_core::serialize::serialize(&base).unwrap();
        let bytes = mkit_core::serialize::serialize(&object).unwrap();
        let mut writer = PackWriter::new_raw_only();
        writer.push_raw(base_id, &base_bytes).unwrap();
        let base_pack_bytes = writer.finish().unwrap();
        let base_pack = mkit_core::hash::hash(&base_pack_bytes);
        upload(&blobs, base_pack, &base_pack_bytes);
        seed_member(
            &store.inner,
            shards,
            &repo(),
            base_id,
            base_pack,
            u64::try_from(base_bytes.len()).unwrap(),
        );
        let mut writer = PackWriter::new();
        writer
            .push_delta(
                &base_id,
                &mkit_core::delta::encode(&base_bytes, &bytes).unwrap(),
            )
            .unwrap();
        let pack_bytes = writer.finish().unwrap();
        let pack = mkit_core::hash::hash(&pack_bytes);
        upload(&blobs, pack, &pack_bytes);
        seed_member(
            &store.inner,
            shards,
            &repo(),
            id,
            pack,
            u64::try_from(bytes.len()).unwrap(),
        );
        let row = index::IndexValue {
            frame_offset: 12,
            frame_length: u64::try_from(pack_bytes.len() - 12 - 32).unwrap(),
            wire_type: pack_bytes[12],
            decoded_size: u64::try_from(bytes.len()).unwrap(),
            chain_depth: 1,
            delta_base: Some(base_id),
        };
        put(
            &store.inner,
            &shards.object_index(&repo(), &id),
            keys::object_index(&repo().name, &id, &pack),
            codec::encode_object_index(&id, &row).unwrap(),
        );
        DeltaFixture {
            store,
            blobs,
            base: base_id,
            base_pack,
            id,
            pack,
            bytes,
        }
    }

    #[test]
    fn direct_typed_read_modes_gate_rows_and_preserve_external_base_denial() {
        for shards in maps() {
            for enabled in [false, true] {
                for blocked in 0..4 {
                    let fx = delta_fixture(shards.as_ref());
                    let reads = ReadAccess::new(
                        &fx.store,
                        shards.as_ref(),
                        RepoVisibility::Public,
                        enabled,
                    );
                    let limits = MemberReadLimits {
                        max_delta_depth: 32,
                        max_decode_bytes: 1024,
                    };
                    let before = block_on(reads.locate_object(&repo(), &fx.id))
                        .unwrap()
                        .unwrap();
                    assert!(!before.denied);
                    assert_eq!(
                        block_on(reads.read_member_canonical(&fx.blobs, &repo(), fx.id, limits))
                            .unwrap()
                            .unwrap()
                            .bytes
                            .as_ref(),
                        fx.bytes.as_slice()
                    );
                    let stopped = [fx.id, fx.pack, fx.base, fx.base_pack][blocked];
                    block_on(
                        crate::ContentIndex::new(crate::store::BorrowedStore(&fx.store.inner))
                            .block(
                                &crate::takedown::DenialCapability::for_test(),
                                &stopped,
                                &crate::store::BlockEntry::new("test stop", 1),
                                1,
                            ),
                    )
                    .unwrap();
                    *fx.store.denial_reads.lock().unwrap() = 0;
                    let member = block_on(reads.locate_object(&repo(), &fx.id))
                        .unwrap()
                        .unwrap();
                    let batch = block_on(reads.locate_objects(&repo(), &[fx.id, fx.id])).unwrap();
                    assert_eq!(batch, [Some(member), Some(member)]);
                    assert_eq!(member.denied, enabled && blocked < 2);
                    let canonical =
                        block_on(reads.read_member_canonical(&fx.blobs, &repo(), fx.id, limits));
                    if enabled {
                        assert!(canonical.is_err(), "external-base denial remains live");
                        assert!(*fx.store.denial_reads.lock().unwrap() > 0);
                    } else {
                        assert_eq!(member, before);
                        assert_eq!(
                            canonical.unwrap().unwrap().bytes.as_ref(),
                            fx.bytes.as_slice()
                        );
                        assert_eq!(*fx.store.denial_reads.lock().unwrap(), 0);
                    }
                }
            }
        }
    }
}
