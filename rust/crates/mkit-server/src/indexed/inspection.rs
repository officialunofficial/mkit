//! Bounded, metadata-only enumeration of added-pack files for launch inspection.
use std::collections::BTreeMap;

use mkit_core::hash::Hash;
use mkit_core::object::ObjectType;

use crate::ServerError;
use crate::store::{BlobBody, BlobKey, BlobStore, ByteRange, codec::TicketV1};
use futures::StreamExt as _;

/// Launch inspection kinds come directly from verified object types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Any blob, including one used only as a chunk.
    Blob,
    /// A `ChunkedBlob` manifest.
    ChunkedFile,
}

/// One inspected object's metadata, without its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectObject {
    /// Verified content identity.
    pub id: Hash,
    /// Canonical decoded object length.
    pub size: u64,
    /// Blob or chunked file.
    pub kind: Kind,
}

/// The sorted, deduplicated file-typed entries of the advance's added packs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectionSet {
    limit: usize,
    objects: BTreeMap<Hash, InspectObject>,
    added_entries: u64,
    pending: Option<Added>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NativeEntry {
    pub id: Hash,
    pub size: u64,
    pub object_type: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Added {
    Native(Vec<NativeEntry>),
    Scheduled(crate::Partition, Vec<ScheduledPack>),
}

/// Request-local proof of the exact verified job accepted during ticket checking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ScheduledPack {
    pub pack: Hash,
    pub job: crate::Value,
    pub verification: crate::Value,
    pub decoded_bytes: u64,
}

/// The established bounded-index refusal; request size is never unavailability.
#[must_use]
pub fn limit_error() -> ServerError {
    ServerError::invalid_argument("object index limit exceeded")
}

impl InspectionSet {
    /// Create a whole-advance collector with its configured object limit.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            objects: BTreeMap::new(),
            added_entries: 0,
            pending: None,
        }
    }

    /// Refuse the conservative count before decoding or enumeration.
    ///
    /// # Errors
    /// The existing index-limit error if the bound exceeds the launch limit.
    pub fn preflight(&self, count: u64) -> Result<(), ServerError> {
        if count > self.limit as u64 {
            return Err(limit_error());
        }
        Ok(())
    }

    /// Reserve the conservative count of all added-pack entries.
    ///
    /// # Errors
    /// The existing index-limit refusal when the header/job bound is oversized.
    pub fn reserve_added_count(&mut self, count: u64) -> Result<(), ServerError> {
        self.preflight(count)?;
        self.added_entries = count;
        Ok(())
    }

    pub(super) fn defer_native(&mut self, entries: Vec<NativeEntry>) {
        self.pending = Some(Added::Native(entries));
    }

    pub(super) fn defer_scheduled(&mut self, packs: Vec<ScheduledPack>, source: crate::Partition) {
        self.pending = Some(Added::Scheduled(source, packs));
    }

    /// Collect added entries after header/job preflight, without reading bytes.
    ///
    /// # Errors
    /// Existing indexed storage, metadata decoding and bounded-enumeration refusals.
    pub async fn complete_added<S: crate::NamespaceStore>(
        &mut self,
        store: &S,
        repo: &crate::RepoId,
    ) -> Result<(), ServerError> {
        self.preflight(self.added_entries)?;
        match self.pending.take() {
            Some(Added::Native(entries)) => {
                for entry in entries {
                    self.entry(entry.id, entry.size, entry.object_type)?;
                }
            }
            Some(Added::Scheduled(source, packs)) => {
                let added =
                    scheduled_entries(store, repo, &source, &packs, self.limit, self.added_entries)
                        .await?;
                self.objects = added.objects;
            }
            None => {}
        }
        Ok(())
    }

    /// Insert verified metadata, ignoring non-file object types.
    ///
    /// # Errors
    /// Index-limit refusal or inconsistent immutable metadata.
    pub fn entry(&mut self, id: Hash, size: u64, object_type: u8) -> Result<(), ServerError> {
        if !(ObjectType::Blob as u8..=ObjectType::Tag as u8).contains(&object_type) {
            return Err(ServerError::unavailable(
                "verified object metadata inconsistency",
            ));
        }
        let kind = if object_type == ObjectType::Blob as u8 {
            Kind::Blob
        } else if object_type == ObjectType::ChunkedBlob as u8 {
            Kind::ChunkedFile
        } else {
            return Ok(());
        };
        if let Some(old) = self.objects.get(&id) {
            if old.size != size || old.kind != kind {
                return Err(ServerError::unavailable(
                    "verified object metadata inconsistency",
                ));
            }
            return Ok(());
        }
        if self.objects.len() >= self.limit {
            return Err(limit_error());
        }
        self.objects.insert(id, InspectObject { id, size, kind });
        Ok(())
    }

    /// Final metadata in stable object-id order.
    #[must_use]
    pub fn finalize(self) -> Vec<InspectObject> {
        self.objects.into_values().collect()
    }
}

/// Read only fixed-size headers before native whole-pack allocation/decoding.
pub(super) async fn preflight_native<B: BlobStore>(
    blobs: &B,
    tickets: &[TicketV1],
    limit: usize,
) -> Result<u64, ServerError> {
    let mut count = 0_u64;
    for ticket in tickets {
        let body = blobs
            .get(
                &BlobKey::pack(ticket.pack_id),
                Some(ByteRange {
                    start: 0,
                    end_inclusive: 11,
                }),
            )
            .await
            .map_err(|_| ServerError::unavailable("object storage request failed"))?
            .ok_or_else(|| ServerError::unavailable("object storage request failed"))?;
        let mut prefix = Vec::with_capacity(12);
        match body {
            BlobBody::Bytes(bytes) => {
                if bytes.len() != 12 {
                    return Err(ServerError::invalid_argument("object hash mismatch"));
                }
                prefix.extend_from_slice(&bytes);
            }
            BlobBody::Stream { len, mut stream } => {
                if len != 12 {
                    return Err(ServerError::unavailable("object storage request failed"));
                }
                while let Some(bytes) = stream.next().await {
                    let bytes = bytes
                        .map_err(|_| ServerError::unavailable("object storage request failed"))?;
                    if prefix.len().saturating_add(bytes.len()) > 12 {
                        return Err(ServerError::unavailable("object storage request failed"));
                    }
                    prefix.extend_from_slice(&bytes);
                }
            }
        }
        if prefix.len() != 12 {
            return Err(ServerError::invalid_argument("object hash mismatch"));
        }
        if super::classify::classify(&prefix)? == super::classify::UploadType::Pack {
            let entries = u32::from_le_bytes(prefix[8..12].try_into().map_err(|_| limit_error())?);
            count = count.saturating_add(u64::from(entries));
            if count > limit as u64 {
                return Err(limit_error());
            }
        }
    }
    Ok(count)
}

fn metadata_error(error: &crate::StoreError) -> ServerError {
    if super::budget::is_exhausted(error) {
        limit_error()
    } else {
        ServerError::unavailable("object storage request failed")
    }
}

async fn guard_jobs<S: crate::NamespaceStore>(
    store: &S,
    repo: &crate::RepoId,
    source: &crate::Partition,
    packs: &[ScheduledPack],
) -> Result<(), ServerError> {
    if packs.is_empty() {
        return Ok(());
    }
    let keys = packs
        .iter()
        .flat_map(|pack| {
            [
                crate::store::keys::verify_job(&repo.name, &pack.pack),
                crate::store::keys::verification(&repo.name, &pack.pack),
            ]
        })
        .collect::<Vec<_>>();
    let current = store
        .get_many(source, &keys)
        .await
        .map_err(|error| metadata_error(&error))?;
    if current.len() != keys.len() {
        return Err(ServerError::unavailable("object storage request failed"));
    }
    if packs.iter().enumerate().any(|(i, pack)| {
        current[2 * i].as_ref() != Some(&pack.job)
            || current[2 * i + 1].as_ref() != Some(&pack.verification)
    }) {
        return Err(super::pending(1000));
    }
    Ok(())
}

/// Page verified first-occurrence frame rows, without reference scans or R2 reads.
pub(super) async fn scheduled_entries<S: crate::NamespaceStore>(
    store: &S,
    repo: &crate::RepoId,
    source: &crate::Partition,
    additions: &[ScheduledPack],
    limit: usize,
    added_count: u64,
) -> Result<InspectionSet, ServerError> {
    use crate::store::keys;
    let failed = || ServerError::unavailable("object storage request failed");
    let mut set = InspectionSet::new(limit);
    set.reserve_added_count(added_count)?;
    guard_jobs(store, repo, source, additions).await?;
    let mut entries = 0_u64;
    for pack in additions {
        let mut decoded_bytes = 0_u64;
        let (start, end) = keys::verify_range(&repo.name, &pack.pack, Some(keys::VC_FRAME));
        let mut after = None;
        loop {
            let page = store
                .scan(source, &start, &end, after.as_ref(), 1000)
                .await
                .map_err(|error| metadata_error(&error))?;
            if page.entries.len() > 1000 {
                return Err(failed());
            }
            for (key, raw) in page.entries {
                let Some(keys::ParsedKey::VerifyCursor {
                    repo: found,
                    pack_id,
                    sub,
                    id: Some(id),
                }) = keys::parse(&key)
                else {
                    return Err(failed());
                };
                if found != repo.name || pack_id != pack.pack || sub != keys::VC_FRAME {
                    return Err(failed());
                }
                entries = entries.saturating_add(1);
                if entries > added_count {
                    return Err(failed());
                }
                let frame = super::checkpoint::decode_frame(&id, &raw).map_err(|_| failed())?;
                decoded_bytes = decoded_bytes
                    .checked_add(frame.value.decoded_size)
                    .ok_or_else(failed)?;
                set.entry(id, frame.value.decoded_size, frame.object_type)?;
            }
            match page.next {
                Some(next) if after.as_ref() != Some(&next) => after = Some(next),
                Some(_) => return Err(failed()),
                None => break,
            }
        }
        if decoded_bytes != pack.decoded_bytes {
            return Err(super::pending(1000));
        }
    }
    guard_jobs(store, repo, source, additions).await?;
    Ok(set)
}

#[cfg(all(test, feature = "memory"))]
mod tests {
    use super::*;
    use crate::indexed::checkpoint::{FrameRow, encode_frame};
    use crate::indexed::tests::{NOW, repo, source, ticket, upload};
    use crate::memory::{MemoryBlobStore, MemoryKv};
    use crate::pipeline::SinglePartition;
    use crate::rt::ManualClock;
    use crate::store::{Batch, NamespaceStore, index::IndexValue, keys};
    use crate::telemetry::NoopMetrics;
    use futures_executor::block_on;
    use mkit_core::hash::hash;
    use mkit_core::object::{
        Blob, ChunkedBlob, Commit, EntryMode, Identity, Object, Tree, TreeEntry,
    };
    use mkit_core::pack::{DecodeLimits, NoExternalBases, PackWriter, decode_entries_with};
    use mkit_core::serialize::serialize;
    use mkit_core::sign::{KeyPair, sign_commit};
    use std::sync::Arc;

    fn verified_pack(
        store: &MemoryKv,
        repo: &crate::RepoId,
        pack: Hash,
        entries: u64,
        decoded_bytes: u64,
    ) -> ScheduledPack {
        let mut job = super::super::checkpoint::VerifyJobV1::new(hash(&pack), NOW as u64, 1, 4096);
        job.kind = super::super::checkpoint::Kind::Pack;
        job.phase = super::super::checkpoint::Phase::Watch;
        job.entries = entries;
        job.in_pack_bytes = decoded_bytes;
        let snapshot = ScheduledPack {
            pack,
            job: super::super::checkpoint::encode_job(&job),
            verification: super::super::state::encode(
                &super::super::state::VerificationV1::Verified {
                    pack_len: 1,
                    verified_at_ms: NOW as u64,
                },
            ),
            decoded_bytes,
        };
        block_on(
            store.apply(
                &source(repo),
                Batch::new()
                    .put(keys::verify_job(&repo.name, &pack), snapshot.job.clone())
                    .put(
                        keys::verification(&repo.name, &pack),
                        snapshot.verification.clone(),
                    ),
            ),
        )
        .expect("seed deterministic verified-pack metadata");
        snapshot
    }

    #[allow(clippy::unwrap_used)] // Deterministic valid objects used only by these tests.
    fn fixture() -> (Vec<u8>, Hash, Vec<(Hash, Kind)>) {
        let chunk = Object::Blob(Blob {
            data: b"one".to_vec(),
        });
        let dual = Object::Blob(Blob {
            data: b"two".to_vec(),
        });
        let extra = Object::Blob(Blob {
            data: b"surplus".to_vec(),
        });
        let manifest = Object::ChunkedBlob(ChunkedBlob {
            total_size: 6,
            chunk_size: 0,
            chunks: vec![chunk.id().unwrap(), dual.id().unwrap()],
        });
        let tree = Object::Tree(Tree {
            entries: vec![
                TreeEntry {
                    name: b"direct".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: dual.id().unwrap(),
                },
                TreeEntry {
                    name: b"manifest".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: manifest.id().unwrap(),
                },
            ],
        });
        let key = KeyPair::from_seed([7; 32]);
        let mut commit = Commit::new_unannotated(
            tree.id().unwrap(),
            vec![],
            Identity::ed25519(key.public.0),
            key.public.0,
            b"inspection".to_vec(),
            42,
            [0; 64],
        );
        commit.signature = sign_commit(&commit, &key).unwrap().0;
        let commit = Object::Commit(commit);
        let mut writer = PackWriter::new_raw_only();
        for object in [&chunk, &dual, &extra, &manifest, &tree, &commit, &chunk] {
            writer
                .push_raw(object.id().unwrap(), &serialize(object).unwrap())
                .unwrap();
        }
        let mut expected = vec![
            (chunk.id().unwrap(), Kind::Blob),
            (dual.id().unwrap(), Kind::Blob),
            (extra.id().unwrap(), Kind::Blob),
            (manifest.id().unwrap(), Kind::ChunkedFile),
        ];
        expected.sort_by_key(|e| e.0);
        (writer.finish().unwrap(), commit.id().unwrap(), expected)
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One native/scheduled parity scenario and its preflight failure.
    fn native_and_worker_enumerate_surplus_manifests_chunks_dual_uses_and_duplicates() {
        let (pack, head, expected) = fixture();
        let repo = repo("inspection-union");
        let blobs = MemoryBlobStore::default();
        upload(&blobs, &pack);
        let clock = Arc::new(ManualClock::new(NOW));
        let store = MemoryKv::with_clock(clock.clone());
        let ticket = ticket(&repo, &pack, NOW as u64);
        let mut native = block_on(super::super::verify::verify_ticketed_inspected(
            &blobs,
            &store,
            &SinglePartition,
            &repo,
            &source(&repo),
            std::slice::from_ref(&ticket),
            &[hash(&ticket.pack_id)],
            head,
            super::super::IndexedConfig::default(),
            clock.as_ref(),
            &NoopMetrics,
            10,
        ))
        .unwrap()
        .inspection
        .unwrap();
        assert!(native.objects.is_empty());
        block_on(native.complete_added(&store, &repo)).unwrap();
        let native = native.finalize();
        assert_eq!(
            native.iter().map(|e| (e.id, e.kind)).collect::<Vec<_>>(),
            expected
        );
        let mut frames = BTreeMap::new();
        decode_entries_with(
            &pack,
            &mut NoExternalBases,
            DecodeLimits::default(),
            |entry| {
                let row = FrameRow {
                    object_type: entry.object.object_type() as u8,
                    external: None,
                    value: IndexValue {
                        frame_offset: entry.frame_offset,
                        frame_length: entry.frame_length,
                        wire_type: entry.wire_type,
                        decoded_size: entry.bytes.len() as u64,
                        chain_depth: 0,
                        delta_base: None,
                    },
                };
                frames
                    .entry(entry.id)
                    .or_insert_with(|| encode_frame(&entry.id, &row).unwrap());
                Ok(())
            },
        )
        .unwrap();
        let in_pack_bytes = frames
            .iter()
            .map(|(id, raw)| {
                super::super::checkpoint::decode_frame(id, raw)
                    .unwrap()
                    .value
                    .decoded_size
            })
            .sum();
        let mut batch = Batch::new();
        for (id, raw) in frames {
            batch = batch.put(
                keys::verify_row(&repo.name, &ticket.pack_id, keys::VC_FRAME, Some(&id)),
                raw,
            );
        }
        block_on(store.apply(&source(&repo), batch)).unwrap();
        let mut job = super::super::checkpoint::VerifyJobV1::new(
            hash(&ticket.pack_id),
            NOW as u64,
            pack.len() as u64,
            4096,
        );
        job.kind = super::super::checkpoint::Kind::Pack;
        job.phase = super::super::checkpoint::Phase::Watch;
        job.entries = 7;
        job.in_pack_bytes = in_pack_bytes;
        let ready = Batch::new()
            .put(
                keys::verify_job(&repo.name, &ticket.pack_id),
                super::super::checkpoint::encode_job(&job),
            )
            .put(
                keys::verification(&repo.name, &ticket.pack_id),
                super::super::state::encode(&super::super::state::VerificationV1::Verified {
                    pack_len: pack.len() as u64,
                    verified_at_ms: NOW as u64,
                }),
            );
        block_on(store.apply(&source(&repo), ready)).unwrap();
        let accepted = ScheduledPack {
            pack: ticket.pack_id,
            job: super::super::checkpoint::encode_job(&job),
            verification: super::super::state::encode(
                &super::super::state::VerificationV1::Verified {
                    pack_len: pack.len() as u64,
                    verified_at_ms: NOW as u64,
                },
            ),
            decoded_bytes: job.in_pack_bytes,
        };
        let worker = block_on(scheduled_entries(
            &store,
            &repo,
            &source(&repo),
            &[accepted],
            10,
            7,
        ))
        .unwrap()
        .finalize();
        assert_eq!(native, worker);
        let mut checked = block_on(super::super::scheduled::check_inspected(
            &blobs,
            &store,
            &SinglePartition,
            &repo,
            &source(&repo),
            std::slice::from_ref(&ticket),
            &[job.ticket_id],
            head,
            super::super::IndexedConfig::default(),
            clock.as_ref(),
            &NoopMetrics,
            10,
        ))
        .unwrap()
        .inspection
        .unwrap();
        assert!(checked.objects.is_empty());
        block_on(checked.complete_added(&store, &repo)).unwrap();
        assert_eq!(checked.finalize(), native);
        let error = block_on(super::super::scheduled::check_inspected(
            &blobs,
            &store,
            &SinglePartition,
            &repo,
            &source(&repo),
            &[ticket],
            &[job.ticket_id],
            head,
            super::super::IndexedConfig::default(),
            clock.as_ref(),
            &NoopMetrics,
            6,
        ))
        .unwrap_err();
        assert_eq!(error.public_message(), "object index limit exceeded");
    }

    #[test]
    fn oversize_native_header_refuses_before_verification_writes() {
        let (pack, head, _) = fixture();
        let repo = repo("inspection-size");
        let blobs = MemoryBlobStore::default();
        upload(&blobs, &pack);
        let clock = Arc::new(ManualClock::new(NOW));
        let store = MemoryKv::with_clock(clock.clone());
        let ticket = ticket(&repo, &pack, NOW as u64);
        let error = block_on(super::super::verify::verify_ticketed_inspected(
            &blobs,
            &store,
            &SinglePartition,
            &repo,
            &source(&repo),
            &[ticket],
            &[[1; 32]],
            head,
            super::super::IndexedConfig::default(),
            clock.as_ref(),
            &NoopMetrics,
            6,
        ))
        .unwrap_err();
        assert_eq!(error.code(), crate::Code::InvalidArgument);
        assert_eq!(error.public_message(), "object index limit exceeded");
        assert_eq!(block_on(store.stats(&source(&repo))).unwrap().keys, Some(0));
    }

    #[test]
    fn frame_scan_budget_exhaustion_is_an_index_limit_refusal() {
        let repo = repo("inspection-scan-budget");
        let store = MemoryKv::default();
        let accepted = verified_pack(&store, &repo, [1; 32], 1, 11);
        let budget = super::super::budget::SliceBudget::new(1);
        let bounded = super::super::budget::Budgeted::new(&store, &budget);
        let error = block_on(scheduled_entries(
            &bounded,
            &repo,
            &source(&repo),
            &[accepted],
            10_000,
            1,
        ))
        .unwrap_err();
        assert_eq!(error.code(), crate::Code::InvalidArgument);
        assert_eq!(error.public_message(), "object index limit exceeded");
        assert_eq!(budget.used(), 1);
    }

    #[test]
    fn conservative_added_count_is_independent_of_deduplication() {
        let mut set = InspectionSet::new(4);
        set.reserve_added_count(4).unwrap();
        set.entry([1; 32], 11, ObjectType::Blob as u8).unwrap();
        set.entry([1; 32], 11, ObjectType::Blob as u8).unwrap();
        assert!(set.reserve_added_count(5).is_err());
        assert_eq!(set.finalize().len(), 1);
    }

    #[test]
    fn unknown_checkpoint_object_types_fail_closed() {
        let mut set = InspectionSet::new(4);
        for tag in [0, 8, 255] {
            assert_eq!(
                set.entry([tag; 32], 11, tag).unwrap_err().code(),
                crate::Code::Unavailable
            );
        }
        assert!(set.finalize().is_empty());
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One real 400-entry pack compares native and Worker enumeration.
    fn small_valid_manifest_pack_accepts_with_one_scan_two_guards_and_native_parity() {
        let repo = repo("manifest-budget-reproduction");
        let mut writer = PackWriter::new_raw_only();
        for n in 0_u8..200 {
            let blob = Object::Blob(Blob { data: vec![n] });
            let manifest = Object::ChunkedBlob(ChunkedBlob {
                total_size: 1,
                chunk_size: 0,
                chunks: vec![blob.id().unwrap()],
            });
            for object in [&blob, &manifest] {
                writer
                    .push_raw(object.id().unwrap(), &serialize(object).unwrap())
                    .unwrap();
            }
        }
        let pack = writer.finish().unwrap();
        let pack_id = hash(&pack);
        let blobs = MemoryBlobStore::default();
        upload(&blobs, &pack);
        let store = MemoryKv::default();
        let mut frames = Vec::new();
        let mut entries = Vec::new();
        decode_entries_with(
            &pack,
            &mut NoExternalBases,
            DecodeLimits::default(),
            |entry| {
                let object_type = entry.object.object_type() as u8;
                let row = FrameRow {
                    object_type,
                    external: None,
                    value: IndexValue {
                        frame_offset: entry.frame_offset,
                        frame_length: entry.frame_length,
                        wire_type: entry.wire_type,
                        decoded_size: entry.bytes.len() as u64,
                        chain_depth: 0,
                        delta_base: None,
                    },
                };
                frames.push((
                    keys::verify_row(&repo.name, &pack_id, keys::VC_FRAME, Some(&entry.id)),
                    encode_frame(&entry.id, &row).unwrap(),
                ));
                entries.push(NativeEntry {
                    id: entry.id,
                    size: entry.bytes.len() as u64,
                    object_type,
                });
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(entries.len(), 400);
        for rows in frames.chunks(90) {
            let batch = rows.iter().fold(Batch::new(), |batch, (key, raw)| {
                batch.put(key.clone(), raw.clone())
            });
            block_on(store.apply(&source(&repo), batch)).unwrap();
        }
        let mut native = InspectionSet::new(10_000);
        native.reserve_added_count(400).unwrap();
        native.defer_native(entries);
        block_on(native.complete_added(&store, &repo)).unwrap();
        let native = native.finalize();
        assert_eq!(native.len(), 400);
        let metadata = super::super::budget::SliceBudget::new(256);
        let mut worker = InspectionSet::new(10_000);
        worker.reserve_added_count(400).unwrap();
        let accepted = verified_pack(
            &store,
            &repo,
            pack_id,
            400,
            native.iter().map(|e| e.size).sum(),
        );
        worker.defer_scheduled(vec![accepted], source(&repo));
        block_on(worker.complete_added(
            &super::super::budget::Budgeted::new(&store, &metadata),
            &repo,
        ))
        .unwrap();
        assert_eq!(worker.finalize(), native);
        assert_eq!(metadata.used(), 3);
    }

    #[test]
    fn worker_enumeration_resumes_frame_pages_within_the_shared_call_budget() {
        let repo = repo("inspection-pages");
        let store = MemoryKv::default();
        let pack = [9; 32];
        let mut decoded_bytes = 0_u64;
        for first in (0_u64..1500).step_by(90) {
            let mut batch = Batch::new();
            for n in first..(first + 90).min(1500) {
                let bytes = serialize(&Object::Blob(Blob {
                    data: n.to_le_bytes().to_vec(),
                }))
                .unwrap();
                decoded_bytes += bytes.len() as u64;
                let id = hash(&bytes);
                let frame = FrameRow {
                    object_type: ObjectType::Blob as u8,
                    external: None,
                    value: IndexValue {
                        frame_offset: 12 + n * 23,
                        frame_length: 23,
                        wire_type: 0,
                        decoded_size: bytes.len() as u64,
                        chain_depth: 0,
                        delta_base: None,
                    },
                };
                batch = batch.put(
                    keys::verify_row(&repo.name, &pack, keys::VC_FRAME, Some(&id)),
                    encode_frame(&id, &frame).unwrap(),
                );
            }
            block_on(store.apply(&source(&repo), batch)).unwrap();
        }
        let accepted = verified_pack(&store, &repo, pack, 1500, decoded_bytes);
        let budget = super::super::budget::SliceBudget::new(256);
        let bounded = super::super::budget::Budgeted::new(&store, &budget);
        let entries = block_on(scheduled_entries(
            &bounded,
            &repo,
            &source(&repo),
            &[accepted],
            1500,
            1500,
        ))
        .unwrap()
        .finalize();
        assert_eq!(entries.len(), 1500);
        assert_eq!(budget.used(), 4);
        assert!(entries.windows(2).all(|w| w[0].id < w[1].id));
    }
    #[test]
    #[allow(clippy::too_many_lines)] // Worst-case page rounding across seven consumed packs.
    fn cap_across_seven_packs_uses_sixteen_scans_two_guards_and_matches_native() {
        let repo = repo("inspection-seven-pack-cap");
        let store = MemoryKv::default();
        let counts = [1001_u64, 1001, 1001, 1001, 1001, 1001, 3994];
        let mut packs = Vec::new();
        let mut entries = Vec::new();
        let mut sequence = 0_u64;
        for (pack_number, count) in counts.into_iter().enumerate() {
            let pack = [u8::try_from(pack_number + 1).unwrap(); 32];
            let mut decoded_bytes = 0_u64;
            for first in (0..count).step_by(90) {
                let mut batch = Batch::new();
                for n in first..(first + 90).min(count) {
                    let bytes = serialize(&Object::Blob(Blob {
                        data: sequence.to_le_bytes().to_vec(),
                    }))
                    .unwrap();
                    sequence += 1;
                    decoded_bytes += bytes.len() as u64;
                    let id = hash(&bytes);
                    let row = FrameRow {
                        object_type: ObjectType::Blob as u8,
                        external: None,
                        value: IndexValue {
                            frame_offset: 12 + n * 23,
                            frame_length: 23,
                            wire_type: 0,
                            decoded_size: bytes.len() as u64,
                            chain_depth: 0,
                            delta_base: None,
                        },
                    };
                    entries.push(NativeEntry {
                        id,
                        size: bytes.len() as u64,
                        object_type: row.object_type,
                    });
                    batch = batch.put(
                        keys::verify_row(&repo.name, &pack, keys::VC_FRAME, Some(&id)),
                        encode_frame(&id, &row).unwrap(),
                    );
                }
                block_on(store.apply(&source(&repo), batch)).unwrap();
            }
            packs.push(verified_pack(&store, &repo, pack, count, decoded_bytes));
        }
        assert_eq!(sequence, 10_000);
        let metadata = super::super::budget::SliceBudget::new(18);
        let bounded_store = super::super::budget::Budgeted::new(&store, &metadata);
        let mut native = InspectionSet::new(10_000);
        native.reserve_added_count(10_000).unwrap();
        native.defer_native(entries);
        block_on(native.complete_added(&bounded_store, &repo)).unwrap();
        assert_eq!(metadata.used(), 0);
        let mut worker = InspectionSet::new(10_000);
        worker.reserve_added_count(10_000).unwrap();
        worker.defer_scheduled(packs, source(&repo));
        block_on(worker.complete_added(&bounded_store, &repo)).unwrap();
        let native = native.finalize();
        assert_eq!(native.len(), 10_000);
        assert_eq!(worker.finalize(), native);
        assert_eq!(metadata.used(), 18);
    }
    #[test]
    fn missing_verified_frames_are_pending_before_inspection() {
        let repo = repo("inspection-missing-frames");
        let store = MemoryKv::default();
        let pack = [7; 32];
        let accepted = verified_pack(&store, &repo, pack, 1, 11);
        let mut worker = InspectionSet::new(10_000);
        worker.reserve_added_count(1).unwrap();
        worker.defer_scheduled(vec![accepted], source(&repo));
        let error = block_on(worker.complete_added(&store, &repo)).unwrap_err();
        assert_eq!(error.public_message(), "pack verification pending");
    }
    struct ReplaceAfterScan<'a> {
        inner: &'a MemoryKv,
        job_key: crate::Key,
        replacement: crate::Value,
    }
    impl NamespaceStore for ReplaceAfterScan<'_> {
        fn capabilities(&self) -> crate::StoreCapabilities {
            self.inner.capabilities()
        }
        async fn get(
            &self,
            p: &crate::Partition,
            key: &crate::Key,
        ) -> Result<Option<crate::Value>, crate::StoreError> {
            self.inner.get(p, key).await
        }
        async fn get_many(
            &self,
            p: &crate::Partition,
            keys: &[crate::Key],
        ) -> Result<Vec<Option<crate::Value>>, crate::StoreError> {
            self.inner.get_many(p, keys).await
        }
        async fn scan(
            &self,
            p: &crate::Partition,
            start: &crate::Key,
            end: &crate::Key,
            after: Option<&crate::store::Cursor>,
            limit: u32,
        ) -> Result<crate::store::ScanPage, crate::StoreError> {
            let page = self.inner.scan(p, start, end, after, limit).await?;
            self.inner
                .apply(
                    p,
                    Batch::new().put(self.job_key.clone(), self.replacement.clone()),
                )
                .await?;
            Ok(page)
        }
        async fn apply(
            &self,
            p: &crate::Partition,
            batch: Batch,
        ) -> Result<crate::BatchOutcome, crate::StoreError> {
            self.inner.apply(p, batch).await
        }
        async fn stats(
            &self,
            p: &crate::Partition,
        ) -> Result<crate::PartitionStats, crate::StoreError> {
            self.inner.stats(p).await
        }
        async fn probe(&self) -> Result<(), crate::StoreError> {
            self.inner.probe().await
        }
    }

    #[test]
    fn replacement_verification_job_is_pending_before_and_during_enumeration() {
        for during_scan in [false, true] {
            let repo = repo("inspection-replaced-job");
            let store = MemoryKv::default();
            let pack = [7; 32];
            let accepted = verified_pack(&store, &repo, pack, 1, 11);
            let frame = FrameRow {
                object_type: ObjectType::Blob as u8,
                external: None,
                value: IndexValue {
                    frame_offset: 12,
                    frame_length: 23,
                    wire_type: 0,
                    decoded_size: 11,
                    chain_depth: 0,
                    delta_base: None,
                },
            };
            block_on(store.apply(
                &source(&repo),
                Batch::new().put(
                    keys::verify_row(&repo.name, &pack, keys::VC_FRAME, Some(&[9; 32])),
                    encode_frame(&[9; 32], &frame).unwrap(),
                ),
            ))
            .unwrap();
            let mut replacement = super::super::checkpoint::decode_job(&accepted.job).unwrap();
            replacement.ticket_id = [99; 32];
            replacement.phase = super::super::checkpoint::Phase::Decode;
            let replacement = super::super::checkpoint::encode_job(&replacement);
            let job_key = keys::verify_job(&repo.name, &pack);
            let budget = super::super::budget::SliceBudget::new(3);
            let mut worker = InspectionSet::new(10_000);
            worker.reserve_added_count(1).unwrap();
            worker.defer_scheduled(vec![accepted], source(&repo));
            let error =
                if during_scan {
                    let racing = ReplaceAfterScan {
                        inner: &store,
                        job_key,
                        replacement,
                    };
                    block_on(worker.complete_added(
                        &super::super::budget::Budgeted::new(&racing, &budget),
                        &repo,
                    ))
                    .unwrap_err()
                } else {
                    block_on(store.apply(&source(&repo), Batch::new().put(job_key, replacement)))
                        .unwrap();
                    block_on(worker.complete_added(
                        &super::super::budget::Budgeted::new(&store, &budget),
                        &repo,
                    ))
                    .unwrap_err()
                };
            assert_eq!(error.public_message(), "pack verification pending");
            assert_eq!(budget.used(), if during_scan { 3 } else { 1 });
        }
    }
}
