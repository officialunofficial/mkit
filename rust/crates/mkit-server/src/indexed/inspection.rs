//! Bounded metadata for the complete launch-profile inspected set.
use std::collections::{BTreeMap, BTreeSet};

use mkit_core::hash::Hash;
use mkit_core::object::{EntryMode, Object, ObjectType};

use crate::ServerError;
use crate::store::{BlobBody, BlobKey, BlobStore, ByteRange, codec::TicketV1};
use futures::StreamExt as _;

/// Metadata kind; a blob used directly as a file takes precedence over a chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Plain file or surplus blob.
    Blob,
    /// ChunkedBlob manifest.
    ChunkedFile,
    /// Blob referenced only as a chunk.
    Chunk,
}

/// One inspected object's metadata, without its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectObject {
    /// Verified content identity.
    pub id: Hash,
    /// Canonical decoded object length.
    pub size: u64,
    /// File, manifest, or chunk.
    pub kind: Kind,
}

/// One sorted, deduplicated union of added and newly reachable file objects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectionSet {
    limit: usize,
    objects: BTreeMap<Hash, InspectObject>,
    files: BTreeSet<Hash>,
    chunks: BTreeSet<Hash>,
    added_entries: u64,
    added_ids: Option<BTreeSet<Hash>>,
    newly_reachable: u64,
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
            files: BTreeSet::new(),
            chunks: BTreeSet::new(),
            added_entries: 0,
            added_ids: None,
            newly_reachable: 0,
        }
    }

    /// Refuse a conservative entry-count bound before decoding/enumeration.
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

    /// Freeze added-pack identities before adding newly reachable objects.
    pub fn finish_added(&mut self) {
        self.added_ids = Some(self.objects.keys().copied().collect());
    }

    /// Record the role of an object that is already selected for inspection.
    pub fn role(&mut self, id: Hash, kind: Kind) {
        if self.contains(&id) {
            match kind {
                Kind::Blob => {
                    self.files.insert(id);
                }
                Kind::Chunk => {
                    self.chunks.insert(id);
                }
                Kind::ChunkedFile => {}
            }
        }
    }

    /// Whether the union already includes this object.
    #[must_use]
    pub fn contains(&self, id: &Hash) -> bool {
        self.objects.contains_key(id)
    }

    /// Insert metadata from a verified entry, ignoring non-file object types.
    ///
    /// # Errors
    /// Index-limit refusal or inconsistent immutable metadata.
    pub fn entry(&mut self, id: Hash, size: u64, object_type: u8) -> Result<(), ServerError> {
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
        if self
            .added_ids
            .as_ref()
            .is_some_and(|ids| !ids.contains(&id))
        {
            let next = self.newly_reachable.saturating_add(1);
            self.preflight(self.added_entries.saturating_add(next))?;
            self.newly_reachable = next;
        }
        if self.objects.len() >= self.limit {
            return Err(limit_error());
        }
        self.objects.insert(id, InspectObject { id, size, kind });
        Ok(())
    }

    /// Record file/chunk usage from an already decoded tree or manifest.
    ///
    /// # Errors
    /// Index-limit refusal for an excessive role-reference upper bound.
    pub fn roles(&mut self, object: &Object) -> Result<(), ServerError> {
        match object {
            Object::ChunkedBlob(manifest) => {
                for id in &manifest.chunks {
                    self.role(*id, Kind::Chunk);
                }
            }
            Object::Tree(tree) => {
                for entry in &tree.entries {
                    if entry.mode != EntryMode::Tree {
                        self.role(entry.object_hash, Kind::Blob);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Final metadata in stable object-id order, with file/chunk precedence.
    #[must_use]
    pub fn finalize(self) -> Vec<InspectObject> {
        self.objects
            .into_values()
            .map(|mut entry| {
                if entry.kind == Kind::Blob
                    && self.chunks.contains(&entry.id)
                    && !self.files.contains(&entry.id)
                {
                    entry.kind = Kind::Chunk;
                }
                entry
            })
            .collect()
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

/// Page existing first-occurrence frame rows, sharing the advance's call budget.
#[allow(clippy::too_many_arguments)]
pub(super) async fn scheduled_entries<B: BlobStore, S: crate::NamespaceStore>(
    blobs: &B,
    store: &S,
    shards: &dyn crate::pipeline::ShardMap,
    repo: &crate::RepoId,
    source: &crate::Partition,
    additions: &[Hash],
    cfg: super::IndexedConfig,
    limit: usize,
    added_count: u64,
    metrics: &dyn crate::telemetry::Metrics,
) -> Result<InspectionSet, ServerError> {
    use crate::store::{index::LocatedObject, keys};
    let failed = || ServerError::unavailable("object storage request failed");
    let mut set = InspectionSet::new(limit);
    set.reserve_added_count(added_count)?;
    let mut entries = 0_u64;
    let mut roles = Vec::new();
    let mut remaining = cfg.decode_budget;
    for pack in additions {
        let (start, end) = keys::verify_range(&repo.name, pack, Some(keys::VC_FRAME));
        let mut after = None;
        loop {
            let page = store
                .scan(source, &start, &end, after.as_ref(), 1000)
                .await
                .map_err(|_| failed())?;
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
                if found != repo.name || pack_id != *pack || sub != keys::VC_FRAME {
                    return Err(failed());
                }
                entries = entries.saturating_add(1);
                set.preflight(entries)?;
                let frame = super::checkpoint::decode_frame(&id, &raw).map_err(|_| failed())?;
                set.entry(id, frame.value.decoded_size, frame.object_type)?;
                if frame.object_type == ObjectType::Tree as u8
                    || frame.object_type == ObjectType::ChunkedBlob as u8
                {
                    roles.push((*pack, id, frame.value));
                }
            }
            match page.next {
                Some(next) => after = Some(next),
                None => break,
            }
        }
    }
    for (pack, id, value) in roles {
        let mut memo = super::resolve::MemberCache::with_work_budget(256);
        let mut visiting = BTreeSet::new();
        let (bytes, _) = super::resolve::member_object(
            blobs,
            store,
            shards,
            repo,
            id,
            LocatedObject { pack, value },
            cfg.max_delta_chain_depth,
            remaining.min(super::checkpoint::WINDOW_BYTES),
            &mut memo,
            &mut visiting,
            metrics,
        )
        .await
        .map_err(|e| match e {
            super::resolve::ResolveFailure::Other(error) => error,
            _ => limit_error(),
        })?;
        remaining = remaining
            .checked_sub(memo.retained_bytes())
            .ok_or_else(limit_error)?;
        let object = mkit_core::serialize::deserialize(&bytes).map_err(|_| failed())?;
        set.roles(&object)?;
    }
    set.finish_added();
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
    use mkit_core::object::{Blob, ChunkedBlob, Commit, Identity, Tree, TreeEntry};
    use mkit_core::pack::{DecodeLimits, NoExternalBases, PackWriter, decode_entries_with};
    use mkit_core::serialize::serialize;
    use mkit_core::sign::{KeyPair, sign_commit};
    use std::sync::Arc;

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
            (chunk.id().unwrap(), Kind::Chunk),
            (dual.id().unwrap(), Kind::Blob),
            (extra.id().unwrap(), Kind::Blob),
            (manifest.id().unwrap(), Kind::ChunkedFile),
        ];
        expected.sort_by_key(|e| e.0);
        (writer.finish().unwrap(), commit.id().unwrap(), expected)
    }

    #[test]
    fn native_and_worker_enumerate_surplus_manifests_chunks_dual_uses_and_duplicates() {
        let (pack, head, expected) = fixture();
        let repo = repo("inspection-union");
        let blobs = MemoryBlobStore::default();
        upload(&blobs, &pack);
        let clock = Arc::new(ManualClock::new(NOW));
        let store = MemoryKv::with_clock(clock.clone());
        let ticket = ticket(&repo, &pack, NOW as u64);
        let native = block_on(super::super::verify::verify_ticketed_inspected(
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
        .unwrap()
        .finalize();
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
        let mut batch = Batch::new();
        for (id, raw) in frames {
            batch = batch.put(
                keys::verify_row(&repo.name, &ticket.pack_id, keys::VC_FRAME, Some(&id)),
                raw,
            );
        }
        block_on(store.apply(&source(&repo), batch)).unwrap();
        let worker = block_on(scheduled_entries(
            &blobs,
            &store,
            &SinglePartition,
            &repo,
            &source(&repo),
            &[ticket.pack_id],
            super::super::IndexedConfig::default(),
            10,
            7,
            &NoopMetrics,
        ))
        .unwrap()
        .finalize();
        assert_eq!(native, worker);
        let mut job = super::super::checkpoint::VerifyJobV1::new(
            hash(&ticket.pack_id),
            NOW as u64,
            pack.len() as u64,
            4096,
        );
        job.kind = super::super::checkpoint::Kind::Pack;
        job.phase = super::super::checkpoint::Phase::Watch;
        job.entries = 7;
        job.in_pack_bytes = native.iter().map(|e| e.size).sum();
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
        let checked = block_on(super::super::scheduled::check_inspected(
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
        .unwrap()
        .finalize();
        assert_eq!(checked, native);
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
    fn conservative_added_count_survives_dedup_before_new_reachability() {
        let mut set = InspectionSet::new(4);
        set.reserve_added_count(4).unwrap();
        set.entry([1; 32], 11, ObjectType::Blob as u8).unwrap();
        set.entry([1; 32], 11, ObjectType::Blob as u8).unwrap();
        set.finish_added();
        assert!(set.entry([2; 32], 11, ObjectType::Blob as u8).is_err());
        assert_eq!(set.finalize().len(), 1);
    }

    #[test]
    fn worker_enumeration_resumes_frame_pages_within_the_shared_call_budget() {
        let repo = repo("inspection-pages");
        let store = MemoryKv::default();
        let pack = [9; 32];
        for first in (0_u64..1500).step_by(90) {
            let mut batch = Batch::new();
            for n in first..(first + 90).min(1500) {
                let bytes = serialize(&Object::Blob(Blob {
                    data: n.to_le_bytes().to_vec(),
                }))
                .unwrap();
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
        let budget = super::super::budget::SliceBudget::new(300);
        let bounded = super::super::budget::Budgeted::new(&store, &budget);
        let entries = block_on(scheduled_entries(
            &MemoryBlobStore::default(),
            &bounded,
            &SinglePartition,
            &repo,
            &source(&repo),
            &[pack],
            super::super::IndexedConfig::default(),
            1500,
            1500,
            &NoopMetrics,
        ))
        .unwrap()
        .finalize();
        assert_eq!(entries.len(), 1500);
        assert_eq!(budget.used(), 2);
        assert!(entries.windows(2).all(|w| w[0].id < w[1].id));
    }
}
