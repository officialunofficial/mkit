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
    /// `ChunkedBlob` manifest.
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
    added_packs: Vec<Hash>,
    pending: Option<Added>,
    newly_reachable: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NativeEntry {
    pub id: Hash,
    pub size: u64,
    pub object_type: u8,
    pub roles: Option<Object>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Added {
    Native(Vec<NativeEntry>),
    Scheduled(crate::Partition),
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
            added_packs: Vec::new(),
            pending: None,
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

    pub(super) fn defer_native(&mut self, packs: Vec<Hash>, entries: Vec<NativeEntry>) {
        self.added_packs = packs;
        self.pending = Some(Added::Native(entries));
    }

    pub(super) fn defer_scheduled(&mut self, packs: Vec<Hash>, source: crate::Partition) {
        self.added_packs = packs;
        self.pending = Some(Added::Scheduled(source));
    }

    /// Count a distinct newly reachable file outside added packs before collection.
    ///
    /// # Errors
    /// The established conservative whole-advance index-limit refusal.
    pub(super) fn reachable_entry(
        &mut self,
        id: Hash,
        size: u64,
        object_type: u8,
    ) -> Result<(), ServerError> {
        if !self.objects.contains_key(&id) {
            let next = self.newly_reachable.saturating_add(1);
            self.preflight(self.added_entries.saturating_add(next))?;
            self.newly_reachable = next;
        }
        self.entry(id, size, object_type)
    }

    pub(super) async fn in_added<S: crate::NamespaceStore>(
        &self,
        store: &S,
        shards: &dyn crate::pipeline::ShardMap,
        repo: &crate::RepoId,
        id: Hash,
        located_pack: Hash,
    ) -> Result<bool, ServerError> {
        use crate::store::{codec, keys};
        if self.added_packs.contains(&located_pack) {
            return Ok(true);
        }
        if self.added_packs.is_empty() {
            return Ok(false);
        }
        let keys: Vec<_> = self
            .added_packs
            .iter()
            .map(|pack| keys::object_index(&repo.name, &id, pack))
            .collect();
        let rows = store
            .get_many(&shards.object_index(repo, &id), &keys)
            .await
            .map_err(|_| ServerError::unavailable("object storage request failed"))?;
        if rows.len() != keys.len() {
            return Err(ServerError::unavailable("object storage request failed"));
        }
        let mut found = false;
        for raw in rows.into_iter().flatten() {
            codec::decode_object_index(&id, &raw)
                .map_err(|_| ServerError::unavailable("object storage request failed"))?;
            found = true;
        }
        Ok(found)
    }

    /// Enumerate added entries only after the combined conservative preflight.
    ///
    /// # Errors
    /// Existing indexed storage, decoding and bounded-enumeration refusals.
    #[allow(clippy::too_many_arguments)]
    pub async fn complete_added<B: BlobStore, S: crate::NamespaceStore>(
        &mut self,
        blobs: &B,
        store: &S,
        shards: &dyn crate::pipeline::ShardMap,
        repo: &crate::RepoId,
        cfg: super::IndexedConfig,
        metrics: &dyn crate::telemetry::Metrics,
    ) -> Result<(), ServerError> {
        self.preflight(self.added_entries.saturating_add(self.newly_reachable))?;
        match self.pending.take() {
            Some(Added::Native(entries)) => {
                for entry in &entries {
                    self.entry(entry.id, entry.size, entry.object_type)?;
                }
                for entry in entries {
                    if let Some(object) = entry.roles {
                        self.roles(&object);
                    }
                }
            }
            Some(Added::Scheduled(source)) => {
                let added = scheduled_entries(
                    blobs,
                    store,
                    shards,
                    repo,
                    &source,
                    &self.added_packs,
                    cfg,
                    self.limit,
                    self.added_entries,
                    Some(self),
                    metrics,
                )
                .await?;
                for entry in added.objects.into_values() {
                    self.entry(
                        entry.id,
                        entry.size,
                        match entry.kind {
                            Kind::ChunkedFile => ObjectType::ChunkedBlob as u8,
                            _ => ObjectType::Blob as u8,
                        },
                    )?;
                }
                self.files.extend(added.files);
                self.chunks.extend(added.chunks);
            }
            None => {}
        }
        Ok(())
    }

    /// Record a reachable role, including added objects collected after preflight.
    pub fn role(&mut self, id: Hash, kind: Kind) {
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

    /// Record file/chunk usage from an already decoded tree or manifest.
    pub fn roles(&mut self, object: &Object) {
        match object {
            Object::ChunkedBlob(manifest) => {
                for id in &manifest.chunks {
                    if self.contains(id) {
                        self.role(*id, Kind::Chunk);
                    }
                }
            }
            Object::Tree(tree) => {
                for entry in &tree.entries {
                    if entry.mode != EntryMode::Tree && self.contains(&entry.object_hash) {
                        self.role(entry.object_hash, Kind::Blob);
                    }
                }
            }
            _ => {}
        }
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
    existing: Option<&InspectionSet>,
    metrics: &dyn crate::telemetry::Metrics,
) -> Result<InspectionSet, ServerError> {
    use crate::store::{index::LocatedObject, keys};
    let failed = || ServerError::unavailable("object storage request failed");
    let mut set = InspectionSet::new(limit);
    if let Some(existing) = existing {
        // Include outside-pack candidates when surplus trees/manifests assign roles.
        set.objects.clone_from(&existing.objects);
    }
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
        set.roles(&object);
    }
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
            (chunk.id().unwrap(), Kind::Chunk),
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
        block_on(native.complete_added(
            &blobs,
            &store,
            &SinglePartition,
            &repo,
            super::super::IndexedConfig::default(),
            &NoopMetrics,
        ))
        .unwrap();
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
            None,
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
        block_on(checked.complete_added(
            &blobs,
            &store,
            &SinglePartition,
            &repo,
            super::super::IndexedConfig::default(),
            &NoopMetrics,
        ))
        .unwrap();
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
    fn conservative_added_count_survives_dedup_before_new_reachability() {
        let mut set = InspectionSet::new(4);
        set.reserve_added_count(4).unwrap();
        set.entry([1; 32], 11, ObjectType::Blob as u8).unwrap();
        set.entry([1; 32], 11, ObjectType::Blob as u8).unwrap();
        assert!(
            set.reachable_entry([2; 32], 11, ObjectType::Blob as u8)
                .is_err()
        );
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
    fn worker_surplus_roles_include_newly_reachable_objects_outside_added_packs() {
        let repo = repo("outside-surplus-roles");
        let id = [8; 32];
        let objects = [
            Object::Tree(Tree {
                entries: vec![TreeEntry {
                    name: b"file".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: id,
                }],
            }),
            Object::ChunkedBlob(ChunkedBlob {
                total_size: 11,
                chunk_size: 0,
                chunks: vec![id],
            }),
        ];
        let mut writer = PackWriter::new_raw_only();
        for object in &objects {
            writer
                .push_raw(object.id().unwrap(), &serialize(object).unwrap())
                .unwrap();
        }
        let pack = writer.finish().unwrap();
        let pack_id = hash(&pack);
        let blobs = MemoryBlobStore::default();
        upload(&blobs, &pack);
        let store = MemoryKv::default();
        let mut batch = Batch::new();
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
                batch = std::mem::take(&mut batch).put(
                    keys::verify_row(&repo.name, &pack_id, keys::VC_FRAME, Some(&entry.id)),
                    encode_frame(&entry.id, &row).unwrap(),
                );
                Ok(())
            },
        )
        .unwrap();
        block_on(store.apply(&source(&repo), batch)).unwrap();
        let mut outside = InspectionSet::new(3);
        outside
            .reachable_entry(id, 11, ObjectType::Blob as u8)
            .unwrap();
        let added = block_on(scheduled_entries(
            &blobs,
            &store,
            &SinglePartition,
            &repo,
            &source(&repo),
            &[pack_id],
            super::super::IndexedConfig::default(),
            3,
            2,
            Some(&outside),
            &NoopMetrics,
        ))
        .unwrap();
        assert!(added.files.contains(&id));
        assert!(added.chunks.contains(&id));
        let entries = added.finalize();
        assert_eq!(entries.len(), 2);
        assert!(entries.contains(&InspectObject {
            id,
            size: 11,
            kind: Kind::Blob
        }));
        assert!(
            entries
                .iter()
                .any(|e| e.id == objects[1].id().unwrap() && e.kind == Kind::ChunkedFile)
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One blocker reproduction compares native and both Worker budgets.
    fn small_valid_manifest_pack_exceeds_worker_role_enumeration_budget() {
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
                    roles: matches!(entry.object, Object::ChunkedBlob(_)).then_some(entry.object),
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
        native.defer_native(vec![pack_id], entries);
        block_on(native.complete_added(
            &blobs,
            &store,
            &SinglePartition,
            &repo,
            super::super::IndexedConfig::default(),
            &NoopMetrics,
        ))
        .unwrap();
        let native = native.finalize();
        assert_eq!(native.len(), 400);
        let generous = super::super::budget::SliceBudget::new(1000);
        let mut worker = InspectionSet::new(10_000);
        worker.reserve_added_count(400).unwrap();
        worker.defer_scheduled(vec![pack_id], source(&repo));
        block_on(worker.complete_added(
            &super::super::budget::Budgeted::new(&blobs, &generous),
            &super::super::budget::Budgeted::new(&store, &generous),
            &SinglePartition,
            &repo,
            super::super::IndexedConfig::default(),
            &NoopMetrics,
        ))
        .unwrap();
        assert_eq!(worker.finalize(), native);
        assert_eq!(generous.used(), 401);
        let actual = super::super::budget::SliceBudget::new(256);
        let mut worker = InspectionSet::new(10_000);
        worker.reserve_added_count(400).unwrap();
        worker.defer_scheduled(vec![pack_id], source(&repo));
        let error = block_on(worker.complete_added(
            &super::super::budget::Budgeted::new(&blobs, &actual),
            &super::super::budget::Budgeted::new(&store, &actual),
            &SinglePartition,
            &repo,
            super::super::IndexedConfig::default(),
            &NoopMetrics,
        ))
        .unwrap_err();
        assert_eq!(actual.used(), 256);
        assert_eq!(error.code(), crate::Code::Unavailable);
        eprintln!(
            "valid pack bytes={}, entries=400; native objects={}; Worker calls={}; shared256 refuses after {} calls: {}",
            pack.len(),
            native.len(),
            generous.used(),
            actual.used(),
            error.public_message()
        );
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
        let budget = super::super::budget::SliceBudget::new(256);
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
            None,
            &NoopMetrics,
        ))
        .unwrap()
        .finalize();
        assert_eq!(entries.len(), 1500);
        assert_eq!(budget.used(), 2);
        assert!(entries.windows(2).all(|w| w[0].id < w[1].id));
    }
}
