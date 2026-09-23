//! Test-only trusted protocol model. It is not SQL/R2 durability evidence.

use super::*;
use std::ops::Range;

use mkit_core::pack::{PackWriter, pack_key};
use mkit_core::partial::{MAX_STAGED_PAGE, StagedRequiredObservation, next_required_chunk_ids};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Job {
    generation: u64,
    pairs: VecDeque<ChangedPairRecord>,
    files: VecDeque<RequiredFileRecord>,
    required: BTreeMap<Hash, u64>,
    matched: BTreeSet<u32>,
    usage: StagedUpdateUsageV1,
}

impl Job {
    fn reconcile(
        &self,
        observations: &[StagedRequiredObservation],
        supplied: &BTreeMap<Hash, (Range<usize>, u64)>,
    ) -> Option<(BTreeMap<Hash, u64>, Vec<Hash>)> {
        let mut next = self.required.clone();
        let mut new = Vec::new();
        for observation in observations {
            let id = observation.id();
            let length = observation.canonical_len();
            if supplied.get(&id)?.1 != length {
                return None;
            }
            if let Some(previous) = next.insert(id, length) {
                if previous != length {
                    return None;
                }
            } else if !new.contains(&id) {
                new.push(id);
            }
        }
        Some((next, new))
    }

    fn changed(
        &mut self,
        generation: u64,
        prior: Option<&ChangedPairRecord>,
        step: &ChangedPairStep,
        successors: &[ChangedPairRecord],
        files: &[RequiredFileRecord],
        supplied: &BTreeMap<Hash, (Range<usize>, u64)>,
        context: &StagedValidationContext,
    ) -> Option<()> {
        if generation != self.generation
            || prior.is_some() && self.pairs.front() != prior
            || successors != step.successors()
            || files != step.files()
        {
            return None;
        }
        let (required, new) = self.reconcile(step.observations(), supplied)?;
        let mut matched = self.matched.clone();
        for index in step.matched_indices() {
            if usize::try_from(*index).ok()? >= context.header().changes().len()
                || !matched.insert(*index)
            {
                return None;
            }
        }
        let usage = apply_changed_accounting(self.usage, step, &new, context).ok()?;
        if prior.is_some() {
            self.pairs.pop_front();
        }
        self.pairs.extend(successors.iter().cloned());
        self.files.extend(files.iter().cloned());
        self.required = required;
        self.matched = matched;
        self.usage = usage;
        Some(())
    }

    fn file(
        &mut self,
        generation: u64,
        prior: &RequiredFileRecord,
        step: &mkit_core::partial::RequiredFileStep,
        successors: &[RequiredFileRecord],
        supplied: &BTreeMap<Hash, (Range<usize>, u64)>,
        context: &StagedValidationContext,
    ) -> Option<()> {
        if generation != self.generation
            || self.files.front() != Some(prior)
            || successors != step.successors()
        {
            return None;
        }
        let (required, new) = self.reconcile(step.observations(), supplied)?;
        let usage = apply_required_accounting(self.usage, step, &new, context).ok()?;
        self.files.pop_front();
        self.files.extend(successors.iter().cloned());
        self.required = required;
        self.usage = usage;
        Some(())
    }
}

#[derive(Debug)]
struct RunMetrics {
    usage: StagedUpdateUsageV1,
    caller_owned_carrier_bytes: usize,
    // Largest simultaneous canonical input slices, not allocator/RSS peak.
    max_source_input_bytes: usize,
    max_frontier_records: usize,
    max_ledger_entries: usize,
    // Structural variable-length Tree/manifest fact payload estimate only.
    max_fact_metadata_bytes: usize,
    // Compact key/range/length payload; excludes BTreeMap node overhead.
    retained_index_bytes: usize,
}

fn supplied<'a>(
    pack: &'a [u8],
    index: &BTreeMap<Hash, (Range<usize>, u64)>,
    id: Hash,
) -> Option<&'a [u8]> {
    pack.get(index.get(&id)?.0.clone())
}

fn fact_metadata(fact: &mkit_core::partial::InspectedObject) -> usize {
    if let Some(count) = fact.tree_entries_len() {
        let names = fact.tree_page(0, count).map_or(0, |entries| {
            entries.iter().map(|entry| entry.name.len()).sum()
        });
        count * std::mem::size_of::<TreeEntry>() + names
    } else if let Some((_, _, count)) = fact.manifest() {
        count * std::mem::size_of::<Hash>()
    } else {
        0
    }
}

fn walk<F: FnMut(Hash) -> Option<Vec<u8>>>(
    root: Hash,
    role: SnapshotRole,
    limits: SnapshotWalkLimits,
    inspection: mkit_core::partial::ObjectInspectionLimits,
    fetch: &mut F,
    metrics: &mut RunMetrics,
) -> Option<SnapshotWalkUsage> {
    let mut queue = VecDeque::from([start_snapshot_walk(root, role).ok()?]);
    let mut seen = BTreeMap::new();
    let mut usage = SnapshotWalkUsage::default();
    let width = NonZeroUsize::new(MAX_STAGED_PAGE)?;
    while let Some(record) = queue.pop_front() {
        metrics.max_frontier_records = metrics.max_frontier_records.max(queue.len() + 1);
        let bytes = fetch(record.id())?;
        metrics.max_source_input_bytes = metrics.max_source_input_bytes.max(bytes.len());
        let fact = inspect_snapshot_object(record.id(), &bytes, record.role(), inspection).ok()?;
        metrics.max_fact_metadata_bytes = metrics.max_fact_metadata_bytes.max(fact_metadata(&fact));
        let ids = if matches!(record, SnapshotWalkRecord::ManifestPage { .. }) {
            next_manifest_ids(&record, &fact, width).ok()?.to_vec()
        } else {
            Vec::new()
        };
        let chunks = ids
            .iter()
            .map(|id| {
                let chunk_bytes = fetch(*id)?;
                metrics.max_source_input_bytes =
                    metrics.max_source_input_bytes.max(chunk_bytes.len());
                inspect_snapshot_object(*id, &chunk_bytes, SnapshotRole::Chunk, inspection).ok()
            })
            .collect::<Option<Vec<_>>>()?;
        metrics.max_fact_metadata_bytes = metrics
            .max_fact_metadata_bytes
            .max(fact_metadata(&fact) + chunks.iter().map(fact_metadata).sum::<usize>());
        let step = advance_snapshot_walk(&record, &fact, &chunks, width, &limits).ok()?;
        let mut new = BTreeSet::new();
        for observation in step.observations() {
            if let Some(previous) = seen.get(&observation.id()) {
                if *previous != observation.canonical_len() {
                    return None;
                }
            } else {
                new.insert(observation.id());
            }
        }
        usage = apply_walk_accounting(usage, &step, &new.into_iter().collect::<Vec<_>>(), limits)
            .ok()?;
        for observation in step.observations() {
            seen.insert(observation.id(), observation.canonical_len());
        }
        metrics.max_ledger_entries = metrics.max_ledger_entries.max(seen.len());
        queue.extend(step.successors().iter().copied());
    }
    Some(usage)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WalkJob {
    generation: u64,
    queue: VecDeque<SnapshotWalkRecord>,
    seen: BTreeMap<Hash, u64>,
    usage: SnapshotWalkUsage,
}

impl WalkJob {
    fn commit(
        &mut self,
        generation: u64,
        prior: &SnapshotWalkRecord,
        step: &mkit_core::partial::SnapshotWalkStep,
        successors: &[SnapshotWalkRecord],
        limits: SnapshotWalkLimits,
    ) -> Option<()> {
        if generation != self.generation
            || self.queue.front() != Some(prior)
            || successors != step.successors()
        {
            return None;
        }
        let mut seen = self.seen.clone();
        let mut new = BTreeSet::new();
        for observation in step.observations() {
            if let Some(previous) = seen.insert(observation.id(), observation.canonical_len()) {
                if previous != observation.canonical_len() {
                    return None;
                }
            } else {
                new.insert(observation.id());
            }
        }
        let usage = apply_walk_accounting(
            self.usage,
            step,
            &new.into_iter().collect::<Vec<_>>(),
            limits,
        )
        .ok()?;
        self.queue.pop_front();
        self.queue.extend(successors.iter().copied());
        self.seen = seen;
        self.usage = usage;
        Some(())
    }
}

#[test]
fn candidate_walk_model_refuses_omission_stale_and_prior_length_atomically() {
    let (source, base, _) = base_source();
    let checked = CheckedMkwu::open(
        GOLDEN,
        GOLDEN.len() as u64,
        mkit_core::hash::hash(GOLDEN),
        base,
        PartialLimits::V1,
        StagedUpdateLimitsV1::default(),
    )
    .unwrap();
    let context = super::context(&checked);
    let bytes = checked
        .pack()
        .entries()
        .find(|entry| {
            inspect_staged_inventory_object(entry.payload(), &context)
                .unwrap()
                .object()
                .id()
                == checked.header().candidate_id()
        })
        .unwrap();
    let fact = inspect_staged_candidate(bytes.payload(), &context).unwrap();
    let record = start_snapshot_walk(fact.id(), SnapshotRole::CandidateRoot).unwrap();
    let limits = StagedUpdateLimitsV1::default().candidate_walk;
    let step = advance_snapshot_walk(
        &record,
        fact.object(),
        &[],
        NonZeroUsize::new(64).unwrap(),
        &limits,
    )
    .unwrap();
    let mut job = WalkJob {
        generation: 4,
        queue: VecDeque::from([record]),
        seen: BTreeMap::new(),
        usage: SnapshotWalkUsage::default(),
    };
    let before = job.clone();
    assert!(job.commit(4, &record, &step, &[], limits).is_none());
    assert_eq!(job, before);
    assert!(
        job.commit(3, &record, &step, step.successors(), limits)
            .is_none()
    );
    assert_eq!(job, before);
    job.seen.insert(fact.id(), 1);
    let corrupt = job.clone();
    assert!(
        job.commit(4, &record, &step, step.successors(), limits)
            .is_none()
    );
    assert_eq!(job, corrupt);
    job = before.clone();
    job.commit(4, &record, &step, step.successors(), limits)
        .unwrap();
    let mut replay = before;
    replay
        .commit(4, &record, &step, step.successors(), limits)
        .unwrap();
    assert_eq!(job, replay);
    assert_eq!(job.queue.len(), 1);
    assert_eq!(job.usage.objects, 1);
    let mut fetch = |id| source.0.get(&id).cloned();
    assert!(complete(GOLDEN, base, &mut fetch).is_some());
}

fn complete<F: FnMut(Hash) -> Option<Vec<u8>>>(
    carrier: &[u8],
    base_id: Hash,
    source: &mut F,
) -> Option<RunMetrics> {
    complete_with(
        carrier,
        base_id,
        source,
        PartialLimits::V1,
        StagedUpdateLimitsV1::default(),
    )
}

fn complete_with<F: FnMut(Hash) -> Option<Vec<u8>>>(
    carrier: &[u8],
    base_id: Hash,
    source: &mut F,
    portable: PartialLimits,
    staged: StagedUpdateLimitsV1,
) -> Option<RunMetrics> {
    let checked = CheckedMkwu::open(
        carrier,
        carrier.len() as u64,
        mkit_core::hash::hash(carrier),
        base_id,
        portable,
        staged,
    )
    .ok()?;
    let mut inspection = default_staged_inspection_limits();
    inspection.max_object_bytes = inspection.max_object_bytes.min(portable.max_object_bytes);
    inspection.max_tree_bytes = inspection
        .max_tree_bytes
        .min(portable.max_tree_object_bytes);
    inspection.max_tree_entries = inspection.max_tree_entries.min(portable.max_tree_entries);
    let context =
        StagedValidationContext::new(checked.header().clone(), portable, staged, inspection)
            .ok()?;
    let pack = &carrier[checked.header().pack_offset()..];
    let mut metrics = RunMetrics {
        usage: checked.initial_usage(),
        caller_owned_carrier_bytes: carrier.len(),
        max_source_input_bytes: 0,
        max_frontier_records: 0,
        max_ledger_entries: 0,
        max_fact_metadata_bytes: 0,
        retained_index_bytes: 0,
    };
    let mut cursor = StagedInventoryCursor::default();
    let mut index = BTreeMap::new();
    for entry in checked.pack().entries() {
        let fact = inspect_staged_inventory_object(entry.payload(), &context).ok()?;
        metrics.max_fact_metadata_bytes = metrics
            .max_fact_metadata_bytes
            .max(fact_metadata(fact.object()));
        let step =
            advance_staged_inventory(&cursor, u64::from(entry.ordinal()), &fact, &context).ok()?;
        metrics.usage = apply_inventory_accounting(metrics.usage, &step, &context).ok()?;
        cursor = step.cursor();
        if index
            .insert(step.id(), (entry.payload_range(), step.canonical_len()))
            .is_some()
        {
            return None;
        }
    }
    if cursor.count != u64::from(checked.pack().entry_count()) {
        return None;
    }
    metrics.retained_index_bytes = index.len() * (32 + 2 * std::mem::size_of::<usize>() + 8);
    metrics.usage.base_walk = walk(
        base_id,
        SnapshotRole::BaseRoot,
        staged.base_walk,
        context.inspection(),
        source,
        &mut metrics,
    )?;
    let base_bytes = source(base_id)?;
    let base = inspect_snapshot_object(
        base_id,
        &base_bytes,
        SnapshotRole::BaseRoot,
        context.inspection(),
    )
    .ok()?;
    let candidate_bytes = supplied(pack, &index, checked.header().candidate_id())?;
    let candidate = inspect_staged_candidate(candidate_bytes, &context).ok()?;
    let mut job = Job {
        generation: 1,
        pairs: VecDeque::new(),
        files: VecDeque::new(),
        required: BTreeMap::new(),
        matched: BTreeSet::new(),
        usage: metrics.usage,
    };
    let start = start_changed_pairs(&base, &candidate, &context).ok()?;
    job.changed(
        1,
        None,
        &start,
        start.successors(),
        start.files(),
        &index,
        &context,
    )?;
    let width = NonZeroUsize::new(MAX_STAGED_PAGE)?;
    while let Some(record) = job.pairs.front().cloned() {
        metrics.max_frontier_records = metrics
            .max_frontier_records
            .max(job.pairs.len() + job.files.len());
        let old_bytes = source(record.old_id())?;
        let new_bytes = supplied(pack, &index, record.new_id())?;
        metrics.max_source_input_bytes = metrics
            .max_source_input_bytes
            .max(old_bytes.len() + new_bytes.len());
        let old = inspect_snapshot_object(
            record.old_id(),
            &old_bytes,
            SnapshotRole::Tree,
            context.inspection(),
        )
        .ok()?;
        let new = inspect_snapshot_object(
            record.new_id(),
            new_bytes,
            SnapshotRole::Tree,
            context.inspection(),
        )
        .ok()?;
        metrics.max_fact_metadata_bytes = metrics
            .max_fact_metadata_bytes
            .max(fact_metadata(&old) + fact_metadata(&new));
        let step = advance_changed_pair(&record, &old, &new, &context, width).ok()?;
        job.changed(
            1,
            Some(&record),
            &step,
            step.successors(),
            step.files(),
            &index,
            &context,
        )?;
        metrics.max_ledger_entries = metrics.max_ledger_entries.max(job.required.len());
    }
    while let Some(record) = job.files.front().cloned() {
        metrics.max_frontier_records = metrics.max_frontier_records.max(job.files.len());
        let file_bytes = supplied(pack, &index, record.expected_file_id())?;
        let file = inspect_snapshot_object(
            record.expected_file_id(),
            file_bytes,
            SnapshotRole::File,
            context.inspection(),
        )
        .ok()?;
        metrics.max_fact_metadata_bytes = metrics.max_fact_metadata_bytes.max(fact_metadata(&file));
        let ids = if matches!(record, RequiredFileRecord::ManifestPage { .. }) {
            next_required_chunk_ids(&record, &file, &job.usage, &context, width)
                .ok()?
                .to_vec()
        } else {
            Vec::new()
        };
        let chunks = ids
            .iter()
            .map(|id| {
                inspect_snapshot_object(
                    *id,
                    supplied(pack, &index, *id)?,
                    SnapshotRole::Chunk,
                    context.inspection(),
                )
                .ok()
            })
            .collect::<Option<Vec<_>>>()?;
        metrics.max_fact_metadata_bytes = metrics
            .max_fact_metadata_bytes
            .max(fact_metadata(&file) + chunks.iter().map(fact_metadata).sum::<usize>());
        let step =
            advance_required_file(&record, &file, &chunks, width, &job.usage, &context).ok()?;
        job.file(1, &record, &step, step.successors(), &index, &context)?;
        metrics.max_ledger_entries = metrics.max_ledger_entries.max(job.required.len());
    }
    if job.matched.len() != context.header().changes().len()
        || !job.pairs.is_empty()
        || !job.files.is_empty()
        || job.required.keys().copied().collect::<BTreeSet<_>>()
            != index.keys().copied().collect::<BTreeSet<_>>()
    {
        return None;
    }
    metrics.usage = job.usage;
    metrics.usage.candidate_walk = walk(
        context.header().candidate_id(),
        SnapshotRole::CandidateRoot,
        staged.candidate_walk,
        context.inspection(),
        &mut |id| {
            supplied(pack, &index, id)
                .map(ToOwned::to_owned)
                .or_else(|| source(id))
        },
        &mut metrics,
    )?;
    Some(metrics)
}

#[test]
fn complete_golden_driver_drains_every_stage() {
    let (source, base, _) = base_source();
    let mut fetch = |id| source.0.get(&id).cloned();
    let metrics = complete(GOLDEN, base, &mut fetch).expect("whole staged validation");
    assert_eq!(metrics.usage.inventory_entries, 3);
    assert_eq!(metrics.usage.changed_total_bytes, 4096);
    assert_eq!(metrics.usage.required_unique_ids, 3);
    assert_eq!(metrics.usage.base_walk.objects, 3);
    assert_eq!(metrics.usage.candidate_walk.objects, 3);
}

fn carrier(
    base: Hash,
    candidate: Hash,
    changes: &[(Vec<Vec<u8>>, EntryMode, Hash, Hash)],
    supplied: &BTreeMap<Hash, Vec<u8>>,
) -> Vec<u8> {
    let mut writer = PackWriter::new_raw_only();
    for (id, bytes) in supplied {
        writer.push_raw(*id, bytes).unwrap();
    }
    let pack = writer.finish().unwrap();
    let mut out = Vec::new();
    out.extend_from_slice(b"MKWU");
    out.push(1);
    out.extend_from_slice(&base);
    out.extend_from_slice(&candidate);
    append_varint(&mut out, changes.len());
    for (path, mode, old, new) in changes {
        append_varint(&mut out, path.len());
        for component in path {
            append_varint(&mut out, component.len());
            out.extend_from_slice(component);
        }
        out.push(*mode as u8);
        out.extend_from_slice(old);
        out.extend_from_slice(new);
    }
    out.extend_from_slice(&pack_key(&pack));
    out.extend_from_slice(&(pack.len() as u64).to_be_bytes());
    append_varint(&mut out, pack.len());
    out.extend_from_slice(&pack);
    out
}

fn signed_root(tree: Hash, parents: Vec<Hash>, seed: u8) -> Object {
    let key = KeyPair::from_seed([seed; 32]);
    let mut commit = Commit::new_unannotated(
        tree,
        parents,
        Identity::ed25519(key.public.0),
        key.public.0,
        b"test".to_vec(),
        1_700_000_001,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &key).unwrap().0;
    Object::Commit(commit)
}

struct Fixture {
    source: BTreeMap<Hash, Vec<u8>>,
    supplied: BTreeMap<Hash, Vec<u8>>,
    base: Hash,
    candidate: Hash,
    changes: Vec<(Vec<Vec<u8>>, EntryMode, Hash, Hash)>,
    bytes: Vec<u8>,
}

#[allow(clippy::similar_names)] // path-specific a/b/c fixture values are intentionally parallel
fn shared_fixture(two_sided: bool) -> Fixture {
    let mut source = BTreeMap::new();
    let mut supplied = BTreeMap::new();
    let old_file = put(
        &mut source,
        Object::Blob(Blob {
            data: b"old".to_vec(),
        }),
    );
    let old_shared = put(
        &mut source,
        Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: b"file".to_vec(),
                mode: EntryMode::Blob,
                object_hash: old_file,
            }],
        }),
    );
    let old_nested = put(
        &mut source,
        Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: b"d".to_vec(),
                mode: EntryMode::Tree,
                object_hash: old_shared,
            }],
        }),
    );
    let old_root = put(
        &mut source,
        Object::Tree(Tree {
            entries: vec![
                TreeEntry {
                    name: b"a".to_vec(),
                    mode: EntryMode::Tree,
                    object_hash: old_shared,
                },
                TreeEntry {
                    name: b"b".to_vec(),
                    mode: EntryMode::Tree,
                    object_hash: old_shared,
                },
                TreeEntry {
                    name: b"c".to_vec(),
                    mode: EntryMode::Tree,
                    object_hash: old_nested,
                },
            ],
        }),
    );
    let base = put(&mut source, signed_root(old_root, Vec::new(), 51));
    let new_a_file = put(
        &mut supplied,
        Object::Blob(Blob {
            data: b"a new".to_vec(),
        }),
    );
    let new_a = put(
        &mut supplied,
        Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: b"file".to_vec(),
                mode: EntryMode::Blob,
                object_hash: new_a_file,
            }],
        }),
    );
    let mut entries = vec![
        TreeEntry {
            name: b"a".to_vec(),
            mode: EntryMode::Tree,
            object_hash: new_a,
        },
        TreeEntry {
            name: b"b".to_vec(),
            mode: EntryMode::Tree,
            object_hash: old_shared,
        },
        TreeEntry {
            name: b"c".to_vec(),
            mode: EntryMode::Tree,
            object_hash: old_nested,
        },
    ];
    let mut changes = vec![(
        vec![b"a".to_vec(), b"file".to_vec()],
        EntryMode::Blob,
        old_file,
        new_a_file,
    )];
    if two_sided {
        let new_b_file = put(
            &mut supplied,
            Object::Blob(Blob {
                data: b"b new".to_vec(),
            }),
        );
        let new_b = put(
            &mut supplied,
            Object::Tree(Tree {
                entries: vec![TreeEntry {
                    name: b"file".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: new_b_file,
                }],
            }),
        );
        entries[1].object_hash = new_b;
        changes.push((
            vec![b"b".to_vec(), b"file".to_vec()],
            EntryMode::Blob,
            old_file,
            new_b_file,
        ));
        let new_c_file = put(
            &mut supplied,
            Object::Blob(Blob {
                data: b"c new".to_vec(),
            }),
        );
        let new_c_leaf = put(
            &mut supplied,
            Object::Tree(Tree {
                entries: vec![TreeEntry {
                    name: b"file".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: new_c_file,
                }],
            }),
        );
        let new_c = put(
            &mut supplied,
            Object::Tree(Tree {
                entries: vec![TreeEntry {
                    name: b"d".to_vec(),
                    mode: EntryMode::Tree,
                    object_hash: new_c_leaf,
                }],
            }),
        );
        entries[2].object_hash = new_c;
        changes.push((
            vec![b"c".to_vec(), b"d".to_vec(), b"file".to_vec()],
            EntryMode::Blob,
            old_file,
            new_c_file,
        ));
    }
    let new_root = put(&mut supplied, Object::Tree(Tree { entries }));
    let candidate = put(&mut supplied, signed_root(new_root, vec![base], 52));
    let bytes = carrier(base, candidate, &changes, &supplied);
    Fixture {
        source,
        supplied,
        base,
        candidate,
        changes,
        bytes,
    }
}

fn chunked_fixture() -> Fixture {
    let (base_source, base, old_tree) = base_source();
    let source = base_source.0;
    let old = match mkit_core::deserialize(source.get(&old_tree).unwrap()).unwrap() {
        Object::Tree(tree) => tree.entries[0].object_hash,
        _ => unreachable!(),
    };
    let mut supplied = BTreeMap::new();
    let chunk_a = put(
        &mut supplied,
        Object::Blob(Blob {
            data: b"a".to_vec(),
        }),
    );
    let chunk_b = put(
        &mut supplied,
        Object::Blob(Blob {
            data: b"bb".to_vec(),
        }),
    );
    let file = put(
        &mut supplied,
        Object::ChunkedBlob(ChunkedBlob {
            total_size: 3,
            chunk_size: 0,
            chunks: vec![chunk_a, chunk_b],
        }),
    );
    let tree = put(
        &mut supplied,
        Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: b"a.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: file,
            }],
        }),
    );
    let candidate = put(&mut supplied, signed_root(tree, vec![base], 61));
    let changes = vec![(vec![b"a.txt".to_vec()], EntryMode::Blob, old, file)];
    let bytes = carrier(base, candidate, &changes, &supplied);
    Fixture {
        source,
        supplied,
        base,
        candidate,
        changes,
        bytes,
    }
}

#[test]
fn chunked_file_queue_retries_every_position_and_requires_supplied_chunks() {
    let fixture = chunked_fixture();
    let mut fetch = |id| fixture.source.get(&id).cloned();
    let metrics = complete(&fixture.bytes, fixture.base, &mut fetch).unwrap();
    assert_eq!(metrics.usage.changed_total_bytes, 3);
    assert_eq!(metrics.usage.required_unique_ids, 5);
    let mut old = BaseSource(fixture.source.clone());
    assert!(
        verify_partial_update(
            fixture.base,
            &fixture.bytes,
            &mut old,
            &PartialLimits::V1,
            &RecipientLimits::DEFAULT,
        )
        .is_ok()
    );
    for chunk in fixture.supplied.iter().filter_map(|(id, bytes)| {
        matches!(mkit_core::deserialize(bytes).unwrap(), Object::Blob(_)).then_some(*id)
    }) {
        let mut supplied = fixture.supplied.clone();
        let mut hidden = fixture.source.clone();
        hidden.insert(chunk, supplied.remove(&chunk).unwrap());
        let bytes = carrier(fixture.base, fixture.candidate, &fixture.changes, &supplied);
        assert!(complete(&bytes, fixture.base, &mut |id| hidden.get(&id).cloned()).is_none());
    }
    let checked = CheckedMkwu::open(
        &fixture.bytes,
        fixture.bytes.len() as u64,
        mkit_core::hash::hash(&fixture.bytes),
        fixture.base,
        PartialLimits::V1,
        StagedUpdateLimitsV1::default(),
    )
    .unwrap();
    let context = super::context(&checked);
    let mut index = BTreeMap::new();
    for entry in checked.pack().entries() {
        let fact = inspect_staged_inventory_object(entry.payload(), &context).unwrap();
        index.insert(
            fact.object().id(),
            (entry.payload_range(), fact.object().canonical_len() as u64),
        );
    }
    let file_id = fixture.changes[0].3;
    let file = inspect_snapshot_object(
        file_id,
        fixture.supplied.get(&file_id).unwrap(),
        SnapshotRole::File,
        context.inspection(),
    )
    .unwrap();
    let record = RequiredFileRecord::Visit {
        change_index: 0,
        expected_file_id: file_id,
    };
    let mut job = Job {
        generation: 7,
        pairs: VecDeque::new(),
        files: VecDeque::from([record.clone()]),
        required: BTreeMap::new(),
        matched: BTreeSet::new(),
        usage: checked.initial_usage(),
    };
    let one = NonZeroUsize::new(1).unwrap();
    let visit = advance_required_file(&record, &file, &[], one, &job.usage, &context).unwrap();
    let unchanged = job.clone();
    assert!(
        job.file(7, &record, &visit, &[], &index, &context)
            .is_none()
    );
    assert_eq!(job, unchanged);
    assert!(
        job.file(6, &record, &visit, visit.successors(), &index, &context)
            .is_none()
    );
    assert_eq!(job, unchanged);
    job.file(7, &record, &visit, visit.successors(), &index, &context)
        .unwrap();
    let mut replay = unchanged;
    replay
        .file(7, &record, &visit, visit.successors(), &index, &context)
        .unwrap();
    assert_eq!(replay, job);
    assert_eq!(job.usage.changed_total_bytes, 3);
    for _ in 0..2 {
        let prior = job.files.front().unwrap().clone();
        let ids = next_required_chunk_ids(&prior, &file, &job.usage, &context, one).unwrap();
        let chunks = ids
            .iter()
            .map(|id| {
                inspect_snapshot_object(
                    *id,
                    fixture.supplied.get(id).unwrap(),
                    SnapshotRole::Chunk,
                    context.inspection(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let step =
            advance_required_file(&prior, &file, &chunks, one, &job.usage, &context).unwrap();
        let unchanged = job.clone();
        if !step.successors().is_empty() {
            assert!(job.file(7, &prior, &step, &[], &index, &context).is_none());
            assert_eq!(job, unchanged);
        }
        let mut bad = job.clone();
        bad.required.insert(ids[0], 1_000);
        assert!(
            bad.file(7, &prior, &step, step.successors(), &index, &context)
                .is_none()
        );
        assert_eq!(bad.files, unchanged.files);
        job.file(7, &prior, &step, step.successors(), &index, &context)
            .unwrap();
    }
    assert!(job.files.is_empty());
    assert_eq!(
        job.usage.changed_total_bytes, 3,
        "manifest completion never charges twice"
    );
}

#[test]
fn shared_tree_occurrences_one_sided_and_nested_two_sided_match_old_recipient() {
    for two_sided in [false, true] {
        let fixture = shared_fixture(two_sided);
        let mut fetch = |id| fixture.source.get(&id).cloned();
        let metrics = complete(&fixture.bytes, fixture.base, &mut fetch)
            .expect("all shared occurrences validated");
        assert_eq!(
            metrics.usage.changed_total_bytes,
            if two_sided { 15 } else { 5 }
        );
        assert_eq!(
            metrics.usage.diff_pair_visits,
            if two_sided { 5 } else { 2 }
        );
        let mut old = BaseSource(fixture.source.clone());
        assert!(
            verify_partial_update(
                fixture.base,
                &fixture.bytes,
                &mut old,
                &PartialLimits::V1,
                &RecipientLimits::DEFAULT,
            )
            .is_ok()
        );
    }
}

#[test]
fn every_named_staged_counter_accepts_exact_and_refuses_one_below() {
    let fixture = shared_fixture(true);
    let baseline = complete(&fixture.bytes, fixture.base, &mut |id| {
        fixture.source.get(&id).cloned()
    })
    .unwrap()
    .usage;
    let value = |kind| match kind {
        0 => baseline.header_bytes,
        1 => baseline.update_bytes,
        2 => baseline.pack_bytes,
        3 => baseline.inventory_entries,
        4 => baseline.inventory_payload_bytes,
        5 => baseline.inventory_work,
        6 => baseline.base_walk.objects,
        7 => baseline.base_walk.canonical_bytes,
        8 => baseline.base_walk.max_tree_depth,
        9 => baseline.base_walk.work,
        10 => baseline.candidate_walk.objects,
        11 => baseline.candidate_walk.canonical_bytes,
        12 => baseline.candidate_walk.max_tree_depth,
        13 => baseline.candidate_walk.work,
        14 => baseline.diff_pair_visits,
        15 => baseline.diff_work,
        16 => baseline.required_unique_ids,
        17 => baseline.required_canonical_bytes,
        _ => baseline.origin_work,
    };
    for kind in 0..19 {
        let observed = value(kind);
        assert!(observed > 0, "case {kind} must reach its intended guard");
        for (cap, accepted) in [(observed, true), (observed - 1, false)] {
            let mut limits = StagedUpdateLimitsV1::default();
            match kind {
                0 => limits.max_header_bytes = cap,
                1 => limits.max_update_bytes = cap,
                2 => {
                    limits.max_pack_bytes = cap;
                    limits.max_inventory_payload_bytes = baseline.inventory_payload_bytes.min(cap);
                }
                3 => limits.max_inventory_entries = cap,
                4 => limits.max_inventory_payload_bytes = cap,
                5 => limits.max_inventory_work = cap,
                6 => limits.base_walk.max_objects = cap,
                7 => limits.base_walk.max_canonical_bytes = cap,
                8 => limits.base_walk.max_tree_depth = cap,
                9 => limits.base_walk.max_work = cap,
                10 => limits.candidate_walk.max_objects = cap,
                11 => limits.candidate_walk.max_canonical_bytes = cap,
                12 => limits.candidate_walk.max_tree_depth = cap,
                13 => limits.candidate_walk.max_work = cap,
                14 => limits.max_diff_pair_visits = cap,
                15 => limits.max_diff_work = cap,
                16 => limits.max_required_unique_ids = cap,
                17 => limits.max_required_canonical_bytes = cap,
                _ => limits.max_origin_work = cap,
            }
            let result = complete_with(
                &fixture.bytes,
                fixture.base,
                &mut |id| fixture.source.get(&id).cloned(),
                PartialLimits::V1,
                limits,
            );
            assert_eq!(result.is_some(), accepted, "counter {kind} cap {cap}");
        }
    }
    for (field, exact) in [
        (0, baseline.max_changed_file_bytes_seen),
        (1, baseline.changed_total_bytes),
    ] {
        for (cap, accepted) in [(exact, true), (exact - 1, false)] {
            let mut portable = PartialLimits::V1;
            if field == 0 {
                portable.max_selected_file_bytes = usize::try_from(cap).unwrap();
            } else {
                portable.max_total_selected_bytes = usize::try_from(cap).unwrap();
            }
            assert_eq!(
                complete_with(
                    &fixture.bytes,
                    fixture.base,
                    &mut |id| fixture.source.get(&id).cloned(),
                    portable,
                    StagedUpdateLimitsV1::default(),
                )
                .is_some(),
                accepted,
                "positional field {field} cap {cap}"
            );
        }
    }
}

#[test]
fn portable_object_tree_manifest_and_page_guards_reach_their_facts() {
    let fixture = chunked_fixture();
    let checked = CheckedMkwu::open(
        &fixture.bytes,
        fixture.bytes.len() as u64,
        mkit_core::hash::hash(&fixture.bytes),
        fixture.base,
        PartialLimits::V1,
        StagedUpdateLimitsV1::default(),
    )
    .unwrap();
    let manifest_id = fixture.changes[0].3;
    let manifest = fixture.supplied.get(&manifest_id).unwrap();
    let tree = fixture
        .supplied
        .iter()
        .find_map(|(_, bytes)| {
            matches!(mkit_core::deserialize(bytes).unwrap(), Object::Tree(_)).then_some(bytes)
        })
        .unwrap();
    let make = |portable: PartialLimits, inspection: mkit_core::partial::ObjectInspectionLimits| {
        StagedValidationContext::new(
            checked.header().clone(),
            portable,
            StagedUpdateLimitsV1::default(),
            inspection,
        )
        .unwrap()
    };
    for (kind, exact) in [(0, manifest.len()), (1, tree.len()), (2, 1), (3, 2), (4, 3)] {
        for (cap, accepted) in [(exact, true), (exact - 1, false)] {
            let mut portable = PartialLimits::V1;
            let mut inspection = default_staged_inspection_limits();
            match kind {
                0 => {
                    portable.max_object_bytes = cap;
                    inspection.max_object_bytes = cap;
                }
                1 => {
                    portable.max_tree_object_bytes = cap;
                    inspection.max_tree_bytes = cap;
                }
                2 => {
                    portable.max_tree_entries = cap;
                    inspection.max_tree_entries = cap;
                }
                3 => inspection.max_manifest_chunks = cap,
                _ => portable.max_selected_file_bytes = cap,
            }
            let context = make(portable, inspection);
            let input = if kind == 1 || kind == 2 {
                tree
            } else {
                manifest
            };
            assert_eq!(
                inspect_staged_inventory_object(input, &context).is_ok(),
                accepted,
                "portable/inspection field {kind} cap {cap}"
            );
        }
    }
    let context = super::context(&checked);
    let file = inspect_snapshot_object(
        manifest_id,
        manifest,
        SnapshotRole::File,
        context.inspection(),
    )
    .unwrap();
    let record = RequiredFileRecord::ManifestPage {
        change_index: 0,
        expected_file_id: manifest_id,
        next_index: 0,
        sum: 0,
    };
    assert!(
        next_required_chunk_ids(
            &record,
            &file,
            &StagedUpdateUsageV1::default(),
            &context,
            NonZeroUsize::new(64).unwrap(),
        )
        .is_ok()
    );
    assert!(
        next_required_chunk_ids(
            &record,
            &file,
            &StagedUpdateUsageV1::default(),
            &context,
            NonZeroUsize::new(65).unwrap(),
        )
        .is_err()
    );
    let corrupt = RequiredFileRecord::ManifestPage {
        change_index: 0,
        expected_file_id: manifest_id,
        next_index: u32::MAX,
        sum: u64::MAX,
    };
    assert!(
        next_required_chunk_ids(
            &corrupt,
            &file,
            &StagedUpdateUsageV1::default(),
            &context,
            NonZeroUsize::new(1).unwrap(),
        )
        .is_err()
    );
    let first = checked.pack().entries().next().unwrap();
    let fact = inspect_staged_inventory_object(first.payload(), &context).unwrap();
    let step =
        advance_staged_inventory(&StagedInventoryCursor::default(), 0, &fact, &context).unwrap();
    let mut corrupt_usage = checked.initial_usage();
    corrupt_usage.inventory_entries = u64::MAX;
    assert!(apply_inventory_accounting(corrupt_usage, &step, &context).is_err());
    let corrupt_cursor = StagedInventoryCursor {
        next_ordinal: u64::MAX,
        previous_id: Some([0; 32]),
        count: u64::MAX,
        canonical_bytes: u64::MAX,
    };
    assert!(advance_staged_inventory(&corrupt_cursor, u64::MAX, &fact, &context).is_err());
}

#[test]
fn complete_driver_refuses_hidden_repair_extra_and_wrong_declared_old_id() {
    let fixture = shared_fixture(true);
    for missing in [
        fixture
            .supplied
            .iter()
            .find(|(_, bytes)| matches!(mkit_core::deserialize(bytes).unwrap(), Object::Tree(_)))
            .unwrap()
            .0,
        fixture
            .supplied
            .iter()
            .find(|(_, bytes)| matches!(mkit_core::deserialize(bytes).unwrap(), Object::Blob(_)))
            .unwrap()
            .0,
    ] {
        let mut supplied = fixture.supplied.clone();
        let mut source = fixture.source.clone();
        source.insert(*missing, supplied.remove(missing).unwrap());
        let bytes = carrier(fixture.base, fixture.candidate, &fixture.changes, &supplied);
        assert!(complete(&bytes, fixture.base, &mut |id| source.get(&id).cloned()).is_none());
        assert!(
            verify_partial_update(
                fixture.base,
                &bytes,
                &mut BaseSource(source),
                &PartialLimits::V1,
                &RecipientLimits::DEFAULT,
            )
            .is_err()
        );
    }
    let mut extra = fixture.supplied.clone();
    put(
        &mut extra,
        Object::Blob(Blob {
            data: b"unrelated".to_vec(),
        }),
    );
    let bytes = carrier(fixture.base, fixture.candidate, &fixture.changes, &extra);
    assert!(
        complete(&bytes, fixture.base, &mut |id| fixture
            .source
            .get(&id)
            .cloned())
        .is_none()
    );
    let mut wrong = fixture.changes.clone();
    wrong[0].2 = [9; 32];
    let bytes = carrier(fixture.base, fixture.candidate, &wrong, &fixture.supplied);
    assert!(
        complete(&bytes, fixture.base, &mut |id| fixture
            .source
            .get(&id)
            .cloned())
        .is_none()
    );
}

#[test]
fn actual_shared_frontier_refuses_name_mode_and_undeclared_tree_graft() {
    for variant in 0..3 {
        let mut fixture = shared_fixture(false);
        let Object::Commit(old_candidate) =
            mkit_core::deserialize(fixture.supplied.get(&fixture.candidate).unwrap()).unwrap()
        else {
            unreachable!()
        };
        let old_root_id = old_candidate.tree_hash;
        let Object::Tree(mut tree) =
            mkit_core::deserialize(fixture.supplied.get(&old_root_id).unwrap()).unwrap()
        else {
            unreachable!()
        };
        match variant {
            0 => tree.entries[0].name = b"aa".to_vec(),
            1 => tree.entries[0].mode = EntryMode::Blob,
            _ => tree.entries[1].object_hash = tree.entries[0].object_hash,
        }
        fixture.supplied.remove(&fixture.candidate);
        fixture.supplied.remove(&old_root_id);
        let new_root = put(&mut fixture.supplied, Object::Tree(tree));
        fixture.candidate = put(
            &mut fixture.supplied,
            signed_root(new_root, vec![fixture.base], 52),
        );
        fixture.bytes = carrier(
            fixture.base,
            fixture.candidate,
            &fixture.changes,
            &fixture.supplied,
        );
        assert!(
            complete(&fixture.bytes, fixture.base, &mut |id| fixture
                .source
                .get(&id)
                .cloned())
            .is_none()
        );
        assert!(
            verify_partial_update(
                fixture.base,
                &fixture.bytes,
                &mut BaseSource(fixture.source),
                &PartialLimits::V1,
                &RecipientLimits::DEFAULT,
            )
            .is_err()
        );
    }
}

#[test]
fn valid_edit_over_distinct_135_mib_base_is_fully_walked_without_second_graph() {
    const LARGE: usize = 15 * 1024 * 1024;
    let mut large_ids = BTreeMap::new();
    let mut base_objects = BTreeMap::new();
    let mut entries = Vec::new();
    let mut independent_bytes = 0u64;
    for seed in 1..=9u8 {
        let object = Object::Blob(Blob {
            data: vec![seed; LARGE],
        });
        let bytes = serialize(&object).unwrap();
        let id = id_from_object(&object, &bytes);
        independent_bytes += bytes.len() as u64;
        large_ids.insert(id, seed);
        entries.push(TreeEntry {
            name: format!("large{seed:02}").into_bytes(),
            mode: EntryMode::Blob,
            object_hash: id,
        });
        // The object and serialized bytes are dropped here. Only compact IDs
        // and deterministic seeds survive until the on-demand source fetch.
    }
    assert!(independent_bytes > 128 * 1024 * 1024);
    let old = put(
        &mut base_objects,
        Object::Blob(Blob {
            data: b"old".to_vec(),
        }),
    );
    entries.push(TreeEntry {
        name: b"small".to_vec(),
        mode: EntryMode::Blob,
        object_hash: old,
    });
    let old_tree = put(
        &mut base_objects,
        Object::Tree(Tree {
            entries: entries.clone(),
        }),
    );
    let base = put(&mut base_objects, signed_root(old_tree, Vec::new(), 41));
    let mut supplied = BTreeMap::new();
    let new_file = put(
        &mut supplied,
        Object::Blob(Blob {
            data: b"new".to_vec(),
        }),
    );
    entries.last_mut().unwrap().object_hash = new_file;
    let new_tree = put(&mut supplied, Object::Tree(Tree { entries }));
    let candidate = put(&mut supplied, signed_root(new_tree, vec![base], 42));
    let update = carrier(
        base,
        candidate,
        &[(vec![b"small".to_vec()], EntryMode::Blob, old, new_file)],
        &supplied,
    );
    let mut max_generated_source = 0usize;
    let mut source = |id| {
        if let Some(bytes) = base_objects.get(&id) {
            return Some(bytes.clone());
        }
        let seed = *large_ids.get(&id)?;
        let object = Object::Blob(Blob {
            data: vec![seed; LARGE],
        });
        let bytes = serialize(&object).ok()?;
        max_generated_source = max_generated_source.max(bytes.len());
        (id_from_object(&object, &bytes) == id).then_some(bytes)
    };
    let metrics = complete(&update, base, &mut source).expect("valid large semantic edit");
    eprintln!(
        "large staged fixture: unique base bytes={}, carrier bytes={}, max canonical source input={}, compact index payload={}, max frontier records={}, max ledger entries={}, max structural fact metadata={}",
        metrics.usage.base_walk.canonical_bytes,
        metrics.caller_owned_carrier_bytes,
        metrics.max_source_input_bytes,
        metrics.retained_index_bytes,
        metrics.max_frontier_records,
        metrics.max_ledger_entries,
        metrics.max_fact_metadata_bytes,
    );
    assert_eq!(
        metrics.usage.base_walk.canonical_bytes,
        independent_bytes
            + base_objects
                .values()
                .map(|bytes| bytes.len() as u64)
                .sum::<u64>()
    );
    assert_eq!(metrics.usage.base_walk.objects, 12);
    assert_eq!(metrics.usage.candidate_walk.objects, 12);
    assert_eq!(metrics.usage.changed_total_bytes, 3);
    assert_eq!(metrics.usage.required_unique_ids, 3);
    assert!(max_generated_source <= LARGE + 16);
    assert!(metrics.max_source_input_bytes <= LARGE + 16);
    assert_eq!(
        metrics.retained_index_bytes,
        3 * (32 + 2 * std::mem::size_of::<usize>() + 8)
    );
    assert!(metrics.max_frontier_records <= 11);
    assert!(metrics.max_ledger_entries <= 12);
    assert!(metrics.max_fact_metadata_bytes < 4096);
    assert_eq!(metrics.caller_owned_carrier_bytes, update.len());
    assert!(
        metrics.caller_owned_carrier_bytes < 4096,
        "caller-owned carrier measured separately"
    );
}
