//! Borrowed MKWU and local staged-step evidence against committed v1 bytes.
#![allow(clippy::unwrap_used)] // each unwrap is a fixture assertion

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::num::NonZeroUsize;

use mkit_core::object::id_from_object;
use mkit_core::partial::{
    ChangedPairRecord, ChangedPairStep, CheckedMkwu, PartialLimits, RecipientLimits,
    RequiredFileRecord, SnapshotRole, SnapshotWalkLimits, SnapshotWalkRecord, SnapshotWalkUsage,
    StagedInventoryCursor, StagedUpdateLimitsV1, StagedUpdateUsageV1, StagedValidationContext,
    advance_changed_pair, advance_required_file, advance_snapshot_walk, advance_staged_inventory,
    apply_changed_accounting, apply_inventory_accounting, apply_required_accounting,
    apply_walk_accounting, default_staged_inspection_limits, inspect_snapshot_object,
    inspect_staged_candidate, inspect_staged_inventory_object, next_manifest_ids,
    parse_mkwu_header_prefix, start_changed_pairs, start_snapshot_walk,
};
use mkit_core::sign::sign_commit;
use mkit_core::verify::{ObjectSource, VerifyError};
use mkit_core::{
    Blob, ChunkedBlob, Commit, EntryMode, Hash, Identity, KeyPair, Object, Tree, TreeEntry,
    serialize, verify_partial_update,
};

const GOLDEN: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/golden/partial_update/ordinary_update.bin"
));

struct BaseSource(BTreeMap<Hash, Vec<u8>>);

impl ObjectSource for BaseSource {
    fn fetch(&mut self, id: &Hash) -> Result<Option<Cow<'_, [u8]>>, VerifyError> {
        Ok(self.0.get(id).map(|bytes| Cow::Borrowed(bytes.as_slice())))
    }
}

fn put(map: &mut BTreeMap<Hash, Vec<u8>>, object: Object) -> Hash {
    let bytes = serialize(&object).unwrap();
    let id = id_from_object(&object, &bytes);
    map.insert(id, bytes);
    id
}

fn base_source() -> (BaseSource, Hash, Hash) {
    let mut map = BTreeMap::new();
    let old = put(
        &mut map,
        Object::Blob(Blob {
            data: b"old golden bytes".to_vec(),
        }),
    );
    let tree = put(
        &mut map,
        Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: b"a.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: old,
            }],
        }),
    );
    let key = KeyPair::from_seed([21; 32]);
    let mut commit = Commit::new_unannotated(
        tree,
        vec![],
        Identity::ed25519(key.public.0),
        key.public.0,
        b"golden base".to_vec(),
        1_700_000_000,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &key).unwrap().0;
    let root = put(&mut map, Object::Commit(commit));
    (BaseSource(map), root, tree)
}

fn context<'a>(checked: &CheckedMkwu<'a>) -> StagedValidationContext {
    StagedValidationContext::new(
        checked.header().clone(),
        PartialLimits::V1,
        StagedUpdateLimitsV1::default(),
        default_staged_inspection_limits(),
    )
    .unwrap()
}

#[test]
fn borrowed_envelope_and_inventory_consume_committed_golden() {
    let (mut source, base_id, _) = base_source();
    let checked = CheckedMkwu::open(
        GOLDEN,
        GOLDEN.len() as u64,
        mkit_core::hash::hash(GOLDEN),
        base_id,
        PartialLimits::V1,
        StagedUpdateLimitsV1::default(),
    )
    .unwrap();
    assert_eq!(checked.header().base_id(), base_id);
    assert_eq!(checked.header().changes().len(), 1);
    assert_eq!(
        checked.header().pack_len(),
        checked
            .pack()
            .entries()
            .map(|e| e.payload().len() + 5)
            .sum::<usize>()
            + 44
    );
    assert!(matches!(
        parse_mkwu_header_prefix(
            &GOLDEN[..checked.header().pack_offset()],
            &PartialLimits::V1,
            &StagedUpdateLimitsV1::default()
        )
        .unwrap(),
        mkit_core::partial::HeaderPrefix::Parsed(_)
    ));
    let context = context(&checked);
    let mut cursor = StagedInventoryCursor::default();
    let mut usage = checked.initial_usage();
    let mut inventory = BTreeMap::new();
    for entry in checked.pack().entries() {
        let fact = inspect_staged_inventory_object(entry.payload(), &context).unwrap();
        let step =
            advance_staged_inventory(&cursor, entry.ordinal().into(), &fact, &context).unwrap();
        usage = apply_inventory_accounting(usage, &step, &context).unwrap();
        cursor = step.cursor();
        inventory.insert(step.id(), entry.payload().to_vec());
    }
    assert_eq!(cursor.count, u64::from(checked.pack().entry_count()));
    assert_eq!(usage.inventory_work, 2 * cursor.count);
    let candidate = inventory.get(&checked.header().candidate_id()).unwrap();
    inspect_staged_candidate(candidate, &context).unwrap();
    assert!(
        verify_partial_update(
            base_id,
            GOLDEN,
            &mut source,
            &PartialLimits::V1,
            &RecipientLimits::DEFAULT
        )
        .is_ok()
    );

    let mut wrong = GOLDEN.to_vec();
    wrong.push(0);
    assert!(
        CheckedMkwu::open(
            &wrong,
            wrong.len() as u64,
            mkit_core::hash::hash(&wrong),
            base_id,
            PartialLimits::V1,
            StagedUpdateLimitsV1::default()
        )
        .is_err()
    );
    assert!(
        CheckedMkwu::open(
            GOLDEN,
            GOLDEN.len() as u64,
            [0; 32],
            base_id,
            PartialLimits::V1,
            StagedUpdateLimitsV1::default()
        )
        .is_err()
    );
    assert!(
        CheckedMkwu::open(
            GOLDEN,
            GOLDEN.len() as u64,
            mkit_core::hash::hash(GOLDEN),
            [9; 32],
            PartialLimits::V1,
            StagedUpdateLimitsV1::default()
        )
        .is_err()
    );
}

#[test]
fn actual_frontier_and_visit_reservation_match_old_recipient() {
    let (mut source, base_id, old_tree_id) = base_source();
    let checked = CheckedMkwu::open(
        GOLDEN,
        GOLDEN.len() as u64,
        mkit_core::hash::hash(GOLDEN),
        base_id,
        PartialLimits::V1,
        StagedUpdateLimitsV1::default(),
    )
    .unwrap();
    let context = context(&checked);
    let supplied = checked
        .pack()
        .entries()
        .map(|entry| {
            let fact = inspect_staged_inventory_object(entry.payload(), &context).unwrap();
            (fact.object().id(), entry.payload().to_vec())
        })
        .collect::<BTreeMap<_, _>>();
    let base = inspect_snapshot_object(
        base_id,
        source.0.get(&base_id).unwrap(),
        SnapshotRole::BaseRoot,
        context.inspection(),
    )
    .unwrap();
    let candidate_bytes = supplied.get(&checked.header().candidate_id()).unwrap();
    let candidate = inspect_staged_candidate(candidate_bytes, &context).unwrap();
    let width = NonZeroUsize::new(64).unwrap();
    let mut usage = checked.initial_usage();
    let start = start_changed_pairs(&base, &candidate, &context).unwrap();
    usage = apply_changed_accounting(usage, &start, &[candidate.id()], &context).unwrap();
    let root_record = start.successors().first().unwrap();
    let new_tree_id = root_record.new_id();
    assert_eq!(root_record.old_id(), old_tree_id);
    let old_tree = inspect_snapshot_object(
        old_tree_id,
        source.0.get(&old_tree_id).unwrap(),
        SnapshotRole::Tree,
        context.inspection(),
    )
    .unwrap();
    let new_tree = inspect_snapshot_object(
        new_tree_id,
        supplied.get(&new_tree_id).unwrap(),
        SnapshotRole::Tree,
        context.inspection(),
    )
    .unwrap();
    let visit = advance_changed_pair(root_record, &old_tree, &new_tree, &context, width).unwrap();
    usage = apply_changed_accounting(usage, &visit, &[new_tree_id], &context).unwrap();
    let page = advance_changed_pair(
        visit.successors().first().unwrap(),
        &old_tree,
        &new_tree,
        &context,
        width,
    )
    .unwrap();
    usage = apply_changed_accounting(usage, &page, &[], &context).unwrap();
    assert_eq!(page.matched_indices(), &[0]);
    assert!(page.successors().is_empty());
    let record = page.files().first().unwrap();
    let RequiredFileRecord::Visit {
        expected_file_id, ..
    } = record
    else {
        panic!("file Visit");
    };
    let file = inspect_snapshot_object(
        *expected_file_id,
        supplied.get(expected_file_id).unwrap(),
        SnapshotRole::File,
        context.inspection(),
    )
    .unwrap();
    let file_step = advance_required_file(record, &file, &[], width, &usage, &context).unwrap();
    let before = usage.changed_total_bytes;
    usage = apply_required_accounting(usage, &file_step, &[*expected_file_id], &context).unwrap();
    assert_eq!(
        usage.changed_total_bytes - before,
        file.blob_len().unwrap() as u64
    );
    assert!(file_step.complete());
    assert_eq!(usage.diff_pair_visits, 1);
    assert_eq!(usage.diff_compared_entries, 1);
    let required = BTreeSet::from([candidate.id(), new_tree_id, *expected_file_id]);
    let supplied_ids = supplied.keys().copied().collect::<BTreeSet<_>>();
    assert_eq!(required, supplied_ids, "complete golden supply is exact");
    assert!(
        verify_partial_update(
            base_id,
            GOLDEN,
            &mut source,
            &PartialLimits::V1,
            &RecipientLimits::DEFAULT
        )
        .is_ok()
    );
}

#[test]
fn corrupt_inventory_and_contexts_refuse_locally() {
    let (_, base_id, _) = base_source();
    let checked = CheckedMkwu::open(
        GOLDEN,
        GOLDEN.len() as u64,
        mkit_core::hash::hash(GOLDEN),
        base_id,
        PartialLimits::V1,
        StagedUpdateLimitsV1::default(),
    )
    .unwrap();
    let context = context(&checked);
    let entry = checked.pack().entries().next().unwrap();
    let fact = inspect_staged_inventory_object(entry.payload(), &context).unwrap();
    let cursor = StagedInventoryCursor::default();
    assert!(advance_staged_inventory(&cursor, 1, &fact, &context).is_err());
    let first = advance_staged_inventory(&cursor, 0, &fact, &context).unwrap();
    assert!(advance_staged_inventory(&first.cursor(), 1, &fact, &context).is_err());
    let mut lower = PartialLimits::V1;
    lower.max_object_bytes = 1;
    let low_context = StagedValidationContext::new(
        checked.header().clone(),
        lower,
        StagedUpdateLimitsV1::default(),
        mkit_core::partial::ObjectInspectionLimits {
            max_object_bytes: 1,
            max_tree_bytes: 1,
            max_tree_entries: 0,
            max_manifest_chunks: 0,
        },
    )
    .unwrap();
    assert!(inspect_staged_inventory_object(entry.payload(), &low_context).is_err());
    let mut over = StagedUpdateLimitsV1::default();
    over.max_origin_work += 1;
    assert!(
        StagedValidationContext::new(
            checked.header().clone(),
            PartialLimits::V1,
            over,
            default_staged_inspection_limits()
        )
        .is_err()
    );
}

#[test]
fn header_prefix_distinguishes_incomplete_from_invalid_and_legacy_vectors_stay_pinned() {
    let limits = PartialLimits::V1;
    let staged = StagedUpdateLimitsV1::default();
    assert!(matches!(
        parse_mkwu_header_prefix(&GOLDEN[..4], &limits, &staged).unwrap(),
        mkit_core::partial::HeaderPrefix::NeedMore
    ));
    let mut wrong_magic = GOLDEN[..8].to_vec();
    wrong_magic[0] ^= 1;
    assert!(parse_mkwu_header_prefix(&wrong_magic, &limits, &staged).is_err());
    let mut nonminimal = GOLDEN.to_vec();
    nonminimal.splice(69..70, [0x81, 0x00]);
    assert!(parse_mkwu_header_prefix(&nonminimal, &limits, &staged).is_err());
    let denied = [
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/golden/partial_update/neg_pack_length.bin"
        ))
        .as_slice(),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/golden/partial_update/neg_pack_hash.bin"
        ))
        .as_slice(),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/golden/partial_update/neg_trailing.bin"
        ))
        .as_slice(),
    ];
    assert!(mkit_core::PartialUpdate::decode(GOLDEN, &limits).is_ok());
    for bytes in denied {
        assert!(mkit_core::PartialUpdate::decode(bytes, &limits).is_err());
    }
}

#[test]
fn file_visit_rejects_aggregate_and_forged_record_before_chunk_request() {
    let (_, base_id, _) = base_source();
    let checked = CheckedMkwu::open(
        GOLDEN,
        GOLDEN.len() as u64,
        mkit_core::hash::hash(GOLDEN),
        base_id,
        PartialLimits::V1,
        StagedUpdateLimitsV1::default(),
    )
    .unwrap();
    let context = context(&checked);
    let change = &checked.header().changes()[0];
    let payload = checked
        .pack()
        .entries()
        .find(|entry| {
            inspect_staged_inventory_object(entry.payload(), &context)
                .unwrap()
                .object()
                .id()
                == change.new_id()
        })
        .unwrap();
    let file = inspect_snapshot_object(
        change.new_id(),
        payload.payload(),
        SnapshotRole::File,
        context.inspection(),
    )
    .unwrap();
    let record = RequiredFileRecord::Visit {
        change_index: 0,
        expected_file_id: change.new_id(),
    };
    let width = NonZeroUsize::new(64).unwrap();
    let mut usage = checked.initial_usage();
    usage.changed_total_bytes =
        PartialLimits::V1.max_total_selected_bytes as u64 - file.blob_len().unwrap() as u64 + 1;
    assert!(advance_required_file(&record, &file, &[], width, &usage, &context).is_err());
    let wrong_index = RequiredFileRecord::Visit {
        change_index: 1,
        expected_file_id: change.new_id(),
    };
    assert!(
        advance_required_file(
            &wrong_index,
            &file,
            &[],
            width,
            &checked.initial_usage(),
            &context
        )
        .is_err()
    );
    let hidden_id = RequiredFileRecord::Visit {
        change_index: 0,
        expected_file_id: base_id,
    };
    assert!(
        advance_required_file(
            &hidden_id,
            &file,
            &[],
            width,
            &checked.initial_usage(),
            &context
        )
        .is_err()
    );
    let mut corrupt = checked.initial_usage();
    corrupt.required_unique_ids = StagedUpdateLimitsV1::default().max_required_unique_ids + 1;
    assert!(advance_required_file(&record, &file, &[], width, &corrupt, &context).is_err());
}

fn complete_walk(
    objects: &BTreeMap<Hash, Vec<u8>>,
    root: Hash,
    role: SnapshotRole,
    limits: SnapshotWalkLimits,
) -> Option<SnapshotWalkUsage> {
    let mut queue = VecDeque::from([start_snapshot_walk(root, role).ok()?]);
    let mut seen = BTreeMap::<Hash, u64>::new();
    let mut usage = SnapshotWalkUsage::default();
    let width = NonZeroUsize::new(64).unwrap();
    while let Some(record) = queue.pop_front() {
        let bytes = objects.get(&record.id())?;
        let parent = inspect_snapshot_object(
            record.id(),
            bytes,
            record.role(),
            default_staged_inspection_limits(),
        )
        .ok()?;
        let chunks = if matches!(record, SnapshotWalkRecord::ManifestPage { .. }) {
            next_manifest_ids(&record, &parent, width)
                .ok()?
                .iter()
                .map(|id| {
                    inspect_snapshot_object(
                        *id,
                        objects.get(id)?,
                        SnapshotRole::Chunk,
                        default_staged_inspection_limits(),
                    )
                    .ok()
                })
                .collect::<Option<Vec<_>>>()?
        } else {
            Vec::new()
        };
        let step = advance_snapshot_walk(&record, &parent, &chunks, width, &limits).ok()?;
        let mut new = BTreeSet::new();
        for observation in step.observations() {
            if let Some(old_len) = seen.get(&observation.id()) {
                if *old_len != observation.canonical_len() {
                    return None;
                }
            } else {
                new.insert(observation.id());
            }
        }
        usage = apply_walk_accounting(
            usage,
            &step,
            &new.iter().copied().collect::<Vec<_>>(),
            limits,
        )
        .ok()?;
        for observation in step.observations() {
            seen.insert(observation.id(), observation.canonical_len());
        }
        queue.extend(step.successors().iter().copied());
    }
    Some(usage)
}

#[test]
fn complete_source_only_base_and_candidate_walks_are_independent() {
    let (mut source, base_id, _) = base_source();
    let checked = CheckedMkwu::open(
        GOLDEN,
        GOLDEN.len() as u64,
        mkit_core::hash::hash(GOLDEN),
        base_id,
        PartialLimits::V1,
        StagedUpdateLimitsV1::default(),
    )
    .unwrap();
    let limits = StagedUpdateLimitsV1::default();
    let base = complete_walk(&source.0, base_id, SnapshotRole::BaseRoot, limits.base_walk).unwrap();
    assert_eq!(base.objects, 3);
    // The uploaded candidate cannot repair a missing source-only base Blob.
    let old_blob = source
        .0
        .keys()
        .copied()
        .find(|id| {
            *id != base_id && {
                matches!(
                    mkit_core::deserialize(source.0.get(id).unwrap()).unwrap(),
                    Object::Blob(_)
                )
            }
        })
        .unwrap();
    let mut missing = source.0.clone();
    missing.remove(&old_blob);
    assert!(complete_walk(&missing, base_id, SnapshotRole::BaseRoot, limits.base_walk).is_none());
    let mut all = source.0.clone();
    for entry in checked.pack().entries() {
        let context = context(&checked);
        let fact = inspect_staged_inventory_object(entry.payload(), &context).unwrap();
        all.insert(fact.object().id(), entry.payload().to_vec());
    }
    let candidate = complete_walk(
        &all,
        checked.header().candidate_id(),
        SnapshotRole::CandidateRoot,
        limits.candidate_walk,
    )
    .unwrap();
    assert!(candidate.objects >= 3);
    assert!(
        verify_partial_update(
            base_id,
            GOLDEN,
            &mut source,
            &PartialLimits::V1,
            &RecipientLimits::DEFAULT
        )
        .is_ok()
    );
}

#[test]
fn facts_cannot_cross_into_a_stricter_context() {
    let (source, base_id, old_tree_id) = base_source();
    let checked = CheckedMkwu::open(
        GOLDEN,
        GOLDEN.len() as u64,
        mkit_core::hash::hash(GOLDEN),
        base_id,
        PartialLimits::V1,
        StagedUpdateLimitsV1::default(),
    )
    .unwrap();
    let generous = context(&checked);
    let supplied = checked
        .pack()
        .entries()
        .map(|entry| {
            let fact = inspect_staged_inventory_object(entry.payload(), &generous).unwrap();
            (fact.object().id(), entry.payload().to_vec())
        })
        .collect::<BTreeMap<_, _>>();
    let first = checked.pack().entries().next().unwrap();
    let generous_inventory = inspect_staged_inventory_object(first.payload(), &generous).unwrap();
    let mut portable = PartialLimits::V1;
    portable.max_object_bytes = first.payload().len() - 1;
    let mut inspection = default_staged_inspection_limits();
    inspection.max_object_bytes = portable.max_object_bytes;
    let lower = StagedValidationContext::new(
        checked.header().clone(),
        portable,
        StagedUpdateLimitsV1::default(),
        inspection,
    )
    .unwrap();
    assert!(
        advance_staged_inventory(
            &StagedInventoryCursor::default(),
            0,
            &generous_inventory,
            &lower
        )
        .is_err()
    );

    let base = inspect_snapshot_object(
        base_id,
        source.0.get(&base_id).unwrap(),
        SnapshotRole::BaseRoot,
        generous.inspection(),
    )
    .unwrap();
    let candidate = inspect_staged_candidate(
        supplied.get(&checked.header().candidate_id()).unwrap(),
        &generous,
    )
    .unwrap();
    let mut portable = PartialLimits::V1;
    portable.max_commit_message_bytes = 1;
    let lower_message = StagedValidationContext::new(
        checked.header().clone(),
        portable,
        StagedUpdateLimitsV1::default(),
        default_staged_inspection_limits(),
    )
    .unwrap();
    assert!(start_changed_pairs(&base, &candidate, &lower_message).is_err());

    let root_record = start_changed_pairs(&base, &candidate, &generous)
        .unwrap()
        .successors()[0]
        .clone();
    let old_tree = inspect_snapshot_object(
        old_tree_id,
        source.0.get(&old_tree_id).unwrap(),
        SnapshotRole::Tree,
        generous.inspection(),
    )
    .unwrap();
    let new_tree = inspect_snapshot_object(
        root_record.new_id(),
        supplied.get(&root_record.new_id()).unwrap(),
        SnapshotRole::Tree,
        generous.inspection(),
    )
    .unwrap();
    let mut portable = PartialLimits::V1;
    portable.max_tree_entries = 0;
    let mut inspection = default_staged_inspection_limits();
    inspection.max_tree_entries = 0;
    let lower_tree = StagedValidationContext::new(
        checked.header().clone(),
        portable,
        StagedUpdateLimitsV1::default(),
        inspection,
    )
    .unwrap();
    assert!(
        advance_changed_pair(
            &root_record,
            &old_tree,
            &new_tree,
            &lower_tree,
            NonZeroUsize::new(64).unwrap()
        )
        .is_err()
    );

    let mut portable = PartialLimits::V1;
    portable.max_changed_paths = 0;
    assert!(
        StagedValidationContext::new(
            checked.header().clone(),
            portable,
            StagedUpdateLimitsV1::default(),
            default_staged_inspection_limits()
        )
        .is_err()
    );
}

fn append_varint(out: &mut Vec<u8>, mut value: usize) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

#[test]
fn native_near_pack_cap_borrows_large_distinct_payloads_without_decoded_map() {
    use mkit_core::pack::{PackWriter, pack_key};

    let (_, base_id, _) = base_source();
    let reference = CheckedMkwu::open(
        GOLDEN,
        GOLDEN.len() as u64,
        mkit_core::hash::hash(GOLDEN),
        base_id,
        PartialLimits::V1,
        StagedUpdateLimitsV1::default(),
    )
    .unwrap();
    // This tests framing and per-object inventory input, not a semantically
    // valid edit: the filler objects are not in the exact required set.
    let mut writer = PackWriter::new_raw_only();
    let mut expected_payload = 0usize;
    for seed in 0..47u8 {
        let object = Object::Blob(Blob {
            data: vec![seed; 1024 * 1024 - 10],
        });
        let bytes = serialize(&object).unwrap();
        expected_payload += bytes.len();
        writer
            .push_raw(id_from_object(&object, &bytes), &bytes)
            .unwrap();
    }
    let mut pack = writer.finish().unwrap();
    assert!(pack.len() > 46 * 1024 * 1024);
    assert!(pack.len() <= PartialLimits::V1.max_raw_pack_bytes);
    let mut carrier = Vec::with_capacity(pack.len() + 256);
    carrier.extend_from_slice(b"MKWU");
    carrier.push(1);
    carrier.extend_from_slice(&base_id);
    carrier.extend_from_slice(&reference.header().candidate_id());
    append_varint(&mut carrier, 1);
    let change = &reference.header().changes()[0];
    append_varint(&mut carrier, change.path().len());
    for component in change.path() {
        append_varint(&mut carrier, component.len());
        carrier.extend_from_slice(component);
    }
    carrier.push(change.old_mode() as u8);
    carrier.extend_from_slice(&change.old_id());
    carrier.extend_from_slice(&change.new_id());
    carrier.extend_from_slice(&pack_key(&pack));
    carrier.extend_from_slice(&(pack.len() as u64).to_be_bytes());
    append_varint(&mut carrier, pack.len());
    carrier.append(&mut pack);
    let checked = CheckedMkwu::open(
        &carrier,
        carrier.len() as u64,
        mkit_core::hash::hash(&carrier),
        base_id,
        PartialLimits::V1,
        StagedUpdateLimitsV1::default(),
    )
    .unwrap();
    assert_eq!(checked.pack().entry_count(), 47);
    assert_eq!(
        checked
            .pack()
            .entries()
            .map(|entry| entry.payload().len())
            .sum::<usize>(),
        expected_payload
    );
    assert!(checked.initial_usage().update_bytes < 48 * 1024 * 1024 + 128 * 1024);
    assert_eq!(
        reference.header().candidate_id(),
        checked.header().candidate_id()
    );
}

#[test]
fn changed_pair_continuation_is_required_and_undeclared_fanout_refuses() {
    let (_, base_id, _) = base_source();
    let checked = CheckedMkwu::open(
        GOLDEN,
        GOLDEN.len() as u64,
        mkit_core::hash::hash(GOLDEN),
        base_id,
        PartialLimits::V1,
        StagedUpdateLimitsV1::default(),
    )
    .unwrap();
    let context = context(&checked);
    let change = &context.header().changes()[0];
    let mut old_entries = Vec::new();
    let mut new_entries = Vec::new();
    for number in 0..64 {
        let entry = TreeEntry {
            name: format!("A{number:02}").into_bytes(),
            mode: EntryMode::Blob,
            object_hash: [number as u8; 32],
        };
        old_entries.push(entry.clone());
        new_entries.push(entry);
    }
    old_entries.push(TreeEntry {
        name: b"a.txt".to_vec(),
        mode: EntryMode::Blob,
        object_hash: change.old_id(),
    });
    new_entries.push(TreeEntry {
        name: b"a.txt".to_vec(),
        mode: EntryMode::Blob,
        object_hash: change.new_id(),
    });
    let old_object = Object::Tree(Tree {
        entries: old_entries,
    });
    let new_object = Object::Tree(Tree {
        entries: new_entries,
    });
    let old_bytes = serialize(&old_object).unwrap();
    let new_bytes = serialize(&new_object).unwrap();
    let old_id = id_from_object(&old_object, &old_bytes);
    let new_id = id_from_object(&new_object, &new_bytes);
    let old = inspect_snapshot_object(old_id, &old_bytes, SnapshotRole::Tree, context.inspection())
        .unwrap();
    let new = inspect_snapshot_object(new_id, &new_bytes, SnapshotRole::Tree, context.inspection())
        .unwrap();
    let width = NonZeroUsize::new(64).unwrap();
    let visit = advance_changed_pair(
        &ChangedPairRecord::Visit {
            old_id,
            new_id,
            path: Vec::new(),
        },
        &old,
        &new,
        &context,
        width,
    )
    .unwrap();
    let first = advance_changed_pair(&visit.successors()[0], &old, &new, &context, width).unwrap();
    assert!(first.matched_indices().is_empty());
    assert_eq!(first.successors().len(), 1, "continuation is mandatory");
    let second = advance_changed_pair(&first.successors()[0], &old, &new, &context, width).unwrap();
    assert_eq!(second.matched_indices(), &[0]);
    assert!(second.successors().is_empty());
    // Omitting the first step's continuation would leave the declared-change
    // ledger unmatched; the local step cannot itself certify completion.
    assert_ne!(
        first.matched_indices().len(),
        context.header().changes().len()
    );

    let mut grafted = match old_object {
        Object::Tree(tree) => tree,
        _ => unreachable!(),
    };
    grafted.entries[0].mode = EntryMode::Tree;
    let mut other = grafted.clone();
    other.entries[0].object_hash = [255; 32];
    let grafted_object = Object::Tree(grafted);
    let other_object = Object::Tree(other);
    let grafted_bytes = serialize(&grafted_object).unwrap();
    let other_bytes = serialize(&other_object).unwrap();
    let grafted_id = id_from_object(&grafted_object, &grafted_bytes);
    let other_id = id_from_object(&other_object, &other_bytes);
    let grafted_fact = inspect_snapshot_object(
        grafted_id,
        &grafted_bytes,
        SnapshotRole::Tree,
        context.inspection(),
    )
    .unwrap();
    let other_fact = inspect_snapshot_object(
        other_id,
        &other_bytes,
        SnapshotRole::Tree,
        context.inspection(),
    )
    .unwrap();
    let visit = advance_changed_pair(
        &ChangedPairRecord::Visit {
            old_id: grafted_id,
            new_id: other_id,
            path: Vec::new(),
        },
        &grafted_fact,
        &other_fact,
        &context,
        width,
    )
    .unwrap();
    assert!(
        advance_changed_pair(
            &visit.successors()[0],
            &grafted_fact,
            &other_fact,
            &context,
            width
        )
        .is_err()
    );
}

#[test]
fn old_recipient_and_staged_exact_set_both_refuse_extra_supply() {
    let bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/golden/partial_update/neg_extra_object.bin"
    ));
    let (mut source, base_id, old_tree_id) = base_source();
    let checked = CheckedMkwu::open(
        bytes,
        bytes.len() as u64,
        mkit_core::hash::hash(bytes),
        base_id,
        PartialLimits::V1,
        StagedUpdateLimitsV1::default(),
    )
    .unwrap();
    let context = context(&checked);
    let supplied = checked
        .pack()
        .entries()
        .map(|entry| {
            let fact = inspect_staged_inventory_object(entry.payload(), &context).unwrap();
            (fact.object().id(), entry.payload().to_vec())
        })
        .collect::<BTreeMap<_, _>>();
    let candidate = inspect_staged_candidate(
        supplied.get(&checked.header().candidate_id()).unwrap(),
        &context,
    )
    .unwrap();
    let base = inspect_snapshot_object(
        base_id,
        source.0.get(&base_id).unwrap(),
        SnapshotRole::BaseRoot,
        context.inspection(),
    )
    .unwrap();
    let start = start_changed_pairs(&base, &candidate, &context).unwrap();
    let pair = &start.successors()[0];
    let old = inspect_snapshot_object(
        old_tree_id,
        source.0.get(&old_tree_id).unwrap(),
        SnapshotRole::Tree,
        context.inspection(),
    )
    .unwrap();
    let new = inspect_snapshot_object(
        pair.new_id(),
        supplied.get(&pair.new_id()).unwrap(),
        SnapshotRole::Tree,
        context.inspection(),
    )
    .unwrap();
    let width = NonZeroUsize::new(64).unwrap();
    let visit = advance_changed_pair(pair, &old, &new, &context, width).unwrap();
    let page = advance_changed_pair(&visit.successors()[0], &old, &new, &context, width).unwrap();
    assert_eq!(page.matched_indices(), &[0]);
    let required = BTreeSet::from([
        candidate.id(),
        pair.new_id(),
        page.files()[0].expected_file_id(),
    ]);
    let supplied_ids = supplied.keys().copied().collect::<BTreeSet<_>>();
    assert!(required.is_subset(&supplied_ids));
    assert_ne!(
        required, supplied_ids,
        "extra supplied object must fail the anti-join"
    );
    assert!(
        verify_partial_update(
            base_id,
            bytes,
            &mut source,
            &PartialLimits::V1,
            &RecipientLimits::DEFAULT
        )
        .is_err()
    );
}

// A protocol model, not SQL durability evidence. The service must make the
// same predecessor/ledger/counter/all-successor decision atomically.
#[derive(Clone)]
struct ModelDiffJob {
    generation: u64,
    queue: VecDeque<ChangedPairRecord>,
    files: VecDeque<RequiredFileRecord>,
    seen: BTreeMap<Hash, u64>,
    usage: StagedUpdateUsageV1,
}

impl ModelDiffJob {
    fn commit(
        &mut self,
        generation: u64,
        prior: &ChangedPairRecord,
        step: &ChangedPairStep,
        proposed: &[ChangedPairRecord],
        proposed_files: &[RequiredFileRecord],
        context: &StagedValidationContext,
    ) -> Result<(), ()> {
        if generation != self.generation
            || self.queue.front() != Some(prior)
            || proposed != step.successors()
            || proposed_files != step.files()
        {
            return Err(());
        }
        let mut next_seen = self.seen.clone();
        let mut newly = BTreeSet::new();
        for item in step.observations() {
            if let Some(old) = next_seen.insert(item.id(), item.canonical_len()) {
                if old != item.canonical_len() {
                    return Err(());
                }
            } else {
                newly.insert(item.id());
            }
        }
        let next_usage = apply_changed_accounting(
            self.usage,
            step,
            &newly.into_iter().collect::<Vec<_>>(),
            context,
        )
        .map_err(|_| ())?;
        self.queue.pop_front();
        self.queue.extend(proposed.iter().cloned());
        self.files.extend(proposed_files.iter().cloned());
        self.seen = next_seen;
        self.usage = next_usage;
        Ok(())
    }
}

#[test]
fn model_driver_requires_all_successors_prior_lengths_and_fenced_generation() {
    let (source, base_id, old_tree_id) = base_source();
    let checked = CheckedMkwu::open(
        GOLDEN,
        GOLDEN.len() as u64,
        mkit_core::hash::hash(GOLDEN),
        base_id,
        PartialLimits::V1,
        StagedUpdateLimitsV1::default(),
    )
    .unwrap();
    let context = context(&checked);
    let supplied = checked
        .pack()
        .entries()
        .map(|entry| {
            let fact = inspect_staged_inventory_object(entry.payload(), &context).unwrap();
            (fact.object().id(), entry.payload().to_vec())
        })
        .collect::<BTreeMap<_, _>>();
    let base = inspect_snapshot_object(
        base_id,
        source.0.get(&base_id).unwrap(),
        SnapshotRole::BaseRoot,
        context.inspection(),
    )
    .unwrap();
    let candidate = inspect_staged_candidate(
        supplied.get(&checked.header().candidate_id()).unwrap(),
        &context,
    )
    .unwrap();
    let root = start_changed_pairs(&base, &candidate, &context).unwrap();
    let record = root.successors()[0].clone();
    let old = inspect_snapshot_object(
        old_tree_id,
        source.0.get(&old_tree_id).unwrap(),
        SnapshotRole::Tree,
        context.inspection(),
    )
    .unwrap();
    let new = inspect_snapshot_object(
        record.new_id(),
        supplied.get(&record.new_id()).unwrap(),
        SnapshotRole::Tree,
        context.inspection(),
    )
    .unwrap();
    let visit = advance_changed_pair(
        &record,
        &old,
        &new,
        &context,
        NonZeroUsize::new(64).unwrap(),
    )
    .unwrap();
    let mut job = ModelDiffJob {
        generation: 3,
        queue: VecDeque::from([record.clone()]),
        files: VecDeque::new(),
        seen: BTreeMap::new(),
        usage: checked.initial_usage(),
    };
    assert!(job.commit(3, &record, &visit, &[], &[], &context).is_err());
    assert_eq!(job.queue.front(), Some(&record));
    assert_eq!(job.usage.diff_pair_visits, 0);
    assert!(
        job.commit(2, &record, &visit, visit.successors(), &[], &context)
            .is_err()
    );
    job.seen.insert(record.new_id(), 1);
    assert!(
        job.commit(3, &record, &visit, visit.successors(), &[], &context)
            .is_err()
    );
    job.seen.clear();
    let restored = job.clone();
    job.commit(3, &record, &visit, visit.successors(), &[], &context)
        .unwrap();
    assert_eq!(job.usage.diff_pair_visits, 1);
    assert_eq!(job.queue.front(), visit.successors().first());
    // A restart from a trusted pre-commit record may replay the same exact
    // step; it cannot treat a partly enqueued step as committed.
    let mut replay = restored;
    replay
        .commit(3, &record, &visit, visit.successors(), &[], &context)
        .unwrap();
    assert_eq!(replay.usage, job.usage);
    assert_eq!(replay.queue, job.queue);
    let page_record = job.queue.front().unwrap().clone();
    let page = advance_changed_pair(
        &page_record,
        &old,
        &new,
        &context,
        NonZeroUsize::new(64).unwrap(),
    )
    .unwrap();
    assert!(
        job.commit(3, &page_record, &page, page.successors(), &[], &context)
            .is_err()
    );
    assert!(job.files.is_empty());
    job.commit(
        3,
        &page_record,
        &page,
        page.successors(),
        page.files(),
        &context,
    )
    .unwrap();
    assert_eq!(job.files.len(), 1);
}

fn manifest_context(file_id: Hash, portable: PartialLimits) -> StagedValidationContext {
    let mut prefix = Vec::new();
    prefix.extend_from_slice(b"MKWU");
    prefix.push(1);
    prefix.extend_from_slice(&[1; 32]);
    prefix.extend_from_slice(&[2; 32]);
    append_varint(&mut prefix, 1);
    append_varint(&mut prefix, 1);
    append_varint(&mut prefix, 4);
    prefix.extend_from_slice(b"file");
    prefix.push(EntryMode::Blob as u8);
    prefix.extend_from_slice(&[3; 32]);
    prefix.extend_from_slice(&file_id);
    prefix.extend_from_slice(&[0; 32]);
    prefix.extend_from_slice(&44u64.to_be_bytes());
    append_varint(&mut prefix, 44);
    let mkit_core::partial::HeaderPrefix::Parsed(header) =
        parse_mkwu_header_prefix(&prefix, &portable, &StagedUpdateLimitsV1::default()).unwrap()
    else {
        panic!("complete prefix");
    };
    StagedValidationContext::new(
        header,
        portable,
        StagedUpdateLimitsV1::default(),
        default_staged_inspection_limits(),
    )
    .unwrap()
}

#[test]
fn repeated_cdc_chunks_reserve_once_but_charge_each_position() {
    use mkit_core::partial::next_required_chunk_ids;

    let blob = Object::Blob(Blob {
        data: b"xy".to_vec(),
    });
    let blob_bytes = serialize(&blob).unwrap();
    let blob_id = id_from_object(&blob, &blob_bytes);
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: 4,
        chunk_size: 0,
        chunks: vec![blob_id, blob_id],
    });
    let manifest_bytes = serialize(&manifest).unwrap();
    let manifest_id = id_from_object(&manifest, &manifest_bytes);
    let context = manifest_context(manifest_id, PartialLimits::V1);
    let file = inspect_snapshot_object(
        manifest_id,
        &manifest_bytes,
        SnapshotRole::File,
        context.inspection(),
    )
    .unwrap();
    let record = RequiredFileRecord::Visit {
        change_index: 0,
        expected_file_id: manifest_id,
    };
    let width = NonZeroUsize::new(1).unwrap();
    let before = StagedUpdateUsageV1::default();
    assert!(next_required_chunk_ids(&record, &file, &before, &context, width).is_err());
    let visit = advance_required_file(&record, &file, &[], width, &before, &context).unwrap();
    let mut usage = apply_required_accounting(before, &visit, &[manifest_id], &context).unwrap();
    assert_eq!(usage.changed_total_bytes, 4);
    assert!(!visit.complete());
    let mut record = visit.successors()[0].clone();
    for position in 0..2 {
        assert_eq!(
            next_required_chunk_ids(&record, &file, &usage, &context, width).unwrap(),
            &[blob_id]
        );
        let chunk = inspect_snapshot_object(
            blob_id,
            &blob_bytes,
            SnapshotRole::Chunk,
            context.inspection(),
        )
        .unwrap();
        let step =
            advance_required_file(&record, &file, &[chunk], width, &usage, &context).unwrap();
        let newly_required = if position == 0 {
            &[blob_id][..]
        } else {
            &[][..]
        };
        usage = apply_required_accounting(usage, &step, newly_required, &context).unwrap();
        assert_eq!(
            usage.changed_total_bytes, 4,
            "final page never charges twice"
        );
        if position == 0 {
            record = step.successors()[0].clone();
        } else {
            assert!(step.complete());
        }
    }
    assert_eq!(usage.origin_work, 3);
    assert_eq!(usage.required_unique_ids, 2);

    let mut lower = PartialLimits::V1;
    lower.max_selected_file_bytes = 3;
    let lower_context = manifest_context(manifest_id, lower);
    assert!(
        advance_required_file(
            &RequiredFileRecord::Visit {
                change_index: 0,
                expected_file_id: manifest_id,
            },
            &file,
            &[],
            width,
            &before,
            &lower_context
        )
        .is_err()
    );
    assert!(next_required_chunk_ids(&record, &file, &usage, &lower_context, width).is_err());

    let zero = Object::Blob(Blob { data: Vec::new() });
    let zero_bytes = serialize(&zero).unwrap();
    let zero_id = id_from_object(&zero, &zero_bytes);
    let cdc = Object::ChunkedBlob(ChunkedBlob {
        total_size: 2,
        chunk_size: 0,
        chunks: vec![zero_id, blob_id],
    });
    let cdc_bytes = serialize(&cdc).unwrap();
    let cdc_id = id_from_object(&cdc, &cdc_bytes);
    let cdc_context = manifest_context(cdc_id, PartialLimits::V1);
    let cdc_fact = inspect_snapshot_object(
        cdc_id,
        &cdc_bytes,
        SnapshotRole::File,
        cdc_context.inspection(),
    )
    .unwrap();
    let cdc_visit = advance_required_file(
        &RequiredFileRecord::Visit {
            change_index: 0,
            expected_file_id: cdc_id,
        },
        &cdc_fact,
        &[],
        NonZeroUsize::new(2).unwrap(),
        &before,
        &cdc_context,
    )
    .unwrap();
    let zero_fact = inspect_snapshot_object(
        zero_id,
        &zero_bytes,
        SnapshotRole::Chunk,
        cdc_context.inspection(),
    )
    .unwrap();
    let blob_fact = inspect_snapshot_object(
        blob_id,
        &blob_bytes,
        SnapshotRole::Chunk,
        cdc_context.inspection(),
    )
    .unwrap();
    let cdc_usage = apply_required_accounting(before, &cdc_visit, &[cdc_id], &cdc_context).unwrap();
    assert!(
        advance_required_file(
            &cdc_visit.successors()[0],
            &cdc_fact,
            &[zero_fact, blob_fact],
            NonZeroUsize::new(2).unwrap(),
            &cdc_usage,
            &cdc_context
        )
        .unwrap()
        .complete()
    );

    let fixed = Object::ChunkedBlob(ChunkedBlob {
        total_size: 2,
        chunk_size: 2,
        chunks: vec![zero_id, blob_id],
    });
    let fixed_bytes = serialize(&fixed).unwrap();
    let fixed_id = id_from_object(&fixed, &fixed_bytes);
    let fixed_context = manifest_context(fixed_id, PartialLimits::V1);
    let fixed_fact = inspect_snapshot_object(
        fixed_id,
        &fixed_bytes,
        SnapshotRole::File,
        fixed_context.inspection(),
    )
    .unwrap();
    let fixed_visit = advance_required_file(
        &RequiredFileRecord::Visit {
            change_index: 0,
            expected_file_id: fixed_id,
        },
        &fixed_fact,
        &[],
        NonZeroUsize::new(2).unwrap(),
        &before,
        &fixed_context,
    )
    .unwrap();
    let zero_fact = inspect_snapshot_object(
        zero_id,
        &zero_bytes,
        SnapshotRole::Chunk,
        fixed_context.inspection(),
    )
    .unwrap();
    let blob_fact = inspect_snapshot_object(
        blob_id,
        &blob_bytes,
        SnapshotRole::Chunk,
        fixed_context.inspection(),
    )
    .unwrap();
    let fixed_usage =
        apply_required_accounting(before, &fixed_visit, &[fixed_id], &fixed_context).unwrap();
    assert!(
        advance_required_file(
            &fixed_visit.successors()[0],
            &fixed_fact,
            &[zero_fact, blob_fact],
            NonZeroUsize::new(2).unwrap(),
            &fixed_usage,
            &fixed_context
        )
        .is_err()
    );
}
