//! Restored private lookup counters retain the native candidate cap.
use super::*;
use crate::store::{Precondition, index};
use crate::timers::{DueTimer, Fired, TimerCtx, TimerHandler};
use std::panic::{AssertUnwindSafe, catch_unwind};

fn closure_lookup() -> (Rig, TestExtraction, TicketV1, Hash, Key) {
    let rig = Rig::new();
    let target = [223; 32];
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: 1,
        chunk_size: 0,
        chunks: vec![target],
    });
    let (tree, commit, head) = tree_head(&[manifest.id().unwrap()]);
    let (ticket, id) = rig.add(&pack(&[manifest, tree, commit]));
    assert!(rig.check(&[(&ticket, id)], head).is_err());
    let extension = TestExtraction::new(&rig);
    for _ in 0..100 {
        if rig
            .job(&ticket.pack_id)
            .unwrap()
            .extraction
            .as_ref()
            .is_some_and(|x| x.stage == 10)
        {
            break;
        }
        tick(&rig, &extension, rig.store.as_ref(), true);
        rig.clock.advance(1_000);
    }
    let job = rig.job(&ticket.pack_id).unwrap();
    let x = job.extraction.as_ref().unwrap();
    assert_eq!(x.stage, 10);
    let key = lookup_key(&rig, &ticket.pack_id, x.group, target, target, 0);
    (rig, extension, ticket, target, key)
}

fn lookup_key(rig: &Rig, pack: &Hash, group: Hash, target: Hash, id: Hash, level: u32) -> Key {
    let object = hash(&[target.as_slice(), id.as_slice()].concat());
    lookup_key_object(rig, pack, group, object, level)
}

fn lookup_key_object(rig: &Rig, pack: &Hash, group: Hash, object: Hash, level: u32) -> Key {
    let mut digest = mkit_core::hash::Hasher::new();
    digest.update(b"mkit-extraction-row:v1");
    digest.update(b"member-lookup");
    digest.update(&group);
    digest.update(&object);
    digest.update(&level.to_be_bytes());
    keys::verify_row(
        &rig.repo.name,
        pack,
        keys::VC_CANDIDATE,
        Some(&digest.finalize()),
    )
}

fn lookup_counter(rig: &Rig, key: &Key, rows: u32, pages: u32) {
    let mut bytes = vec![crate::store::codec::CODEC_V1];
    bytes.extend(
        serde_json::to_vec(&serde_json::json!({
            "after": [], "rows": rows, "pages": pages, "partitions": []
        }))
        .unwrap(),
    );
    block_on(rig.store.apply(
        &rig.source(),
        Batch::new().put(key.clone(), Value::new(bytes)),
    ))
    .unwrap();
}

fn lookup_fire(rig: &Rig, extension: &TestExtraction, pack: Hash) -> Result<Fired, StoreError> {
    block_on(extraction_handler(rig, extension.clone()).fire(
        &TimerCtx {
            store: rig.store.as_ref(),
            partition: &rig.source(),
            now_ms: u64::try_from(rig.clock.now_ms()).unwrap(),
        },
        &DueTimer {
            due_at_ms: u64::try_from(rig.clock.now_ms()).unwrap(),
            kind: crate::timers::registry::kinds::VERIFY,
            reference: Bytes::from(checkpoint::timer_reference(&rig.repo.name, &pack)),
            value: Value::default(),
        },
    ))
}

fn apply_fire(rig: &Rig, fired: Fired) {
    match fired {
        Fired::Done(batch) | Fired::Reschedule { batch, .. } => {
            assert_eq!(
                block_on(rig.store.apply(&rig.source(), batch)).unwrap(),
                BatchOutcome::Committed
            );
        }
        Fired::Retry => {}
    }
    rig.clock.advance(1_000);
}

#[test]
fn restored_lookup_page_overflow_fails_closed_without_panicking() {
    let (rig, extension, ticket, _, key) = closure_lookup();
    lookup_counter(&rig, &key, 1, u32::MAX);
    for _ in 0..10 {
        let result = catch_unwind(AssertUnwindSafe(|| {
            lookup_fire(&rig, &extension, ticket.pack_id)
        }));
        assert!(
            result.is_ok(),
            "restored lookup pages overflowed before validation"
        );
        match result.unwrap() {
            Err(StoreError::Corrupt(_)) => return,
            Err(other) => panic!("unexpected lookup failure: {other}"),
            Ok(fired) => apply_fire(&rig, fired),
        }
    }
    panic!("the corrupt lookup counter was not rejected");
}

#[test]
fn restored_lookup_cannot_accept_a_member_beyond_candidate_4096() {
    let (rig, extension, ticket, target, key) = closure_lookup();
    let index = codec::encode_object_index(
        &target,
        &index::IndexValue {
            frame_offset: 8,
            frame_length: 8,
            wire_type: 0,
            decoded_size: 1,
            chain_depth: 0,
            delta_base: None,
        },
    )
    .unwrap();
    let partition = rig.shards.object_index(&rig.repo, &target);
    for ordinal in 1_u8..=8 {
        let mut pack = [0; 32];
        pack[31] = ordinal;
        block_on(rig.store.apply(
            &partition,
            Batch::new().put(
                keys::object_index(&rig.repo.name, &target, &pack),
                index.clone(),
            ),
        ))
        .unwrap();
        if ordinal == 8 {
            block_on(rig.store.apply(
                &rig.shards.membership(&rig.repo, &BlobKey::pack(pack)),
                Batch::new().put(keys::membership(&rig.repo.name, &pack), Value::default()),
            ))
            .unwrap();
        }
    }
    lookup_counter(&rig, &key, 4095, 0);
    for _ in 0..10 {
        apply_fire(&rig, lookup_fire(&rig, &extension, ticket.pack_id).unwrap());
        if block_on(rig.store.get(&rig.source(), &key))
            .unwrap()
            .is_none()
        {
            assert_eq!(
                rig.job(&ticket.pack_id).unwrap().outcome,
                Some(checkpoint::Outcome::ClosureCapped),
                "a candidate past the native4096-row prefix was accepted"
            );
            return;
        }
    }
    panic!("the remaining one-candidate lookup page did not finish");
}

#[test]
fn restored_head_reconstruction_ignores_a_different_bases_lookup_prefix() {
    let (rig, extension, ticket, _, _) = closure_lookup();
    let base = Object::Blob(Blob { data: vec![19; 10] });
    let id = base.id().unwrap();
    seed_member(&rig, id, &serialize(&base).unwrap());
    let target = [210; 32];
    let old_base = [255; 32];
    assert!(id < old_base);
    let key = keys::verify_job(&rig.repo.name, &ticket.pack_id);
    let prior = block_on(rig.store.get(&rig.source(), &key))
        .unwrap()
        .unwrap();
    let mut job = rig.job(&ticket.pack_id).unwrap();
    job.extraction_head = Some(target);
    let x = job.extraction.as_mut().unwrap();
    x.stage = 13;
    x.reconstruction = Some(checkpoint::MemberCursor {
        target,
        next: id,
        level: 1,
        ..checkpoint::MemberCursor::default()
    });
    let group = x.group;
    let batch = checkpoint::write_job(
        Batch::new().require(Precondition::Equals(key, prior.clone())),
        &mut job,
        Some(&prior),
        &rig.repo.name,
        &ticket.pack_id,
    )
    .unwrap();
    assert_eq!(
        block_on(rig.store.apply(&rig.source(), batch)).unwrap(),
        BatchOutcome::Committed
    );
    let legacy = lookup_key_object(&rig, &ticket.pack_id, group, target, 1);
    let old = lookup_key(&rig, &ticket.pack_id, group, target, old_base, 1);
    let after = keys::object_index(&rig.repo.name, &old_base, &[255; 32]);
    let mut bytes = vec![crate::store::codec::CODEC_V1];
    bytes.extend(
        serde_json::to_vec(&serde_json::json!({
            "after": after.as_bytes(), "rows": 8, "pages": 0, "partitions": []
        }))
        .unwrap(),
    );
    let row = Value::new(bytes);
    block_on(
        rig.store.apply(
            &rig.source(),
            Batch::new()
                .put(legacy, row.clone())
                .put(old.clone(), row.clone()),
        ),
    )
    .unwrap();
    apply_fire(&rig, lookup_fire(&rig, &extension, ticket.pack_id).unwrap());
    let observed = rig.job(&ticket.pack_id).unwrap();
    assert_eq!(observed.outcome, None);
    let cursor = observed.extraction.unwrap().reconstruction.unwrap();
    assert!(
        cursor.ascending,
        "the old base's prefix hid the new base's first member"
    );
    assert_eq!(cursor.next, id);
    assert_eq!(
        block_on(rig.store.get(&rig.source(), &old)).unwrap(),
        Some(row)
    );
}
