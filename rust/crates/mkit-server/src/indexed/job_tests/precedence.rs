//! SPEC-PACKFILE §§6.1–6.2: integrity precedes competing entry faults.
use super::*;
use mkit_primitives::{
    error::FailureCode,
    evidence::{PackSource, RepositoryId, SourceBinding},
    limits::{IndexedProfile, VerifyLimits},
    pack_verify::{Acquisition, ByteSource, Request, Response, Step, verify::VerifyDriver},
};

fn inline(
    rig: &Rig,
    ticket: &TicketV1,
    id: Hash,
    head: Hash,
) -> Result<super::super::verify::StagedCommits, crate::ServerError> {
    block_on(super::super::verify::verify_ticketed(
        rig.blobs.as_ref(),
        rig.store.as_ref(),
        rig.shards.as_ref(),
        &rig.repo,
        &rig.source(),
        std::slice::from_ref(ticket),
        &[id],
        head,
        rig.cfg,
        true,
        rig.clock.as_ref(),
        rig.recorder.as_ref(),
    ))
}

fn corrupt_trailer(mut pack: Vec<u8>) -> Vec<u8> {
    let last = pack.len() - 1;
    pack[last] ^= 1;
    pack
}

fn missing_base() -> (Vec<u8>, Hash) {
    let (base, base_raw) = blob(1, 3_000);
    let (_, target_raw) = blob(2, 3_000);
    (thin(base, &base_raw, &target_raw), base)
}

// Deterministic incompressible padding keeps these restart fixtures multi-window
// even when another workspace crate enables the writer's zstd compression.
fn padding_blob(tag: u16) -> (Hash, Vec<u8>) {
    let mut data = vec![0; 768 << 10];
    let mut hasher = blake3::Hasher::new();
    hasher.update(&tag.to_le_bytes());
    hasher.finalize_xof().fill(&mut data);
    let object = Object::Blob(Blob { data });
    (object.id().unwrap(), serialize(&object).unwrap())
}

fn primitive_integrity_refusal(bytes: &[u8]) -> FailureCode {
    let mut driver = VerifyDriver::new(
        PackSource {
            id: hash(bytes),
            len: bytes.len() as u64,
            binding: SourceBinding([7; 32]),
        },
        RepositoryId([9; 32]),
        IndexedProfile {
            pack_bytes: 2 << 30,
            decoded_bytes: 2 << 30,
            delta_depth: 50,
        },
        VerifyLimits::indexed(),
        1,
    )
    .unwrap();
    loop {
        match driver.step() {
            Err(failure) => return failure.code,
            Ok(Step::RetainEvidence(page)) => {
                let commitment = page.commitment;
                driver.acknowledge_retention(commitment).unwrap();
            }
            Ok(Step::Request(Request::Bytes {
                request,
                source: source @ ByteSource::Pack(_),
                range,
            })) => {
                if let Err(failure) = driver.supply(Response::Bytes {
                    request,
                    source,
                    range,
                    value: Acquisition::Present(
                        &bytes[usize::try_from(range.offset).unwrap()
                            ..usize::try_from(range.offset + range.len).unwrap()],
                    ),
                }) {
                    return failure.code;
                }
            }
            Ok(Step::Progress) => (),
            // In particular, no external-base lookup may precede integrity.
            other => panic!("unexpected step before integrity refusal {other:?}"),
        }
    }
}

fn assert_competing_fault(bytes: &[u8], head: Hash) {
    assert_eq!(
        primitive_integrity_refusal(bytes),
        FailureCode::PackfileCorrupted
    );
    for aged in [false, true] {
        let oracle = Rig::new();
        let (ticket, id) = oracle.add(bytes);
        if aged {
            oracle
                .clock
                .advance(i64::try_from(oracle.cfg.relay_lag_bound_ms).unwrap() + 1);
        }
        let inline_error = inline(&oracle, &ticket, id, head).unwrap_err();
        assert_eq!(inline_error.code(), crate::error::Code::InvalidArgument);
        assert_eq!(inline_error.public_message(), "object hash mismatch");
        let expected = rejected(&oracle, &ticket.pack_id);
        assert_eq!(
            expected,
            Some(("invalid_argument".into(), "object hash mismatch".into()))
        );
        let rig = Rig::new();
        let (ticket, id) = rig.add(bytes);
        rig.create(&ticket, id);
        if aged {
            rig.clock
                .advance(i64::try_from(rig.cfg.relay_lag_bound_ms).unwrap() + 1);
        }
        rig.drive(|rig| rig.finished(&ticket.pack_id));
        let scheduled = rig.check(&[(&ticket, id)], head).unwrap_err();
        assert_eq!(scheduled.code(), inline_error.code());
        assert_eq!(scheduled.public_message(), inline_error.public_message());
        assert_eq!(rejected(&rig, &ticket.pack_id), expected);
        assert_eq!(rig.job(&ticket.pack_id).unwrap().outcome, None);
    }
}

#[test]
fn inline_integrity_precedes_missing_external_base() {
    let (pack, head) = missing_base();
    let bytes = corrupt_trailer(pack);
    let rig = Rig::new();
    let (ticket, id) = rig.add(&bytes);
    rig.clock
        .advance(i64::try_from(rig.cfg.relay_lag_bound_ms).unwrap() + 1);
    let error = inline(&rig, &ticket, id, head).unwrap_err();
    assert_eq!(error.code(), crate::error::Code::InvalidArgument);
    assert_eq!(error.public_message(), "object hash mismatch");
    assert_eq!(
        rejected(&rig, &ticket.pack_id),
        Some(("invalid_argument".into(), "object hash mismatch".into()))
    );
}

#[test]
fn scheduled_integrity_precedes_missing_external_base() {
    let (pack, head) = missing_base();
    assert_competing_fault(&corrupt_trailer(pack), head);
}

#[test]
fn integrity_precedes_a_forward_in_pack_base() {
    let (base, base_raw) = blob(1, 3_000);
    let (_, target_raw) = blob(2, 3_000);
    let mut writer = PackWriter::new();
    writer
        .push_delta(
            &base,
            &mkit_core::delta::encode(&base_raw, &target_raw).unwrap(),
        )
        .unwrap();
    writer.push_raw(base, &base_raw).unwrap();
    assert_competing_fault(&corrupt_trailer(writer.finish().unwrap()), base);
}

#[test]
fn integrity_precedes_bad_signature() {
    let (pack, head) = tree_pack(1, 200);
    let last_signature_byte = pack.len() - 33;
    let bad_signature = repaired(pack, last_signature_byte);
    assert_competing_fault(&corrupt_trailer(bad_signature), head);
}

#[test]
fn integrity_precedes_invalid_frame_type() {
    let (mut pack, head) = tree_pack(1, 200);
    pack[12] = 0x7f;
    assert_competing_fault(&corrupt_trailer(pack), head);
}

#[test]
fn integrity_precedes_indexed_canonical_cap() {
    let object = Object::Blob(Blob {
        data: vec![17; usize::try_from(super::super::geometry::PAYLOAD_BYTES).unwrap() + 1],
    });
    let bytes = serialize(&object).unwrap();
    let mut writer = PackWriter::new();
    writer.push_raw(object.id().unwrap(), &bytes).unwrap();
    assert_competing_fault(
        &corrupt_trailer(writer.finish().unwrap()),
        object.id().unwrap(),
    );
}

#[test]
fn failure_integrity_resumes_from_durable_windows_without_visibility() {
    let (base, base_raw) = blob(1, 3_000);
    let (_, target_raw) = blob(2, 3_000);
    let mut writer = PackWriter::new();
    writer
        .push_delta(
            &base,
            &mkit_core::delta::encode(&base_raw, &target_raw).unwrap(),
        )
        .unwrap();
    for n in 0..6 {
        let (id, bytes) = padding_blob(n);
        writer.push_raw(id, &bytes).unwrap();
    }
    let bytes = corrupt_trailer(writer.finish().unwrap());
    assert!(bytes.len() as u64 > 3 * WINDOW);
    let rig = Rig::new();
    let (ticket, id) = rig.add(&bytes);
    rig.create(&ticket, id);
    let mut observed = 0;
    rig.drive(|rig| {
        let job = rig.job(&ticket.pack_id).unwrap();
        if job.integrity.is_some() {
            observed += 1;
            assert!(!job.usable());
            assert!(!matches!(
                rig.state(&ticket.pack_id),
                Some(VerificationV1::Verified { .. })
            ));
            let decoded = decode_job(&super::super::checkpoint::encode_job(&job)).unwrap();
            assert_eq!(decoded.integrity, job.integrity);
            assert!(rig.rows(&ticket.pack_id, keys::VC_FRAME).is_empty());
        }
        rig.finished(&ticket.pack_id)
    });
    assert!(
        observed >= 3,
        "several fresh handlers must resume failure-only progress"
    );
    assert_eq!(
        rejected(&rig, &ticket.pack_id),
        Some(("invalid_argument".into(), "object hash mismatch".into()))
    );
}

#[test]
fn membership_arriving_during_integrity_is_retried_fresh() {
    let (base, base_raw) = blob(1, 3_000);
    let (_, target_raw) = blob(2, 3_000);
    let mut writer = PackWriter::new();
    writer
        .push_delta(
            &base,
            &mkit_core::delta::encode(&base_raw, &target_raw).unwrap(),
        )
        .unwrap();
    for n in 0..3 {
        let (id, bytes) = padding_blob(n);
        writer.push_raw(id, &bytes).unwrap();
    }
    let bytes = writer.finish().unwrap();
    assert!(bytes.len() as u64 > 3 * WINDOW);
    let rig = Rig::new();
    let (ticket, id) = rig.add(&bytes);
    rig.create(&ticket, id);
    rig.clock
        .advance(i64::try_from(rig.cfg.relay_lag_bound_ms).unwrap() + 1);
    rig.drive(|rig| rig.job(&ticket.pack_id).unwrap().integrity.is_some());
    seed_member(&rig, base, &base_raw);
    rig.drive(|rig| rig.job(&ticket.pack_id).unwrap().phase != Phase::Decode);
    let job = rig.job(&ticket.pack_id).unwrap();
    assert_eq!(
        job.outcome, None,
        "the initial absence is not a terminal snapshot"
    );
    assert_eq!(job.entries, 4);
    assert!(job.integrity.is_none());
    assert!(rejected(&rig, &ticket.pack_id).is_none());
}

#[test]
fn valid_missing_base_reuses_integrity_while_retrying_membership() {
    let (bytes, head) = missing_base();
    let rig = Rig::new();
    let (ticket, id) = rig.add(&bytes);
    rig.create(&ticket, id);
    rig.drive(|rig| {
        serde_json::to_value(rig.job(&ticket.pack_id).unwrap()).unwrap()["integrity"]["offset"]
            .as_u64()
            == Some(bytes.len() as u64)
    });
    let marker = rig.job(&ticket.pack_id).unwrap().integrity;
    for _ in 0..3 {
        rig.tick();
        rig.clock.advance(1_000);
        assert_eq!(rig.job(&ticket.pack_id).unwrap().integrity, marker);
        assert!(rejected(&rig, &ticket.pack_id).is_none());
    }
    rig.clock
        .advance(i64::try_from(rig.cfg.relay_lag_bound_ms).unwrap());
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    let error = rig.check(&[(&ticket, id)], head).unwrap_err();
    assert_eq!(error.code(), crate::Code::FailedPrecondition);
    assert_eq!(
        error.public_message(),
        "delta base not available in this repository"
    );
    assert!(rejected(&rig, &ticket.pack_id).is_none());
}

#[test]
fn a_changed_source_discards_failure_integrity_progress() {
    let (bytes, _) = missing_base();
    let rig = Rig::new();
    let (ticket, id) = rig.add(&bytes);
    rig.create(&ticket, id);
    rig.drive(|rig| rig.job(&ticket.pack_id).unwrap().integrity.is_some());
    *rig.windows.flip_after.lock().unwrap() = Some(rig.windows.reads.load(Ordering::SeqCst));
    rig.drive(|rig| rig.job(&ticket.pack_id).unwrap().restarts > 0);
    let job = rig.job(&ticket.pack_id).unwrap();
    assert!(job.integrity.is_none());
    assert!(!job.usable());
    assert!(rejected(&rig, &ticket.pack_id).is_none());
}
