//! Frozen verify checkpoints and strict deferred-refusal syntax.
use super::*;
use crate::evidence::checkpoint::{self, CheckpointView};
use mkit_core::pack::window::WindowCursor;

#[test]
fn canonical_verify_checkpoint_fixture() {
    let mut writer = PackWriter::new();
    for data in [b"alpha".as_slice(), b"beta".as_slice()] {
        let (id, bytes) = blob(data);
        writer.push_raw(id, &bytes).unwrap();
    }
    let pack = writer.finish().unwrap();
    let mut host = Host::new(&pack);
    let mut machine = driver(&pack);
    let snapshot = loop {
        match machine.step().unwrap() {
            Step::Request(request) => host.serve(&mut machine, &request).unwrap(),
            Step::ProvisionalObject(fragment) => {
                host.fragments
                    .entry(fragment.ordinal)
                    .or_default()
                    .extend_from_slice(fragment.bytes);
            }
            Step::RetainEvidence(page) => {
                let commitment = page.commitment;
                host.pages.push((commitment, page.bytes.to_vec()));
                machine.acknowledge_retention(commitment).unwrap();
            }
            Step::Progress | Step::ReleasePage(_) => (),
            Step::Complete(_) => panic!("first entry boundary was not checkpointable"),
        }
        if machine.ordinal == 1
            && let Ok(snapshot) = machine.checkpoint()
        {
            break Checkpoint::from_bytes(snapshot.bytes(), limits()).unwrap();
        }
    };
    let mut state = snapshot.decode(limits()).unwrap();
    // Portable cumulative history is independent of pointer width, allocator,
    // and incidental checkpoint attempts made by this fixture generator.
    state.meta.usage.peak_resident_bytes = 50_000_000;
    state.meta.usage.work = 2_000_000;
    let snapshot = checkpoint::encode(
        &CheckpointView {
            meta: state.meta,
            integrity: None,
            cursor: &state.cursor,
            verify: state.verify,
        },
        limits(),
    )
    .unwrap();
    assert_eq!(state.meta.ordinal, 1);
    assert!(state.verify.unwrap().deferred_failure.is_none());
    let cursor = WindowCursor::from_bytes(&state.cursor).unwrap();
    assert!(cursor.metadata().unwrap().exact());
    assert!(!cursor.metadata().unwrap().integrity_only());
    if let Some(destination) = std::env::var_os("MKIT_CHECKPOINT_FIXTURES") {
        let destination = std::path::PathBuf::from(destination);
        write_checkpoint_fixtures(&destination, &snapshot, &state);
    } else {
        assert_eq!(
            snapshot.bytes(),
            include_bytes!("../../../../fixtures/evidence/checkpoint-verify.bin")
        );
    }
    let mut resumed = VerifyDriver::resume(
        source(&pack),
        REPOSITORY,
        profile(),
        limits(),
        18,
        &snapshot,
    )
    .unwrap();
    assert_eq!(host.finish(&mut resumed).unwrap().counts().entries, 2);

    // Unknown deferred codes and incoherent phase/mode combinations never encode.
    let mut verify = state.verify.unwrap();
    verify.deferred_failure = Some((&failure(FailureCode::UnavailableInput)).into());
    assert_eq!(
        checkpoint::encode(
            &CheckpointView {
                meta: state.meta,
                integrity: None,
                cursor: &state.cursor,
                verify: Some(verify)
            },
            limits()
        )
        .unwrap_err()
        .code,
        FailureCode::InvalidCheckpoint
    );
}

#[test]
fn deferred_absence_checkpoint_resumes_only_hashing_without_prefix_or_page_reads() {
    let pack = missing_base_pack_with_unread_tail();
    let mut host = Host::new(&pack);
    host.members_absent = true;
    let execution_limits = VerifyLimits {
        acquisition_bytes: 64 << 10,
        ..limits()
    };
    let mut machine =
        VerifyDriver::new(source(&pack), REPOSITORY, profile(), execution_limits, 17).unwrap();
    let mut acquired_end = 0;
    let snapshot = loop {
        match machine.step().unwrap() {
            Step::Request(request) => {
                if let Request::Bytes {
                    source: ByteSource::Pack(_),
                    range,
                    ..
                } = request
                {
                    acquired_end = acquired_end.max(range.offset + range.len);
                }
                host.serve(&mut machine, &request).unwrap();
            }
            Step::ProvisionalObject(fragment) => host
                .fragments
                .entry(fragment.ordinal)
                .or_default()
                .extend_from_slice(fragment.bytes),
            Step::RetainEvidence(page) => {
                let commitment = page.commitment;
                host.pages.push((commitment, page.bytes.to_vec()));
                machine.acknowledge_retention(commitment).unwrap();
            }
            Step::Progress | Step::ReleasePage(_) => (),
            Step::Complete(_) => panic!("missing base accepted"),
        }
        if machine.phase == Phase::Drain
            && let Ok(checkpoint) = machine.checkpoint()
        {
            break Checkpoint::from_bytes(checkpoint.bytes(), execution_limits).unwrap();
        }
    };
    assert!(acquired_end < pack.len() as u64);
    assert_checkpoint_preserves_integrity_work(&snapshot, execution_limits);
    let state = snapshot.decode(execution_limits).unwrap();
    assert_eq!(
        state.meta.phase,
        crate::evidence::checkpoint::CheckpointPhase::Drain
    );
    assert_eq!(
        state
            .verify
            .unwrap()
            .deferred_failure
            .unwrap()
            .failure()
            .code,
        FailureCode::ExternalBaseAbsent
    );
    let mut resumed = VerifyDriver::resume(
        source(&pack),
        REPOSITORY,
        profile(),
        execution_limits,
        18,
        &snapshot,
    )
    .unwrap();
    let failure = loop {
        match resumed.step() {
            Err(failure) => break failure,
            Ok(Step::Request(request)) => {
                if let Request::Bytes {
                    source: ByteSource::Pack(_),
                    range,
                    ..
                } = request
                {
                    assert!(
                        range.offset >= acquired_end,
                        "drain reread an acquired prefix"
                    );
                } else {
                    panic!("drain requested content or evidence pages");
                }
                host.serve(&mut resumed, &request).unwrap();
            }
            Ok(Step::Progress | Step::ReleasePage(_)) => (),
            Ok(_) => panic!("drain emitted provisional or verified evidence"),
        }
    };
    assert_eq!(failure.code, FailureCode::ExternalBaseAbsent);
}

fn write_checkpoint_fixtures(
    destination: &std::path::Path,
    snapshot: &Checkpoint,
    state: &crate::evidence::checkpoint::CheckpointState,
) {
    std::fs::write(destination.join("checkpoint-verify.bin"), snapshot.bytes()).unwrap();
    let m = state.meta;
    let last = m.last_retained.unwrap();
    let json = serde_json::json!({
        "description": "Format version 3 all-entry verification checkpoint at the first entry boundary, including exact acquisition hash frontiers and bounded deferred-refusal state.",
        "format_version": 3, "expected": "Checkpoint", "encoded_bytes": snapshot.bytes().len(),
        "cursor_bytes": state.cursor.len(), "generation": m.generation,
        "header": { "version": m.header.unwrap().0, "count": m.header.unwrap().1 },
        "ordinal": m.ordinal, "payload_bytes": m.payload, "phase": "decode", "integrity": null,
        "profile": "indexed", "ruleset": 1, "repository": hash::to_hex(&m.repository.0),
        "source_id": hash::to_hex(&m.source.id), "source_len": m.source.len,
        "source_binding": hash::to_hex(&m.source.binding.0), "sequence": m.sequence,
        "trailer": hash::to_hex(&m.trailer), "retention_count": m.retention_count,
        "last_retained": {"digest": hash::to_hex(&last.digest), "kind": 5, "len": last.len, "items": last.items},
        "deferred_failure": null,
        "usage": {"resident_bytes": m.usage.resident_bytes, "peak_resident_bytes": m.usage.peak_resident_bytes,
            "evidence_bytes": m.usage.evidence_bytes, "evidence_pages": m.usage.evidence_pages, "work": m.usage.work}
    });
    std::fs::write(
        destination.join("checkpoint-verify.json"),
        format!("{}\n", serde_json::to_string_pretty(&json).unwrap()),
    )
    .unwrap();
    let header = include_bytes!("../../../../fixtures/evidence/checkpoint-header.bin");
    let mut unsupported = header[..header.len() - 32].to_vec();
    unsupported[4..6].copy_from_slice(&4_u16.to_le_bytes());
    let checksum = hash::domain_digest(b"mkit-checkpoint-checksum:v1", &unsupported);
    unsupported.extend_from_slice(&checksum);
    std::fs::write(destination.join("checkpoint-version.bin"), &unsupported).unwrap();
}

fn missing_base_pack_with_unread_tail() -> Vec<u8> {
    let mut writer = PackWriter::new_raw_only();
    let (id, bytes) = blob(b"first");
    writer.push_raw(id, &bytes).unwrap();
    let (missing, base) = blob(b"external base");
    let (_, target) = blob(b"delta target");
    let insertion = 12 + 5 + bytes.len();
    for byte in 1..=3 {
        let (id, bytes) = blob(&vec![byte; 60 << 10]);
        writer.push_raw(id, &bytes).unwrap();
    }
    let mut pack = writer.finish().unwrap();
    pack.truncate(pack.len() - 32);
    let mut payload = missing.to_vec();
    payload.extend_from_slice(&delta::encode(&base, &target).unwrap());
    let mut frame = vec![2];
    frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
    frame.extend_from_slice(&payload);
    pack.splice(insertion..insertion, frame);
    pack[8..12].copy_from_slice(&5_u32.to_le_bytes());
    pack.extend_from_slice(&hash::hash(&pack));
    pack
}

fn assert_checkpoint_preserves_integrity_work(snapshot: &Checkpoint, limits: VerifyLimits) {
    let mut state = snapshot.decode(limits).unwrap();
    let end = WindowCursor::from_bytes(&state.cursor)
        .unwrap()
        .metadata()
        .unwrap()
        .acquired_end()
        .unwrap();
    let remaining_work = 3 * (state.meta.source.len - end);
    assert!(remaining_work > 0);
    state.meta.usage.work = limits.work - remaining_work;
    let view = |meta| CheckpointView {
        meta,
        integrity: None,
        cursor: &state.cursor,
        verify: state.verify,
    };
    // The exact remaining hashing allowance is valid state; ordinary work
    // cannot consume even one unit of that protected allowance.
    let exact = checkpoint::encode(&view(state.meta), limits).unwrap();
    assert_eq!(
        Checkpoint::from_bytes(exact.bytes(), limits)
            .unwrap()
            .bytes(),
        exact.bytes()
    );
    state.meta.usage.work += 1;
    assert_eq!(
        checkpoint::encode(&view(state.meta), limits)
            .unwrap_err()
            .code,
        FailureCode::InvalidCheckpoint
    );
}
