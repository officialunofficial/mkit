//! SPEC-PACKFILE 6.1: one refusal order and one classification across the inline
//! path, the scheduled path and the primitive driver. Every case compares the
//! complete observable outcome: code, message and what is persisted.
use super::*;
use crate::store::{BlockEntry, ContentIndex};
use mkit_primitives::error::{Failure, FailureCode, Persistence};
use mkit_primitives::{
    evidence::{PackSource, RepositoryId, SourceBinding},
    limits::{IndexedProfile, VerifyLimits},
    pack_verify::{Acquisition, ByteSource, Request, Response, Step, verify::VerifyDriver},
};

/// What a caller and the store can observe after one refusal.
#[derive(Debug, PartialEq, Eq)]
struct Observed {
    code: crate::Code,
    message: String,
    /// The persisted rejection of each consumed pack, in ticket order.
    persisted: Vec<Option<(String, String)>>,
}

fn observe(
    rig: &Rig,
    result: Result<super::super::verify::StagedCommits, crate::ServerError>,
    packs: &[Hash],
) -> Observed {
    let error = result.unwrap_err();
    // The first ticket with a refusal wins. Scheduled verification runs every
    // job to completion, so later tickets' rows are not part of the outcome.
    let mut persisted = Vec::new();
    for pack in packs {
        let row = rejected(rig, pack);
        let stop = row.is_some();
        persisted.push(row);
        if stop {
            break;
        }
    }
    Observed {
        code: error.code(),
        message: error.public_message().to_owned(),
        persisted,
    }
}

fn inline_all(rig: &Rig, items: &[(&TicketV1, Hash)], head: Hash) -> Observed {
    let tickets: Vec<_> = items.iter().map(|(ticket, _)| (*ticket).clone()).collect();
    let ids: Vec<_> = items.iter().map(|(_, id)| *id).collect();
    let result = block_on(super::super::verify::verify_ticketed(
        rig.blobs.as_ref(),
        rig.store.as_ref(),
        rig.shards.as_ref(),
        &rig.repo,
        &rig.source(),
        &tickets,
        &ids,
        head,
        rig.cfg,
        true,
        rig.clock.as_ref(),
        rig.recorder.as_ref(),
    ));
    let packs: Vec<_> = items.iter().map(|(ticket, _)| ticket.pack_id).collect();
    observe(rig, result, &packs)
}

fn scheduled_all(rig: &Rig, items: &[(&TicketV1, Hash)], head: Hash) -> Observed {
    for (ticket, id) in items {
        rig.create(ticket, *id);
    }
    let packs: Vec<_> = items.iter().map(|(ticket, _)| ticket.pack_id).collect();
    rig.drive(|rig| packs.iter().all(|pack| rig.finished(pack)));
    let result = rig.check(items, head);
    observe(rig, result, &packs)
}

fn block(rig: &Rig, object: &Hash) {
    let now = u64::try_from(rig.clock.now_ms()).unwrap();
    block_on(
        ContentIndex::new(crate::store::BorrowedStore(rig.store.as_ref())).block(
            &crate::takedown::DenialCapability::for_test(),
            object,
            &BlockEntry::new("test denial", now),
            now,
        ),
    )
    .unwrap();
}

/// Run `bytes` through both server paths, each in a fresh repository prepared
/// by `setup`, and require identical outcomes. `aged` moves the clock past the
/// membership lag window first. Returns the outcome for further assertions.
fn assert_parity(
    packs: &[&[u8]],
    head: Hash,
    aged: bool,
    setup: impl Fn(&Rig),
    tune: impl Fn(&mut Rig),
) -> Observed {
    let build = || {
        let mut rig = Rig::new();
        tune(&mut rig);
        setup(&rig);
        if aged {
            rig.clock
                .advance(i64::try_from(rig.cfg.relay_lag_bound_ms).unwrap() + 1);
        }
        rig
    };
    let oracle = build();
    let added: Vec<_> = packs.iter().map(|bytes| oracle.add(bytes)).collect();
    let items: Vec<_> = added.iter().map(|(ticket, id)| (ticket, *id)).collect();
    let inline = inline_all(&oracle, &items, head);
    let rig = build();
    let added: Vec<_> = packs.iter().map(|bytes| rig.add(bytes)).collect();
    let items: Vec<_> = added.iter().map(|(ticket, id)| (ticket, *id)).collect();
    let scheduled = scheduled_all(&rig, &items, head);
    assert_eq!(inline, scheduled, "inline versus scheduled");
    inline
}

/// The primitive driver's complete refusal for `bytes`, with every external
/// base answered as an authenticated absence; `None` when it accepts the pack.
fn driver_refusal(bytes: &[u8], profile: IndexedProfile) -> Option<Failure> {
    let mut driver = VerifyDriver::new(
        PackSource {
            id: hash(bytes),
            len: bytes.len() as u64,
            binding: SourceBinding([7; 32]),
        },
        RepositoryId([9; 32]),
        profile,
        VerifyLimits::indexed(),
        1,
    )
    .ok()?;
    // The host retains canonical bytes it may be asked to re-serve as an
    // in-pack delta base; a failing tail simply leaves later entries out.
    let mut canonical = std::collections::BTreeMap::new();
    let _ = decode_entries_with(
        bytes,
        &mut NoExternalBases,
        DecodeLimits::default(),
        |entry| {
            canonical.insert(entry.id, entry.bytes.to_vec());
            Ok(())
        },
    );
    let mut pages = Vec::new();
    loop {
        let step = match driver.step() {
            Ok(step) => step,
            Err(failure) => return Some(failure),
        };
        let supplied = match step {
            Step::RetainEvidence(page) => {
                let commitment = page.commitment;
                pages.push((commitment, page.bytes.to_vec()));
                driver.acknowledge_retention(commitment)
            }
            Step::Request(Request::EvidencePage { request, page }) => {
                let bytes = &pages.iter().find(|(c, _)| *c == page).unwrap().1;
                driver.supply(Response::EvidencePage {
                    request,
                    page,
                    value: Acquisition::Present(bytes),
                })
            }
            Step::Request(Request::Bytes {
                request,
                source: source @ ByteSource::Pack(_),
                range,
            }) => driver.supply(Response::Bytes {
                request,
                source,
                range,
                value: Acquisition::Present(
                    &bytes[usize::try_from(range.offset).unwrap()
                        ..usize::try_from(range.offset + range.len).unwrap()],
                ),
            }),
            Step::Request(Request::Bytes {
                request,
                source: source @ ByteSource::Canonical { object, .. },
                range,
            }) => driver.supply(Response::Bytes {
                request,
                source,
                range,
                value: Acquisition::Present(
                    &canonical[&object][usize::try_from(range.offset).unwrap()
                        ..usize::try_from(range.offset + range.len).unwrap()],
                ),
            }),
            Step::Request(Request::ExternalObject { request, .. }) => {
                driver.supply(Response::ExternalObject {
                    request,
                    value: Acquisition::Absent,
                })
            }
            Step::Progress | Step::ProvisionalObject(_) => Ok(()),
            Step::Complete(_) => return None,
            other => panic!("unexpected driver step {other:?}"),
        };
        if let Err(failure) = supplied {
            return Some(failure);
        }
    }
}

/// The public refusal an embedder derives from a driver `Failure` alone:
/// message and persistence, with no server state.
fn derived(failure: &Failure) -> (&'static str, bool) {
    let message = match failure.code {
        FailureCode::BadSignature => "bad signature",
        FailureCode::DeltaChainTooDeep | FailureCode::ExternalDeltaChainTooDeep => {
            "delta chain too deep"
        }
        FailureCode::PackfileTooLarge => "pack exceeds indexed decode budget",
        _ => "object hash mismatch",
    };
    (message, failure.persistence() == Persistence::Content)
}

/// The driver refuses `bytes` as the servers observed.
fn assert_driver(bytes: &[u8], observed: &Observed, profile: IndexedProfile) {
    let failure = driver_refusal(bytes, profile).expect("the driver refuses the pack");
    let (message, persisted) = derived(&failure);
    assert_eq!(message, observed.message, "driver {failure:?}");
    assert_eq!(
        persisted,
        observed.persisted[0].is_some(),
        "driver persistence {failure:?}"
    );
}

fn profile(rig_depth: u32, decoded: u64) -> IndexedProfile {
    IndexedProfile {
        pack_bytes: 2 << 30,
        decoded_bytes: decoded,
        delta_depth: rig_depth,
    }
}

fn mismatch() -> (String, String) {
    ("invalid_argument".into(), "object hash mismatch".into())
}

/// A pack whose entry bytes are not a storable object.
fn garbage_entry(writer: &mut PackWriter) {
    writer
        .push_raw(hash(b"garbage"), b"garbage that is no object")
        .unwrap();
}

/// A chain of `links` blobs, each a delta over the one before. When `bad_tail`
/// the last delta rebuilds bytes that are no object.
fn chain(links: usize, bad_tail: bool) -> (Vec<u8>, Hash) {
    let mut writer = PackWriter::new();
    let (mut previous_id, mut previous) = blob(0, 3_000);
    writer.push_raw(previous_id, &previous).unwrap();
    for link in 1..links {
        let next = if bad_tail && link + 1 == links {
            b"not an object at all, only bytes".to_vec()
        } else {
            blob(u16::try_from(link).unwrap(), 3_000).1
        };
        writer
            .push_delta(
                &hash(&previous),
                &mkit_core::delta::encode(&previous, &next).unwrap(),
            )
            .unwrap();
        previous_id = hash(&next);
        previous = next;
    }
    (writer.finish().unwrap(), previous_id)
}

#[test]
fn depth_is_checked_before_the_entry_is_decoded() {
    // Cap 2: the fourth link is one past it, and its delta rebuilds garbage.
    let (pack, head) = chain(4, true);
    let outcome = assert_parity(&[&pack], head, false, |_| {}, |rig| {
        rig.cfg.max_delta_chain_depth = 2;
    });
    assert_eq!(outcome.message, "delta chain too deep");
    assert_eq!(
        outcome.persisted,
        [Some(("invalid_argument".into(), "delta chain too deep".into()))]
    );
    assert_driver(&pack, &outcome, profile(2, 2 << 30));
    // Within the cap the same garbage is a content refusal.
    let (pack, head) = chain(3, true);
    let outcome = assert_parity(&[&pack], head, false, |_| {}, |rig| {
        rig.cfg.max_delta_chain_depth = 2;
    });
    assert_eq!(outcome.persisted, [Some(mismatch())]);
    assert_driver(&pack, &outcome, profile(2, 2 << 30));
}

#[test]
fn a_later_frame_cap_does_not_outrank_an_earlier_content_refusal() {
    let mut writer = PackWriter::new_raw_only();
    garbage_entry(&mut writer);
    let oversized = Object::Blob(Blob {
        data: vec![5; usize::try_from(super::super::geometry::FRAME_PAYLOAD_BYTES).unwrap() + 1],
    });
    writer
        .push_raw(oversized.id().unwrap(), &serialize(&oversized).unwrap())
        .unwrap();
    let pack = writer.finish().unwrap();
    let outcome = assert_parity(&[&pack], oversized.id().unwrap(), false, |_| {}, |rig| {
        rig.limits.window_bytes = 4 << 20;
    });
    assert_eq!(outcome.message, "object hash mismatch");
    assert_eq!(outcome.persisted, [Some(mismatch())]);
    assert_driver(&pack, &outcome, profile(50, 2 << 30));
    // Alone, the cap is a deployment limit: refused, never persisted.
    let mut writer = PackWriter::new_raw_only();
    writer
        .push_raw(oversized.id().unwrap(), &serialize(&oversized).unwrap())
        .unwrap();
    let pack = writer.finish().unwrap();
    let outcome = assert_parity(&[&pack], oversized.id().unwrap(), false, |_| {}, |rig| {
        rig.limits.window_bytes = 4 << 20;
    });
    assert_eq!(outcome.message, "pack exceeds indexed decode budget");
    assert_eq!(outcome.persisted, [None]);
}

#[test]
fn denial_follows_integrity_and_every_content_refusal() {
    let (pack, head) = tree_pack(2, 200);
    let blob_id = blob(0, 200).0;
    // Denial alone is a definite permission refusal and is never persisted.
    let outcome = assert_parity(&[&pack], head, false, |rig| block(rig, &blob_id), |_| {});
    assert_eq!(
        (outcome.code, outcome.message.as_str()),
        (crate::Code::PermissionDenied, "object blocked")
    );
    assert_eq!(outcome.persisted, [None]);
    // A corrupt trailer is an integrity failure: it precedes denial.
    let corrupt = {
        let mut bytes = pack.clone();
        *bytes.last_mut().unwrap() ^= 1;
        bytes
    };
    let outcome = assert_parity(&[&corrupt], head, false, |rig| block(rig, &blob_id), |_| {});
    assert_eq!(outcome.message, "object hash mismatch");
    assert_eq!(outcome.persisted, [Some(mismatch())]);
    // So is a bad signature, whichever object of the pack is denied.
    let signature = pack.len() - 33;
    let unsigned = repaired(pack.clone(), signature);
    for denied in [blob_id, head] {
        let outcome = assert_parity(&[&unsigned], head, false, |rig| block(rig, &denied), |_| {});
        assert_eq!(outcome.message, "bad signature");
        assert_eq!(
            outcome.persisted,
            [Some(("invalid_argument".into(), "bad signature".into()))]
        );
        assert_driver(&unsigned, &outcome, profile(50, 2 << 30));
    }
    // The corrupt trailer is the same refusal for the driver.
    let outcome = assert_parity(&[&corrupt], head, false, |rig| block(rig, &blob_id), |_| {});
    assert_driver(&corrupt, &outcome, profile(50, 2 << 30));
}

#[test]
fn tickets_are_judged_in_ticket_order_with_per_pack_precedence_inside() {
    let (signed, head) = tree_pack(1, 200);
    let unsigned = repaired(signed.clone(), signed.len() - 33);
    let mut writer = PackWriter::new_raw_only();
    garbage_entry(&mut writer);
    let broken = writer.finish().unwrap();
    // A bad signature in the first pack outranks a decode error in the second.
    let outcome = assert_parity(&[&unsigned, &broken], head, false, |_| {}, |_| {});
    assert_eq!(outcome.message, "bad signature");
    assert_eq!(outcome.persisted[0].as_ref().map(|r| r.1.as_str()), Some("bad signature"));
    // And the other way round: the first ticket's decode error wins.
    let outcome = assert_parity(&[&broken, &unsigned], head, false, |_| {}, |_| {});
    assert_eq!(outcome.message, "object hash mismatch");
    assert_eq!(outcome.persisted[0], Some(mismatch()));
}

#[test]
fn corrupt_stored_base_bytes_are_unavailable_never_a_client_refusal() {
    let (base, base_raw) = blob(1, 3_000);
    let (_, target_raw) = blob(2, 3_000);
    let thin = thin(base, &base_raw, &target_raw);
    let seed = |rig: &Rig| {
        // The index row names `base`, but the frame it locates holds another
        // object of the same size: the stored bytes are corrupt.
        let (_, other_raw) = blob(9, 3_000);
        let mut writer = PackWriter::new_raw_only();
        writer.push_raw(hash(&other_raw), &other_raw).unwrap();
        let stored = writer.finish().unwrap();
        let pack_id = hash(&stored);
        super::super::tests::upload(&rig.blobs, &stored);
        let mut frame = None;
        decode_entries_with(&stored, &mut NoExternalBases, DecodeLimits::default(), |entry| {
            frame = Some((entry.frame_offset, entry.frame_length, entry.wire_type));
            Ok(())
        })
        .unwrap();
        let (frame_offset, frame_length, wire_type) = frame.unwrap();
        let value = crate::store::index::IndexValue {
            frame_offset,
            frame_length,
            wire_type,
            decoded_size: other_raw.len() as u64,
            chain_depth: 0,
            delta_base: None,
        };
        block_on(
            rig.store.apply(
                &rig.source(),
                Batch::new()
                    .put(
                        keys::object_index(&rig.repo.name, &base, &pack_id),
                        codec::encode_object_index(&base, &value).unwrap(),
                    )
                    .put(keys::membership(&rig.repo.name, &pack_id), Value::default()),
            ),
        )
        .unwrap();
    };
    // Inline answers a retryable fault and persists nothing.
    let oracle = Rig::new();
    seed(&oracle);
    let (ticket, id) = oracle.add(&thin);
    let inline = inline_all(&oracle, &[(&ticket, id)], hash(&target_raw));
    assert_eq!(inline.code, crate::Code::Unavailable);
    assert_eq!(inline.message, "member content unavailable");
    assert_eq!(inline.persisted, [None]);
    // Scheduled keeps retrying: no terminal outcome, no rejection, and the
    // advance is told to retry.
    let rig = Rig::new();
    seed(&rig);
    let (ticket, id) = rig.add(&thin);
    rig.create(&ticket, id);
    for _ in 0..40 {
        rig.tick();
        rig.clock.advance(1_000);
    }
    let job = rig.job(&ticket.pack_id).unwrap();
    assert_eq!((job.phase, job.outcome), (Phase::Decode, None));
    assert_eq!(rejected(&rig, &ticket.pack_id), None);
    let error = rig.check(&[(&ticket, id)], hash(&target_raw)).unwrap_err();
    assert_eq!(error.code(), crate::Code::Unavailable);
}

#[test]
fn the_in_pack_decode_budget_is_a_limit_never_a_persisted_rejection() {
    let (pack, head) = tree_pack(12, 3_000);
    let outcome = assert_parity(&[&pack], head, false, |_| {}, |rig| {
        rig.cfg.decode_budget = 20_000;
    });
    assert_eq!(outcome.message, "pack exceeds indexed decode budget");
    assert_eq!(outcome.persisted, [None]);
    assert_driver(&pack, &outcome, profile(50, 20_000));
}

#[test]
fn persistence_of_a_primitive_refusal_matches_what_the_servers_persist() {
    // The pure classification an embedder uses, against the servers above.
    for (code, persisted) in [
        (FailureCode::ObjectHashMismatch, true),
        (FailureCode::BadSignature, true),
        (FailureCode::DeltaChainTooDeep, true),
        (FailureCode::ExternalDeltaChainTooDeep, false),
        (FailureCode::PackfileTooLarge, false),
        (FailureCode::ExternalBaseAbsent, false),
        (FailureCode::MissingClosure, false),
        (FailureCode::UnavailableInput, false),
        (FailureCode::ResourceLimit, false),
    ] {
        let expected = if persisted {
            Persistence::Content
        } else {
            Persistence::Transient
        };
        assert_eq!(code.persistence(), expected, "{code:?}");
    }
    let failure = Failure {
        code: FailureCode::ExternalDeltaChainTooDeep,
        location: mkit_primitives::error::Location::default(),
        detail: mkit_primitives::error::BoundedDetail::None,
    };
    assert_eq!(failure.persistence(), Persistence::Transient);
}

/// Known scheduled-path divergence from SPEC-PACKFILE 6.1, pinned until
/// verification moves onto the driver: scheduled denial is read per admitted
/// batch, before any row of the denied object is written, so a denied object in
/// an earlier batch is reported ahead of a content refusal in a later entry.
/// Inline verification sees the whole pack and reports the content refusal.
#[test]
fn scheduled_denial_in_an_earlier_batch_outranks_a_later_content_refusal() {
    let (id, raw) = blob(0, 200);
    let mut writer = PackWriter::new_raw_only();
    writer.push_raw(id, &raw).unwrap();
    garbage_entry(&mut writer);
    let pack = writer.finish().unwrap();
    let build = || {
        let rig = Rig::new();
        block(&rig, &id);
        rig
    };
    let oracle = build();
    let (ticket, tid) = oracle.add(&pack);
    let inline = inline_all(&oracle, &[(&ticket, tid)], id);
    assert_eq!(inline.message, "object hash mismatch");
    assert_eq!(inline.persisted, [Some(mismatch())]);
    let rig = build();
    let (ticket, tid) = rig.add(&pack);
    let scheduled = scheduled_all(&rig, &[(&ticket, tid)], id);
    assert_eq!(
        (scheduled.code, scheduled.message.as_str()),
        (crate::Code::PermissionDenied, "object blocked")
    );
    assert_eq!(scheduled.persisted, [None]);
}
