//! Actual header/body bounds and guarded generation/lifetime regressions.
use super::{
    Arc, Cursor, MemoryKv, Ordering, Partition, PartitionStats, ScanPage, StoreCapabilities,
};
use super::{
    Batch, BatchOutcome, Hash, Key, Kind, NOW, NamespaceStore, Phase, Rig, StoreError, Value,
    VerifyJobV1, block_on,
};
use crate::indexed::checkpoint::{self, ExtractionGroupMember, ExtractionSource, ExtractionV1};
use crate::store::{Precondition, keys};
use std::sync::atomic::AtomicBool;

fn save(rig: &Rig, pack: &Hash, job: &mut VerifyJobV1, prior: Option<&Value>) -> Value {
    let key = keys::verify_job(&rig.repo.name, pack);
    let batch = Batch::new()
        .require(Precondition::NotAfter(u64::MAX))
        .require(match prior {
            Some(raw) => Precondition::Equals(key.clone(), raw.clone()),
            None => Precondition::Absent(key.clone()),
        });
    let batch = checkpoint::write_job(batch, job, prior, &rig.repo.name, pack).unwrap();
    batch.validate(&rig.store.capabilities()).unwrap();
    assert!(matches!(
        block_on(rig.store.apply(&rig.source(), batch)).unwrap(),
        BatchOutcome::Committed
    ));
    block_on(rig.store.get(&rig.source(), &key))
        .unwrap()
        .unwrap()
}

fn body_key(rig: &Rig, pack: &Hash, job: &VerifyJobV1) -> Key {
    keys::verify_row(
        &rig.repo.name,
        pack,
        keys::VC_CANDIDATE,
        job.member_body_id.as_ref(),
    )
}

fn stale_guard_loses(rig: &Rig, pack: &Hash, prior: &Value) {
    assert!(matches!(
        block_on(
            rig.store.apply(
                &rig.source(),
                Batch::new()
                    .require(Precondition::Equals(
                        keys::verify_job(&rig.repo.name, pack),
                        prior.clone()
                    ))
                    .put(keys::ticket(&[99; 32]), Value::default())
            )
        )
        .unwrap(),
        BatchOutcome::PreconditionFailed { .. }
    ));
}

fn largest_job(extracting: bool) -> VerifyJobV1 {
    let member = ExtractionGroupMember {
        pack: [255; 32],
        ticket: [255; 32],
        bytes: u64::MAX,
        created_at_ms: u64::MAX,
        already_verified: false,
    };
    let mut job = VerifyJobV1::new([255; 32], u64::MAX, u64::MAX, u32::MAX);
    job.extraction_group = vec![member.clone(); 7];
    job.extraction_head = Some([255; 32]);
    job.member_body_id = Some([255; 32]);
    job.generation = u64::MAX;
    job.kind = Kind::Packlist;
    job.version = u32::MAX;
    job.cursor = vec![255; 4096];
    job.etag = Some("f".repeat(64));
    job.entries = u64::MAX;
    job.in_pack_bytes = u64::MAX;
    job.external_bytes = u64::MAX;
    job.windows_done = u32::MAX;
    job.attempts = u32::MAX;
    job.closure_cap = u32::MAX;
    job.restarts = u8::MAX;
    job.extract_needed = true;
    job.scan = vec![255; 324];
    job.owed = u64::MAX;
    job.final_pass = true;
    job.last_relay_seq = Some(u64::MAX);
    job.closure_final_at_ms = Some(u64::MAX);
    job.outcome = Some(checkpoint::Outcome::ExtractionUnavailable);
    if extracting {
        job.phase = Phase::Extract;
        job.cursor.clear();
        job.extraction = Some(ExtractionV1 {
            sources: vec![
                ExtractionSource {
                    member,
                    etag: Some("f".repeat(64)),
                    version: u32::MAX,
                    entries: u64::MAX,
                    decoded: u64::MAX,
                    member_body_id: Some([255; 32])
                };
                7
            ],
            group: [255; 32],
            reconstruction: Some(checkpoint::MemberCursor {
                target: [255; 32],
                next: [255; 32],
                preferred: Some(([255; 32], u64::MAX)),
                level: u32::from(u16::MAX),
                local: true,
                ascending: true,
                canonical: Some(([255; 32], 8 << 20, u32::MAX)),
                bytes: u64::MAX,
            }),
            stage: 13,
            member: 7,
            scan: vec![255; 324],
            staged_objects: u64::MAX,
            staged_bytes: u64::MAX,
            selected_bytes: u64::MAX,
            object: Some([255; 32]),
            length: u64::MAX,
            chunk: u32::MAX,
            chunk_offset: u64::MAX,
            written: u64::MAX,
            cvs: 10_000,
            root: Some([255; 32]),
            session: vec![255; 1024],
            uploaded: 10_000,
            relay: Some(u64::MAX),
        });
    }
    job
}

#[test]
fn job_headers_and_member_bodies_fit_their_explicit_bounds() {
    for extracting in [false, true] {
        let job = largest_job(extracting);
        let raw = checkpoint::encode_job(&job);
        eprintln!(
            "job header bytes: extracting={extracting}, bytes={}",
            raw.as_bytes().len()
        );
        assert!(raw.as_bytes().len() <= checkpoint::MAX_JOB_HEADER_BYTES);
        checkpoint::decode_job(&raw).unwrap();
    }
    let rig = Rig::new();
    let mut job = VerifyJobV1::new([255; 32], 0, 0, 1);
    job.satisfying = vec![[255; 32]; 256];
    job.packlist = vec![[255; 32]; 263];
    let raw = save(&rig, &[3; 32], &mut job, None);
    let body = block_on(
        rig.store
            .get(&rig.source(), &body_key(&rig, &[3; 32], &job)),
    )
    .unwrap()
    .unwrap();
    eprintln!("job member body bytes: {}", body.as_bytes().len());
    assert!(body.as_bytes().len() <= 68 << 10);
    assert!(raw.as_bytes().len() < 2 << 10);
    let hydrated = rig.job(&[3; 32]).unwrap();
    assert_eq!(hydrated.satisfying, job.satisfying);
    assert_eq!(hydrated.packlist, job.packlist);
}

#[test]
fn header_only_reuse_preserves_immutable_member_lists() {
    let rig = Rig::new();
    let pack = [3; 32];
    let mut job = VerifyJobV1::new([4; 32], 5, 6, 1);
    job.satisfying = vec![[7; 32]];
    job.packlist = vec![[8; 32]];
    let old = save(&rig, &pack, &mut job, None);
    let key = body_key(&rig, &pack, &job);
    let old_body = block_on(rig.store.get(&rig.source(), &key)).unwrap();
    let mut header = checkpoint::decode_job(&old).unwrap();
    assert!(!header.members_loaded);
    header.extraction_group.push(ExtractionGroupMember {
        pack,
        ticket: [4; 32],
        bytes: 6,
        created_at_ms: 5,
        already_verified: true,
    });
    let batch = checkpoint::write_job(Batch::new(), &mut header, Some(&old), &rig.repo.name, &pack)
        .unwrap();
    assert_eq!(batch.writes.len(), 1, "unchanged member body was rewritten");
    let new = save(&rig, &pack, &mut header, Some(&old));
    assert!(header.generation > job.generation);
    assert_eq!(header.member_body_id, job.member_body_id);
    assert_eq!(
        block_on(rig.store.get(&rig.source(), &key)).unwrap(),
        old_body
    );
    assert_eq!(rig.job(&pack).unwrap().satisfying, job.satisfying);
    assert_eq!(rig.job(&pack).unwrap().packlist, job.packlist);
    stale_guard_loses(&rig, &pack, &old);
    assert_ne!(old, new);
}

#[test]
fn list_and_phase_mutations_advance_generation_and_preserve_old_bodies() {
    let rig = Rig::new();
    let pack = [3; 32];
    let mut job = VerifyJobV1::new([4; 32], 5, 6, 1);
    job.satisfying = vec![[7; 32]];
    let old = save(&rig, &pack, &mut job, None);
    let old_key = body_key(&rig, &pack, &job);
    let old_body = block_on(rig.store.get(&rig.source(), &old_key)).unwrap();
    job.satisfying.push([8; 32]);
    let changed = save(&rig, &pack, &mut job, Some(&old));
    assert_eq!(job.generation, 2);
    assert_eq!(
        block_on(rig.store.get(&rig.source(), &old_key)).unwrap(),
        old_body
    );
    stale_guard_loses(&rig, &pack, &old);
    let body = job.member_body_id;
    job.phase = Phase::Watch;
    job.outcome = Some(checkpoint::Outcome::DecodeBudget);
    job.attempts += 1;
    save(&rig, &pack, &mut job, Some(&changed));
    assert_eq!(job.generation, 3);
    assert_eq!(job.member_body_id, body);
    stale_guard_loses(&rig, &pack, &changed);
}

#[test]
fn cleanup_retains_generation_and_same_ticket_recreation_cannot_aba() {
    let rig = Rig::new();
    let pack = [3; 32];
    let mut job = VerifyJobV1::new([4; 32], 5, 6, 1);
    job.phase = Phase::Watch;
    job.satisfying = vec![[7; 32]];
    let old = save(&rig, &pack, &mut job, None);
    let old_body = body_key(&rig, &pack, &job);
    block_on(rig.store.apply(
        &rig.source(),
        Batch::new().put(
            keys::timer(
                u64::try_from(NOW).unwrap(),
                crate::timers::registry::kinds::VERIFY.get(),
                &checkpoint::timer_reference(&rig.repo.name, &pack),
            ),
            Value::default(),
        ),
    ))
    .unwrap();
    rig.tick();
    assert!(rig.job(&pack).is_none());
    let gone = block_on(
        rig.store
            .get(&rig.source(), &keys::verify_job(&rig.repo.name, &pack)),
    )
    .unwrap()
    .unwrap();
    let tombstone = checkpoint::decode_job(&gone).unwrap();
    assert!(tombstone.gone);
    assert_eq!(tombstone.generation, 2);
    assert!(
        block_on(rig.store.get(&rig.source(), &old_body))
            .unwrap()
            .is_none()
    );
    let mut recreated = VerifyJobV1::new([4; 32], 5, 6, 1);
    recreated.phase = Phase::Watch;
    recreated.satisfying = vec![[7; 32]];
    save(&rig, &pack, &mut recreated, Some(&gone));
    assert_eq!(recreated.generation, 3);
    assert_eq!(recreated.member_body_id, job.member_body_id);
    stale_guard_loses(&rig, &pack, &old);
    stale_guard_loses(&rig, &pack, &gone);
}

#[test]
fn missing_or_corrupt_member_body_fails_closed() {
    let rig = Rig::new();
    let pack = [3; 32];
    let mut job = VerifyJobV1::new([4; 32], 5, 6, 1);
    job.satisfying = vec![[7; 32]];
    save(&rig, &pack, &mut job, None);
    let key = body_key(&rig, &pack, &job);
    block_on(rig.store.apply(
        &rig.source(),
        Batch::new().put(key.clone(), Value::new(b"\x01{}".to_vec())),
    ))
    .unwrap();
    assert!(matches!(
        block_on(checkpoint::read_job(
            rig.store.as_ref(),
            &rig.source(),
            &rig.repo.name,
            &pack
        )),
        Err(StoreError::Corrupt(_))
    ));
    block_on(rig.store.apply(&rig.source(), Batch::new().delete(key))).unwrap();
    assert!(matches!(
        block_on(checkpoint::read_job(
            rig.store.as_ref(),
            &rig.source(),
            &rig.repo.name,
            &pack
        )),
        Err(StoreError::Unavailable(_))
    ));
}

#[test]
fn oversized_headers_and_generation_overflow_fail_closed() {
    let rig = Rig::new();
    let mut job = largest_job(false);
    job.cursor.push(255);
    assert!(checkpoint::decode_job(&checkpoint::encode_job(&job)).is_err());
    job = largest_job(true);
    job.extraction.as_mut().unwrap().session.push(255);
    assert!(checkpoint::decode_job(&checkpoint::encode_job(&job)).is_err());
    let prior = checkpoint::encode_job(&largest_job(false));
    assert!(
        checkpoint::write_job(
            Batch::new(),
            &mut VerifyJobV1::new([4; 32], 0, 0, 1),
            Some(&prior),
            &rig.repo.name,
            &[3; 32]
        )
        .is_err()
    );
}

fn arm_cleanup(rig: &Rig, pack: &Hash) {
    block_on(rig.store.apply(
        &rig.source(),
        Batch::new().put(
            keys::timer(
                u64::try_from(NOW).unwrap(),
                crate::timers::registry::kinds::VERIFY.get(),
                &checkpoint::timer_reference(&rig.repo.name, pack),
            ),
            Value::default(),
        ),
    ))
    .unwrap();
}

fn cleanup_group(rig: &Rig, peer_phase: Phase) -> (Hash, Value, Key, Hash, Value) {
    let pack = [31; 32];
    let peer_pack = [32; 32];
    let group: Vec<_> = [pack, peer_pack]
        .into_iter()
        .map(|pack| ExtractionGroupMember {
            pack,
            ticket: pack,
            bytes: 0,
            created_at_ms: 0,
            already_verified: false,
        })
        .collect();
    let mut own = VerifyJobV1::new(pack, 0, 0, 1);
    own.phase = Phase::Watch;
    own.extraction_group.clone_from(&group);
    own.satisfying = vec![[7; 32]];
    let own_raw = save(rig, &pack, &mut own, None);
    let body = body_key(rig, &pack, &own);
    let mut peer = VerifyJobV1::new(peer_pack, 0, 0, 1);
    peer.phase = peer_phase;
    peer.extraction_group = group;
    let peer_raw = save(rig, &peer_pack, &mut peer, None);
    install_peer_ticket(rig, &peer_pack, u64::try_from(NOW).unwrap() + 60_000);
    arm_cleanup(rig, &pack);
    (pack, own_raw, body, peer_pack, peer_raw)
}

#[test]
fn expired_ready_source_is_retained_for_every_unfinished_peer_phase() {
    for phase in [
        Phase::Decode,
        Phase::ClosureResolve,
        Phase::EmitIndex,
        Phase::AwaitDelivery,
        Phase::Extract,
        Phase::Verify,
    ] {
        let rig = Rig::new();
        let (pack, raw, body, _, _) = cleanup_group(&rig, phase);
        assert_eq!(rig.tick().failed, 0);
        assert_eq!(
            block_on(
                rig.store
                    .get(&rig.source(), &keys::verify_job(&rig.repo.name, &pack))
            )
            .unwrap(),
            Some(raw),
            "peer phase {phase:?}"
        );
        assert!(
            block_on(rig.store.get(&rig.source(), &body))
                .unwrap()
                .is_some()
        );
    }
}

struct RestartPeerDuringGone {
    inner: Arc<MemoryKv>,
    own: Key,
    peer: Key,
    before: Option<Value>,
    after: Value,
    injected: AtomicBool,
}

impl NamespaceStore for RestartPeerDuringGone {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.inner.get(p, key).await
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
        let gone = batch.writes.iter().any(|w| matches!(w, crate::store::Write::Put(key, raw) if key == &self.own && checkpoint::decode_job(raw).is_ok_and(|job| job.gone)));
        if gone && !self.injected.swap(true, Ordering::SeqCst) {
            let outcome = self
                .inner
                .apply(
                    p,
                    Batch::new()
                        .require(match &self.before {
                            Some(raw) => Precondition::Equals(self.peer.clone(), raw.clone()),
                            None => Precondition::Absent(self.peer.clone()),
                        })
                        .put(self.peer.clone(), self.after.clone()),
                )
                .await?;
            assert!(matches!(outcome, BatchOutcome::Committed));
        }
        self.inner.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

#[test]
fn peer_restart_after_cleanup_observation_loses_gone_cas() {
    let rig = Rig::new();
    let (pack, raw, body, peer_pack, peer_raw) = cleanup_group(&rig, Phase::Watch);
    let mut peer = checkpoint::decode_job(&peer_raw).unwrap();
    peer.phase = Phase::Decode;
    peer.generation += 1;
    let race = RestartPeerDuringGone {
        inner: rig.store.clone(),
        own: keys::verify_job(&rig.repo.name, &pack),
        peer: keys::verify_job(&rig.repo.name, &peer_pack),
        before: Some(peer_raw),
        after: checkpoint::encode_job(&peer),
        injected: AtomicBool::new(false),
    };
    assert_eq!(rig.tick_on(&race).failed, 1);
    assert!(race.injected.load(Ordering::SeqCst));
    assert_eq!(
        block_on(rig.store.get(&rig.source(), &race.own)).unwrap(),
        Some(raw)
    );
    assert!(
        block_on(rig.store.get(&rig.source(), &body))
            .unwrap()
            .is_some()
    );
}

#[test]
fn persisted_multipart_counters_cannot_exceed_the_plan_cap() {
    for counter in [true, false] {
        let mut job = largest_job(true);
        let x = job.extraction.as_mut().unwrap();
        if counter {
            x.cvs = 10_001;
        } else {
            x.uploaded = 10_001;
        }
        assert!(checkpoint::decode_job(&checkpoint::encode_job(&job)).is_err());
    }
}

#[test]
fn terminal_membership_failures_resume_only_before_extraction_effects() {
    for (outcome, object, retry) in [
        (checkpoint::Outcome::ClosureMissing, None, true),
        (checkpoint::Outcome::PacklistMissing, None, true),
        (checkpoint::Outcome::BaseCapped, None, true),
        (checkpoint::Outcome::OpenClosure, None, false),
        (checkpoint::Outcome::ClosureMissing, Some([1; 32]), false),
    ] {
        let rig = Rig::new();
        let (ticket, id) = rig.add(b"live membership retry ticket");
        let mut job = VerifyJobV1::new(id, 0, 0, 1);
        job.phase = Phase::Watch;
        job.outcome = Some(outcome);
        job.extraction = Some(ExtractionV1 {
            stage: 10,
            object,
            ..ExtractionV1::default()
        });
        save(&rig, &ticket.pack_id, &mut job, None);
        arm_cleanup(&rig, &ticket.pack_id);
        assert_eq!(rig.tick().failed, 0);
        let observed = rig.job(&ticket.pack_id).unwrap();
        assert_eq!(
            observed.phase,
            if retry { Phase::Extract } else { Phase::Watch }
        );
        // Watch schedules validation without hiding the last closure failure.
        assert_eq!(observed.outcome, Some(outcome));
        assert_eq!(observed.extraction, job.extraction);
    }
}

fn install_peer_ticket(rig: &Rig, pack: &Hash, expiry: u64) -> Value {
    let ticket = crate::store::codec::TicketV1 {
        authority_generation: None,
        repo: rig.repo.name.clone(),
        ref_name: "refs/heads/main".into(),
        signer: [3; 32],
        pack_id: *pack,
        bytes: 1,
        part_size: 8 << 20,
        expires_at_ms: expiry,
        created_at_ms: u64::try_from(NOW).unwrap() - 1,
        reservation_id: "cleanup-peer".into(),
        upload_session: None,
    };
    let raw = crate::store::codec::encode_ticket(&ticket);
    block_on(rig.store.apply(
        &rig.source(),
        Batch::new().put(keys::ticket(pack), raw.clone()),
    ))
    .unwrap();
    raw
}

#[test]
fn persisted_extraction_stage_and_member_are_bounded() {
    for (stage, member) in [(14, 7), (13, 8), (13, usize::MAX)] {
        let mut job = largest_job(true);
        let x = job.extraction.as_mut().unwrap();
        x.stage = stage;
        x.member = member;
        assert!(checkpoint::decode_job(&checkpoint::encode_job(&job)).is_err());
    }
}

#[test]
fn expired_pre_effect_peers_cannot_pin_each_other_forever() {
    for ticket_present in [false, true] {
        let rig = Rig::new();
        let (pack, own, body, peer_pack, _) = cleanup_group(&rig, Phase::Decode);
        let mut job = checkpoint::decode_job(&own).unwrap();
        job.phase = Phase::Decode;
        save(&rig, &pack, &mut job, Some(&own));
        if ticket_present {
            install_peer_ticket(&rig, &peer_pack, u64::try_from(NOW).unwrap());
        } else {
            block_on(
                rig.store
                    .apply(&rig.source(), Batch::new().delete(keys::ticket(&peer_pack))),
            )
            .unwrap();
        }
        arm_cleanup(&rig, &peer_pack);
        // Expiry can leave its row until the existing ticket lifecycle fires.
        // Even during that interval it must not pin the canceled source.
        if ticket_present {
            rig.tick();
            assert!(rig.job(&pack).is_none());
            block_on(
                rig.store
                    .apply(&rig.source(), Batch::new().delete(keys::ticket(&peer_pack))),
            )
            .unwrap();
        }
        for _ in 0..4 {
            rig.tick();
            rig.clock.advance(1_000);
        }
        assert!(rig.job(&pack).is_none());
        assert!(rig.job(&peer_pack).is_none());
        assert!(
            block_on(rig.store.get(&rig.source(), &body))
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn started_extraction_retains_source_after_peer_ticket_disappears() {
    let rig = Rig::new();
    let (pack, raw, body, peer_pack, peer_raw) = cleanup_group(&rig, Phase::Extract);
    let mut peer = checkpoint::decode_job(&peer_raw).unwrap();
    peer.extraction = Some(ExtractionV1 {
        stage: 5,
        object: Some([7; 32]),
        ..ExtractionV1::default()
    });
    save(&rig, &peer_pack, &mut peer, Some(&peer_raw));
    block_on(
        rig.store
            .apply(&rig.source(), Batch::new().delete(keys::ticket(&peer_pack))),
    )
    .unwrap();
    assert_eq!(rig.tick().failed, 0);
    assert_eq!(
        block_on(
            rig.store
                .get(&rig.source(), &keys::verify_job(&rig.repo.name, &pack))
        )
        .unwrap(),
        Some(raw)
    );
    assert!(
        block_on(rig.store.get(&rig.source(), &body))
            .unwrap()
            .is_some()
    );
}

#[test]
fn peer_ticket_arrival_or_renewal_after_cleanup_observation_loses_gone_cas() {
    for ticket_present in [false, true] {
        let rig = Rig::new();
        let (pack, raw, body, peer_pack, _) = cleanup_group(&rig, Phase::Decode);
        let ticket = block_on(rig.store.get(&rig.source(), &keys::ticket(&peer_pack)))
            .unwrap()
            .unwrap();
        let before = if ticket_present {
            Some(install_peer_ticket(
                &rig,
                &peer_pack,
                u64::try_from(NOW).unwrap(),
            ))
        } else {
            block_on(
                rig.store
                    .apply(&rig.source(), Batch::new().delete(keys::ticket(&peer_pack))),
            )
            .unwrap();
            None
        };
        let race = RestartPeerDuringGone {
            inner: rig.store.clone(),
            own: keys::verify_job(&rig.repo.name, &pack),
            peer: keys::ticket(&peer_pack),
            before,
            after: ticket,
            injected: AtomicBool::new(false),
        };
        assert_eq!(rig.tick_on(&race).failed, 1);
        assert!(race.injected.load(Ordering::SeqCst));
        assert_eq!(
            block_on(rig.store.get(&rig.source(), &race.own)).unwrap(),
            Some(raw)
        );
        assert!(
            block_on(rig.store.get(&rig.source(), &body))
                .unwrap()
                .is_some()
        );
    }
}
