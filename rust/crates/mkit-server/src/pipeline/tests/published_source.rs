//! Published-pair copies retain the ordinary advance boundaries.
use super::*;
use crate::store::publication::{Pair, Publication};

struct PairAdmission {
    seen: Mutex<Vec<(u64, Vec<ResolvedRefUpdate>)>>,
    refusal: Option<AdmissionDecision>,
}
impl Admission for PairAdmission {
    async fn admit(&self, input: &AdmissionInput<'_>) -> Result<AdmissionDecision, ServerError> {
        assert_eq!(input.op.procedure(), Procedure::AdvanceRefs);
        assert!(input.op.published_source.is_some());
        let mut seen = self.seen.lock().unwrap();
        let rid = format!("pair-copy-{}", seen.len());
        seen.push((input.declared_bytes, input.resolved_ref_updates.clone()));
        Ok(self
            .refusal
            .clone()
            .unwrap_or_else(|| AdmissionDecision::allow(Vec::new()).with_reservation(rid)))
    }
}

fn admitted_pipe(
    w: World,
    refusal: Option<AdmissionDecision>,
) -> Pipeline<MemoryBlobStore, Spy, Hooks<OpenAuthorizer, PairAdmission>> {
    Pipeline::new(
        w.env.pipe.blobs,
        w.env.pipe.meta,
        with_admission(PairAdmission {
            seen: Mutex::new(Vec::new()),
            refusal,
        }),
        w.env.pipe.cfg,
        w.env.clock,
        w.env.metrics,
    )
    .unwrap()
}

fn expected_copy_effects(pair: &Pair) -> Vec<ResolvedRefUpdate> {
    vec![
        ResolvedRefUpdate {
            name: "refs/mkit/packmap/copy".into(),
            new: pair.packmap,
            effect: RefEffect::Create,
        },
        ResolvedRefUpdate {
            name: "refs/heads/copy".into(),
            new: pair.head,
            effect: RefEffect::Create,
        },
    ]
}

#[test]
fn published_source_admits_exact_create_effects_and_settles_commit_and_conflict() {
    let w = World::new(Path::Immediate);
    history(&w);
    let pair = published(&w, HEAD).value;
    let first = auth(&w);
    let second = auth(&w);
    let repo = w.repo.clone();
    let pipe = admitted_pipe(w, None);
    for (a, expected) in [
        (&first, AdvanceOutcome::Committed),
        (&second, AdvanceOutcome::PackmapConflict),
    ] {
        assert_eq!(
            block_on(pipe.advance_refs_from_published(
                a,
                HEAD.into(),
                "refs/heads/copy".into(),
                pair.head,
            ))
            .unwrap(),
            expected
        );
    }
    assert_eq!(
        *pipe.hooks.admission.seen.lock().unwrap(),
        vec![(0, expected_copy_effects(&pair)); 2]
    );
    let partition = pipe.shards.ref_shard(&repo, "refs/heads/copy");
    assert_eq!(
        block_on(crate::store::publication::read(
            &pipe.meta,
            &partition,
            &repo.name,
            "refs/heads/copy",
        ))
        .unwrap()
        .value,
        pair
    );
    let reservation = |rid| {
        codec::decode_reservation(
            &block_on(pipe.meta.get(&partition, &keys::reservation(rid).unwrap()))
                .unwrap()
                .unwrap(),
        )
        .unwrap()
    };
    assert!(matches!(
        reservation("pair-copy-0"),
        codec::ReservationV1::Committed { .. }
    ));
    assert!(matches!(
        reservation("pair-copy-1"),
        codec::ReservationV1::Aborted {
            reason: codec::AbortReason::RefConflict,
            ..
        }
    ));
    assert!(pipe.meta.batches.lock().unwrap().iter().any(|batch| {
        ["refs/heads/copy", "refs/mkit/packmap/copy"].iter().all(|name| batch.writes.iter().any(|write| matches!(write, Write::Put(key, _) if *key == keys::ref_key(&repo.name, name))))
            && batch.writes.iter().any(|write| matches!(write, Write::Put(key, value) if *key == keys::reservation("pair-copy-0").unwrap() && matches!(codec::decode_reservation(value), Ok(codec::ReservationV1::Committed { .. }))))
    }));
}

#[test]
fn published_source_refusal_and_challenge_leave_both_destinations_absent() {
    for refusal in [
        AdmissionDecision::Deny(ServerError::permission_denied("ref cap")),
        AdmissionDecision::challenge(
            vec![Challenge {
                scheme: "mpp".into(),
                value: "ref-slot".into(),
            }],
            "ref slot required",
        ),
    ] {
        let w = World::new(Path::Immediate);
        history(&w);
        let pair = published(&w, HEAD).value;
        let a = auth(&w);
        let repo = w.repo.clone();
        let pipe = admitted_pipe(w, Some(refusal));
        let before_batches = pipe.meta.batches.lock().unwrap().len();
        let error = block_on(pipe.advance_refs_from_published(
            &a,
            HEAD.into(),
            "refs/heads/copy".into(),
            pair.head,
        ))
        .unwrap_err();
        assert_eq!(error.code(), Code::PermissionDenied);
        assert_eq!(pipe.meta.batches.lock().unwrap().len(), before_batches);
        assert_eq!(
            *pipe.hooks.admission.seen.lock().unwrap(),
            vec![(0, expected_copy_effects(&pair))]
        );
        for name in ["refs/heads/copy", "refs/mkit/packmap/copy"] {
            let partition = pipe.shards.ref_shard(&repo, name);
            assert!(
                block_on(pipe.meta.get(&partition, &keys::ref_key(&repo.name, name)))
                    .unwrap()
                    .is_none()
            );
            assert!(
                block_on(
                    pipe.meta
                        .get(&partition, &keys::reservation("pair-copy-0").unwrap())
                )
                .unwrap()
                .is_none()
            );
        }
    }
}

fn auth(w: &World) -> Authenticated {
    w.env
        .auth(&signed(
            &w.owner,
            &w.identity,
            Procedure::AdvanceRefs,
            w.nonce(),
        ))
        .unwrap()
}

fn copy(
    w: &World,
    source: &str,
    dest: &str,
    tip: Option<Hash>,
) -> Result<AdvanceOutcome, ServerError> {
    block_on(
        w.env
            .pipe
            .advance_refs_from_published(&auth(w), source.into(), dest.into(), tip),
    )
}

fn published(w: &World, name: &str) -> Publication {
    block_on(crate::store::publication::read(
        &w.env.pipe.meta,
        &w.env.pipe.shards.ref_shard(&w.repo, name),
        &w.repo.name,
        name,
    ))
    .unwrap()
}

fn relay(w: &World) {
    let timers = crate::timers::TimerRegistry::new().register(crate::relay::RelayHandler {
        target: BorrowedStore(&w.env.pipe.meta),
        hook: crate::relay::NoHook,
        budget: crate::relay::RelayBudget::default(),
    });
    for _ in 0..8 {
        block_on(crate::timers::run_due(
            &w.env.pipe.meta,
            &w.source(),
            &timers,
            w.env.clock.as_ref(),
            u64::try_from(w.env.clock.now_ms()).unwrap(),
            &crate::timers::TickBudget::default(),
        ))
        .unwrap();
    }
}

#[test]
fn published_source_create_succeeds_on_every_path_with_zero_added_bytes() {
    for path in std::iter::once(&Path::Immediate).chain(PATHS) {
        let w = World::new(*path);
        let h = history(&w);
        let source = published(&w, HEAD);
        let counter = keys::repo_storage(&w.repo.name);
        let coordinator = w.env.pipe.shards.coordinator(&w.repo.namespace);
        let bytes = block_on(w.env.pipe.meta.get(&coordinator, &counter)).unwrap();
        w.settle(60, |w| {
            copy(w, HEAD, "refs/heads/copy", Some(h.second.head))
                .map(|result| assert_eq!(result, AdvanceOutcome::Committed))
        })
        .unwrap();
        assert_eq!(
            serde_json::to_vec(&published(&w, "refs/heads/copy").value).unwrap(),
            serde_json::to_vec(&source.value).unwrap()
        );
        let after = block_on(w.env.pipe.meta.get(&coordinator, &counter)).unwrap();
        assert_eq!(bytes, after);
    }
}

#[test]
fn published_source_copy_preserves_immediate_coverage() {
    let w = World::new(Path::Immediate);
    let h = history(&w);
    let other = unrelated(5);
    w.publish(&branch("other"), None, &other);
    // Existing immediate UpdateRef permits this uncovered pair. Copying it
    // must not introduce a history-capacity gate or repair the source silently.
    w.update(PACKMAP, Some(h.second.map()), Some(other.map()))
        .unwrap();
    let original = published(&w, HEAD);
    assert_eq!(
        copy(&w, HEAD, "refs/heads/copy", Some(h.second.head)).unwrap(),
        AdvanceOutcome::Committed
    );
    assert_eq!(published(&w, "refs/heads/copy").value, original.value);
    assert_eq!(
        original.value,
        Pair {
            head: Some(h.second.head),
            packmap: Some(other.map())
        }
    );
}

#[test]
fn published_source_expected_tip_missing_cas_and_replay() {
    let w = World::new(Path::Immediate);
    let h = history(&w);
    let error = copy(&w, HEAD, "refs/heads/copy", Some(h.first.head)).unwrap_err();
    assert_eq!(
        (error.code(), error.public_message()),
        (Code::FailedPrecondition, "source tip changed")
    );
    assert_eq!(w.pair(&branch("copy")), (None, None));
    let a = auth(&w);
    let run = || {
        block_on(w.env.pipe.advance_refs_from_published(
            &a,
            HEAD.into(),
            "refs/heads/copy".into(),
            None,
        ))
    };
    assert_eq!(run().unwrap(), AdvanceOutcome::Committed);
    let landed = published(&w, "refs/heads/copy");
    w.update(HEAD, Some(h.second.head), None).unwrap();
    assert_eq!(run().unwrap(), AdvanceOutcome::Committed);
    assert_eq!(published(&w, "refs/heads/copy"), landed);
    // A different, still-published branch supplies the fresh request's source.
    assert_eq!(
        copy(&w, "refs/heads/copy", "refs/heads/copy", None).unwrap(),
        AdvanceOutcome::PackmapConflict
    );
    assert_eq!(published(&w, "refs/heads/copy"), landed);
    w.update("refs/heads/head-only", None, Some(h.second.head))
        .unwrap();
    assert_eq!(
        copy(&w, "refs/heads/copy", "refs/heads/head-only", None).unwrap(),
        AdvanceOutcome::HeadConflict
    );
    assert_eq!(w.read("refs/mkit/packmap/head-only"), None);
}

#[test]
fn published_source_absence_and_authorization_are_uniform() {
    let mut w = World::new(Path::Immediate);
    history(&w);
    let stranger = key(8);
    for source in [HEAD, "refs/heads/absent"] {
        let a = w
            .env
            .auth(&signed(
                &stranger,
                &w.identity,
                Procedure::AdvanceRefs,
                w.nonce(),
            ))
            .unwrap();
        // Restrict the source through current read authorization.
        w.env.pipe.cfg.authorizer_role = AuthorizerRole::Check;
        w.env.pipe.cfg.write_policy = WritePolicy::Owner;
        let p = w.env.pipe.shards.coordinator(&w.repo.namespace);
        block_on(w.env.pipe.meta.inner.apply(
            &p,
            Batch::new().put(
                keys::repo_visibility(&w.repo.name),
                codec::encode_repo_visibility(&codec::RepoVisibilityV1 {
                    visibility: codec::StoredVisibility::Private,
                    last_created_ms: 0,
                    last_statement_id: None,
                    changed_ms: 0,
                }),
            ),
        ))
        .unwrap();
        let error = block_on(w.env.pipe.advance_refs_from_published(
            &a,
            source.into(),
            "refs/heads/copy".into(),
            Some(A),
        ))
        .unwrap_err();
        assert_eq!(
            (error.code(), error.public_message()),
            (Code::NotFound, "source not found")
        );
    }
    let error = copy(&w, "refs/heads/absent", "refs/heads/copy", Some(A)).unwrap_err();
    assert_eq!(
        (error.code(), error.public_message()),
        (Code::NotFound, "source not found")
    );
}

fn two_published_pairs(w: &World, number: u32) -> (Pair, Pair) {
    let first = unrelated(number);
    w.publish(&branch("main"), None, &first);
    relay(w);
    let second = unrelated(number + 100);
    w.publish(&branch("main"), Some(pair_of(&first)), &second);
    relay(w);
    let pair = |push: &Push| Pair {
        head: Some(push.head),
        packmap: Some(push.map()),
    };
    (pair(&first), pair(&second))
}

/// Move the complete source publication in another partition just before the
/// destination batch reaches storage, after the source fence. The destination
/// must retain BOTH original values, even if its live source now names another pair.
#[test]
fn published_source_cross_partition_move_after_fence_copies_exact_pair() {
    let mut w = World::with_sharding(Path::Immediate, Sharding::D34);
    let (previous, current) = two_published_pairs(&w, 6);
    let original = published(&w, HEAD);
    let source = w.source();
    let destination = w.env.pipe.shards.ref_shard(&w.repo, "refs/heads/copy");
    assert_ne!(source, destination);
    let repo = w.repo.clone();
    let mut moved = original.clone();
    moved.sequence += 1;
    moved.published = moved.sequence;
    moved.value = previous;
    let armed = Arc::new(AtomicBool::new(true));
    let arm = armed.clone();
    w.env.pipe.meta.hook = Some(Box::new(move |kv, p, batch| {
        if *p == destination && batch.writes.iter().any(|write| matches!(write, Write::Put(k, _) if *k == keys::ref_key(&repo.name, "refs/heads/copy"))) && arm.swap(false, Ordering::SeqCst) {
            now(kv.apply(&source, Batch::new()
                .put(keys::publication(&repo.name, HEAD), moved.encode().unwrap())
                .put(keys::ref_key(&repo.name, HEAD), codec::encode_ref_id(&moved.value.head.unwrap()))
                .put(keys::ref_key(&repo.name, PACKMAP), codec::encode_ref_id(&moved.value.packmap.unwrap())))).unwrap();
        }
    }));
    assert_eq!(
        copy(&w, HEAD, "refs/heads/copy", current.head).unwrap(),
        AdvanceOutcome::Committed
    );
    assert!(!armed.load(Ordering::SeqCst));
    assert_ne!(published(&w, HEAD).value, original.value);
    assert_eq!(
        serde_json::to_vec(&published(&w, "refs/heads/copy").value).unwrap(),
        serde_json::to_vec(&original.value).unwrap()
    );
}

#[cfg(feature = "__test-faults")]
struct MoveSource {
    kv: Arc<MemoryKv>,
    source: Partition,
    repo: RepoName,
    moved: Publication,
    armed: AtomicBool,
}

#[cfg(feature = "__test-faults")]
impl faults::FaultHooks for MoveSource {
    async fn at(
        &self,
        point: faults::FaultPoint,
        op: &Operation,
        _: &faults::TestDirectives,
    ) -> Result<(), ServerError> {
        if point == faults::FaultPoint::BeforeFinalApply
            && op.published_source.is_some()
            && self.armed.swap(false, Ordering::SeqCst)
        {
            self.kv
                .apply(
                    &self.source,
                    Batch::new().put(
                        keys::publication(&self.repo, HEAD),
                        self.moved.encode().unwrap(),
                    ),
                )
                .await
                .unwrap();
        }
        Ok(())
    }
}

#[cfg(feature = "__test-faults")]
#[test]
fn published_source_fence_refuses_tip_and_aba_changes_before_apply() {
    for (expected, aba) in [(true, false), (false, false), (false, true)] {
        let mut w = World::with_sharding(Path::Immediate, Sharding::D34);
        let (previous, current) = two_published_pairs(&w, 7);
        let mut moved = published(&w, HEAD);
        moved.sequence += 1;
        moved.published = moved.sequence;
        if !aba {
            moved.value = previous;
        }
        let hook = MoveSource {
            kv: w.env.pipe.meta.inner.clone(),
            source: w.source(),
            repo: w.repo.name.clone(),
            moved,
            armed: AtomicBool::new(true),
        };
        w.env.pipe = w.env.pipe.with_faults(hook);
        let error = copy(
            &w,
            HEAD,
            "refs/heads/copy",
            expected.then_some(current.head.unwrap()),
        )
        .unwrap_err();
        if expected {
            assert_eq!(
                (error.code(), error.public_message()),
                (Code::FailedPrecondition, "source tip changed")
            );
        } else {
            assert_eq!(
                (error.code(), error.public_message()),
                (Code::Unavailable, "source publication changed; retry")
            );
        }
        assert_eq!(w.pair(&branch("copy")), (None, None));
        assert_eq!(published(&w, "refs/heads/copy"), Publication::default());
    }
}

#[test]
fn published_source_replans_refence_the_source() {
    let mut w = World::with_sharding(Path::Immediate, Sharding::D34);
    let (previous, current) = two_published_pairs(&w, 8);
    let source = w.source();
    let destination = w.env.pipe.shards.ref_shard(&w.repo, "refs/heads/copy");
    let repo = w.repo.clone();
    let mut moved = published(&w, HEAD);
    moved.sequence += 1;
    moved.published = moved.sequence;
    moved.value = previous;
    let armed = Arc::new(AtomicBool::new(true));
    let arm = armed.clone();
    w.env.pipe.meta.hook = Some(Box::new(move |kv, p, batch| {
        if *p == destination && batch.writes.iter().any(|write| matches!(write, Write::Put(k, _) if *k == keys::ref_key(&repo.name, "refs/heads/copy"))) && arm.swap(false, Ordering::SeqCst) {
            now(kv.apply(&source, Batch::new().put(keys::publication(&repo.name, HEAD), moved.encode().unwrap()))).unwrap();
            // Break a destination planner guard so the first apply cannot commit.
            now(kv.apply(p, Batch::new().put(keys::outbox_sequence(), codec::encode_u64(100)))).unwrap();
        }
    }));
    let error = copy(&w, HEAD, "refs/heads/copy", current.head).unwrap_err();
    assert_eq!(
        (error.code(), error.public_message()),
        (Code::FailedPrecondition, "source tip changed")
    );
    assert!(!armed.load(Ordering::SeqCst));
    assert_eq!(w.pair(&branch("copy")), (None, None));
}

#[test]
fn published_source_keeps_configured_coverage_denial_policy_and_quota_checks() {
    let mut w = World::new(Path::Immediate);
    let h = history(&w);
    let other = unrelated(9);
    w.publish(&branch("other"), None, &other);
    w.update(PACKMAP, Some(h.second.map()), Some(other.map()))
        .unwrap();
    w.env.pipe.publication_policy = Some(Arc::new(clearance::Immediate));
    let error = copy(&w, HEAD, "refs/heads/copy", None).unwrap_err();
    assert_eq!(
        (error.code(), error.public_message()),
        (Code::Unavailable, "repository membership not yet visible")
    );
    assert_eq!(w.pair(&branch("copy")), (None, None));
    w.env.pipe.publication_policy = None;
    // Ref policy still applies to the destination and its paired packmap.
    w.env.pipe.cfg.ref_policy = Some(crate::policy::RefPolicy::new(vec![
        crate::policy::RefRule::new(
            mkit_attest::grant::RefPattern::parse("refs/heads/copy").unwrap(),
            Some([[0; 32]].into()),
            false,
        ),
    ]));
    assert_eq!(
        copy(&w, HEAD, "refs/heads/copy", None).unwrap_err().code(),
        Code::PermissionDenied
    );
    w.env.pipe.cfg.ref_policy = None;
    w.env.pipe.cfg.write_quota = Some(QuotaLimits::new(60_000, 0, 0));
    assert_eq!(
        copy(&w, HEAD, "refs/heads/copy", None).unwrap_err().code(),
        Code::ResourceExhausted
    );
    w.env.pipe.cfg.write_quota = None;
    w.env.pipe.cfg.takedown_denial = true;
    w.block(&h.second.head, 42);
    assert_eq!(
        copy(&w, HEAD, "refs/heads/copy", None).unwrap_err().code(),
        Code::PermissionDenied
    );
    assert_eq!(w.pair(&branch("copy")), (None, None));
}

struct RecordSourceRead(Arc<AtomicBool>);
impl Authorizer for RecordSourceRead {
    async fn authorize(&self, op: &Operation) -> Result<AuthzFacts, ServerError> {
        if matches!(op.kind, OpKind::ReadRef { .. }) {
            self.0.store(true, Ordering::SeqCst);
        }
        Ok(AuthzFacts::default())
    }
}

#[test]
fn published_source_bounds_names_before_authorization() {
    let w = World::new(Path::Immediate);
    history(&w);
    let a = auth(&w);
    let read = Arc::new(AtomicBool::new(false));
    let defaults = Hooks::new();
    let hooks = Hooks {
        authorizer: RecordSourceRead(read.clone()),
        admission: defaults.admission,
        pre_receive: defaults.pre_receive,
        receipts: defaults.receipts,
        outcomes: defaults.outcomes,
    };
    let pipe = Pipeline::new(
        w.env.pipe.blobs,
        w.env.pipe.meta,
        hooks,
        w.env.pipe.cfg,
        w.env.clock,
        w.env.metrics,
    )
    .unwrap();
    for source in [
        String::new(),
        "refs/tags/tag".into(),
        "refs/heads/bad\0name".into(),
        format!("refs/heads/{}", "x".repeat(1 << 20)),
    ] {
        let error =
            block_on(pipe.advance_refs_from_published(&a, source, "refs/heads/copy".into(), None))
                .unwrap_err();
        assert_eq!(
            (error.code(), error.public_message()),
            (Code::NotFound, "source not found")
        );
        assert!(!read.load(Ordering::SeqCst));
    }
    let error = block_on(pipe.advance_refs_from_published(
        &a,
        "refs/heads/absent".into(),
        "refs/heads/copy".into(),
        None,
    ))
    .unwrap_err();
    assert_eq!(
        (error.code(), error.public_message()),
        (Code::NotFound, "source not found")
    );
    assert!(read.load(Ordering::SeqCst));
}

#[test]
fn published_source_bounds_the_derived_packmap_before_hooks_or_writes() {
    let mut w = World::new(Path::Immediate);
    history(&w);
    let invalid_auth = auth(&w);
    let valid_auth = auth(&w);
    let expected = published(&w, HEAD).value;
    let read = Arc::new(AtomicBool::new(false));
    let writes = Arc::new(AtomicBool::new(false));
    let observed_writes = writes.clone();
    w.env.pipe.meta.hook = Some(Box::new(move |_, _, _| {
        observed_writes.store(true, Ordering::SeqCst);
    }));
    let defaults = Hooks::new();
    let hooks = Hooks {
        authorizer: RecordSourceRead(read.clone()),
        admission: defaults.admission,
        pre_receive: defaults.pre_receive,
        receipts: defaults.receipts,
        outcomes: defaults.outcomes,
    };
    let pipe = Pipeline::new(
        w.env.pipe.blobs,
        w.env.pipe.meta,
        hooks,
        w.env.pipe.cfg,
        w.env.clock,
        w.env.metrics,
    )
    .unwrap();
    let valid = format!(
        "refs/heads/{}",
        "x".repeat(crate::refs::MAX_REF_NAME_BYTES - "refs/mkit/packmap/".len())
    );
    let invalid = format!("{valid}x");
    let valid_map = mkit_attest::grant::head_packmap(&valid).unwrap();
    let invalid_map = mkit_attest::grant::head_packmap(&invalid).unwrap();
    assert_eq!(valid.len(), 505);
    assert_eq!(valid_map.len(), crate::refs::MAX_REF_NAME_BYTES);
    assert_eq!(invalid.len(), 506);
    assert_eq!(invalid_map.len(), crate::refs::MAX_REF_NAME_BYTES + 1);
    let error = block_on(pipe.advance_refs_from_published(
        &invalid_auth,
        HEAD.into(),
        invalid.clone(),
        None,
    ))
    .unwrap_err();
    assert_eq!(
        (error.code(), error.public_message()),
        (Code::InvalidArgument, crate::refs::REF_NAME_TOO_LONG)
    );
    assert!(!read.load(Ordering::SeqCst));
    assert!(!writes.load(Ordering::SeqCst));
    for name in [&invalid, &invalid_map] {
        let partition = pipe.shards.ref_shard(&w.repo, name);
        assert!(
            block_on(
                pipe.meta
                    .get(&partition, &keys::ref_key(&w.repo.name, name))
            )
            .unwrap()
            .is_none()
        );
    }
    assert_eq!(
        block_on(pipe.advance_refs_from_published(&valid_auth, HEAD.into(), valid.clone(), None,))
            .unwrap(),
        AdvanceOutcome::Committed
    );
    let partition = pipe.shards.ref_shard(&w.repo, &valid);
    assert_eq!(
        block_on(crate::store::publication::read(
            &pipe.meta,
            &partition,
            &w.repo.name,
            &valid,
        ))
        .unwrap()
        .value,
        expected
    );
}

struct RevokeRead(Arc<AtomicBool>);
impl Authorizer for RevokeRead {
    async fn authorize(&self, op: &Operation) -> Result<AuthzFacts, ServerError> {
        if matches!(op.kind, OpKind::ReadRef { .. }) && self.0.load(Ordering::SeqCst) {
            Err(ServerError::permission_denied("source read revoked"))
        } else {
            Ok(AuthzFacts::default())
        }
    }
}
struct RevokeAfterAdmission(Arc<AtomicBool>);
impl PreReceive for RevokeAfterAdmission {
    async fn check(
        &self,
        op: &Operation,
        _: Option<&crate::store::BlobKey>,
    ) -> Result<(), ServerError> {
        if op.published_source.is_some() {
            self.0.store(true, Ordering::SeqCst);
        }
        Ok(())
    }
}

#[test]
fn published_source_current_read_authorization_is_rechecked_after_admission() {
    let w = World::new(Path::Immediate);
    history(&w);
    let a = auth(&w);
    let revoked = Arc::new(AtomicBool::new(false));
    let defaults = Hooks::new();
    let hooks = Hooks {
        authorizer: RevokeRead(revoked.clone()),
        admission: defaults.admission,
        pre_receive: RevokeAfterAdmission(revoked.clone()),
        receipts: defaults.receipts,
        outcomes: defaults.outcomes,
    };
    let pipe = Pipeline::new(
        w.env.pipe.blobs,
        w.env.pipe.meta,
        hooks,
        w.env.pipe.cfg,
        w.env.clock,
        w.env.metrics,
    )
    .unwrap();
    let error =
        block_on(pipe.advance_refs_from_published(&a, HEAD.into(), "refs/heads/copy".into(), None))
            .unwrap_err();
    assert!(revoked.load(Ordering::SeqCst));
    assert_eq!(
        (error.code(), error.public_message()),
        (Code::NotFound, "source not found")
    );
    let dest = pipe.shards.ref_shard(&w.repo, "refs/heads/copy");
    assert!(
        block_on(
            pipe.meta
                .get(&dest, &keys::ref_key(&w.repo.name, "refs/heads/copy"))
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn published_source_unpaired_and_deleted_branches_are_uniformly_absent() {
    let w = World::new(Path::Immediate);
    let h = history(&w);
    w.update("refs/heads/unpaired", None, Some(h.second.head))
        .unwrap();
    for source in ["refs/heads/unpaired", "refs/heads/absent", "refs/tags/v1"] {
        let error = copy(&w, source, "refs/heads/copy", Some(A)).unwrap_err();
        assert_eq!(
            (error.code(), error.public_message()),
            (Code::NotFound, "source not found")
        );
    }
    w.update(HEAD, Some(h.second.head), None).unwrap();
    let error = copy(&w, HEAD, "refs/heads/copy", None).unwrap_err();
    assert_eq!(
        (error.code(), error.public_message()),
        (Code::NotFound, "source not found")
    );
}

struct PendingSource;
impl clearance::PublicationPolicy for PendingSource {
    fn prepare<'a>(
        &'a self,
        op: &'a Operation,
        pair: &'a Pair,
    ) -> crate::BoxFuture<'a, Result<crate::store::publication::Advance, ServerError>> {
        Box::pin(async move {
            let mut advance = clearance::immediate(pair.clone(), [0; 32], vec![]);
            if matches!(&op.kind, OpKind::AdvanceRefs { head, .. } if head.name == HEAD) {
                advance.state = crate::store::publication::Clearance::Pending;
            }
            Ok(advance)
        })
    }
    fn pack_available(&self, _: &RepoId, _: &Hash) -> bool {
        true
    }
}

#[test]
fn published_source_copies_published_pair_when_live_source_is_ahead() {
    let mut w = World::new(Path::Immediate);
    let h = history(&w);
    let original = published(&w, HEAD);
    w.env.pipe.publication_policy = Some(Arc::new(PendingSource));
    let other = unrelated(10);
    w.publish(&h.names, Some(pair_of(&h.second)), &other);
    assert_eq!(w.read(HEAD), Some(other.head));
    let pending = published(&w, HEAD);
    assert!(pending.sequence > pending.published);
    assert_eq!(pending.value, original.value);
    assert_eq!(
        copy(&w, HEAD, "refs/heads/copy", Some(h.second.head)).unwrap(),
        AdvanceOutcome::Committed
    );
    assert_eq!(published(&w, "refs/heads/copy").value, original.value);
}
