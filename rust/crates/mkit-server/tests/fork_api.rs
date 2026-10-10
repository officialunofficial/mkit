//! `Pipeline::fork_repo` against a published source repository: the request
//! stages around the durable job (SPEC-SERVER §9.9).
#![cfg(feature = "memory")]
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
mod fork_support;
use fork_support::*;
use mkit_attest::grant::Visibility;
use mkit_server::fork::{ForkRequest, ForkResult};
use mkit_server::pipeline::ShardMap as _;
use mkit_server::pipeline::{
    Admission, AdmissionDecision, AdmissionInput, Authenticated, Authorizer, HookSet, Hooks,
    NoOutcomes, NoPreReceive, NoReceipts, Pipeline,
};
use mkit_server::quota::{QuotaCharge, QuotaLimits, QuotaScope};
use mkit_server::store::adapter_spi::{
    codec::{self, ReservationV1},
    keys,
};
use mkit_server::{
    AuthzFacts, Code, MemoryBlobStore, NamespaceStore, OpKind, Operation, Partition, Procedure,
    ServerError,
};
use std::sync::{Arc, Mutex};

fn denial(mut cfg: mkit_server::pipeline::PipelineConfig) -> mkit_server::pipeline::PipelineConfig {
    cfg.takedown_denial = true;
    cfg
}

fn request(source: &Source) -> ForkRequest {
    ForkRequest {
        source: source.repo.clone(),
        source_ref: "refs/heads/main".into(),
        expected_tip: source.head,
        dest_visibility: Visibility::Public,
    }
}

/// What admission saw: declared bytes, bytes new to the repository, and the
/// fork's source name and charged bytes.
type Admitted = (u64, Option<u64>, Option<(String, u64)>);

/// What the hooks saw.
#[derive(Default)]
struct Seen {
    /// Refuse the destination write of a fork.
    refuse_forks: std::sync::atomic::AtomicBool,
    ops: Mutex<Vec<Operation>>,
    admissions: Mutex<Vec<Admitted>>,
}

/// An authorizer that records operations and can refuse reads of one name.
struct Spy {
    seen: Arc<Seen>,
    refuse_reads_of: Option<String>,
}

impl Authorizer for Spy {
    fn authorize(
        &self,
        op: &Operation,
    ) -> impl core::future::Future<Output = Result<AuthzFacts, ServerError>> + mkit_server::MaybeSend
    {
        self.seen.ops.lock().unwrap().push(op.clone());
        let refuse = self
            .refuse_reads_of
            .as_deref()
            .is_some_and(|name| op.repo.name.as_str() == name && !op.procedure().is_write())
            || (op.procedure() == Procedure::Fork
                && self
                    .seen
                    .refuse_forks
                    .load(std::sync::atomic::Ordering::SeqCst));
        async move {
            if refuse {
                Err(ServerError::permission_denied("not for you"))
            } else {
                Ok(AuthzFacts::default())
            }
        }
    }
}

/// An admission that records its input and answers with a scripted charge
/// and reservation.
struct Scripted {
    seen: Arc<Seen>,
    limits: QuotaLimits,
    /// Reservation ids are `<prefix>-<n>`, one per admission.
    reservation: Option<&'static str>,
    count: std::sync::atomic::AtomicU32,
}

impl Admission for Scripted {
    fn admit(
        &self,
        input: &AdmissionInput<'_>,
    ) -> impl core::future::Future<Output = Result<AdmissionDecision, ServerError>>
    + mkit_server::MaybeSend {
        self.seen.admissions.lock().unwrap().push((
            input.declared_bytes,
            input.new_to_repo_bytes,
            input
                .fork
                .map(|f| (f.source.name.as_str().to_owned(), f.pack_bytes)),
        ));
        let charge = input.op.auth.as_ref().map(|auth| QuotaCharge {
            scope: QuotaScope::for_signer(&input.op.repo.namespace, &auth.signer),
            bytes: input.declared_bytes,
            limits: self.limits,
        });
        let mut decision = AdmissionDecision::allow(charge.into_iter().collect());
        if let Some(prefix) = self.reservation {
            let n = self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            decision = decision.with_reservation(format!("{prefix}-{n}"));
        }
        async move { Ok(decision) }
    }
}

type Hooked = Hooks<Spy, Scripted, NoPreReceive, NoReceipts, NoOutcomes>;

fn hooked(
    source: &Source,
    refuse_reads_of: Option<&str>,
    limits: QuotaLimits,
    reservation: Option<&'static str>,
) -> (Pipeline<MemoryBlobStore, Counting, Hooked>, Arc<Seen>) {
    let seen = Arc::new(Seen::default());
    let hooks = Hooks {
        authorizer: Spy {
            seen: seen.clone(),
            refuse_reads_of: refuse_reads_of.map(str::to_owned),
        },
        admission: Scripted {
            seen: seen.clone(),
            limits,
            reservation,
            count: std::sync::atomic::AtomicU32::new(0),
        },
        pre_receive: NoPreReceive,
        receipts: NoReceipts,
        outcomes: NoOutcomes,
    };
    let mut cfg = denial(Source::config(source.namespace));
    cfg.authorizer_role = mkit_server::policy::AuthorizerRole::Check;
    let pipe = Pipeline::new(
        source.blobs.clone(),
        source.store.clone(),
        hooks,
        cfg,
        source.clock.clone(),
        Arc::new(mkit_server::telemetry::NoopMetrics),
    )
    .unwrap();
    (pipe, seen)
}

fn authenticate(dest: &Source, nonce: u32, request: &ForkRequest) -> Authenticated {
    dest.authenticate_body(Procedure::Fork, nonce, &request.canonical_body())
}

async fn call<H: HookSet>(
    pipe: &Pipeline<MemoryBlobStore, Counting, H>,
    dest: &Source,
    nonce: u32,
    request: &ForkRequest,
) -> Result<ForkResult, ServerError> {
    Box::pin(pipe.fork_repo(&authenticate(dest, nonce, request), request.clone())).await
}

fn in_progress(error: &ServerError) -> bool {
    error.code() == Code::Unavailable && error.public_message() == "fork in progress"
}

/// Call until the fork finishes, running the deployment's timers between
/// calls, each with a fresh nonce.
async fn finish<H: HookSet>(
    pipe: &Pipeline<MemoryBlobStore, Counting, H>,
    dest: &mut Source,
    request: &ForkRequest,
) -> Result<ForkResult, ServerError> {
    let registry = dest.fork_registry(true);
    let coordinator = Partition::Coordinator(dest.repo.namespace.clone());
    for _ in 0..40 {
        let nonce = dest.next_nonce();
        match call(pipe, dest, nonce, request).await {
            Err(error) if in_progress(&error) => dest.drain(&registry, &coordinator).await,
            other => return other,
        }
    }
    panic!("fork did not finish");
}

async fn reservation(source: &Source, dest: &RepoId, rid: &str) -> Option<ReservationV1> {
    source
        .store
        .inner
        .get(
            &source.shards.coordinator(&dest.namespace),
            &keys::reservation(rid).unwrap(),
        )
        .await
        .unwrap()
        .map(|raw| codec::decode_reservation(&raw).unwrap())
}

use mkit_server::RepoId;

#[tokio::test]
async fn a_signed_fork_is_visible_to_a_remix_and_a_replay_returns_the_same_result() {
    let source = Source::build_with("source", 12, denial).await;
    let mut dest = source.at("forked");
    let req = request(&source);
    let result = finish(source.pipe.as_ref(), &mut dest, &req).await.unwrap();
    assert_eq!(result.tip, source.head);
    assert_eq!(result.packmap, source.packmap);
    assert!(result.pack_count >= 2 && result.object_count >= 12);
    // The destination holds membership and no ref: a plain copy is never visible.
    assert!(dest.published("refs/heads/main").await.is_none());
    // The same signed request returns the stored result, through its replay
    // record, without running anything again.
    let nonce = dest.nonce;
    let before = source.store.calls();
    let again = call(source.pipe.as_ref(), &dest, nonce, &req)
        .await
        .unwrap();
    assert_eq!(again, result);
    assert!(
        source.store.calls() - before < 12,
        "a replay is a few reads"
    );
    // A remix commit on the inherited tree publishes on top of the fork.
    let (bytes, head) = commit_pack(source.tree, vec![], b"remix");
    let pack = mkit_core::hash::hash(&bytes);
    dest.push(bytes, head, Some(source.packmap), &[pack]).await;
    assert_eq!(
        dest.published("refs/heads/main").await.map(|p| p.0),
        Some(Some(head))
    );
}

#[tokio::test]
async fn refusals_are_uniform_and_the_tip_is_a_required_cas() {
    let source = Source::build_with("source", 6, denial).await;
    let mut dest = source.at("forked");
    let mut absent = request(&source);
    absent.source.name = mkit_server::RepoName::new("nowhere").unwrap();
    let (refusing, _) = hooked(
        &source,
        Some("source"),
        QuotaLimits::new(3_600_000, 10, 1 << 40),
        None,
    );
    let (open, _) = hooked(
        &source,
        None,
        QuotaLimits::new(3_600_000, 10, 1 << 40),
        None,
    );
    let n = dest.next_nonce();
    let unreadable = call(&refusing, &dest, n, &request(&source))
        .await
        .unwrap_err();
    let n = dest.next_nonce();
    let missing = call(&open, &dest, n, &absent).await.unwrap_err();
    for error in [&unreadable, &missing] {
        assert_eq!(error.code(), Code::NotFound);
        assert_eq!(error.public_message(), "source not found");
    }
    assert_eq!(format!("{unreadable:?}"), format!("{missing:?}"));
    // A branch the source never published is the same answer.
    let mut no_branch = request(&source);
    no_branch.source_ref = "refs/heads/other".into();
    let n = dest.next_nonce();
    assert_eq!(
        format!("{:?}", call(&open, &dest, n, &no_branch).await.unwrap_err()),
        format!("{missing:?}")
    );
    // After read authorization the tip is a required compare-and-swap.
    let mut stale = request(&source);
    stale.expected_tip = [9; 32];
    let n = dest.next_nonce();
    let error = call(&open, &dest, n, &stale).await.unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert_eq!(error.public_message(), "source tip changed");
    // Nothing was registered by any refusal.
    assert!(
        source
            .store
            .inner
            .get(
                &source.shards.coordinator(&dest.repo.namespace),
                &keys::repo_record(&dest.repo.name)
            )
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn the_hooks_see_the_source_facts_and_the_charge_settles_once() {
    let source = Source::build_with("source", 8, denial).await;
    let mut dest = source.at("forked");
    let limits = QuotaLimits::new(3_600_000, 10, 1 << 40);
    let (pipe, seen) = hooked(&source, None, limits, Some("fork-rid-1"));
    let req = request(&source);
    let result = finish(&pipe, &mut dest, &req).await.unwrap();
    // The Authority hook decided on the destination write with the source facts.
    let ops = seen.ops.lock().unwrap().clone();
    let fork = ops
        .iter()
        .find_map(|op| match &op.kind {
            OpKind::ForkRepo {
                source,
                source_ref,
                expected_tip,
                source_visibility,
                source_visibility_revision,
                dest_visibility,
            } => Some((
                source.clone(),
                source_ref.clone(),
                *expected_tip,
                *source_visibility,
                *source_visibility_revision,
                *dest_visibility,
                op.repo.clone(),
            )),
            _ => None,
        })
        .expect("the write was authorized as a fork");
    assert_eq!(fork.0, source.repo);
    assert_eq!(fork.1, "refs/heads/main");
    assert_eq!(fork.2, source.head);
    assert_eq!(fork.3, Some(Visibility::Public));
    assert_eq!(fork.4, 0);
    assert_eq!(fork.5, Visibility::Public);
    assert_eq!(fork.6, dest.repo);
    // Admission was charged the exact bytes the fork inherits, which the
    // source's counter bounds.
    let stored = codec::decode_repo_storage(
        &source
            .store
            .inner
            .get(
                &source.shards.coordinator(&source.repo.namespace),
                &keys::repo_storage(&source.repo.name),
            )
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap()
    .stored_bytes;
    let admissions = seen.admissions.lock().unwrap().clone();
    let forked: Vec<_> = admissions.iter().filter(|a| a.2.is_some()).collect();
    assert_eq!(forked[0].0, result.pack_bytes);
    assert_eq!(forked[0].1, Some(result.pack_bytes));
    assert_eq!(forked[0].2, Some(("source".to_owned(), result.pack_bytes)));
    assert!(result.pack_bytes <= stored);
    // The reservation committed with the exact inherited bytes, once.
    let Some(ReservationV1::Committed {
        bytes_stored,
        new_to_repo,
        refs,
        ..
    }) = reservation(&source, &dest.repo, "fork-rid-1-1").await
    else {
        panic!("expected a committed reservation")
    };
    assert_eq!(
        (bytes_stored, new_to_repo),
        (result.pack_bytes, result.pack_bytes)
    );
    assert!(refs.is_empty());
}

#[tokio::test]
async fn an_exhausted_quota_window_refuses_the_fork_before_any_work() {
    let source = Source::build_with("source", 6, denial).await;
    let mut dest = source.at("forked");
    // The window holds no operation: a hard bound, not advisory.
    let (pipe, _) = hooked(
        &source,
        None,
        QuotaLimits::new(3_600_000, 0, 1 << 40),
        Some("fork-rid-2"),
    );
    source
        .store
        .record
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let error = finish(&pipe, &mut dest, &request(&source))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::ResourceExhausted);
    assert!(error.public_message().contains("quota"), "{error:?}");
    // No job, no registered destination, and the reservation was aborted.
    let coordinator = source.shards.coordinator(&dest.repo.namespace);
    assert!(
        mkit_server::fork::read_job(&source.store, source.shards.as_ref(), &dest.repo)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        source
            .store
            .inner
            .get(&coordinator, &keys::repo_record(&dest.repo.name))
            .await
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        reservation(&source, &dest.repo, "fork-rid-2-1").await,
        Some(ReservationV1::Aborted { .. })
    ));
    // Only the reservation was written, then released: no row of the fork.
    let writes = source.store.log.lock().unwrap().len();
    assert!(writes <= 2, "{writes} batches before the refusal");
}

#[tokio::test]
async fn a_second_request_for_the_same_fork_joins_the_job_and_is_not_charged() {
    let source = Source::build_with("source", 6, denial).await;
    let mut dest = source.at("forked");
    let limits = QuotaLimits::new(3_600_000, 10, 1 << 40);
    let (pipe, _) = hooked(&source, None, limits, Some("fork-rid-3"));
    let req = request(&source);
    let first = call(&pipe, &dest, dest.nonce + 1, &req).await;
    let joined = call(&pipe, &dest, dest.nonce + 2, &req).await;
    for r in [&first, &joined] {
        if let Err(error) = r {
            assert!(in_progress(error), "{error:?}");
        }
    }
    let result = finish(&pipe, &mut dest, &req).await.unwrap();
    assert!(result.pack_count > 0);
    // The first request's reservation is the job's and committed; a request
    // that joins the job is admitted, reserved and charged nothing.
    assert!(matches!(
        reservation(&source, &dest.repo, "fork-rid-3-1").await,
        Some(ReservationV1::Committed { .. })
    ));
    for n in 2..=4 {
        assert!(
            reservation(&source, &dest.repo, &format!("fork-rid-3-{n}"))
                .await
                .is_none()
        );
    }
    let signer = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let scope = QuotaScope::for_signer(&dest.repo.namespace, signer.verifying_key().as_bytes());
    let ops = source
        .store
        .inner
        .get(
            &source.shards.coordinator(&dest.repo.namespace),
            &keys::quota(&scope),
        )
        .await
        .unwrap()
        .map(|raw| codec::decode_quota_state(&raw).unwrap().ops);
    assert_eq!(ops, Some(1));
}

#[tokio::test]
async fn malformed_and_unauthorized_requests_are_refused_before_any_state() {
    let source = Source::build_with("source", 4, denial).await;
    let mut dest = source.at("forked");
    let req = request(&source);
    // The signed body must be the request.
    let other = ForkRequest {
        dest_visibility: Visibility::Private,
        ..req.clone()
    };
    let n = dest.next_nonce();
    let auth = authenticate(&dest, n, &other);
    let error = Box::pin(source.pipe.fork_repo(&auth, req.clone()))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::Unauthenticated);
    // A fork of a repository into itself is a malformed request.
    let n = dest.next_nonce();
    let same = ForkRequest {
        source: dest.repo.clone(),
        ..req.clone()
    };
    let error = call(source.pipe.as_ref(), &dest, n, &same)
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);
    // Only a branch can be forked.
    let n = dest.next_nonce();
    let tag = ForkRequest {
        source_ref: "refs/tags/v1".into(),
        ..req.clone()
    };
    let error = call(source.pipe.as_ref(), &dest, n, &tag)
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);
    // A destination that exists is not empty; so is one a different fork
    // already claimed.
    let mut dest = source.at("forked");
    finish(source.pipe.as_ref(), &mut dest, &req).await.unwrap();
    let n = dest.next_nonce();
    let error = call(source.pipe.as_ref(), &dest, n, &other)
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert_eq!(error.public_message(), "destination not empty");
}

/// Fork through the pipeline, then publish a remix on the inherited tree, at
/// 50 ms per storage call; report the time to visible and the walk's work.
async fn measure(files: u32, extra: u32) {
    use mkit_server::Clock as _;
    use std::sync::atomic::Ordering;
    let objects = files + extra + 2;
    let source = Source::build_full("source", files, extra, denial).await;
    let mut dest = source.at("forked");
    let req = request(&source);
    source.store.latency_ms.store(50, Ordering::SeqCst);
    let (calls, started) = (source.store.calls(), source.clock.now_ms());
    let result = finish(source.pipe.as_ref(), &mut dest, &req).await.unwrap();
    let (fork_calls, fork_ms) = (
        source.store.calls() - calls,
        source.clock.now_ms() - started,
    );
    let cleared = source
        .store
        .inner
        .get(
            &source.shards.coordinator(&dest.repo.namespace),
            &keys::fork_set(&dest.repo.name, 0),
        )
        .await
        .unwrap()
        .map_or(0, |v| v.as_bytes().len() / 32);
    // The remix: its modeled work is the calls it makes at 50 ms each.
    let (bytes, head) = commit_pack(source.tree, vec![], b"remix");
    let pack = mkit_core::hash::hash(&bytes);
    source.store.latency_ms.store(0, Ordering::SeqCst);
    source.store.scans.store(0, Ordering::SeqCst);
    let calls = source.store.calls();
    dest.push(bytes, head, Some(source.packmap), &[pack]).await;
    let remix_calls = source.store.calls() - calls;
    let scans = source.store.scans.load(Ordering::SeqCst);
    eprintln!(
        "FORKAPI objects={objects} packs={} fork_calls={fork_calls} fork_s={} cleared={cleared} \
         remix_calls={remix_calls} remix_s={} remix_index_scans={scans} visible_s={}",
        result.pack_count,
        fork_ms / 1000,
        remix_calls * 50 / 1000,
        (fork_ms + i64::try_from(remix_calls * 50).unwrap()) / 1000,
    );
    assert!(scans < 40, "{scans} index scans walked inherited objects");
}

#[tokio::test]
async fn measures_500_objects_through_the_pipeline() {
    measure(496, 0).await;
}

#[tokio::test]
#[ignore = "large fork fixture; exercised by the ignored-lane CI profile"]
async fn measures_3000_objects_through_the_pipeline() {
    measure(2_996, 0).await;
}

#[tokio::test]
#[ignore = "large fork fixture; exercised by the ignored-lane CI profile"]
async fn measures_10000_objects_through_the_pipeline() {
    measure(2_996, 7_000).await;
}

fn plain_limits() -> QuotaLimits {
    QuotaLimits::new(3_600_000, 10, 1 << 40)
}

async fn quota_ops(source: &Source, dest: &RepoId) -> Option<u32> {
    let signer = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let scope = QuotaScope::for_signer(&dest.namespace, signer.verifying_key().as_bytes());
    source
        .store
        .inner
        .get(
            &source.shards.coordinator(&dest.namespace),
            &keys::quota(&scope),
        )
        .await
        .unwrap()
        .map(|raw| codec::decode_quota_state(&raw).unwrap().ops)
}

#[tokio::test]
async fn a_request_that_loses_the_race_to_start_the_job_releases_its_reservation() {
    use mkit_server::fork::{ForkEnv, ForkLimits};
    let source = Source::build_with("source", 6, denial).await;
    let mut dest = source.at("forked");
    let (pipe, _) = hooked(&source, None, plain_limits(), Some("race"));
    let req = request(&source);
    // A competing request creates the same job just before this one's batch.
    let (store, clock) = (source.store.clone(), source.clock.clone());
    let spec = req.spec_for(dest.repo.clone());
    let hook: Hook = Arc::new(move || {
        let (store, clock, spec) = (store.clone(), clock.clone(), spec.clone());
        Box::pin(async move {
            let shards = mkit_server::pipeline::D34Shards;
            let env = ForkEnv {
                store: &store,
                shards: &shards,
                clock: clock.as_ref(),
                takedown_denial: true,
                extract_min_bytes: None,
                limits: ForkLimits::default(),
            };
            mkit_server::fork::start(&env, &spec, None).await.unwrap();
        })
    });
    *source.store.trigger.lock().unwrap() = Some(("fj", hook));
    let result = finish(&pipe, &mut dest, &req).await.unwrap();
    assert!(result.pack_count > 0);
    // The loser's reservation is released as a replay race and its charge
    // went with its failed batch.
    assert!(matches!(
        reservation(&source, &dest.repo, "race-1").await,
        Some(ReservationV1::Aborted {
            reason: mkit_server::store::adapter_spi::codec::AbortReason::ReplayRace,
            ..
        })
    ));
    assert_eq!(quota_ops(&source, &dest.repo).await, None);
}

#[tokio::test]
async fn a_lost_reply_on_the_job_batch_is_a_start_not_a_failure() {
    let source = Source::build_with("source", 6, denial).await;
    let mut dest = source.at("forked");
    let (pipe, _) = hooked(&source, None, plain_limits(), Some("lost"));
    // Applies of the request: the reservation, then the job batch, whose
    // reply is lost after it committed.
    source.store.crash_after(2, true);
    let result = finish(&pipe, &mut dest, &request(&source)).await.unwrap();
    assert!(result.pack_count > 0);
    assert!(matches!(
        reservation(&source, &dest.repo, "lost-1").await,
        Some(ReservationV1::Committed { .. })
    ));
    assert_eq!(quota_ops(&source, &dest.repo).await, Some(1));
}

#[tokio::test]
async fn a_destination_the_hook_refuses_or_that_exists_is_refused_before_admission() {
    let source = Source::build_with("source", 6, denial).await;
    let mut dest = source.at("forked");
    let (pipe, seen) = hooked(&source, None, plain_limits(), Some("early"));
    let req = request(&source);
    // The Authorize hook refuses the destination write.
    seen.refuse_forks
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let n = dest.next_nonce();
    let error = call(&pipe, &dest, n, &req).await.unwrap_err();
    assert_eq!(error.code(), Code::PermissionDenied);
    seen.refuse_forks
        .store(false, std::sync::atomic::Ordering::SeqCst);
    // A destination registered by anything else is not empty.
    source
        .store
        .inner
        .apply(
            &source.shards.coordinator(&dest.repo.namespace),
            mkit_server::Batch::new().put(
                keys::repo_record(&dest.repo.name),
                codec::encode_repo_record(&codec::RepoRecord { created_at_ms: 1 }),
            ),
        )
        .await
        .unwrap();
    let n = dest.next_nonce();
    let error = call(&pipe, &dest, n, &req).await.unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert_eq!(error.public_message(), "destination not empty");
    // Neither reached admission: no reservation, no charge.
    assert!(seen.admissions.lock().unwrap().is_empty());
    assert!(reservation(&source, &dest.repo, "early-1").await.is_none());
    assert_eq!(quota_ops(&source, &dest.repo).await, None);
}

#[tokio::test]
async fn blocked_content_is_the_same_not_found_as_an_absent_source() {
    use mkit_server::Clock as _;
    use mkit_server::store::{BlockEntry, ContentIndex};
    let source = Source::build_with("source", 6, denial).await;
    let mut dest = source.at("forked");
    let (pipe, seen) = hooked(&source, None, plain_limits(), Some("blk"));
    let mut absent = request(&source);
    absent.source.name = mkit_server::RepoName::new("nowhere").unwrap();
    let n = dest.next_nonce();
    let missing = call(&pipe, &dest, n, &absent).await.unwrap_err();
    let now = u64::try_from(source.clock.now_ms()).unwrap();
    ContentIndex::new(source.store.inner.clone())
        .block(&blob(1, 8).0, &BlockEntry::new("takedown", now), now)
        .await
        .unwrap();
    let n = dest.next_nonce();
    let blocked = call(&pipe, &dest, n, &request(&source)).await.unwrap_err();
    assert_eq!(format!("{blocked:?}"), format!("{missing:?}"));
    assert_eq!(blocked.public_message(), "source not found");
    // The source was refused before anything was admitted or reserved.
    assert!(seen.admissions.lock().unwrap().is_empty());
    assert!(reservation(&source, &dest.repo, "blk-1").await.is_none());
}

#[tokio::test]
async fn a_source_that_changes_visibility_while_the_hooks_run_refuses_the_fork() {
    let source = Source::build_with("source", 6, denial).await;
    let mut dest = source.at("forked");
    let (pipe, _) = hooked(&source, None, plain_limits(), Some("flip"));
    // The owner makes the source private after the Authorize hook decided on a
    // public one, just before the reservation is recorded.
    let (store, repo) = (source.store.clone(), source.repo.clone());
    let hook: Hook = Arc::new(move || {
        let (store, repo) = (store.clone(), repo.clone());
        Box::pin(async move {
            let shards = mkit_server::pipeline::D34Shards;
            store
                .inner
                .apply(
                    &shards.coordinator(&repo.namespace),
                    mkit_server::Batch::new().put(
                        keys::repo_visibility(&repo.name),
                        codec::encode_repo_visibility(&codec::RepoVisibilityV1 {
                            visibility: codec::StoredVisibility::Private,
                            last_created_ms: 0,
                            last_statement_id: None,
                            changed_ms: 0,
                        }),
                    ),
                )
                .await
                .unwrap();
        })
    });
    *source.store.trigger.lock().unwrap() = Some(("o", hook));
    let n = dest.next_nonce();
    let error = call(&pipe, &dest, n, &request(&source)).await.unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(error.public_message(), "source changed; retry");
    assert!(matches!(
        reservation(&source, &dest.repo, "flip-1").await,
        Some(ReservationV1::Aborted { .. })
    ));
    assert!(
        mkit_server::fork::read_job(&source.store, source.shards.as_ref(), &dest.repo)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(quota_ops(&source, &dest.repo).await, None);
}

#[tokio::test]
async fn the_default_admission_counts_a_fork_against_the_namespace_cap() {
    use mkit_server::Clock as _;
    let source = Source::build_with("source", 6, denial).await;
    let mut dest = source.at("forked");
    finish(source.pipe.as_ref(), &mut dest, &request(&source))
        .await
        .unwrap();
    let window = mkit_server::quota::namespace_window(
        source.clock.now_ms(),
        mkit_server::quota::DEFAULT_WRITE_QUOTA.window_ms,
    );
    let usage = source
        .store
        .inner
        .get(
            &source.shards.coordinator(&dest.repo.namespace),
            &keys::quota_total(window),
        )
        .await
        .unwrap()
        .expect("the namespace counter is charged by the fork");
    assert!(codec::decode_namespace_usage(&usage).unwrap().ops >= 1);
}
