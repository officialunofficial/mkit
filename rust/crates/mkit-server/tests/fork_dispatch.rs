//! `Pipeline::dispatch_fork`: the embedded entry for `ForkRepo` (SPEC-SERVER
//! §9.9), written the way a downstream embedder would use it: only the
//! public dispatch types, with no replay key, codec, job decoder or
//! classifier in sight.
#![cfg(feature = "memory")]
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
mod fork_support;
use fork_support::*;
use mkit_attest::grant::Visibility;
use mkit_server::fork::{ForkRequest, ForkResult};
use mkit_server::pipeline::{
    Admission, AdmissionDecision, AdmissionInput, Authenticated, EmbeddedGate, Hooks, NoGate,
    NoOutcomes, NoPreReceive, NoReceipts, OpenAuthorizer, Pipeline,
};
use mkit_server::{BoxFuture, Code, MemoryBlobStore, Partition, Procedure, ServerError};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

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

/// The embedder's gate: counts both checks, notes the storage calls made
/// before each, and can refuse either.
#[derive(Default)]
struct Gate {
    deployments: AtomicU32,
    policies: AtomicU32,
    calls_at_deployment: AtomicU64,
    refuse_deployment: bool,
    refuse_policy: bool,
    store: Option<Counting>,
}

impl Gate {
    fn watching(store: &Counting) -> Self {
        Self {
            store: Some(store.clone()),
            ..Self::default()
        }
    }
}

impl EmbeddedGate<ForkRequest> for Gate {
    fn deployment(&self) -> BoxFuture<'_, Result<(), ServerError>> {
        self.deployments.fetch_add(1, Ordering::SeqCst);
        if let Some(store) = &self.store {
            self.calls_at_deployment
                .store(store.calls(), Ordering::SeqCst);
        }
        let refuse = self.refuse_deployment;
        Box::pin(async move {
            if refuse {
                Err(ServerError::unavailable("deployment sharding mismatch"))
            } else {
                Ok(())
            }
        })
    }

    fn policy<'a>(
        &'a self,
        a: &'a Authenticated,
        request: &'a ForkRequest,
    ) -> BoxFuture<'a, Result<(), ServerError>> {
        assert_eq!(a.procedure(), Procedure::Fork);
        assert_eq!(request.source_ref, "refs/heads/main");
        self.policies.fetch_add(1, Ordering::SeqCst);
        let refuse = self.refuse_policy;
        Box::pin(async move {
            if refuse {
                Err(ServerError::permission_denied("source is not forkable"))
            } else {
                Ok(())
            }
        })
    }
}

async fn dispatch<G: EmbeddedGate<ForkRequest>>(
    source: &Source,
    dest: &Source,
    nonce: u32,
    request: &ForkRequest,
    gate: &G,
) -> Result<ForkResult, ServerError> {
    let body = request.canonical_body();
    let headers = dest.signed_headers(Procedure::Fork, nonce, &body);
    let header = |name: &str| {
        headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };
    Box::pin(source.pipe.dispatch_fork(&header, &body, gate))
        .await
        .map(|(result, _)| result)
}

fn in_progress(error: &ServerError) -> bool {
    let pending = error.code() == Code::Unavailable && error.public_message() == "fork in progress";
    if pending {
        // The pending fork keeps the transport path's status and retry hint.
        assert_eq!(error.http_status(), Some(503));
        assert_eq!(
            error.headers(),
            [("Retry-After".to_owned(), "1".to_owned())]
        );
    }
    pending
}

/// Dispatch with a fresh nonce each time until the fork finishes, running the
/// deployment's timers between calls. Returns the nonce that started it.
async fn finish<G: EmbeddedGate<ForkRequest>>(
    source: &Source,
    dest: &mut Source,
    request: &ForkRequest,
    gate: &G,
) -> (ForkResult, u32) {
    let registry = dest.fork_registry(true);
    let coordinator = Partition::Coordinator(dest.repo.namespace.clone());
    let first = dest.next_nonce();
    let mut nonce = first;
    for _ in 0..40 {
        match dispatch(source, dest, nonce, request, gate).await {
            Err(error) if in_progress(&error) => dest.drain(&registry, &coordinator).await,
            other => return (other.unwrap(), first),
        }
        nonce = dest.next_nonce();
    }
    panic!("fork did not finish");
}

#[tokio::test]
async fn the_policy_runs_for_a_fresh_fork_and_for_an_in_flight_fork() {
    let source = Source::build_with("source", 6, denial).await;
    let dest = source.at("forked");
    let req = request(&source);

    // A fresh fork: the policy runs once, then the fork does.
    let gate = Gate::watching(&source.store);
    match dispatch(&source, &dest, 1, &req, &gate).await {
        Ok(result) => assert_eq!(result.tip, source.head),
        Err(error) => assert!(in_progress(&error), "{error:?}"),
    }
    assert_eq!(gate.deployments.load(Ordering::SeqCst), 1);
    assert_eq!(gate.policies.load(Ordering::SeqCst), 1);

    // An in-flight fork: its job exists and has not run a step. A request for
    // the same fork under a new nonce still goes through the policy, and a
    // refusal stops it before it can advance the job.
    let other = source.at("second");
    let env = mkit_server::fork::ForkEnv {
        store: &source.store,
        shards: source.shards.as_ref(),
        clock: source.clock.as_ref(),
        takedown_denial: true,
        extract_min_bytes: Some(source.cfg.extract_min_bytes),
        limits: mkit_server::fork::ForkLimits::default(),
    };
    mkit_server::fork::start(&env, &req.spec_for(other.repo.clone()), None)
        .await
        .unwrap();
    let refusing = Gate {
        refuse_policy: true,
        ..Gate::default()
    };
    let error = dispatch(&source, &other, 5, &req, &refusing)
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::PermissionDenied);
    assert_eq!(refusing.policies.load(Ordering::SeqCst), 1);
    let job = mkit_server::fork::read_job(&source.store, source.shards.as_ref(), &other.repo)
        .await
        .unwrap()
        .unwrap()
        .0;
    assert!(
        !job.finished(),
        "the refused request did not advance the job"
    );
    // An allowing policy lets the same request join and finish the job.
    let allow = Gate::default();
    match dispatch(&source, &other, 6, &req, &allow).await {
        Ok(result) => assert_eq!(result.tip, source.head),
        Err(error) => assert!(in_progress(&error), "{error:?}"),
    }
    assert_eq!(allow.policies.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn errors_keep_their_status_and_retry_after_through_the_entry() {
    // The entry returns the pipeline's `ServerError` as is: a pending fork's
    // `Retry-After` (503) and a policy's own hint reach the caller untouched.
    struct Busy;
    impl EmbeddedGate<ForkRequest> for Busy {
        fn policy<'a>(
            &'a self,
            _: &'a Authenticated,
            _: &'a ForkRequest,
        ) -> BoxFuture<'a, Result<(), ServerError>> {
            Box::pin(async {
                Err(ServerError::unavailable("busy")
                    .with_http_status(503)
                    .with_header("Retry-After", "7"))
            })
        }
    }
    let source = Source::build_with("source", 4, denial).await;
    let dest = source.at("forked");
    let error = dispatch(&source, &dest, 1, &request(&source), &Busy)
        .await
        .unwrap_err();
    assert_eq!(error.http_status(), Some(503));
    assert_eq!(
        error.headers(),
        &[("Retry-After".to_owned(), "7".to_owned())]
    );
}

#[tokio::test]
async fn the_policy_is_skipped_only_for_a_completed_replay() {
    let source = Source::build_with("source", 6, denial).await;
    let mut dest = source.at("forked");
    let req = request(&source);
    let gate = Gate::watching(&source.store);
    let (result, nonce) = finish(&source, &mut dest, &req, &gate).await;
    assert_eq!(result.tip, source.head);
    let policies = gate.policies.load(Ordering::SeqCst);
    assert!(policies >= 1);

    // The completed request, replayed: the policy stands aside and the
    // result still comes from the pipeline.
    let witness = {
        let headers = dest.signed_headers(Procedure::Fork, nonce, &req.canonical_body());
        let a = authenticate(&source, &headers, &req);
        source.pipe.completed_fork(&a, &req).await.unwrap().unwrap()
    };
    assert_eq!(witness.source(), &source.repo);
    assert_eq!(witness.destination(), &dest.repo);
    let refusing = Gate {
        refuse_policy: true,
        ..Gate::default()
    };
    let again = dispatch(&source, &dest, nonce, &req, &refusing)
        .await
        .unwrap();
    assert_eq!(again, result);
    assert_eq!(refusing.policies.load(Ordering::SeqCst), 0);
    assert_eq!(refusing.deployments.load(Ordering::SeqCst), 1);

    // Any other request to the finished destination is a new request: the
    // policy runs, and its refusal is returned unchanged.
    let error = dispatch(&source, &dest, nonce + 500, &req, &refusing)
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::PermissionDenied);
    assert_eq!(error.public_message(), "source is not forkable");
    assert_eq!(refusing.policies.load(Ordering::SeqCst), 1);
    // The query never answers for a request that is not a completed replay.
    let headers = dest.signed_headers(Procedure::Fork, nonce + 500, &req.canonical_body());
    let a = authenticate(&source, &headers, &req);
    assert!(
        source
            .pipe
            .completed_fork(&a, &req)
            .await
            .unwrap()
            .is_none()
    );
}

fn authenticate(source: &Source, headers: &[(String, String)], req: &ForkRequest) -> Authenticated {
    let body = req.canonical_body();
    source
        .pipe
        .authenticate(&mkit_server::pipeline::RequestMeta {
            procedure: Procedure::Fork,
            header: &|name| {
                headers
                    .iter()
                    .find(|(key, _)| key == name)
                    .map(|(_, value)| value.clone())
            },
            header_values: None,
            unary_body: Some(&body),
            transport_principal: None,
        })
        .unwrap()
}

#[tokio::test]
async fn a_policy_refusal_stops_a_fresh_fork_before_any_work() {
    let source = Source::build_with("source", 4, denial).await;
    let dest = source.at("forked");
    let req = request(&source);
    let gate = Gate {
        refuse_policy: true,
        ..Gate::default()
    };
    let error = dispatch(&source, &dest, 1, &req, &gate).await.unwrap_err();
    assert_eq!(error.code(), Code::PermissionDenied);
    // Nothing was started: the destination has no job.
    assert!(
        mkit_server::fork::read_job(&source.store, source.shards.as_ref(), &dest.repo)
            .await
            .unwrap()
            .is_none()
    );
    // A gate that allows now runs the fork.
    let allow = Gate::default();
    match dispatch(&source, &dest, 2, &req, &allow).await {
        Ok(result) => assert_eq!(result.tip, source.head),
        Err(error) => assert!(in_progress(&error), "{error:?}"),
    }
    assert_eq!(allow.policies.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_unauthenticated_or_mis_signed_request_is_refused_before_any_storage_read() {
    let source = Source::build_with("source", 4, denial).await;
    let dest = source.at("forked");
    let req = request(&source);
    let gate = Gate::default();
    let before = source.store.calls();

    // No credentials at all.
    let body = req.canonical_body();
    let repository = format!("{}/{}", dest.namespace, dest.name);
    let none = |name: &str| (name == "x-repository").then(|| repository.clone());
    let error = source
        .pipe
        .dispatch_fork(&none, &body, &gate)
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::Unauthenticated);

    // A signature over a different body.
    let other = ForkRequest {
        dest_visibility: Visibility::Private,
        ..req.clone()
    };
    let headers = dest.signed_headers(Procedure::Fork, 1, &other.canonical_body());
    let header = |name: &str| {
        headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };
    let error = source
        .pipe
        .dispatch_fork(&header, &body, &gate)
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::Unauthenticated);

    // A signature for a different procedure.
    let headers = dest.signed_headers(Procedure::BeginUpload, 2, &body);
    let header = |name: &str| {
        headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };
    let error = source
        .pipe
        .dispatch_fork(&header, &body, &gate)
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::Unauthenticated);

    assert_eq!(source.store.calls(), before, "no storage read happened");
    assert_eq!(gate.deployments.load(Ordering::SeqCst), 0);
    assert_eq!(gate.policies.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn the_deployment_check_runs_before_any_pipeline_read_and_refuses() {
    let source = Source::build_with("source", 4, denial).await;
    let dest = source.at("forked");
    let req = request(&source);
    let gate = Gate {
        refuse_deployment: true,
        store: Some(source.store.clone()),
        ..Gate::default()
    };
    let before = source.store.calls();
    let error = dispatch(&source, &dest, 1, &req, &gate).await.unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(error.public_message(), "deployment sharding mismatch");
    assert_eq!(gate.calls_at_deployment.load(Ordering::SeqCst), before);
    assert_eq!(source.store.calls(), before);
    assert_eq!(gate.policies.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_unreadable_store_never_skips_the_policy() {
    let source = Source::build_with("source", 6, denial).await;
    let mut dest = source.at("forked");
    let req = request(&source);
    let (_, nonce) = finish(&source, &mut dest, &req, &NoGate).await;
    let gate = Gate::default();
    source.store.fail_reads.store(true, Ordering::SeqCst);
    let error = dispatch(&source, &dest, nonce, &req, &gate)
        .await
        .unwrap_err();
    source.store.fail_reads.store(false, Ordering::SeqCst);
    // The pipeline's own storage error, never a bypass.
    assert!(
        matches!(error.code(), Code::Unavailable | Code::Internal),
        "{error:?}"
    );
    assert_eq!(
        gate.policies.load(Ordering::SeqCst),
        0,
        "no policy, no bypass"
    );
    // Storage back: the completed replay is recognized again.
    dispatch(&source, &dest, nonce, &req, &gate).await.unwrap();
    assert_eq!(gate.policies.load(Ordering::SeqCst), 0);
}

/// An admission that always challenges.
struct Challenging;
impl Admission for Challenging {
    #[allow(clippy::manual_async_fn)] // The trait names `impl Future + MaybeSend`.
    fn admit(
        &self,
        _input: &AdmissionInput<'_>,
    ) -> impl core::future::Future<Output = Result<AdmissionDecision, ServerError>>
    + mkit_server::MaybeSend {
        async {
            Ok(AdmissionDecision::challenge(
                vec![mkit_server::pipeline::Challenge {
                    scheme: "mpp".into(),
                    value: "id=\"c1\"".into(),
                }],
                "payment required",
            ))
        }
    }
}

#[tokio::test]
async fn an_admission_challenge_keeps_its_status_headers_and_details() {
    let source = Source::build_with("source", 4, denial).await;
    let dest = source.at("forked");
    let req = request(&source);
    let pipe = Pipeline::new(
        source.blobs.clone(),
        source.store.clone(),
        Hooks {
            authorizer: OpenAuthorizer,
            admission: Challenging,
            pre_receive: NoPreReceive,
            receipts: NoReceipts,
            outcomes: NoOutcomes,
        },
        denial(Source::config(source.namespace)),
        source.clock.clone(),
        Arc::new(mkit_server::telemetry::NoopMetrics),
    )
    .unwrap();
    let body = req.canonical_body();
    let sign = |nonce: u32| dest.signed_headers(Procedure::Fork, nonce, &body);
    let pick = |headers: &Vec<(String, String)>, name: &str| {
        headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };
    let first = sign(1);
    let embedded = pipe
        .dispatch_fork(&|name| pick(&first, name), &body, &NoGate)
        .await
        .unwrap_err();
    // The transport path's answer for the same request.
    let second = sign(2);
    let a = pipe
        .authenticate(&mkit_server::pipeline::RequestMeta {
            procedure: Procedure::Fork,
            header: &|name| pick(&second, name),
            header_values: None,
            unary_body: Some(&body),
            transport_principal: None,
        })
        .unwrap();
    let direct = Box::pin(pipe.fork_repo(&a, req.clone())).await.unwrap_err();
    assert_eq!(embedded.code(), direct.code());
    assert_eq!(embedded.http_status(), direct.http_status());
    assert_eq!(embedded.headers(), direct.headers());
    assert_eq!(embedded.details(), direct.details());
    assert!(
        !embedded.details().is_empty(),
        "the challenge is in the details"
    );
    let _: &MemoryBlobStore = &source.blobs;
}
