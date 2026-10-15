//! Portable fork cases over test-only fixture controls and signed operations.
//! A binding may prepare a valid source; every fork decision and destination
//! read/write probe still passes through the server's ordinary authentication.

use std::time::Duration;

use buffa::Message as _;
use mkit_core::hash::{from_hex, hash, to_hex};
use mkit_transport_connect::generated::{
    AdvanceRefsResponse, DownloadPackRequest, DownloadPackResponse, PackExistsRequest,
    PackExistsResponse,
};

use crate::control::{
    ForkFixture, ForkFixtureQuery, ForkObservation, ForkQuery, ForkResultView, ReplayIdentity,
    Request,
};
use crate::controlled::ControlClient;
use crate::wire::Feature;
use crate::wire::cases::{CaseResult, Ctx, Exp, Failure, advance_req, ensure, sign_unary};
use crate::wire::client::{Reply, Rpc, frame};
use crate::wire::sign::{SignedOp, body_commitment};

const FORK_PROCEDURE: &str = "/mkit.server.v1/ForkRepo";
const FORK_PATH: &str = "/__mkit_test/fork";

#[derive(Clone)]
struct ForkOperation {
    signed: SignedOp,
    body: Vec<u8>,
}

struct Fixture {
    source: ForkFixture,
    query: ForkQuery,
    op: ForkOperation,
}

async fn fixture(ctx: &Ctx, control: &ControlClient, ordinal: u64) -> Result<Fixture, Failure> {
    let signer = ctx.v2_signer("main")?;
    let namespace = format!("ed25519-{}", signer.public_key_hex());
    let suffix = to_hex(&hash(ctx.ns().as_bytes()));
    let destination = format!("{namespace}/fork-{}-{ordinal}", &suffix[..16]);
    let source = control
        .command(&Request::PrepareFork {
            query: ForkFixtureQuery {
                destination: destination.clone(),
                signer: signer.public_key_hex(),
                source_head: ctx.head("source"),
            },
        })
        .await?
        .fork_fixture
        .ok_or("prepare_fork returned no valid-source fixture")?;
    ensure!(
        !source.packs.is_empty() && source.packs.len() == source.objects.len(),
        "fork fixture needs a nonempty pack/object pair list"
    );
    for id in source
        .packs
        .iter()
        .chain(&source.objects)
        .chain([&source.tip, &source.packmap])
    {
        from_hex(id).map_err(|e| format!("invalid fork fixture object ID: {e}"))?;
    }
    ensure!(
        source.source_repository != destination
            && source.source_repository.split_once('/').map(|(ns, _)| ns)
                == Some(namespace.as_str())
            && source.source_head == ctx.head("source"),
        "fork fixture has the wrong source identity"
    );
    let body = format!(
        "mkit-fork:v1\n{}\n{}\n{}\npublic",
        source.source_repository, source.source_head, source.tip
    )
    .into_bytes();
    let mut envelope = signer.envelope(FORK_PROCEDURE, body_commitment(&body));
    envelope.repository.clone_from(&destination);
    envelope.digest = Some(to_hex(&hash(&body)));
    let envelope_signature = signer.sign(&envelope);
    let query = ForkQuery {
        destination: destination.clone(),
        replay: ReplayIdentity {
            audience: envelope.audience,
            repository: destination,
            signer: signer.public_key_hex(),
            nonce: envelope_signature.nonce.clone(),
        },
        packs: source.packs.clone(),
    };
    Ok(Fixture {
        source,
        query,
        op: ForkOperation {
            signed: envelope_signature,
            body,
        },
    })
}

async fn observe(control: &ControlClient, fixture: &Fixture) -> Result<ForkObservation, Failure> {
    let snapshot = control
        .command(&Request::ObserveFork {
            query: fixture.query.clone(),
        })
        .await?
        .fork_observation
        .ok_or("observe_fork returned no atomic snapshot")?;
    ensure!(
        snapshot.staged_memberships.len() == fixture.source.packs.len()
            && snapshot.visible_memberships.len() == fixture.source.packs.len(),
        "fork observation did not preserve membership query order/length"
    );
    ensure!(
        snapshot.head.is_none() && snapshot.packmap.is_none(),
        "fork created a destination ref: {snapshot:?}"
    );
    Ok(snapshot)
}

async fn pause(
    control: &ControlClient,
    fixture: &Fixture,
    step: &str,
    decision_class: &str,
    occurrence: Option<u64>,
) -> CaseResult {
    control
        .command(&Request::Pause {
            step: step.into(),
            repository: fixture.query.destination.clone(),
            head: fixture.source.source_head.clone(),
            decision_class: Some(decision_class.into()),
            occurrence,
            on_resume: None,
        })
        .await?;
    Ok(())
}

async fn invoke(ctx: &Ctx, op: &ForkOperation) -> Result<Reply, Failure> {
    ctx.client()
        .post(
            FORK_PATH,
            "application/octet-stream",
            &op.signed.headers,
            op.body.clone(),
        )
        .await
        .map_err(Into::into)
}

fn refusal(reply: &Reply) -> Result<String, Failure> {
    let value: serde_json::Value = serde_json::from_slice(&reply.body)
        .map_err(|e| format!("fork refusal is not JSON: {e}"))?;
    value
        .get("code")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Failure::Fail(format!("fork refusal has no protocol code: {value}")))
}

/// Same signed identity on every retry. A pending job is neither success nor a
/// terminal refusal; the outer case timeout bounds implementations that stall.
async fn drive(ctx: Ctx, op: ForkOperation) -> Result<Reply, Failure> {
    loop {
        let reply = invoke(&ctx, &op).await?;
        if reply.status == 200 || !matches!(refusal(&reply)?.as_str(), "aborted" | "unavailable") {
            return Ok(reply);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

struct PendingFork(tokio::task::JoinHandle<Result<Reply, Failure>>);

impl Drop for PendingFork {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn start(ctx: &Ctx, fixture: &Fixture) -> PendingFork {
    PendingFork(tokio::spawn(drive(ctx.clone(), fixture.op.clone())))
}

async fn finish(mut pending: PendingFork) -> Result<Reply, Failure> {
    (&mut pending.0)
        .await
        .map_err(|e| format!("fork request task: {e}"))?
}

fn inert(snapshot: &ForkObservation) -> CaseResult {
    ensure!(
        !snapshot.accepted
            && !snapshot.writable
            && snapshot.result.is_none()
            && snapshot.visible_memberships.iter().all(|visible| !visible)
            && snapshot.replay.as_ref().is_none_or(|replay| {
                replay.state != "committed" || replay.result.as_deref() != Some("fork_committed")
            })
            && snapshot
                .outcome
                .as_ref()
                .is_none_or(|o| o.state != "committed" && o.terminal_count <= 1),
        "unaccepted fork destination became active: {snapshot:?}"
    );
    Ok(())
}

fn accepted(snapshot: &ForkObservation, fixture: &Fixture) -> CaseResult {
    let count = u64::try_from(fixture.source.packs.len())
        .map_err(|e| format!("fixture pack count: {e}"))?;
    let result_matches = snapshot.result.as_ref().is_some_and(|result| {
        result.source_repository == fixture.source.source_repository
            && result.source_head == fixture.source.source_head
            && result.tip == fixture.source.tip
            && result.packmap == fixture.source.packmap
            && result.pack_count == count
            && from_hex(&result.pack_set_digest).is_ok()
    });
    ensure!(
        snapshot.accepted
            && !snapshot.failed
            && result_matches
            && snapshot.progress_commits == fixture.source.advancing_commits
            && snapshot.replay.as_ref().is_some_and(|r| {
                r.state == "committed" && r.result.as_deref() == Some("fork_committed")
            })
            && snapshot
                .outcome
                .as_ref()
                .is_some_and(|o| o.state == "committed" && o.terminal_count == 1),
        "fork acceptance lacks atomic result, replay, or single outcome: {snapshot:?}"
    );
    Ok(())
}

fn success(reply: &Reply, fixture: &Fixture) -> CaseResult {
    ensure!(reply.status == 200, "fork did not succeed: {reply:?}");
    let result: serde_json::Value =
        serde_json::from_slice(&reply.body).map_err(|e| format!("fork result schema: {e}"))?;
    let pack_count = u64::try_from(fixture.source.packs.len())
        .map_err(|e| format!("fixture pack count: {e}"))?;
    ensure!(
        result.get("tip").and_then(serde_json::Value::as_str) == Some(&fixture.source.tip)
            && result.get("pack_count").and_then(serde_json::Value::as_u64) == Some(pack_count),
        "fork returned a result inconsistent with its source: {result:?}"
    );
    Ok(())
}

fn wire_result_matches(reply: &Reply, expected: &ForkResultView) -> CaseResult {
    let result: serde_json::Value =
        serde_json::from_slice(&reply.body).map_err(|e| format!("fork result schema: {e}"))?;
    for (field, value) in [
        ("source_sequence", expected.source_sequence),
        ("pack_count", expected.pack_count),
        ("pack_bytes", expected.pack_bytes),
        ("object_count", expected.object_count),
        ("membership_generation", expected.membership_generation),
    ] {
        ensure!(
            result.get(field).and_then(serde_json::Value::as_u64) == Some(value),
            "fork response {field} disagrees with saved result: {result:?}"
        );
    }
    ensure!(
        result.get("tip").and_then(serde_json::Value::as_str) == Some(expected.tip.as_str()),
        "fork response tip disagrees with saved result: {result:?}"
    );
    Ok(())
}

async fn probe_inert(ctx: &Ctx, fixture: &Fixture) -> CaseResult {
    let signer = ctx.v2_signer("main")?;
    for (pack, object) in fixture.source.packs.iter().zip(&fixture.source.objects) {
        let request = PackExistsRequest {
            pack_id: Some(from_hex(pack).map_err(|e| e.to_string())?.to_vec()),
            ..Default::default()
        };
        let probe = sign_unary(&signer, Rpc::PackExists, &request, |envelope| {
            envelope.repository.clone_from(&fixture.query.destination);
        });
        match ctx.send::<PackExistsResponse>(&probe).await? {
            Ok(result) => ensure!(
                result.exists != Some(true),
                "inert destination exposed pack {pack}"
            ),
            Err(error) => ensure!(
                error.code == "not_found",
                "destination membership probe returned {}",
                error.code
            ),
        }
        let download = DownloadPackRequest {
            pack_id: Some(from_hex(pack).map_err(|e| e.to_string())?.to_vec()),
            ..Default::default()
        };
        let body = frame(&download.encode_to_vec());
        let mut envelope = signer.envelope(Rpc::DownloadPack.procedure(), body_commitment(&body));
        envelope.repository.clone_from(&fixture.query.destination);
        envelope.digest = Some(to_hex(&hash(&body)));
        let download = ctx
            .client()
            .stream::<DownloadPackResponse>(
                Rpc::DownloadPack,
                body,
                &signer.sign(&envelope).headers,
            )
            .await?;
        ensure!(
            download.messages.is_empty()
                && download
                    .error
                    .as_ref()
                    .is_some_and(|e| e.code == "not_found"),
            "inert destination served an imported pack: {download:?}"
        );
        if ctx.profile().has(Feature::HttpObjects) {
            let read = ctx
                .client()
                .get(&format!(
                    "/{}/-/objects/{object}",
                    fixture.query.destination
                ))
                .await?;
            ensure!(
                read.status == 404,
                "inert destination served an imported object: HTTP {}",
                read.status
            );
        }
    }
    let tip = from_hex(&fixture.source.tip).map_err(|e| e.to_string())?;
    let packmap = from_hex(&fixture.source.packmap).map_err(|e| e.to_string())?;
    // The binding promises this pair passes content validation after activation;
    // a missing proof or packmap must not masquerade as a destination gate.
    let write = sign_unary(
        &signer,
        Rpc::AdvanceRefs,
        &advance_req(
            (&ctx.head("source"), Exp::Missing, &tip),
            (&ctx.packmap("source"), Exp::Missing, &packmap),
        ),
        |envelope| envelope.repository.clone_from(&fixture.query.destination),
    );
    let response = ctx.send::<AdvanceRefsResponse>(&write).await?;
    ensure!(
        matches!(response, Err(ref error) if matches!(error.code.as_str(), "not_found" | "permission_denied" | "failed_precondition" | "unavailable")),
        "inert destination accepted a write or returned a non-gate error: {response:?}"
    );
    Ok(())
}

pub(crate) async fn destination_gate_before_acceptance(
    ctx: Ctx,
    control: &ControlClient,
) -> CaseResult {
    let fixture = fixture(&ctx, control, 0).await?;
    pause(
        control,
        &fixture,
        "before_acceptance",
        "fork_acceptance",
        None,
    )
    .await?;
    let pending = start(&ctx, &fixture);
    control.wait_paused().await?;
    let snapshot = observe(control, &fixture).await?;
    inert(&snapshot)?;
    ensure!(
        snapshot.staged_memberships.iter().any(|staged| *staged),
        "fork fixture reached acceptance without staged membership; gate was not exercised"
    );
    probe_inert(&ctx, &fixture).await?;
    inert(&observe(control, &fixture).await?)?;
    control.command(&Request::Resume).await?;
    success(&finish(pending).await?, &fixture)?;
    accepted(&observe(control, &fixture).await?, &fixture)
}

pub(crate) async fn acceptance_result_replay_outcome_atomic(
    ctx: Ctx,
    control: &ControlClient,
) -> CaseResult {
    let fixture = fixture(&ctx, control, 0).await?;
    inert(&observe(control, &fixture).await?)?;
    pause(
        control,
        &fixture,
        "after_durable_acceptance_before_response",
        "fork_acceptance",
        None,
    )
    .await?;
    let pending = start(&ctx, &fixture);
    control.wait_paused().await?;
    let before = observe(control, &fixture).await?;
    accepted(&before, &fixture)?;
    control.command(&Request::Resume).await?;
    let original = finish(pending).await?;
    success(&original, &fixture)?;
    let saved = before
        .result
        .as_ref()
        .ok_or("accepted fork has no result")?;
    wire_result_matches(&original, saved)?;
    // Resolve a lost-response identity through its original signature. Only
    // acceptance-owned fields are compared: publication may advance meanwhile.
    let replay = invoke(&ctx, &fixture.op).await?;
    success(&replay, &fixture)?;
    wire_result_matches(&replay, saved)?;
    let after = observe(control, &fixture).await?;
    accepted(&after, &fixture)?;
    ensure!(
        before.result == after.result
            && before.replay == after.replay
            && before.outcome == after.outcome
            && before.progress_commits == after.progress_commits,
        "fork replay repeated acceptance or settlement: before={before:?}, after={after:?}"
    );
    Ok(())
}

async fn reject_after_bump(
    ctx: &Ctx,
    control: &ControlClient,
    fixture: &Fixture,
    decision_class: &str,
    occurrence: Option<u64>,
) -> Result<ForkObservation, Failure> {
    pause(
        control,
        fixture,
        "before_acceptance",
        decision_class,
        occurrence,
    )
    .await?;
    let pending = start(ctx, fixture);
    control.wait_paused().await?;
    let before = observe(control, fixture).await?;
    inert(&before)?;
    if let Some(ordinal) = occurrence {
        ensure!(
            before.progress_commits == ordinal - 1,
            "fork progress barrier paused at the wrong protocol commit: {before:?}"
        );
    }
    let namespace = fixture
        .query
        .destination
        .split_once('/')
        .map(|(namespace, _)| namespace)
        .ok_or("fork destination needs a full repository identity")?;
    control
        .command(&Request::BumpAuthority {
            namespace: namespace.into(),
        })
        .await?;
    control.command(&Request::Resume).await?;
    let reply = finish(pending).await?;
    ensure!(
        reply.status != 200 && refusal(&reply)? == "permission_denied",
        "fork authority final guard returned the wrong refusal: {reply:?}"
    );
    let after = observe(control, fixture).await?;
    inert(&after)?;
    ensure!(
        after.failed && after.progress_commits == before.progress_commits,
        "fork committed guarded progress after authority changed: before={before:?}, after={after:?}"
    );
    Ok(after)
}

pub(crate) async fn failed_destination_inert(ctx: Ctx, control: &ControlClient) -> CaseResult {
    let fixture = fixture(&ctx, control, 0).await?;
    reject_after_bump(&ctx, control, &fixture, "fork_acceptance", None).await?;
    probe_inert(&ctx, &fixture).await?;
    let after = observe(control, &fixture).await?;
    inert(&after)?;
    ensure!(after.failed, "write probe reactivated a failed destination");
    Ok(())
}

pub(crate) async fn authority_at_acceptance(ctx: Ctx, control: &ControlClient) -> CaseResult {
    let fixture = fixture(&ctx, control, 0).await?;
    reject_after_bump(&ctx, control, &fixture, "fork_acceptance", None).await?;
    Ok(())
}

pub(crate) async fn authority_each_progress_commit(
    ctx: Ctx,
    control: &ControlClient,
) -> CaseResult {
    let first = fixture(&ctx, control, 1).await?;
    let count = first.source.advancing_commits;
    ensure!(
        count > 0,
        "progress-fence fixture has no preparatory commits"
    );
    for ordinal in 1..=count {
        let next;
        let fixture = if ordinal == 1 {
            &first
        } else {
            next = fixture(&ctx, control, ordinal).await?;
            ensure!(
                next.source.advancing_commits == count
                    && next.source.tip == first.source.tip
                    && next.source.packmap == first.source.packmap
                    && next.source.packs == first.source.packs,
                "fork fixture is not deterministic across fresh destinations"
            );
            &next
        };
        reject_after_bump(&ctx, control, fixture, "fork_progress", Some(ordinal)).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use axum::{Json, Router, routing::post};

    use super::*;
    use crate::control::{CONTROL_PATH, Response};
    use crate::wire::client::Client;
    use crate::wire::{Profile, WireAuth};

    /// A dishonest binding must fail the real executable case, rather than
    /// passing because the reference target declares that case unsupported.
    #[tokio::test]
    async fn gate_case_rejects_preaccepted_visible_or_writable_destination() {
        for visible in [false, true] {
            let started = Arc::new(AtomicBool::new(false));
            let control_started = started.clone();
            let app = Router::new()
                .route(
                    CONTROL_PATH,
                    post(move |Json(request): Json<Request>| {
                        let started = control_started.clone();
                        async move {
                            let mut response = Response::default();
                            match request {
                                Request::PrepareFork { query } => {
                                    response.fork_fixture = Some(ForkFixture {
                                        source_repository: format!("{}-source", query.destination),
                                        source_head: query.source_head,
                                        tip: to_hex(&[1; 32]),
                                        packmap: to_hex(&[2; 32]),
                                        packs: vec![to_hex(&[3; 32])],
                                        objects: vec![to_hex(&[4; 32])],
                                        advancing_commits: 1,
                                    });
                                }
                                Request::Pause { .. } => {}
                                Request::BarrierStatus => {
                                    response.paused = started.load(Ordering::SeqCst);
                                }
                                Request::ObserveFork { .. } => {
                                    response.fork_observation = Some(ForkObservation {
                                        accepted: false,
                                        failed: false,
                                        writable: !visible,
                                        head: None,
                                        packmap: None,
                                        staged_memberships: vec![true],
                                        visible_memberships: vec![visible],
                                        progress_commits: 1,
                                        result: None,
                                        replay: None,
                                        outcome: None,
                                    });
                                }
                                other => panic!("unexpected test-control request: {other:?}"),
                            }
                            Json(response)
                        }
                    }),
                )
                .route(
                    FORK_PATH,
                    post(move || {
                        let started = started.clone();
                        async move {
                            started.store(true, Ordering::SeqCst);
                            (
                                http::StatusCode::CONFLICT,
                                Json(serde_json::json!({"code":"aborted"})),
                            )
                        }
                    }),
                );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind portable fake host");
            let base = url::Url::parse(&format!(
                "http://{}",
                listener.local_addr().expect("fake host address")
            ))
            .expect("fake host URL");
            let host = tokio::spawn(async move { axum::serve(listener, app).await });
            let profile = Profile::new(WireAuth::AuthV2 {
                audience: base.as_str().trim_end_matches('/').into(),
                repository: "default".into(),
                seed: [5; 32],
            });
            let ctx = Ctx::new(
                Client::new(&base).expect("fake wire client"),
                Arc::new(profile),
                "fork.destination_gate_before_acceptance",
            );
            let control = ControlClient::new(&base).expect("fake control client");
            let result = tokio::time::timeout(
                Duration::from_secs(10),
                destination_gate_before_acceptance(ctx, &control),
            )
            .await
            .expect("fake binding case must finish");
            host.abort();
            assert!(
                matches!(result, Err(Failure::Fail(ref message)) if message.contains("unaccepted fork destination became active")),
                "malformed fork snapshot escaped the gate case: {result:?}"
            );
        }
    }
}
