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
    ForkFixture, ForkFixtureQuery, ForkObservation, ForkQuery, ForkResultView, ForkSourceChange,
    ReplayIdentity, Request,
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
        source.source_repository != destination && source.source_head == ctx.head("source"),
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
        if reply.status == 200 {
            return Ok(reply);
        }
        let error: serde_json::Value = serde_json::from_slice(&reply.body)
            .map_err(|e| format!("fork refusal is not JSON: {e}"))?;
        // Only the specified pending answer permits another request. Retrying
        // other refusals could hide an incorrect code behind a later answer.
        if reply.status != 503
            || error.get("code").and_then(serde_json::Value::as_str) != Some("unavailable")
            || error.get("message").and_then(serde_json::Value::as_str) != Some("fork in progress")
        {
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

fn source_not_found(reply: &Reply) -> CaseResult {
    let value: serde_json::Value = serde_json::from_slice(&reply.body)
        .map_err(|e| format!("fork source refusal is not JSON: {e}"))?;
    ensure!(
        reply.status == 404
            && value.get("code").and_then(serde_json::Value::as_str) == Some("not_found")
            && value.get("message").and_then(serde_json::Value::as_str) == Some("source not found"),
        "fork source final proof must refuse uniformly with not_found/source not found: {reply:?}"
    );
    Ok(())
}

fn acceptance_unchanged(before: &ForkObservation, after: &ForkObservation) -> CaseResult {
    ensure!(
        before.result == after.result
            && before.replay == after.replay
            && before.outcome == after.outcome
            && before.progress_commits == after.progress_commits,
        "source change invalidated or repeated durable fork acceptance: before={before:?}, after={after:?}"
    );
    Ok(())
}

async fn source_change_before_fixture(
    ctx: &Ctx,
    control: &ControlClient,
    fixture: &Fixture,
    change: ForkSourceChange,
    mutation_query: ForkQuery,
) -> CaseResult {
    pause(
        control,
        fixture,
        "before_acceptance",
        "fork_source_proof",
        None,
    )
    .await?;
    let pending = start(ctx, fixture);
    control.wait_paused().await?;
    let before = observe(control, fixture).await?;
    inert(&before)?;
    ensure!(
        before.staged_memberships.iter().all(|staged| *staged),
        "final source-proof barrier must follow every staged membership: {before:?}"
    );
    control
        .command(&Request::ChangeForkSource {
            query: mutation_query,
            change,
        })
        .await?;
    inert(&observe(control, fixture).await?)?;
    control.command(&Request::Resume).await?;
    source_not_found(&finish(pending).await?)?;
    let after = observe(control, fixture).await?;
    inert(&after)?;
    ensure!(
        after.failed && after.progress_commits == before.progress_commits,
        "failed final source proof committed fork progress: before={before:?}, after={after:?}"
    );
    probe_inert(ctx, fixture).await?;
    inert(&observe(control, fixture).await?)?;
    Ok(())
}

async fn source_change_after_fixture(
    ctx: &Ctx,
    control: &ControlClient,
    fixture: &Fixture,
    change: ForkSourceChange,
    mutation_query: ForkQuery,
) -> CaseResult {
    pause(
        control,
        fixture,
        "after_durable_acceptance_before_response",
        "fork_acceptance",
        None,
    )
    .await?;
    let pending = start(ctx, fixture);
    control.wait_paused().await?;
    let before = observe(control, fixture).await?;
    accepted(&before, fixture)?;
    control
        .command(&Request::ChangeForkSource {
            query: mutation_query,
            change,
        })
        .await?;
    // Assert recovery evidence before letting the original answer or replay run:
    // a replay must not repair an acceptance invalidated by a later source change.
    let changed = observe(control, fixture).await?;
    accepted(&changed, fixture)?;
    acceptance_unchanged(&before, &changed)?;
    control.command(&Request::Resume).await?;
    let original = finish(pending).await?;
    success(&original, fixture)?;
    let saved = before
        .result
        .as_ref()
        .ok_or("accepted fork has no result")?;
    wire_result_matches(&original, saved)?;
    let replay = invoke(ctx, &fixture.op).await?;
    success(&replay, fixture)?;
    wire_result_matches(&replay, saved)?;
    let after = observe(control, fixture).await?;
    accepted(&after, fixture)?;
    acceptance_unchanged(&before, &after)
}

async fn source_change_cases(
    ctx: Ctx,
    control: &ControlClient,
    change: ForkSourceChange,
    after_acceptance: bool,
) -> CaseResult {
    let mut expected_packs = None;
    let mut ordinal = 0_usize;
    loop {
        let fixture = fixture(
            &ctx,
            control,
            u64::try_from(ordinal).map_err(|e| e.to_string())?,
        )
        .await?;
        let mut mutation_query = fixture.query.clone();
        if change == ForkSourceChange::Denied {
            let packs = expected_packs.get_or_insert_with(|| fixture.source.packs.clone());
            ensure!(
                *packs == fixture.source.packs,
                "denial fixtures must preserve the deterministic imported pack set"
            );
            // Select each pack explicitly. A proof that checks only one special
            // pack must not pass while another imported member is denied.
            mutation_query.packs = vec![packs[ordinal].clone()];
        }
        if after_acceptance {
            source_change_after_fixture(&ctx, control, &fixture, change, mutation_query).await?;
        } else {
            source_change_before_fixture(&ctx, control, &fixture, change, mutation_query).await?;
        }
        ordinal += 1;
        if expected_packs
            .as_ref()
            .is_none_or(|packs| ordinal == packs.len())
        {
            return Ok(());
        }
    }
}

async fn source_change_before_acceptance(
    ctx: Ctx,
    control: &ControlClient,
    change: ForkSourceChange,
) -> CaseResult {
    source_change_cases(ctx, control, change, false).await
}

async fn source_change_after_acceptance(
    ctx: Ctx,
    control: &ControlClient,
    change: ForkSourceChange,
) -> CaseResult {
    source_change_cases(ctx, control, change, true).await
}

macro_rules! source_cases {
    ($(($before:ident, $after:ident, $change:ident)),* $(,)?) => {
        $(
            pub(crate) async fn $before(ctx: Ctx, control: &ControlClient) -> CaseResult {
                source_change_before_acceptance(ctx, control, ForkSourceChange::$change).await
            }

            pub(crate) async fn $after(ctx: Ctx, control: &ControlClient) -> CaseResult {
                source_change_after_acceptance(ctx, control, ForkSourceChange::$change).await
            }
        )*
    };
}

source_cases! {
    (source_moved_before_acceptance, source_moved_after_acceptance, Moved),
    (source_unpublished_before_acceptance, source_unpublished_after_acceptance, Unpublished),
    (source_visibility_revoked_before_acceptance, source_visibility_revoked_after_acceptance, VisibilityRevoked),
    (source_denied_before_acceptance, source_denied_after_acceptance, Denied),
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

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
                                http::StatusCode::SERVICE_UNAVAILABLE,
                                Json(serde_json::json!({"code":"unavailable", "message":"fork in progress"})),
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

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum SourceDefect {
        None,
        StaleProof,
        LastPackOnlyProof,
        RetryableRefusalThenNotFound,
        WrongRefusalCode,
        WrongRefusalMessage,
        PartialStaging,
        EmptyStaging,
        InvalidatedAcceptance,
    }

    struct SourceState {
        fixture: Option<ForkFixture>,
        after_acceptance: bool,
        started: bool,
        resumed: bool,
        changed: Option<ForkSourceChange>,
        changes: Vec<(ForkSourceChange, Vec<String>)>,
        terminal_attempts: usize,
        defect: SourceDefect,
    }

    impl SourceState {
        fn accepted(&self) -> bool {
            let misses_denial = self.defect == SourceDefect::LastPackOnlyProof
                && self.changes.last().is_some_and(|(change, packs)| {
                    *change == ForkSourceChange::Denied
                        && packs.iter().any(|pack| {
                            Some(pack)
                                != self
                                    .fixture
                                    .as_ref()
                                    .and_then(|fixture| fixture.packs.last())
                        })
                });
            self.started
                && ((self.after_acceptance
                    && !(self.changed.is_some()
                        && self.defect == SourceDefect::InvalidatedAcceptance))
                    || (self.resumed && (self.defect == SourceDefect::StaleProof || misses_denial)))
        }

        fn snapshot(&self) -> ForkObservation {
            let fixture = self.fixture.as_ref().expect("prepared source");
            let accepted = self.accepted();
            let failed = self.resumed && !accepted;
            ForkObservation {
                accepted,
                failed,
                writable: accepted,
                head: None,
                packmap: None,
                staged_memberships: if self.defect == SourceDefect::EmptyStaging {
                    vec![]
                } else {
                    vec![true, self.defect != SourceDefect::PartialStaging]
                },
                visible_memberships: vec![accepted; 2],
                progress_commits: 1,
                result: accepted.then(|| ForkResultView {
                    source_repository: fixture.source_repository.clone(),
                    source_head: fixture.source_head.clone(),
                    tip: fixture.tip.clone(),
                    source_sequence: 7,
                    packmap: fixture.packmap.clone(),
                    pack_count: 2,
                    pack_bytes: 123,
                    object_count: 4,
                    pack_set_digest: to_hex(&[6; 32]),
                    membership_generation: 0,
                }),
                replay: Some(crate::control::ReplayView {
                    state: if accepted || failed {
                        "committed"
                    } else {
                        "in_flight"
                    }
                    .into(),
                    result: if accepted {
                        Some("fork_committed".into())
                    } else {
                        None
                    },
                    fingerprint: Some("fixed request commitment".into()),
                }),
                outcome: Some(crate::control::ReservationView {
                    state: if accepted {
                        "committed"
                    } else if failed {
                        "aborted"
                    } else {
                        "pending"
                    }
                    .into(),
                    terminal_count: u32::from(accepted || failed),
                }),
            }
        }

        fn command(&mut self, request: Request) -> Response {
            let mut response = Response::default();
            match request {
                Request::PrepareFork { query } => {
                    let fixture = ForkFixture {
                        source_repository: format!("ed25519-{}/source", to_hex(&[8; 32])),
                        source_head: query.source_head,
                        tip: to_hex(&[1; 32]),
                        packmap: to_hex(&[2; 32]),
                        packs: vec![to_hex(&[3; 32]), to_hex(&[4; 32])],
                        objects: vec![to_hex(&[5; 32]), to_hex(&[6; 32])],
                        advancing_commits: 1,
                    };
                    self.fixture = Some(fixture.clone());
                    self.after_acceptance = false;
                    self.started = false;
                    self.resumed = false;
                    self.changed = None;
                    self.terminal_attempts = 0;
                    response.fork_fixture = Some(fixture);
                }
                Request::Pause {
                    step,
                    decision_class,
                    ..
                } => {
                    self.after_acceptance = step == "after_durable_acceptance_before_response";
                    assert_eq!(
                        decision_class.as_deref(),
                        Some(if self.after_acceptance {
                            "fork_acceptance"
                        } else {
                            "fork_source_proof"
                        })
                    );
                }
                Request::BarrierStatus => response.paused = self.started && !self.resumed,
                Request::ObserveFork { .. } => response.fork_observation = Some(self.snapshot()),
                Request::ChangeForkSource { change, query } => {
                    self.changed = Some(change);
                    self.changes.push((change, query.packs));
                }
                Request::Resume => self.resumed = true,
                other => panic!("unexpected source test command: {other:?}"),
            }
            response
        }

        fn fork(&mut self) -> (http::StatusCode, Json<serde_json::Value>) {
            self.started = true;
            if !self.resumed {
                return (
                    http::StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({"code":"unavailable", "message":"fork in progress"})),
                );
            }
            self.terminal_attempts += 1;
            if self.defect == SourceDefect::RetryableRefusalThenNotFound
                && self.terminal_attempts == 1
            {
                return (
                    http::StatusCode::SERVICE_UNAVAILABLE,
                    Json(
                        serde_json::json!({"code":"unavailable", "message":"source changed; retry"}),
                    ),
                );
            }
            if let Some(result) = self.snapshot().result {
                return (
                    http::StatusCode::OK,
                    Json(serde_json::json!({
                        "tip":result.tip, "pack_count":result.pack_count, "pack_bytes":result.pack_bytes,
                        "object_count":result.object_count, "source_sequence":result.source_sequence,
                        "membership_generation":result.membership_generation,
                    })),
                );
            }
            let code = if self.defect == SourceDefect::WrongRefusalCode {
                "failed_precondition"
            } else {
                "not_found"
            };
            let message = if self.defect == SourceDefect::WrongRefusalMessage {
                "source tip changed"
            } else {
                "source not found"
            };
            (
                http::StatusCode::NOT_FOUND,
                Json(serde_json::json!({"code":code,"message":message})),
            )
        }
    }

    struct SourceHost {
        ctx: Ctx,
        control: ControlClient,
        state: Arc<Mutex<SourceState>>,
        task: tokio::task::JoinHandle<std::io::Result<()>>,
    }

    impl Drop for SourceHost {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl SourceHost {
        async fn start(defect: SourceDefect) -> Self {
            let state = Arc::new(Mutex::new(SourceState {
                fixture: None,
                after_acceptance: false,
                started: false,
                resumed: false,
                changed: None,
                changes: vec![],
                terminal_attempts: 0,
                defect,
            }));
            let app = Router::new()
                .route(CONTROL_PATH, post({
                    let state = state.clone();
                    move |Json(request): Json<Request>| {
                        let state = state.clone();
                        async move { Json(state.lock().unwrap().command(request)) }
                    }
                }))
                .route(FORK_PATH, post({
                    let state = state.clone();
                    move || {
                        let state = state.clone();
                        async move { state.lock().unwrap().fork() }
                    }
                }))
                .route(Rpc::PackExists.procedure(), post(|| async {
                    ([ ("content-type", "application/proto") ],
                    PackExistsResponse { exists: Some(false), ..Default::default() }.encode_to_vec())
                }))
                .route(Rpc::DownloadPack.procedure(), post(|| async {
                    (http::StatusCode::NOT_FOUND, Json(serde_json::json!({"code":"not_found","message":"pack not found"})))
                }))
                .route(Rpc::AdvanceRefs.procedure(), post(|| async {
                    (http::StatusCode::PRECONDITION_FAILED, Json(serde_json::json!({"code":"failed_precondition","message":"destination inactive"})))
                }));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base =
                url::Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
            let task = tokio::spawn(async move { axum::serve(listener, app).await });
            let profile = Profile::new(WireAuth::AuthV2 {
                audience: base.as_str().trim_end_matches('/').into(),
                repository: "default".into(),
                seed: [5; 32],
            });
            Self {
                ctx: Ctx::new(
                    Client::new(&base).unwrap(),
                    Arc::new(profile),
                    "fork.source_eligibility",
                ),
                control: ControlClient::new(&base).unwrap(),
                state,
                task,
            }
        }
    }

    #[tokio::test]
    async fn source_cases_run_all_changes_before_and_after_acceptance() {
        for change in [
            ForkSourceChange::Moved,
            ForkSourceChange::Unpublished,
            ForkSourceChange::VisibilityRevoked,
            ForkSourceChange::Denied,
        ] {
            for after in [false, true] {
                let host = SourceHost::start(SourceDefect::None).await;
                let result = if after {
                    source_change_after_acceptance(host.ctx.clone(), &host.control, change).await
                } else {
                    source_change_before_acceptance(host.ctx.clone(), &host.control, change).await
                };
                assert!(result.is_ok(), "valid source case failed: {result:?}");
                let state = host.state.lock().unwrap();
                assert_eq!(state.changed, Some(change));
                if change == ForkSourceChange::Denied {
                    assert_eq!(
                        state.changes,
                        vec![
                            (change, vec![to_hex(&[3; 32])]),
                            (change, vec![to_hex(&[4; 32])]),
                        ],
                        "denial cases must select every imported pack in a fresh fixture"
                    );
                } else {
                    assert_eq!(state.changes.len(), 1);
                }
            }
        }
    }

    #[tokio::test]
    async fn source_cases_detect_stale_proof_refusal_leaks_and_partial_staging() {
        for (defect, expected) in [
            (SourceDefect::StaleProof, "fork source final proof"),
            (SourceDefect::WrongRefusalCode, "fork source final proof"),
            (SourceDefect::WrongRefusalMessage, "fork source final proof"),
            (SourceDefect::PartialStaging, "every staged membership"),
            (SourceDefect::EmptyStaging, "membership query order/length"),
        ] {
            let host = SourceHost::start(defect).await;
            let result = source_change_before_acceptance(
                host.ctx.clone(),
                &host.control,
                ForkSourceChange::Moved,
            )
            .await;
            assert!(
                matches!(result, Err(Failure::Fail(ref message)) if message.contains(expected)),
                "bad final proof escaped the executable case: {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn source_case_rejects_retryable_refusal_before_uniform_terminal_reply() {
        let host = SourceHost::start(SourceDefect::RetryableRefusalThenNotFound).await;
        let result = source_change_before_acceptance(
            host.ctx.clone(),
            &host.control,
            ForkSourceChange::Moved,
        )
        .await;
        let attempts = host.state.lock().unwrap().terminal_attempts;
        assert!(
            matches!(result, Err(Failure::Fail(_))),
            "retryable source refusal was hidden by a later terminal answer: result={result:?}, terminal_attempts={attempts}"
        );
        assert_eq!(
            attempts, 1,
            "source refusal must fail before another terminal request"
        );
    }

    #[tokio::test]
    async fn denial_case_rejects_a_proof_that_checks_only_the_last_pack() {
        let host = SourceHost::start(SourceDefect::LastPackOnlyProof).await;
        let result = source_change_before_acceptance(
            host.ctx.clone(),
            &host.control,
            ForkSourceChange::Denied,
        )
        .await;
        assert!(
            matches!(result, Err(Failure::Fail(ref message)) if message.contains("fork source final proof")),
            "last-pack-only proof escaped the all-imported-packs oracle: {result:?}"
        );
    }

    #[tokio::test]
    async fn source_change_must_preserve_acceptance_before_replay_can_repair_it() {
        let host = SourceHost::start(SourceDefect::InvalidatedAcceptance).await;
        let result = source_change_after_acceptance(
            host.ctx.clone(),
            &host.control,
            ForkSourceChange::VisibilityRevoked,
        )
        .await;
        assert!(
            matches!(result, Err(Failure::Fail(ref message)) if message.contains("fork acceptance lacks atomic")),
            "source change invalidated acceptance without failing the case: {result:?}"
        );
        assert!(
            !host.state.lock().unwrap().resumed,
            "case checked acceptance only after replay"
        );
    }
}
