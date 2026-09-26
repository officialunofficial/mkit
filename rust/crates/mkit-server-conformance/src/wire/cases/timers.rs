//! Timer directives and the adapter's autonomous driver.
use super::{A, CaseResult, Commit, Ctx, Exp, Failure, ensure, update_req, want_ok};
use crate::wire::client::Rpc;
use buffa::Message;
use mkit_transport_connect::generated::{ListRefsRequest, ListRefsResponse, UpdateRefResponse};
use std::time::{Duration, Instant};
const TIMER: &str = "x-mkit-test-timer-ms";
const RUN: &str = "x-mkit-test-run-timers";
const SKEW: &str = "x-mkit-test-clock-skew-ms";

async fn create(ctx: &Ctx, name: &str, delay: &str) -> CaseResult {
    let body = update_req(name, Exp::Missing, &A).encode_to_vec();
    let mut headers = ctx.auth_headers(Rpc::UpdateRef, Commit::Body(&body));
    headers.push((TIMER.into(), delay.into()));
    let _: UpdateRefResponse = want_ok(
        ctx.client().unary(Rpc::UpdateRef, body, &headers).await?,
        "timed UpdateRef",
    )?;
    Ok(())
}
async fn list_tick(ctx: &Ctx, name: &str, skew: Option<&str>) -> Result<bool, Failure> {
    let (prefix, leaf) = name.rsplit_once('/').ok_or("timer ref has no parent")?;
    let body = ListRefsRequest {
        prefix: Some(prefix.into()),
        ..Default::default()
    }
    .encode_to_vec();
    let mut headers = ctx.auth_headers(Rpc::ListRefs, Commit::Body(&body));
    headers.push((RUN.into(), name.into()));
    if let Some(skew) = skew {
        headers.push((SKEW.into(), skew.into()));
    }
    let reply: ListRefsResponse = want_ok(
        ctx.client().unary(Rpc::ListRefs, body, &headers).await?,
        "timer ListRefs",
    )?;
    Ok(reply.refs.iter().any(|entry| {
        entry.name.as_deref() == Some(leaf) && entry.object_id.as_deref() == Some(&A[..])
    }))
}
async fn exercise_directive(ctx: &Ctx, redeliver: bool) -> CaseResult {
    let name = ctx.head("X");
    create(ctx, &name, "600000").await?;
    ensure!(list_tick(ctx, &name, None).await?, "future timer deleted X");
    ensure!(
        !list_tick(ctx, &name, Some("1200000")).await?,
        "due timer did not delete X"
    );
    ctx.expect_ref(&name, None).await?;
    if redeliver {
        for _ in 0..2 {
            ensure!(
                !list_tick(ctx, &name, Some("1200000")).await?,
                "redelivery changed listing"
            );
            ctx.expect_ref(&name, None).await?;
        }
    }
    Ok(())
}
pub(super) async fn directive_fires_due(ctx: Ctx) -> CaseResult {
    exercise_directive(&ctx, false).await
}
pub(super) async fn redelivery_is_idempotent(ctx: Ctx) -> CaseResult {
    exercise_directive(&ctx, true).await
}
pub(super) async fn fire_on_schedule(ctx: Ctx) -> CaseResult {
    let name = ctx.head("Y");
    create(&ctx, &name, "1000").await?;
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if ctx.read(&name).await?.is_none() {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "timer did not fire within 20 seconds"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
