//! Concurrent compare-and-swap (SPEC-REFS §7, test vectors 4 and 5; SPEC-
//! TRANSPORT-CONNECT §3, §4): of N racing writes with the same precondition
//! exactly one wins, every other one gets the conflict, and the ref ends at
//! the winner's value. A server that checks and writes non-atomically
//! (read-then-write) lets several win.
//!
//! Each racer is a distinct operation (its own id and, under auth v2, its
//! own signer), never a replay of another.

use futures::future::join_all;
use mkit_core::hash::hash;
use mkit_transport_connect::generated::{AdvanceOutcome, AdvanceRefsResponse, UpdateRefResponse};

use super::{A, CaseResult, Ctx, Exp, Failure, advance_req, ensure, update_req, want_outcome};
use crate::wire::client::{Rpc, RpcError};

/// Racers per case.
const RACERS: usize = 24;

/// Racer `i`'s new id.
fn racer_id(i: usize) -> [u8; 32] {
    hash(&(i as u64).to_be_bytes())
}

/// The one winner among `results` (`Ok` = won); every loser must carry
/// `conflict`.
fn one_winner<T>(
    results: Vec<Result<Result<T, RpcError>, String>>,
    conflict: &str,
) -> Result<usize, Failure> {
    let mut winners = Vec::new();
    for (i, result) in results.into_iter().enumerate() {
        match result? {
            Ok(_) => winners.push(i),
            Err(e) if e.code == conflict => {}
            Err(e) => {
                return Err(Failure::Fail(format!(
                    "racer {i}: expected ok or {conflict}, got {e}"
                )));
            }
        }
    }
    ensure!(
        winners.len() == 1,
        "{} racers won (racers {winners:?}), want exactly 1",
        winners.len()
    );
    Ok(winners[0])
}

async fn race_update(ctx: &Ctx, exp: Exp<'_>) -> Result<usize, Failure> {
    let name = ctx.head("main");
    let racers = (0..RACERS).map(|i| {
        let req = update_req(&name, exp, &racer_id(i));
        let label = format!("racer{i}");
        async move {
            ctx.call_as::<UpdateRefResponse>(&label, Rpc::UpdateRef, &req)
                .await
        }
    });
    let winner = one_winner(join_all(racers).await, "failed_precondition")?;
    ctx.expect_ref(&name, Some(&racer_id(winner))).await?;
    Ok(winner)
}

pub(super) async fn missing_one_winner(ctx: Ctx) -> CaseResult {
    race_update(&ctx, Exp::Missing).await.map(|_| ())
}

pub(super) async fn match_one_winner(ctx: Ctx) -> CaseResult {
    ctx.set(&ctx.head("main"), Exp::Missing, &A).await?;
    race_update(&ctx, Exp::Match(&A)).await.map(|_| ())
}

/// All racers advance from A; exactly one is `COMMITTED`, the rest are
/// typed conflicts (never errors), and head and packmap both end at the
/// winner's id.
pub(super) async fn advance_one_committed(ctx: Ctx) -> CaseResult {
    let (head, packmap) = (ctx.head("main"), ctx.packmap("main"));
    let seed = advance_req((&head, Exp::Missing, &A), (&packmap, Exp::Missing, &A));
    want_outcome(
        ctx.advance(&seed).await?,
        AdvanceOutcome::ADVANCE_OUTCOME_COMMITTED,
    )?;
    let racer_ctx = &ctx;
    let racers = (0..RACERS).map(|i| {
        let ctx = racer_ctx;
        let id = racer_id(i);
        let req = advance_req(
            (&head, Exp::Match(&A), &id),
            (&packmap, Exp::Match(&A), &id),
        );
        let label = format!("racer{i}");
        async move {
            let got: Result<AdvanceRefsResponse, RpcError> =
                ctx.call_as(&label, Rpc::AdvanceRefs, &req).await?;
            Ok::<_, String>(got.map(|r| r.outcome.map_or(0, |o| o.to_i32())))
        }
    });
    let committed = AdvanceOutcome::ADVANCE_OUTCOME_COMMITTED as i32;
    let conflicts = [
        AdvanceOutcome::ADVANCE_OUTCOME_HEAD_CONFLICT as i32,
        AdvanceOutcome::ADVANCE_OUTCOME_PACKMAP_CONFLICT as i32,
    ];
    let mut winners = Vec::new();
    for (i, result) in join_all(racers).await.into_iter().enumerate() {
        match result? {
            Ok(o) if o == committed => winners.push(i),
            Ok(o) if conflicts.contains(&o) => {}
            Ok(o) => {
                return Err(Failure::Fail(format!(
                    "racer {i}: outcome {}",
                    super::outcome_name(o)
                )));
            }
            Err(e) => {
                return Err(Failure::Fail(format!(
                    "racer {i}: a conflict must be an outcome, got {e}"
                )));
            }
        }
    }
    ensure!(
        winners.len() == 1,
        "{} racers committed (racers {winners:?}), want exactly 1",
        winners.len()
    );
    let id = racer_id(winners[0]);
    ctx.expect_ref(&head, Some(&id)).await?;
    ctx.expect_ref(&packmap, Some(&id)).await
}
