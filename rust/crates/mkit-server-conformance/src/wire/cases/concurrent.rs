//! Concurrent compare-and-swap (SPEC-REFS §7, test vectors 4 and 5; SPEC-
//! TRANSPORT-CONNECT §3, §4): of N racing writes with the same precondition
//! exactly one wins, every other one gets the conflict, and the ref ends at
//! the winner's value. A server that checks and writes non-atomically
//! (read-then-write) lets several win.
//!
//! Each racer is a distinct operation (its own id and, under auth v2, its
//! own signer), never a replay of another. Each case races [`ROUNDS`]
//! times, on a fresh ref each round, so a narrow race window has several
//! chances to show.

use futures::future::join_all;
use mkit_core::hash::hash;
use mkit_transport_connect::generated::{AdvanceOutcome, AdvanceRefsResponse, UpdateRefResponse};

use super::{A, CaseResult, Ctx, Exp, Failure, advance_req, ensure, update_req, want_outcome};
use crate::wire::client::{Rpc, RpcError};

/// Racers per round.
const RACERS: usize = 24;
/// Rounds per case, each with the same assertions.
const ROUNDS: usize = 3;

/// Racer `i`'s new id in round `round`.
fn racer_id(round: usize, i: usize) -> [u8; 32] {
    hash(format!("{round}/{i}").as_bytes())
}

/// Racer `i`'s signer label in round `round`.
fn racer_label(round: usize, i: usize) -> String {
    format!("racer{round}-{i}")
}

/// The one winner among `results` (`Ok` = won); every loser must carry
/// `conflict`.
fn one_winner<T>(
    round: usize,
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
                    "round {round}, racer {i}: expected ok or {conflict}, got {e}"
                )));
            }
        }
    }
    ensure!(
        winners.len() == 1,
        "round {round}: {} racers won (racers {winners:?}), want exactly 1",
        winners.len()
    );
    Ok(winners[0])
}

/// Race `RACERS` updates of `<ns>/main-r<round>` under `exp`.
async fn race_update(ctx: &Ctx, round: usize, exp: Exp<'_>) -> CaseResult {
    let name = ctx.head(&format!("main-r{round}"));
    let racers = (0..RACERS).map(|i| {
        let req = update_req(&name, exp, &racer_id(round, i));
        let label = racer_label(round, i);
        async move {
            ctx.call_as::<UpdateRefResponse>(&label, Rpc::UpdateRef, &req)
                .await
        }
    });
    let winner = one_winner(round, join_all(racers).await, "failed_precondition")?;
    ctx.expect_ref(&name, Some(&racer_id(round, winner))).await
}

pub(super) async fn missing_one_winner(ctx: Ctx) -> CaseResult {
    for round in 0..ROUNDS {
        race_update(&ctx, round, Exp::Missing).await?;
    }
    Ok(())
}

pub(super) async fn match_one_winner(ctx: Ctx) -> CaseResult {
    for round in 0..ROUNDS {
        ctx.set(&ctx.head(&format!("main-r{round}")), Exp::Missing, &A)
            .await?;
        race_update(&ctx, round, Exp::Match(&A)).await?;
    }
    Ok(())
}

/// All racers advance from A; exactly one is `COMMITTED`, the rest are
/// typed conflicts (never errors), and head and packmap both end at the
/// winner's id.
pub(super) async fn advance_one_committed(ctx: Ctx) -> CaseResult {
    for round in 0..ROUNDS {
        advance_round(&ctx, round).await?;
    }
    Ok(())
}

async fn advance_round(ctx: &Ctx, round: usize) -> CaseResult {
    let leaf = format!("main-r{round}");
    let (head, packmap) = (ctx.head(&leaf), ctx.packmap(&leaf));
    let seed = advance_req((&head, Exp::Missing, &A), (&packmap, Exp::Missing, &A));
    want_outcome(
        ctx.advance(&seed).await?,
        AdvanceOutcome::ADVANCE_OUTCOME_COMMITTED,
    )?;
    let racers = (0..RACERS).map(|i| {
        let id = racer_id(round, i);
        let req = advance_req(
            (&head, Exp::Match(&A), &id),
            (&packmap, Exp::Match(&A), &id),
        );
        let label = racer_label(round, i);
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
                    "round {round}, racer {i}: outcome {}",
                    super::outcome_name(o)
                )));
            }
            Err(e) => {
                return Err(Failure::Fail(format!(
                    "round {round}, racer {i}: a conflict must be an outcome, got {e}"
                )));
            }
        }
    }
    ensure!(
        winners.len() == 1,
        "round {round}: {} racers committed (racers {winners:?}), want exactly 1",
        winners.len()
    );
    let id = racer_id(round, winners[0]);
    ctx.expect_ref(&head, Some(&id)).await?;
    ctx.expect_ref(&packmap, Some(&id)).await
}
