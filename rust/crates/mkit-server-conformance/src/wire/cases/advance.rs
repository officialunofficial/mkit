//! `AdvanceRefs` (SPEC-TRANSPORT-CONNECT §4): conflicts are typed outcomes,
//! never errors; a non-atomic server writes the packmap before the head.

use mkit_transport_connect::generated::AdvanceOutcome;

use super::{A, B, C, CaseResult, Ctx, Exp, advance_req, want_code, want_outcome};

/// Advance `main` and its packmap to A (both created).
async fn seed(ctx: &Ctx) -> CaseResult {
    let req = advance_req(
        (&ctx.head("main"), Exp::Missing, &A),
        (&ctx.packmap("main"), Exp::Missing, &A),
    );
    want_outcome(
        ctx.advance(&req).await?,
        AdvanceOutcome::ADVANCE_OUTCOME_COMMITTED,
    )
}

pub(super) async fn committed(ctx: Ctx) -> CaseResult {
    seed(&ctx).await?;
    ctx.expect_ref(&ctx.head("main"), Some(&A)).await?;
    ctx.expect_ref(&ctx.packmap("main"), Some(&A)).await?;
    let req = advance_req(
        (&ctx.head("main"), Exp::Match(&A), &B),
        (&ctx.packmap("main"), Exp::Match(&A), &C),
    );
    want_outcome(
        ctx.advance(&req).await?,
        AdvanceOutcome::ADVANCE_OUTCOME_COMMITTED,
    )?;
    ctx.expect_ref(&ctx.head("main"), Some(&B)).await?;
    ctx.expect_ref(&ctx.packmap("main"), Some(&C)).await
}

/// The head precondition fails, the packmap's holds.
fn head_conflict(ctx: &Ctx) -> mkit_transport_connect::generated::AdvanceRefsRequest {
    advance_req(
        (&ctx.head("main"), Exp::Match(&C), &B),
        (&ctx.packmap("main"), Exp::Match(&A), &B),
    )
}

pub(super) async fn head_conflict_typed(ctx: Ctx) -> CaseResult {
    seed(&ctx).await?;
    want_outcome(
        ctx.advance(&head_conflict(&ctx)).await?,
        AdvanceOutcome::ADVANCE_OUTCOME_HEAD_CONFLICT,
    )?;
    ctx.expect_ref(&ctx.head("main"), Some(&A)).await
}

pub(super) async fn packmap_conflict_typed(ctx: Ctx) -> CaseResult {
    seed(&ctx).await?;
    let req = advance_req(
        (&ctx.head("main"), Exp::Match(&A), &B),
        (&ctx.packmap("main"), Exp::Match(&C), &B),
    );
    want_outcome(
        ctx.advance(&req).await?,
        AdvanceOutcome::ADVANCE_OUTCOME_PACKMAP_CONFLICT,
    )?;
    // The packmap is decided first on every server: neither ref moved.
    ctx.expect_ref(&ctx.head("main"), Some(&A)).await?;
    ctx.expect_ref(&ctx.packmap("main"), Some(&A)).await
}

pub(super) async fn atomic_both_untouched(ctx: Ctx) -> CaseResult {
    seed(&ctx).await?;
    want_outcome(
        ctx.advance(&head_conflict(&ctx)).await?,
        AdvanceOutcome::ADVANCE_OUTCOME_HEAD_CONFLICT,
    )?;
    ctx.expect_ref(&ctx.head("main"), Some(&A)).await?;
    ctx.expect_ref(&ctx.packmap("main"), Some(&A)).await
}

/// §4: without atomic advance the server writes the packmap, then the
/// head; a head conflict leaves the packmap advanced.
pub(super) async fn nonatomic_packmap_first(ctx: Ctx) -> CaseResult {
    seed(&ctx).await?;
    want_outcome(
        ctx.advance(&head_conflict(&ctx)).await?,
        AdvanceOutcome::ADVANCE_OUTCOME_HEAD_CONFLICT,
    )?;
    ctx.expect_ref(&ctx.head("main"), Some(&A)).await?;
    ctx.expect_ref(&ctx.packmap("main"), Some(&B)).await
}

pub(super) async fn unspecified_invalid_argument(ctx: Ctx) -> CaseResult {
    let cases = [
        advance_req(
            (&ctx.head("main"), Exp::Unset, &A),
            (&ctx.packmap("main"), Exp::Any, &A),
        ),
        advance_req(
            (&ctx.head("main"), Exp::Any, &A),
            (&ctx.packmap("main"), Exp::Unset, &A),
        ),
        advance_req(
            (&ctx.head("main"), Exp::Any, &[1; 31]),
            (&ctx.packmap("main"), Exp::Any, &A),
        ),
    ];
    for req in &cases {
        want_code(ctx.advance(req).await?, "invalid_argument", "AdvanceRefs")?;
    }
    ctx.expect_ref(&ctx.head("main"), None).await?;
    ctx.expect_ref(&ctx.packmap("main"), None).await
}
