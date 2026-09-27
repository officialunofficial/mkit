//! Epoch bump directives over the existing `ListRefs` wire route.

use buffa::Message;
use mkit_transport_connect::generated::{ListRefsRequest, ListRefsResponse};

use super::{A, B, CaseResult, Commit, Ctx, Exp, Failure, want_code, want_ok};
use crate::wire::client::Rpc;

const BUMP: &str = "x-mkit-test-bump-epoch";

pub(super) async fn bump_completes_and_writes_continue(ctx: Ctx) -> CaseResult {
    if !ctx.profile().fresh_target {
        return Err(Failure::Skip(
            "epoch bump requires a fresh disposable target".into(),
        ));
    }
    let name = ctx.head("main");
    ctx.set(&name, Exp::Missing, &A).await?;

    let body = ListRefsRequest {
        prefix: Some(name.clone()),
        ..Default::default()
    }
    .encode_to_vec();
    let mut headers = ctx.auth_headers(Rpc::ListRefs, Commit::Body(&body));
    headers.push((BUMP.into(), "1".into()));
    let bumped: Result<ListRefsResponse, _> = ctx
        .client()
        .unary(Rpc::ListRefs, body.clone(), &headers)
        .await?;
    if ctx.profile().sharding_d34 {
        // The directive runs before listing. D34 listing is deliberately
        // deferred, so the route returns this error after completing the bump.
        want_code(bumped, "unimplemented", "D34 listing after epoch bump")?;
    } else {
        want_ok(bumped, "listing after epoch bump")?;
    }

    // An ignored directive would also return Unimplemented under D34.
    // Repeating the same epoch must instead fail at the bump's monotonicity
    // check, proving that the first directive changed the coordinator epoch.
    let repeated: Result<ListRefsResponse, _> =
        ctx.client().unary(Rpc::ListRefs, body, &headers).await?;
    want_code(repeated, "invalid_argument", "repeated epoch bump")?;

    ctx.set(&name, Exp::Match(&A), &B).await?;
    ctx.expect_ref(&name, Some(&B)).await
}
