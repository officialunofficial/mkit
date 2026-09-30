//! The eventual `ListRefs` window (SPEC-TRANSPORT-CONNECT §7.9) over the real
//! wire: with D34 a committed ref reads strongly at once, and the ref-name
//! index a listing reads catches up when the source shard's relay delivers.
//! `x-mkit-test-relay-delay-ms` (`test-faults`) holds that relay, so the
//! window is observable instead of a race.

use mkit_transport_connect::generated::UpdateRefResponse;

use super::{
    A, CaseResult, Ctx, Exp, Failure, ensure, eventually_listed, sign_unary, update_req, want_ok,
};
use crate::wire::RELAY_DELAY_MS_HEADER;
use crate::wire::client::Rpc;

/// How long the relay is held. The listing read must land inside it; a
/// slower server skips instead of failing.
const LAG_MS: u64 = 8_000;

pub(super) async fn list_refs_window(ctx: Ctx) -> CaseResult {
    if !ctx.profile().sharding_d34 {
        return Err(Failure::Skip("requires a lagging ref index (D34)".into()));
    }
    let name = ctx.head("lagged");
    let prefix = format!("refs/heads/{}/", ctx.ns());
    let held = sign_unary(
        &ctx.v2_signer("main")?,
        Rpc::UpdateRef,
        &update_req(&name, Exp::Any, &A),
        |_| {},
    )
    .with_header(RELAY_DELAY_MS_HEADER, LAG_MS.to_string());
    let started = std::time::Instant::now();
    want_ok(
        ctx.send::<UpdateRefResponse>(&held).await?,
        "held UpdateRef",
    )?;
    // The write is strongly readable at once, but not yet listed.
    ctx.expect_ref(&name, Some(&A)).await?;
    let early = want_ok(ctx.list(&prefix).await?, "ListRefs in the window")?;
    if started.elapsed().as_millis() >= u128::from(LAG_MS) {
        return Err(Failure::Skip(
            "the lag window closed before the read".into(),
        ));
    }
    ensure!(
        early.is_empty(),
        "a ref was listed while its relay was held: {early:?}"
    );
    // Then the relay delivers within the bound.
    eventually_listed(
        &prefix,
        || async { want_ok(ctx.list(&prefix).await?, "ListRefs after the window") },
        |refs| refs.iter().any(|(n, id)| n == "lagged" && id == &A),
    )
    .await?;
    Ok(())
}
