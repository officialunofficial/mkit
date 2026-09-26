//! `ListRefs` at scale. M0 has no paging on the wire; this case records the
//! size of one large response so M1 (WP-1.27) can assert the page bound.

use buffa::Message as _;
use futures::StreamExt as _;
use mkit_core::hash::hash;
use mkit_transport_connect::generated::{ListRefsRequest, ListRefsResponse, UpdateRefResponse};

use super::{CaseResult, Commit, Ctx, Exp, Failure, ensure, update_req, want_ok};
use crate::wire::client::{Rpc, RpcError, UNARY_PROTO, decode_unary};

/// Writes in flight at once.
const PARALLEL: usize = 8;

/// Create ref `i` (signed by a signer shared by a block of writes small
/// enough for the per-signer quota).
async fn create(
    ctx: Ctx,
    i: u32,
    per_signer: u32,
) -> Result<Result<UpdateRefResponse, RpcError>, String> {
    let id = hash(&i.to_be_bytes());
    let body = update_req(&ctx.head(&format!("r{i:06}")), Exp::Missing, &id).encode_to_vec();
    let headers = match ctx.signer(&format!("w{}", i / per_signer)) {
        Some(signer) => signer.sign_body(Rpc::UpdateRef.procedure(), &body).headers,
        None => ctx.auth_headers(Rpc::UpdateRef, Commit::Body(&body)),
    };
    ctx.client().unary(Rpc::UpdateRef, body, &headers).await
}

pub(super) async fn large_response_within_limit(ctx: Ctx) -> CaseResult {
    let n = ctx.profile().list_refs;
    if n == 0 {
        return Err(Failure::Skip("the profile sets list_refs = 0".to_owned()));
    }
    let per_signer = ctx.profile().quota.map_or(100, |q| q.max_ops.clamp(1, 100));
    let mut writes = futures::stream::iter(0..n)
        .map(|i| create(ctx.clone(), i, per_signer))
        .buffer_unordered(PARALLEL);
    while let Some(result) = writes.next().await {
        want_ok(result?, "UpdateRef")?;
    }
    let prefix = format!("refs/heads/{}/", ctx.ns());
    let req = ListRefsRequest {
        prefix: Some(prefix.clone()),
        ..Default::default()
    };
    let body = req.encode_to_vec();
    let headers = ctx.auth_headers(Rpc::ListRefs, Commit::Body(&body));
    let reply = ctx
        .client()
        .post(Rpc::ListRefs.procedure(), UNARY_PROTO, &headers, body)
        .await?;
    let resp: ListRefsResponse = want_ok(decode_unary(&reply)?, "ListRefs")?;
    let count = u32::try_from(resp.refs.len()).unwrap_or(u32::MAX);
    ensure!(count == n, "ListRefs {prefix:?}: {count} refs, created {n}");
    let names: Vec<_> = resp
        .refs
        .iter()
        .map(|r| r.name.as_deref().unwrap_or(""))
        .collect();
    ensure!(names.is_sorted(), "ListRefs: names are not sorted");
    ctx.set_note(format!(
        "{n} refs: {} bytes in one response",
        reply.body.len()
    ));
    Ok(())
}
