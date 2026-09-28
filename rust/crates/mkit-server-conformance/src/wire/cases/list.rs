//! `ListRefs` at scale, following continuation tokens and checking each page.

use buffa::Message as _;
use futures::StreamExt as _;
use mkit_core::hash::hash;
use mkit_transport_connect::generated::{
    GetServerInfoResponse, ListRefsRequest, ListRefsResponse, UpdateRefResponse,
};

use super::{CaseResult, Commit, Ctx, Exp, Failure, ensure, update_req, want_code, want_ok};
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
    let body = update_req(
        &ctx.head(&format!("{}/r{i:06}{}", "a".repeat(150), "b".repeat(150))),
        Exp::Missing,
        &id,
    )
    .encode_to_vec();
    let headers = match ctx.signer(&format!("w{}", i / per_signer)) {
        Some(signer) => signer.sign_body(Rpc::UpdateRef.procedure(), &body).headers,
        None => ctx.auth_headers(Rpc::UpdateRef, Commit::Body(&body)),
    };
    ctx.client().unary(Rpc::UpdateRef, body, &headers).await
}

pub(super) async fn paging_wire(ctx: Ctx) -> CaseResult {
    for i in 0..3 {
        want_ok(create(ctx.clone(), i, 100).await?, "UpdateRef")?;
    }
    let prefix = format!("refs/heads/{}/", ctx.ns());
    let request = |page_size, page_token| ListRefsRequest {
        prefix: Some(prefix.clone()),
        page_size,
        page_token,
        ..Default::default()
    };
    let call = |req: ListRefsRequest| {
        let ctx = ctx.clone();
        async move {
            let body = req.encode_to_vec();
            let headers = ctx.auth_headers(Rpc::ListRefs, Commit::Body(&body));
            let reply = ctx
                .client()
                .post(Rpc::ListRefs.procedure(), UNARY_PROTO, &headers, body)
                .await?;
            decode_unary::<ListRefsResponse>(&reply)
        }
    };
    let first = want_ok(call(request(Some(1), None)).await?, "ListRefs first page")?;
    ensure!(
        first.refs.len() == 1,
        "page_size=1 returned {} refs",
        first.refs.len()
    );
    let token = first
        .next_page_token
        .clone()
        .ok_or("missing continuation token")?;
    let second = want_ok(
        call(request(Some(1), Some(token.clone()))).await?,
        "ListRefs second page",
    )?;
    ensure!(
        second.refs.len() == 1 && first.refs[0].name < second.refs[0].name,
        "token did not advance listing"
    );
    for bad in ["not-base64!".to_owned(), "A".repeat(800)] {
        want_code(
            call(request(Some(1), Some(bad))).await?,
            "invalid_argument",
            "bad page token",
        )?;
    }
    let foreign = ListRefsRequest {
        prefix: Some("refs/tags/".into()),
        page_size: Some(1),
        page_token: Some(token),
        ..Default::default()
    };
    want_code(
        call(foreign).await?,
        "invalid_argument",
        "foreign prefix token",
    )?;
    let absent = want_ok(call(request(None, None)).await?, "absent page_size")?;
    let zero = want_ok(call(request(Some(0), None)).await?, "zero page_size")?;
    ensure!(
        absent.refs == zero.refs && absent.next_page_token == zero.next_page_token,
        "absent and zero page sizes differ"
    );
    let info_reply = ctx
        .client()
        .post(
            "/mkit.transport.v1.TransportService/GetServerInfo",
            UNARY_PROTO,
            &[],
            Vec::new(),
        )
        .await?;
    let info: GetServerInfoResponse = want_ok(decode_unary(&info_reply)?, "GetServerInfo")?;
    let cap = info
        .max_list_refs_page_size
        .ok_or("missing max_list_refs_page_size")?;
    let above = want_ok(
        call(request(Some(cap.saturating_add(1)), None)).await?,
        "above-cap page_size",
    )?;
    ensure!(
        above.refs.len() <= cap as usize,
        "above-cap page exceeded advertised maximum"
    );
    ensure!(
        above.refs == absent.refs,
        "above-cap page differs from default maximum"
    );
    Ok(())
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
    let info_reply = ctx
        .client()
        .post(
            "/mkit.transport.v1.TransportService/GetServerInfo",
            UNARY_PROTO,
            &[],
            Vec::new(),
        )
        .await?;
    let info: GetServerInfoResponse = want_ok(decode_unary(&info_reply)?, "GetServerInfo")?;
    let cap = info
        .max_list_refs_page_size
        .ok_or("missing max_list_refs_page_size")?;
    let prefix = format!("refs/heads/{}/", ctx.ns());
    let mut token = None;
    let mut seen = std::collections::HashSet::new();
    let mut last = String::new();
    let mut count = 0u32;
    let mut pages = 0u32;
    loop {
        let req = ListRefsRequest {
            prefix: Some(prefix.clone()),
            page_token: token,
            ..Default::default()
        };
        let body = req.encode_to_vec();
        let headers = ctx.auth_headers(Rpc::ListRefs, Commit::Body(&body));
        let reply = ctx
            .client()
            .post(Rpc::ListRefs.procedure(), UNARY_PROTO, &headers, body)
            .await?;
        let resp: ListRefsResponse = want_ok(decode_unary(&reply)?, "ListRefs")?;
        ensure!(
            reply.body.len() <= 2 * 1024 * 1024,
            "ListRefs page exceeds 2 MiB"
        );
        ensure!(
            resp.refs.len() <= cap as usize,
            "ListRefs page exceeds advertised ref cap"
        );
        pages += 1;
        for r in &resp.refs {
            let name = r.name.as_deref().unwrap_or("");
            ensure!(name > last.as_str(), "ListRefs names are not increasing");
            name.clone_into(&mut last);
            count += 1;
        }
        match resp.next_page_token.filter(|s| !s.is_empty()) {
            Some(next) => {
                ensure!(
                    !resp.refs.is_empty(),
                    "ListRefs continuation made no progress"
                );
                ensure!(seen.insert(next.clone()), "ListRefs repeated a page token");
                token = Some(next);
            }
            None => break,
        }
    }
    ensure!(count == n, "ListRefs {prefix:?}: {count} refs, created {n}");
    ctx.set_note(format!("{n} refs across {pages} pages"));
    Ok(())
}
