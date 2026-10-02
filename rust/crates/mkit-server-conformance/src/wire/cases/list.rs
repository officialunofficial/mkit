//! `ListRefs` at scale, following continuation tokens and checking each page.

use std::time::Duration;

use buffa::Message as _;
use futures::StreamExt as _;
use mkit_core::hash::hash;
use mkit_transport_connect::generated::{
    GetServerInfoResponse, ListRefsRequest, ListRefsResponse, UpdateRefResponse,
};

use super::{
    CaseResult, Commit, Ctx, Exp, Failure, ensure, eventually_listed, eventually_listed_within,
    update_req, want_code, want_ok,
};
use crate::wire::client::{Rpc, RpcError, UNARY_PROTO, decode_unary};

/// Writes in flight at once when the profile does not override it.
const DEFAULT_PARALLEL: usize = 8;

/// Filler on each side of a listed ref's counter: names of about 300 bytes.
const FILL: usize = 150;

/// The listing size `list.merge_paging_over_32_mib` must exceed.
const OVER: usize = 32 * 1024 * 1024;

/// Create ref `i` (signed by a signer shared by a block of writes small
/// enough for the per-signer quota).
async fn create(
    ctx: Ctx,
    i: u32,
    per_signer: u32,
    fill: usize,
) -> Result<Result<UpdateRefResponse, RpcError>, String> {
    let id = hash(&i.to_be_bytes());
    let body = update_req(
        &ctx.head(&format!("{}/r{i:06}{}", "a".repeat(fill), "b".repeat(fill))),
        Exp::Missing,
        &id,
    )
    .encode_to_vec();
    let headers = match ctx.signer(&format!("w{}", i / per_signer)) {
        Some(signer) => signer.sign_body(Rpc::UpdateRef.procedure(), &body).headers,
        None => ctx.auth_headers(Rpc::UpdateRef, Commit::Body(&body)),
    };
    // Resend the same bytes. miniflare's proxy drops a connection ("Network
    // connection lost"; the dev server continues) after a few thousand
    // requests. A lost response may already have committed; a new nonce
    // would then fail the Missing precondition. Replay returns the stored ok
    // once the original commits; while it is still in flight the duplicate
    // answers retryable `aborted` (STC §5), so a resend retries that too.
    let mut attempt = 0u32;
    loop {
        let failed = match ctx
            .client()
            .unary(Rpc::UpdateRef, body.clone(), &headers)
            .await
        {
            Ok(Ok(value)) => return Ok(Ok(value)),
            Ok(Err(error)) if proxy_blip(&error.message) => error.to_string(),
            Ok(Err(error)) if attempt > 0 && error.code == "aborted" => error.to_string(),
            Ok(Err(error)) => return Ok(Err(error)),
            Err(error) if proxy_blip(&error) => error,
            Err(error) => return Err(error),
        };
        if attempt >= 8 {
            return Err(failed);
        }
        attempt += 1;
        ctx.record_retry(&failed);
        // Up to about 5 s in total: an in-flight original took 2-3 s to commit.
        tokio::time::sleep(std::time::Duration::from_millis(
            (200 * u64::from(attempt)).min(1_000),
        ))
        .await;
    }
}

/// miniflare's dev proxy, not a server answer. The dev server keeps running.
fn proxy_blip(message: &str) -> bool {
    message.contains("Network connection lost") || message.contains("client error (Connect)")
}

pub(super) async fn paging_wire(ctx: Ctx) -> CaseResult {
    for i in 0..3 {
        want_ok(create(ctx.clone(), i, 100, FILL).await?, "UpdateRef")?;
    }
    let prefix = format!("refs/heads/{}/", ctx.ns());
    eventually_listed(
        &prefix,
        || async { want_ok(ctx.list(&prefix).await?, "ListRefs before paging") },
        |refs| refs.len() == 3,
    )
    .await?;
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
    let lag = Duration::from_millis(mkit_server::relay::RELAY_LAG_BOUND_MS);
    let (_, pages, _) = large_listing(&ctx, n, FILL, lag).await?;
    ctx.set_note(format!("{n} refs across {pages} pages"));
    Ok(())
}

/// A listing whose wire size passes 32 MiB, so the merge that pages the ref
/// index must hold its 2 MiB page bound over hundreds of pages (STC §7.9).
/// Only a native deployment creates that many refs in reasonable time.
pub(super) async fn merge_paging_over_32_mib(ctx: Ctx) -> CaseResult {
    let n = ctx.profile().merge_paging_refs;
    if n == 0 {
        return Err(Failure::Skip(
            "the profile sets merge_paging_refs = 0 (native deployments only)".to_owned(),
        ));
    }
    // Names at the 512-byte cap, less the counter and rounding: 510 bytes.
    let fill = mkit_server::refs::MAX_REF_NAME_BYTES.saturating_sub(ctx.head("").len() + 8) / 2;
    // The large source-shard backlog can take minutes on a shared machine;
    // this case measures paging correctness, rather than a throughput bar.
    let (_, pages, bytes) = large_listing(&ctx, n, fill, Duration::from_mins(20)).await?;
    ensure!(
        bytes > OVER,
        "the {n} refs listed in {bytes} bytes, under the {OVER} the case needs"
    );
    ctx.set_note(format!("{n} refs, {bytes} bytes across {pages} pages"));
    Ok(())
}

/// Create `n` refs of names `fill` filler bytes wide, then follow every
/// page of their listing: `(count, pages, body bytes)`.
#[allow(clippy::too_many_lines)] // One helper: paced fixture, lag wait and paged assertions.
async fn large_listing(
    ctx: &Ctx,
    n: u32,
    fill: usize,
    lag: Duration,
) -> Result<(u32, u32, usize), Failure> {
    let per_signer = ctx.profile().quota.map_or(100, |q| q.max_ops.clamp(1, 100));
    let parallel = usize::try_from(ctx.profile().list_parallel).unwrap_or(DEFAULT_PARALLEL);
    let parallel = parallel.clamp(1, 32);
    let mut writes = futures::stream::iter(0..n)
        .map(|i| create(ctx.clone(), i, per_signer, fill))
        .buffer_unordered(parallel);
    let started = std::time::Instant::now();
    let mut done = 0u32;
    let mut last_mark = started;
    while let Some(result) = writes.next().await {
        if !matches!(result, Ok(Ok(_))) {
            eprintln!(
                "large listing: a write failed after {done}/{n} successful writes, {:?} (chunk {:?})",
                started.elapsed(),
                last_mark.elapsed()
            );
        }
        want_ok(result?, "UpdateRef")?;
        done += 1;
        if done.is_multiple_of(1000) {
            let now = std::time::Instant::now();
            eprintln!(
                "large listing: {done}/{n} writes in {:?} (last 1000: {:?})",
                started.elapsed(),
                now.duration_since(last_mark)
            );
            last_mark = now;
        }
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
    let (count, pages, bytes) = eventually_listed_within(
        lag,
        &prefix,
        || async {
            let mut token = None;
            let mut seen = std::collections::HashSet::new();
            let mut last = String::new();
            let mut count = 0u32;
            let mut pages = 0u32;
            let mut bytes = 0usize;
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
                bytes += reply.body.len();
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
            Ok((count, pages, bytes))
        },
        |(count, _, _)| *count == n,
    )
    .await?;
    ensure!(count == n, "ListRefs {prefix:?}: {count} refs, created {n}");
    Ok((count, pages, bytes))
}
