//! M3 admission on a real wire and a loopback MPP fixture.
use super::{
    A, B, CaseResult, Commit, Ctx, Exp, Failure, Signed, advance_req, ensure, sign_unary,
    upload_msgs, want_ok, want_outcome,
};
use crate::wire::client::{Client, Reply, Rpc, UNARY_JSON, UNARY_PROTO, decode_unary, frames};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use buffa::Message;
use mkit_transport_connect::generated::__buffa::oneof::begin_upload_response::Result as BeginResult;
use mkit_transport_connect::generated::{
    AdmissionChallenge, BeginUploadRequest, BeginUploadResponse, UploadPackResponse,
};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

pub(super) fn stub(ctx: &Ctx) -> Result<Client, Failure> {
    let url = ctx
        .profile()
        .hook_stub
        .as_ref()
        .ok_or_else(|| Failure::Skip("no hook stub".into()))?;
    Client::new(url).map_err(Into::into)
}
pub(super) async fn mode(ctx: &Ctx, admit: &str, outcome: &str) -> CaseResult {
    let reply = stub(ctx)?
        .post(
            "/__stub/mode",
            UNARY_JSON,
            &[],
            serde_json::to_vec(&serde_json::json!({"admit":admit,"outcome":outcome}))
                .map_err(|_| "control encoding")?,
        )
        .await?;
    ensure!(reply.status == 200, "stub control failed");
    Ok(())
}
pub(super) async fn calls(ctx: &Ctx) -> Result<u64, Failure> {
    let reply = stub(ctx)?.get("/__stub/calls").await?;
    let counts: BTreeMap<String, u64> =
        serde_json::from_slice(&reply.body).map_err(|_| "invalid stub counts")?;
    Ok(counts.get("Admit").copied().unwrap_or_default())
}
pub(super) async fn post(ctx: &Ctx, signed: &Signed) -> Result<Reply, Failure> {
    ctx.client()
        .post(
            signed.rpc.procedure(),
            UNARY_PROTO,
            &signed.headers,
            signed.body.clone(),
        )
        .await
        .map_err(Into::into)
}
pub(super) fn credential(reply: &Reply) -> Result<String, Failure> {
    let json: serde_json::Value =
        serde_json::from_slice(&reply.body).map_err(|_| "invalid challenge error")?;
    let value = json["details"][0]["value"]
        .as_str()
        .ok_or("no challenge detail")?;
    let bytes = STANDARD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(value))
        .map_err(|_| "invalid detail encoding")?;
    let detail =
        AdmissionChallenge::decode_from_slice(&bytes).map_err(|_| "invalid challenge detail")?;
    let value = detail
        .challenges
        .first()
        .and_then(|c| c.value.as_deref())
        .ok_or("empty challenge list")?;
    #[cfg(feature = "stubs")]
    {
        crate::stubs::mpp::credential_for(value).map_err(Into::into)
    }
    #[cfg(not(feature = "stubs"))]
    {
        let _ = value;
        Err(Failure::Skip("runner needs feature stubs".into()))
    }
}
pub(super) async fn paid(
    ctx: &Ctx,
    label: &str,
    rpc: Rpc,
    req: &impl Message,
) -> Result<(Signed, Reply), Failure> {
    let signed = sign_unary(&ctx.v2_signer(label)?, rpc, req, |_| {});
    let challenge = post(ctx, &signed).await?;
    ensure!(
        challenge.status == 402,
        "first attempt must challenge: {}",
        challenge.status
    );
    let credential = credential(&challenge)?;
    let signed = signed.with_header("Authorization", credential);
    let reply = post(ctx, &signed).await?;
    Ok((signed, reply))
}
/// Ledger snapshots contain no credentials or receipt values.
pub(super) async fn ledger(ctx: &Ctx) -> Result<serde_json::Value, Failure> {
    let reply = stub(ctx)?.get("/__stub/outcomes").await?;
    serde_json::from_slice(&reply.body).map_err(|_| Failure::Fail("invalid ledger".into()))
}
async fn expect_absent(ctx: &Ctx) -> CaseResult {
    if ctx.profile().has(crate::wire::Feature::MultiRepo) {
        super::want_code(
            ctx.call::<mkit_transport_connect::generated::ReadRefResponse>(
                Rpc::ReadRef,
                &mkit_transport_connect::generated::ReadRefRequest {
                    name: Some(ctx.head("main")),
                    ..Default::default()
                },
            )
            .await?,
            "not_found",
            "unallocated Multi repository",
        )?;
        Ok(())
    } else {
        ctx.expect_ref(&ctx.head("main"), None).await
    }
}
pub(super) async fn prepare_ticket(
    ctx: &Ctx,
    leaf: &str,
) -> Result<(mkit_transport_connect::generated::AdvanceRefsRequest, Reply), Failure> {
    let pack = super::random_pack(128);
    let req = BeginUploadRequest {
        r#ref: Some(ctx.head(leaf)),
        pack_id: Some(mkit_core::hash::hash(&pack).to_vec()),
        bytes: Some(pack.len() as u64),
        ..Default::default()
    };
    let (_, reply) = paid(ctx, "main", Rpc::BeginUpload, &req).await?;
    let begin: BeginUploadResponse = want_ok(decode_unary(&reply)?, "paid BeginUpload")?;
    let Some(BeginResult::Ticket(ticket)) = begin.result else {
        return Err("no upload ticket".into());
    };
    let mut msgs = upload_msgs(&pack, 2);
    if let Some(
        mkit_transport_connect::generated::__buffa::oneof::upload_pack_request::Body::Header(h),
    ) = &mut msgs[0].body
    {
        h.ticket_token = ticket.token;
    }
    let headers = ctx.auth_headers(
        Rpc::UploadPack,
        Commit::Pack(&mkit_core::hash::hash(&pack), pack.len() as u64),
    );
    let upload = ctx
        .client()
        .stream::<UploadPackResponse>(Rpc::UploadPack, frames(&msgs), &headers)
        .await?;
    ensure!(upload.error.is_none(), "ticketed upload rejected");
    let mut advance = advance_req(
        (&ctx.head(leaf), Exp::Missing, &A),
        (&ctx.packmap(leaf), Exp::Missing, &B),
    );
    advance.ticket_ids = vec![ticket.id.ok_or("no ticket id")?];
    Ok((advance, reply))
}
pub(super) async fn helper_flow_commit(ctx: Ctx) -> CaseResult {
    let ctx = ctx.in_owned_repository()?;
    mode(&ctx, "normal", "normal").await?;
    let admit_count = calls(&ctx).await?;
    let before = snapshot(&ctx).await?;
    let (advance, reply) = prepare_ticket(&ctx, "main").await?;
    ensure!(
        calls(&ctx).await? == admit_count + 2,
        "helper admission count"
    );
    ensure!(
        reply.headers.contains_key("payment-receipt"),
        "missing receipt"
    );
    ensure!(
        reply
            .headers
            .get("cache-control")
            .is_some_and(|v| v == "private"),
        "receipt cache policy"
    );
    want_outcome(
        ctx.advance(&advance).await?,
        mkit_transport_connect::generated::AdvanceOutcome::ADVANCE_OUTCOME_COMMITTED,
    )?;
    let rows = wait_new(&ctx, &before, 1).await?;
    ensure!(
        rows.len() == 1 && rows[0]["kind"] == "committed" && rows[0]["settled"] == true,
        "commit ledger"
    );
    Ok(())
}

/// Hold the first paid Admit while sending exactly the same signed bytes.
/// Release the fixture before asserting, so a divergence cannot strand a request.
pub(super) async fn concurrent_duplicate_during_admit(ctx: Ctx) -> CaseResult {
    let ctx = ctx.in_owned_repository()?;
    mode(&ctx, "hold", "normal").await?;
    let before = calls(&ctx).await?;
    let ledger_before = snapshot(&ctx).await?;
    let req = super::update_req(&ctx.head("main"), Exp::Missing, &A);
    let signed = sign_unary(&ctx.v2_signer("main")?, Rpc::UpdateRef, &req, |_| {});
    let challenge = post(&ctx, &signed).await?;
    ensure!(challenge.status == 402, "initial challenge status");
    let signed = signed.with_header("Authorization", credential(&challenge)?);
    let first = {
        let (ctx, signed) = (ctx.clone(), signed.clone());
        tokio::spawn(async move { post(&ctx, &signed).await })
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while calls(&ctx).await? < before + 2 {
        ensure!(
            tokio::time::Instant::now() < deadline,
            "held Admit deadline"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let duplicate = tokio::time::timeout(Duration::from_secs(2), post(&ctx, &signed)).await;
    stub(&ctx)?
        .post("/__stub/release", UNARY_JSON, &[], vec![])
        .await?;
    mode(&ctx, "normal", "normal").await?;
    let first = first.await.map_err(|_| "first request task failed")??;
    ensure!(
        first.status == 200,
        "released first request: {}",
        first.status
    );
    let duplicate = duplicate.map_err(|_| "duplicate did not return while Admit was held")??;
    if duplicate.status == 200 {
        ensure!(
            duplicate.body == first.body,
            "duplicate result differs from caller's result"
        );
    }
    // The hook may deny a spent credential; a completed retry may return the
    // saved result. Repository state and the ledger below decide conformance.
    ctx.expect_ref(&ctx.head("main"), Some(&A)).await?;
    let rows = wait_new(&ctx, &ledger_before, 1).await?;
    ensure!(
        rows.len() == 1 && rows[0]["kind"] == "committed" && rows[0]["settled"] == true,
        "duplicate charged twice"
    );
    let other = sign_unary(&ctx.v2_signer("other")?, Rpc::UpdateRef, &req, |env| {
        env.nonce.clone_from(&signed.nonce);
    });
    let foreign = post(&ctx, &other).await?;
    ensure!(
        foreign.status != 200,
        "another caller received stored result"
    );
    Ok(())
}

pub(super) fn want_error(reply: &Reply, status: u16, code: &str) -> CaseResult {
    let error: serde_json::Value =
        serde_json::from_slice(&reply.body).map_err(|_| "invalid error JSON")?;
    ensure!(
        reply.status == status && error["code"] == code,
        "expected HTTP {status}/{code}, got {}",
        reply.status
    );
    Ok(())
}
pub(super) async fn snapshot(ctx: &Ctx) -> Result<BTreeSet<String>, Failure> {
    Ok(ledger(ctx)
        .await?
        .as_object()
        .ok_or("ledger map")?
        .keys()
        .cloned()
        .collect())
}
pub(super) async fn wait_new(
    ctx: &Ctx,
    before: &BTreeSet<String>,
    minimum: usize,
) -> Result<Vec<serde_json::Value>, Failure> {
    let deadline = tokio::time::Instant::now() + Duration::from_mins(1);
    loop {
        let ledger = ledger(ctx).await?;
        let rows: Vec<_> = ledger
            .as_object()
            .ok_or("ledger map")?
            .iter()
            .filter(|(id, _)| !before.contains(*id))
            .map(|(_, row)| row.clone())
            .collect();
        if rows.len() >= minimum
            && rows
                .iter()
                .all(|r| r["acknowledged"].as_u64().unwrap_or_default() > 0)
        {
            return Ok(rows);
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "outcome delivery deadline: needed {minimum}, saw {} rows, acknowledged {}",
            rows.len(),
            rows.iter()
                .filter(|r| r["acknowledged"].as_u64().unwrap_or_default() > 0)
                .count()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
fn update(ctx: &Ctx) -> Result<Signed, Failure> {
    Ok(sign_unary(
        &ctx.v2_signer("main")?,
        Rpc::UpdateRef,
        &super::update_req(&ctx.head("main"), Exp::Missing, &A),
        |_| {},
    ))
}
pub(super) async fn challenge_402_typed_detail(ctx: Ctx) -> CaseResult {
    let ctx = ctx.in_owned_repository()?;
    mode(&ctx, "golden", "normal").await?;
    let reply = post(&ctx, &update(&ctx)?).await?;
    want_error(&reply, 402, "permission_denied")?;
    let error: serde_json::Value = serde_json::from_slice(&reply.body).map_err(|_| "error JSON")?;
    ensure!(
        error["details"].as_array().is_some_and(|d| d.len() == 1),
        "challenge detail count"
    );
    ensure!(
        error["details"][0]["type"] == "mkit.transport.v1.AdmissionChallenge",
        "detail type"
    );
    let raw = error["details"][0]["value"]
        .as_str()
        .ok_or("detail value")?;
    let bytes = STANDARD
        .decode(raw)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(raw))
        .map_err(|_| "detail encoding")?;
    ensure!(
        bytes == include_bytes!("../../../../../tests/golden/transport/admission-challenge.bin"),
        "challenge golden differs"
    );
    let fields: Vec<_> = reply
        .headers
        .get_all("www-authenticate")
        .iter()
        .map(|v| v.to_str().map_err(|_| "challenge header encoding"))
        .collect::<Result<_, _>>()?;
    if ctx
        .profile()
        .has(crate::wire::Feature::CombinedChallengeFields)
    {
        ensure!(
            fields.len() == 1 || fields.len() == 2,
            "challenge field count"
        );
    } else {
        ensure!(fields.len() == 2, "native challenge field count");
    }
    let challenges = crate::wire::challenges::parse(&fields.join(", "))?;
    ensure!(challenges.len() == 2, "challenge list count");
    ensure!(
        challenges[0].scheme.eq_ignore_ascii_case("Payment")
            && challenges[0]
                .params
                .get("method")
                .is_some_and(|v| v == "stub")
            && challenges[0]
                .params
                .get("id")
                .is_some_and(|v| v.len() == 64)
            && challenges[1].scheme.eq_ignore_ascii_case("Payment")
            && challenges[1]
                .params
                .get("id")
                .is_some_and(|v| v == "second"),
        "challenge list content/order"
    );
    ensure!(
        reply
            .headers
            .get("payment-required")
            .is_some_and(|v| v == "stub"),
        "payment-required pass-through"
    );
    ensure!(
        reply
            .headers
            .get("cache-control")
            .is_some_and(|v| v == "no-store"),
        "challenge cache policy"
    );
    mode(&ctx, "normal", "normal").await?;
    Ok(())
}
pub(super) async fn deny_403_no_detail(ctx: Ctx) -> CaseResult {
    let ctx = ctx.in_owned_repository()?;
    mode(&ctx, "deny", "normal").await?;
    let reply = post(&ctx, &update(&ctx)?).await?;
    want_error(&reply, 403, "permission_denied")?;
    let error: serde_json::Value = serde_json::from_slice(&reply.body).map_err(|_| "error JSON")?;
    ensure!(
        error["details"].as_array().is_none_or(Vec::is_empty),
        "deny has details"
    );
    for name in [
        "www-authenticate",
        "payment-required",
        "payment-receipt",
        "payment-response",
    ] {
        ensure!(!reply.headers.contains_key(name), "deny has payment header");
    }
    expect_absent(&ctx).await?;
    mode(&ctx, "normal", "normal").await
}
pub(super) async fn no_state_on_challenge(ctx: Ctx) -> CaseResult {
    let ctx = ctx.in_owned_repository()?;
    mode(&ctx, "normal", "normal").await?;
    let before = snapshot(&ctx).await?;
    let signed = update(&ctx)?;
    let challenge = post(&ctx, &signed).await?;
    want_error(&challenge, 402, "permission_denied")?;
    expect_absent(&ctx).await?;
    let listing = ctx.list(&ctx.head("")).await?;
    if ctx.profile().has(crate::wire::Feature::MultiRepo) {
        super::want_code(listing, "not_found", "challenged Multi repository")?;
    } else {
        ensure!(
            want_ok(listing, "challenge listing")?.is_empty(),
            "challenged operation created refs"
        );
    }
    ensure!(
        snapshot(&ctx).await? == before,
        "challenge generated outcome"
    );
    let retry = post(
        &ctx,
        &signed.with_header("Authorization", credential(&challenge)?),
    )
    .await?;
    ensure!(retry.status == 200, "challenged nonce consumed");
    ctx.expect_ref(&ctx.head("main"), Some(&A)).await?;
    wait_new(&ctx, &before, 1).await?;
    Ok(())
}
pub(super) async fn replay_skips_admission(ctx: Ctx) -> CaseResult {
    let ctx = ctx.in_owned_repository()?;
    mode(&ctx, "normal", "normal").await?;
    let before = snapshot(&ctx).await?;
    let (signed, first) = paid(
        &ctx,
        "main",
        Rpc::UpdateRef,
        &super::update_req(&ctx.head("main"), Exp::Missing, &A),
    )
    .await?;
    ensure!(first.status == 200, "first commit");
    let count = calls(&ctx).await?;
    let replay = post(&ctx, &signed).await?;
    ensure!(
        replay.status == 200 && replay.body == first.body,
        "replay differs"
    );
    ensure!(calls(&ctx).await? == count, "replay reached Admit");
    for name in ["payment-receipt", "payment-response"] {
        ensure!(!replay.headers.contains_key(name), "replay has receipt");
    }
    ensure!(
        wait_new(&ctx, &before, 1).await?.len() == 1,
        "replay added reservation"
    );
    Ok(())
}
pub(super) async fn challenge_exhausted(ctx: Ctx) -> CaseResult {
    let ctx = ctx.in_owned_repository()?;
    mode(&ctx, "always-challenge", "normal").await?;
    let before = snapshot(&ctx).await?;
    let (_, reply) = paid(
        &ctx,
        "main",
        Rpc::UpdateRef,
        &super::update_req(&ctx.head("main"), Exp::Missing, &A),
    )
    .await?;
    want_error(&reply, 402, "permission_denied")?;
    expect_absent(&ctx).await?;
    ensure!(
        snapshot(&ctx).await? == before,
        "exhausted challenge generated outcome"
    );
    mode(&ctx, "normal", "normal").await
}
pub(super) async fn hook_down_unavailable(ctx: Ctx) -> CaseResult {
    let ctx = ctx.in_owned_repository()?;
    mode(&ctx, "down", "normal").await?;
    let before = snapshot(&ctx).await?;
    want_error(&post(&ctx, &update(&ctx)?).await?, 503, "unavailable")?;
    expect_absent(&ctx).await?;
    ensure!(
        snapshot(&ctx).await? == before,
        "unavailable generated outcome"
    );
    mode(&ctx, "normal", "normal").await
}
pub(super) async fn ticketless_upload_refused(ctx: Ctx) -> CaseResult {
    let ctx = ctx.in_owned_repository()?;
    let pack = super::random_pack(64);
    let headers = ctx.auth_headers(
        Rpc::UploadPack,
        Commit::Pack(&mkit_core::hash::hash(&pack), pack.len() as u64),
    );
    let reply = ctx
        .client()
        .post(
            Rpc::UploadPack.procedure(),
            crate::wire::client::STREAM_PROTO,
            &headers,
            frames(&upload_msgs(&pack, 1)),
        )
        .await?;
    ensure!(reply.status != 402, "stream returned a challenge");
    let stream: crate::wire::client::StreamReply<UploadPackResponse> =
        crate::wire::client::decode_stream(&reply)?;
    let error = stream.error.ok_or("ticketless upload accepted")?;
    ensure!(
        error.code == "failed_precondition" && error.details.is_empty(),
        "ticketless stream refusal must have no challenge detail"
    );
    Ok(())
}
