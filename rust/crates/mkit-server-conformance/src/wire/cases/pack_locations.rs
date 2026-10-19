//! Opt-in pack locations retain the existing streaming contract by default.

use buffa::Message as _;
use mkit_core::hash::hash;
use mkit_transport_connect::generated::{DownloadPackRequest, GetServerInfoResponse};

use super::{CaseResult, Commit, Ctx, DownloadBody, Rpc, ensure, frame, random_pack, want_ok};
use crate::wire::client::{Client, UNARY_PROTO, decode_unary};

pub(super) async fn opt_in_round_trip(ctx: Ctx) -> CaseResult {
    if ctx.profile().has(super::Feature::PackLocationFixtures) {
        return super::pack_location_fixtures::round_trip(ctx).await;
    }
    let reply = ctx
        .client()
        .post(
            "/mkit.transport.v1.TransportService/GetServerInfo",
            UNARY_PROTO,
            &[],
            Vec::new(),
        )
        .await?;
    let info = want_ok(
        decode_unary::<GetServerInfoResponse>(&reply)?,
        "GetServerInfo",
    )?;
    ensure!(
        info.supports_pack_locations == Some(true),
        "pack locations not advertised"
    );
    let bound = info.max_pack_location_lifetime_ms.unwrap_or(0);
    ensure!(bound > 0, "location lifetime bound is missing");
    let pack = random_pack(1024);
    ctx.put_pack(&pack).await?;
    let request = DownloadPackRequest {
        pack_id: Some(hash(&pack).to_vec()),
        accept_location: Some(true),
        ..Default::default()
    };
    let body = frame(&request.encode_to_vec());
    let headers = ctx.auth_headers(Rpc::DownloadPack, Commit::Body(&body));
    let reply = ctx
        .client()
        .stream::<mkit_transport_connect::generated::DownloadPackResponse>(
            Rpc::DownloadPack,
            body,
            &headers,
        )
        .await?;
    ensure!(
        reply.error.is_none(),
        "opted-in download failed: {:?}",
        reply.error
    );
    let Some(Some(DownloadBody::Location(location))) =
        reply.messages.first().map(|m| m.body.as_ref())
    else {
        // A capable server may choose streaming on any individual request.
        Ctx::downloaded_bytes(&hash(&pack), reply)?;
        return Ok(());
    };
    ensure!(
        reply.messages.len() == 1,
        "location mixed with stream messages"
    );
    ensure!(
        location.total_bytes == Some(pack.len() as u64),
        "incorrect location length"
    );
    let expiry = location.expires_at_ms.ok_or("missing location expiry")?;
    let now = ctx.server_now_ms();
    ensure!(
        expiry > now && expiry - now <= i64::try_from(bound).unwrap_or(i64::MAX),
        "location expiry exceeds advertised bound"
    );
    let url = url::Url::parse(location.url.as_deref().ok_or("missing location URL")?)
        .map_err(|e| e.to_string())?;
    let loopback = url
        .host_str()
        .and_then(|host| host.parse::<std::net::IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback());
    ensure!(
        url.scheme() == "https"
            || (ctx.profile().server_clock.is_some() && loopback && url.scheme() == "http"),
        "location must use HTTPS"
    );
    // This client is built from the location origin with no RPC credentials.
    let origin = url::Url::parse(&url.origin().ascii_serialization()).map_err(|e| e.to_string())?;
    let client = Client::new(&origin)?;
    let path = format!(
        "{}{}",
        url.path(),
        url.query().map_or(String::new(), |q| format!("?{q}"))
    );
    let fetched = client.read("GET", &path, &[]).await?;
    ensure!(
        fetched.status == 200,
        "location fetch HTTP {}",
        fetched.status
    );
    ensure!(fetched.body.len() == pack.len(), "location length mismatch");
    ensure!(
        hash(&fetched.body) == hash(&pack),
        "location content address mismatch"
    );
    Ok(())
}

pub(super) async fn no_location_without_opt_in(ctx: Ctx) -> CaseResult {
    if ctx.profile().has(super::Feature::PackLocationFixtures) {
        return super::pack_location_fixtures::no_opt_in(ctx).await;
    }
    let pack = random_pack(1024);
    ctx.put_pack(&pack).await?;
    let reply = ctx.download(&hash(&pack)).await?;
    ensure!(
        !reply
            .messages
            .iter()
            .any(|message| matches!(message.body, Some(DownloadBody::Location(_)))),
        "location without client opt-in"
    );
    let fetched = Ctx::downloaded_bytes(&hash(&pack), reply)?;
    ensure!(fetched == pack, "streamed bytes differ");
    Ok(())
}
