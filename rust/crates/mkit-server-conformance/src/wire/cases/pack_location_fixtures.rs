//! Portable pack-location scenarios using negotiated disposable fixture controls.
use super::{CaseResult, Ctx, DownloadBody, Failure, Rpc, ensure, frame, random_pack, want_ok};
use crate::control::{self, Capabilities, PackLocationState, Request, Response};
use crate::wire::client::{Client, Reply, StreamReply, UNARY_PROTO, decode_unary};
use buffa::Message as _;
use mkit_core::hash::{hash, to_hex};
use mkit_transport_connect::generated::{
    DownloadPackLocation, DownloadPackRequest, DownloadPackResponse, GetServerInfoResponse,
};

struct Fixture {
    repository: String,
    pack: Vec<u8>,
}
async fn command(ctx: &Ctx, request: &Request) -> Result<Response, Failure> {
    let response = ctx
        .client()
        .post(
            control::CONTROL_PATH,
            "application/json",
            &[],
            serde_json::to_vec(request).map_err(|error| error.to_string())?,
        )
        .await?;
    ensure!(
        response.status == 200,
        "pack-location fixture command HTTP {}",
        response.status
    );
    serde_json::from_slice(&response.body).map_err(|error| error.to_string().into())
}
async fn fixture_now(ctx: &Ctx) -> Result<i64, Failure> {
    command(ctx, &Request::AdvanceClock { delta_ms: 0 })
        .await?
        .now_ms
        .ok_or_else(|| "clock control omitted current time".into())
}
async fn prepare(ctx: &Ctx) -> Result<Fixture, Failure> {
    let response = ctx.client().get(control::CAPABILITIES_PATH).await?;
    ensure!(
        response.status == 200,
        "pack-location controls unavailable: HTTP {}",
        response.status
    );
    let capabilities: Capabilities =
        serde_json::from_slice(&response.body).map_err(|error| error.to_string())?;
    ensure!(
        capabilities.version == control::VERSION,
        "unknown fixture control version"
    );
    for required in ["pack-locations.fixture", "clock.advance"] {
        ensure!(
            capabilities
                .controls
                .iter()
                .any(|control| control == required),
            "missing declared fixture capability {required}"
        );
    }
    let fixture = Fixture {
        repository: format!("ed25519-{}/locations", to_hex(&hash(ctx.ns().as_bytes()))),
        pack: random_pack(1024),
    };
    set_state(ctx, &fixture, PackLocationState::Available).await?;
    Ok(fixture)
}
async fn set_state(ctx: &Ctx, fixture: &Fixture, state: PackLocationState) -> CaseResult {
    command(
        ctx,
        &Request::PackLocationFixture {
            repository: fixture.repository.clone(),
            pack: fixture.pack.clone(),
            state,
        },
    )
    .await?;
    Ok(())
}
async fn download(
    ctx: &Ctx,
    fixture: &Fixture,
    accept: bool,
) -> Result<StreamReply<DownloadPackResponse>, Failure> {
    let body = frame(
        &DownloadPackRequest {
            pack_id: Some(hash(&fixture.pack).to_vec()),
            accept_location: accept.then_some(true),
            ..Default::default()
        }
        .encode_to_vec(),
    );
    // Unsigned requests exercise public/private read authorization directly.
    Ok(ctx
        .client()
        .stream(
            Rpc::DownloadPack,
            body,
            &[("x-repository".into(), fixture.repository.clone())],
        )
        .await?)
}
fn location(reply: StreamReply<DownloadPackResponse>) -> Result<DownloadPackLocation, Failure> {
    ensure!(
        reply.error.is_none(),
        "fixture download failed: {:?}",
        reply.error
    );
    ensure!(
        reply.messages.len() == 1,
        "fixture must return exactly one location"
    );
    match reply
        .messages
        .into_iter()
        .next()
        .and_then(|message| message.body)
    {
        Some(DownloadBody::Location(location)) => Ok(location),
        _ => Err("fixture did not issue a location".into()),
    }
}
async fn fetch(ctx: &Ctx, location: &DownloadPackLocation) -> Result<Reply, Failure> {
    let url = url::Url::parse(location.url.as_deref().ok_or("missing location URL")?)
        .map_err(|error| error.to_string())?;
    let loopback = url
        .host_str()
        .and_then(|host| host.parse::<std::net::IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback());
    ensure!(
        url.scheme() == "https"
            || (ctx.profile().has(super::Feature::PackLocationFixtures)
                && loopback
                && url.scheme() == "http"),
        "location must use HTTPS"
    );
    ensure!(
        url.username().is_empty() && url.password().is_none() && url.fragment().is_none(),
        "invalid location authority or fragment"
    );
    let origin =
        url::Url::parse(&url.origin().ascii_serialization()).map_err(|error| error.to_string())?;
    let client = Client::new(&origin)?;
    let path = format!(
        "{}{}",
        url.path(),
        url.query()
            .map_or(String::new(), |query| format!("?{query}"))
    );
    Ok(client.read("GET", &path, &[]).await?)
}
fn verified(fixture: &Fixture, location: &DownloadPackLocation, response: &Reply) -> bool {
    response.status == 200
        && location.total_bytes == Some(response.body.len() as u64)
        && hash(&response.body) == hash(&fixture.pack)
}
async fn info(ctx: &Ctx) -> Result<GetServerInfoResponse, Failure> {
    let response = ctx
        .client()
        .post(
            "/mkit.transport.v1.TransportService/GetServerInfo",
            UNARY_PROTO,
            &[],
            Vec::new(),
        )
        .await?;
    want_ok(decode_unary(&response)?, "GetServerInfo")
}
pub(super) async fn round_trip(ctx: Ctx) -> CaseResult {
    let fixture = prepare(&ctx).await?;
    let info = info(&ctx).await?;
    ensure!(
        info.supports_pack_locations == Some(true),
        "location capability missing"
    );
    let bound = info
        .max_pack_location_lifetime_ms
        .filter(|bound| *bound > 0)
        .ok_or("missing advertised lifetime")?;
    let location = location(download(&ctx, &fixture, true).await?)?;
    let now = fixture_now(&ctx).await?;
    let expiry = location.expires_at_ms.ok_or("missing location expiry")?;
    ensure!(
        expiry > now && expiry - now <= i64::try_from(bound).unwrap_or(i64::MAX),
        "expiry exceeds advertised bound"
    );
    ensure!(
        verified(&fixture, &location, &fetch(&ctx, &location).await?),
        "fixture location failed length/content-address verification"
    );
    Ok(())
}
pub(super) async fn no_opt_in(ctx: Ctx) -> CaseResult {
    let fixture = prepare(&ctx).await?;
    let response = download(&ctx, &fixture, false).await?;
    ensure!(
        Ctx::downloaded_bytes(&hash(&fixture.pack), response)? == fixture.pack,
        "default streaming bytes differ"
    );
    Ok(())
}
pub(super) async fn guard_refusals(ctx: Ctx) -> CaseResult {
    for state in [
        PackLocationState::Denied,
        PackLocationState::Held,
        PackLocationState::Pending,
        PackLocationState::Private,
    ] {
        let fixture = prepare(&ctx).await?;
        location(download(&ctx, &fixture, true).await?)?;
        set_state(&ctx, &fixture, state).await?;
        for accept in [false, true] {
            let response = download(&ctx, &fixture, accept).await?;
            ensure!(
                response.messages.is_empty(),
                "{state:?} content disclosed before refusal"
            );
            ensure!(
                response
                    .error
                    .is_some_and(|error| error.code == "not_found"),
                "{state:?} content was not hidden"
            );
        }
    }
    // A real second repository is readable but has no membership for the first pack.
    let source = prepare(&ctx).await?;
    let other = Fixture {
        repository: format!("{}-other", source.repository),
        pack: random_pack(1024),
    };
    set_state(&ctx, &other, PackLocationState::Available).await?;
    let cross_repo = Fixture {
        repository: other.repository,
        pack: source.pack,
    };
    let response = download(&ctx, &cross_repo, true).await?;
    ensure!(
        response.messages.is_empty()
            && response
                .error
                .is_some_and(|error| error.code == "not_found"),
        "cross-repository location disclosed"
    );
    Ok(())
}
pub(super) async fn denial_after_issue_bound(ctx: Ctx) -> CaseResult {
    let fixture = prepare(&ctx).await?;
    let info = info(&ctx).await?;
    ensure!(
        info.supports_pack_locations == Some(true),
        "location capability missing"
    );
    let bound = info
        .max_pack_location_lifetime_ms
        .ok_or("missing advertised lifetime")?;
    let now = fixture_now(&ctx).await?;
    let location = location(download(&ctx, &fixture, true).await?)?;
    let expiry = location.expires_at_ms.ok_or("missing location expiry")?;
    ensure!(
        expiry > now && expiry - now <= i64::try_from(bound).unwrap_or(i64::MAX),
        "expiry exceeds advertised bound"
    );
    ensure!(
        verified(&fixture, &location, &fetch(&ctx, &location).await?),
        "issued location not usable"
    );
    set_state(&ctx, &fixture, PackLocationState::Denied).await?;
    let denied = download(&ctx, &fixture, true).await?;
    ensure!(
        denied.messages.is_empty() && denied.error.is_some_and(|error| error.code == "not_found"),
        "denial did not stop new locations"
    );
    command(&ctx, &Request::AdvanceClock { delta_ms: bound }).await?;
    let expired = fetch(&ctx, &location).await?;
    ensure!(
        matches!(expired.status, 403 | 404 | 410),
        "issued location still usable at advertised denial bound"
    );
    Ok(())
}
pub(super) async fn corrupt_location_fallback(ctx: Ctx) -> CaseResult {
    let fixture = prepare(&ctx).await?;
    set_state(&ctx, &fixture, PackLocationState::Corrupt).await?;
    let location = location(download(&ctx, &fixture, true).await?)?;
    let corrupt = fetch(&ctx, &location).await?;
    ensure!(
        corrupt.status == 200 && location.total_bytes == Some(corrupt.body.len() as u64),
        "corrupt fixture must have exact advertised length"
    );
    ensure!(
        !verified(&fixture, &location, &corrupt),
        "corruption fixture returned valid content"
    );
    // Exactly one fresh DownloadPack without opt-in after verification fails.
    let fallback = download(&ctx, &fixture, false).await?;
    ensure!(
        Ctx::downloaded_bytes(&hash(&fixture.pack), fallback)? == fixture.pack,
        "streaming fallback bytes differ"
    );
    Ok(())
}
