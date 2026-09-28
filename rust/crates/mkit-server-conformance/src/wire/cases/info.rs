//! STC §2.1: unauthenticated, repository-independent deployment discovery.

use mkit_transport_connect::generated::GetServerInfoResponse;

use super::{CaseResult, Ctx, Feature, ensure, want_ok};
use crate::wire::client::{Reply, UNARY_PROTO, decode_unary};
use crate::wire::profile::WireAuth;

const INFO: &str = "/mkit.transport.v1.TransportService/GetServerInfo";

async fn discover(ctx: &Ctx, headers: &[(String, String)]) -> Result<Reply, super::Failure> {
    // Deliberately bypass Ctx::call, which adds the profile's credentials.
    let reply = ctx
        .client()
        .post(INFO, UNARY_PROTO, headers, Vec::new())
        .await?;
    want_ok(
        decode_unary::<GetServerInfoResponse>(&reply)?,
        "GetServerInfo",
    )?;
    Ok(reply)
}

#[allow(clippy::too_many_lines)] // One discovery response is checked against its full advertised contract.
pub(super) async fn shape_and_policy(ctx: Ctx) -> CaseResult {
    let reply = discover(&ctx, &[]).await?;
    let info = want_ok(
        decode_unary::<GetServerInfoResponse>(&reply)?,
        "GetServerInfo",
    )?;
    ensure!(
        info.protocol.as_deref() == Some("mkit.transport.v1"),
        "incorrect protocol"
    );
    ensure!(info.spec_version == Some(2), "incorrect spec_version");
    let part_size = info.part_size.ok_or("missing part_size")?;
    ensure!(
        part_size.is_power_of_two() && part_size >= 8 * 1024 * 1024,
        "invalid part_size: {part_size}"
    );
    let max_parts = info.max_parts.ok_or("missing max_parts")?;
    ensure!(max_parts >= 1, "max_parts is zero");
    let max_pack = info.max_pack_bytes.ok_or("missing max_pack_bytes")?;
    ensure!(
        u128::from(max_pack) <= u128::from(part_size) * u128::from(max_parts),
        "max_pack_bytes is unreachable"
    );
    let page_size = info
        .max_list_refs_page_size
        .ok_or("missing max_list_refs_page_size")?;
    ensure!(
        (1..=10_000).contains(&page_size),
        "invalid page size: {page_size}"
    );
    ensure!(info.index_fanout == Some(4096), "incorrect index_fanout");
    let depth = info
        .max_delta_chain_depth
        .ok_or("missing max_delta_chain_depth")?;
    ensure!(
        info.indexed_mode == Some(true) || depth == 0,
        "max_delta_chain_depth must be 0 outside indexed mode: {depth}"
    );
    ensure!(
        info.atomic_advance == Some(ctx.profile().has(Feature::AtomicAdvance)),
        "atomic_advance disagrees with profile"
    );
    let multi = ctx.profile().has(Feature::MultiRepo);
    ensure!(
        if multi {
            matches!(info.namespace_policy.as_deref(), Some("allowlist" | "any"))
        } else {
            info.namespace_policy.as_deref() == Some("single-repository")
        },
        "namespace_policy disagrees with profile"
    );
    let admission = info.admission.ok_or("missing admission")?;
    ensure!(
        info.begin_upload_threshold_bytes.is_some(),
        "missing begin_upload_threshold_bytes"
    );
    if multi || admission {
        ensure!(
            info.begin_upload_threshold_bytes == Some(0),
            "multi-repo/admission must require BeginUpload"
        );
    }
    ensure!(
        info.receipt_public_key.as_ref().is_some_and(Vec::is_empty),
        "receipt_public_key must be empty"
    );
    ensure!(
        info.receipt_key_id.as_deref() == Some(""),
        "receipt_key_id must be empty"
    );
    let expected = if ctx.profile().has(Feature::Grants) {
        vec!["ed25519", "secp256k1-eip191", "webauthn-p256"]
    } else {
        vec![]
    };
    ensure!(
        info.grant_schemes == expected,
        "grant_schemes disagrees with the grants profile: {:?}",
        info.grant_schemes
    );
    let cache = reply
        .headers
        .get("cache-control")
        .ok_or("missing Cache-Control")?
        .to_str()
        .map_err(|e| e.to_string())?;
    let directives: Vec<_> = cache.split(',').map(str::trim).collect();
    ensure!(
        directives.contains(&"private"),
        "Cache-Control must be private: {cache}"
    );
    let ages: Vec<_> = directives
        .iter()
        .filter_map(|s| s.strip_prefix("max-age="))
        .collect();
    ensure!(
        ages.len() == 1 && ages[0].parse::<u32>().is_ok_and(|n| n <= 60),
        "invalid Cache-Control max-age: {cache}"
    );
    Ok(())
}

pub(super) async fn ignores_repository_header(ctx: Ctx) -> CaseResult {
    let original = discover(&ctx, &[]).await?;
    let nonexistent = format!("ed25519-{}/info-{}", "00".repeat(32), ctx.profile().run_id);
    // The configured (existing) repository must not change the answer
    // either: that would make GetServerInfo an existence oracle.
    let existing = match &ctx.profile().auth {
        WireAuth::AuthV2 { repository, .. } => repository.clone(),
        _ => "default".to_owned(),
    };
    for repository in [
        existing.as_str(),
        nonexistent.as_str(),
        "Uppercase/../invalid",
    ] {
        let reply = discover(&ctx, &[("x-repository".into(), repository.into())]).await?;
        ensure!(
            reply.body == original.body,
            "GetServerInfo varies with X-Repository {repository:?}"
        );
    }
    Ok(())
}
