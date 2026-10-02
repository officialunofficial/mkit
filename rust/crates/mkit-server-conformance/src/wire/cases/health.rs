//! `grpc.health.v1.Health/Check`: unauthenticated in every auth mode,
//! `SERVING` for the server and the transport service, `not_found` for any
//! other service. Sent as Connect JSON, so no health proto is needed.

use super::{CaseResult, Ctx, ensure};
use crate::wire::client::{UNARY_JSON, decode_unary};

const CHECK: &str = "/grpc.health.v1.Health/Check";

/// `Check(service)`: the status name, or the Connect error code.
async fn check(ctx: &Ctx, service: &str) -> Result<Result<String, String>, super::Failure> {
    let body = serde_json::to_vec(&serde_json::json!({ "service": service }))
        .map_err(|e| format!("suite bug: {e}"))?;
    let reply = ctx.client().post(CHECK, UNARY_JSON, &[], body).await?;
    if reply.status != 200 {
        // Any `Message` type decodes the error path.
        let err = decode_unary::<mkit_transport_connect::generated::UpdateRefResponse>(&reply)?
            .err()
            .ok_or("suite bug: non-200 decoded as ok")?;
        return Ok(Err(err.code));
    }
    let json: serde_json::Value = serde_json::from_slice(&reply.body)
        .map_err(|e| format!("Check: a 200 response that is not JSON: {e}"))?;
    // proto3 JSON omits a zero enum: absent is `UNKNOWN`.
    let status = json
        .get("status")
        .and_then(|s| s.as_str())
        .unwrap_or("UNKNOWN");
    Ok(Ok(status.to_owned()))
}

pub(super) async fn serving(ctx: Ctx) -> CaseResult {
    for service in ["", "mkit.transport.v1.TransportService"] {
        let got = check(&ctx, service).await?;
        ensure!(
            got.as_deref() == Ok("SERVING"),
            "Check({service:?}): {got:?}"
        );
    }
    Ok(())
}

pub(super) async fn unknown_service_not_found(ctx: Ctx) -> CaseResult {
    let got = check(&ctx, "mkit.conformance.NoSuchService").await?;
    ensure!(
        got == Err("not_found".to_owned()),
        "Check(unknown service): {got:?}"
    );
    Ok(())
}
