use super::{CaseResult, Ctx, ensure};
use crate::wire::client::Rpc;

pub(super) async fn preflight_payment_headers(ctx: Ctx) -> CaseResult {
    let before = super::admission::calls(&ctx).await?;
    let reply = ctx
        .client()
        .options(
            Rpc::UpdateRef.procedure(),
            &[
                ("Origin".into(), "https://browser.test".into()),
                ("Access-Control-Request-Method".into(), "POST".into()),
                (
                    "Access-Control-Request-Headers".into(),
                    "payment-authorization, payment-signature".into(),
                ),
            ],
        )
        .await?;
    ensure!((200..300).contains(&reply.status), "preflight failed");
    let allowed = reply
        .headers
        .get("access-control-allow-headers")
        .and_then(|v| v.to_str().ok())
        .ok_or("missing CORS allow headers")?;
    for name in ["payment-authorization", "payment-signature"] {
        ensure!(
            allowed
                .split(',')
                .any(|v| v.trim().eq_ignore_ascii_case(name)),
            "CORS payment header missing"
        );
    }
    ensure!(
        super::admission::calls(&ctx).await? == before,
        "preflight reached Admit"
    );
    Ok(())
}
pub(super) async fn expose_admission_headers(ctx: Ctx) -> CaseResult {
    let reply = ctx.client().get("/healthz").await?;
    let exposed = reply
        .headers
        .get("access-control-expose-headers")
        .and_then(|v| v.to_str().ok())
        .ok_or("missing exposed headers")?;
    for name in mkit_server::pipeline::ADMISSION_EXPOSE_HEADERS {
        ensure!(
            exposed
                .split(',')
                .any(|v| v.trim().eq_ignore_ascii_case(name)),
            "admission header not exposed"
        );
    }
    Ok(())
}
