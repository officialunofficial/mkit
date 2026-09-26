//! `DownloadPack` (SPEC-TRANSPORT-CONNECT §6.2): `not_found` before any
//! message, or one header and contiguous chunks ending with `last`.

use mkit_core::hash::hash;

use super::{CaseResult, Ctx, ensure, random_pack};

pub(super) async fn not_found_before_any_message(ctx: Ctx) -> CaseResult {
    let reply = ctx.download(&hash(&random_pack(32))).await?;
    ensure!(
        reply.messages.is_empty(),
        "{} messages before not_found",
        reply.messages.len()
    );
    let err = reply
        .error
        .ok_or("DownloadPack of an absent pack succeeded")?;
    ensure!(
        err.code == "not_found",
        "DownloadPack of an absent pack: {err}"
    );
    Ok(())
}

pub(super) async fn chunks_contiguous_ending_last(ctx: Ctx) -> CaseResult {
    // Large enough to span several chunks on common servers; the checks
    // hold for any chunking.
    let pack = random_pack(900 * 1024);
    ctx.put_pack(&pack).await?;
    let got = ctx.fetch(&hash(&pack)).await?;
    ensure!(
        got == pack,
        "downloaded bytes differ from the uploaded ones"
    );
    Ok(())
}
