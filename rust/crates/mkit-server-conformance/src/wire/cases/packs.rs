//! `PackExists` (SPEC-TRANSPORT-CONNECT §2, §5).

use mkit_core::hash::hash;

use super::{CaseResult, Ctx, random_pack, want_code};

pub(super) async fn exists_false_then_true(ctx: Ctx) -> CaseResult {
    let pack = random_pack(1000);
    let id = hash(&pack);
    ctx.expect_exists(&id, false).await?;
    ctx.put_pack(&pack).await?;
    ctx.expect_exists(&id, true).await
}

pub(super) async fn pack_id_wrong_length(ctx: Ctx) -> CaseResult {
    for id in [&[7u8; 31][..], &[7; 33], &[]] {
        want_code(
            ctx.exists(id).await?,
            "invalid_argument",
            &format!("PackExists of a {}-byte id", id.len()),
        )?;
        let reply = ctx.download(id).await?;
        super::ensure!(
            reply.messages.is_empty(),
            "DownloadPack sent messages for a malformed id"
        );
        let err = reply
            .error
            .ok_or("DownloadPack of a malformed id succeeded")?;
        super::ensure!(
            err.code == "invalid_argument",
            "DownloadPack of a {}-byte id: {err}",
            id.len()
        );
    }
    Ok(())
}
