//! `UploadPack` framing (SPEC-TRANSPORT-CONNECT §6.1): every rejection is
//! decided before `UploadPackResponse`, and never creates or overwrites
//! the destination pack.

use mkit_core::hash::hash;
use mkit_transport_connect::generated::UploadPackRequest;

use super::{CaseResult, Ctx, chunk_msg, ensure, header_msg, random_pack, upload_msgs};

const INVALID: &str = "invalid_argument";

/// Fail unless `id` is absent: `PackExists` false and `DownloadPack`
/// `not_found`.
async fn absent(ctx: &Ctx, id: &[u8]) -> CaseResult {
    ctx.expect_exists(id, false).await?;
    let reply = ctx.download(id).await?;
    let code = reply.error.map(|e| e.code);
    ensure!(
        reply.messages.is_empty() && code.as_deref() == Some("not_found"),
        "DownloadPack of a rejected pack: {code:?}"
    );
    Ok(())
}

pub(super) async fn roundtrip_multi_chunk(ctx: Ctx) -> CaseResult {
    let pack = random_pack(3000);
    let id = hash(&pack);
    ensure!(
        upload_msgs(&pack, 3).len() == 4,
        "suite bug: expected 3 chunks"
    );
    ctx.put_pack(&pack).await?;
    let got = ctx.fetch(&id).await?;
    ensure!(
        got == pack,
        "downloaded bytes differ from the uploaded ones"
    );
    Ok(())
}

pub(super) async fn empty_pack(ctx: Ctx) -> CaseResult {
    // One header, then one `last` chunk with empty data (§6.1).
    ctx.put_pack(&[]).await?;
    let got = ctx.fetch(&hash(&[])).await?;
    ensure!(
        got.is_empty(),
        "the empty pack downloaded as {} bytes",
        got.len()
    );
    Ok(())
}

pub(super) async fn first_not_header(ctx: Ctx) -> CaseResult {
    let pack = random_pack(16);
    let id = hash(&pack);
    let commit = (&id[..], 16);
    ctx.upload_rejected(&[chunk_msg(&id, 0, &pack, true)], commit, INVALID)
        .await?;
    ctx.upload_rejected(&[], commit, INVALID).await?;
    absent(&ctx, &id).await
}

pub(super) async fn second_header(ctx: Ctx) -> CaseResult {
    let pack = random_pack(16);
    let id = hash(&pack);
    let msgs = [
        header_msg(&id, 16),
        header_msg(&id, 16),
        chunk_msg(&id, 0, &pack, true),
    ];
    ctx.upload_rejected(&msgs, (&id, 16), INVALID).await?;
    let msgs = [
        header_msg(&id, 16),
        chunk_msg(&id, 0, &pack[..8], false),
        header_msg(&id, 16),
    ];
    ctx.upload_rejected(&msgs, (&id, 16), INVALID).await?;
    absent(&ctx, &id).await
}

pub(super) async fn empty_message(ctx: Ctx) -> CaseResult {
    let pack = random_pack(16);
    let id = hash(&pack);
    let msgs = [
        header_msg(&id, 16),
        UploadPackRequest::default(),
        chunk_msg(&id, 0, &pack, true),
    ];
    ctx.upload_rejected(&msgs, (&id, 16), INVALID).await?;
    absent(&ctx, &id).await
}

pub(super) async fn chunk_pack_id_mismatch(ctx: Ctx) -> CaseResult {
    let pack = random_pack(16);
    let id = hash(&pack);
    let msgs = [header_msg(&id, 16), chunk_msg(&[9; 32], 0, &pack, true)];
    ctx.upload_rejected(&msgs, (&id, 16), INVALID).await?;
    absent(&ctx, &id).await
}

pub(super) async fn offset_gap(ctx: Ctx) -> CaseResult {
    let pack = random_pack(16);
    let id = hash(&pack);
    // A gap, then an overlap.
    for (second, data) in [(9u64, &pack[8..15]), (4, &pack[4..16])] {
        let msgs = [
            header_msg(&id, 16),
            chunk_msg(&id, 0, &pack[..8], false),
            chunk_msg(&id, second, data, true),
        ];
        ctx.upload_rejected(&msgs, (&id, 16), INVALID).await?;
    }
    absent(&ctx, &id).await
}

pub(super) async fn overrun(ctx: Ctx) -> CaseResult {
    let pack = random_pack(16);
    let id = hash(&pack[..8]);
    // The header declares 8 bytes; the chunk carries 16.
    ctx.upload_rejected(
        &[header_msg(&id, 8), chunk_msg(&id, 0, &pack, true)],
        (&id, 8),
        INVALID,
    )
    .await?;
    absent(&ctx, &id).await
}

pub(super) async fn no_last(ctx: Ctx) -> CaseResult {
    let pack = random_pack(16);
    let id = hash(&pack);
    let msgs = [header_msg(&id, 16), chunk_msg(&id, 0, &pack, false)];
    ctx.upload_rejected(&msgs, (&id, 16), INVALID).await?;
    ctx.upload_rejected(&[header_msg(&id, 16)], (&id, 16), INVALID)
        .await?;
    absent(&ctx, &id).await
}

pub(super) async fn declared_mismatch(ctx: Ctx) -> CaseResult {
    let pack = random_pack(16);
    let id = hash(&pack);
    // The header declares 20 bytes; `last` arrives after 16.
    let msgs = [header_msg(&id, 20), chunk_msg(&id, 0, &pack, true)];
    ctx.upload_rejected(&msgs, (&id, 20), INVALID).await?;
    absent(&ctx, &id).await
}

pub(super) async fn hash_mismatch_not_stored(ctx: Ctx) -> CaseResult {
    let pack = random_pack(16);
    let other = random_pack(16);
    let id = hash(&pack);
    let msgs = [header_msg(&id, 16), chunk_msg(&id, 0, &other, true)];
    ctx.upload_rejected(&msgs, (&id, 16), INVALID).await?;
    absent(&ctx, &id).await
}

/// A header declaring one byte over the profile's cap is refused before
/// any chunk (§5: `PayloadTooLarge`).
pub(super) async fn oversize(ctx: Ctx) -> CaseResult {
    let id = hash(&random_pack(32));
    let total = ctx.profile().max_pack_bytes.saturating_add(1);
    ctx.upload_rejected(
        &[header_msg(&id, total)],
        (&id, total),
        "resource_exhausted",
    )
    .await?;
    ctx.expect_exists(&id, false).await
}

pub(super) async fn rejected_never_overwrites(ctx: Ctx) -> CaseResult {
    let pack = random_pack(64);
    let id = hash(&pack);
    ctx.put_pack(&pack).await?;
    let bad = random_pack(64);
    let msgs = [header_msg(&id, 64), chunk_msg(&id, 0, &bad, true)];
    ctx.upload_rejected(&msgs, (&id, 64), INVALID).await?;
    let got = ctx.fetch(&id).await?;
    ensure!(got == pack, "a rejected upload changed the stored pack");
    Ok(())
}
