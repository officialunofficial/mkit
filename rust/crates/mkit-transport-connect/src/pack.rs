//! `UploadPack` (client-streaming) / `DownloadPack` (server-streaming)
//! wire logic, per SPEC-TRANSPORT-CONNECT §6.
//!
//! Both directions buffer the full pack in memory before touching
//! storage or the wire — the same approach `mkit-cli`'s SSH `serve_loop`
//! and `mkit-transport-file`/`-http`/`-s3` already take (packs are
//! bounded by [`PACK_BODY_LIMIT`]) — so this file's only job is
//! validating the streamed envelope and slicing/reassembling bytes;
//! [`crate::service`] owns the actual [`Transport`] call.
//!
//! [`Transport`]: mkit_core::protocol::Transport

use connectrpc::{ConnectError, InboundStream};
use futures::StreamExt;
use mkit_core::hash::Hash;
use mkit_core::protocol::PACK_BODY_LIMIT_USIZE;

use crate::hashutil::hash_from_slice;
use crate::proto::mkit::transport::v1::__buffa::oneof::download_pack_response::Body as DownloadBody;
use crate::proto::mkit::transport::v1::__buffa::oneof::upload_pack_request::Body as UploadBody;
use crate::proto::mkit::transport::v1::{
    DownloadPackHeader, DownloadPackResponse, PackChunk, UploadPackRequest,
};

/// Pack chunk size cap during downloads — keeps each `PackChunk` message
/// a manageable size regardless of the server's `max_message_size`
/// policy. Mirrors `mkit-cli`'s SSH-server `PACK_CHUNK_DATA_MAX`
/// (`rust/crates/mkit-cli/src/commands/serve/mod.rs`).
const DOWNLOAD_CHUNK_SIZE: usize = 800 * 1024;

/// Drain an `UploadPack` client-streaming request into `(pack_id,
/// pack_bytes)`, enforcing every check SPEC-TRANSPORT-CONNECT §6.1
/// requires — the same set SPEC-TRANSPORT §4.2 already requires of the
/// SSH server's `UploadPack` handling:
///
/// - the first message MUST be `header`;
/// - every following message MUST be `chunk`, with `chunk.pack_id ==
///   header.pack_id` and `chunk.offset` equal to the running received
///   byte count (no gaps);
/// - the stream MUST end with a `chunk.last = true` message;
/// - the received byte count MUST equal `header.total_bytes`; and
/// - `BLAKE3(received bytes)` MUST equal `header.pack_id`.
///
/// No bytes are handed back until every check passes, so a caller that
/// only stores what this function returns can never persist a partial or
/// mismatched upload — satisfying "a rejected stream never creates or
/// overwrites the destination pack" without [`crate::pack`] needing to
/// know anything about storage.
pub(crate) async fn drain_upload(
    mut requests: InboundStream<UploadPackRequest>,
) -> Result<(Hash, Vec<u8>), ConnectError> {
    let first = requests
        .next()
        .await
        .ok_or_else(|| ConnectError::invalid_argument("UploadPack: empty request stream"))??;
    let (header_pack_id, total_bytes) = match first.to_owned_message().body {
        Some(UploadBody::Header(h)) => (
            h.pack_id.unwrap_or_default(),
            h.total_bytes.unwrap_or_default(),
        ),
        _ => {
            return Err(ConnectError::invalid_argument(
                "UploadPack: first message MUST be `header`",
            ));
        }
    };
    let pack_id = hash_from_slice(&header_pack_id)?;
    let total_bytes_usize = usize::try_from(total_bytes).map_err(|_| {
        ConnectError::resource_exhausted(format!(
            "UploadPack: total_bytes {total_bytes} overflows usize"
        ))
    })?;
    if total_bytes_usize > PACK_BODY_LIMIT_USIZE {
        return Err(ConnectError::resource_exhausted(format!(
            "UploadPack: total_bytes {total_bytes} exceeds the {PACK_BODY_LIMIT_USIZE}-byte cap"
        )));
    }

    let mut buf: Vec<u8> = Vec::new();
    let mut saw_last = false;
    while let Some(item) = requests.next().await {
        let chunk = match item?.to_owned_message().body {
            Some(UploadBody::Chunk(c)) => *c,
            Some(UploadBody::Header(_)) => {
                return Err(ConnectError::invalid_argument(
                    "UploadPack: saw a second `header` message",
                ));
            }
            None => {
                return Err(ConnectError::invalid_argument(
                    "UploadPack: message with neither `header` nor `chunk` set",
                ));
            }
        };
        if chunk.pack_id.as_deref().unwrap_or_default() != header_pack_id.as_slice() {
            return Err(ConnectError::invalid_argument(
                "UploadPack: chunk.pack_id does not match header.pack_id",
            ));
        }
        let offset = chunk.offset.unwrap_or_default();
        if offset != buf.len() as u64 {
            return Err(ConnectError::invalid_argument(format!(
                "UploadPack: chunk.offset {offset} does not match the expected offset {}",
                buf.len()
            )));
        }
        let data = chunk.data.unwrap_or_default();
        if buf.len() + data.len() > total_bytes_usize {
            return Err(ConnectError::invalid_argument(
                "UploadPack: received bytes exceed header.total_bytes",
            ));
        }
        buf.extend_from_slice(&data);
        if chunk.last.unwrap_or(false) {
            saw_last = true;
            break;
        }
    }
    if !saw_last {
        return Err(ConnectError::invalid_argument(
            "UploadPack: stream ended without a `chunk.last = true` message",
        ));
    }
    if buf.len() != total_bytes_usize {
        return Err(ConnectError::invalid_argument(format!(
            "UploadPack: received {} bytes, header declared {total_bytes}",
            buf.len()
        )));
    }
    let actual = mkit_core::hash::hash(&buf);
    if actual != pack_id {
        return Err(ConnectError::invalid_argument(
            "UploadPack: BLAKE3(received bytes) does not equal header.pack_id",
        ));
    }
    Ok((pack_id, buf))
}

/// Split `bytes` into the `DownloadPack` header-then-chunks sequence
/// SPEC-TRANSPORT-CONNECT §6.2 specifies: one `header` message, then
/// `chunk` messages ending with `chunk.last = true`. An empty pack still
/// yields one `last = true` chunk with empty `data`, matching the
/// SSH/enc wire's convention.
#[allow(clippy::cast_possible_truncation)] // pack sizes fit u64 well below usize::MAX on any real target
pub(crate) fn chunk_download(pack_id: Hash, bytes: &[u8]) -> Vec<DownloadPackResponse> {
    let total_bytes = bytes.len() as u64;
    let mut out = Vec::with_capacity(2 + bytes.len() / DOWNLOAD_CHUNK_SIZE);
    out.push(DownloadPackResponse {
        body: Some(DownloadBody::Header(Box::new(
            DownloadPackHeader::default().with_total_bytes(total_bytes),
        ))),
        ..Default::default()
    });
    if bytes.is_empty() {
        out.push(DownloadPackResponse {
            body: Some(DownloadBody::Chunk(Box::new(
                PackChunk::default()
                    .with_pack_id(pack_id.to_vec())
                    .with_offset(0)
                    .with_data(Vec::new())
                    .with_last(true),
            ))),
            ..Default::default()
        });
        return out;
    }
    let mut offset = 0usize;
    while offset < bytes.len() {
        let end = (offset + DOWNLOAD_CHUNK_SIZE).min(bytes.len());
        let last = end == bytes.len();
        out.push(DownloadPackResponse {
            body: Some(DownloadBody::Chunk(Box::new(
                PackChunk::default()
                    .with_pack_id(pack_id.to_vec())
                    .with_offset(offset as u64)
                    .with_data(bytes[offset..end].to_vec())
                    .with_last(last),
            ))),
            ..Default::default()
        });
        offset = end;
    }
    out
}
