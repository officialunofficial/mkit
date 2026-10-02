//! Independently owned, immutable preservation pieces in a separate `BlobStore`.
use crate::store::{BlobBody, BlobKey, BlobStore, MAX_BLOB_PIECE_BYTES, PackSink, StoreError};
use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use mkit_core::hash::{Hash, hash};
use serde::{Deserialize, Serialize};

/// The owning action/object/offset header is included in each stored hash.
pub(super) const HEADER: usize = 72;
pub(super) const PIECE_BYTES: usize = MAX_BLOB_PIECE_BYTES - HEADER;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Piece {
    pub storage: Hash,
    pub object: Hash,
    pub offset: u64,
    pub length: u32,
}
fn bad() -> StoreError {
    StoreError::Corrupt("invalid preserved copy".into())
}
/// Verify the immutable header and every returned byte before use or deletion.
pub(super) async fn read<P: BlobStore>(
    store: &P,
    action: &Hash,
    piece: &Piece,
) -> Result<Option<Bytes>, StoreError> {
    let expected = usize::try_from(piece.length)
        .map_err(|_| bad())?
        .checked_add(HEADER)
        .ok_or_else(bad)?;
    if piece.length == 0 || expected > MAX_BLOB_PIECE_BYTES {
        return Err(bad());
    }
    let Some(body) = store.get(&BlobKey::pack(piece.storage), None).await? else {
        return Ok(None);
    };
    let bytes = match body {
        BlobBody::Bytes(bytes) => bytes,
        BlobBody::Stream { len, mut stream } => {
            if len != u64::try_from(expected).map_err(|_| bad())? {
                return Err(bad());
            }
            let mut out = BytesMut::with_capacity(expected);
            while let Some(next) = stream.next().await {
                let next = next?;
                if next.len() > MAX_BLOB_PIECE_BYTES
                    || out
                        .len()
                        .checked_add(next.len())
                        .is_none_or(|n| n > expected)
                {
                    return Err(bad());
                }
                out.extend_from_slice(&next);
            }
            out.freeze()
        }
    };
    if bytes.len() != expected
        || hash(&bytes) != piece.storage
        || bytes[..32] != *action
        || bytes[32..64] != piece.object
        || bytes[64..HEADER] != piece.offset.to_be_bytes()
    {
        return Err(bad());
    }
    Ok(Some(bytes.slice(HEADER..)))
}
/// Deterministic intent recorded before a preservation PUT can become visible.
pub(super) fn plan(
    action: &Hash,
    object: &Hash,
    offset: u64,
    bytes: &[u8],
) -> Result<Piece, StoreError> {
    if bytes.is_empty() || bytes.len() > PIECE_BYTES {
        return Err(bad());
    }
    let mut digest = blake3::Hasher::new();
    for part in [
        action.as_slice(),
        object.as_slice(),
        &offset.to_be_bytes(),
        bytes,
    ] {
        digest.update(part);
    }
    Ok(Piece {
        storage: *digest.finalize().as_bytes(),
        object: *object,
        offset,
        length: u32::try_from(bytes.len()).map_err(|_| bad())?,
    })
}
/// Put one bounded canonical slice, then verify its durable stored copy.
pub(super) async fn write<P: BlobStore>(
    store: &P,
    action: &Hash,
    object: &Hash,
    offset: u64,
    bytes: &[u8],
) -> Result<Piece, StoreError> {
    if bytes.is_empty() || bytes.len() > PIECE_BYTES {
        return Err(bad());
    }
    let mut framed = Vec::with_capacity(HEADER + bytes.len());
    framed.extend_from_slice(action);
    framed.extend_from_slice(object);
    framed.extend_from_slice(&offset.to_be_bytes());
    framed.extend_from_slice(bytes);
    let piece = plan(action, object, offset, bytes)?;
    let mut sink = store
        .begin(
            BlobKey::pack(piece.storage),
            u64::try_from(framed.len()).map_err(|_| bad())?,
        )
        .await?;
    sink.write(Bytes::from(framed)).await?;
    sink.commit().await?;
    if read(store, action, &piece).await?.as_deref() != Some(bytes) {
        return Err(bad());
    }
    Ok(piece)
}

#[cfg(all(test, feature = "memory"))]
#[path = "copy_tests.rs"]
mod tests;
