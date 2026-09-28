//! Content-addressed proof that a ticket holder uploaded a complete pack.

use bytes::Bytes;
use mkit_core::hash::{Hash, hash};

use crate::store::{BlobKey, BlobStore, PackSink, StoreError};

/// Versioned marker content domain, separate from packs.
pub(crate) const UPLOAD_MARKER_DOMAIN: &[u8] = b"mkit-upload-marker:v1\0";

/// Marker content: DOMAIN || ticket_id(32) || pack_id(32). Its blob key is BLAKE3(content).
pub(crate) fn upload_marker(ticket_id: &[u8; 32], pack_id: &Hash) -> (BlobKey, Vec<u8>) {
    let mut bytes = Vec::with_capacity(UPLOAD_MARKER_DOMAIN.len() + 64);
    bytes.extend_from_slice(UPLOAD_MARKER_DOMAIN);
    bytes.extend_from_slice(ticket_id);
    bytes.extend_from_slice(pack_id);
    (BlobKey::upload_marker(hash(&bytes)), bytes)
}

/// Persist the marker through the ordinary content-addressed put-if-absent path.
pub(crate) async fn write_upload_marker<B: BlobStore>(
    blobs: &B,
    ticket_id: &[u8; 32],
    pack_id: &Hash,
) -> Result<(), StoreError> {
    let (key, bytes) = upload_marker(ticket_id, pack_id);
    let mut sink = blobs.begin(key, bytes.len() as u64).await?;
    sink.write(Bytes::from(bytes)).await?;
    sink.commit().await?;
    Ok(())
}
