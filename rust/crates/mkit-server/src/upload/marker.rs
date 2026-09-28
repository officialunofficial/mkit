//! Content-addressed proof that a ticket holder uploaded a verified pack.

use bytes::Bytes;
use mkit_core::hash::Hash;

use crate::store::{BlobKey, BlobStore, PackSink, StoreError};

pub(crate) const UPLOAD_MARKER_DOMAIN: &[u8] = b"mkit-upload-marker:v1\0";

/// Marker content: `DOMAIN || ticket_id(32) || pack_id(32)`.
/// Its blob key is `BLAKE3(content)`.
pub(crate) fn upload_marker(ticket_id: &[u8; 32], pack_id: &Hash) -> (BlobKey, Vec<u8>) {
    let mut content = Vec::with_capacity(UPLOAD_MARKER_DOMAIN.len() + 64);
    content.extend_from_slice(UPLOAD_MARKER_DOMAIN);
    content.extend_from_slice(ticket_id);
    content.extend_from_slice(pack_id);
    let key = BlobKey::upload_marker(*blake3::hash(&content).as_bytes());
    (key, content)
}

/// Write a verified marker through the blob store's put-if-absent path.
pub(crate) async fn write_upload_marker<B: BlobStore>(
    blobs: &B,
    ticket_id: &[u8; 32],
    pack_id: &Hash,
) -> Result<(), StoreError> {
    let (key, content) = upload_marker(ticket_id, pack_id);
    let mut sink = blobs.begin(key, content.len() as u64).await?;
    sink.write(Bytes::from(content)).await?;
    sink.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_core::hash::{hash, to_hex, to_hex_bytes};
    use std::fs;
    use std::path::Path;

    #[test]
    fn golden_upload_marker_v1() {
        let ticket = [0x11; 32];
        let pack = [0x33; 32];
        let (key, content) = upload_marker(&ticket, &pack);
        assert_eq!(key.namespace(), crate::store::BlobNamespace::UploadMarker);
        assert_eq!(&content[..UPLOAD_MARKER_DOMAIN.len()], UPLOAD_MARKER_DOMAIN);
        let expected = format!(
            "{{\n  \"ticket_id\": \"{}\",\n  \"pack_id\": \"{}\",\n  \"content_hex\": \"{}\",\n  \"key\": \"upload-markers/v1/{}\"\n}}\n",
            to_hex(&ticket),
            to_hex(&pack),
            to_hex_bytes(&content),
            key.to_hex()
        );
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/uploads");
        let name = "upload-marker-v1.json";
        if std::env::var("UPDATE_GOLDEN").as_deref() == Ok("1") {
            fs::write(dir.join(name), &expected).unwrap();
            let manifest = fs::read_to_string(dir.join("MANIFEST.txt")).unwrap();
            let mut lines: Vec<_> = manifest
                .lines()
                .filter(|line| !line.starts_with(&format!("{name} ")))
                .map(str::to_owned)
                .collect();
            lines.push(format!("{name} {}", to_hex(&hash(expected.as_bytes()))));
            fs::write(dir.join("MANIFEST.txt"), lines.join("\n") + "\n").unwrap();
        }
        assert_eq!(fs::read(dir.join(name)).unwrap(), expected.as_bytes());
        let manifest = fs::read_to_string(dir.join("MANIFEST.txt")).unwrap();
        assert!(
            manifest
                .lines()
                .any(|line| line == format!("{name} {}", to_hex(&hash(expected.as_bytes()))))
        );
    }
}
