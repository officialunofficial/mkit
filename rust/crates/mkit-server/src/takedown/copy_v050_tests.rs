#![allow(clippy::unwrap_used, clippy::too_many_lines)] // Independent fixed-format cases.
use super::*;
#[test]
fn v050_stored_encodings() {
    let _ = crate::stored_golden::json_fixture!(Piece, "takedown-copy-Piece");
}
#[test]
fn v050_binary_rows() {
    use crate::stored_golden::hex_fixture;
    use futures_executor::block_on;
    let expected = hex_fixture!("preserved-piece");
    let store = crate::MemoryBlobStore::default();
    let piece = block_on(write(&store, &[1; 32], &[2; 32], 3, b"abc")).unwrap();
    let raw = block_on(store.get(&BlobKey::pack(piece.storage), None))
        .unwrap()
        .unwrap();
    let BlobBody::Bytes(raw) = raw else {
        panic!("memory body")
    };
    assert_eq!(raw.as_ref(), expected.as_bytes());
    assert_eq!(
        block_on(read(&store, &[1; 32], &piece))
            .unwrap()
            .unwrap()
            .as_ref(),
        b"abc"
    );
}
