use super::*;
use crate::MemoryBlobStore;
#[tokio::test]
async fn equal_canonical_pieces_have_independent_verified_action_ownership() {
    let store = MemoryBlobStore::default();
    let one = write(&store, &[1; 32], &[8; 32], 0, b"canonical piece")
        .await
        .unwrap();
    let two = write(&store, &[2; 32], &[8; 32], 0, b"canonical piece")
        .await
        .unwrap();
    assert_ne!(one.storage, two.storage);
    assert_eq!(
        read(&store, &[1; 32], &one).await.unwrap().unwrap(),
        b"canonical piece"[..]
    );
    assert!(read(&store, &[2; 32], &one).await.is_err());
    store.delete(&BlobKey::pack(one.storage)).await.unwrap();
    assert!(read(&store, &[1; 32], &one).await.unwrap().is_none());
    assert_eq!(
        read(&store, &[2; 32], &two).await.unwrap().unwrap(),
        b"canonical piece"[..]
    );
}
#[tokio::test]
async fn duplicate_copy_validates_stored_bytes_and_exact_header_geometry() {
    let store = MemoryBlobStore::default();
    let piece = write(&store, &[1; 32], &[2; 32], 123, b"bytes")
        .await
        .unwrap();
    let duplicate = write(&store, &[1; 32], &[2; 32], 123, b"bytes")
        .await
        .unwrap();
    assert_eq!(piece.storage, duplicate.storage);
    for modified in [
        Piece {
            offset: 124,
            ..piece.clone()
        },
        Piece {
            length: 4,
            ..piece.clone()
        },
        Piece {
            object: [3; 32],
            ..piece
        },
    ] {
        assert!(read(&store, &[1; 32], &modified).await.is_err());
    }
    assert!(
        write(&store, &[1; 32], &[2; 32], 0, &vec![0; PIECE_BYTES + 1])
            .await
            .is_err()
    );
    assert!(write(&store, &[1; 32], &[2; 32], 0, &[]).await.is_err());
}
