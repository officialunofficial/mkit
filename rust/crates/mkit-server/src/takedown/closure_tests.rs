#![allow(clippy::unwrap_used)] // Invalid fixture setup must fail immediately.
use super::*;
use crate::indexed::budget::{Budgeted, SliceBudget};
use crate::store::{BlobBody, BlobKey, BlobMeta, ByteRange};
use crate::{Batch, MemoryBlobStore, MemoryKv, NamespaceKey};
use mkit_core::{
    hash::hash,
    object::{Blob, ChunkedBlob, Object},
    serialize::serialize,
};

struct Fixture {
    metadata: MemoryKv,
    preserved: MemoryBlobStore,
    root: Partition,
    action: Hash,
    manifest: Hash,
    info: ObjectInfo,
    canonical: Vec<u8>,
    children: Vec<(Hash, Vec<u8>)>,
}
impl Fixture {
    async fn put(&self, id: &Hash, canonical: &[u8], kind: u8) -> ObjectInfo {
        let mut batch = Batch::new();
        for (index, bytes) in canonical.chunks(copy::PIECE_BYTES).enumerate() {
            let offset = u64::try_from(index * copy::PIECE_BYTES).unwrap();
            let piece = copy::write(&self.preserved, &self.action, id, offset, bytes)
                .await
                .unwrap();
            let tail = [id.as_slice(), &offset.to_be_bytes()].concat();
            batch = batch.put(
                work::key(b"piece", &self.action, &tail),
                intent::encode(&piece).unwrap(),
            );
        }
        let info = ObjectInfo {
            kind,
            size: canonical.len() as u64,
            copied: canonical.len() as u64,
            verified: true,
            ..ObjectInfo::default()
        };
        batch = batch.put(
            work::key(b"object", &self.action, id),
            intent::encode(&info).unwrap(),
        );
        self.metadata.apply(&self.root, batch).await.unwrap();
        info
    }
    async fn advance(&self, checkpoint: Checkpoint) -> Result<Step, StoreError> {
        step(
            &self.metadata,
            &self.preserved,
            &self.root,
            &self.action,
            &self.manifest,
            &self.info,
            checkpoint,
        )
        .await
    }
}
async fn fixture(data: &[&[u8]], ordered: &[usize], fixed: u32) -> Fixture {
    let children: Vec<_> = data
        .iter()
        .map(|bytes| {
            let canonical = serialize(&Object::Blob(Blob {
                data: bytes.to_vec(),
            }))
            .unwrap();
            (hash(&canonical), canonical)
        })
        .collect();
    let manifest = ChunkedBlob {
        total_size: ordered.iter().map(|index| data[*index].len() as u64).sum(),
        chunk_size: fixed,
        chunks: ordered.iter().map(|index| children[*index].0).collect(),
    };
    let id = mkit_core::merkle::compute_chunked_id(&manifest);
    let canonical = serialize(&Object::ChunkedBlob(manifest)).unwrap();
    let mut f = Fixture {
        metadata: MemoryKv::default(),
        preserved: MemoryBlobStore::default(),
        root: Partition::Namespace(NamespaceKey::deployment_default()),
        action: [9; 32],
        manifest: id,
        info: ObjectInfo::default(),
        canonical,
        children,
    };
    f.info = f.put(&f.manifest, &f.canonical, 5).await;
    for (id, bytes) in &f.children {
        f.put(id, bytes, 1).await;
    }
    f
}

#[tokio::test]
async fn odd_ordered_duplicates_cross_checkpoint_and_match_core_bmt() {
    let order: Vec<_> = (0..129).map(|index| index % 2).collect();
    let f = fixture(&[b"A", b"B"], &order, 1).await;
    let mut checkpoint = Checkpoint::default();
    for (expected, calls) in [(64, 196), (128, 196), (129, 7)] {
        let budget = SliceBudget::new(700);
        let result = step(
            &Budgeted::new(&f.metadata, &budget),
            &Budgeted::new(&f.preserved, &budget),
            &f.root,
            &f.action,
            &f.manifest,
            &f.info,
            checkpoint,
        )
        .await
        .unwrap();
        assert_eq!(result.checkpoint.next, expected);
        assert_eq!(result.checkpoint.bytes, u64::from(expected));
        assert_eq!(result.complete, expected == 129);
        assert_eq!(budget.used(), calls);
        checkpoint = intent::decode(&intent::encode(&result.checkpoint).unwrap()).unwrap();
    }
    assert!(f.advance(checkpoint).await.unwrap().complete);
}

#[tokio::test]
async fn fixed_geometry_total_and_root_mismatches_fail_closed() {
    let f = fixture(&[b"AA", b"B"], &[0, 1], 2).await;
    assert!(f.advance(Checkpoint::default()).await.unwrap().complete);
    let mut invalid = f.canonical.clone();
    invalid[14..18].copy_from_slice(&3u32.to_le_bytes());
    f.put(&f.manifest, &invalid, 5).await;
    assert!(f.advance(Checkpoint::default()).await.is_err());
    invalid = f.canonical.clone();
    invalid[6..14].copy_from_slice(&4u64.to_le_bytes());
    f.put(&f.manifest, &invalid, 5).await;
    assert!(f.advance(Checkpoint::default()).await.is_err());
    let f = fixture(&[b"A", b"B"], &[0, 1, 0], 0).await;
    invalid = f.canonical.clone();
    invalid[22..54].copy_from_slice(&f.children[1].0);
    invalid[54..86].copy_from_slice(&f.children[0].0);
    f.put(&f.manifest, &invalid, 5).await;
    assert!(f.advance(Checkpoint::default()).await.is_err());
}

#[tokio::test]
async fn child_kind_length_missing_copy_and_nonverified_metadata_fail_closed() {
    let f = fixture(&[b"AA"], &[0], 0).await;
    let (child, canonical) = &f.children[0];
    f.put(child, canonical, 2).await;
    assert!(f.advance(Checkpoint::default()).await.is_err());
    let mut wrong_length = canonical.clone();
    wrong_length[6..10].copy_from_slice(&3u32.to_le_bytes());
    f.put(child, &wrong_length, 1).await;
    assert!(f.advance(Checkpoint::default()).await.is_err());
    let mut info = f.put(child, canonical, 1).await;
    info.verified = false;
    f.metadata
        .apply(
            &f.root,
            Batch::new().put(
                work::key(b"object", &f.action, child),
                intent::encode(&info).unwrap(),
            ),
        )
        .await
        .unwrap();
    assert!(f.advance(Checkpoint::default()).await.is_err());
    f.put(child, canonical, 1).await;
    let piece = copy::plan(&f.action, child, 0, canonical).unwrap();
    f.preserved
        .delete(&crate::BlobKey::pack(piece.storage))
        .await
        .unwrap();
    assert!(f.advance(Checkpoint::default()).await.is_err());
}

#[tokio::test]
async fn preserved_ranges_cross_piece_boundary_without_serving_source() {
    let f = fixture(&[], &[], 0).await;
    let data = vec![b'Z'; copy::PIECE_BYTES + 100];
    let object = hash(&data);
    f.put(&object, &data, 1).await;
    let budget = SliceBudget::new(10);
    let reader = Reader {
        metadata: &Budgeted::new(&f.metadata, &budget),
        preserved: &Budgeted::new(&f.preserved, &budget),
        root: &f.root,
        action: &f.action,
    };
    let bytes = reader
        .read(
            &object,
            data.len() as u64,
            copy::PIECE_BYTES as u64 - 10,
            32,
        )
        .await
        .unwrap();
    assert_eq!(&bytes[..], &[b'Z'; 32]);
    assert_eq!(budget.used(), 4);
    assert!(f.advance(Checkpoint::default()).await.unwrap().complete);
}

struct Tampered<'a>(&'a MemoryBlobStore);
impl BlobStore for Tampered<'_> {
    type Sink = <MemoryBlobStore as BlobStore>::Sink;
    async fn begin(&self, key: BlobKey, len: u64) -> Result<Self::Sink, StoreError> {
        self.0.begin(key, len).await
    }
    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobBody>, StoreError> {
        let result = self.0.get(key, range).await?;
        Ok(result.map(|body| match body {
            BlobBody::Bytes(bytes) => {
                let mut bytes = bytes.to_vec();
                let last = bytes.len() - 1;
                bytes[last] ^= 1;
                BlobBody::Bytes(Bytes::from(bytes))
            }
            BlobBody::Stream { .. } => panic!("bounded memory fixture must return bytes"),
        }))
    }
    async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
        self.0.head(key).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.0.probe().await
    }
    async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
        self.0.delete(key).await
    }
}
#[tokio::test]
async fn physically_corrupted_preserved_data_cannot_complete_closure() {
    let f = fixture(&[b"A"], &[0, 0, 0], 1).await;
    assert!(
        step(
            &f.metadata,
            &Tampered(&f.preserved),
            &f.root,
            &f.action,
            &f.manifest,
            &f.info,
            Checkpoint::default()
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn another_equal_length_chunk_piece_cannot_satisfy_the_named_child() {
    let f = fixture(&[b"A", b"B"], &[0], 0).await;
    let (other, bytes) = &f.children[1];
    let piece = copy::plan(&f.action, other, 0, bytes).unwrap();
    let child = &f.children[0].0;
    let tail = [child.as_slice(), &0u64.to_be_bytes()].concat();
    f.metadata
        .apply(
            &f.root,
            Batch::new().put(
                work::key(b"piece", &f.action, &tail),
                intent::encode(&piece).unwrap(),
            ),
        )
        .await
        .unwrap();
    assert!(f.advance(Checkpoint::default()).await.is_err());
}

#[test]
fn frontier_matches_core_for_every_small_odd_and_even_count() {
    for count in 0..300 {
        let chunks: Vec<_> = (0..count)
            .map(|index| [u8::try_from(index % 3).unwrap(); 32])
            .collect();
        let cb = ChunkedBlob {
            total_size: 99,
            chunk_size: 0,
            chunks,
        };
        let mut checkpoint = Checkpoint::default();
        let mut meta = cb.total_size.to_le_bytes().to_vec();
        meta.extend_from_slice(&cb.chunk_size.to_le_bytes());
        checkpoint.add(0, &domain_digest(b"mkit-cblob-meta-v1", &meta));
        for (index, chunk) in cb.chunks.iter().enumerate() {
            checkpoint.add(u32::try_from(index + 1).unwrap(), chunk);
        }
        assert_eq!(
            checkpoint.root(count + 1).unwrap(),
            mkit_core::merkle::compute_chunked_id(&cb)
        );
    }
}
