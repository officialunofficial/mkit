//! Ordered manifest closure over independently preserved canonical pieces.
use super::{
    copy, intent,
    work::{self, ObjectInfo},
};
use crate::store::{MAX_BLOB_PIECE_BYTES, StoreError};
use crate::{BlobStore, NamespaceStore, Partition};
use bytes::{Bytes, BytesMut};
use mkit_core::{
    hash::{Hash, domain_digest},
    merkle::{ObjectKind, wrap_id},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Checkpoint {
    pub next: u32,
    pub bytes: u64,
    frontier: Vec<Option<Hash>>,
}
pub(super) struct Step {
    pub checkpoint: Checkpoint,
    pub complete: bool,
}
fn bad() -> StoreError {
    StoreError::Corrupt("invalid preserved manifest closure".into())
}
fn digest(left: &[u8], right: &[u8]) -> Hash {
    let mut hash = blake3::Hasher::new();
    hash.update(left).update(right);
    *hash.finalize().as_bytes()
}
impl Checkpoint {
    fn add(&mut self, position: u32, leaf: &Hash) {
        let mut node = digest(&position.to_be_bytes(), leaf);
        let mut level = 0;
        loop {
            if level == self.frontier.len() {
                self.frontier.push(None);
            }
            if let Some(left) = self.frontier[level].take() {
                node = digest(&left, &node);
            } else {
                self.frontier[level] = Some(node);
                break;
            }
            level += 1;
        }
    }
    fn root(&self, count: u32) -> Result<Hash, StoreError> {
        let mut right: Option<Hash> = None;
        let mut height = 0;
        for (level, left) in self.frontier.iter().enumerate() {
            if let Some(left) = left {
                right = Some(if let Some(mut node) = right {
                    while height < level {
                        node = digest(&node, &node);
                        height += 1;
                    }
                    height += 1;
                    digest(left, &node)
                } else {
                    height = level;
                    *left
                });
            }
        }
        Ok(wrap_id(
            ObjectKind::ChunkedBlob,
            &digest(&count.to_be_bytes(), &right.ok_or_else(bad)?),
        ))
    }
}
struct Reader<'a, N, P> {
    metadata: &'a N,
    preserved: &'a P,
    root: &'a Partition,
    action: &'a Hash,
}
impl<N: NamespaceStore, P: BlobStore> Reader<'_, N, P> {
    async fn read(
        &self,
        object: &Hash,
        size: u64,
        offset: u64,
        length: usize,
    ) -> Result<Bytes, StoreError> {
        let end = offset
            .checked_add(u64::try_from(length).map_err(|_| bad())?)
            .ok_or_else(bad)?;
        if length > MAX_BLOB_PIECE_BYTES || end > size {
            return Err(bad());
        }
        let mut out = BytesMut::with_capacity(length);
        let mut at = offset;
        while at < end {
            let start = at / copy::PIECE_BYTES as u64 * copy::PIECE_BYTES as u64;
            let tail = [object.as_slice(), &start.to_be_bytes()].concat();
            let raw = self
                .metadata
                .get(self.root, &work::key(b"piece", self.action, &tail))
                .await?
                .ok_or_else(|| StoreError::unavailable("preserved piece unavailable"))?;
            let piece: copy::Piece = intent::decode(&raw).map_err(|_| bad())?;
            let expected = (size - start).min(copy::PIECE_BYTES as u64);
            if piece.object != *object
                || piece.offset != start
                || u64::from(piece.length) != expected
            {
                return Err(bad());
            }
            let data = copy::read(self.preserved, self.action, &piece)
                .await?
                .ok_or_else(|| StoreError::unavailable("preserved piece unavailable"))?;
            let from = usize::try_from(at - start).map_err(|_| bad())?;
            let take =
                usize::try_from((end - at).min(expected - (at - start))).map_err(|_| bad())?;
            out.extend_from_slice(&data[from..from + take]);
            at += u64::try_from(take).map_err(|_| bad())?;
        }
        Ok(out.freeze())
    }
}
/// Resume at most 64 ordered chunks; commit the result under the workflow CAS.
#[allow(clippy::too_many_arguments)]
pub(super) async fn step<N: NamespaceStore, P: BlobStore>(
    metadata: &N,
    preserved: &P,
    root: &Partition,
    action: &Hash,
    manifest: &Hash,
    info: &ObjectInfo,
    mut checkpoint: Checkpoint,
) -> Result<Step, StoreError> {
    if info.kind != 5 || !info.verified || info.copied != info.size || info.size < 22 {
        return Err(bad());
    }
    let reader = Reader {
        metadata,
        preserved,
        root,
        action,
    };
    let header = reader.read(manifest, info.size, 0, 22).await?;
    if header[..6] != *b"\x05MKT1\x01" {
        return Err(bad());
    }
    let total = u64::from_le_bytes(header[6..14].try_into().map_err(|_| bad())?);
    let fixed = u32::from_le_bytes(header[14..18].try_into().map_err(|_| bad())?);
    let count = u32::from_le_bytes(header[18..22].try_into().map_err(|_| bad())?);
    if count > 1_000_000
        || info.size != 22 + u64::from(count) * 32
        || checkpoint.next > count
        || checkpoint.bytes > total
    {
        return Err(bad());
    }
    if checkpoint.frontier.is_empty() {
        if checkpoint.next != 0 || checkpoint.bytes != 0 {
            return Err(bad());
        }
        checkpoint.add(0, &domain_digest(b"mkit-cblob-meta-v1", &header[6..18]));
    }
    let leaves = checkpoint.next + 1;
    if checkpoint.frontier.len() > 21
        || checkpoint
            .frontier
            .iter()
            .enumerate()
            .any(|(level, node)| node.is_some() != (leaves & (1 << level) != 0))
        || leaves >> checkpoint.frontier.len() != 0
    {
        return Err(bad());
    }
    let stop = count.min(checkpoint.next.saturating_add(64));
    let ids = reader
        .read(
            manifest,
            info.size,
            22 + u64::from(checkpoint.next) * 32,
            usize::try_from(stop - checkpoint.next).map_err(|_| bad())? * 32,
        )
        .await?;
    for bytes in ids.chunks_exact(32) {
        let child: Hash = bytes.try_into().map_err(|_| bad())?;
        let raw = metadata
            .get(root, &work::key(b"object", action, &child))
            .await?
            .ok_or_else(|| StoreError::unavailable("preserved chunk unavailable"))?;
        let child_info: ObjectInfo = intent::decode(&raw).map_err(|_| bad())?;
        if child_info.kind != 1
            || !child_info.verified
            || child_info.copied != child_info.size
            || child_info.size < 10
        {
            return Err(bad());
        }
        let blob = reader.read(&child, child_info.size, 0, 10).await?;
        let size = child_info.size - 10;
        if blob[..6] != *b"\x01MKT1\x01"
            || u64::from(u32::from_le_bytes(
                blob[6..10].try_into().map_err(|_| bad())?,
            )) != size
            || fixed != 0
                && (size > u64::from(fixed)
                    || checkpoint.next + 1 < count && size != u64::from(fixed))
        {
            return Err(bad());
        }
        checkpoint.bytes = checkpoint
            .bytes
            .checked_add(size)
            .filter(|n| *n <= total)
            .ok_or_else(bad)?;
        checkpoint.add(checkpoint.next + 1, &child);
        checkpoint.next += 1;
    }
    let complete = checkpoint.next == count;
    if complete && (checkpoint.bytes != total || checkpoint.root(count + 1)? != *manifest) {
        return Err(bad());
    }
    Ok(Step {
        checkpoint,
        complete,
    })
}

#[cfg(all(test, feature = "memory"))]
#[path = "closure_tests.rs"]
mod tests;
