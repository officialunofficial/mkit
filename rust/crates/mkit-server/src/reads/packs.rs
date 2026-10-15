//! Exact pack evidence without index scans or storage-layout imports.
use super::{ReadAccess, classify, corrupt, failure};
use crate::store::{BlobKey, NamespaceStore, codec, keys, publication};
use crate::{RepoId, ServerError};
use mkit_core::hash::Hash;

/// Maximum supplied packs in one exact index query.
pub const MAX_OBJECT_INDEX_PACKS: usize = 1024;
/// Maximum keys per exact index read; each batch charges one store call.
pub const OBJECT_INDEX_BATCH_SIZE: usize = 128;

/// A pack identifier and its caller-validated stored length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackRef {
    pub id: Hash,
    pub len: u64,
}

/// Validated frame location and decode metadata from an exact index row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct FrameLocation {
    pub frame_offset: u64,
    pub frame_length: u64,
    /// Pack entry type: raw, delta, zstd raw, or zstd delta.
    pub wire_type: u8,
    pub decoded_size: u64,
    pub in_pack_delta_depth: u32,
    pub delta_base: Option<Hash>,
}

/// Typed membership clearance, independent of its stored representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VisibilityWitness {
    pub generation: u64,
    pub sequence: u64,
    pub published: bool,
    /// Serving stop, including for writers.
    pub held: bool,
    pub boundary: bool,
}

impl VisibilityWitness {
    pub(super) fn from_witness(w: publication::Witness) -> Self {
        Self {
            generation: w.generation,
            sequence: w.sequence,
            published: w.published,
            held: w.held,
            boundary: w.boundary,
        }
    }
}

impl VisibilityWitness {
    /// Apply the same clearance rule as the internal serving view.
    #[must_use]
    pub fn visible(self, writer: bool, generation: u64) -> bool {
        publication::Witness {
            generation: self.generation,
            sequence: self.sequence,
            published: self.published,
            held: self.held,
            boundary: self.boundary,
        }
        .visible(writer, generation)
    }
}

/// Fresh local membership and published-member observations for one pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PackWitness {
    pub member: Option<VisibilityWitness>,
    pub published: Option<VisibilityWitness>,
}

impl PackWitness {
    /// Both rows must exist and each must be unheld, match `generation`, and
    /// either be published or be queried in a writer view. Sequence and boundary
    /// do not change this rule. This is evidence, not authorization or denial.
    #[must_use]
    pub fn visible(self, writer: bool, generation: u64) -> bool {
        self.member.is_some_and(|w| w.visible(writer, generation))
            && self
                .published
                .is_some_and(|w| w.visible(writer, generation))
    }
}

impl<N: NamespaceStore> ReadAccess<'_, N> {
    /// Read only the requested object's exact rows in the supplied packs.
    /// Present rows retain input order and duplicates; absent rows are omitted.
    /// No membership, publication, denial, or global blob checks run here.
    /// Pack lengths must come from trusted inventory. Every present row's frame
    /// end is checked against its corresponding supplied length.
    /// At most eight sequential 128-key reads run through the caller's store.
    ///
    /// # Errors
    /// `invalid_argument` above [`MAX_OBJECT_INDEX_PACKS`]; `internal` for a
    /// corrupt row or a frame contradicting the supplied length;
    /// `unavailable` for malformed replies or failed reads.
    /// Any error refuses the entire result, including earlier successful batches.
    pub async fn object_index_in_packs(
        &self,
        repo: &RepoId,
        object: &Hash,
        packs: &[PackRef],
    ) -> Result<Vec<(Hash, FrameLocation)>, ServerError> {
        if packs.len() > MAX_OBJECT_INDEX_PACKS {
            return Err(ServerError::invalid_argument("too many packs"));
        }
        let partition = self.shards.object_index(repo, object);
        let mut result = Vec::with_capacity(packs.len());
        for batch in packs.chunks(OBJECT_INDEX_BATCH_SIZE) {
            let keys = batch
                .iter()
                .map(|p| keys::object_index(&repo.name, object, &p.id))
                .collect::<Vec<_>>();
            let rows = self
                .store
                .get_many(&partition, &keys)
                .await
                .map_err(classify)?;
            if rows.len() != batch.len() {
                return Err(failure());
            }
            for (pack, row) in batch.iter().zip(rows) {
                let Some(row) = row else { continue };
                let value = codec::decode_object_index(object, &row).map_err(corrupt)?;
                if value
                    .frame_offset
                    .checked_add(value.frame_length)
                    .is_none_or(|end| end > pack.len)
                {
                    return Err(corrupt("object index frame exceeds pack length"));
                }
                result.push((
                    pack.id,
                    FrameLocation {
                        frame_offset: value.frame_offset,
                        frame_length: value.frame_length,
                        wire_type: value.wire_type,
                        decoded_size: value.decoded_size,
                        in_pack_delta_depth: value.chain_depth,
                        delta_base: value.delta_base,
                    },
                ));
            }
        }
        Ok(result)
    }

    /// Decode both pack witnesses in one fresh, routed, two-key store call.
    /// Neither row substitutes for the other. Both are validated even if one
    /// is absent or invisible. Use [`PackWitness::visible`] for the joint rule.
    /// Serving policy, reachability and live denial remain caller boundaries.
    ///
    /// # Errors
    /// `internal` for either corrupt row; `unavailable` for malformed replies
    /// or failed reads.
    pub async fn pack_witness(
        &self,
        repo: &RepoId,
        pack: &Hash,
    ) -> Result<PackWitness, ServerError> {
        let rows = self
            .store
            .get_many(
                &self.shards.membership(repo, &BlobKey::pack(*pack)),
                &[
                    keys::membership(&repo.name, pack),
                    keys::published_member(&repo.name, pack),
                ],
            )
            .await
            .map_err(classify)?;
        let [member, published]: [Option<crate::Value>; 2] =
            rows.try_into().map_err(|_| failure())?;
        let decode = |row: Option<crate::Value>| {
            row.as_ref()
                .map(publication::Witness::decode)
                .transpose()
                .map(|w| w.map(VisibilityWitness::from_witness))
                .map_err(corrupt)
        };
        Ok(PackWitness {
            member: decode(member)?,
            published: decode(published)?,
        })
    }
}
