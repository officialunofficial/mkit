//! Remove objects from a pack without leaving deltas over removed bases.
//!
//! Rewrites are deterministic within a build's feature set. Native writers
//! (`pack-zstd`) may compress entries; decode-only wasm writers emit v1 packs.
//! Both preserve the same objects, but their pack bytes may differ. WP-5.7b
//! pins rewrites to the native path for stable pack identities.

use super::{
    DecodeLimits, DecodedEntry, DeltaBaseSource, ENTRY_FRAME_LEN, HEADER_LEN, PackError,
    PackWriter, decode_entries_with, decompress_zstd_entry,
};
use crate::hash::Hash;
use std::collections::HashSet;

/// A rewritten pack and the entries affected by the exclusions.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Rewritten {
    /// The rewritten pack. Equal to the input bytes when `unchanged`.
    pub bytes: Vec<u8>,
    /// Dropped ids, deduplicated in first-occurrence pack order.
    pub removed: Vec<Hash>,
    /// Ids of delta entries re-emitted as raw, in pack order.
    pub rawified: Vec<Hash>,
    /// True when nothing was removed or rawified.
    pub unchanged: bool,
}

/// Drop every entry named by `excluded`, rawifying surviving deltas whose
/// direct base is excluded. A delta over a rawified entry remains a delta.
///
/// All entries, including dropped entries, are validated and decoded using
/// exactly [`decode_entries_with`]'s [`DecodeLimits`] accounting. External
/// bases come only from the caller's repository-scoped `bases`; an excluded
/// id that is neither an entry nor a base causes no lookup. Unchanged packs
/// are returned verbatim, even if this build would encode them differently.
///
/// # Errors
///
/// Invalid input produces the decoder's error, including
/// [`PackError::DeltaBaseMissing`] when a required excluded base cannot be
/// supplied. A changed output exceeding the writer's caps produces the
/// writer's existing error. No partial output is returned.
#[allow(clippy::implicit_hasher)] // The orchestrator fixes this additive API signature.
pub fn rewrite_excluding<B: DeltaBaseSource>(
    pack: &[u8],
    excluded: &HashSet<Hash>,
    bases: &mut B,
    limits: DecodeLimits,
) -> Result<Rewritten, PackError> {
    let mut rewrite = Rewrite::new(pack, excluded);
    decode_entries_with(pack, bases, limits, |entry| rewrite.accept(&entry))?;
    rewrite.finish()
}

struct Rewrite<'a> {
    pack: &'a [u8],
    excluded: &'a HashSet<Hash>,
    pos: usize,
    writer: PackWriter,
    removed: Vec<Hash>,
    removed_seen: HashSet<Hash>,
    rawified: Vec<Hash>,
    writer_error: Option<PackError>,
}

impl<'a> Rewrite<'a> {
    fn new(pack: &'a [u8], excluded: &'a HashSet<Hash>) -> Self {
        Self {
            pack,
            excluded,
            pos: HEADER_LEN,
            writer: PackWriter::new(),
            removed: Vec::new(),
            removed_seen: HashSet::new(),
            rawified: Vec::new(),
            writer_error: None,
        }
    }

    fn accept(&mut self, entry: &DecodedEntry<'_>) -> Result<(), PackError> {
        // The decoder validated all framing before its first sink call. Walk
        // only wire offsets here: a second PackEntries iterator would allocate
        // another decompressed raw payload while the decoder still holds it.
        let start = self.pos;
        let payload_start = start
            .checked_add(ENTRY_FRAME_LEN)
            .ok_or(PackError::UnexpectedEof)?;
        let frame = self
            .pack
            .get(start..payload_start)
            .ok_or(PackError::UnexpectedEof)?;
        let len = u32::from_le_bytes(
            frame[1..]
                .try_into()
                .map_err(|_| PackError::UnexpectedEof)?,
        );
        let payload_end = payload_start
            .checked_add(usize::try_from(len).map_err(|_| PackError::UnexpectedEof)?)
            .ok_or(PackError::UnexpectedEof)?;
        let payload = self
            .pack
            .get(payload_start..payload_end)
            .ok_or(PackError::UnexpectedEof)?;
        self.pos = payload_end;

        if self.excluded.contains(&entry.id) {
            if self.removed_seen.insert(entry.id) {
                self.removed.push(entry.id);
            }
            return Ok(());
        }
        let base = if entry.from_delta {
            Some(
                <Hash>::try_from(payload.get(..32).ok_or(PackError::DeltaEntryTruncated)?)
                    .map_err(|_| PackError::DeltaEntryTruncated)?,
            )
        } else {
            None
        };
        let rawify = base.is_some_and(|id| self.excluded.contains(&id));
        if rawify {
            self.rawified.push(entry.id);
        }
        if self.writer_error.is_some() {
            return Ok(());
        }
        let written = match base {
            Some(base) if !rawify => {
                let stream = &payload[32..];
                if frame[0] == 0x04 {
                    // decode_entries_with drops this entry's owned stream
                    // before calling the sink. Its claim stays reserved, so
                    // this replacement uses the same charged bytes, never a
                    // second resident copy. No other frame is decompressed.
                    let stream = decompress_zstd_entry(stream)?;
                    self.writer.push_delta(&base, &stream)
                } else {
                    self.writer.push_delta(&base, stream)
                }
            }
            _ => self.writer.push_raw(entry.id, entry.bytes).map(|_| ()),
        };
        // Finish validating input even if output exceeds a writer cap: a
        // later decoder error wins, and an unchanged pack needs no rewrite.
        if let Err(error) = written {
            self.writer_error = Some(error);
        }
        Ok(())
    }

    fn finish(self) -> Result<Rewritten, PackError> {
        let unchanged = self.removed.is_empty() && self.rawified.is_empty();
        let bytes = if unchanged {
            // Release speculative output before copying the original pack.
            drop(self.writer);
            self.pack.to_vec()
        } else {
            if let Some(error) = self.writer_error {
                return Err(error);
            }
            self.writer.finish()?
        };
        Ok(Rewritten {
            bytes,
            removed: self.removed,
            rawified: self.rawified,
            unchanged,
        })
    }
}

#[cfg(test)]
mod tests;
