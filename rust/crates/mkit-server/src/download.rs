//! `DownloadPack` chunking (SPEC-TRANSPORT-CONNECT §6.2).
//!
//! The canonical copy of the chunk loops in `mkit-transport-connect` 0.4's
//! `pack.rs` (`chunk_download`) and `mkit serve`'s `download_chunks`; `vcs-worker`
//! adopted this plan in WP-M0-17 (planner decision Q17). The old copies are
//! gone: `mkit serve`'s in WP-M0-13, `mkit-transport-connect`'s with its
//! server in WP-M0-15.

/// Largest `PackChunk.data` a server sends: well below the 1 MiB frame limit
/// of the ssh/enc framing, and a manageable Connect message size.
pub const DOWNLOAD_CHUNK_MAX: usize = 800 * 1024;

/// One `PackChunk` of a download: `len` bytes at `offset`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkSpan {
    /// Byte offset of the chunk in the pack.
    pub offset: u64,
    /// Chunk length in bytes.
    pub len: usize,
    /// Whether this is the final chunk (`PackChunk.last`).
    pub last: bool,
}

/// Split a `total`-byte pack into contiguous chunks of at most `max` bytes
/// (a `max` of 0 counts as 1). Only the final span is `last`. An empty pack
/// yields exactly one `{offset: 0, len: 0, last: true}` span, so the client
/// always sees a terminator.
pub fn chunk_plan(total: u64, max: usize) -> impl Iterator<Item = ChunkSpan> {
    let step = u64::try_from(max.max(1)).unwrap_or(u64::MAX);
    let mut offset = 0u64;
    let mut done = false;
    std::iter::from_fn(move || {
        if done {
            return None;
        }
        let len = (total - offset).min(step);
        offset += len;
        done = offset == total;
        Some(ChunkSpan {
            offset: offset - len,
            // `len <= step`, which came from a `usize`.
            len: usize::try_from(len).unwrap_or(usize::MAX),
            last: done,
        })
    })
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn plan(total: u64, max: usize) -> Vec<ChunkSpan> {
        chunk_plan(total, max).collect()
    }

    fn span(offset: u64, len: usize, last: bool) -> ChunkSpan {
        ChunkSpan { offset, len, last }
    }

    #[test]
    fn chunk_plan_empty_is_single_last() {
        assert_eq!(plan(0, DOWNLOAD_CHUNK_MAX), [span(0, 0, true)]);
    }

    #[test]
    fn chunk_plan_exact_multiple() {
        let max = DOWNLOAD_CHUNK_MAX;
        let total = 2 * max as u64;
        assert_eq!(
            plan(total, max),
            [span(0, max, false), span(max as u64, max, true)]
        );
        assert_eq!(plan(4, 4), [span(0, 4, true)]);
    }

    #[test]
    fn chunk_plan_remainder() {
        assert_eq!(
            plan(10, 4),
            [span(0, 4, false), span(4, 4, false), span(8, 2, true)]
        );
        assert_eq!(
            plan(3, 0),
            [span(0, 1, false), span(1, 1, false), span(2, 1, true)]
        );
    }

    proptest! {
        #[test]
        fn chunk_plan_spans_are_contiguous(total in 0u64..100_000, max in 1usize..5_000) {
            let spans = plan(total, max);
            let mut next = 0u64;
            for (i, s) in spans.iter().enumerate() {
                prop_assert_eq!(s.offset, next);
                prop_assert!(s.len <= max);
                prop_assert_eq!(s.last, i + 1 == spans.len());
                if total > 0 {
                    prop_assert!(s.len > 0);
                }
                next += s.len as u64;
            }
            prop_assert_eq!(next, total);
        }
    }
}
