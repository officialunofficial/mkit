//! Rayon-backed `read_chunks` for
//! `mkit_core::ops::restore::restore_tree_to_worktree_with` — the
//! read-side counterpart of `commands::add`'s ingest-side chunk-hashing
//! fan-out (`hash_pending`/`chunk_fanout_threshold`).
//!
//! Materialising a `ChunkedBlob` (checkout/clone/reset/restore of a file
//! above `worktree::CHUNK_THRESHOLD`) used to read every chunk
//! sequentially: one `open` + BLAKE3-verify + decode per chunk, entirely
//! on the calling thread, even though each chunk's read is independent
//! of every other chunk in the same file — the same shape `add`'s
//! chunk-hashing fan-out already exploits on the write side. This module
//! fans a restore batch out across rayon once it is large enough to
//! amortize dispatch cost, using the same "sequential below a threshold,
//! `par_iter` at or above it" shape as [`crate::fanout`].

use mkit_core::hash::Hash;
use mkit_core::object::Object;
use mkit_core::ops::restore::{RestoreError, RestoreResult};
use mkit_core::store::ObjectStore;

/// Chunks-per-thread budget below which [`read_chunks_fanout`] reads a
/// restore batch sequentially instead of fanning it out across rayon —
/// same crossover shape as `commands::add`'s
/// `CHUNK_FANOUT_CHUNKS_PER_THREAD`, sized separately because a restore
/// chunk's cost (open + BLAKE3-verify + decode, no write-side hashing)
/// differs from an ingest chunk's (hash + store).
///
/// Measured with `cargo bench -p mkit-benches --bench restore_chunk_fanout`
/// on a 4-core host (`batch/N_chunks`, sequential vs rayon): 8 chunks is
/// a wash (0.164 ms vs 0.170 ms), 16 chunks already wins clearly (0.343
/// ms vs 0.265 ms, ~23%), and the win widens through a full 64-chunk
/// batch (1.441 ms vs 0.638 ms, ~56%). 4 chunks/thread puts the
/// crossover at 16 chunks on a 4-core pool — past the 8-chunk wash, at
/// the first batch size the data shows a clean win, mirroring
/// `commands::add`'s own `CHUNK_FANOUT_CHUNKS_PER_THREAD` reasoning.
/// End-to-end (`file/N_mib`, a real chunked-blob restore, sequential
/// `restore_tree_to_worktree` vs fully rayon-fanned
/// `restore_tree_to_worktree_with`, same host): 8 MiB 5.893 ms → 4.745
/// ms, 32 MiB 26.458 ms → 21.042 ms, 128 MiB 115.293 ms → 83.199 ms —
/// roughly 1.2-1.4x, smaller than the ingest-side ratio because a
/// restored chunk's cost is read + BLAKE3-verify + decode + a
/// sequential `write_all` into one shared tmp file, so the fan-out only
/// parallelizes the read/verify/decode share of each chunk's work, not
/// the write.
const RESTORE_FANOUT_CHUNKS_PER_THREAD: usize = 4;

fn restore_fanout_threshold() -> usize {
    crate::fanout::threshold(RESTORE_FANOUT_CHUNKS_PER_THREAD)
}

/// `read_chunks` callback for `restore_tree_to_worktree_with`: reads
/// `hashes` sequentially below [`restore_fanout_threshold`], via rayon
/// at or above it.
pub(crate) fn read_chunks_fanout(
    store: &ObjectStore,
    hashes: &[Hash],
) -> RestoreResult<Vec<Vec<u8>>> {
    crate::fanout::try_map_seq_or_par(hashes, restore_fanout_threshold(), |h| {
        match store.read_object(h)? {
            Object::Blob(b) => Ok(b.data),
            _ => Err(RestoreError::NotABlob),
        }
    })
}
