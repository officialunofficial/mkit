//! Shared rayon fan-out sizing helper.
//!
//! Multiple bulk-parallel paths (`commands::add`'s per-file hashing
//! fan-out, PR #951; `remote_dispatch`'s per-entry pack-compression
//! fan-out) use the same "sequential below N-per-thread, rayon at or
//! above it" crossover shape — rayon's pool-dispatch overhead loses to
//! a plain loop for a handful of items and wins clearly once there's
//! enough work per thread to amortize it. Each call site picks its own
//! `N` (entries-per-thread) from its own bench, since the per-item cost
//! differs (a BLAKE3 hash vs. a zstd compression pass); this is the one
//! place the `N * rayon::current_num_threads()` arithmetic itself
//! lives, so the two call sites can't drift on the formula, only on the
//! bench-measured constant each passes in.

/// The item count at or above which a caller should fan work out across
/// rayon's global thread pool instead of running it in a plain
/// sequential loop, for a pool of the process's actual size.
///
/// Reads rayon's already-initialized global pool size (cheap: an
/// atomic load after first use, no allocation).
#[must_use]
pub(crate) fn threshold(entries_per_thread: usize) -> usize {
    entries_per_thread.saturating_mul(rayon::current_num_threads())
}
