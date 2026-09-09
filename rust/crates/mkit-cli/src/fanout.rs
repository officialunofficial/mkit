//! Shared rayon fan-out sizing helper, plus the two "sequential below a
//! threshold, rayon `par_iter` at or above it" dispatch shapes every
//! per-item fan-out in this crate uses.
//!
//! Multiple bulk-parallel paths (`commands::add`'s per-file and per-chunk
//! hashing fan-outs; `remote_dispatch`'s per-entry pack-compression,
//! delta-encoding, and signature-verification fan-outs) share this
//! crossover shape — rayon's pool-dispatch overhead loses to a plain loop
//! for a handful of items and wins clearly once there's enough work per
//! thread to amortize it. Each call site picks its own `N`
//! (entries-per-thread) from its own bench, since the per-item cost
//! differs (a BLAKE3 hash vs. a zstd compression pass vs. an Ed25519
//! verify); [`threshold`] is the one place the
//! `N * rayon::current_num_threads()` arithmetic itself lives, so call
//! sites can't drift on the formula, only on the bench-measured constant
//! each passes in.
//!
//! [`map_seq_or_par`]/[`try_map_seq_or_par`] additionally share the
//! branch-and-collect boilerplate itself, for the two shapes common to
//! more than one call site (by-reference, `Fn(&T[, bool]) -> U`/
//! `Result<U, E>`, output in input order). Not every fan-out fits: a
//! few sites need a different shape on purpose —
//! `remote_dispatch::mod::prepare_delta_batch` consumes its input by
//! value (`into_par_iter`, avoiding a clone `&[T]` would force), and
//! `remote_dispatch::packmap::verify_new_object_signatures` chunks the
//! parallel path deliberately (bounding wasted work past a hostile
//! fetch's first bad signature — see that function's own doc). Forcing
//! either into one of these two shapes would need extra generic
//! machinery to claw back what a bespoke loop gets for free; they stay
//! bespoke rather than fit a shape that doesn't actually match their
//! constraint.

use rayon::prelude::*;

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

/// Map `f` over `items` — sequentially below `threshold`, via rayon's
/// global thread pool at or above it — preserving input order either
/// way. `f`'s second argument is `true` exactly when the parallel path
/// was taken, for the rare caller (`commands::add::hash_pending_batch`)
/// whose per-item work itself needs to know whether it's already running
/// as one of several concurrently-busy rayon workers (to avoid nesting
/// a second fan-out into an already-saturated pool) — callers that don't
/// care can ignore the argument.
pub(crate) fn map_seq_or_par<T, U>(
    items: &[T],
    threshold: usize,
    f: impl Fn(&T, bool) -> U + Sync,
) -> Vec<U>
where
    T: Sync,
    U: Send,
{
    if items.len() < threshold {
        items.iter().map(|it| f(it, false)).collect()
    } else {
        items.par_iter().map(|it| f(it, true)).collect()
    }
}

/// [`map_seq_or_par`], for a per-item `f` that can fail — the collected
/// `Result` short-circuits on the first `Err` either way (rayon's
/// `FromParallelIterator` impl for `Result` matches `Iterator`'s in that
/// respect, modulo already-dispatched parallel work still running to
/// completion — see `verify_new_object_signatures`'s doc for why that
/// distinction matters enough to keep it bespoke there).
pub(crate) fn try_map_seq_or_par<T, U, E>(
    items: &[T],
    threshold: usize,
    f: impl Fn(&T) -> Result<U, E> + Sync + Send,
) -> Result<Vec<U>, E>
where
    T: Sync,
    U: Send,
    E: Send,
{
    if items.len() < threshold {
        items.iter().map(f).collect()
    } else {
        items.par_iter().map(f).collect()
    }
}
