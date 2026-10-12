//! Shared rayon fan-out sizing helper, plus the two "sequential below a
//! threshold, rayon `par_iter` at or above it" dispatch shapes every
//! per-item fan-out in this crate uses. The implementation lives in
//! `mkit-sync` (its fetch-side signature verification and restore use the
//! same shapes); this module re-exports it so call sites keep one path.

pub(crate) use mkit_sync::fanout::{map_seq_or_par, threshold, try_map_seq_or_par};
