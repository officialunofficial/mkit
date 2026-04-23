//! `mkit sparse_checkout` — Phase 10 follow-up in the Rust port. The backing
//! library ops live in `mkit-core::ops::sparse_checkout` (or equivalent); wiring
//! them to a CLI surface that preserves the Zig behaviour is deferred.

#[must_use]
pub fn run(_args: &[String]) -> u8 {
    super::not_yet_ported("sparse_checkout")
}
