//! `mkit fetch` — alias for pull in the 0.2.x Rust port (no merge
//! semantics yet), but re-implemented to keep the CLI surface honest
//! with the Zig help text.

#[must_use]
pub fn run(args: &[String]) -> u8 {
    super::pull::run(args)
}
