#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]
#![doc = include_str!("../README.md")]
//!
//! Deterministic mkit↔git bridge translation core.
//!
//! Implements [`SPEC-GIT-BRIDGE`](../../../docs/specs/SPEC-GIT-BRIDGE.md):
//! every mkit v1 object maps to a git object whose bytes are a pure
//! function of the source bytes, with mkit-only fields carried in
//! `mkit-*` commit/tag headers so the original object — and its
//! Ed25519 signature — can be reconstructed and re-verified.
//!
//! Export ([`translate`]) is specified by SPEC-GIT-BRIDGE; import is
//! specified by SPEC-GIT-IMPORT. The [`reconstruct`] module is the
//! export mapping's verification-grade inverse, **not** an import
//! path: it is defined only on objects [`translate`] can emit and
//! fails loudly on anything else.
//!
//! The blake3↔sha1 mapping ([`map`]) is always a rebuildable cache —
//! determinism means deleting it and re-deriving yields identical
//! results, so it is never a source of truth.

pub mod author;
mod b64;
pub mod error;
pub mod gitobj;
pub mod gitparse;
pub mod gitsrc;
pub mod headers;
pub mod import;
pub mod map;
pub mod reconstruct;
pub mod refname;
pub mod remoteid;
pub mod translate;
pub mod verify;

pub use error::{BridgeError, Refusal};
pub use gitobj::{GitObject, GitType, Sha1Id};
pub use translate::{ObjectSource, TranslationBatch, translate_closure};
