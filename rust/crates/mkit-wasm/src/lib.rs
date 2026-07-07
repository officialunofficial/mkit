#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]
//! WASM bindings for the mkit demo site.
//!
//! Thin wrappers over the pure byte-format and crypto paths in
//! `mkit-core` and `mkit-attest`. No filesystem access — the demo runs
//! entirely in the browser.
//!
//! The public `#[wasm_bindgen]` surface is split across cohesive
//! submodules; this root only wires them together and re-exports their
//! exported items so the generated JS surface (function names, struct
//! names, getter names) is identical to the single-file layout:
//!
//! * `objects` — blob / tree / commit / remix encode + decode and the
//!   object-kind probe, plus their view structs.
//! * `crypto` — Ed25519 keygen + sign / verify (commit-domain and raw)
//!   and `blake3_hex`.
//! * `attest` — in-toto / DSSE attestations and the `WebAuthn` passkey
//!   signing lifecycle.
//! * `chunking` — `FastCDC` chunker, chunked-blob manifest, delta, and
//!   Bao verified streaming.
//! * `common` — shared private helpers (hex / JSON parsing, count /
//!   index policy, object encoding) and the internal `CommitCore`.

#![forbid(unsafe_code)]
#![allow(clippy::multiple_crate_versions)]

mod attest;
mod chunking;
mod common;
mod crypto;
mod objects;

// Re-export every `#[wasm_bindgen]`-exported item at the crate root.
// wasm-bindgen registers exports wherever the item is defined, so these
// `pub use`s are for the Rust `rlib` consumers (tests, downstream crates)
// — they keep `mkit_wasm::<name>` resolving exactly as it did when every
// item lived in this file, without altering the JS export names.
pub use attest::{
    AttestKeyPairJs, AttestationJs, attest_build, attest_keypair, attest_pae, attest_verify,
    verify_webauthn_wrapping, verify_webauthn_wrapping_with_policy,
};
pub use chunking::{
    BaoEncoded, BaoVerify, ChunkInfo, ChunkedBlobJs, ChunkerResult, DeltaOp, DeltaSummary,
    bao_encode, bao_slice, bao_verify_slice, chunk_boundaries, chunked_blob_encode, delta_encode,
};
pub use crypto::{
    KeyPairJs, blake3_hex, ed25519_pubkey_from_seed, ed25519_sign, ed25519_verify,
    keypair_from_seed, keypair_generate, sign_bytes_commit_domain, verify_bytes_commit_domain,
};
pub use objects::{
    CommitInfoJs, EncodedCommit, EncodedObject, RemixInfoJs, RemixSourceJs, blob_encode,
    commit_decode, commit_encode_and_sign, commit_verify, object_kind, remix_decode,
    remix_encode_and_sign, tree_encode,
};
