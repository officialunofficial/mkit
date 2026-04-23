//! mkit-core — BLAKE3 hashing and canonical v1 object byte format.
//!
//! This crate is the Rust port of the Zig modules `src/hash.zig`,
//! `src/object.zig`, and `src/serialize.zig` on the `main` branch.
//!
//! The byte layout implemented here is defined, normatively, in
//! `docs/SPEC-OBJECTS.md` (version `0x01`, magic `"MKT1"`). Any change
//! to this crate MUST update the spec in the same PR.
//!
//! The library is `#![no_std]`-friendly only via `alloc`; for now we
//! depend on `std` (like the Zig original) to keep the port readable.
//! No `serde`, no `anyhow`, no panics on unchecked input.

#![forbid(unsafe_code)]
// `ed25519-dalek` v2.2 still pulls in older sha2/cpufeatures (and
// rand_core 0.6 which transitively wants getrandom 0.2). These are
// transitive duplicates we cannot dedupe without forking dalek; allow
// them. cargo-deny still tracks them at warn level via deny.toml.
#![allow(clippy::multiple_crate_versions)]

pub mod chunker;
pub mod delta;
pub mod hash;
pub mod object;
pub mod serialize;
pub mod sign;
pub mod store;

pub use hash::{HASH_LEN, HEX_LEN, Hash, Hasher};
pub use object::{
    Blob, ChunkedBlob, Commit, Delta, EntryMode, IDENTITY_MAX_LEN, Identity, IdentityKind, MAGIC,
    MkitError, Object, ObjectType, Remix, RemixSource, SCHEMA_VERSION, Tree, TreeEntry,
};
pub use serialize::{deserialize, serialize};
pub use sign::{
    COMMIT_DOMAIN, KeyPair, PublicKey, REMIX_DOMAIN, SecretSeed, Signature, commit_signing_bytes,
    commit_signing_hash, remix_signing_bytes, remix_signing_hash, sign_commit, sign_remix, verify,
    verify_commit, verify_remix,
};
pub use store::{MAX_RAW_OBJECT_SIZE, MKIT_DIR, OBJECTS_DIR, ObjectStore, StoreError, StoreResult};

// Phase 3 — content-defined chunker (FastCDC v1).
pub use chunker::{
    AVG_SIZE as CHUNK_AVG_SIZE, ChunkBoundary, ChunkIterator, FastCdc, MASK_L as CHUNK_MASK_L,
    MASK_S as CHUNK_MASK_S, MAX_SIZE as CHUNK_MAX_SIZE, MIN_SIZE as CHUNK_MIN_SIZE,
    SEED as CHUNK_SEED, chunk_boundaries, gear_table_digest,
};

// Phase 3 — delta instruction stream (SPEC-DELTA v1).
pub use delta::{HEADER_LEN as DELTA_HEADER_LEN, MAX_INSERT_LEN, OP_COPY, STREAM_VERSION};
