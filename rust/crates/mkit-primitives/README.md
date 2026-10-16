# mkit-primitives

Pure protocol contracts for pack verification, repository closure, and guarded
write decisions. Version **0.1.0** is independent of the workspace release train.
All public APIs are **ALPHA**. This skeleton defines types and traits; it does
not yet provide verification, closure, acceptance, or encoded formats.

Callers own acquisition, immutable byte retention, clocks, execution, and atomic
commits. The crate has no storage callbacks, runtime, HTTP client, or server
dependency. It supports `std`, including `wasm32-unknown-unknown`, and forbids
unsafe code. Core retains existing codecs, hashes, and individual signatures.

`VerifiedPack` establishes pack validity, `ClosureProof` establishes closure in
a repository view, and `Guarded<D>` carries every atomic comparison needed by
a decision. Their construction is private to their owning modules. None can be
deserialized or forged through a public testing helper. Host-supplied facts are
trusted observations, not remote attestations. Only a successful host atomic
comparison and commit accepts a write.

The default `pack-ruzstd` feature selects pure-Rust decoding. `pack-zstd` enables
the native backend. Raw-only and both-backend builds are supported. Backend
capability never substitutes for content verification.

Crate API version, normative ruleset, evidence format version, and checkpoint
format version are separate contracts. No checkpoint or evidence encoding is
defined yet. Future unsupported state versions require restart; historical
readers are not promised. Existing normative wire bytes remain unchanged.

```rust
use mkit_primitives::evidence::{PackSource, SourceBinding};
let source = PackSource { id: [1; 32], len: 128, binding: SourceBinding([2; 32]) };
assert_eq!(source.len, 128);
```

## Module inventory

Every item below inherits ALPHA from its enclosing module, including fields,
variants, associated items, trait members, and re-exports.

| Module | Contract |
|---|---|
| `error` | Stable `FailureCode::as_str`, `Failure`, numeric location and bounded detail |
| `limits` | Finite `VerifyLimits::indexed` execution defaults and explicit `IndexedProfile` content ceilings |
| `evidence` | Repository/source/revision/ruleset bindings, page/proof references, repository-scoped member facts |
| `pack_verify` | Byte-range requests and bound responses, backpressure events, paged summaries, opaque `VerifiedPack` accessors |
| `closure` | Batched membership facts, edge obligations, pure `InPackObjectView`, opaque `ClosureProof` accessors |
| `decision` | Observations/snapshots, exact guard variants, source fences, semantic effects, decisions, opaque `Guarded<D>` accessors |

`evidence::acceptance` reserves the envelope module without defining a schema.
Membership observations retain their object key even for absence. Terminal
replay refusals retain the exact public message under an explicit finite
`DecisionLimits` byte budget. Reservation settlements and durable delivery use
the same reservation-terminal payload, keyed by reservation identity rather
than only operation identity. Nonterminal ticket binding is a separate effect.

The private cursor and budget are infrastructure for future bounded decoders.
There are zero decoder entry points and zero registered encoded types in this
skeleton. Checkpoints, authenticated pages, framing vectors, and their fixtures
land with the framing implementation.
