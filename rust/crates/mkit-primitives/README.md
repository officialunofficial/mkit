# mkit-primitives

Pure protocol contracts for pack verification, repository closure, and guarded
write decisions. Version **0.1.0** is independent of the workspace release train.
All public APIs are **ALPHA**. The crate provides guarded fork acceptance and
shared contracts. Pack verification, closure walking, and encoded formats are
implemented by their owning modules as they become available.

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
| `fork` | Bounded complete inventory plans, final source fences, guarded acceptance, exact replay and reservation settlement |
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

## Fork acceptance

Use `fork::ForkPlan::seal` with complete authenticated whole-pack inventories,
including transitive external suppliers. Call `fork::decide_fork_acceptance`
with exact typed destination facts and the final source proof. Acceptance saves
the terminal response, replay response, and outcome responsibility and settles
the exact reservation in one atomic unit. It emits no visible membership,
ref, or permission to write. Activation is separate published clearance.

The host compares every returned destination fact and revision atomically.
Its emptiness revision covers phantom additions. The source proof is a separate
ordered fence after the final staged membership effect and before this apply
attempt. A later source change cannot invalidate acceptance or a saved result.
See the [guard matrix and host contract](docs/fork.md) for exact requirements,
resource bounds, replay rules, and verification scope.
