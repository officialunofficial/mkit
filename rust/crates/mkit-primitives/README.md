# mkit-primitives

Pure protocol contracts for pack verification, repository closure, and guarded
write decisions. Version **0.1.0** is independent of the workspace release train.
The reference server depends on this crate; publish the required primitives
version independently before publishing a workspace release that uses it.
All public APIs are **ALPHA**. Auth-v2 validation and replay classification use
the existing protocol rules. The crate also provides guarded fork acceptance
and bounded direct-child closure with authenticated local evidence pages.
Pack verification and other decision drivers currently expose contracts;
their implementations land separately.

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
format version are separate contracts. Closure state, witness, and missing-set pages use strict version-one formats.
No serialized walker checkpoint is defined. Unsupported state versions and
lost pages require verification restart; historical readers are not promised. Existing normative wire bytes remain unchanged.

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
| `closure` | `ClosureWalker`, finite `ClosureLimits`, batched requests/replies, pure verified-object view and manifest summaries, opaque closure/missing results, bounded authenticated output page decoders |
| `fork` | Bounded complete inventory plans, final source fences, guarded acceptance, exact replay and reservation settlement |
| `decision` | Observations/snapshots, exact guard variants, source fences, semantic effects, decisions, opaque `Guarded<D>` accessors |

`evidence::acceptance` reserves the envelope module without defining a schema.
Membership observations retain their object key even for absence. Terminal
replay refusals retain the exact public message under an explicit finite
`DecisionLimits` byte budget. Reservation settlements and durable delivery use
the same reservation-terminal payload, keyed by reservation identity rather
than only operation identity. Nonterminal ticket binding is a separate effect.

The private cursor and budget are infrastructure for future bounded decoders.
Closure owns three local encoded page types and three validation/decoding entry
points: `output::{validate_state_page, decode_witness, decode_missing}`. Every
entry point takes a finite `PageDecodeCfg`; the internal journal additionally
uses a fixed 1,024-byte state-page ceiling. Frozen positive and negative bytes
are registered under the closure section of `fixtures/manifest.toml`.
`closure_steps` and `closure_pages` share stable replay bodies with libFuzzer.

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

Run `cargo run -p mkit-primitives --example fork_acceptance` for a complete
plan-sealing and acceptance example using deterministic host observations.

## Direct-child closure

Drive `closure::ClosureWalker::new` with the complete verified object view,
requested heads, repository identity/incarnation, ruleset, finite limits, and a
fresh run generation. Poll `step`; answer exact acquisition requests and retain
and acknowledge every page. Only `Closed` or `Missing` is a complete result.
The API example demonstrates an empty view; real views bind every record and
manifest summary to their sealed pack-verification artifact, and report
retained view memory through `InPackObjectView::retained_bytes`.

The proof's `relied_on_members` points to witness pages exposing exact supplier
packs and membership revisions. Acceptance guards those facts separately from
publication, external delta-base suppliers, denial, inspection, and authority.
Direct-child closure does not establish resulting-pair coverage. Tree/tag kind
hints and cycles are diagnostics; every chunk occurrence requires Blob integrity
and checked manifest totals. Resource exhaustion never returns a truncated set.

Pages are local evidence, not transport messages or remote attestations. After
page loss, replay from the same immutable inputs with a fresh generation.

## Authentication and replay

`auth::validate_envelope` delegates raw canonical fields, commitments, time
bounds, and strict signatures to `mkit_core::write_auth`. Call
`auth::inspect_headers` on raw header multiplicities first: any field in
`auth::TRIGGER_HEADER_NAMES` marks an envelope. Repository addressing and an
idempotency key alone do not. Partial or duplicate envelopes fail closed. Unary
requests require `x-digest`; upload streams may omit it. Trusted destination
identity comes from configuration and resolved addressing. Verification grants
no permission and reserves no nonce.

Envelope expiry is inclusive at ingress. Current host acceptance deadlines
remain separate; replay never extends envelope validity. Signed reads verify
fully and bypass the replay ledger.

`replay::classify_replay` returns the saved terminal result by reference. Hosts
supply successful durable results through `RecordedResult::success`; permanent
refusals pass the explicit allowlist through `RecordedResult::rejection`.
Challenges, membership lag, pending verification, and unavailable inspection
cannot be constructed through the rejection path. A fresh result requires an
absence guard before reservation or commit. A different fingerprint conflicts;
nonresumable in-flight work is retryable. Hosts atomically guard replay and
commit its transitions with their effects.

Claims validation takes borrowed principal and pack bindings after the host
has authenticated its token. Token encoding, MAC, keys, rotation, expiry,
current ticket state, and authorization remain host responsibilities. There is
no portable token encoding or new signing domain.
