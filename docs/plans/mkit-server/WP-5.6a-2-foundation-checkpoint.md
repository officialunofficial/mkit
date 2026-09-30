# WP-5.6a-2 foundation checkpoint (R-190 / R-198)

PR 1 is open as [#1242](https://github.com/officialunofficial/mkit/pull/1242),
targeting `feat/mkit-server`, at `1c7383faabff696d5795f6e632b97610707faaec`.
Production takedown activation remains off. This checkpoint is on
`mkit-server/wp-5-6a-2-preservation`, branched from that commit. It changes no
production code and makes no preservation or launch-readiness claim.

## Ruling required: authoritative namespace enumeration

[SPEC-SERVER §14.3](../../specs/SPEC-SERVER.md#143-lifecycle-and-completion)
requires each takedown to run a durable, resumable deployment-wide sweep after
the safety cut. It enumerates namespaces, waits for their relay watermarks, then
enumerates the union of repository registries and active-shard tables. Incomplete
reads must retry. The approved B3/B4 scope retains this discovery work even while
the lean request remains honestly unresolved.

The merged base supplies traversal after a namespace is known. It does not supply
the authoritative namespace catalog needed for open-namespace deployments:

- [Partition's enumeration contract](../../../rust/crates/mkit-server/src/store/partition.rs)
  lines 20–28 uses configuration/allowlists for finite deployments and reserves a
  deployment-maintained list for `namespace_policy = any`. It explicitly states
  that a Durable Object namespace cannot enumerate its instances.
- [The `nl` key reservation](../../../rust/crates/mkit-server/src/store/keys.rs)
  lines 174–177 states that there is no M1 consumer or deployment-wide partition.
  Searches of server/native/Worker source find the reservation and codec tests,
  but no catalog writer or reader.
- [NamespaceStore](../../../rust/crates/mkit-server/src/store/kv.rs) supports
  bounded scans within a supplied partition; it has no namespace enumeration API.
- [Worker addressing configuration](../../../rust/crates/mkit-server-worker/src/adapter.rs)
  lines 625–708 permits `ADDRESSING=multi`, `NAMESPACE_POLICY=any`, and
  `UNSAFE_OPEN_NAMESPACES=true`; its namespace allowlist is mutually exclusive
  with that policy. This is an existing supported configuration.

Scanning known content holders cannot discover a namespace with committed but
not yet delivered membership. It therefore cannot establish which watermarks
must pass the safety cut. Treating that list as exhaustive would misstate discovery
completeness; silently restricting takedown to finite namespaces would change the
approved scope. A new authoritative cross-partition catalog is not implemented.

The ruling needed is the authoritative namespace source, its owner, and its
registration/durability contract, or an explicitly approved deployment-supplied
exhaustive namespace registry. The existing `nl` reservation needs no new tag
allocation. No new tag, timer, storage primitive, or cross-partition protocol is
proposed here.

B3/B4 permit incomplete discovery metadata and durable sweep/watermark seams.
This gap prevents claiming an exhaustive Any sweep; it does not make ordinary
acquisition, adapters, admin operations, or finite-namespace traversal impossible.
The local checkpoint follows R-198's explicit stop procedure before selecting
the missing catalog protocol, rather than treating incomplete lean preservation
as forbidden.

## Remaining authorized implementation

- Bounded canonical acquisition still needs implementation. The existing
  [preservation resolver](../../../rust/crates/mkit-server/src/indexed/resolve.rs)
  lines 435–454 collects a whole encoded frame, decodes a canonical `Vec`, and
  converts it to `Arc`. [Manifest BMT construction](../../../rust/crates/mkit-core/src/merkle.rs)
  lines 237–265 retains every tree level. Those paths do not establish the required
  resident bound for large valid objects/manifests. PR 1's sorted, deduplicated
  chunk pages cannot reconstruct canonical ordering or duplicates. A bounded
  canonical source and verifier must preserve those facts; no implementation is
  selected in this checkpoint.
- Merged 4.10b-1 makes the ct handoff required. The existing
  [holder producer](../../../rust/crates/mkit-server/src/relay/content.rs) at line
  274 observes only the exact V1 block entry. It needs V2 action-aware production
  and durable timer-13 ownership transfer before acknowledgment, using the
  existing handoff rather than a new wire/tag/timer allocation.
- Timer 15 must acquire, discover, and purge with one bounded alarm budget and
  `TimerCtx.store` for local partition access. No self-DO calls are permitted.
- Per-action preserved copies need verified bounded reads, checked retention,
  guarded legal holds and audited purge ownership. Admin replay must retain a
  bounded result descriptor; each byte read must verify the emitted piece.
- Native/Worker adapters, user provisioning templates, admin reads/legal hold,
  and the remaining lean normative amendment are still required PR 2 work.
  Nothing is deferred to satisfy either approved cap.

## Stop rule and validation

The explicitly required `executor-common-external.md` R-198 rule says:
“A new R-row, key tag, timer kind, wire or dispatch version, storage primitive or
cross-partition protocol needs an orchestrator ruling. Stop, commit coherent work,
and report the concrete source evidence instead of designing it.” Its stop
procedure requires a local commit without a push unless instructed otherwise.

This is a source-evidence checkpoint, not a reproduced runtime failure. Three
read-only investigations checked discovery/canonical acquisition, adapters, and
streaming/retention contracts. Documentation links and whitespace are checked;
an independent checkpoint review confirms the enumeration gap and permitted
incomplete states. Application gates are not rerun for this documentation-only
change. PR 1's gates,
line count and exceptions remain recorded in its
[contract](WP-5.6a-1-contract.md) and PR body. PR 2 adds zero Rust production lines.
