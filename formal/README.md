# mkit formal models

Formal checks of mkit's specifications (formal verification effort). Start with
[`docs/FORMAL.md`](../docs/FORMAL.md): it explains the tool split, what
each result means (proved, exhaustive, bounded, simulated, tested), the
spec-to-property traceability table, the assumptions and the findings.
This directory holds the models; each subdirectory's README has the full
list of properties, mutants, bounds and recorded results.

| Directory | Tool | Covers | Model |
|---|---|---|---|
| [`quint/refs/`](quint/refs/README.md) | Quint, TLC, Apalache | Ref CAS per lock domain, lock order, recovery log, `serve.lock` and `server.lock`, served names; `refs_mbt.qnt` feeds the conformance test | ref concurrency model, ref conformance model |
| [`quint/history/`](quint/history/README.md) | Quint, TLC, Apalache | History publication, crash recovery, the scrub schedule | MKIT-20 |
| [`quint/gc/`](quint/gc/README.md) | Quint, TLC, Apalache | `mkit gc`, the recovery log, concurrent writers and the grace window, the server `ContentIndex` GC ordering | garbage-collection model |
| [`quint/transport/`](quint/transport/README.md) | Quint, TLC, Apalache | Requested transport identities, shard quorum, release threshold signing | transport model |
| [`quint/advance/`](quint/advance/README.md) | Quint, TLC, Apalache | `advance_refs`, the retry ladder, `read_ref` disambiguation, the re-baseline gate | remote-advance model |
| [`lean/`](lean/README.md) | Lean 4 | Merkle inclusion proofs and the delta codec: proofs plus differential tests against Rust | Merkle proof model, delta model |
| [`kani/`](kani/README.md) | Kani | Bounded checks of the untrusted-input decoders (harnesses live next to the Rust code) | MKIT-23 |
| [`scripts/`](scripts/) | quint, jq | `gen-refs-traces.sh`: regenerates the ITF fixtures for `rust/crates/mkit-formal-conformance` | ref conformance model |

## Running

From the repository root:

```sh
just formal               # quint default mode + lean + conformance
just formal-quint         # every quint/*/check.sh, default mode
just formal-apalache      # the bounded Apalache runs
just formal-lean          # lake build + both difftests
just formal-kani          # every Kani harness, one at a time
just formal-conformance   # replay the refs traces against the code
```

Each `quint/*/check.sh` also runs on its own (`./check.sh`, see its
header for knobs). Tool pins and install steps are in
[`docs/FORMAL.md`](../docs/FORMAL.md#run-the-checks); the nightly
workflow is [`.github/workflows/formal.yml`](../.github/workflows/formal.yml).

## Conventions for a new model

- Cite the spec section each invariant comes from.
- Give every invariant a mutant or canary that the checker must report
  as violated, and list the expected outcome of each check in the
  model's `check.sh`, which exits 1 on anything unexpected.
- Record bounds, commands and outcomes in the model's README. Never call
  a bounded result proved.
- `just formal-quint` picks up any new `quint/<name>/check.sh`
  automatically.
