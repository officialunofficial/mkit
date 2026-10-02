# ListRepos feasibility escalation

Status: **resolved by the user visibility-index ruling (2026-10-02)**.
The original escalation below records why the prior storage contracts were
insufficient. The ruling authorizes coordinator-local `rl` subkeys `p` and `d`,
atomic index updates alongside creation and SetRepoVisibility, and public-only
listing rights for grants. No cross-partition protocol or backfill is permitted.
Implementation and the additive contract are in
[SPEC-TRANSPORT-CONNECT §7.10](../../../specs/SPEC-TRANSPORT-CONNECT.md#710-namespace-repository-listing).
The `rl` tag was absent from the base key registry; the key-tag uniqueness test
includes it. The old R-208 stop is superseded by this ruling.
Base: `2db7f9c29fda85b973060c242401dfd628ba1f54` on `feat/mkit-server-next`.
Decision row: R-208.

## Storage contracts at the escalation base

- [`Partition`](../../../../rust/crates/mkit-server/src/store/partition.rs)
  documents one repository registry per namespace coordinator. A D34
  `RepoIndex` is keyed by namespace, **already-known repository name**, and
  object-id prefix. It indexes objects within a repository, not repository
  names across a namespace.
- [`ShardMap`](../../../../rust/crates/mkit-server/src/pipeline/shard.rs)
  exposes one `coordinator(namespace)`. Its enumerable partitions are ref
  indexes within a known repository. There is no repository-name shard fan-out.
  Single maps the coordinator to the Namespace partition.
- [`keys`](../../../../rust/crates/mkit-server/src/store/keys.rs) defines
  `rr\0<repo>` for registered repositories and `rv\0<repo>` for visibility,
  both in the coordinator. There is no visibility-selective repository-name
  index. A visibility row may exist before registration and cannot alone
  establish repository existence.
- [`RepoRecord`](../../../../rust/crates/mkit-server/src/store/codec.rs)
  contains only `created_at_ms`. It has no visibility, head, or last-update
  field. [`commit_creation`](../../../../rust/crates/mkit-server/src/pipeline/coordinator.rs)
  writes this record on the first authorized write.
- [`read_repo_state`](../../../../rust/crates/mkit-server/src/pipeline/mod.rs)
  resolves registration, visibility and epoch through one coordinator
  `get_many`. Explicit visibility overrides the deployment default.
- [`NamespaceStore`](../../../../rust/crates/mkit-server/src/store/kv.rs)
  supports key-range scans and point reads, with no value predicate or join.
  A scan can return a short page with a continuation. Filtering visibility
  therefore requires inspecting candidate repositories after enumeration.
- The Worker [`namespace client`](../../../../rust/crates/mkit-server-worker/src/ns_client.rs)
  implements batched visibility reads in one round trip. Its
  [`wire`](../../../../rust/crates/mkit-server-worker/src/wire.rs) caps
  `get_many` requests at 1 MiB. The
  [`adapter`](../../../../rust/crates/mkit-server-worker/src/adapter.rs)
  shares a finite 9,000-call request allowance between backends. No repository
  count ceiling is defined by the registry, routing, or pipeline configuration.

## Blocking counterexample

Consider the same namespace and prefix in three healthy stores:

1. No registered repositories.
2. An arbitrarily long, lexically ordered run of private repositories, none
   readable by the anonymous caller.
3. The same private run followed by one public repository.

The first two must have the same externally observable listing result under
the brief's no-existence-oracle rule. The third must eventually list the public
repository. This applies equally when private visibility is the deployment
default and no explicit `rv` rows exist.

With the existing index, a finite candidate-scan allowance cannot distinguish
the second store from the third after the allowance is spent. Each fallback
breaks a fixed requirement:

- Continuing until exhaustion makes request reads and work unbounded.
- Returning a continuation after examining only hidden rows distinguishes the
  private-only store from the empty store. A MAC or encryption hides cursor
  contents, but cannot hide the continuation's presence or number of pages.
- Returning a budget error makes the same distinction through the error.
- Returning terminal success silently omits later public repositories.

Batching `rv` reads removes a per-repository round trip for a **bounded candidate
page**. It does not bound the number of candidate pages needed to produce a
complete, oracle-free visible page. Moving this filtering into a Durable Object
would introduce a new query/storage primitive and still require a bound on its
work; the generic storage contract does not provide that operation.

## Ruling requested at the escalation base

The existing registry supports deterministic coordinator pagination, but not
the decided k-way pagination across repository-name shards. More fundamentally,
meeting bounded, complete visibility filtering without a private existence
oracle needs an approved visibility-selective enumeration foundation, or an
explicit change to the fixed listing contract. The key layout and authorization
semantics of that foundation require a ruling before implementation.

At the initial escalation commit, no runtime, wire or storage foundation had
been introduced. The subsequent user ruling above authorizes the coordinator
visibility index and resolves this stop. Native-server code remains out of scope.
