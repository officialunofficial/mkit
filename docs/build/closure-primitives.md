# Driving direct-child closure

`mkit_primitives::closure::ClosureWalker` checks direct references from every
object in a supplied verified pack view and every advanced head. The caller
owns acquisition, private retention, execution scheduling, and final acceptance.
The machine performs no I/O and uses no clock, runtime, or storage callbacks.

Construct it with an immutable `InPackObjectView`, the exact head sequence,
repository identity and incarnation, ruleset binding, finite `ClosureLimits`,
and a run generation. The view must derive its metadata, edge occurrences,
and chunk manifest summaries from canonical verified objects. Its root must
match the sealed verification artifact used by acceptance. An implementation
of the view must only inspect already supplied immutable data.

Poll `step` until it requests acquisition, retention, or returns a terminal
result. `Progress` is one finite internal transition. Polling an outstanding
request or retention event repeats the same identity without advancing work.
Answers and acknowledgements are accepted only for that exact event.

| Request/event | Host answer | Binding and failure behavior |
|---|---|---|
| `Membership` | Complete ordered `MembershipResponse` | Exact run, sequence, repository, incarnation, ID count and order. Present answers preserve supplier pack, immutable byte source and membership revision. Partial, duplicate, reordered, stale or foreign replies invalidate the run. |
| `Canonical` | Exact canonical external Blob bytes | Exact request and complete member/source binding, exact byte length, core canonical Blob prologue and content hash. No existence inference from a kind assertion. |
| `Page` | Exact previously retained visited-state bytes | Exact request, page role, count, length and domain-separated digest; strict current-version parsing. Absent/unavailable pages are acquisition failure, never object absence. |
| `Retain` | `acknowledge(request, page)` | Retain the exact immutable bytes before acknowledgement. Roots advance only after acknowledgement. A lost reply is handled by polling the unchanged event. |

Membership requests contain at most `membership_batch` IDs, sorted and unique
within a frontier. Repeated references use the authenticated visited journal;
chunk lengths still count once per occurrence. A frontier contains a bounded
edge window rather than issuing a callback for every child. Single-element
frontiers are possible when only one unresolved external ID remains.

`Closed` contains a privately constructed `ClosureProof`. Its roots bind the
complete supplied set and exact heads. `relied_on_members` points to the first
witness page; `output::decode_witness` exposes every exact membership revision
and supplier pack. Acceptance must guard those dependencies at its own boundary.
Published membership, external delta-base suppliers, denial, inspection,
authorization, and resulting-pair coverage remain separate obligations.

`Missing` is produced only after all required reachable checks finish and every
output page is retained. Follow `MissingSet::root` with
`output::decode_missing`; IDs are sorted and deduplicated, and each page preserves
its reference-occurrence reasons. Intermediate pages are not a complete result.
An unavailable response or exhausted bound invalidates the run. Replay from
immutable inputs with a fresh generation after page loss; never manufacture an
absence response from a lost page. There is no serialized walker checkpoint or
proof constructor in this API.

## Bounds

`ClosureLimits` separately bounds distinct reached IDs, edge occurrences, newly
entered depth, cumulative canonical bytes, one canonical object, resident bytes,
retained evidence bytes/pages, distinct missing IDs, membership batch size, and
cumulative work. The reached-ID ceiling remains ten million, including external
frontier stops. Roots have depth zero. Revisiting a gray node reports a cycle;
revisiting shared black structure does not consume another depth level.

The visited journal has 256 fixed bucket roots and one bounded page decoder.
Frame storage, edge windows, responses, retained output, and missing-reason
storage have explicit resident allowances. Missing reasons also consume edge,
work and resident budgets; a capacity failure never returns a truncated set.
Journal scans charge both steps and authenticated bytes. A pathological bucket
may exhaust work before the reached-ID ceiling. This is execution exhaustion,
not invalid content. Host memory allocated before supplying a borrowed byte
slice is outside primitive allocation accounting; accepted outstanding bytes
still consume the configured allowance.

The algorithm preserves existence-only tree/tag child closure, excludes remix
sources, and checks Blob integrity and ordered summed lengths for every consumed
chunk manifest, including surplus manifests. It adds no fixed-size chunk rule,
cycle content refusal, graph-depth content rule, or server refusal mapping.
See [the server edge and evidence contracts](../specs/SPEC-SERVER.md#direct-child-closure-edges).

Local page formats are current-version-only. Unsupported or lost local evidence
requires verification restart. They do not change repository storage or transport
formats. Reference inline/scheduled integration is separate work.
