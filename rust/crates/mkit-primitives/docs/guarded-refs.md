# Guarded ref decisions

Call `decision::ref_write::decide_ref_write` with the original request and fresh,
authoritative observations. The function performs no I/O. Missing acquisition
returns `UnavailableInput`; an acquired absence is `Observed::Absent(revision)`.
Bound facts, bytes, comparisons, guards, and public message size explicitly.

The module reuses core ref grammar and expectation types. It defines no token,
wire encoding, signing domain, physical key, or transaction representation.
Its API inherits the decision module's ALPHA stability.

## Decisions and dependencies

| Rule | Required dependency |
| --- | --- |
| Unconditional overwrite | No ref value guard |
| Missing or exact-match expectation | Exact observed ref value or absence |
| Grant's ref-presence constraint | Observed ref presence |
| Custom admission | Original proposed target and retained presence; mutable admission fact when applicable |
| Fast-forward on an existing unconditional ref | Exact observed value plus acquired ancestry evidence |
| Restricted signer or deployment fast-forward | Exact intersected policy observation |
| Scoped authorization | Original grant identity and epoch |
| Commit-fenced authority | Original mode and generation |
| Content membership or indexed head | Exact keyed membership observations |
| Final denial proof | Exact denial observation |
| Publication | Complete publication observation |
| Business validity | Original absolute upper bound |
| Signed operation | Exact replay scope and observation |

Paired operations evaluate packmap before head. A conflict changes neither ref.
Only the conflicting component's value enters the terminal result. Earlier
conditional comparisons retain their guards; an earlier unconditional value
is absent from the result. Deletion requires exact-match expectations and no
new targets. Fast-forward-only policy refuses deletion.

The host authenticates the current envelope before decision. Completed replay
returns its saved result before fresh policy or authorization work. Membership
visibility lag is retryable. The host derives `membership_window` from the original
request time and its existing visibility rule; retries do not renew that window.
An indexed-head absence after the window is `invalid_argument: open closure`.
Membership existence does not introduce a separate held/unpublished refusal.

A policy refusal may carry a terminal replay result. Grant epoch, authority,
ref-presence, and final denial errors remain unstored in this decision path.
An invalid original lifecycle binding returns a retry; the host retains its
lifecycle policy rather than acquiring a new public lifecycle error here.

## Atomic application

`Guarded<WriteDecision>` has private construction. Keep it intact through
lowering. `required_guard_kinds(class, &guarded)` combines independent effect
requirements with sealed read dependencies. Bare mutation lists cannot
distinguish unconditional writes from exact comparisons or refusal-only reads.
`check_guard_completeness` also checks every exact key and value. A second
ref guard cannot substitute for the first. Unknown adapter categories or
requirements versions fail closed through `validate_guard_kind`.

The adapter compares all dependencies and commits all composed effects in one
atomic unit. A lost guard requires fresh acquisition and decision. It never
replaces the original authorization generation, admission proposal, or validity
bound with a more permissive one. `guards_match` is a conformance comparator;
it does not replace a transaction.

Published-source creation carries a separate `RequiredSourceFence`. Before
every destination apply attempt, reauthorize source reads and compare the
complete captured publication. The fence includes the pair, generation,
sequence, deletion boundary, ref, and repository. A later source change is
concurrent with creation; the fence does not claim cross-source atomic CAS.
Completed replay requires no fresh source fence.

`decide_ref_publication` composes a fixed-size publication metadata decision
with accepted ref effects. It increments the sequence, preserves blocked
prefixes, and prevents partial deletion from publishing a surviving uncleared
component. Deletion advances the boundary even at the backlog ceiling.
Retained advance proofs, membership installation, tickets, accounting, and
reservation settlement remain separate effect groups.

## Reference integration and checks

The server acquires existing rows, invokes the portable ref decision, and lowers
its guards and effects. It checks every physical projection before commit.
The publication adapter checks the encoded publication result and its atomic
guard against the sealed publication decision. No extra store reads are added.

The surrounding planner retains replay, quota, lease, ticket, and outcome
composition in their existing order. Deployment policy acquisition and source
reauthorization remain host boundaries. The non-atomic paired fallback remains
sequential, as required by the existing server contract.

Executable fixtures cover the CAS matrix. Deterministic fuzz replay exercises
bounded models against an independent CAS oracle. Mutation tests change each
applicable dependency and omit each guard, including omissions within one
category. A frozen reference planner compares complete physical plans and exact
errors for CAS, admission, grant presence, replay, authority, quota, deletion,
publication prefixes, backlog, and competing corrupt observations.
