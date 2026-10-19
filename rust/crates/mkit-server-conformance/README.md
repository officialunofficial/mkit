# Server conformance

The protocol contract is the normative specifications plus conformance. Any
server implementation can run these suites. Reference-server storage layouts
are private to its test binding.

- **Tier 1: wire.** Ordinary transport HTTP requests, a base URL, and a declared
  wire profile. No server control is required.
- **Tier 2: server control.** The wire URL and profile plus the version 1
  test-only HTTP binding below, at the same or a separate origin. Cases combine
  wire operations with controlled restart, authority changes, barriers, and atomic
  observations.
- **Optional storage SPI suite.** Enable `storage-spi` to implement
  `storage::KvHarness` and invoke `storage_suite!`. This tests the reference
  server's storage API; other implementations do not have to implement it.

The default library and runner expose Tier 1, Tier 2, and their message types
without a dependency on `mkit-server`. The optional `storage-spi`, `stubs`, and
`test-host` features add reference-server support. An out-of-tree server needs
only the conformance dependency, its base URL and profile, and its own test-control
binding; it need not implement a Rust trait or adopt the reference storage SPI.

## Pack-location profile

Add `pack-locations` to the wire profile's `features` to exercise negotiated
locations and unchanged streaming requests. The optional test host then mounts
an expiring local HTTP listener for single-pack URLs. That loopback fixture is
only for conformance; production locations require HTTPS. The focused
`pack_locations` tests also cover denied, held, pending, private, and foreign
repository packs, expiry after denial, and client fallback from corrupt bytes.

## Out-of-tree runner

This crate is prepared for the next lockstep release; it is not published by
this change. Until that release, use a pinned git dependency. After release,
add `mkit-server-conformance` at the same released version as any other mkit
dependencies, or install its binary with `cargo install mkit-server-conformance`.
The published package includes its fixtures; no workspace paths are required.

```rust,no_run
use std::collections::BTreeMap;
use mkit_server_conformance::{controlled, wire::{Profile, WireTarget}};

# async fn check(profile: Profile, expected_skips: BTreeMap<String, String>) {
let target = WireTarget {
    base_url: "http://127.0.0.1:8080".parse().unwrap(),
    profile, // the server's declared signed-write profile
};
let wire_report = mkit_server_conformance::wire::run(&target, None).await;
let control_report = controlled::run(&target, &expected_skips, None).await;
assert!(!wire_report.failed(), "{}", wire_report.tap());
assert!(!control_report.failed(), "{}", control_report.tap());
# }
```

```sh
mkit-server-conformance wire --base-url http://127.0.0.1:8080 \
  --auth auth-v2 --audience http://127.0.0.1:8080 --repository default \
  --random-signer --atomic-advance
mkit-server-conformance controlled --base-url http://127.0.0.1:8080 \
  --profile conformance.toml --declared-skips declared-skips.json
```

Both commands print TAP and exit 1 on a failed case, 2 on usage errors.
`--list-cases` prints each tier's registry. `--filter` selects case names.
The wire profile declares authentication, optional features, and fixture limits;
`wire::ProfileSpec` documents all TOML fields. Controls never enable production
capabilities. Run Tier 2 only against an isolated disposable test instance.

## Standalone run and differential commands

Install the portable runner at the same immutable revision as your server:

```sh
cargo install --git https://github.com/officialunofficial/mkit --rev <revision> \
  --locked mkit-server-conformance
```

The `run` command runs Tier 1 and Tier 2 without linking a Rust dependency.
Specify the transport URL and the test-control binding separately when needed:

```sh
mkit-server-conformance run --base-url http://127.0.0.1:8080 \
  --control-url http://127.0.0.1:8081 --profile conformance.toml
```

Copy the packaged [example runner profile](fixtures/runner.toml) to
**conformance.toml**. Edit its origin, repository, limits, features, controls, and
known gaps to match your disposable server, and set `CONFORMANCE_SIGNER_SEED` to
a 64-character hex test seed. Installing the binary does not copy fixture files
into your working directory.

The version 1 runner profile contains the existing wire profile under `[wire]`
and test-control declarations under `[control]`. These declarations describe an
already isolated test host; they never enable production routes.

```toml
version = 1

[wire]
auth = "auth-v2"
audience = "http://127.0.0.1:8080"
repository = "default"
signer_seed_env = "CONFORMANCE_SIGNER_SEED"
atomic_advance = true
run_id = "standalone"
features = ["tickets", "-authority-fencing", "-authority-setter", "-fork"]
relay_lag_bound_ms = 0

[control]
controls = ["clock.pin", "observe", "restart.graceful"]

[control.declared_skips]
"acceptance.kill_recovery" = "This test host retains process-local memory only."
```

Use `--tier wire` or `--tier controlled` to select one tier, and `--filter` to
select case names. Every selected case appears in the report. Missing optional
features are not applicable; missing controls require a concrete declared skip
for the applicable case. Negotiation errors fail setup. Even `--tier wire` negotiates the test binding.
The optional `[control]` field `url` sets its origin; `--control-url` overrides it.

Install the embedded reference test utility for differential runs:

```sh
cargo install --git https://github.com/officialunofficial/mkit --rev <revision> \
  --locked --features reference-runner mkit-server-conformance
mkit-server-conformance diff --base-url http://127.0.0.1:8080 \
  --control-url http://127.0.0.1:8081 --profile conformance.toml
```

`diff` starts a fresh reference server on loopback and drives the same
canonical fixtures against it and the target. Both test bindings pin business
time; fixed keys, nonces, and timestamps make each logical operation repeatable.
Run against disposable instances with no other writers. Differential writes use
an Ed25519 test key whose public seed is 32 bytes of `0x75`, independently of the
profile's Tier-1 signer seed. A multi-repository target must admit that key's
owner namespace and the repository named `differential-v1`; a single-repository
target uses the configured repository. The reference host supports its declared
test profile; unsupported profiles fail setup explicitly. Indexed differential
profiles declare `multi-repo`, `indexed-mode`, `tickets`, auth v2, and atomic
advance. The native CLI regression exercises that profile without dropping its
features; the small canonical packs complete verification within the inline bound.
This does not establish scheduled-verification equivalence.

Normalization excludes allocated server identifiers, timing fields, and
`Retry-After` values. Refusal comparison uses protocol error codes. Replay
fingerprints are first checked against each exact signed operation, including
its target audience, then normalized to that operation's logical role. Each
server must replay its original receipt bytes. Receipt issuance, signatures, and
statement fields are outside these differential fixtures; they require separate
receipt conformance coverage. Atomic snapshots retain ref pairs, ticket and
reservation order, membership, terminal result multiplicity, and quota counters. The report names each differing field.
Two failed executions never count as passing equivalence.

Differential results establish decision equivalence for these deterministic
fixtures. They do not establish crash, recovery, or concurrency behavior;
Tier 2 covers those properties separately. Cloud Build's all-feature workspace
suite exercises two native reference hosts over HTTP.

Both commands write a versioned JSON report to stdout by default; `run` also
supports `--format tap`. JSON contains case results and differences, without
credentials or signing material. Exit codes are `0` for a passing run, `1` for a
failed case or differential mismatch, and `2` for usage, profile, setup,
negotiation, or runner execution-limit errors. Existing `wire` and `controlled`
commands retain TAP output.

Differential decisions have a 45-second execution budget. The runner honors
valid pending-verification polling hints clamped to 1–60 seconds. If a mandatory
wait cannot fit, the JSON case status is `runner_error` and the command exits 2;
this is inconclusive, not a protocol failure or a match. An already observed
protocol violation remains `failed` with exit 1 even if a later step or the other
target reaches this budget. Rerun against a disposable
fixture whose verification resolves within that budget. The runner never polls
early to avoid the wait. Ordinary protocol refusals retain their failure result.

## Version 1 test-control binding

**Protocol requirement (test interface only).** This interface is optional test
infrastructure, outside the public transport wire. A production build MUST NOT
mount these routes. The reference binding requires `test-host`. Optimized
builds additionally require the explicit `reference-runner` test utility feature. Production artifacts
never enable these features. A server under test implements the binding
in its own test host; it need not use Rust or any reference storage layout.

`GET /__mkit_test/v1/capabilities` returns JSON with `version: 1`, `controls`
(an array of supported names), `durability_profile` (the actual failure
promise), and `unsupported` (an object mapping unavailable control names to
reasons). Unknown versions, malformed responses, contradictory declarations,
and missing negotiation routes fail the run. An unavailable capability is a
coverage gap, never a passing assertion.

`POST /__mkit_test/v1/control` accepts the JSON encoding of `control::Request`.
The `operation` discriminator and fields are:

| Operation | Fields | Meaning / capability |
| --- | --- | --- |
| `pin_clock` | `now_ms` | Pin business time in Unix milliseconds; `clock.pin`. |
| `advance_clock` | `delta_ms` | Advance business time by a nonnegative duration; `clock.advance`. |
| `prepare_authority_setter` | none | Return `authority_namespace`, a valid `authority_statement`, and a strictly newer `generation`, without changing authority; `authority.setter_fixture`. Uses a dedicated test deployment key, never key material in the response. |
| `bump_authority` | `namespace` | Install a strictly newer authority generation, including the local acceptance fence; `authority.bump`. |
| `pause` | `step`, `repository`, `head`; optional `decision_class`, `occurrence`, `on_resume` | Arm a one-shot protocol boundary for the selected decision. Capabilities are `pause.<step>` and, for a non-default decision class, `decision.<decision_class>`. |
| `barrier_status` | none | Return `paused` once the operation reaches its armed boundary. |
| `resume` | none | Release the barrier, including after failure. |
| `restart` | `mode` | `graceful` drains accepted commands or preserves recovery responsibility; `kill` terminates the hosted process where supported. Capabilities `restart.graceful` and `restart.kill` are separate. Origin, store identity, configuration, and replay identities survive within the declared durability profile. |
| `observe` | `query` | One atomic authoritative acceptance snapshot; `observe`. |
| `observe_publication` | `query: { acceptance: ObservationQuery }` | Atomically observe acceptance, live and published sequences, published pair, deletion boundary, and published memberships; `observe.publication`. |
| `set_publication_eligibility` | `repository`, `head`, `eligible` | Hold or release eligibility of future decisions on this branch; `publication.eligibility`. This does not claim an integrated asynchronous inspector. |
| `drive_publication` | `repository`, `head` | Drive outstanding real clearance without replaying acceptance; `publication.drive`. |
| `prepare_reliance` | `query: { purpose, repository, head, signer }` | Establish a valid accepted unique base and return unpublished dependent candidate bytes; `reliance.fixture`. |
| `prepare_gc_drop` | `repository`, `pack` | Capture the genuine recheck proof without removing the member; `gc.prepare_drop`. |
| `commit_gc_drop` | `repository`, `pack` | Attempt that original guarded drop; `gc.commit_drop`. Return `gc_drop_result: committed` or `conflict`, never a case verdict. |
| `hide_member` | `repository`, `pack` | Commit an inspection verdict or hold preventing reliance; `inspection.hide_member`. |
| `observe_reliance` | `query: ObservationQuery` | Atomically observe acceptance and each selected member's usability for delta bases and closure; `reliance.observe`. |
| `prepare_fork` | `query` | Seed a valid published source without creating or starting the destination; `fork.fixture`. |
| `observe_fork` | `query` | One atomic authoritative fork snapshot; `fork.observe`. |
| `change_fork_source` | `query`, `change` | Commit a source change for a prepared fork; `fork.source_change.<change>`. Never modify the destination. |

Success is HTTP 200 with `control::Response` JSON. Unsupported controls return
HTTP 501 without mutation. Rejected requests return a 4xx response without mutation.
The response has optional `authority_namespace`, `authority_statement`, `observation`, `now_ms`, `generation`, `fork_fixture`,
`fork_observation`, `publication_observation`, `reliance_fixture`,
`reliance_observation`, and `gc_drop_result`, plus `paused`. New optional fields
are omitted when absent. Clock controls do not advance monotonic
execution budgets or simulate durability.

The four boundaries come from [SPEC-SERVER §18.1](../../../docs/specs/SPEC-SERVER.md#181-protocol-conformance-tiers):

| `step` | Meaning |
| --- | --- |
| `before_acceptance` | Before the final guarded acceptance decision. |
| `after_durable_acceptance_before_response` | After the complete accepted unit is durable, before releasing its response. |
| `after_response` | After releasing the response; this does not assert that the client received it. |
| `before_published_clearance` | Before the guarded decision that makes eligible membership and the published value reader-visible. |

These names identify protocol decisions, not engine steps or storage layouts.
A binding advertises only boundaries it can reach. The optional `decision_class`
defaults to `ref_acceptance`; fork cases select `fork_acceptance`, `fork_progress`,
or `fork_source_proof`. For the latter, `before_acceptance` is after **all**
destination membership effects are staged and before obtaining the final source
proof. Its capability is `decision.fork_source_proof`; `fork.final_source_proof`
asserts that the target implements that complete source proof, not merely
per-pack checks. The boundary does not prescribe construction steps.
`fork_destination_claim` selects the decision that first atomically excludes
competing destination creation or writes. `writer_authority_ready` selects an
ordinary signed write immediately before acceptance, after it has acquired
reusable write authority; resumption exercises that retained authority. These
classes require `decision.fork_destination_claim` and
`decision.writer_authority_ready`, respectively. They expose semantic decisions,
not leases or storage rows. The registration race lets a competing writer claim
the destination while fork's claim is paused. The acceptance race proves fork
exclusion defeats a new writer. The retained-authority race lets a previously
ready writer defeat fork registration. Each asserts exactly one winner; it does
not require an impossible reverse ordering after authority is already usable.
The failed-destination case additionally advances beyond the reference job and
lease lifetimes, restarts, and repeats signed read/write probes.

The optional `occurrence` is one-based and defaults to the first occurrence in
that operation's selected decision class. It permits fencing every advancing
commit without prescribing a job's internal phases or number of commits.
Pause/resume cannot move guard checks earlier.

At `after_durable_acceptance_before_response`, setting
`on_resume: "uncertain_storage_result"` requests an uncertain storage error
after release, while retaining the committed state. It requires
`fault.uncertain_result`. The public error may be `internal` or `unavailable`;
neither proves abort. The runner verifies the full committed observation,
retries the original signed identity, and checks that settlement did not repeat.
The after-response restart case first receives the response at the client,
then requests restart; it does not need a server-side `after_response` barrier.

An observation query selects a full `repository`, head ref `head` and its implicit
paired packmap, optional `replay` identity (`audience`, `repository`, `signer`,
`nonce`), `ticket_ids`, `reservation_ids`, `packs`, and optional `quota` window
(`signer`, optional `window_start_ms`; null selects the current window).
Object/pack/ticket IDs and signed hexadecimal fields use lowercase hex;
reservation IDs remain opaque. Times use Unix milliseconds.
It accepts no storage keys. The observation returns live head/packmap IDs,
semantic replay state and saved result class, ticket states, reservation states
and terminal-result counts, local live membership, and quota counters. Every
returned value MUST coexist at one authoritative observation point. A binding
MUST reject queries outside its declared atomic domain rather than combine
independent snapshots. Arrays preserve query order. Missing tickets with no
closure evidence are reported as null. A binding can
report `consumed` or `expired` from retained terminal evidence; absence alone
MUST NOT be interpreted as consumption.

With empty `reservation_ids`, infer the reservations bound to `ticket_ids` in
order, followed by the ref reservation bound to `replay`. The test fixture grants
a separate ref reservation and advertises `fixture.ref_reservation`; its actual
reservation names stay private. Terminal counts exclude repeated sink delivery.
Fixtures retain replay, ticket closure evidence, and terminal responsibility for
the case; timers must not prune asserted evidence during an observation.
Result classes include `advance_committed`, `update_ref_committed`, and conflict or
rejection classes. A replay fingerprint binds the original signed request.

The acceptance fixture uses opaque packs and arbitrary ref targets, advertised
as `fixture.opaque_refs`. An indexed-only test configuration cannot advertise
that fixture; its missing capability is a visible coverage gap. The reference
control host supports unsharded opaque and indexed modes. The reference
indexed configuration requires Multi addressing. Indexed profiles use
real signed uploads and advances for publication-control fixtures. Ordinary
indexed wire cases remain in Tier 1.

A fork fixture query contains `destination`, `signer`, and `source_head`.
`prepare_fork` returns `fork_fixture` with the source repository and head,
`tip`, `packmap`, ordered `packs` and one `objects` entry per pack, and
`advancing_commits`. The source is public and readable by the fixture
signer. It may have a distinct owner so a visibility change can revoke the
forking principal's read access. Its tip/packmap pair must pass content validation once the destination
activates. Repeated preparation for fresh destinations yields the same source
contents and preparatory-commit count; acceptance is excluded from that count.
The count selects observable commit occurrences and imposes no orchestration.

A fork observation query contains `destination`, the original `replay` identity,
and `packs`. `observe_fork` returns `fork_observation`: `accepted`, `failed`,
`writable`, the destination `head`/`packmap`, ordered `staged_memberships` and
`visible_memberships`, `progress_commits`, the saved `result`, `replay`, and
reservation `outcome`. These values coexist at one authoritative observation
point. Internal staging may exist while the destination remains unreadable and
unwritable. Fork itself creates no destination ref. A saved result includes the
source identity, source publication sequence, tip/packmap, pack count and bytes,
object count, sorted-pack-set digest, and membership generation.

`change_fork_source` takes the same `query` as `observe_fork` and one `change`:
`moved` publishes a different head/packmap pair; `unpublished` removes the
admitted publication; `visibility_revoked` commits a visibility change that
makes the source unreadable to the forking principal; `denied` denies
each inherited pack explicitly selected by the nonempty `query.packs` list.
Denial cases use fresh forks and target every imported pack separately, so
checking only a final pack cannot establish conformance. The binding MUST
commit the selected source change before returning success, and MUST NOT modify the destination. The final-proof cases
pause after every queried membership is staged, commit that change, resume,
and require `not_found` / `source not found` with an inert destination. The
post-acceptance cases commit the same changes after durable acceptance and
inspect accepted result, replay and terminal responsibility **before** a replay
can repair or hide loss. They then require the original replay to preserve them.
Source denial does not waive independently applicable destination denial;
these cases assert acceptance stability, not immunity from later takedown.

`fork.invoke` declares the test-only signed bridge at `POST /__mkit_test/fork`,
which uses the canonical body and auth-v2 procedure described in SPEC-SERVER §9.9.
The bridge calls the server's ordinary authenticated fork path. Fixture setup
and snapshots do not replace the cases' destination read/write probes. This
bridge is outside the public transport, like the other controls.

Publication observations include the original acceptance snapshot plus
`published_head`, `published_packmap`, `live_sequence`, `published_sequence`,
`deletion_boundary`, and `published_memberships` in query order. These values
MUST coexist at one authoritative observation point. The snapshot reports
published membership itself, rather than an eventually consistent projection.
Eligibility controls affect future prepares; clearance driving only releases
outstanding work for the selected branch. A server can use separate clearance
and leave `combined-publication` undeclared.

The reliance fixture MUST seed its base through a valid accepted operation and
keep the candidate branch absent. The query declares `purpose: gc` or
`inspection`; a binding must not infer that choice from a ref name. For `gc`,
on return from setup the base has no live or retained publication root,
ticket pin, or hold that independently forbids its
prepared GC drop; any required GC mark and wait have already completed at
the pinned clock. Its accepted membership remains usable. Fixture setup may
construct the required valid history before returning, but must restore the
pinned clock and must not fabricate accepted state. The fixture may
delete its seeding ref through a valid operation to establish this state.
Its returned `pack` contains an external delta base available only in
`base_pack`; `head` identifies the candidate object. `packmap_pack` is an
independent canonical packlist containing the candidate and base, with ID
`packmap`. The `inspection` purpose needs no GC mark or wait history. The
verdict case uploads and accepts the candidate through signed wire requests. GC cases instead create a paired ref using the already accepted
`base_head` and `base_packmap`, without tickets: a candidate ticket would itself
root its external bases and prevent a genuine GC drop. Both original members
remain unrooted before that ticketless attempt. Removal controls never supply
an acceptance result.

The runner pins the business clock throughout these races so ticket age and
the declared membership-lag permission are deterministic. The prepared GC
attempt retains its original recheck proof across the competing acceptance;
a later fresh recheck is outside this race. Hiding the unique base supplies
no replacement and does not change the repository generation. Fixture bytes
are bounded to 1 MiB each. `gc` declares repository membership GC;
`async-inspection` declares verdicts or holds that can hide relied-on members.
Neither is inferred from the unrelated lease or synchronous-inspector flags.

A case requiring an unsupported control is a **declared skip** only when its
stable case name appears with a nonempty reason in the runner's expected-skip
map. An undeclared skip fails; a declared case that passes also fails, so stale
gaps must be removed. Missing wire features report not applicable instead of a declared skip.
A known gap is never a conformance certificate. CI profiles that require a
capability reject skips for it.

**Reference-server behavior.** `test_host::ControlledHost` exposes retained
process-local memory, real core handlers, a manual clock, test admission, and
local authority fencing. It supports the first two boundaries for
`ref_acceptance`, occurrence one, and the uncertain-result action. It rebuilds
the pipeline and cancels old request futures on restart. It declares
`restart.kill` unsupported because retained memory does not prove process,
disk, host, or zone recovery. It also declares `pause.after_response` unsupported
because the client observes receipt. Indexed profiles support
`pause.before_published_clearance`, publication observations, eligibility, and
scoped real clearance driving. Opaque profiles declare these controls
unsupported. Indexed profiles advertise `combined-publication` because eligible
acceptance already includes publication. Repository GC and asynchronous
inspection are not integrated in this host: `gc` and `async-inspection` remain
undeclared, and their removal controls return HTTP 501 without mutation.
The original `TestHost` remains available without these control routes.

The reference control host also provides an indexed, leased fork pipeline on
its isolated stores. Its fork fixture seeds signed canonical contents, sealed
inventories, indexes, and published source membership without creating the
queried destination. Fork requests and ordinary destination probes use the
same authenticated pipeline. The wrapper pauses at source proof, preparatory
commits, and guarded acceptance, and observes all partitions under its mutation
gate. Sixteen fork cases exercise this binding without declared fork skips;
results are established by running the suite, not by the capability declaration.

The HTTP binding above is normative for black-box Tier-2 runs. Every case
uses these routes; an optional in-process trait cannot be required by a case.

The profile declares optional features using `features`: `transport-writes`
(enabled by default; use `-transport-writes` for a read-only target),
`authority-setter` (both wire getter and setter), `authority-fencing`, and `fork`.
Absent feature names mean the feature is not offered. `relay_lag_bound_ms`
declares the membership visibility bound, defaulting to zero. Immediate
membership visibility is conforming; a zero-bound target never returns
`MembershipNotVisible`. Controls and their gaps are negotiated separately.
A missing feature reports **not applicable** with its name, distinct from a
**declared skip** for a known gap in an offered feature. A declared skip for a
non-applicable case fails rather than hiding a stale declaration.

## Protocol coverage and remaining work

Classification applies to the rule, not to reference mechanisms used to test it.
The table tracks [SPEC-SERVER](../../../docs/specs/SPEC-SERVER.md) and
[SPEC-TRANSPORT-CONNECT](../../../docs/specs/SPEC-TRANSPORT-CONNECT.md) requirements.
**Case** means executable portable coverage. **Declared skip** names an
executable case unavailable in the reference profile. **Planned** means a
portable independent assertion still needs implementation; a reference layout
or orchestration audit is supporting evidence, not a portable conformance case.
A planned entry is not a skip and certifies no requirement. Conditional rules
apply when a server offers the feature.

| Rule | Classification | Coverage |
| --- | --- | --- |
| Verification, decision, and acceptance may use separate trusted components, bound to frozen pack ID/length and every relied-on mutable fact, including external delta bases (§3.1) | Protocol requirement | Covered by the acceptance atomicity and guard-matrix cases; topology is not observable. Independent external-delta-base race coverage is planned. |
| Optional wire authority getter/setter is either disabled or accepts a valid deployment-authority statement (§6.2.1) | Protocol requirement when RPCs are offered; disabled rejection otherwise | **Case:** Tier 2 `authority.setter_disabled` requires HTTP 501 / `unimplemented` from both RPCs; `authority.setter_enabled` sets a strictly newer generation and checks the getter. Pending HTTP 503 / `unavailable` requires delay-seconds `Retry-After`; identical statement retries are bounded to 45 seconds, and other refusals fail immediately. Generation races use `bump_authority`, not the wire setter. |
| Eventual membership visibility is permitted, including a zero relay-lag bound (STC §7.9) | Protocol requirement | Existing successful membership wire cases accept immediate visibility. Zero-bound profiles do not require `MembershipNotVisible`; a forced-lag reference fixture is a separate mechanism test. |
| Signed acceptance commits the live pair, replay, applicable quotas, local membership responsibility, ticket closure, and terminal responsibilities together (§3.1; STC §7.7) | Protocol requirement | **Case:** Tier 2 `acceptance.before_acceptance_restart`, `acceptance.after_durable_acceptance_restart`, `acceptance.after_response_restart`; each consumes two tickets and a separate ref reservation, with quota assertions when configured. |
| Failed paired CAS changes neither ref; an observed acceptance has a saved result (§3.1) | Protocol requirement | **Case:** Tier 1 `advance.atomic_both_untouched`, typed-conflict cases, `advance.concurrent_one_committed`, `replay.observed_pair_has_saved_result`. Separate reads do not certify concurrent snapshot atomicity. |
| Replay repeats no acceptance, charge, ticket consumption, or terminal outcome (§3.2) | Protocol requirement | **Case:** Tier 1 `replay.same_op_returns_saved_result_after_ref_moved`, `replay.advance_replay_equals_first_result`, `quota.replay_not_charged`; Tier 2 `replay.moves_and_generation` compares authoritative state. |
| Final authority guard refuses stale ref acceptance with `permission_denied` (§6.2.1) | Protocol requirement when fencing is offered | **Case:** Tier 2 `guard.authority_final_boundary`, covering UpdateRef, paired advance, paired deletion, and ticketed paired advance. It checks unchanged charges, ticket/membership state and ticket reservations, plus exactly one aborted ref reservation. |
| Acknowledged acceptance survives restart; response loss resolves through the original identity (§3.2) | Protocol requirement within the declared durability profile | **Case:** Tier 2 acceptance restart cases observe recovered state before replay and then require replay to leave any recovered acceptance unchanged. **Declared skip:** `acceptance.kill_recovery` for the volatile reference host, which has no process-persistent store. |
| An uncertain storage result never becomes a definite abort or second settlement (§3.2; STC §7.7) | Protocol requirement | **Case:** Tier 2 `recovery.uncertain_commit`, comparing committed state before and after original-identity replay. |
| Cancellation preserves atomicity and never rolls observed accepted state backward (§3.2) | Protocol requirement | **Case:** Tier 2 restart boundaries; optional SPI `dur_cancelled_apply_is_all_or_nothing` supplies reference-adapter evidence. **Planned:** portable cancellation during asynchronous durability work. |
| Acknowledgement and dependent disclosure wait for declared durability; group sync preserves dependencies and final deadlines (§3.2) | Protocol requirement | **Case:** restart cases for the declared volatile profile. Optional SPI durability/deadline cases supply adapter evidence. **Planned:** persistent-host kill/reopen, dependency-closed recovery, group-sync acknowledgement, and ownership/deadline races; memory tests do not certify disk or failover guarantees. |
| Authority mode is optional, independently configured, and fail-closed when facts are missing (§6.2.1) | Protocol requirement when fencing is offered | **Planned:** independent configuration, statement authorization, malformed/missing fact, activation, and disabled-executor cases. Local test-control generation changes do not exercise the signed setter. |
| Namespace/repository registration compares current authority facts without suppressing first-write admission (§6.2.1) | Protocol requirement when fencing is offered | **Planned:** stale creation and activation races with typed registration/accounting observations. |
| Generation-change acknowledgement fences old acceptance; barrier work survives restart, replacement, and restore (§6.2.1) | Protocol requirement when fencing is offered | **Planned:** portable setter/barrier/replacement recovery cases, including missing authoritative state, rollback refusal, and retained unresolved work. The unsharded final-guard case covers only its local decision. |
| Replacing an older-generation ticket atomically closes its reservation and opens the replacement without extra open-ticket allowance (§6.2.1) | Protocol requirement when fencing is offered | **Planned:** replacement/consumption/expiry races, counts, invalidated verification evidence, and crash-safe multipart cleanup. |
| Ticket-only staging, completion, receipts, and verification markers retain authority checks around backend awaits (§6.2.1; STC §7.7) | Protocol requirement when fencing is offered | **Planned:** paused backend writes and completion with generation changes; private buffering is not accepted state. |
| Every granted reservation reaches one terminal result; duplicate sink delivery retains its stable identity (§§3, 5, 6.5; STC §7.7) | Protocol requirement | **Case:** Tier 1 `outcomes.aborted_on_cas_loss`, `outcomes.expired_ticket`, `outcomes.eventual_completeness`; Tier 2 acceptance and uncertainty cases count terminal creation separately from delivery. **Planned:** independent abandoned-reservation reconciliation and sink lost-acknowledgement/restart cases. |
| Remote projection and counter responsibility survives recovery; duplicate delivery applies a logical contribution once (§3.1; §§5–6.5.1) | Protocol requirement | **Planned:** independent source/target restart and lost-acknowledgement cases with typed counters and memberships. Existing reference relay/layout audits do not certify remote exact-once effects. |
| Ticketless creation from a published source retains current source evidence at final acceptance (STC §4.1) | Protocol requirement when offered | **Case:** Tier 1 `advance.from_published` covers ordinary creation. **Planned:** source move, publication/visibility/authority change, and denial at the final boundary. |
| Verification checks integrity, signatures, closure, delta limits, and repository-isolated evidence (§§9.3–9.5) | Protocol requirement when indexed mode is offered | **Case:** existing Tier 1 indexed and repository-isolation cases. **Planned:** independent recovery/checkpoint tests binding retained evidence to content, current denial, expiry, and authorization. |
| Pending-verification waits release attempt-local authority and re-enter all live guards on wake (§9.5) | Protocol requirement when asynchronous verification is offered | **Case:** existing Tier 1 pending-verification cases. **Planned:** deterministic cancellation, wake, deadline, and generation/denial/CAS races. |
| Fork destination membership and writes remain gated before acceptance (§9.9; STC §7.7) | Protocol requirement when fork is offered | **Case:** `fork.destination_gate_before_acceptance`; the reference controlled host executes this assertion. |
| A failed fork destination remains inert (§9.9) | Protocol requirement when fork is offered | **Case:** `fork.failed_destination_inert`; the reference controlled host executes this assertion. |
| Destination creation and fork registration arbitrate atomically | Protocol requirement when fork is offered | **Cases:** `fork.writer_against_registration`, `fork.leased_writer_against_registration`; ordinary signed ticket writes compete at semantic decision barriers. |
| Fork exclusion defeats a competing writer at acceptance | Protocol requirement when fork is offered | **Case:** `fork.writer_against_acceptance`; only fork succeeds. |
| Fork terminal result, replay, and one terminal outcome share guarded acceptance; replay repeats no effects (§9.9) | Protocol requirement when fork is offered | **Case:** `fork.acceptance_result_replay_outcome_atomic`; the reference controlled host executes this assertion. |
| Fork acceptance compares recorded authority facts (§9.9) | Protocol requirement when fork and authority fencing are offered | **Case:** `fork.authority_at_acceptance`; the reference controlled host executes this assertion. |
| Every commit advancing a fork compares recorded authority facts (§9.9) | Protocol requirement when fork and authority fencing are offered | **Case:** `fork.authority_each_progress_commit`; the reference controlled host executes this assertion. |
| Source movement before the final proof refuses uniformly as a missing source (§9.9) | Protocol requirement when fork is offered | **Case:** `fork.source_moved_before_acceptance`; the reference controlled host executes this assertion. |
| Source movement after acceptance does not invalidate its result, replay or terminal responsibility (§9.9) | Protocol requirement when fork is offered | **Case:** `fork.source_moved_after_acceptance`; the reference controlled host executes this assertion. |
| Source unpublication before the final proof refuses uniformly as a missing source (§9.9) | Protocol requirement when fork is offered | **Case:** `fork.source_unpublished_before_acceptance`; the reference controlled host executes this assertion. |
| Source unpublication after acceptance does not invalidate its result, replay or terminal responsibility (§9.9) | Protocol requirement when fork is offered | **Case:** `fork.source_unpublished_after_acceptance`; the reference controlled host executes this assertion. |
| Source visibility revocation before the final proof refuses uniformly as a missing source (§9.9) | Protocol requirement when fork is offered | **Case:** `fork.source_visibility_revoked_before_acceptance`; the reference controlled host executes this assertion. |
| Source visibility revocation after acceptance does not invalidate its result, replay or terminal responsibility (§9.9) | Protocol requirement when fork is offered | **Case:** `fork.source_visibility_revoked_after_acceptance`; the reference controlled host executes this assertion. |
| Source denial before the final proof refuses uniformly as a missing source (§9.9) | Protocol requirement when fork is offered | **Case:** `fork.source_denied_before_acceptance`; the reference controlled host executes this assertion. |
| Source denial after acceptance does not invalidate its result, replay or terminal responsibility (§9.9) | Protocol requirement when fork is offered | **Case:** `fork.source_denied_after_acceptance`; the reference controlled host executes this assertion. |
| Source proof retains admitted membership generation and ordering for changes between proof and acceptance (§9.9) | Protocol requirement when fork is offered | **Planned:** dedicated generation-only mutation and post-proof/pre-commit race cases; source move/unpublication/read-revocation/pack-denial cases cover the decided before-proof and after-acceptance boundaries. |
| Fork source authorization, source visibility consistency, admission bounds, isolation, and recovery remain guarded (§9.9) | Protocol requirement when fork is offered | **Planned:** independent initial authorization, pre-construction visibility-race refusal, admission/join, discarded-attempt re-admission and charge accounting, reservation expiry, destination takedown, and retained-evidence cases. The existing `fork.driver_probe` measures construction and does not establish these guarantees. |
| Published clearance atomically establishes eligible membership and the largest eligible prefix, preserves the pair and deletion boundary, and never settles acceptance again (§10.2) | Protocol requirement | **Cases:** `publication.deferred_restart_no_resettlement`, `publication.out_of_order_prefix`, and `publication.deletion_boundary`; real wire acceptance, restart before replay, atomic snapshots, paused clearance, repeated driving, and original replay. Negative HTTP proxies reject torn publication and duplicate terminal responsibility. |
| Configured publication Events share the pointer-changing clearance unit and identify the resulting prefix; membership-only clearance emits none (§§10.2, 12.4) | Protocol requirement when configured | **Planned:** authoritative configured-Event snapshot and interrupted delivery cases. The reference server has no configured lifecycle Event sink; the binding never fabricates Event evidence. |
| Acceptance may include eligible clearance with every clearance fact guarded (§10.2) | Protocol permission when combined publication is offered | **Cases:** `publication.combined_acceptance` and `publication.combined_deletion_race`, gated on `combined-publication`. A real delete and recreation changes the deletion boundary before the candidate applies. |
| Namespaced embedding guards, evidence, and durable responsibilities commit with acceptance or clearance within a declared atomic domain (§10.4) | Protocol requirement in the draft composition profile, pending architecture review | **Planned:** independent commit/abort, failed guard, declared-domain, replay short circuit, and clearance-without-acceptance-resettlement cases once a composition seam exists. Composition is planned, not a declared skip; no existing binding claims support. |
| Every reader applies the published view, current visibility, repository membership, and denial; hidden state answers uniformly absent (§§9.4, 10.1, 10.3) | Protocol requirement | **Case:** Tier 1 `reads.private_not_found_byte_identical`, private owner/grant cases, repository isolation, and public/private file readback. **Planned:** independent publication/denial changes across every read surface and retained-history continuation. |
| Inspection and private scanner retrieval preserve current ticket, membership, generation, denial, and publication guards (§11) | Protocol requirement when inspection is offered | **Case:** existing Tier 1 inspection refusal cases cover ordinary answers. **Planned:** independent scanner-capability, backend-await, resolution, replay, cancellation, and stale-evidence races. |
| Inspection inputs and fail-closed launch configuration obey the advertised bounds; deferred full-profile batching does not weaken guards (§§11.1–11.3, 18) | Protocol requirement for the selected inspection profile | **Case:** Tier 1 `launch.inspection_rejects_advance` covers configured refusal. **Planned:** independent complete inspected-set, input-bound, scanner startup, asynchronous resolution, and deferred full-profile batching cases. |
| Lease-change completion prevents later use of stale cached terms or authority (§12) | Protocol requirement when storage leases are offered | **Planned:** independent cache/lease staleness and bounded-completion tests. Namespace epoch-lease wire cases cover a different feature. |
| GC retains every live, published, uncleared, ticket, hold, replacement, and preservation root; incomplete discovery fails closed (§13) | Protocol requirement when GC is offered | **Planned:** portable root snapshots, concurrent acquisition/removal, membership drop, global deletion, and restart/recovery cases. Reference key/mark/holder audits remain supporting evidence only. |
| A newly relying acceptance defeats an earlier GC drop proposal through mark clearing or a repository reliance version (§13.3) | Protocol requirement when GC is offered | **Cases:** `reliance.gc_drop_before_acceptance` and `reliance.gc_drop_after_acceptance`, gated on `gc`. They attempt the original drop before and after a real signed ticketless acceptance. The competing case accepts either conforming reliance mechanism and requires exactly one winner. The reference profile does not offer integrated GC; cases are not applicable. |
| Membership generation and removal version guard every relied-on member's continued usability, paired with the reliance fence (§13.3.1) | Protocol requirement when this witness is used | **Case:** `reliance.verdict_hide_delta_base`, gated on `async-inspection`; a real verdict races a signed external-delta acceptance. **Audit:** removal inventory includes §§11.2–11.3, 12.2, 13.3–13.4, and 14.4; per-ref deletion changes neither version. Independent denial, lease, and authorization guards remain required. The reference profile does not offer asynchronous member hiding. |
| Takedown discovers all affected members, including inherited and external-base dependencies, and preserves current denial during rewrite/substitution (§14) | Protocol requirement when takedown is offered | **Case:** Tier 1 `takedown.contract` and `takedown.persisted_denial` cover immediate and persisted denial. **Planned:** independent discovery completeness, rewrite, preservation, replacement, and recovery races. |
| Restore/recovery preserves authoritative fences, unresolved work, replay, and denial (§§6.2.1, 14.9, 17) | Protocol requirement for the offered recovery profile | **Planned:** independent import/restore and interrupted-recovery cases; reference layout export/import audits do not certify protocol recovery. |
| Admin replay completes the original operation and audit responsibility survives interruption (§16) | Protocol requirement when admin is offered | **Case:** the takedown contract checks restricted admin status. **Planned:** independent interrupted admin acceptance, operation replay, audit completion, and recovery cases. |
| Profile advertisement matches implemented capabilities, retention, limits, and the declared launch/admin scope (§18; STC §2.1) | Protocol requirement | **Case:** existing Tier 1 server-info and enabled takedown contract checks. **Planned:** independent unsupported-configuration refusal, declared namespace coverage, resource-exhaustion classification, and launch subset boundary cases. |
| Protocol boundary controls remain test-only and disabled without the test feature (§18.1) | Protocol requirement for this test interface | **Case:** control-host negotiation/rejection tests and `public_service_has_no_test_control_routes`; the reference host requires an explicit test feature; optimized test utilities additionally require `reference-runner`. |
| Deterministic protocol decision equivalence across implementations | Test runner guarantee | **Case:** native two-host differential acceptance, replay, paired-CAS and refusal fixtures; comparator mutation tests. This does not claim crash, recovery, or concurrency coverage. |
| Standalone runner profile, separate control binding, and JSON exit status | Test runner interface | **Case:** runner profile/report tests, CLI tests, and `controlled_cases_keep_transport_requests_on_the_transport_origin`. |
| Reference NamespaceStore transaction, key, batch, and timer mechanisms | Reference-server behavior | **Case:** the optional `storage-spi` suite and reference host tests; these mechanisms are not requirements for other servers. |

## In-process test host

Contract tests that need real loopback HTTP can use the debug-only
`test-host` feature. It runs the production core Connect handlers over fresh
`MemoryKv` and `MemoryBlobStore` instances and exposes the same profile shape
as the wire suite. This is an unstable test-support API. Optimized builds reject
the feature unless the standalone test utility opts into `reference-runner`.

Pin the feature-enabled dependency to the same mkit revision as the other
contract-test dependencies:

```toml
[dev-dependencies]
mkit-server-conformance = { git = "https://github.com/officialunofficial/mkit", rev = "<same-revision-as-mkit-dependencies>", features = ["test-host"] }
```

```rust,ignore
use mkit_server_conformance::test_host::TestHost;
use mkit_server_conformance::wire::{Profile, WireAuth, WireTarget, run};

let profile = Profile::new(WireAuth::AuthV2 {
    audience: String::new(), // replaced with the allocated canonical origin
    repository: "default".into(),
    seed: [0x5e; 32],
});
let host = TestHost::start(profile).await?;
let target = WireTarget {
    base_url: host.base_url().parse()?,
    profile: host.profile().clone(),
};
let report = run(&target, None).await;
// Run the consumer's shared contract macro/report assertions here.
host.shutdown().await;
```

`TestHost::start_with_hooks` accepts a consumer's core `HookSet`, including
scripted admission and outcome hooks. `start_with_hooks_factory` supplies the
allocated server origin and manual clock so callers can connect `RemoteAdmission`
to `stubs::hook::FakeHook` through `LoopbackHookChannel`. `clock()` returns a deterministic
`ManualClock`; advance it explicitly and call `drain_core_timers()` with a
partition and budget when a case needs timer delivery. `drain_timers()` accepts
a custom core `TimerRegistry` for tests that need to control the handler set.
Drains have a finite executor-poll budget. A handler or outcome sink that stays
pending returns an unavailable error; its uncommitted timer remains queued.
Each host owns its stores and listener. Dropping it aborts the listener task.

## Portable file and takedown contracts

The shared registry includes `health.deadline_headers`, which
exercises absent, finite, paired and malformed headers over Connect and gRPC;
the existing runtime probe also covers zero timeouts, configured defaults and
all supported wasm dispatch entry points. Native stalled-body deadline tests
remain in `mkit-server`.

`files.empty_readback`, `files.deep_tree`, `files.long_path`,
`files.byte_distinct_names` and `files.path_limits` publish canonical packs and
paired refs through the ordinary transport. Names stay in memory as bytes;
checkout filesystem normalization and case sensitivity cannot change them.
A 100-directory tree round-trips over the ref route. A 2048-byte core path
round-trips through disclosure lookup and object-ID HTTP reads; its ref URL
returns 400 under the specified 1024-byte HTTP limit. Separate boundaries cover
128/129 authenticated core steps, 255/256-byte components and 1024/1025-byte HTTP
paths. `embedding.multipart_file_readback` retains the existing binary payload
and multipart upload, adding GET/HEAD, metadata, conditionals and exact ranges.
Committed advances can precede published indexes. Fixture setup uses bounded
HEAD readiness for each positive HTTP selector, then runs immediate exact
byte/metadata/range assertions. Negative bounds and all takedown denial checks
remain immediate. Private token setup also waits for published membership before
minting the token and checking its HTTP selector; an owner live ref is insufficient.
The Worker observer rejects zero-length R2 ranges; the core HTTP spy also checks
backend range geometry and absence of an empty payload fetch.

`takedown.contract` requires `takedown`, `admin`, `signed-reads`, indexed HTTP
objects and ticketed multi-repository transport. Use a fresh private-by-default
fixture with the synthetic operator key used by the runtime probe. It publishes
the same content into public and private repositories, proves public/ref reads,
private URL-token reads and signed owner downloads work, accepts signed admin
Takedown, and asserts their denial plus restricted admin status. Failure to provide
the enabled capability fails the test. It never silently skips setup failures.
The token stays in an exclusive, mode-0600 scratch file and never enters TAP.

Restart the server over the same stores, origin and configuration, then run
`takedown.persisted_denial` with the original run ID and signer seed. This checks
the original token, owner download, public/ref denial and admin identity/selectors,
then deletes the scratch capture. It fails when the producer capture is missing.
The native test host mounts the two signed admin routes for this profile and
`restart_with_default_hooks()` rebuilds its listener, pipeline and admin engine
over the same metadata, serving and preservation stores. This fixture does not
assert preservation completion; the full admin rehearsal covers acquisition,
legal hold, retention and audit separately.

```sh
python3 scripts/connect-deadline-runtime.py --portable
```

This pinned local workerd run prints all nine selected wire cases (eight new,
one extended), rejects missing/skipped cases, restarts its own process over
persisted state, and checks the R2 observer ran. Hosted Workers CI invokes it.
It proves local runtime behavior, not cloud placement or production timing.

The coverage audit found existing one-winner and atomic-advance races,
`replay.expired_retry_rejected`, nonce/different-operation rejection,
`admission.concurrent_duplicate_during_admit`, repository isolation, private
owner/grant/non-owner reads and URL-token visibility revocation. These seeds add
no duplicate race/replay/privacy-only variants, URL staging or product policy.

The separate `pack-location-fixtures` profile flag requires negotiated test
controls `pack-locations.fixture` and `clock.advance`. It adds portable wire
cases for denied, held, pending and unauthorized private content, repository
isolation, denial after issue within the advertised bound, and corrupt-location
verification followed by exactly one streaming retry. These cases use only HTTP
and protocol identities; an external disposable server can implement the same
controls. The actual client implementation is exercised independently by the
`client_verifies_corrupt_location_and_retries_streaming_once` integration test.

The additive version-1 test-control request is:

```json
{"operation":"pack_location_fixture","repository":"ed25519-<public-key>/locations","pack":[1,2,3],"state":"available"}
```

`pack` is a nonempty byte array of at most 64 KiB. Its hash identifies the pack.
States are `available`, `held`, `pending`, `private`, `denied`, and `corrupt`.
The fixture establishes real repository membership and the selected serving
state. `corrupt` preserves the exact body length and changes location bytes;
streaming remains correct. `denied` is irreversible, so each scenario uses fresh
bytes. `advance_clock` uses the existing control request and must advance both
the server's business clock and location expiry enforcement. These controls are
disposable test infrastructure and must never be mounted on a production server.

Existing test-control implementers can retain their current handlers and report
`pack-locations.fixture` as unsupported; enable `pack-location-fixtures` only
when implementing this additional command. The reference test host exposes it
only under that explicit profile flag and requires indexed Multi addressing
with auth v2 for its security fixtures.

The wire runner executes cases sequentially. The denial-after-issue probe is the
last registered case because it advances the disposable host clock by the
advertised lifetime. Fixture-served locations must enforce expiry against that
same clock. The probe retains the advanced time and never resets it backwards;
use a fresh disposable host when starting another independent full-suite run.
