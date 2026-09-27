## Purpose

The M1 upload lifecycle (STC §7.6–§7.7, SPEC-SERVER §3/§5) needs new rows in a ref shard:
- **tickets**, with an idempotency index and open-ticket counters for caps;
- **reservations and their outcomes**, which is the "exactly one outcome" state machine;
- **local membership** of packs in the repository;
- **the outbox:** outcome rows for delivery, relay rows that propagate membership to repo index shards, a sequence,
  and a backlog counter.

This WP fixes their byte layouts and codecs, and provides pure, deterministic planners that emit `Precondition`s and
`Write`s. The WPs that wire them compose these fragments into their batches.

## A. Fixed by the plan and specs (do not change)

1. **Plan:** `m1-m2-breakdown.md` "WP-1.7" (lines ~202–218), and the consumers "WP-1.9", "WP-1.10", "WP-1.14" and
   "WP-1.23"; `m3-m5-breakdown.md` "WP-3.3"; `00-plan.md` R-04 (`tickets_open`), R-35/R-49 (`oc` backlog), R-37 and
   R-91.
2. **Specs:**
   - STC §7.6: tickets are 32-byte ids, expire in under 7 days, and bind (audience, repo, signer, pack_id, bytes);
   - STC §7.7: which apply writes what; exactly one outcome per reservation;
   - STC §7.9: ref-shard membership backs `X-Mkit-Ref` reads;
   - SPEC-SERVER §3 rules a–e and §5: the pending-record arbiter; every replacement conditional on still-pending;
     `Aborted(ABANDONED)` by reconcile; `Expired` only for tickets; backlog bound;
   - SPEC-SERVER §6.6: `reservation_id` is 1–128 bytes of `[A-Za-z0-9._:-]`.
3. **M0-02a key registry** (`briefs/WP-M0-02a.md:217, 232–236`): membership is `m 00 <repo> 00 <pack:32>`. `oc` is
   written by 1.7 and enforced by 3.3. Tags that prefix each other terminate with `00`.
4. **Store limits (`kv.rs`):** `MAX_KEY_BYTES` 1024, `MAX_VALUE_BYTES` 512 KiB, `MAX_BATCH_OPS` 100, `MAX_BATCH_BYTES`
   1 MiB.
5. **Codec style (`store/codec.rs`):** `CODEC_V1` plus serde JSON; DTOs with `deny_unknown_fields` and validating
   decodes; golden and rejection tests (follow WP-1.22's `NamespaceRecord`).
6. **Timer kinds (`timers/registry.rs`):** WP-1.25 takes **kind 1** (`LEASE_SWEEP`). **This WP takes kind 2**
   (`TICKET_EXPIRY`).
7. **No physical migration, and `LAYOUT_VERSION` stays 1.** Only new key classes are added.

## B. Decided by the orchestrator (do not change)

### B.1 Module home

Add public, pure modules, following the `ContentIndex` precedent in `store/` (so conformance can drive them):
- `rust/crates/mkit-server/src/store/tickets.rs`: tickets, counters, the expiry timer and membership;
- `rust/crates/mkit-server/src/store/outbox.rs`: reservations and outcomes, relay rows, sequence and backlog.

Export them as `mkit_server::store::{tickets, outbox}`. Planners are deterministic: no clock, no randomness (callers
pass `now_ms`).

### B.2 Key layouts (exact; each with golden bytes in `keys.rs` tests)

Remove `t`, `m`, `o`, `oq`, `os` and `oc` from `RESERVED_TAGS`. New tags: `ti`, `tc`, `tu`, `or`. Every new tag must
pass `class_scans_never_overlap`.

| Class | Key | Value |
|---|---|---|
| ticket | `t 00 <ticket_id:32>` | codec `TicketV1` |
| ticket idempotency index | `ti 00 <repo> 00 <ref> 00 <pack:32> <signer:32>` | raw 32-byte ticket id |
| open tickets per ref | `tc 00 <repo> 00 <ref>` | be64; absent means 0; deleted at 0, never written as 0 |
| open tickets per (ref, signer) | `tu 00 <repo> 00 <ref> 00 <signer:32>` | be64, same rules |
| ticket expiry timer | `keys::timer(expires_at_ms, TICKET_EXPIRY, <ticket_id:32>)` | empty |
| local membership | `m 00 <repo> 00 <pack:32>` | empty |
| reservation and outcome | `o 00 <reservation_id>` | codec `ReservationV1` |
| outcome pending index | `oq 00 <seq:be64> <reservation_id>` | empty |
| relay queue | `or 00 <seq:be64>` | codec `RelayV1` |
| outbox sequence | `os 00` | be64 last allocated; starts at 1; never deleted |
| outcome backlog | `oc 00` | codec `Backlog { rows: u64, bytes: u64 }`; absent means zero |

- Add `ParsedKey` variants and `parse` arms for every class.
- Constructors validate: `reservation_id` against §6.6, and every key under `MAX_KEY_BYTES`, with the worst case
  `ti` asserted in a `const`.
- Allocate `kinds::TICKET_EXPIRY = TimerKind::new(2)` and update the kinds table. **Register no handler** (that's
  WP-1.14).

### B.3 Codecs (`store/codec.rs`)

- **`TicketV1`:**
  - `{ repo, ref_name, signer: hex32, pack_id: hex32, bytes: u64 (>0), part_size: u64 (power of two, ≥
    mkit_core::upload_parts::MIN_PART_SIZE), expires_at_ms, created_at_ms, reservation_id, upload_session:
    Option<String> }`;
  - `deny_unknown_fields`, with a validating decode.
- **`ReservationV1`:** a `state`-tagged enum with these variants:
  - `Ticketed { ticket_id: hex32 }`;
  - `Committed { bytes_stored, new_to_repo, new_to_store, refs: [{ name, new: Option<hex32>, deleted: bool }] }`;
  - `Aborted { reason: AbortReason, detail (≤512 bytes) }`;
  - `Expired {}`.

  Terminal variants also carry `repository` and `occurred_at_ms`. `AbortReason` mirrors the hooks proto's names
  (`REF_CONFLICT`, `EPOCH_MISMATCH`, `PACK_MISSING`, `REPLAY_RACE`, `INTERNAL`, `ABANDONED`).
  - **Leave room for WP-3.3:** document that `Pending { … }` and `ReadServed { … }` are added later under
    `CODEC_V1`. Unknown `state` values fail decode, which is fail-closed.
- **`RelayV1`:** `{ target: hex(Partition::encode), puts: [[key_hex, value_hex]] }`, generic idempotent upserts only.
- **`Backlog`:** `{ rows, bytes }`.

### B.4 Reservation ids when admission returns none

Default admission returns no reservation. Provide
`outbox::synthetic_reservation_id(replay_scope: &Hash) -> String` = `"s:" + lowercase hex(replay_scope)` (66 bytes,
a valid charset), and `tickets::ticket_id(reservation_id: &str) -> [u8; 32]` = BLAKE3 of
`b"mkit.ticket.v1\n" ‖ reservation_id`.

The wiring WPs use the admission's id when present, and the synthetic id otherwise, so M1 tickets still get outcome
rows. Add row `R-99` to `00-plan.md`:

> WP-1.7: a ticket whose admission returned no reservation id uses `s:<hex replay scope>`, and its ticket id is
> derived from the reservation id, so tickets always have exactly one outcome row. Admission-supplied ids are unique
> per audience (SPEC-SERVER §6.6), and the `Absent(o rid)` guard detects duplicates within the ref shard that holds
> the row.

### B.5 Planners (public API; the signatures are fixed and the internals are yours)

```rust
// tickets.rs
pub struct TicketSpec { repo, ref_name, signer: [u8;32], pack_id: [u8;32], bytes, part_size, expires_at_ms, created_at_ms, reservation_id, upload_session: Option<String> }
pub struct TicketCaps { pub per_ref: u64, pub per_signer: u64 }
pub struct TicketReadKeys { /* t?, ti, tc, tu, o rid */ }        // pub fn keys(&TicketSpec) -> TicketReadKeys
pub struct TicketReads { /* the Option<Value>s for those keys */ }
pub enum TicketPlanError { Existing(TicketV1), CapExceeded { per_ref: bool }, Corrupt(StoreError), Invalid(&'static str) }
pub fn plan_ticket_open(spec: &TicketSpec, reads: &TicketReads, caps: TicketCaps,
                        pre: &mut Vec<Precondition>, writes: &mut Vec<Write>) -> Result<[u8;32], TicketPlanError>;
pub enum CloseReason { Consumed, Expired }
pub fn plan_ticket_close(ticket_id: &[u8;32], ticket: &TicketV1, ticket_value: &Value, ti_value: Option<&Value>,
                         tc: Option<&Value>, tu: Option<&Value>, why: CloseReason,
                         pre: &mut Vec<Precondition>, writes: &mut Vec<Write>) -> Result<(), StoreError>;
pub fn plan_membership(repo: &RepoName, packs: &[[u8;32]], source: &Partition, shards: &dyn ShardMap,
                       repo_id: &RepoId, outbox: &mut OutboxBuilder, writes: &mut Vec<Write>);

// outbox.rs
pub struct OutboxBuilder { /* reads os, oc once */ }
impl OutboxBuilder {
    pub fn new(os: Option<&Value>, oc: Option<&Value>) -> Result<Self, StoreError>;
    pub fn reserve(&mut self, rid: &str, ticket_id: [u8;32], prior: Option<&Value>);            // Absent(o) + put Ticketed
    pub fn outcome(&mut self, rid: &str, prior: &Value, terminal: Terminal);                     // Equals(o) + put terminal + oq + backlog
    pub fn relay(&mut self, target: &Partition, puts: Vec<(Key, Value)>);                       // or row, grouped by target
    pub fn finish(self, pre: &mut Vec<Precondition>, writes: &mut Vec<Write>);                  // one guard + put each for os/oc if touched
}
pub fn plan_ack(rid: &str, value: &Value, oq_seq: u64, oc: Option<&Value>, pre: &mut Vec<Precondition>, writes: &mut Vec<Write>) -> Result<(), StoreError>;
pub const MAX_TICKETS_PER_ADVANCE: usize = 7;   // with a const assertion that the worst-case ops fit MAX_BATCH_OPS
```

**`plan_ticket_open`:**
- Uses the idempotency index `ti`:
  - pointing at a live ticket → `Err(Existing(ticket))`, with no writes;
  - pointing at an expired ticket (`expires_at_ms <= now` is the caller's decision: take `now_ms` in the spec, or
    as a param) → overwritten with an `Equals` guard.
- Writes:
  - `Absent(t)` + put;
  - the `ti` guard + put;
  - both counters, guarded and incremented;
  - the expiry timer;
  - `OutboxBuilder::reserve`, which the caller finishes.
- It checks caps against the read counters: at the cap → `CapExceeded`.

**`plan_ticket_close`:**
- `Equals(t, ticket_value)`: the `tickets_open` precondition (R-04);
- delete `t`;
- delete `ti` only if it names this id;
- decrement both counters, deleting a counter at 0.

On `Consumed` it leaves the expiry timer: WP-1.14's handler treats a missing ticket as a no-op. The terminal outcome
is written by the caller through `OutboxBuilder::outcome` (`Committed` or `Expired`).

**`plan_membership`:**
- Puts `m` in the source partition for each pack.
- Queues a relay row only when `shards.membership(repo_id, pack) != *source`. Under `SinglePartition` that's a no-op.
- Relay puts use the identical `m` key and value (WP-1.23 applies them in `RepoIndex` shards).

**`OutboxBuilder`:**
- Allocates `seq` from `os`, starting at 1, monotonic, and emits exactly one guard and put on `os` per batch.
- `oc` counts **terminal outcome rows only**. `bytes` is the key length plus the value length of each terminal `o`
  row, so decrements on ack are exact.
- Relay backlog is not in `oc`; that's WP-1.23's own metric.

### B.6 Budget

- Per consumed ticket, the worst case is:
  - `Equals t`, delete `t`, delete `ti`;
  - `Equals o`, put `o`, put `oq`;
  - put `m`, and one relay put share.
- Per distinct signer: 2 counter ops. Shared ops for the head/packmap CAS, replay, `os`, `oc`, `NotAfter` and the
  lease guard: at most 20.
- `MAX_TICKETS_PER_ADVANCE = 7` must hold that under `MAX_BATCH_OPS` = 100. Prove it with a `const` assert over the
  documented worst case, and with a planner test that builds the maximal batch and runs `Batch::validate`.
- WP-1.10 enforces the limit on the wire, and adds the STC note. **Not this WP.**

### B.7 Doc fixes (exact)

- `m3-m5-breakdown.md` WP-3.3 "Risks": replace "emits `Expired` for reservations with no outcome past ticket expiry"
  with "records `Aborted(ABANDONED)` for pending reservations past their authentication validity (SPEC-SERVER §5,
  R-91); ticket reservations get `Expired` at ticket expiry".
- `keys.rs` module doc table: all the new classes.
- `INVARIANTS.md`: a section "Ticket, reservation and outbox rows keep exactly one outcome per reservation".
- CHANGELOG entry.

### B.8 Explicitly not in this WP

- Wiring into RPCs.
- Cap values and the ticket TTL (1.9 decides; suggest per (ref, signer) 64, per ref 1024, TTL 24 h in the PR's
  carry-forward).
- The expiry handler (1.14).
- The relay timer and its application (1.23).
- Delivery, `Pending`, reconcile and backpressure enforcement (3.3).
- `BeginUpload.ref` normalisation (1.9: carry-forward, refuse `refs/mkit/packmap/*`).
- A different signer consuming a ticket (1.10).

## C. Your decisions

- The internals of the planners and helper names beyond B.5's signatures.
- Whether `now_ms` goes in `TicketSpec` or is a parameter.
- Test organisation.
- Any additional private helpers.

## Tests (required)

1. **Keys:** golden bytes for every class; parse round-trip; `class_scans_never_overlap` including the new tags; the
   worst-case `ti` fits.
2. **Codecs:** golden bytes, round-trip, and rejection lists (bad hex, `bytes == 0`, `part_size` not a power of two,
   an unknown field, an unknown `state`, a `detail` over 512 bytes, a bad reservation-id charset).
3. **Planners, pure:**
   - open (new), open (existing → `Existing`), open over an expired `ti`;
   - both cap paths;
   - close consumed and close expired: counters decremented and deleted at 0;
   - `tickets_open`: a changed `t` makes the batch fail its precondition;
   - outbox `seq` monotonic across builders;
   - `oc` exact across outcome then ack;
   - relay grouping;
   - the membership no-op under `SinglePartition` and relay under `D34Shards`;
   - the maximal advance batch validates.
4. **Storage and planner cases** (the conformance storage suite, a new `kv_cases` module), over memory and SQLite, with
   the RefsOnly stores skipped via `need_all_classes`/`need_atomic`:
   - ticket create, then an idempotent re-create for the same (signer, ref, pack) finds `Existing`;
   - the atomic "refs + membership + outcome" batch commits all or nothing;
   - a failed precondition writes nothing;
   - ack deletes the `o` and `oq` rows and decrements `oc`.
5. Goldens unchanged except the new key and codec entries.

## D. Escalate (stop and report) if

- The B.6 worst case can't fit `MAX_BATCH_OPS` with 7 tickets. Report the real count, and don't lower the constant
  silently.
- A B.2 tag collides in `class_scans_never_overlap` with WP-1.25's `el`/`ls` after rebasing.
- SPEC-SERVER §5's arbiter rule can't be expressed with `ReservationV1` as a single guarded key.

## Gates

- `just ci-server`
- `cargo nextest run --locked -p mkit-server -p mkit-server-conformance -p mkit-server-native --all-features`
- the wasm32 check of `mkit-server`
- goldens as above
