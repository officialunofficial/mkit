## Purpose

GC (SPEC-SERVER §13.3) and takedown (§14) wait until the **namespace relay watermark** passes a point in time. The
watermark is the time before which every relay row, from every shard of the namespace, has been delivered.

This WP makes the coordinator track that watermark:
- per shard, as a running maximum;
- with lease-table rows retained while a shard's outbox is undelivered;
- exposed to consumers as the minimum across shards.

## A. Fixed (do not change)

1. **R-106:**
   - the coordinator keeps the running maximum per shard, because WP-1.23a's per-source lower bound can move
     backwards;
   - an `ls` row is retained while its shard's outbox is undelivered;
   - `namespace_relay_watermark()` is the minimum across shards.
2. **P-15:** the relay-lag bound is 60 s. **R-110:** delivery can exceed it, and consumers must tolerate that.
3. **SPEC-SERVER:**
   - §13.3: GC waits until `now > mark + MAX_APPLY_WINDOW + margin` **and** the watermark has passed that point;
   - §13.5: an unreadable watermark or active-shard table aborts GC.
4. **Takedown.** #1180's fix round waits until the watermark passes `takedown time + MAX_APPLY_WINDOW + margin`. The
   consumer adds `margin`.
5. **Revocation.** `revoke_step` and `push_and_ack` skip expired `ls` rows, so keeping expired rows does not affect
   revocation.

## B. Decided (do not change)

### B.1 Pull at lease expiry, not push on drain

This replaces P-23's "report when the outbox drains". Reporting on every drain would cost about one coordinator write
per ref write.

### B.2 `LeasedShard`

Add `relay_watermark_ms` (the running maximum) and `sweep_due_ms`. Nothing is deployed, so change the V1 codec and its
goldens in place.

### B.3 Renewal

On the renewal path only, `admit_lease` calls `relay_watermark(meta, p, now)` alongside the coordinator `get_many`.
`grant_batch` writes `max(old, reported)` and keeps the old value, even from an expired row.

- **Cost:** one extra scan call on renewal only. A new or expired shard goes from 4 calls to 5; steady-state writes stay
  at 2.
- **Ops:** none added to either batch. Assert this.

### B.4 `LeaseSweep`

`LeaseSweep` gets a client from the coordinator to its shards, generic like `RelayHandler`. At `now ≥ expires` it reads
the shard's `relay_watermark`. Writes under the expired lease can no longer commit, because `NotAfter` is expiry minus
margin.

| Shard outbox state | Action |
|---|---|
| Empty | Delete the row, guarded on its value. |
| Not empty | Raise the maximum, keep the row, and reschedule about 10 s later via `sweep_due_ms`. |
| Read or decode fails, or no client is configured | Keep the row (fail closed). |

Further rules:
- **Budget:** one subrequest per fire. Cap fires per tick at 32, and at 16 on the Workers Free plan.
- **Timers:** fix the stray-timer case. A renewal over a kept row must leave **exactly one** sweep timer; key the timer
  delete on `sweep_due_ms`.

### B.5 API

- `namespace_relay_watermark(store, coordinator, now)` returns the minimum of `now` at scan start and every row's
  maximum.
  - It pages through the table and is resumable with a checkpoint, like `revoke_step`.
  - It returns an error on any undecodable row.
- Add a pipeline wrapper plus `active_shards(ns, cursor, limit)`.
- **Single sharding:** the watermark is `relay_watermark(Namespace partition)`.
- **Docs must state:** consumers add `margin`, and the result is **not** monotonic across recovery.

### B.6 Recovery fence

- **Lease-table recovery:** while an `lr` marker exists without a later reconcile marker, the watermark API returns a
  `Recovering` error. GC and takedown then fail closed.
- **Restore driver:** it resets each restored `ls` maximum to 0. For every restored ref shard that still has relay rows,
  it creates a kept `ls` row: expired, watermark 0, sweep timer due.
- **Reconciling a lost lease table without a restore** is deferred to R-116.

### B.7 Plan

Add row **R-127**:

> WP-1.23c.
> - The watermark is pulled at lease expiry, replacing P-23's drain push.
> - The running maximum lives in `LeasedShard`.
> - `ls` rows are kept while an outbox is undelivered.
> - The API is `namespace_relay_watermark` / `active_shards`; consumers add `margin`.
> - The watermark is unavailable after lease-table recovery until R-116.
> - **Invariant, binding on WP-4.10, 5.3b, 5.6 and 5.7b:** a batch that appends relay rows MUST carry an epoch lease
>   on its source shard, and only ref shards are relay sources. A new relay source needs its own watermark design.

Add an INVARIANTS entry for the same invariant, and a CHANGELOG entry.

## C. Your decisions

- The client injection for `LeaseSweep` on native and on Workers.
- The checkpoint encoding.
- Test organisation.

## D. Escalate (stop and report) if

- The renewal path can't read the shard watermark without a JS await that opens the input gate on Workers.
- The ops-zero claim in B.3 doesn't hold.
- Production changes exceed 1,500 lines. The fallback split is 1.23c-1 (core and native) and 1.23c-2 (the Worker
  `LeaseSweep` client, restore and conformance).

## Tests (required)

1. With the relay-delay fault and lease expiry, the row is kept until the outbox drains, then deleted. If no
   relay-delay fault exists yet, add a minimal test-faults directive for it; WP-1.28b reuses it.
2. **Property test:** over random writes, renewals, relay fires, sweeps and clock steps, the namespace watermark never
   passes the commit time of an undelivered row.
3. A later, lower report doesn't lower the stored maximum.
4. A stuck target, an undecodable row, and an unreachable shard or missing client all hold the watermark.
5. Renewing over a kept row leaves exactly one sweep timer.
6. Revocation completes with kept rows present.
7. A multi-page scan, with inserts during the scan.
8. Single sharding.
9. Restore resets the maximum and creates kept rows.
10. The Workers per-tick subrequest cap.

## Gates

- `just ci-server`
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-worker --all-features`
- the wasm32 check and the worker build
- `scripts/vcs-worker-conformance.sh` (default, and `--sharding d34 --test-faults`)
