# Repairing a corrupt relay row

A `corrupt relay row; tick stopped` warning identifies the source partition
and queue key. Delivery applies the decodable prefix first, then retains the
corrupt row and retries. It never skips that row: advancing a target's `rh`
past an unknown update could permanently lose membership or index state.

1. Stop writes and timer delivery for the affected source. Keep unrelated
   sources running. Capture a backup of the source and affected targets
   before changing any row; preserve the original corrupt bytes and logs.
2. Decode the logged key with `store::keys::parse`: it must be an `or` row
   with a nonzero sequence. Inspect its value with `codec::decode_relay`.
   Check the original committed batch or a trustworthy backup to recover
   the exact target, puts, and plan-time `at_ms`. The target must be the
   original partition, including its namespace and repository.
3. Rebuild the value with `codec::encode_relay`. Validate that its puts fit
   one target batch, including the guarded `rh` update, using `Batch::validate`.
   If the exact original row cannot be recovered, keep the source paused
   and restore from a trustworthy backup. Do not infer missing membership
   from another repository, delete the row, or fabricate a watermark.
4. Replace only that value through an atomic source batch guarded by
   `Equals(queue_key, original_corrupt_value)`. Retain the sequence key,
   `os`, and every target `rh`. A failed guard means the source changed;
   repeat the inspection before attempting another replacement.
5. Resume delivery with its retained RELAY timer. If maintenance removed
   the timer, atomically schedule kind 3 with an empty reference and value
   using `keys::timer(now_ms, kinds::RELAY.get(), b"")`. Observe the queue
   drain and target membership; a retry after target commit remains safe
   because the source/target watermark deduplicates it.

Use the backend's controlled maintenance connection or guarded
`NamespaceStore::apply`; no public repair RPC exists. On Workers, preserve
the class/placement mapping and keep `WORKERS_PLAN` consistent with the
account. RefShard is the only class with relay delivery registered.

Restoring an older source snapshot is a separate recovery operation:
raise its `os` above every target's `rh` for that source or re-key it
before new writes (R-102; WP-1.29). Never lower or prune target watermarks.

Per-fire inspection remains bounded by `4 × max_rows` and 4 MiB of encoded
queue rows. The source's persistent `rs 00` scan row lets the next fire resume
past retained rows for blocked targets, while preserving the per-target order
invariant. A cycle resets after its observed `os` or when its 32-target blocked
set fills. With fewer than 32 distinct failing targets ahead of a healthy
target, a blocked backlog cannot hide that target indefinitely. Repair failing
destinations when the cap is reached; the next cycle retries their rows.

Only failed destinations join the blocked set. A fire that reaches its target
budget pauses before the next target, and a fire with no delivery backs off.
Deleting the source's `rs 00` scan row is always safe: the next fire starts a
fresh cycle from the head. The relay also replaces a corrupt `rs 00` value
under a guard and logs a warning.
