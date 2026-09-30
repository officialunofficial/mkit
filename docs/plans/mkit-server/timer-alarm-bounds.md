# Bounded physical timer alarms

A Worker Durable Object can hold multiple logical partitions. Its physical alarm
shares one `TickState` across raw head enumeration and every partition handler:
512 examined rows, 128 committed batches, 32 handler attempts per kind, and
10,000 injected-clock milliseconds. Handler overrides can lower the per-kind
allowance. Failed attempts consume it. Retry moves count as committed batches.
The elapsed limit stops the next operation; it cannot cancel an operation already
in flight. The final one-row schedule probe is reserved before work starts. When the
commit or clock allowance expires, the driver stops without that probe and
conservatively schedules another alarm to reconcile the remaining work.

Enumeration reads raw `(key, part)` rows through the existing `kv_timers` partial
index, in windows of at most 64 rows with SQL `LIMIT`. It does not aggregate all
rows or collect all logical heads. Partition scans also account for their SQL
lookahead row. Native startup rebuilds its in-memory directory by paging the
same bounded indexed query; its complete startup directory is not a Worker alarm.

An isolate keeps a volatile `(key, part)` cursor. It advances through visited rows
and rotates back to the beginning after reaching the end. No durable cursor,
new table, key tag, timer kind or cross-partition protocol is introduced.

Cold fairness comes from the timer rows themselves. When a kind is unknown or a
handler fails, the driver atomically moves the retained row to a future due time,
guarding the exact old value and requiring the destination to be absent. The
move preserves its kind, reference, original handler due time and payload. It
commits no abandoned handler effects. Backoff starts at five seconds, doubles,
and caps at ten minutes. Because the new due time and attempt survive a restart,
retained failures move behind later due work even when every alarm is cold.
Timers are never skipped because they were fired, nor deleted to gain fairness.
Failed ancillary handler guards also back off when the exact timer is unchanged.
An unavailable store, a timer-value guard race or a corrupt key leaves the
original row for retry or repair. A complete traversal with no progress preserves the core's
conservative retry wake only for the exact already visited physical head;
new earlier work and unfinished traversals wake immediately.

The current internal timer key codec is:

```
w 00 <physical due:be64> <kind:u8> <retry attempt:u8>
     <original handler due:be64> <opaque reference>
```

Ordinary scheduled rows use attempt zero and equal physical/original due times.
A driver retry increments the attempt, capped at eight. A successful handler
reschedule starts a fresh ordinary row. The handler receives the original due
time, which remains valid for companion lease and snapshot state comparisons.
The value is always the unchanged kind-specific payload, including unknown kinds.
Timer payloads are limited to 510 KiB so a guarded move with maximum-size keys
fits the existing 1 MiB batch budget. Other values retain their 512 KiB limit;
packmap limits are unchanged. A narrowly validated pure retry move can use the
existing SQL capacity reserve; it cannot change payloads or add effects.

This replaces an unshipped internal codec. R-198 requires resetting stores from
older builds; there is no migration or compatibility reader.

Regression coverage measures actual SQL virtual-machine steps as well as query
plans, aggregate work with frozen clocks, warm rotation, repeated cold restarts
with more retained failures than the window, capped backoff, concurrency guards,
opaque payload retention, and original handler due-time preservation.
