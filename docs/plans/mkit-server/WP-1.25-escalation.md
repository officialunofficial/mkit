# WP-1.25 Section D escalation

Status: stopped before implementation. The prescribed B.3–B.4 protocol does
not satisfy SPEC-WRITE-GRANTS §5.4–§5.6. Section D requires escalation rather
than changing the orchestrator's fixed decisions.

The first commit records the supplied brief verbatim from Purpose onward.
No production code, existing tests, goldens, or shared plan rows were changed.
The branch is `mkit-server/wp-1-25-epoch-leases`, based on `7a271b85`.

## Renewal acknowledges an epoch before installing it

SPEC-WRITE-GRANTS §5.6 requires:

> Once `SetGrantEpoch` reports success, no write authorized under the old
> epoch commits afterwards, whatever its delivery delay.

B.3.5 unconditionally sets `ls.acked_epoch` to the observed coordinator epoch.
The shard receives that epoch only in the later B.3.6 ref batch. B.4 skips
rows already acknowledged at the current epoch. Thus renewal can make a shard
appear acknowledged while its `el` still permits old-epoch writes.

The following interleaving uses the default parameters, one existing repo,
one ref shard, and equal pipeline and backend clocks. Times are relative to
the original lease grant; adding any Unix timestamp offset changes nothing.

| Time (ms) | Action | Coordinator | Ref shard |
|---|---|---|---|
| 0 | Existing lease | `e=0`, `ls={epoch:0, expires:30000, acked:0}` | `el={epoch:0, expires:30000, config_version:1}` |
| 23999 | A plans an epoch-0 write; lease budget is 1001 ms | unchanged | A guards the observed `el`; deadline is `min(33999,25000)=25000`. Pause before apply. |
| 24501 | `bump_epoch(ns,1)` commits | `e=1` | `el` unchanged; revocation has not pushed yet. |
| 24501 | B reads `el`, then the four coordinator rows | B observes `e=1` and old `ls` | Remaining lease budget is 499 ms, so B must renew. |
| 24501 | B passes authorization/admission and commits B.3.5 | `ls={epoch:1, expires:54501, acked:1}` | `el` unchanged. Pause or cancel B before B.3.6. |
| 24501 | `revoke_step` scans the only `ls` row | Already acknowledged at `e=1`: no push, returns `Complete` | Still epoch 0. |
| 24502 | A applies after completion | unchanged | `NotAfter(25000)` and `Equals(el,old)` both pass. Old-epoch write commits. |

The coordinator's `e`/`ls` guards all hold in this schedule. The timer move
touches only the coordinator and cannot invalidate A's shard guard. Ordinary
ref, replay, layout, and quota guards can remain unchanged; distinct nonces
avoid a replay collision. No clock skew or cross-partition atomicity is assumed.

The optional write gate does not rule out this schedule: the existing pipeline
acquires it inside `apply_loop`, after the coordinator creation/renewal step.
B can commit B.3.5 before entering that gate while A is paused holding it.
In any event, the store contract does not require all requests to share one
pipeline instance or process.

An acknowledgement must reflect a durably installed shard epoch. A possible
amendment is to preserve an existing row's acknowledgement during renewal and
let the revocation push acknowledge after installing `el`, with a separately
specified initial-row rule. Another is a guarded coordinator acknowledgement
after the shard batch. Both alter fixed B.3.5; the latter also changes call
counts. The executor has implemented neither.

## Namespace creation does not establish coordinator recovery time

SPEC-WRITE-GRANTS §5.4 requires:

> A coordinator that lost its lease table MUST NOT report completion until
> `epoch_lease + margin` after it resumes.

B.4 checks `nr.created_at_ms` when there are no `ls` rows. That field was set
when the namespace was created, not when its coordinator resumed. An existing
namespace with `nr.created_at_ms=0`, resuming at `100000` ms with its table
lost, fails the prescribed newer-than-`65000` test and immediately returns
`Complete`. The required wait ends at `135000` ms.

Deferring backup restore implementation to WP-1.29 does not make the prescribed
core check satisfy this rule. An amendment needs a defined recovery marker,
recovery-time input, or conservative completion holdoff whose source actually
establishes resume time. The executor has implemented none of these.

## Evidence and remaining work

A standalone Python protocol model under the executor's private scratch
directory evaluates the exact relevant `Equals`/`Present` guards, the
coordinator renewal, B.4's completion predicate, and the shard's `NotAfter`
guard. It produces:

```text
renewal budget=499 ms; old deadline=25000; Complete=True; old batch=Committed at 24502 ms
lost table: nr.created_at=0; resumed=100000; Complete=True immediately
```

This is a model of the specified protocol, not a reproduction against an
implemented WP-1.25 pipeline. The model source is reproduced below so the
evidence does not depend on retaining scratch files.

The orchestrator must amend acknowledgement ordering and recovery tracking.
All implementation, required regression tests, Rust/wasm/wire gates, R-97/R-98,
adapter registration, and the PR remain outstanding. Rust gates were not run:
only Markdown has changed, and the mandated stop precedes implementation.
The work is committed locally and is intentionally not pushed under Section D.

## Standalone model

```python
from copy import deepcopy

LEASE_MS, MARGIN_MS, MIN_BUDGET_MS, APPLY_WINDOW_MS = 30000, 5000, 1000, 10000
coordinator = {"e": 0, "nr": {"created_at_ms": 0, "config_version": 1}, "rr": {},
               "ls": {"epoch": 0, "expires_at_ms": 30000, "acked_epoch": 0}}
shard = {"el": {"epoch": 0, "expires_at_ms": 30000, "config_version": 1}, "ref": "old"}

def apply(rows, guards, writes, backend_now):
    for kind, key, expected in guards:
        if kind == "NotAfter":
            if backend_now > expected:
                return "DeadlinePassed"
        elif kind == "Equals":
            if key not in rows or rows[key] != expected:
                return "PreconditionFailed"
        elif kind == "Present":
            if key not in rows:
                return "PreconditionFailed"
        else:
            raise AssertionError(kind)
    rows.update(deepcopy(writes))
    return "Committed"

# A was planned with a usable epoch-0 lease. No replay cap binds.
plan_time = 23999
old_el = deepcopy(shard["el"])
assert old_el["expires_at_ms"] - MARGIN_MS - plan_time >= MIN_BUDGET_MS
old_deadline = min(plan_time + APPLY_WINDOW_MS, old_el["expires_at_ms"] - MARGIN_MS)
a_guards = [("NotAfter", None, old_deadline), ("Equals", "el", old_el),
            ("Equals", "ref", "old")]

# Epoch bump commits before B's renewal read and before revoke_step's scan.
now = 24501
assert apply(coordinator, [("Equals", "e", 0)], {"e": 1}, now) == "Committed"

# B observes an unusable lease (499 ms budget) and passes admission.
assert shard["el"]["expires_at_ms"] - MARGIN_MS - now < MIN_BUDGET_MS
observed_e, observed_ls = coordinator["e"], deepcopy(coordinator["ls"])
renewed_ls = {"epoch": observed_e,
              "expires_at_ms": max(observed_ls["expires_at_ms"], now + LEASE_MS),
              "acked_epoch": observed_e}
b_guards = [("Present", "nr", None), ("Present", "rr", None),
            ("Equals", "e", observed_e), ("Equals", "ls", observed_ls)]
assert apply(coordinator, b_guards, {"ls": renewed_ls}, now) == "Committed"
# Timer movement affects only the coordinator, so cannot change shard guards.
# Pause B before its ref-shard batch, or cancel it at this boundary.

# B.4 skips this row and reports Complete, although el still holds epoch 0.
ls, epoch = coordinator["ls"], coordinator["e"]
complete = ls["acked_epoch"] == epoch or ls["expires_at_ms"] <= now
assert complete and shard["el"]["epoch"] == 0
result = apply(shard, a_guards, {"ref": "authorized-at-epoch-0"}, now + 1)
assert result == "Committed"
print(f"renewal budget=499 ms; old deadline={old_deadline}; Complete={complete}; old batch={result} at {now + 1} ms")

# The empty-table rule checks namespace creation, not coordinator resume.
created_at, resume_at = 0, 100000
lost_table_complete = not (created_at > resume_at - (LEASE_MS + MARGIN_MS))
assert lost_table_complete
print(f"lost table: nr.created_at={created_at}; resumed={resume_at}; Complete={lost_table_complete} immediately")
```
