// Pure tick planner (PLAN.md build step 7).
//
// `planTick` is the ONLY thing that decides what the `Spammer` DO's `alarm()`
// emits on a given tick — it does no I/O, holds no wasm handle, and touches
// no clock other than the `now` (ms epoch) its caller passes in. That makes
// it directly host-testable (this file's tests simulate a full hour of ticks
// in a tight loop) and, later, trivially wired into `spammer.ts`: the DO
// reads its `SchedulerState` back from SQLite, calls `planTick(state, Date.now())`,
// emits the returned `events`, then persists `nextState` — no other floor
// bookkeeping lives anywhere else.
//
// Rate-math design (mirrors PLAN.md's "Synthetic-identity / rate-math design",
// corrected for a real ops-per-push accounting error caught in review — do
// not re-derive these numbers casually, they were verified against the real
// repo-worker floors):
//   - Pool: `POOL_SIZE` (64) identities, round-robin per event category. 64,
//     not the originally-planned 32: a commit/remix push is 2 ops
//     (put_object + update_ref), not 1, against the real 300-ops/hr/author
//     cap (`write_quota.rs:31`). At pool=32 (32s natural push spacing per
//     identity), steady-state is already 225 ops/hr/author (75% of the cap)
//     with NO safety margin left for CAS-conflict retries (each retry adds
//     another put+update = +2 ops). At pool=64 (64s natural spacing),
//     steady-state is ~112.5 ops/hr/author, and even the worst case of every
//     single push needing one retry (4 ops/push) stays at 225 ops/hr — a
//     real 25% margin under the cap. See `identities.ts`'s `POOL_SIZE` doc
//     comment for the full math.
//   - Per tick (1000 ms alarm cadence): 2 chat + 1 push ⇒ ~3 events/s
//     aggregate, plus an occasional reaction on top (additive, not part of
//     the 3 — reactions are cheap, floor 150 ms).
//   - Push kind: `commit` on most ticks, `remix` on every `REMIX_EVERY_N_TICKS`th
//     tick.
//   - Safety floors (wider than the REAL server floors on purpose — see
//     PLAN.md "Floor headroom"): refuse to pick an identity for chat within
//     `CHAT_FLOOR_MS` (2500 ms, over the real 2000 ms `chat.rs` floor) of its
//     last chat, or for a push within `PUSH_FLOOR_MS` (30 000 ms, over the
//     real ~24 000 ms/push floor implied by `WRITE_QUOTA_MAX_OPS`) of its
//     last push. At pool=64 this floor no longer binds in practice (natural
//     64s spacing already exceeds it) — it's a redundant backstop, not the
//     operative constraint; the pool size is what carries the real margin.

/** Number of synthetic identities the scheduler round-robins over by default — mirrors `identities.ts`'s `POOL_SIZE`. */
export const POOL_SIZE = 64;

/** Chat events planned per tick (PLAN.md default mix: "2 chat + 1 push"). */
export const CHAT_EVENTS_PER_TICK = 2;

/** Safety floor for chat: refuse an identity whose last chat was less than this many ms ago. 250 ms margin over the real 2000 ms `MIN_POST_INTERVAL_MS` (`chat.rs:26`). */
export const CHAT_FLOOR_MS = 2500;

/** Safety floor for a push (commit or remix): refuse an identity whose last push was less than this many ms ago. 6 s margin over the real ~24 s/push floor implied by `WRITE_QUOTA_MAX_OPS` (`write_quota.rs:31`). */
export const PUSH_FLOOR_MS = 30_000;

/** Safety floor for a reaction. Margin over the real 150 ms `REACT_MIN_INTERVAL_MS` (`chat.rs:90-96`). */
export const REACTION_FLOOR_MS = 200;

/** A push is a `remix` every this-many-th tick (0-indexed `state.tick`); every other push tick is a `commit`. PLAN.md: "every ~8th tick". */
export const REMIX_EVERY_N_TICKS = 8;

/** A reaction is attempted every this-many-th tick — PLAN.md's "occasional reaction ... on a fraction of ticks", additive to the 3-event base mix. */
export const REACTION_EVERY_N_TICKS = 5;

export type EventKind = "chat" | "commit" | "remix" | "reaction";

/** One (identity, event-kind) pair the caller should emit this tick. */
export type PlannedEvent = {
  identityIndex: number;
  kind: EventKind;
};

/**
 * Everything `planTick` needs to carry from one tick to the next. Plain,
 * serializable data (arrays of numbers + a few counters) — no class, no
 * closures — so `spammer.ts` (build step 8) can round-trip it through DO
 * SQLite verbatim.
 *
 * `lastChatMs[i]`/`lastPushMs[i]`/`lastReactionMs[i]` are `undefined` until
 * identity `i` has ever been picked for that category; `undefined` always
 * counts as "eligible" (never inside any floor).
 */
export type SchedulerState = {
  lastChatMs: readonly (number | undefined)[];
  lastPushMs: readonly (number | undefined)[];
  lastReactionMs: readonly (number | undefined)[];
  /** Next identity index each category's round-robin search starts from. */
  chatCursor: number;
  pushCursor: number;
  reactionCursor: number;
  /** Monotonic tick counter (0-indexed), used only to decide push kind / reaction cadence. */
  tick: number;
};

/** A fresh scheduler state: nobody has ever been picked, all cursors at 0, tick 0. */
export function initialSchedulerState(poolSize: number = POOL_SIZE): SchedulerState {
  return {
    lastChatMs: new Array<number | undefined>(poolSize).fill(undefined),
    lastPushMs: new Array<number | undefined>(poolSize).fill(undefined),
    lastReactionMs: new Array<number | undefined>(poolSize).fill(undefined),
    chatCursor: 0,
    pushCursor: 0,
    reactionCursor: 0,
    tick: 0,
  };
}

/**
 * Scan forward from `start` (wrapping, at most one full lap of the pool) for
 * the first identity whose `lastMs` entry is either `undefined` or at least
 * `floorMs` in the past relative to `now`. Returns `null` if the WHOLE pool
 * is currently inside the floor (should not happen at the designed cadence —
 * see this module's doc comment's rate math — but is handled rather than
 * assumed away, since `now` is caller-supplied and ticks can drift/burst).
 *
 * `nextCursor` is always `(foundIndex + 1) % poolSize` on a hit, so the next
 * search for this category starts right after the identity just used —
 * that's what makes the round-robin spread events evenly. On a miss
 * (nothing eligible), the cursor is left unchanged so the next call resumes
 * the search from the same starting point.
 */
function selectEligible(
  start: number,
  poolSize: number,
  lastMs: readonly (number | undefined)[],
  floorMs: number,
  now: number,
): { index: number | null; nextCursor: number } {
  for (let step = 0; step < poolSize; step++) {
    const idx = (start + step) % poolSize;
    const last = lastMs[idx];
    if (last === undefined || now - last >= floorMs) {
      return { index: idx, nextCursor: (idx + 1) % poolSize };
    }
  }
  return { index: null, nextCursor: start };
}

/**
 * Plan one alarm tick: decide which identities emit which event kinds,
 * honoring every per-category floor with `now` as the sole clock reference
 * (so drift/bursty tick timing is handled correctly — a tick that fires
 * early just finds fewer/no eligible identities rather than violating a
 * floor). Pure: same `(state, now)` always yields the same `(events,
 * nextState)`.
 *
 * Order within a tick: `CHAT_EVENTS_PER_TICK` chat picks first (each
 * immediately marks its identity's `lastChatMs` as `now` in the WORKING
 * copy, so the two chat picks in one tick can never land on the same
 * identity — picking the same identity twice in one tick would trivially
 * violate its own floor), then one push pick (kind decided by
 * `REMIX_EVERY_N_TICKS`), then an occasional reaction pick gated by
 * `REACTION_EVERY_N_TICKS`. Chat/push/reaction floors are tracked
 * independently, so the SAME identity can legitimately be picked for, say,
 * both a chat and a push in the same tick — nothing in PLAN.md's floors
 * forbids that.
 */
export function planTick(state: SchedulerState, now: number): { events: PlannedEvent[]; nextState: SchedulerState } {
  const poolSize = state.lastChatMs.length;
  const lastChatMs = state.lastChatMs.slice();
  const lastPushMs = state.lastPushMs.slice();
  const lastReactionMs = state.lastReactionMs.slice();
  const events: PlannedEvent[] = [];

  let chatCursor = state.chatCursor;
  for (let i = 0; i < CHAT_EVENTS_PER_TICK; i++) {
    const picked = selectEligible(chatCursor, poolSize, lastChatMs, CHAT_FLOOR_MS, now);
    chatCursor = picked.nextCursor;
    if (picked.index !== null) {
      events.push({ identityIndex: picked.index, kind: "chat" });
      lastChatMs[picked.index] = now;
    }
  }

  const pushKind: EventKind = state.tick % REMIX_EVERY_N_TICKS === REMIX_EVERY_N_TICKS - 1 ? "remix" : "commit";
  let pushCursor = state.pushCursor;
  const pushPick = selectEligible(pushCursor, poolSize, lastPushMs, PUSH_FLOOR_MS, now);
  pushCursor = pushPick.nextCursor;
  if (pushPick.index !== null) {
    events.push({ identityIndex: pushPick.index, kind: pushKind });
    lastPushMs[pushPick.index] = now;
  }

  let reactionCursor = state.reactionCursor;
  if (state.tick % REACTION_EVERY_N_TICKS === 0) {
    const reactionPick = selectEligible(reactionCursor, poolSize, lastReactionMs, REACTION_FLOOR_MS, now);
    reactionCursor = reactionPick.nextCursor;
    if (reactionPick.index !== null) {
      events.push({ identityIndex: reactionPick.index, kind: "reaction" });
      lastReactionMs[reactionPick.index] = now;
    }
  }

  return {
    events,
    nextState: {
      lastChatMs,
      lastPushMs,
      lastReactionMs,
      chatCursor,
      pushCursor,
      reactionCursor,
      tick: state.tick + 1,
    },
  };
}
