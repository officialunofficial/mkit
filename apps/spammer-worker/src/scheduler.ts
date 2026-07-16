// Pure tick planner (PLAN.md build step 7; extended for issue #850 — see
// "Response-queue draining" below).
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
// Response-queue draining (issue #850, parent #848 "Response planning"):
// `planTick` gained a second job on top of ambient picking — draining
// `SchedulerState.responseQueue`, a list of `ResponseIntent`s produced by
// `enqueueResponseBundle` in reaction to real (non-synthetic) commits/forks
// the observer (#849) detects. This is deliberately NOT a second planner:
// every drained intent is resolved to an identity through the SAME
// `selectEligible` helper and the SAME `lastChatMs`/`lastPushMs`/
// `lastReactionMs`/cursor state that ambient picks read and mutate, and
// draining always runs BEFORE ambient picks each tick, in the SAME working
// copies — so an identity a response intent just consumed is already
// reflected in the floor arrays by the time ambient selection looks for one.
// That single shared-state property is what makes "a response pick and an
// ambient pick can never double-book an identity's floor in the same tick"
// true by construction, with no extra bookkeeping. `planTick` remains the
// sole floor authority.
//
// Quota math is UNCHANGED by this — do not re-derive it here. A response
// `remix` costs the same 2 ops (put_object + update_ref) as an ambient
// `commit`/`remix` push and drains through the exact same `PUSH_FLOOR_MS`
// floor and `pushCursor` round-robin; a response `reaction`/`chat` likewise
// shares the ambient reaction/chat floors. Response traffic is additional
// LOAD on those floors, not a new accounting path, so the ~25% worst-case
// margin this file's rate-math doc comment (below) derives for ambient-only
// traffic still holds under combined load — see `identities.ts`'s
// `POOL_SIZE` doc comment for why draining through the existing per-identity
// floor is what carries that margin, independent of WHICH source (ambient or
// response) is doing the draining.
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
  /**
   * Present only for events drained from the response queue (issue #850) —
   * lets the DO route the emit at a real target (a real user's commit/fork)
   * instead of `main`'s head, and lets it fill reply-template slots (short
   * hash / short author key / branch name). `undefined` for every ambient
   * pick, including on ticks where the response queue is non-empty — ambient
   * picks never carry a response payload.
   */
  response?: ResponsePayload;
};

/** The response-specific fields carried by a `PlannedEvent` drained from the queue — see {@link PlannedEvent.response}. */
export type ResponsePayload = {
  targetIdHex: string;
  ref: string;
  realAuthorPubkeyHex: string;
};

// -----------------------------------------------------------------------------
// Response queue (issue #850)
// -----------------------------------------------------------------------------
//
// `RealEventRef` mirrors the observer's (#849) detected-event shape. It is
// defined locally here rather than imported from an observer module because
// #849 and #850 are independent, parallel-buildable modules per #848's
// "Execution notes" (each has its own test file and can land in any order);
// #854 (the DO wiring issue) is what reconciles the two into a single
// imported type once both exist. The field set below is exactly #848's PRD
// "Implementation Decisions → The observer seam" `realEvents` shape.

/** One real (non-synthetic-author) commit or fork the observer detected — mirrors #849's output shape. Defined locally; see the block comment above for why. */
export type RealEventRef = {
  kind: "commit" | "fork";
  /** The ref the event landed on — `"refs/heads/main"`, a feature branch, or a `forks/...` ref. Any ref, per #848: real-user detection is not `main`-only. */
  ref: string;
  /** The commit/fork target's content-addressed id (hex) — what a response reaction/remix/chat-mention targets, regardless of which ref it lives on. */
  targetIdHex: string;
  /** The real (non-pool) author's pubkey hex — cooldown key, and the reply's "short author key" slot. */
  authorPubkeyHex: string;
};

/**
 * One queued response action produced by {@link enqueueResponseBundle} and
 * consumed by {@link planTick}'s drain step. `kind` never includes `"commit"`
 * — responses only react (reaction/chat) or remix, they never impersonate a
 * fresh top-level commit (see #848 Out of Scope: "never invent claims", and
 * the parent PRD's response-bundle shape).
 */
export type ResponseIntent = {
  kind: "reaction" | "chat" | "remix";
  /** The real commit/fork's content-addressed id (hex) this intent targets — carried through to `PlannedEvent.response.targetIdHex` on drain. */
  targetIdHex: string;
  /** The ref the real event landed on — carried through for the reply-template branch-name slot. */
  ref: string;
  /** The real event's author — carried through for the reply-template short-author-key slot; NOT a synthetic identity. */
  realAuthorPubkeyHex: string;
  /** Earliest `now` (ms epoch) at which this intent is eligible to drain — how a bundle's picks spread across ticks instead of firing all at once. */
  notBeforeMs: number;
  /** Groups every intent {@link enqueueResponseBundle} produced from the SAME real event — used to (a) enforce distinct reaction identities within one bundle and (b) know when a bundle has fully drained. */
  bundleId: string;
};

/** Per-real-author cooldown: an event whose author already got a bundle within this many ms enqueues NOTHING — #848: "a cooldown between response bundles aimed at me, so rapid pushes do not multiply bot attention linearly." ~5 min, per the PRD's proposed bundle composition. */
export const RESPONSE_AUTHOR_COOLDOWN_MS = 5 * 60_000;

/** Global cap on bundles with any undrained intents still in the queue at once. #848: "a global cap on bundles in flight at once" (proposed: one). Enforced at enqueue time — see {@link enqueueResponseBundle}'s doc comment for why an event that arrives while a bundle is in flight is DROPPED, not queued behind it. */
export const MAX_BUNDLES_IN_FLIGHT = 1;

/** How many ms a bundle's reaction/chat/remix picks are spread across via `notBeforeMs` offsets — #848: "spread over the following tens of seconds"; PRD default ~30s. */
export const RESPONSE_BUNDLE_SPREAD_MS = 30_000;

/** Minimum reactions per bundle — #848 proposed composition: "2–3 reactions". */
export const RESPONSE_REACTION_COUNT_MIN = 2;
/** Number of possible reaction counts starting at {@link RESPONSE_REACTION_COUNT_MIN} — 2 gives the range {2, 3}. */
export const RESPONSE_REACTION_COUNT_RANGE = 2;

/** Percent chance (0-100) a bundle includes exactly one chat reply — #848 proposed composition: "usually one chat reply" (i.e. not guaranteed, but the common case). */
export const RESPONSE_CHAT_INCLUDE_PERCENT = 80;

/** Percent chance (0-100) a bundle includes a remix of the real target — #848 proposed composition: "remix at ~20%". */
export const RESPONSE_REMIX_INCLUDE_PERCENT = 20;

/**
 * Deterministic 32-bit FNV-1a hash of a string. The ONLY source of
 * pseudo-randomness `enqueueResponseBundle` is allowed to use — no
 * `Math.random`, no `Date.now` (this module's whole contract is "same
 * inputs, same outputs"; see this file's top doc comment). Domain-separating
 * suffixes (e.g. `":reactionCount"` vs `":chat"`) on the hashed string keep
 * each bundle-composition decision independent of the others even though
 * they all derive from the same `targetIdHex`.
 */
function hashStringToUint32(s: string): number {
  let h = 0x811c9dc5; // FNV offset basis
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193); // FNV prime
  }
  return h >>> 0;
}

/**
 * Expand one detected real event into a response bundle and push its intents
 * onto `state.responseQueue`. Pure: `(state, event, now)` always yields the
 * same `nextState`; `now` is used only to timestamp `notBeforeMs` offsets and
 * the cooldown/bundleId bookkeeping, never as a randomness source.
 *
 * Two independent gates can make this a no-op (returning `state` unchanged):
 *  1. **Cooldown** — `event.authorPubkeyHex` already got a bundle within
 *     {@link RESPONSE_AUTHOR_COOLDOWN_MS}. Enqueuing nothing (rather than
 *     queuing a delayed bundle) is deliberate: the cooldown is about not
 *     multiplying attention on a BURST from one author, not about guaranteeing
 *     every single push eventually gets acknowledged.
 *  2. **Global cap** — {@link MAX_BUNDLES_IN_FLIGHT} bundles already have
 *     undrained intents in the queue. Dropping (not enqueueing behind the
 *     in-flight bundle) is deliberate too: #848 user story 9 wants "a
 *     bounded, tasteful number of responses" that reads as an
 *     ACKNOWLEDGMENT, not a dogpile — a real event that lands mid-bundle is
 *     already covered by the room feeling alive; it does not need its own
 *     separate bundle queued up behind the current one.
 *
 * Otherwise, composes a bundle — {@link RESPONSE_REACTION_COUNT_MIN}..+{@link RESPONSE_REACTION_COUNT_RANGE}
 * reactions (distinct `notBeforeMs` offsets spread across
 * {@link RESPONSE_BUNDLE_SPREAD_MS}; WHICH identity each one lands on is
 * decided later, at drain time, by `planTick`), at most one chat reply
 * ({@link RESPONSE_CHAT_INCLUDE_PERCENT}% of bundles), and a remix
 * ({@link RESPONSE_REMIX_INCLUDE_PERCENT}% of bundles) — all decided by
 * {@link hashStringToUint32} of `event.targetIdHex`, never by `Math.random`.
 *
 * Also prunes `state.lastBundleMsByAuthor`: every entry whose cooldown has
 * already fully elapsed (`now - ms >= RESPONSE_AUTHOR_COOLDOWN_MS`) is
 * dropped before the new author entry is added, since an expired entry can
 * never again change the cooldown check above — keeping it around is dead
 * weight that would otherwise round-trip through DO storage forever on a
 * long-lived room (see {@link SchedulerState.lastBundleMsByAuthor}'s doc
 * comment). Pruning happens ONLY on this success path, not on either
 * no-op/early-return gate above — that keeps this function's "a no-op
 * enqueue returns `state` completely unchanged" contract literal (same
 * object reference back), which is what the cooldown/cap tests rely on.
 * This does not let the map grow unboundedly in the meantime: an entry can
 * only be added by a successful enqueue, and every successful enqueue
 * re-prunes the WHOLE map, so growth stays bounded by "how many bundles
 * have successfully gone out since the oldest still-live entry" — never by
 * "how many distinct authors this room has ever seen."
 */
export function enqueueResponseBundle(state: SchedulerState, event: RealEventRef, now: number): SchedulerState {
  const lastBundleMs = state.lastBundleMsByAuthor?.[event.authorPubkeyHex];
  if (lastBundleMs !== undefined && now - lastBundleMs < RESPONSE_AUTHOR_COOLDOWN_MS) {
    return state;
  }

  const bundleIdsInFlight = new Set((state.responseQueue ?? []).map((intent) => intent.bundleId)).size;
  if (bundleIdsInFlight >= MAX_BUNDLES_IN_FLIGHT) {
    return state;
  }

  const prunedLastBundleMsByAuthor: Record<string, number> = {};
  for (const [author, ms] of Object.entries(state.lastBundleMsByAuthor ?? {})) {
    if (now - ms < RESPONSE_AUTHOR_COOLDOWN_MS) prunedLastBundleMsByAuthor[author] = ms;
  }
  prunedLastBundleMsByAuthor[event.authorPubkeyHex] = now;

  const bundleId = `${event.targetIdHex}:${now}`;
  const intents: ResponseIntent[] = [];

  const reactionCount =
    RESPONSE_REACTION_COUNT_MIN +
    (hashStringToUint32(`${event.targetIdHex}:reactionCount`) % RESPONSE_REACTION_COUNT_RANGE);
  for (let i = 0; i < reactionCount; i++) {
    intents.push({
      kind: "reaction",
      targetIdHex: event.targetIdHex,
      ref: event.ref,
      realAuthorPubkeyHex: event.authorPubkeyHex,
      notBeforeMs: now + Math.floor((i * RESPONSE_BUNDLE_SPREAD_MS) / reactionCount),
      bundleId,
    });
  }

  if (hashStringToUint32(`${event.targetIdHex}:chat`) % 100 < RESPONSE_CHAT_INCLUDE_PERCENT) {
    intents.push({
      kind: "chat",
      targetIdHex: event.targetIdHex,
      ref: event.ref,
      realAuthorPubkeyHex: event.authorPubkeyHex,
      notBeforeMs: now + Math.floor(RESPONSE_BUNDLE_SPREAD_MS / 2),
      bundleId,
    });
  }

  if (hashStringToUint32(`${event.targetIdHex}:remix`) % 100 < RESPONSE_REMIX_INCLUDE_PERCENT) {
    intents.push({
      kind: "remix",
      targetIdHex: event.targetIdHex,
      ref: event.ref,
      realAuthorPubkeyHex: event.authorPubkeyHex,
      notBeforeMs: now + RESPONSE_BUNDLE_SPREAD_MS,
      bundleId,
    });
  }

  return {
    ...state,
    responseQueue: [...(state.responseQueue ?? []), ...intents],
    lastBundleMsByAuthor: prunedLastBundleMsByAuthor,
  };
}

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
  /**
   * Pending response intents (issue #850), drained by `planTick` before
   * ambient picks each tick. `undefined` (or an empty array) means "no
   * response queue" — behaviorally identical to today's ambient-only
   * planner; see this module's doc comment's "Response-queue draining"
   * section for the backward-compat guarantee this enables. OPTIONAL so
   * every existing `SchedulerState` construction site (including
   * `spammer.ts`'s `loadSchedulerState`, which this issue does NOT touch —
   * that's #854) keeps typechecking unchanged.
   */
  responseQueue?: readonly ResponseIntent[];
  /**
   * Last `now` (ms epoch) each real author's pubkey got a response bundle —
   * the cooldown clock {@link enqueueResponseBundle} reads. `undefined` means
   * "no bundle has ever been enqueued in this state's history" (same
   * optional/backward-compat contract as `responseQueue` above).
   *
   * Bounded: {@link enqueueResponseBundle} prunes every entry whose cooldown
   * has fully elapsed on each successful enqueue (an expired entry can never
   * again affect the cooldown check — see that function's doc comment), so
   * an author's entry lives for at most one {@link RESPONSE_AUTHOR_COOLDOWN_MS}
   * window past its last bundle, not forever. Without this bound this map —
   * unlike the observer's capped responded-LRU — would gain one entry per
   * distinct real author for the lifetime of a long-lived public room and
   * round-trip through DO storage on every tick.
   */
  lastBundleMsByAuthor?: Readonly<Record<string, number>>;
  /**
   * Per-bundle set of identity indices already used for a REACTION in that
   * bundle, keyed by `ResponseIntent.bundleId`. Exists solely so
   * "reactions within one bundle go to distinct identities" holds even when
   * a bundle's reaction intents drain across multiple ticks (within a
   * single tick, distinctness falls out for free from the shared floor
   * arrays — see `planTick`'s drain step — but across ticks the reaction
   * floor alone, ~200ms, is far shorter than the ~10-15s a bundle's
   * reactions are spread across, so nothing else would prevent a repeat).
   * Entries are removed once a bundle's intents are fully drained (bounded
   * by {@link MAX_BUNDLES_IN_FLIGHT}, so this never grows unbounded).
   */
  reactionIdentitiesByBundle?: Readonly<Record<string, readonly number[]>>;
};

/** A fresh scheduler state: nobody has ever been picked, all cursors at 0, tick 0, no response queue. */
export function initialSchedulerState(poolSize: number = POOL_SIZE): SchedulerState {
  return {
    lastChatMs: new Array<number | undefined>(poolSize).fill(undefined),
    lastPushMs: new Array<number | undefined>(poolSize).fill(undefined),
    lastReactionMs: new Array<number | undefined>(poolSize).fill(undefined),
    chatCursor: 0,
    pushCursor: 0,
    reactionCursor: 0,
    tick: 0,
    responseQueue: undefined,
    lastBundleMsByAuthor: undefined,
    reactionIdentitiesByBundle: undefined,
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
 *
 * `isExcluded`, when given, skips indices it returns `true` for regardless
 * of floor eligibility — used only by `planTick`'s response-queue drain to
 * enforce "distinct identities within a bundle" for reaction intents (see
 * `SchedulerState.reactionIdentitiesByBundle`'s doc comment). Every ambient
 * call site omits it, so ambient behavior is completely unaffected — this
 * parameter exists purely as an extra constraint response draining layers on
 * top of the SAME floor check, not a second selection mechanism.
 */
function selectEligible(
  start: number,
  poolSize: number,
  lastMs: readonly (number | undefined)[],
  floorMs: number,
  now: number,
  isExcluded?: (index: number) => boolean,
): { index: number | null; nextCursor: number } {
  for (let step = 0; step < poolSize; step++) {
    const idx = (start + step) % poolSize;
    if (isExcluded?.(idx)) continue;
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
 * Two phases, in order:
 *
 * 1. **Response-queue drain** (issue #850): every intent in
 *    `state.responseQueue` whose `notBeforeMs <= now` is resolved to an
 *    identity via `selectEligible`, against the SAME floor arrays and
 *    cursors ambient picks use in phase 2 below — reaction intents drain
 *    through `lastReactionMs`/`reactionCursor`/`REACTION_FLOOR_MS`, chat
 *    intents through `lastChatMs`/`chatCursor`/`CHAT_FLOOR_MS`, remix
 *    intents through `lastPushMs`/`pushCursor`/`PUSH_FLOOR_MS` (a response
 *    remix is still a push for floor purposes — same 2 ops, same floor; see
 *    this file's top doc comment). Intents are drained in queue order
 *    (stable FIFO across possibly-interleaved bundle kinds); an intent whose
 *    floor is saturated this tick (pool fully busy) is put back on the queue
 *    to retry next tick rather than dropped — mirrors ambient's "fewer
 *    events, never a floor violation" behavior in `selectEligible`'s own doc
 *    comment. Reaction intents additionally exclude identities already used
 *    for a REACTION in the same bundle (`reactionIdentitiesByBundle`), so
 *    "distinct identities within a bundle" holds even when a bundle's
 *    reactions drain across separate ticks.
 * 2. **Ambient picks** (original PLAN.md build-step-7 behavior, UNCHANGED):
 *    `CHAT_EVENTS_PER_TICK` chat picks (each immediately marks its
 *    identity's `lastChatMs` as `now` in the WORKING copy, so the two chat
 *    picks in one tick can never land on the same identity), then one push
 *    pick (kind decided by `REMIX_EVERY_N_TICKS` off `state.tick` — NEVER
 *    influenced by the response queue, so ambient commit/remix selection is
 *    byte-for-byte identical whether or not a response bundle is in flight),
 *    then an occasional reaction pick gated by `REACTION_EVERY_N_TICKS`. An
 *    ambient `commit`/`remix` `PlannedEvent` never carries a `response`
 *    payload and (unlike a response `PlannedEvent`) carries no ref/target at
 *    all, so `spammer.ts`'s emit path always resolves it against `main` —
 *    the "ambient commit selection must still only ever target `main`, even
 *    when the response queue is non-empty" guardrail (#850) holds by
 *    construction, not by any check in this function.
 *
 * Because phase 1 runs first against the SAME working-copy arrays phase 2
 * reads, any identity a response intent consumed is already ineligible (for
 * that category) by the time ambient picking looks — the "never double-book
 * a floor in one tick" guarantee falls out of using one set of arrays, not
 * from any explicit cross-checking. When `state.responseQueue` is empty or
 * absent, phase 1 is a no-op and phase 2 runs exactly as it did before this
 * issue — see this module's test file's backward-compat coverage.
 */
export function planTick(state: SchedulerState, now: number): { events: PlannedEvent[]; nextState: SchedulerState } {
  const poolSize = state.lastChatMs.length;
  const lastChatMs = state.lastChatMs.slice();
  const lastPushMs = state.lastPushMs.slice();
  const lastReactionMs = state.lastReactionMs.slice();
  const events: PlannedEvent[] = [];

  let chatCursor = state.chatCursor;
  let pushCursor = state.pushCursor;
  let reactionCursor = state.reactionCursor;

  // --- Phase 1: drain due response intents (issue #850) --------------------
  const reactionIdentitiesByBundle: Record<string, number[]> = state.reactionIdentitiesByBundle
    ? Object.fromEntries(Object.entries(state.reactionIdentitiesByBundle).map(([k, v]) => [k, v.slice()]))
    : {};
  const remainingQueue: ResponseIntent[] = [];

  for (const intent of state.responseQueue ?? []) {
    if (intent.notBeforeMs > now) {
      remainingQueue.push(intent);
      continue;
    }

    const response: ResponsePayload = {
      targetIdHex: intent.targetIdHex,
      ref: intent.ref,
      realAuthorPubkeyHex: intent.realAuthorPubkeyHex,
    };

    if (intent.kind === "chat") {
      const picked = selectEligible(chatCursor, poolSize, lastChatMs, CHAT_FLOOR_MS, now);
      chatCursor = picked.nextCursor;
      if (picked.index === null) {
        remainingQueue.push(intent);
        continue;
      }
      lastChatMs[picked.index] = now;
      events.push({ identityIndex: picked.index, kind: "chat", response });
    } else if (intent.kind === "remix") {
      const picked = selectEligible(pushCursor, poolSize, lastPushMs, PUSH_FLOOR_MS, now);
      pushCursor = picked.nextCursor;
      if (picked.index === null) {
        remainingQueue.push(intent);
        continue;
      }
      lastPushMs[picked.index] = now;
      events.push({ identityIndex: picked.index, kind: "remix", response });
    } else {
      const usedForBundle = reactionIdentitiesByBundle[intent.bundleId] ?? [];
      const picked = selectEligible(reactionCursor, poolSize, lastReactionMs, REACTION_FLOOR_MS, now, (idx) =>
        usedForBundle.includes(idx),
      );
      reactionCursor = picked.nextCursor;
      if (picked.index === null) {
        remainingQueue.push(intent);
        continue;
      }
      lastReactionMs[picked.index] = now;
      reactionIdentitiesByBundle[intent.bundleId] = [...usedForBundle, picked.index];
      events.push({ identityIndex: picked.index, kind: "reaction", response });
    }
  }

  // Drop bookkeeping for any bundle with nothing left in the queue — bounds
  // `reactionIdentitiesByBundle` to at most `MAX_BUNDLES_IN_FLIGHT` entries.
  const bundleIdsStillQueued = new Set(remainingQueue.map((intent) => intent.bundleId));
  for (const bundleId of Object.keys(reactionIdentitiesByBundle)) {
    if (!bundleIdsStillQueued.has(bundleId)) delete reactionIdentitiesByBundle[bundleId];
  }

  // --- Phase 2: ambient picks (unchanged) -----------------------------------
  for (let i = 0; i < CHAT_EVENTS_PER_TICK; i++) {
    const picked = selectEligible(chatCursor, poolSize, lastChatMs, CHAT_FLOOR_MS, now);
    chatCursor = picked.nextCursor;
    if (picked.index !== null) {
      events.push({ identityIndex: picked.index, kind: "chat" });
      lastChatMs[picked.index] = now;
    }
  }

  const pushKind: EventKind = state.tick % REMIX_EVERY_N_TICKS === REMIX_EVERY_N_TICKS - 1 ? "remix" : "commit";
  const pushPick = selectEligible(pushCursor, poolSize, lastPushMs, PUSH_FLOOR_MS, now);
  pushCursor = pushPick.nextCursor;
  if (pushPick.index !== null) {
    events.push({ identityIndex: pushPick.index, kind: pushKind });
    lastPushMs[pushPick.index] = now;
  }

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
      responseQueue: remainingQueue.length > 0 ? remainingQueue : undefined,
      lastBundleMsByAuthor: state.lastBundleMsByAuthor,
      reactionIdentitiesByBundle:
        Object.keys(reactionIdentitiesByBundle).length > 0 ? reactionIdentitiesByBundle : undefined,
    },
  };
}
