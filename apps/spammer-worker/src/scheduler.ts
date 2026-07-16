// Pure tick planner (PLAN.md build step 7; extended for issue #850 — see
// "Response-queue draining" below — and issue #851 — see "Fork-of-fork
// upstream selection" below).
//
// `planTick` is the ONLY thing that decides what the `Spammer` DO's `alarm()`
// emits on a given tick — it does no I/O, holds no wasm handle, and touches
// no clock other than the `now` (ms epoch) its caller passes in, plus (as of
// #851) an optional per-tick `forkUpstreams` snapshot, equally caller-owned.
// That makes it directly host-testable (this file's tests simulate a full
// hour of ticks in a tight loop) and, later, trivially wired into
// `spammer.ts`: the DO reads its `SchedulerState` back from SQLite, calls
// `planTick(state, Date.now(), forkUpstreams)`, emits the returned `events`,
// then persists `nextState` (never `forkUpstreams` itself — see below) — no
// other floor bookkeeping lives anywhere else.
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
// Fork-of-fork upstream selection (issue #851, parent #848 "Fork-of-fork: IN
// scope"): every ambient remix pick used to fork whatever `main`'s head
// currently was — `events.ts`'s `buildSignedRemix` doc comment used to note
// "this build step never remixes another remix" as a simple statement of
// fact, which flattened the refs panel's fork topology to one hop. `planTick`
// now takes an OPTIONAL third argument, `forkUpstreams`, a per-tick snapshot
// of known fork refs and their current heads supplied by the caller — plain
// caller-provided data like `now`, NOT part of `SchedulerState`, because it
// is a live read of room state (the DO's observer watermark, #854), not
// scheduler-internal bookkeeping that needs to round-trip through storage.
// On `FORK_OF_FORK_REMIX_PERCENT`% of ambient remix ticks (deterministically,
// via the same tick-keyed `hashStringToUint32` pattern
// `enqueueResponseBundle` already uses below — no `Math.random`), the planner
// picks one of `forkUpstreams` as the remix's upstream instead of `main`'s
// tip, carried on the `PlannedEvent` as `remixUpstream`. Absence or an empty
// `forkUpstreams` array makes this entirely inert — ambient remix picks fall
// back to `main`-tip remix exactly as before this issue, which is how every
// existing call site (and this file's pre-#851 tests) keeps working
// unmodified. This is a SELECTION-layer change only: `events.ts`'s
// `emitRemix` already accepts any upstream commit hash and needs no change
// (see this file's `PlannedEvent.remixUpstream` doc comment). It touches ONLY
// phase 2's ambient remix pick — response-queue remix intents (phase 1)
// already carry their own real target via `ResponsePayload.targetIdHex` and
// are never candidates for `remixUpstream` substitution.
//
// Rate-math design (mirrors PLAN.md's "Synthetic-identity / rate-math design",
// corrected for a real ops-per-push accounting error caught in review — do
// not re-derive these numbers casually, they were verified against the real
// repo-worker floors):
//   - Pool: `POOL_SIZE` (64) identities, round-robin per event category. 64
//     was sized for the ORIGINAL one-push-per-tick cadence, where a
//     commit/remix push being 2 ops (put_object + update_ref) against the
//     real 300-ops/hr/author cap (`write_quota.rs:31`) left only a 25%
//     worst-case margin (see `identities.ts`'s `POOL_SIZE` doc comment for
//     that original derivation). Under the current gated cadence (one push
//     per `PUSH_EVERY_N_TICKS` ticks), natural per-identity push spacing is
//     POOL_SIZE × PUSH_EVERY_N_TICKS seconds (~16 min), i.e. ~7.5 ops/hr/
//     author — the pool size is now pure headroom rather than the operative
//     constraint, and is kept at 64 for identity-variety, not quota math.
//   - Ambient cadence (1000 ms alarm ticks, per-category gates): one chat
//     every CHAT_EVERY_N_TICKS ticks (~12/min), one push every
//     PUSH_EVERY_N_TICKS ticks (~4/min), one reaction every
//     REACTION_EVERY_N_TICKS ticks (~6/min) ⇒ ~0.4 events/s aggregate.
//     Originally this was 2 chat + 1 push EVERY tick (~3 events/s); that
//     volume starved real users out of the CAS race on `main` (a human's
//     `update_ref` almost always lost to a synthetic push landing the same
//     second) and cycled the chat phrase pool so fast every entry repeated
//     several times per minute. The gates fix both while keeping the room
//     visibly alive. The response-queue drain (phase 1) is NOT gated — it
//     still runs every tick, so real-user acknowledgment latency is
//     unchanged.
//   - Push kind: `commit` on most push ticks, `remix` on every
//     `REMIX_EVERY_N_PUSHES`th push (counted in pushes, not ticks, so the
//     ~1-in-8 remix share survives the push gating).
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

/**
 * One ambient chat pick every this-many-th tick (0-indexed `state.tick`) —
 * ~12 chats/min at the 1000ms alarm cadence. Replaces the original
 * "2 chat per tick" mix (~120/min), which buried real users' messages and
 * cycled the phrase pool so fast every entry repeated several times a
 * minute — see the "Ambient cadence" section of this file's top doc comment.
 */
export const CHAT_EVERY_N_TICKS = 5;

/**
 * One ambient push pick (commit or remix) every this-many-th tick — ~4
 * pushes/min at the 1000ms alarm cadence. Replaces the original one-push-
 * per-tick mix (~60/min), under which a real user's CAS `update_ref` on
 * `main` almost always lost the race to a synthetic push ("Someone pushed
 * first — try again" on every attempt): at ~15s between synthetic pushes, a
 * human's push-plus-one-retry virtually always lands.
 */
export const PUSH_EVERY_N_TICKS = 15;

/** Safety floor for chat: refuse an identity whose last chat was less than this many ms ago. 250 ms margin over the real 2000 ms `MIN_POST_INTERVAL_MS` (`chat.rs:26`). */
export const CHAT_FLOOR_MS = 2500;

/** Safety floor for a push (commit or remix): refuse an identity whose last push was less than this many ms ago. 6 s margin over the real ~24 s/push floor implied by `WRITE_QUOTA_MAX_OPS` (`write_quota.rs:31`). */
export const PUSH_FLOOR_MS = 30_000;

/** Safety floor for a reaction. Margin over the real 150 ms `REACT_MIN_INTERVAL_MS` (`chat.rs:90-96`). */
export const REACTION_FLOOR_MS = 200;

/** A push is a `remix` every this-many-th PUSH (not tick — pushes now fire only every {@link PUSH_EVERY_N_TICKS} ticks); every other push is a `commit`. Preserves PLAN.md's ~1-in-8 remix share of pushes at the calmer cadence. */
export const REMIX_EVERY_N_PUSHES = 8;

/** A reaction is attempted every this-many-th tick (~6/min at the 1000ms alarm cadence) — PLAN.md's "occasional reaction", additive to the chat/push mix above. */
export const REACTION_EVERY_N_TICKS = 10;

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
  /**
   * Present only on an ambient `remix` pick (issue #851) that the fork-of-fork
   * selection in `planTick`'s phase 2 chose to fork an existing fork ref's
   * head instead of `main`'s tip — tells the emitter (`spammer.ts`, calling
   * `events.ts`'s `emitRemix`) which head to pass as `upstreamCommitHash`.
   * `undefined` means "fork `main`'s current tip", the pre-#851 default
   * behavior, which is what every ambient remix pick still does when
   * `planTick`'s `forkUpstreams` argument is absent/empty. Never set together
   * with `response` — a response remix intent already carries its own real
   * target via `ResponsePayload.targetIdHex` and is never a candidate for
   * fork-of-fork substitution (see this file's top doc comment).
   */
  remixUpstream?: ForkUpstreamRef;
};

/** The response-specific fields carried by a `PlannedEvent` drained from the queue — see {@link PlannedEvent.response}. */
export type ResponsePayload = {
  targetIdHex: string;
  ref: string;
  realAuthorPubkeyHex: string;
};

/**
 * One known fork ref and its current head, as the caller (eventually the
 * DO's observer watermark, #854) supplies to `planTick`'s `forkUpstreams`
 * parameter — see {@link PlannedEvent.remixUpstream} and this file's top doc
 * comment's "Fork-of-fork upstream selection" section. `ref` is the fork
 * ref's full name (`events.ts`'s `FORKS_PREFIX`-prefixed `forkRefName`
 * output); `headHex` is that ref's current head commit hash — exactly what
 * `emitRemix` needs as `upstreamCommitHash` to fork it again.
 */
export type ForkUpstreamRef = {
  ref: string;
  headHex: string;
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

// -----------------------------------------------------------------------------
// Fork-of-fork upstream selection (issue #851)
// -----------------------------------------------------------------------------

/**
 * Percent (0-100) of ambient remix ticks that fork a KNOWN fork ref's head
 * instead of `main`'s current tip — #848's "Fork-of-fork: IN scope" proposed
 * rate ("~25%"). Consulted only by {@link selectForkUpstream}, itself called
 * only from `planTick`'s phase 2 ambient remix pick — see this file's top doc
 * comment's "Fork-of-fork upstream selection" section for why this is a
 * selection-layer-only change.
 */
export const FORK_OF_FORK_REMIX_PERCENT = 25;

/**
 * Deterministically decide whether the ambient remix pick on tick `tick`
 * should fork a known fork ref's head instead of `main`'s tip, and if so,
 * which candidate from `forkUpstreams`. Returns `undefined` — "fork `main`'s
 * tip, as before this issue" — when `forkUpstreams` is absent/empty (the
 * feature is entirely inert with no known fork refs, per #851's acceptance
 * criteria: "never fires when no fork refs are known yet") or when the tick's
 * hash misses the {@link FORK_OF_FORK_REMIX_PERCENT} fraction.
 *
 * Both "does it fire this tick" and "which candidate index" are derived from
 * {@link hashStringToUint32} keyed on `tick` (domain-separated suffixes, the
 * same no-`Math.random` pattern `enqueueResponseBundle`'s bundle-composition
 * decisions use above) — NOT on `now`, so the same `(tick, forkUpstreams)`
 * pair always yields the same fire/no-fire decision and the same array index,
 * which is what makes `planTick` pure in its full `(state, now,
 * forkUpstreams)` input set — see `planTick`'s own doc comment.
 */
function selectForkUpstream(
  tick: number,
  forkUpstreams: readonly ForkUpstreamRef[] | undefined,
): ForkUpstreamRef | undefined {
  if (!forkUpstreams || forkUpstreams.length === 0) return undefined;
  if (hashStringToUint32(`fork-of-fork:fires:${tick}`) % 100 >= FORK_OF_FORK_REMIX_PERCENT) return undefined;
  const idx = hashStringToUint32(`fork-of-fork:pick:${tick}`) % forkUpstreams.length;
  return forkUpstreams[idx];
}

/**
 * Plan one alarm tick: decide which identities emit which event kinds,
 * honoring every per-category floor with `now` as the sole clock reference
 * (so drift/bursty tick timing is handled correctly — a tick that fires
 * early just finds fewer/no eligible identities rather than violating a
 * floor). Pure: same `(state, now, forkUpstreams)` always yields the same
 * `(events, nextState)`.
 *
 * `forkUpstreams` (issue #851) is a per-tick snapshot of known fork refs and
 * their current heads, OPTIONAL and supplied by the caller exactly like
 * `now` — NOT persisted in `SchedulerState` and NOT round-tripped into
 * `nextState`, because it is a live read of room state (the DO's observer
 * watermark, wired in #854) the caller re-supplies fresh every tick, not
 * scheduler-owned bookkeeping. Absent or empty, it makes phase 2's
 * fork-of-fork selection (below) a no-op — every ambient remix pick forks
 * `main`'s tip exactly as it did before this issue, so every pre-#851 call
 * site keeps working unmodified with zero behavior change.
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
 * 2. **Ambient picks** (PLAN.md build-step-7 behavior, cadence-gated per
 *    category — see this file's top doc comment's "Ambient cadence" section
 *    and the fork-of-fork addendum below): one chat pick on
 *    `CHAT_EVERY_N_TICKS` tick boundaries (immediately marking its
 *    identity's `lastChatMs` as `now` in the WORKING copy), one push pick on
 *    `PUSH_EVERY_N_TICKS` boundaries (kind decided by
 *    `REMIX_EVERY_N_PUSHES` off the push ordinal — NEVER influenced by the
 *    response queue, so ambient commit/remix selection is byte-for-byte
 *    identical whether or not a response bundle is in flight), and an
 *    occasional reaction pick gated by `REACTION_EVERY_N_TICKS`. An ambient
 *    `commit`/`remix` `PlannedEvent` never carries a `response` payload and
 *    (unlike a response `PlannedEvent`) carries no ref/target at all, so
 *    `spammer.ts`'s emit path always resolves it against `main` — the
 *    "ambient commit selection must still only ever target `main`, even when
 *    the response queue is non-empty" guardrail (#850) holds by construction,
 *    not by any check in this function. This is true of `commit` picks
 *    UNCONDITIONALLY: fork-of-fork selection (#851, immediately below) only
 *    ever touches a `remix` pick, never a `commit` one.
 *
 *    **Fork-of-fork addendum (issue #851):** when the push pick's kind is
 *    `remix`, {@link selectForkUpstream} is consulted (keyed on `state.tick`,
 *    never on which identity was picked) to decide whether this remix forks
 *    a known fork ref's head instead of `main`'s tip; if it does, the head it
 *    picked is attached as `PlannedEvent.remixUpstream`. This is the ONLY
 *    place `forkUpstreams` is read — it cannot affect phase 1 (response
 *    intents already carry their own real target) or a `commit` pick.
 *
 * Because phase 1 runs first against the SAME working-copy arrays phase 2
 * reads, any identity a response intent consumed is already ineligible (for
 * that category) by the time ambient picking looks — the "never double-book
 * a floor in one tick" guarantee falls out of using one set of arrays, not
 * from any explicit cross-checking. When `state.responseQueue` is empty or
 * absent, phase 1 is a no-op and phase 2 runs exactly as it did before this
 * issue — see this module's test file's backward-compat coverage.
 */
export function planTick(
  state: SchedulerState,
  now: number,
  forkUpstreams?: readonly ForkUpstreamRef[],
): { events: PlannedEvent[]; nextState: SchedulerState } {
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

  // --- Phase 2: ambient picks (cadence-gated) --------------------------------
  // Each category fires only on its own tick boundary (`CHAT_EVERY_N_TICKS` /
  // `PUSH_EVERY_N_TICKS` / `REACTION_EVERY_N_TICKS`) instead of every tick —
  // see each constant's doc comment for the rate it produces and the
  // real-user problem (CAS starvation on `main`, feed/phrase-pool churn) the
  // original every-tick mix caused. Within a firing tick the pick mechanics
  // (selectEligible, floors, cursors) are unchanged.
  if (state.tick % CHAT_EVERY_N_TICKS === 0) {
    const picked = selectEligible(chatCursor, poolSize, lastChatMs, CHAT_FLOOR_MS, now);
    chatCursor = picked.nextCursor;
    if (picked.index !== null) {
      events.push({ identityIndex: picked.index, kind: "chat" });
      lastChatMs[picked.index] = now;
    }
  }

  if (state.tick % PUSH_EVERY_N_TICKS === 0) {
    // The remix cadence is counted in PUSHES (this tick's ordinal among push
    // ticks), not raw ticks, so the ~1-in-8 remix share survives the
    // push-gating: push #7, #15, #23, … are remixes, the rest commits.
    const pushIndex = Math.floor(state.tick / PUSH_EVERY_N_TICKS);
    const pushKind: EventKind = pushIndex % REMIX_EVERY_N_PUSHES === REMIX_EVERY_N_PUSHES - 1 ? "remix" : "commit";
    const pushPick = selectEligible(pushCursor, poolSize, lastPushMs, PUSH_FLOOR_MS, now);
    pushCursor = pushPick.nextCursor;
    if (pushPick.index !== null) {
      // Fork-of-fork (#851): only ever consulted for a `remix` pick — a
      // `commit` pick's `PlannedEvent` never gains a `remixUpstream` field, so
      // ambient commit targeting stays `main`-only regardless of
      // `forkUpstreams`'s contents.
      const remixUpstream = pushKind === "remix" ? selectForkUpstream(state.tick, forkUpstreams) : undefined;
      events.push({ identityIndex: pushPick.index, kind: pushKind, ...(remixUpstream ? { remixUpstream } : {}) });
      lastPushMs[pushPick.index] = now;
    }
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
