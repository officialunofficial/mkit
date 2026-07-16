// Personalization budget ledger (#853, "AI quota strategy" in #848).
//
// Mirrors `scheduler.ts`'s pure-state idiom exactly: plain, serializable data
// in, plain data out, `now` passed in by the caller (never `Date.now()` read
// in here) so a full simulated day is directly testable in a tight loop with
// no fake timers. The DO (#854) round-trips `LedgerState` through storage the
// same way it round-trips `SchedulerState`.
//
// This module answers exactly one question — "is it OK to spend one
// personalization call right now?" — and separately records that a call
// happened. It has NO opinion on what the call itself does
// (`generatePersonalizedReply` in `ai-content.ts`) or what happens on
// exhaustion/failure (the DO falls back to `fillReplyTemplate` over the
// static/AI-refreshed template pool — the same never-throw fallback posture
// `ai-content.ts`'s batched refresh already has).
//
// IMPORTANT — these constants are TUNABLES, not derived facts. Workers AI
// does not expose a precise per-call neuron meter to the worker (see #848's
// "Further Notes"), so `COST_PER_CALL_NEURONS` is a conservative estimate,
// and `DAILY_NEURON_BUDGET`/`MIN_SPACING_MS` are deliberately small relative
// to the real 10,000-neuron/day free-tier allowance: the existing ~20-minute
// batched content refresh (`ai-content.ts`) already consumes most of that
// allowance when its own auto-refresh flag is on, so this ledger's slice is
// meant to stay a tiny, separately-accounted "garnish" (on the order of ten
// calls/day) on top, never a second consumer competing for the same budget.

/**
 * Conservative per-call cost estimate in neurons, per #848's "AI quota
 * strategy" ("conservatively costed at ~200 neurons per call"). A tunable,
 * not a measured value — see this module's doc comment.
 */
export const COST_PER_CALL_NEURONS = 200;

/**
 * Daily neuron budget for personalization specifically — deliberately a
 * small slice of the real 10,000/day free-tier allowance (most of which the
 * batched content refresh already spends when enabled). At
 * {@link COST_PER_CALL_NEURONS} = 200, this allows ~10 personalized replies
 * per day, matching #848's "on the order of ten" target.
 */
export const DAILY_NEURON_BUDGET = 2000;

/**
 * Minimum spacing between two personalization calls, regardless of budget
 * remaining — prevents a burst of real events (e.g. several pushes in the
 * same minute) from draining the whole daily budget in one go, independent
 * of the neuron-cost accounting. 10 minutes: generous enough that ~10
 * calls/day physically cannot cluster into a single burst, small enough to
 * not feel unresponsive relative to the response-bundle timescale (#848:
 * bundles spread over "tens of seconds").
 */
export const MIN_SPACING_MS = 10 * 60 * 1000;

/**
 * Everything {@link canPersonalize}/{@link recordCall} need to carry from one
 * call to the next. Plain, serializable data — no class, no closures — same
 * round-trip-through-DO-storage shape as `scheduler.ts`'s `SchedulerState`.
 *
 * `dayKey` is a UTC day key (`YYYY-MM-DD`, see {@link utcDayKey}) — the day
 * `neuronsSpentToday` accounts for. It is read-and-compared against the
 * CURRENT day on every call rather than trusting a background reset, so a
 * "today" that has rolled over (the DO's alarm loop can go quiet for hours
 * without a real event to respond to) is detected lazily, exactly when it
 * next matters, with no separate rollover job to keep in sync.
 */
export type LedgerState = {
  dayKey: string;
  neuronsSpentToday: number;
  /** `undefined` until the first call this ledger has ever recorded — `undefined` always counts as "not within the spacing floor" (mirrors `scheduler.ts`'s `lastChatMs`/etc. convention). */
  lastCallMs: number | undefined;
};

/** A fresh ledger: nothing spent yet, no prior call, dated to `now`'s UTC day. */
export function initialLedgerState(now: number): LedgerState {
  return { dayKey: utcDayKey(now), neuronsSpentToday: 0, lastCallMs: undefined };
}

/** `YYYY-MM-DD` in UTC — deliberately UTC (not local time or the room's timezone, neither of which this Worker has a stable concept of) so rollover is a pure function of `now` alone, matching #848's "UTC day rollover" requirement. */
export function utcDayKey(now: number): string {
  return new Date(now).toISOString().slice(0, 10);
}

/**
 * Neurons already spent on the UTC day containing `now`, per `ledger` — `0`
 * if `ledger` was last touched on a different (necessarily earlier) UTC day,
 * since a day rollover resets spend without any caller having to run a
 * separate "reset" step. Shared by {@link canPersonalize} and
 * {@link recordCall} so the two can never disagree about whether a rollover
 * has happened.
 */
function spentAsOf(ledger: LedgerState, now: number): number {
  return ledger.dayKey === utcDayKey(now) ? ledger.neuronsSpentToday : 0;
}

/**
 * Would spending one more call right now stay within budget AND spacing?
 * Pure, read-only — does not mutate/advance `ledger` (see {@link recordCall}
 * for that). Both conditions must hold:
 *   - budget: today's spend (after UTC-rollover reset, see {@link spentAsOf})
 *     plus one more {@link COST_PER_CALL_NEURONS} must not exceed
 *     {@link DAILY_NEURON_BUDGET}.
 *   - spacing: `now` must be at least {@link MIN_SPACING_MS} past
 *     `ledger.lastCallMs` (or there must be no prior call at all).
 *
 * Never throws — this is pure arithmetic over plain data, there is no
 * failure mode to guard against.
 */
export function canPersonalize(ledger: LedgerState, now: number): boolean {
  const budgetOk = spentAsOf(ledger, now) + COST_PER_CALL_NEURONS <= DAILY_NEURON_BUDGET;
  const spacingOk = ledger.lastCallMs === undefined || now - ledger.lastCallMs >= MIN_SPACING_MS;
  return budgetOk && spacingOk;
}

/**
 * Record that a personalization call happened at `now`, returning the NEXT
 * ledger state — does not mutate `ledger`, mirrors `scheduler.ts`'s
 * `planTick` returning a fresh `nextState` rather than mutating in place.
 * Callers are expected to call this ONLY after `canPersonalize` returned
 * `true` for the same `(ledger, now)` (mirrors `scheduler.ts`'s "picked ⇒
 * spent" contract — see `spammer.ts`'s persist-before-emit comment) — but
 * this function itself does not re-check the budget/spacing, so a caller
 * that calls it unconditionally would silently go over budget. It always
 * applies the same UTC-rollover reset {@link canPersonalize} used, so the two
 * stay consistent even across a rollover boundary.
 */
export function recordCall(ledger: LedgerState, now: number): LedgerState {
  return {
    dayKey: utcDayKey(now),
    neuronsSpentToday: spentAsOf(ledger, now) + COST_PER_CALL_NEURONS,
    lastCallMs: now,
  };
}
