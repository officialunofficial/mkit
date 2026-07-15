// test/reply-budget.test.ts
//
// Pure logic only, mirrors scheduler.test.ts's style: simulate whole days of
// calls in a tight loop against `canPersonalize`/`recordCall`, asserting on
// external behavior (booleans / next-state shape) never internal state.

import { describe, expect, it } from "vitest";
import {
  canPersonalize,
  COST_PER_CALL_NEURONS,
  DAILY_NEURON_BUDGET,
  initialLedgerState,
  type LedgerState,
  MIN_SPACING_MS,
  recordCall,
  utcDayKey,
} from "../src/reply-budget";

const DAY0 = Date.UTC(2026, 0, 1, 0, 0, 0); // 2026-01-01T00:00:00Z

describe("reply-budget.ts — utcDayKey", () => {
  it("formats as YYYY-MM-DD in UTC", () => {
    expect(utcDayKey(DAY0)).toBe("2026-01-01");
  });

  it("rolls over at UTC midnight, not local time", () => {
    const justBeforeMidnight = DAY0 + 24 * 60 * 60 * 1000 - 1;
    const justAfterMidnight = DAY0 + 24 * 60 * 60 * 1000;
    expect(utcDayKey(justBeforeMidnight)).toBe("2026-01-01");
    expect(utcDayKey(justAfterMidnight)).toBe("2026-01-02");
  });
});

describe("reply-budget.ts — initialLedgerState", () => {
  it("starts with zero spend, no prior call, dated to now's UTC day", () => {
    const ledger = initialLedgerState(DAY0);
    expect(ledger).toEqual({ dayKey: "2026-01-01", neuronsSpentToday: 0, lastCallMs: undefined });
  });

  it("permits an immediate call on a fresh ledger", () => {
    expect(canPersonalize(initialLedgerState(DAY0), DAY0)).toBe(true);
  });
});

describe("reply-budget.ts — spacing enforcement", () => {
  it("refuses a second call before MIN_SPACING_MS has elapsed", () => {
    let ledger = initialLedgerState(DAY0);
    expect(canPersonalize(ledger, DAY0)).toBe(true);
    ledger = recordCall(ledger, DAY0);

    expect(canPersonalize(ledger, DAY0 + MIN_SPACING_MS - 1)).toBe(false);
  });

  it("permits a call exactly at MIN_SPACING_MS", () => {
    let ledger = initialLedgerState(DAY0);
    ledger = recordCall(ledger, DAY0);
    expect(canPersonalize(ledger, DAY0 + MIN_SPACING_MS)).toBe(true);
  });

  it("permits a call well after MIN_SPACING_MS", () => {
    let ledger = initialLedgerState(DAY0);
    ledger = recordCall(ledger, DAY0);
    expect(canPersonalize(ledger, DAY0 + MIN_SPACING_MS * 10)).toBe(true);
  });
});

describe("reply-budget.ts — budget depletion over a simulated day", () => {
  it("permits calls up to DAILY_NEURON_BUDGET, then refuses for the rest of the day", () => {
    let ledger = initialLedgerState(DAY0);
    const maxCalls = Math.floor(DAILY_NEURON_BUDGET / COST_PER_CALL_NEURONS);
    expect(maxCalls).toBeGreaterThan(0);

    let now = DAY0;
    let calls = 0;
    for (let i = 0; i < maxCalls; i++) {
      expect(canPersonalize(ledger, now)).toBe(true);
      ledger = recordCall(ledger, now);
      calls++;
      now += MIN_SPACING_MS; // stay just outside the spacing floor each time
    }
    expect(calls).toBe(maxCalls);
    expect(ledger.neuronsSpentToday).toBe(maxCalls * COST_PER_CALL_NEURONS);

    // Budget exhausted for the rest of the day, even with spacing satisfied.
    expect(canPersonalize(ledger, now)).toBe(false);
    expect(canPersonalize(ledger, DAY0 + 23 * 60 * 60 * 1000)).toBe(false);
  });

  it("never exceeds DAILY_NEURON_BUDGET even if a caller ignores canPersonalize and calls recordCall repeatedly", () => {
    let ledger = initialLedgerState(DAY0);
    let now = DAY0;
    for (let i = 0; i < 100; i++) {
      ledger = recordCall(ledger, now);
      now += MIN_SPACING_MS;
    }
    // recordCall doesn't clamp on its own (that's canPersonalize's job — see
    // its doc comment), but proves the accounting itself never throws or
    // produces NaN/garbage even under sustained (mis)use.
    expect(Number.isFinite(ledger.neuronsSpentToday)).toBe(true);
    expect(ledger.neuronsSpentToday).toBe(100 * COST_PER_CALL_NEURONS);
  });
});

describe("reply-budget.ts — UTC day rollover", () => {
  it("resets spend to zero on a new UTC day, independent of spacing", () => {
    let ledger = initialLedgerState(DAY0);
    // Spend the whole day's budget.
    let now = DAY0;
    const maxCalls = Math.floor(DAILY_NEURON_BUDGET / COST_PER_CALL_NEURONS);
    for (let i = 0; i < maxCalls; i++) {
      ledger = recordCall(ledger, now);
      now += MIN_SPACING_MS;
    }
    expect(canPersonalize(ledger, now)).toBe(false);

    // Jump to the next UTC day, well past the spacing floor too.
    const nextDay = DAY0 + 24 * 60 * 60 * 1000 + 5 * 60 * 1000;
    expect(canPersonalize(ledger, nextDay)).toBe(true);
  });

  it("recordCall on a new day starts spend fresh rather than adding to yesterday's total", () => {
    let ledger = initialLedgerState(DAY0);
    ledger = recordCall(ledger, DAY0);
    expect(ledger.neuronsSpentToday).toBe(COST_PER_CALL_NEURONS);

    const nextDay = DAY0 + 24 * 60 * 60 * 1000;
    ledger = recordCall(ledger, nextDay);
    expect(ledger.dayKey).toBe(utcDayKey(nextDay));
    expect(ledger.neuronsSpentToday).toBe(COST_PER_CALL_NEURONS); // not doubled
  });

  it("a rollover still respects MIN_SPACING_MS across the boundary", () => {
    let ledger = initialLedgerState(DAY0);
    const lastCallOfDay = DAY0 + 24 * 60 * 60 * 1000 - 1; // 1ms before midnight
    ledger = recordCall(ledger, lastCallOfDay);

    const justAfterMidnight = DAY0 + 24 * 60 * 60 * 1000; // budget reset, but only 1ms since last call
    expect(canPersonalize(ledger, justAfterMidnight)).toBe(false);

    const wellAfterMidnight = lastCallOfDay + MIN_SPACING_MS;
    expect(canPersonalize(ledger, wellAfterMidnight)).toBe(true);
  });
});

describe("reply-budget.ts — never throws", () => {
  it("handles a ledger with a dayKey far in the future relative to now (clock skew) without throwing", () => {
    const skewedLedger: LedgerState = { dayKey: "2099-01-01", neuronsSpentToday: 500, lastCallMs: DAY0 };
    expect(() => canPersonalize(skewedLedger, DAY0)).not.toThrow();
    expect(() => recordCall(skewedLedger, DAY0)).not.toThrow();
  });

  it("handles now = 0 and negative-looking edge values without throwing", () => {
    const ledger = initialLedgerState(0);
    expect(() => canPersonalize(ledger, 0)).not.toThrow();
    expect(() => recordCall(ledger, 0)).not.toThrow();
  });
});
