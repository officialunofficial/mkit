import { expect, it } from "vitest";
import { refill, waitForCapacity } from "./model-budget";
it("does not grant a fresh minute allowance at a wall-clock boundary", () => {
    const bucket = refill({ at: 59999, tokens: 7500, requests: 25 }, 60000);
    expect(waitForCapacity(bucket, 7500)).toBe(60);
    expect(waitForCapacity(refill(bucket, 90000), 3750)).toBe(0);
});
it("caps replenishment and tolerates clock regressions", () => {
    expect(refill({ at: 1000, tokens: 7500, requests: 25 }, 61000)).toEqual({
        at: 61000,
        tokens: 0,
        requests: 0,
    });
    expect(refill({ at: 1000, tokens: 7500, requests: 25 }, 0).tokens).toBe(7500);
});
it("waits for the tighter request or token allowance", () => {
    expect(waitForCapacity({ at: 0, tokens: 0, requests: 25 }, 100)).toBe(3);
    expect(waitForCapacity({ at: 0, tokens: 7000, requests: 0 }, 1000)).toBe(4);
});
