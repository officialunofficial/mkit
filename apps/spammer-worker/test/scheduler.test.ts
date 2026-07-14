// test/scheduler.test.ts
//
// PLAN.md build step 3 verification (this file grows through step 7 once
// `src/scheduler.ts` lands): confirm `src/envelope.ts` produces a signature
// that wasm's OWN `ed25519_verify` accepts — proof the copied
// `buildSignedEnvelope`/`makeSignFn` logic is byte-for-byte compatible with
// what the deployed repo-worker verifies — and that `src/identities.ts`'s
// POOL_SIZE-seed pool is fully deterministic (same seeds/pubkeys on every call).
//
// Runs in the "unit" vitest project (plain Node — see vitest.config.ts),
// NOT the "integration" Workers-runtime project `src/wasm.ts` needs, because
// a bare `import x from "mkit-wasm/mkit_wasm_bg.wasm"` only resolves under
// Wrangler's bundler transform. Instead this file inits `mkit-wasm` the same
// way `apps/web/src/lib/mkit.node.ts` does for ITS vitest suite: read the
// `.wasm` bytes off disk and hand them to `init({ module_or_path })`
// directly, bypassing both the browser fetch() path and the Workers bundler
// path. `MkitApi` (from `src/wasm.ts`) is `typeof MkitWasm` for this exact
// `mkit-wasm` package, so the namespace object this produces is structurally
// identical — no adapter needed. No live network calls happen anywhere in
// this file.

import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import initMkit, * as MkitWasm from "mkit-wasm";
import { beforeAll, describe, expect, it } from "vitest";
import { buildSignedEnvelope, canonicalString, procedures } from "../src/envelope";
import { POOL_SIZE, getIdentityPool, makeRoundRobinCursor, seedForIndex } from "../src/identities";
import { hexToBytes } from "../src/hex";
import {
  CHAT_FLOOR_MS,
  PUSH_FLOOR_MS,
  REACTION_FLOOR_MS,
  type EventKind,
  type SchedulerState,
  initialSchedulerState,
  planTick,
} from "../src/scheduler";
import type { MkitApi } from "../src/wasm";

const TEXT_ENCODER = new TextEncoder();

let api: MkitApi;

beforeAll(async () => {
  const requireFn = createRequire(import.meta.url);
  const wasmPath = requireFn.resolve("mkit-wasm/mkit_wasm_bg.wasm");
  const bytes = await readFile(wasmPath);
  await initMkit({ module_or_path: bytes });
  // `MkitWasm` is the module namespace object; after `initMkit` resolves its
  // exported functions are backed by the instantiated wasm instance. This is
  // structurally the same `typeof MkitWasm` shape `src/wasm.ts` types
  // `MkitApi` as, so it satisfies `MkitApi` without a cast.
  api = MkitWasm;
});

describe("envelope.ts — signature verification", () => {
  it("produces an envelope whose signature verifies via wasm's own ed25519_verify", () => {
    const seedHex = seedForIndex(api, 0);
    const bodyDigest = api.blake3_hex(TEXT_ENCODER.encode("test post_message body"));
    const env = buildSignedEnvelope(api, seedHex, {
      procedure: procedures.PostMessage,
      bodyDigest,
    });

    // Sanity: the envelope's own `canonical` field matches recomputing it
    // from its parts (pins the canonical-string shape — see PLAN.md's
    // "envelope.ts duplication drift" risk). Note `SignedEnvelope` doesn't
    // carry `procedure` itself, so `canonicalString` needs the parts spelled
    // out explicitly here, not just `env`.
    expect(env.canonical).toBe(
      canonicalString({
        procedure: procedures.PostMessage,
        bodyDigest,
        createdAt: env.createdAt,
        idempotencyKey: env.idempotencyKey,
      }),
    );
    expect(env.canonical).toBe(
      ["mkit-write:v1", procedures.PostMessage, bodyDigest, env.createdAt, env.idempotencyKey].join("\n"),
    );

    // The server's `AuthInterceptor` verifies
    // `ed25519_verify(sig, blake3(canonical), pubkey)` — reconstruct exactly
    // that here instead of trusting `env.digestHex` blindly.
    const recomputedDigest = api.blake3_hex(TEXT_ENCODER.encode(env.canonical));
    expect(recomputedDigest).toBe(env.digestHex);

    const verified = api.ed25519_verify(
      hexToBytes(env.signatureHex),
      hexToBytes(env.digestHex),
      hexToBytes(env.publicKeyHex),
    );
    expect(verified).toBe(true);

    // The pubkey the envelope reports must be the SAME pubkey the identity
    // pool derives for this seed/index — i.e. the envelope really is signed
    // by identity 0, not some other key.
    const pool = getIdentityPool(api);
    expect(env.publicKeyHex).toBe(pool[0].pubkeyHex);
  });

  it("rejects a tampered signature", () => {
    const seedHex = seedForIndex(api, 1);
    const env = buildSignedEnvelope(api, seedHex, {
      procedure: procedures.PutObject,
      bodyDigest: api.blake3_hex(TEXT_ENCODER.encode("other body")),
    });
    const tamperedSig = hexToBytes(env.signatureHex);
    tamperedSig[0] ^= 0xff;
    const verified = api.ed25519_verify(tamperedSig, hexToBytes(env.digestHex), hexToBytes(env.publicKeyHex));
    expect(verified).toBe(false);
  });

  it("rejects verification against the wrong pubkey", () => {
    const envA = buildSignedEnvelope(api, seedForIndex(api, 2), {
      procedure: procedures.React,
      bodyDigest: api.blake3_hex(TEXT_ENCODER.encode("body-a")),
    });
    const pubkeyB = getIdentityPool(api)[3].pubkeyHex;
    const verified = api.ed25519_verify(hexToBytes(envA.signatureHex), hexToBytes(envA.digestHex), hexToBytes(pubkeyB));
    expect(verified).toBe(false);
  });
});

describe("identities.ts — deterministic pool", () => {
  it("derives POOL_SIZE identities with stable, unique seeds/pubkeys across repeated calls", () => {
    const first = getIdentityPool(api);
    const second = getIdentityPool(api);
    expect(first).toHaveLength(POOL_SIZE);
    expect(second).toEqual(first);

    for (let i = 0; i < POOL_SIZE; i++) {
      expect(first[i].index).toBe(i);
      expect(first[i].seedHex).toMatch(/^[0-9a-f]{64}$/);
      expect(first[i].pubkeyHex).toMatch(/^[0-9a-f]{64}$/);
    }

    const uniqueSeeds = new Set(first.map((id) => id.seedHex));
    const uniquePubkeys = new Set(first.map((id) => id.pubkeyHex));
    expect(uniqueSeeds.size).toBe(POOL_SIZE);
    expect(uniquePubkeys.size).toBe(POOL_SIZE);
  });

  it("recomputes the exact same per-index seed independent of the pool memo", () => {
    const pool = getIdentityPool(api);
    for (let i = 0; i < POOL_SIZE; i++) {
      expect(seedForIndex(api, i)).toBe(pool[i].seedHex);
      // Calling it again gives the same answer too — no hidden counter/state.
      expect(seedForIndex(api, i)).toBe(pool[i].seedHex);
    }
  });

  it("round-robins across every pool index exactly once before wrapping", () => {
    const cursor = makeRoundRobinCursor();
    const seen = new Set<number>();
    for (let i = 0; i < POOL_SIZE; i++) seen.add(cursor.next());
    expect(seen.size).toBe(POOL_SIZE);
    expect(cursor.next()).toBe(0); // wraps back to the start
    expect(cursor.next()).toBe(1);
  });
});

// -----------------------------------------------------------------------------
// scheduler.ts — build step 7 verification
// -----------------------------------------------------------------------------
//
// `planTick` is pure (no wasm, no I/O), so these run entirely in the "unit"
// vitest project with plain in-memory simulation — no `beforeAll` wasm init
// needed for this describe block.

type FloorViolation = {
  identityIndex: number;
  kind: EventKind;
  now: number;
  sinceLastMs: number;
  floorMs: number;
};

/**
 * Drive `planTick` for `totalTicks` ticks, advancing an independent clock by
 * `tickIntervalMs` (a fixed number, or a per-tick-index function for
 * irregular/bursty cadences) each tick, and independently re-verify every
 * emitted event against ground-truth "last seen" trackers kept OUTSIDE
 * `planTick`'s own state — i.e. this does not just trust `planTick`'s
 * internal bookkeeping, it re-derives the floor check from the raw event
 * stream. `commit` and `remix` share ONE combined push-floor tracker per
 * identity (PLAN.md: "Writes ... combined" — a commit 5s ago and a remix now
 * from the same identity would violate the SAME 30s push floor).
 */
function runSimulation(
  totalTicks: number,
  tickIntervalMs: number | ((tickIndex: number) => number),
  poolSize: number = POOL_SIZE,
): { violations: FloorViolation[]; totalEvents: number; elapsedMs: number; kindCounts: Record<EventKind, number> } {
  let state = initialSchedulerState(poolSize);
  let now = 0;
  const lastChat = new Array<number | undefined>(poolSize).fill(undefined);
  const lastPush = new Array<number | undefined>(poolSize).fill(undefined);
  const lastReaction = new Array<number | undefined>(poolSize).fill(undefined);
  const violations: FloorViolation[] = [];
  const kindCounts: Record<EventKind, number> = { chat: 0, commit: 0, remix: 0, reaction: 0 };
  let totalEvents = 0;

  for (let t = 0; t < totalTicks; t++) {
    now += typeof tickIntervalMs === "function" ? tickIntervalMs(t) : tickIntervalMs;
    const { events, nextState } = planTick(state, now);
    state = nextState;

    for (const ev of events) {
      totalEvents++;
      kindCounts[ev.kind]++;

      if (ev.kind === "chat") {
        const last = lastChat[ev.identityIndex];
        if (last !== undefined && now - last < CHAT_FLOOR_MS) {
          violations.push({ identityIndex: ev.identityIndex, kind: ev.kind, now, sinceLastMs: now - last, floorMs: CHAT_FLOOR_MS });
        }
        lastChat[ev.identityIndex] = now;
      } else if (ev.kind === "commit" || ev.kind === "remix") {
        const last = lastPush[ev.identityIndex];
        if (last !== undefined && now - last < PUSH_FLOOR_MS) {
          violations.push({ identityIndex: ev.identityIndex, kind: ev.kind, now, sinceLastMs: now - last, floorMs: PUSH_FLOOR_MS });
        }
        lastPush[ev.identityIndex] = now;
      } else {
        const last = lastReaction[ev.identityIndex];
        if (last !== undefined && now - last < REACTION_FLOOR_MS) {
          violations.push({ identityIndex: ev.identityIndex, kind: ev.kind, now, sinceLastMs: now - last, floorMs: REACTION_FLOOR_MS });
        }
        lastReaction[ev.identityIndex] = now;
      }
    }
  }

  return { violations, totalEvents, elapsedMs: now, kindCounts };
}

describe("scheduler.ts — tick planner", () => {
  it("simulates a full hour at the real 1000ms alarm cadence: zero floor violations, aggregate rate ~3/s", () => {
    const SECONDS_PER_HOUR = 3600;
    const { violations, totalEvents, elapsedMs, kindCounts } = runSimulation(SECONDS_PER_HOUR, 1000);

    expect(violations).toEqual([]);
    expect(elapsedMs).toBe(SECONDS_PER_HOUR * 1000);

    // PLAN.md targets "~3 events/s aggregate" (base 2 chat + 1 push), "inside
    // the 2-4/s target", plus an occasional additive reaction.
    const eventsPerSecond = totalEvents / (elapsedMs / 1000);
    expect(eventsPerSecond).toBeGreaterThan(2.5);
    expect(eventsPerSecond).toBeLessThan(4);

    // Push kind mix: remix on ~every 8th push tick, commit otherwise.
    expect(kindCounts.commit).toBeGreaterThan(0);
    expect(kindCounts.remix).toBeGreaterThan(0);
    const pushTotal = kindCounts.commit + kindCounts.remix;
    const remixFraction = kindCounts.remix / pushTotal;
    expect(remixFraction).toBeGreaterThan(0.1);
    expect(remixFraction).toBeLessThan(0.2); // ~1/8 = 0.125
  });

  it("never violates a floor even under bursty/irregular tick timing", () => {
    // Deterministic (no RNG) alternation of fast bursts and slow gaps —
    // proves the floor check is a real elapsed-time comparison against `now`,
    // not merely an artifact of steady round-robin spacing. Some ticks in a
    // burst will legitimately find nothing eligible and emit fewer than 3
    // events — that's correct behavior, not a bug.
    const pattern = [1000, 1000, 200, 200, 200, 1000, 8000, 1000, 500, 1000];
    const totalTicks = 3600;
    const { violations } = runSimulation(totalTicks, (t) => pattern[t % pattern.length]!);
    expect(violations).toEqual([]);
  });

  it("never violates a floor across a full simulated hour for every pool size from 1 to 64", () => {
    // Smaller pools are the adversarial case for the safety floors (less
    // round-robin spacing per identity), so sweep them explicitly rather
    // than only exercising the production POOL_SIZE=64.
    for (const poolSize of [1, 2, 3, 8, 16, 32, 64]) {
      const { violations } = runSimulation(3600, 1000, poolSize);
      expect(violations, `poolSize=${poolSize}`).toEqual([]);
    }
  });

  it("boundary: refuses a chat pick 1ms inside the floor, permits one exactly at the floor", () => {
    const lastChatAt = 100_000;
    const state: SchedulerState = {
      lastChatMs: [lastChatAt, undefined],
      lastPushMs: [undefined, undefined],
      lastReactionMs: [undefined, undefined],
      chatCursor: 0,
      pushCursor: 0,
      reactionCursor: 0,
      tick: 1,
    };

    const tooSoon = planTick(state, lastChatAt + CHAT_FLOOR_MS - 1);
    const chatPicksTooSoon = tooSoon.events.filter((e) => e.kind === "chat").map((e) => e.identityIndex);
    expect(chatPicksTooSoon).not.toContain(0);

    const exactlyAtFloor = planTick(state, lastChatAt + CHAT_FLOOR_MS);
    const chatPicksAtFloor = exactlyAtFloor.events.filter((e) => e.kind === "chat").map((e) => e.identityIndex);
    expect(chatPicksAtFloor).toContain(0);
  });

  it("boundary: refuses a push pick 1ms inside the floor, permits one exactly at the floor", () => {
    const lastPushAt = 500_000;
    const state: SchedulerState = {
      lastChatMs: [undefined, undefined],
      lastPushMs: [lastPushAt, undefined],
      lastReactionMs: [undefined, undefined],
      chatCursor: 0,
      pushCursor: 0,
      reactionCursor: 0,
      tick: 0, // commit tick (not a remix boundary), doesn't affect eligibility
    };

    const tooSoon = planTick(state, lastPushAt + PUSH_FLOOR_MS - 1);
    const pushPicksTooSoon = tooSoon.events
      .filter((e) => e.kind === "commit" || e.kind === "remix")
      .map((e) => e.identityIndex);
    expect(pushPicksTooSoon).not.toContain(0);

    const exactlyAtFloor = planTick(state, lastPushAt + PUSH_FLOOR_MS);
    const pushPicksAtFloor = exactlyAtFloor.events
      .filter((e) => e.kind === "commit" || e.kind === "remix")
      .map((e) => e.identityIndex);
    expect(pushPicksAtFloor).toContain(0);
  });

  it("returns fewer events (not a floor-violating pick) when the entire pool is inside the floor", () => {
    const now = 1_000_000;
    const state: SchedulerState = {
      lastChatMs: [now, now], // both identities chatted "now" already
      lastPushMs: [undefined, undefined],
      lastReactionMs: [undefined, undefined],
      chatCursor: 0,
      pushCursor: 0,
      reactionCursor: 0,
      tick: 0,
    };

    const { events } = planTick(state, now + 1); // 1ms later — nobody clears the 2500ms chat floor
    expect(events.filter((e) => e.kind === "chat")).toEqual([]);
  });

  it("is a pure function: identical (state, now) always yields identical output", () => {
    const state = initialSchedulerState(8);
    const a = planTick(state, 42_000);
    const b = planTick(state, 42_000);
    expect(a.events).toEqual(b.events);
    expect(a.nextState).toEqual(b.nextState);
    // The input state itself must be untouched (no mutation).
    expect(state).toEqual(initialSchedulerState(8));
  });
});
