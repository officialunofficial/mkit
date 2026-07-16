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
  MAX_BUNDLES_IN_FLIGHT,
  PUSH_FLOOR_MS,
  REACTION_FLOOR_MS,
  RESPONSE_AUTHOR_COOLDOWN_MS,
  RESPONSE_BUNDLE_SPREAD_MS,
  RESPONSE_CHAT_INCLUDE_PERCENT,
  RESPONSE_REACTION_COUNT_MIN,
  RESPONSE_REACTION_COUNT_RANGE,
  RESPONSE_REMIX_INCLUDE_PERCENT,
  type EventKind,
  type RealEventRef,
  type ResponseIntent,
  type SchedulerState,
  enqueueResponseBundle,
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

  it("backward compat: a state with the new response fields entirely absent behaves identically to an explicit-undefined state", () => {
    const withExplicitUndefined: SchedulerState = {
      ...initialSchedulerState(8),
      responseQueue: undefined,
      lastBundleMsByAuthor: undefined,
      reactionIdentitiesByBundle: undefined,
    };
    const legacyShape: SchedulerState = {
      lastChatMs: new Array(8).fill(undefined),
      lastPushMs: new Array(8).fill(undefined),
      lastReactionMs: new Array(8).fill(undefined),
      chatCursor: 0,
      pushCursor: 0,
      reactionCursor: 0,
      tick: 0,
      // No responseQueue / lastBundleMsByAuthor / reactionIdentitiesByBundle
      // keys at all — mirrors `spammer.ts`'s `loadSchedulerState`, which
      // this issue deliberately does not touch (see #854).
    };
    const a = planTick(withExplicitUndefined, 42_000);
    const b = planTick(legacyShape, 42_000);
    expect(a.events).toEqual(b.events);
    expect(a.nextState).toEqual(b.nextState);
  });
});

// -----------------------------------------------------------------------------
// scheduler.ts — issue #850 verification: response-queue draining
// -----------------------------------------------------------------------------

describe("enqueueResponseBundle — bundle composition", () => {
  const realEvent = (targetIdHex: string, authorPubkeyHex = "real-author-1", ref = "refs/heads/main"): RealEventRef => ({
    kind: "commit",
    ref,
    targetIdHex,
    authorPubkeyHex,
  });

  it("composes RESPONSE_REACTION_COUNT_MIN..+RANGE-1 reactions from distinct, increasing notBeforeMs offsets spread within RESPONSE_BUNDLE_SPREAD_MS", () => {
    for (const targetIdHex of ["target-a", "target-b", "target-c", "target-d", "target-e"]) {
      const state = enqueueResponseBundle(initialSchedulerState(), realEvent(targetIdHex), 1_000_000);
      const reactions = (state.responseQueue ?? []).filter((intent) => intent.kind === "reaction");

      expect(reactions.length).toBeGreaterThanOrEqual(RESPONSE_REACTION_COUNT_MIN);
      expect(reactions.length).toBeLessThanOrEqual(RESPONSE_REACTION_COUNT_MIN + RESPONSE_REACTION_COUNT_RANGE - 1);

      const offsets = reactions.map((r) => r.notBeforeMs - 1_000_000).sort((x, y) => x - y);
      expect(new Set(offsets).size).toBe(offsets.length); // distinct
      for (const offset of offsets) {
        expect(offset).toBeGreaterThanOrEqual(0);
        expect(offset).toBeLessThan(RESPONSE_BUNDLE_SPREAD_MS);
      }

      // Every intent in the bundle shares one bundleId and carries the real event's ref/author through.
      const bundleIds = new Set((state.responseQueue ?? []).map((i) => i.bundleId));
      expect(bundleIds.size).toBe(1);
      for (const intent of state.responseQueue ?? []) {
        expect(intent.ref).toBe("refs/heads/main");
        expect(intent.realAuthorPubkeyHex).toBe("real-author-1");
        expect(intent.targetIdHex).toBe(targetIdHex);
      }
    }
  });

  it("includes at most one chat reply and a remix at a rate near RESPONSE_REMIX_INCLUDE_PERCENT, both deterministic per target hash", () => {
    const targets = Array.from({ length: 500 }, (_, i) => `target-${i}`);
    let chatCount = 0;
    let remixCount = 0;

    for (const targetIdHex of targets) {
      const state = enqueueResponseBundle(initialSchedulerState(), realEvent(targetIdHex), 0);
      const kinds = (state.responseQueue ?? []).map((intent) => intent.kind);
      const chatKinds = kinds.filter((k) => k === "chat");
      expect(chatKinds.length).toBeLessThanOrEqual(1);
      if (chatKinds.length === 1) chatCount++;
      if (kinds.includes("remix")) remixCount++;

      // Determinism: re-deriving the SAME targetIdHex from a fresh state yields the identical bundle contents.
      const again = enqueueResponseBundle(initialSchedulerState(), realEvent(targetIdHex), 0);
      expect(again.responseQueue).toEqual(state.responseQueue);
    }

    const remixFraction = remixCount / targets.length;
    expect(remixFraction).toBeGreaterThan(0.1);
    expect(remixFraction).toBeLessThan(0.3); // ~20% target (RESPONSE_REMIX_INCLUDE_PERCENT), generous tolerance for hash variance

    const chatFraction = chatCount / targets.length;
    expect(chatFraction).toBeGreaterThan(0.65);
    expect(chatFraction).toBeLessThan(0.95); // ~80% target (RESPONSE_CHAT_INCLUDE_PERCENT), generous tolerance
  });
});

describe("enqueueResponseBundle — per-author cooldown and global bundle cap", () => {
  const realEvent = (targetIdHex: string, authorPubkeyHex: string): RealEventRef => ({
    kind: "commit",
    ref: "refs/heads/main",
    targetIdHex,
    authorPubkeyHex,
  });

  /** Drain a state's responseQueue to empty by repeatedly calling planTick with a generously-spaced clock. */
  function drainFully(state: SchedulerState): SchedulerState {
    let s = state;
    for (let i = 1; i <= 100 && (s.responseQueue?.length ?? 0) > 0; i++) {
      s = planTick(s, i * (RESPONSE_BUNDLE_SPREAD_MS + PUSH_FLOOR_MS)).nextState;
    }
    return s;
  }

  it("an event whose author already got a bundle within RESPONSE_AUTHOR_COOLDOWN_MS enqueues nothing", () => {
    const author = "cooldown-author";
    const first = enqueueResponseBundle(initialSchedulerState(), realEvent("t1", author), 0);
    expect(first.responseQueue!.length).toBeGreaterThan(0);
    const drained = drainFully(first);
    expect(drained.responseQueue ?? []).toEqual([]);

    const stillCoolingDown = enqueueResponseBundle(drained, realEvent("t2", author), RESPONSE_AUTHOR_COOLDOWN_MS - 1);
    expect(stillCoolingDown.responseQueue ?? []).toEqual([]);
    expect(stillCoolingDown.lastBundleMsByAuthor).toEqual(drained.lastBundleMsByAuthor);
  });

  it("enqueues again once the cooldown has fully elapsed", () => {
    const author = "cooldown-author-2";
    const first = enqueueResponseBundle(initialSchedulerState(), realEvent("t1", author), 0);
    const drained = drainFully(first);

    const afterCooldown = enqueueResponseBundle(drained, realEvent("t2", author), RESPONSE_AUTHOR_COOLDOWN_MS);
    expect(afterCooldown.responseQueue!.length).toBeGreaterThan(0);
    expect(afterCooldown.lastBundleMsByAuthor?.[author]).toBe(RESPONSE_AUTHOR_COOLDOWN_MS);
  });

  it("drops an event from a DIFFERENT author that arrives while MAX_BUNDLES_IN_FLIGHT bundles already have pending intents — acknowledgment, not dogpile", () => {
    const inFlight = enqueueResponseBundle(initialSchedulerState(), realEvent("in-flight", "author-1"), 0);
    expect(inFlight.responseQueue!.length).toBeGreaterThan(0);

    const dropped = enqueueResponseBundle(inFlight, realEvent("dropped", "author-2"), 1000);
    expect(dropped.responseQueue).toEqual(inFlight.responseQueue);
    expect(dropped.lastBundleMsByAuthor?.["author-2"]).toBeUndefined();
  });

  it("allows a new bundle once the in-flight bundle has fully drained", () => {
    const first = enqueueResponseBundle(initialSchedulerState(), realEvent("first", "author-1"), 0);
    const drained = drainFully(first);
    expect(drained.responseQueue ?? []).toEqual([]);

    const second = enqueueResponseBundle(drained, realEvent("second", "author-2"), 5_000_000);
    expect(second.responseQueue!.length).toBeGreaterThan(0);
  });
});

describe("enqueueResponseBundle — lastBundleMsByAuthor pruning (unbounded-growth fix)", () => {
  const realEvent = (targetIdHex: string, authorPubkeyHex: string): RealEventRef => ({
    kind: "commit",
    ref: "refs/heads/main",
    targetIdHex,
    authorPubkeyHex,
  });

  /**
   * Drain a state's responseQueue to empty by repeatedly calling planTick
   * with a generously-spaced clock, starting `startNow` ms after the bundle
   * being drained was enqueued (its intents' `notBeforeMs` are absolute, so
   * this must track whatever `now` the enqueue used).
   */
  function drainFully(state: SchedulerState, startNow: number): SchedulerState {
    let s = state;
    for (let i = 1; i <= 100 && (s.responseQueue?.length ?? 0) > 0; i++) {
      s = planTick(s, startNow + i * (RESPONSE_BUNDLE_SPREAD_MS + PUSH_FLOOR_MS)).nextState;
    }
    return s;
  }

  it("drops an author entry whose cooldown has fully elapsed on the next successful enqueue", () => {
    const first = enqueueResponseBundle(initialSchedulerState(), realEvent("t1", "old-author"), 0);
    const drained = drainFully(first, 0);
    expect(drained.lastBundleMsByAuthor).toEqual({ "old-author": 0 });

    // Exactly RESPONSE_AUTHOR_COOLDOWN_MS later, old-author's entry is fully
    // expired (the cooldown check is a strict `<`, so `now - ms === COOLDOWN_MS`
    // no longer counts as cooling down) — a DIFFERENT author's successful
    // enqueue should prune it away.
    const expiredAt = RESPONSE_AUTHOR_COOLDOWN_MS;
    const next = enqueueResponseBundle(drained, realEvent("t2", "new-author"), expiredAt);

    expect(next.lastBundleMsByAuthor).toEqual({ "new-author": expiredAt });
    expect(next.lastBundleMsByAuthor?.["old-author"]).toBeUndefined();
  });

  it("keeps a within-cooldown author entry across a different author's successful enqueue", () => {
    const first = enqueueResponseBundle(initialSchedulerState(), realEvent("t1", "old-author"), 0);
    const drained = drainFully(first, 0);
    expect(drained.lastBundleMsByAuthor).toEqual({ "old-author": 0 });

    const stillWithinCooldown = RESPONSE_AUTHOR_COOLDOWN_MS - 1;
    const next = enqueueResponseBundle(drained, realEvent("t2", "new-author"), stillWithinCooldown);

    expect(next.lastBundleMsByAuthor).toEqual({ "old-author": 0, "new-author": stillWithinCooldown });
  });

  it("does NOT prune (or otherwise touch) lastBundleMsByAuthor on a no-op enqueue — cooldown-hit and cap-hit paths return state completely unchanged", () => {
    // Cooldown-hit path: an author already inside their own cooldown.
    const author = "cooldown-author";
    const withOldAuthor = enqueueResponseBundle(initialSchedulerState(), realEvent("t0", "long-expired-author"), 0);
    const drainedOld = drainFully(withOldAuthor, 0);
    const withBoth = enqueueResponseBundle(
      drainedOld,
      realEvent("t1", author),
      RESPONSE_AUTHOR_COOLDOWN_MS * 2, // long-expired-author's entry is now stale, but this call still succeeds
    );
    const drainedBoth = drainFully(withBoth, RESPONSE_AUTHOR_COOLDOWN_MS * 2);
    // The successful enqueue above already pruned long-expired-author away.
    expect(drainedBoth.lastBundleMsByAuthor).toEqual({ [author]: RESPONSE_AUTHOR_COOLDOWN_MS * 2 });

    const stillCoolingDown = enqueueResponseBundle(
      drainedBoth,
      realEvent("t2", author),
      RESPONSE_AUTHOR_COOLDOWN_MS * 2 + RESPONSE_AUTHOR_COOLDOWN_MS - 1,
    );
    // No-op (cooldown hit): the object comes back completely unchanged, not
    // just deep-equal — pruning never runs on this path.
    expect(stillCoolingDown).toBe(drainedBoth);

    // Cap-hit path: a bundle is in flight, so a different author is dropped.
    const inFlight = enqueueResponseBundle(initialSchedulerState(), realEvent("in-flight", "author-a"), 0);
    const dropped = enqueueResponseBundle(inFlight, realEvent("dropped", "author-b"), RESPONSE_AUTHOR_COOLDOWN_MS * 5);
    expect(dropped).toBe(inFlight);
  });

  it("keeps lastBundleMsByAuthor bounded over a long stream of many distinct authors, never approaching one entry per author ever seen", () => {
    let state = initialSchedulerState();
    let now = 0;
    const AUTHOR_COUNT = 500;
    // Space authors far enough apart that each new bundle both clears the
    // global in-flight cap AND falls outside every earlier author's cooldown
    // window by the time it lands — the worst case for "one entry per
    // distinct author ever seen" growth, which is exactly what the fix rules out.
    const SPACING_MS = RESPONSE_AUTHOR_COOLDOWN_MS * 2;

    for (let i = 0; i < AUTHOR_COUNT; i++) {
      now += SPACING_MS;
      state = enqueueResponseBundle(state, realEvent(`target-${i}`, `author-${i}`), now);
      state = drainFully(state, now);

      // Bounded regardless of how many distinct authors have EVER been seen —
      // only entries within one cooldown window of `now` can still be present,
      // and at this spacing that's at most the just-added entry.
      expect(Object.keys(state.lastBundleMsByAuthor ?? {}).length).toBeLessThanOrEqual(1);
    }

    // Sanity: this really did see AUTHOR_COUNT distinct authors, and the map
    // never grew anywhere close to that size.
    expect(Object.keys(state.lastBundleMsByAuthor ?? {}).length).toBeLessThan(AUTHOR_COUNT);
  });
});

describe("planTick — response-queue draining", () => {
  const POOL = 8;

  function baseState(overrides: Partial<SchedulerState> = {}): SchedulerState {
    return { ...initialSchedulerState(POOL), ...overrides };
  }

  const intent = (bundleId: string, kind: ResponseIntent["kind"], notBeforeMs: number): ResponseIntent => ({
    kind,
    targetIdHex: "real-target-hex",
    ref: "refs/heads/feature",
    realAuthorPubkeyHex: "real-author",
    notBeforeMs,
    bundleId,
  });

  it("drains a due reaction/chat/remix intent through its own floor, carrying the response payload on the PlannedEvent", () => {
    const state = baseState({
      responseQueue: [intent("b1", "reaction", 0), intent("b1", "chat", 0), intent("b1", "remix", 0)],
    });
    const { events, nextState } = planTick(state, 0);

    const expectedPayload = { targetIdHex: "real-target-hex", ref: "refs/heads/feature", realAuthorPubkeyHex: "real-author" };
    expect(events.find((e) => e.kind === "reaction" && e.response)?.response).toEqual(expectedPayload);
    expect(events.find((e) => e.kind === "chat" && e.response)?.response).toEqual(expectedPayload);
    expect(events.find((e) => e.kind === "remix" && e.response)?.response).toEqual(expectedPayload);

    // Every queued intent was due and the pool (8) had room — the bundle fully drains this tick.
    expect(nextState.responseQueue ?? []).toEqual([]);
  });

  it("leaves a not-yet-due intent queued and never emits it early", () => {
    const state = baseState({ responseQueue: [intent("b1", "reaction", 5000)] });
    const { events, nextState } = planTick(state, 1000);
    expect(events.some((e) => e.response)).toBe(false);
    expect(nextState.responseQueue).toEqual([intent("b1", "reaction", 5000)]);
  });

  it("requeues (never drops) a due intent when the entire pool is inside its floor this tick", () => {
    const state = baseState({
      lastReactionMs: new Array(POOL).fill(0),
      responseQueue: [intent("b1", "reaction", 0)],
    });
    const { events, nextState } = planTick(state, 1); // 1ms later — nobody clears REACTION_FLOOR_MS (200ms)
    expect(events.some((e) => e.kind === "reaction")).toBe(false);
    expect(nextState.responseQueue).toEqual([intent("b1", "reaction", 0)]);
  });

  it("requeues (never drops) a due chat intent when the entire pool is inside CHAT_FLOOR_MS", () => {
    const state = baseState({
      lastChatMs: new Array(POOL).fill(0),
      responseQueue: [intent("b1", "chat", 0)],
    });
    const { events, nextState } = planTick(state, 1); // 1ms later — nobody clears CHAT_FLOOR_MS (2500ms)
    expect(events.some((e) => e.kind === "chat")).toBe(false);
    expect(nextState.responseQueue).toEqual([intent("b1", "chat", 0)]);
  });

  it("requeues (never drops) a due remix intent when the entire pool is inside PUSH_FLOOR_MS", () => {
    const state = baseState({
      lastPushMs: new Array(POOL).fill(0),
      responseQueue: [intent("b1", "remix", 0)],
    });
    const { events, nextState } = planTick(state, 1); // 1ms later — nobody clears PUSH_FLOOR_MS (30000ms)
    expect(events.some((e) => e.response && e.kind === "remix")).toBe(false);
    expect(nextState.responseQueue).toEqual([intent("b1", "remix", 0)]);
  });

  it("a response pick and an ambient pick never double-book an identity's floor in the same tick (pool size 1)", () => {
    const state: SchedulerState = {
      lastChatMs: [undefined],
      lastPushMs: [undefined],
      lastReactionMs: [undefined],
      chatCursor: 0,
      pushCursor: 0,
      reactionCursor: 0,
      tick: 0, // commit push-kind tick AND a REACTION_EVERY_N_TICKS boundary — both ambient categories are "live" this tick
      responseQueue: [intent("b1", "reaction", 0), intent("b1", "chat", 0), intent("b1", "remix", 0)],
    };

    const { events } = planTick(state, 0);

    // Exactly one event per category — the response pick claimed the pool's
    // only identity, so the ambient picks that would otherwise ALSO fire
    // this tick (2 chat, 1 push, 1 reaction) all found nobody eligible.
    const reactionEvents = events.filter((e) => e.kind === "reaction");
    const chatEvents = events.filter((e) => e.kind === "chat");
    const pushEvents = events.filter((e) => e.kind === "commit" || e.kind === "remix");
    expect(reactionEvents).toHaveLength(1);
    expect(chatEvents).toHaveLength(1);
    expect(pushEvents).toHaveLength(1);

    // The single push event is the RESPONSE remix (not a separate ambient commit).
    expect(pushEvents[0]!.kind).toBe("remix");
    expect(pushEvents[0]!.response).toBeDefined();
    expect(chatEvents[0]!.response).toBeDefined();
    expect(reactionEvents[0]!.response).toBeDefined();
  });

  it("keeps reaction intents within one bundle on DISTINCT identities even when they drain across separate ticks", () => {
    const poolSize = 2;
    // tick fixed at 1 (not a REACTION_EVERY_N_TICKS boundary) across both
    // calls so ambient reaction picks never interfere with this assertion.
    const stateA: SchedulerState = {
      lastChatMs: new Array(poolSize).fill(undefined),
      lastPushMs: new Array(poolSize).fill(undefined),
      lastReactionMs: new Array(poolSize).fill(undefined),
      chatCursor: 0,
      pushCursor: 0,
      reactionCursor: 0,
      tick: 1,
      responseQueue: [intent("bundle-x", "reaction", 1000)],
    };
    const resultA = planTick(stateA, 1000);
    const firstIdentity = resultA.events.find((e) => e.kind === "reaction")?.identityIndex;
    expect(firstIdentity).toBeDefined();

    // Exactly REACTION_FLOOR_MS (200ms) later: floor alone would allow the
    // SAME identity to be picked again — only the bundle-exclusion tracking
    // (`reactionIdentitiesByBundle`) forces a distinct one.
    const stateB: SchedulerState = {
      ...resultA.nextState,
      tick: 1, // pin tick again so ambient reaction stays off for this call too
      responseQueue: [intent("bundle-x", "reaction", 1000 + REACTION_FLOOR_MS)],
    };
    const resultB = planTick(stateB, 1000 + REACTION_FLOOR_MS);
    const secondIdentity = resultB.events.find((e) => e.kind === "reaction")?.identityIndex;
    expect(secondIdentity).toBeDefined();
    expect(secondIdentity).not.toBe(firstIdentity);
  });

  it("ambient push-kind selection (commit vs remix) is untouched by response-queue contents", () => {
    const withoutQueue = baseState({ tick: 0 }); // 0 % REMIX_EVERY_N_TICKS !== last-of-cycle -> commit tick
    const withQueue = baseState({
      tick: 0,
      responseQueue: [intent("b1", "remix", 0), intent("b1", "chat", 0), intent("b1", "reaction", 0)],
    });

    const a = planTick(withoutQueue, 0);
    const b = planTick(withQueue, 0);

    const ambientPushA = a.events.filter((e) => (e.kind === "commit" || e.kind === "remix") && !e.response);
    const ambientPushB = b.events.filter((e) => (e.kind === "commit" || e.kind === "remix") && !e.response);
    expect(ambientPushA).toHaveLength(1);
    expect(ambientPushB).toHaveLength(1);
    expect(ambientPushA[0]!.kind).toBe("commit");
    expect(ambientPushB[0]!.kind).toBe("commit"); // still a commit — the response remix is a SEPARATE event, not a substitution
  });

  it("is a pure function even with a non-empty response queue: identical (state, now) always yields identical output", () => {
    const state = baseState({
      responseQueue: [intent("b1", "reaction", 0), intent("b1", "chat", 5000), intent("b1", "remix", 20_000)],
      lastBundleMsByAuthor: { "real-author": 0 },
    });
    const a = planTick(state, 10_000);
    const b = planTick(state, 10_000);
    expect(a.events).toEqual(b.events);
    expect(a.nextState).toEqual(b.nextState);
  });

  it("spreads a real bundle's intents across multiple ticks rather than draining it all at once", () => {
    const enqueuedAt = 0;
    const withBundle = enqueueResponseBundle(initialSchedulerState(POOL_SIZE), {
      kind: "commit",
      ref: "refs/heads/main",
      targetIdHex: "spread-target",
      authorPubkeyHex: "spread-author",
    }, enqueuedAt);
    const totalIntents = withBundle.responseQueue!.length;
    expect(totalIntents).toBeGreaterThan(0);

    let state = withBundle;
    let now = enqueuedAt;
    let firstTickDrainedCount = -1;
    let ticksUntilFullyDrained = 0;
    while ((state.responseQueue?.length ?? 0) > 0 && ticksUntilFullyDrained < 60) {
      const before = state.responseQueue?.length ?? 0;
      const { events, nextState } = planTick(state, now);
      const drainedThisTick = events.filter((e) => e.response).length;
      if (firstTickDrainedCount === -1) firstTickDrainedCount = drainedThisTick;
      state = nextState;
      now += 1000;
      ticksUntilFullyDrained++;
      void before;
    }

    // Not everything fires on the very first tick...
    expect(firstTickDrainedCount).toBeLessThan(totalIntents);
    // ...but the whole bundle is fully drained well within RESPONSE_BUNDLE_SPREAD_MS plus a little slack.
    expect(ticksUntilFullyDrained).toBeGreaterThan(1);
    expect(ticksUntilFullyDrained * 1000).toBeLessThanOrEqual(RESPONSE_BUNDLE_SPREAD_MS + 5000);
  });
});

describe("planTick + enqueueResponseBundle — simulated hour under combined ambient + response load", () => {
  it("zero floor violations across a simulated hour with a steady stream of real events feeding the response queue", () => {
    const AUTHORS = ["real-author-a", "real-author-b", "real-author-c", "real-author-d"];
    let state = initialSchedulerState(POOL_SIZE);
    let now = 0;
    const lastChat = new Array<number | undefined>(POOL_SIZE).fill(undefined);
    const lastPush = new Array<number | undefined>(POOL_SIZE).fill(undefined);
    const lastReaction = new Array<number | undefined>(POOL_SIZE).fill(undefined);
    const violations: string[] = [];

    for (let t = 0; t < 3600; t++) {
      now += 1000;

      // A real event lands from a rotating author every 7 seconds.
      if (t % 7 === 0) {
        const author = AUTHORS[(t / 7) % AUTHORS.length]!;
        state = enqueueResponseBundle(
          state,
          { kind: "commit", ref: "refs/heads/main", targetIdHex: `real-target-${t}`, authorPubkeyHex: author },
          now,
        );
      }

      const { events, nextState } = planTick(state, now);
      state = nextState;

      for (const ev of events) {
        if (ev.kind === "chat") {
          const last = lastChat[ev.identityIndex];
          if (last !== undefined && now - last < CHAT_FLOOR_MS) violations.push(`chat identity ${ev.identityIndex} at ${now}`);
          lastChat[ev.identityIndex] = now;
        } else if (ev.kind === "commit" || ev.kind === "remix") {
          const last = lastPush[ev.identityIndex];
          if (last !== undefined && now - last < PUSH_FLOOR_MS) violations.push(`push identity ${ev.identityIndex} at ${now}`);
          lastPush[ev.identityIndex] = now;
        } else {
          const last = lastReaction[ev.identityIndex];
          if (last !== undefined && now - last < REACTION_FLOOR_MS) violations.push(`reaction identity ${ev.identityIndex} at ${now}`);
          lastReaction[ev.identityIndex] = now;
        }
      }
    }

    expect(violations).toEqual([]);
  });

  it("holds the per-author cooldown and the global bundle cap over a simulated hour with a stream of real events", () => {
    const AUTHORS = ["author-a", "author-b", "author-c"];
    let state = initialSchedulerState(POOL_SIZE);
    let now = 0;
    const bundleEnqueueTimesByAuthor: Record<string, number[]> = {};

    for (let t = 0; t < 3600; t++) {
      now += 1000;

      if (t % 10 === 0) {
        const author = AUTHORS[(t / 10) % AUTHORS.length]!;
        const before = state.responseQueue?.length ?? 0;
        state = enqueueResponseBundle(
          state,
          { kind: "commit", ref: "refs/heads/main", targetIdHex: `t-${t}`, authorPubkeyHex: author },
          now,
        );
        const after = state.responseQueue?.length ?? 0;
        if (after > before) (bundleEnqueueTimesByAuthor[author] ??= []).push(now);
      }

      // Global cap: at most MAX_BUNDLES_IN_FLIGHT distinct bundles pending at any instant.
      const distinctBundleIds = new Set((state.responseQueue ?? []).map((intent) => intent.bundleId));
      expect(distinctBundleIds.size).toBeLessThanOrEqual(MAX_BUNDLES_IN_FLIGHT);

      state = planTick(state, now).nextState;
    }

    let totalBundlesEnqueued = 0;
    for (const author of AUTHORS) {
      const times = bundleEnqueueTimesByAuthor[author] ?? [];
      totalBundlesEnqueued += times.length;
      for (let i = 1; i < times.length; i++) {
        expect(times[i]! - times[i - 1]!).toBeGreaterThanOrEqual(RESPONSE_AUTHOR_COOLDOWN_MS);
      }
    }
    // Sanity: the test isn't vacuously true — at least some bundles got through over the hour.
    expect(totalBundlesEnqueued).toBeGreaterThan(0);
  });
});
