// Deterministic synthetic-identity pool (PLAN.md "Synthetic-identity /
// rate-math design").
//
// Every event the `Spammer` DO emits is signed by one of `POOL_SIZE`
// synthetic Ed25519 identities, derived the SAME way on every isolate and
// every redeploy: `seed_i = blake3_hex("mkit-spammer:v1:seed:" + i)`. There is
// no seed persistence anywhere — determinism IS the persistence. This also
// means two isolates (or a local `wrangler dev` vs. the deployed Worker)
// always agree on the same POOL_SIZE pubkeys, which matters for reading the pool's
// own writes back out by author.

import { bytesToHex, hexToBytes } from "./hex";
import type { MkitApi } from "./wasm";

/**
 * Number of synthetic identities in the pool — see PLAN.md's rate-math section.
 *
 * 64, not 32, was derived for the ORIGINAL one-push-per-alarm-tick cadence:
 * at 64s natural per-identity spacing, worst-case ops/hr/author — assuming
 * EVERY push needs one CAS-conflict retry (4 ops: put+update, then a second
 * put+update) — was (3600/64)*4 = 225, a genuine 25% margin under the real
 * 300-op/hr cap (`write_quota.rs:31`), where 32 would have blown it (450).
 * Under the current gated cadence (one push per `PUSH_EVERY_N_TICKS` ticks —
 * see `scheduler.ts`'s "Ambient cadence" doc section), natural spacing is
 * `POOL_SIZE × PUSH_EVERY_N_TICKS` seconds (~16 min), so quota headroom is
 * enormous and the pool size persists for identity variety, not rate math.
 */
export const POOL_SIZE = 64;

/**
 * Domain-separation prefix for the seed derivation. Bumping this (e.g. to
 * `"mkit-spammer:v2:seed:"`) mints an entirely new, disjoint pool with no
 * overlap with the current one — useful if the pool ever needs rotating.
 */
const SEED_PREFIX = "mkit-spammer:v1:seed:";

const TEXT_ENCODER = new TextEncoder();

export type Identity = {
  /** Index into the pool, `0 .. POOL_SIZE - 1`. */
  index: number;
  /** 32-byte (64 hex char) Ed25519 signing seed, deterministic per index. */
  seedHex: string;
  /** Ed25519 public key hex, derived from `seedHex`. */
  pubkeyHex: string;
};

/**
 * The raw signing seed for identity `index`: `blake3_hex` of the
 * domain-separated string `"mkit-spammer:v1:seed:" + index`. Exposed
 * separately from {@link getIdentityPool} so callers (and tests) can recompute
 * a single seed without materializing the whole pool.
 */
export function seedForIndex(api: MkitApi, index: number): string {
  return api.blake3_hex(TEXT_ENCODER.encode(`${SEED_PREFIX}${index}`));
}

// Single-entry memo keyed by the `MkitApi` instance that produced it. A
// Worker isolate only ever has one `MkitApi` (see `wasm.ts`'s own
// per-isolate memoization), so in practice this computes once per isolate
// lifetime; keying by `api` (rather than an unconditional module-level
// singleton) just means a test that swaps in a different wasm instance gets
// a freshly recomputed pool instead of a stale one from a prior instance.
let cachedApi: MkitApi | null = null;
let cachedPool: Identity[] | null = null;

/**
 * Build (once per distinct `api`, memoized) the deterministic pool of
 * {@link POOL_SIZE} identities. Every field is a pure function of `index` —
 * no randomness, no I/O — so the pool is stable across calls, across
 * isolates, and across redeploys.
 */
export function getIdentityPool(api: MkitApi): Identity[] {
  if (cachedApi === api && cachedPool) return cachedPool;
  const pool: Identity[] = [];
  for (let index = 0; index < POOL_SIZE; index++) {
    const seedHex = seedForIndex(api, index);
    const pubkeyHex = bytesToHex(api.ed25519_pubkey_from_seed(hexToBytes(seedHex)));
    pool.push({ index, seedHex, pubkeyHex });
  }
  cachedApi = api;
  cachedPool = pool;
  return pool;
}

/** Test-only: clear the memoized pool so the next {@link getIdentityPool} call recomputes from scratch. */
export function __resetIdentityPoolForTests(): void {
  cachedApi = null;
  cachedPool = null;
}

/**
 * A round-robin cursor over `0 .. poolSize - 1`, wrapping back to `0` after
 * the last index. Used by the tick scheduler (PLAN.md build step 7) to
 * spread events evenly across identities tick over tick, independent of
 * whatever per-tick event-kind mix is chosen.
 */
export type RoundRobinCursor = { next(): number };

export function makeRoundRobinCursor(poolSize: number = POOL_SIZE): RoundRobinCursor {
  let i = 0;
  return {
    next(): number {
      const current = i;
      i = (i + 1) % poolSize;
      return current;
    },
  };
}
