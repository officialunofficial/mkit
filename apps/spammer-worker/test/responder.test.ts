// test/responder.test.ts
//
// Issue #854 verification: responder.ts's pure glue functions are the
// decidable heart of the DO's polling/wiring — this file is where their
// coverage comes from. No wasm, no I/O, no DO storage; mirrors
// observer.test.ts / scheduler.test.ts's "unit" project conventions.

import { describe, expect, it } from "vitest";
import type { ContentPools } from "../src/ai-content";
import { REPLY_TEMPLATES } from "../src/content";
import { FORKS_PREFIX, MAIN_REF } from "../src/events";
import type { Identity } from "../src/identities";
import type { CommitMeta, ObserverWatermark, RefEntry } from "../src/observer";
import {
  MAX_ACCEPTED_COMMITS_PER_REF,
  buildSnapshot,
  chooseReplyText,
  forkUpstreamsFromWatermark,
  mergedSyntheticPubkeys,
  refsNeedingFetch,
} from "../src/responder";

function commit(overrides: Partial<CommitMeta> & { hash: string }): CommitMeta {
  return { parent: "", authorPubkeyHex: "11".repeat(32), kind: "commit", ...overrides };
}

function watermark(overrides: Partial<ObserverWatermark> = {}): ObserverWatermark {
  return { refHeads: {}, knownForkRefs: [], respondedEventIds: [], ...overrides };
}

// -----------------------------------------------------------------------------
// refsNeedingFetch
// -----------------------------------------------------------------------------

describe("responder.ts — refsNeedingFetch", () => {
  it("returns [] outright for a fresh watermark (zero refHeads keys), even with refs present", () => {
    const refs: RefEntry[] = [
      { name: "main", headHex: "m1" },
      { name: "feature/x", headHex: "f1" },
    ];
    expect(refsNeedingFetch(watermark(), refs)).toEqual([]);
  });

  it("excludes a ref whose head is unchanged", () => {
    const wm = watermark({ refHeads: { main: "m1" } });
    const refs: RefEntry[] = [{ name: "main", headHex: "m1" }];
    expect(refsNeedingFetch(wm, refs)).toEqual([]);
  });

  it("includes a ref whose head moved", () => {
    const wm = watermark({ refHeads: { main: "m1" } });
    const refs: RefEntry[] = [{ name: "main", headHex: "m2" }];
    expect(refsNeedingFetch(wm, refs)).toEqual([{ name: "main", headHex: "m2" }]);
  });

  it("includes a brand-new ref absent from watermark.refHeads", () => {
    const wm = watermark({ refHeads: { main: "m1" } });
    const refs: RefEntry[] = [
      { name: "main", headHex: "m1" },
      { name: "feature/new", headHex: "f1" },
    ];
    expect(refsNeedingFetch(wm, refs)).toEqual([{ name: "feature/new", headHex: "f1" }]);
  });

  it("handles a mix of moved/unmoved/new refs in one call", () => {
    const wm = watermark({ refHeads: { main: "m1", "feature/a": "a1", "feature/b": "b1" } });
    const refs: RefEntry[] = [
      { name: "main", headHex: "m1" }, // unmoved
      { name: "feature/a", headHex: "a2" }, // moved
      { name: "feature/b", headHex: "b1" }, // unmoved
      { name: "feature/c", headHex: "c1" }, // new
    ];
    expect(refsNeedingFetch(wm, refs)).toEqual([
      { name: "feature/a", headHex: "a2" },
      { name: "feature/c", headHex: "c1" },
    ]);
  });
});

// -----------------------------------------------------------------------------
// forkUpstreamsFromWatermark
// -----------------------------------------------------------------------------

describe("responder.ts — forkUpstreamsFromWatermark", () => {
  it("returns [] when knownForkRefs is empty", () => {
    expect(forkUpstreamsFromWatermark(watermark())).toEqual([]);
  });

  it("returns each known fork ref's current head from refHeads", () => {
    const forkA = `${FORKS_PREFIX}aaa-111`;
    const forkB = `${FORKS_PREFIX}bbb-222`;
    const wm = watermark({
      refHeads: { main: "m1", [forkA]: "fk1", [forkB]: "fk2" },
      knownForkRefs: [forkA, forkB],
    });
    expect(forkUpstreamsFromWatermark(wm)).toEqual([
      { ref: forkA, headHex: "fk1" },
      { ref: forkB, headHex: "fk2" },
    ]);
  });

  it("skips a known fork ref that was pruned out of refHeads (ref deletion)", () => {
    const forkA = `${FORKS_PREFIX}aaa-111`;
    const forkGone = `${FORKS_PREFIX}gone-999`;
    const wm = watermark({
      refHeads: { main: "m1", [forkA]: "fk1" }, // forkGone absent — pruned
      knownForkRefs: [forkA, forkGone],
    });
    expect(forkUpstreamsFromWatermark(wm)).toEqual([{ ref: forkA, headHex: "fk1" }]);
  });

  it("preserves knownForkRefs order", () => {
    const forkA = `${FORKS_PREFIX}aaa`;
    const forkB = `${FORKS_PREFIX}bbb`;
    const wm = watermark({
      refHeads: { [forkA]: "x1", [forkB]: "x2" },
      knownForkRefs: [forkB, forkA],
    });
    expect(forkUpstreamsFromWatermark(wm).map((f) => f.ref)).toEqual([forkB, forkA]);
  });
});

// -----------------------------------------------------------------------------
// buildSnapshot
// -----------------------------------------------------------------------------

describe("responder.ts — buildSnapshot", () => {
  it("passes refs through unchanged", () => {
    const refs: RefEntry[] = [{ name: "main", headHex: "m2" }];
    const snap = buildSnapshot(refs, {}, watermark());
    expect(snap.refs).toEqual(refs);
    expect(snap.refs).not.toBe(refs); // defensive copy, not the same array reference
  });

  it("a ref with no fetched page contributes no newCommitsByRef entry", () => {
    const refs: RefEntry[] = [{ name: "main", headHex: "m1" }];
    const snap = buildSnapshot(refs, {}, watermark());
    expect(snap.newCommitsByRef).toEqual({});
  });

  it("an empty fetched page contributes no newCommitsByRef entry", () => {
    const refs: RefEntry[] = [{ name: "main", headHex: "m1" }];
    const snap = buildSnapshot(refs, { main: [] }, watermark());
    expect(snap.newCommitsByRef).toEqual({});
  });

  it("trims a ref's page to commits strictly newer than the watermark head, stopping AT (not including) the watermark head", () => {
    const wm = watermark({ refHeads: { main: "m1" } });
    const refs: RefEntry[] = [{ name: "main", headHex: "m3" }];
    const page = [commit({ hash: "m3" }), commit({ hash: "m2" }), commit({ hash: "m1" }), commit({ hash: "m0" })];
    const snap = buildSnapshot(refs, { main: page }, wm);
    expect(snap.newCommitsByRef.main).toEqual([commit({ hash: "m3" }), commit({ hash: "m2" })]);
  });

  it("a ref with no watermark head yet (brand new) accepts the whole page up to the cap, with no stop condition", () => {
    const refs: RefEntry[] = [{ name: "feature/new", headHex: "f3" }];
    const page = [commit({ hash: "f3" }), commit({ hash: "f2" }), commit({ hash: "f1" })];
    const snap = buildSnapshot(refs, { "feature/new": page }, watermark());
    expect(snap.newCommitsByRef["feature/new"]).toEqual(page);
  });

  it("caps accepted commits at MAX_ACCEPTED_COMMITS_PER_REF even when the watermark head never appears in the page", () => {
    const wm = watermark({ refHeads: { main: "m0" } });
    const refs: RefEntry[] = [{ name: "main", headHex: "mN" }];
    const page = Array.from({ length: MAX_ACCEPTED_COMMITS_PER_REF + 5 }, (_, i) => commit({ hash: `m${i + 1}` }));
    const snap = buildSnapshot(refs, { main: page }, wm);
    expect(snap.newCommitsByRef.main).toHaveLength(MAX_ACCEPTED_COMMITS_PER_REF);
    expect(snap.newCommitsByRef.main).toEqual(page.slice(0, MAX_ACCEPTED_COMMITS_PER_REF));
  });

  it("handles multiple refs independently in one call", () => {
    const wm = watermark({ refHeads: { main: "m1", "feature/x": "f1" } });
    const refs: RefEntry[] = [
      { name: "main", headHex: "m2" },
      { name: "feature/x", headHex: "f1" },
    ];
    const snap = buildSnapshot(
      refs,
      {
        main: [commit({ hash: "m2" }), commit({ hash: "m1" })],
        "feature/x": [commit({ hash: "f1" })], // unchanged — but caller wouldn't normally fetch this
      },
      wm,
    );
    expect(snap.newCommitsByRef.main).toEqual([commit({ hash: "m2" })]);
    // f1 IS the watermark head, so it's excluded — the ref ends up with no entry.
    expect(snap.newCommitsByRef["feature/x"]).toBeUndefined();
  });
});

// -----------------------------------------------------------------------------
// chooseReplyText
// -----------------------------------------------------------------------------

const INTENT_MAIN = { targetIdHex: "abcdef1234567890", ref: MAIN_REF, realAuthorPubkeyHex: "22".repeat(32) };
const INTENT_BRANCH = { targetIdHex: "abcdef1234567890", ref: "feature/cool", realAuthorPubkeyHex: "22".repeat(32) };

describe("responder.ts — chooseReplyText", () => {
  it("is deterministic: same inputs yield the same output", () => {
    const a = chooseReplyText(undefined, INTENT_MAIN, 5);
    const b = chooseReplyText(undefined, INTENT_MAIN, 5);
    expect(a).toBe(b);
  });

  it("always returns a non-empty string over the whole default REPLY_TEMPLATES pool, for every counter value", () => {
    for (let counter = 0; counter < REPLY_TEMPLATES.length * 2; counter++) {
      expect(chooseReplyText(undefined, INTENT_MAIN, counter).length).toBeGreaterThan(0);
      expect(chooseReplyText(undefined, INTENT_BRANCH, counter).length).toBeGreaterThan(0);
    }
  });

  it("never leaves an unfilled {branch} token for a main-ref intent, for every counter value", () => {
    for (let counter = 0; counter < REPLY_TEMPLATES.length; counter++) {
      expect(chooseReplyText(undefined, INTENT_MAIN, counter)).not.toContain("{");
    }
  });

  it("can select a {branch}-carrying template for a non-main ref, and fills the branch name in", () => {
    // REPLY_TEMPLATES has entries with {branch} — sweep counters until one hits.
    const found = Array.from({ length: REPLY_TEMPLATES.length }, (_, counter) =>
      chooseReplyText(undefined, INTENT_BRANCH, counter),
    );
    expect(found.some((text) => text.includes(INTENT_BRANCH.ref))).toBe(true);
  });

  it("falls back across the pool deterministically starting at counter (wraps rather than always landing on index 0)", () => {
    const results = new Set(
      Array.from({ length: REPLY_TEMPLATES.length }, (_, counter) => chooseReplyText(undefined, INTENT_MAIN, counter)),
    );
    // Different counters should not all collapse to the exact same text.
    expect(results.size).toBeGreaterThan(1);
  });

  it("uses pools.reply when provided instead of the default REPLY_TEMPLATES", () => {
    const pools: ContentPools = { chat: [], commit: [], remix: [], reply: ["custom line about {author} and {hash}"] };
    const result = chooseReplyText(pools, INTENT_MAIN, 0);
    expect(result).toBe("custom line about {author} and {hash}".replace("{author}", "22222222").replace("{hash}", "abcdef12"));
  });

  it("falls back to the hardcoded ultimate fallback when every pool entry requires {branch} but the intent is main-ref", () => {
    const pools: ContentPools = { chat: [], commit: [], remix: [], reply: ["{author} pushed to {branch}"] };
    const result = chooseReplyText(pools, INTENT_MAIN, 0);
    expect(result.length).toBeGreaterThan(0);
    expect(result).not.toContain("{");
    // The fallback still honestly references the real hash/author.
    expect(result).toContain("abcdef12");
  });

  it("never returns null/undefined even for an empty reply pool", () => {
    const pools: ContentPools = { chat: [], commit: [], remix: [], reply: [] };
    const result = chooseReplyText(pools, INTENT_MAIN, 0);
    expect(typeof result).toBe("string");
    expect(result.length).toBeGreaterThan(0);
  });
});

// -----------------------------------------------------------------------------
// mergedSyntheticPubkeys
// -----------------------------------------------------------------------------

function identity(pubkeyHex: string): Identity {
  return { index: 0, seedHex: "00".repeat(32), pubkeyHex };
}

describe("responder.ts — mergedSyntheticPubkeys", () => {
  it("includes every pool identity's pubkey", () => {
    const pool = [identity("aa".repeat(32)), identity("bb".repeat(32))];
    const set = mergedSyntheticPubkeys(pool, undefined);
    expect(set.has("aa".repeat(32))).toBe(true);
    expect(set.has("bb".repeat(32))).toBe(true);
    expect(set.size).toBe(2);
  });

  it("undefined allowlist contributes nothing beyond the pool", () => {
    const pool = [identity("aa".repeat(32))];
    expect(mergedSyntheticPubkeys(pool, undefined)).toEqual(new Set(["aa".repeat(32)]));
  });

  it("empty-string allowlist contributes nothing beyond the pool", () => {
    const pool = [identity("aa".repeat(32))];
    expect(mergedSyntheticPubkeys(pool, "")).toEqual(new Set(["aa".repeat(32)]));
  });

  it("merges a comma-separated allowlist, trimmed and lowercased", () => {
    const pool = [identity("aa".repeat(32))];
    const allowlist = ` ${"CC".repeat(32)} , ${"dd".repeat(32)} `;
    const set = mergedSyntheticPubkeys(pool, allowlist);
    expect(set.has("cc".repeat(32))).toBe(true);
    expect(set.has("dd".repeat(32))).toBe(true);
    expect(set.size).toBe(3);
  });

  it("ignores empty entries from consecutive/trailing commas", () => {
    const pool = [identity("aa".repeat(32))];
    const set = mergedSyntheticPubkeys(pool, `${"bb".repeat(32)},,`);
    expect(set.size).toBe(2);
  });

  it("lowercases pool pubkeys too, for consistent comparison against wire-format lowercase hex", () => {
    const pool = [identity("AA".repeat(32))];
    const set = mergedSyntheticPubkeys(pool, undefined);
    expect(set.has("aa".repeat(32))).toBe(true);
    expect(set.has("AA".repeat(32))).toBe(false);
  });
});
