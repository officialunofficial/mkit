// test/observer.test.ts
//
// Issue #849 verification: `observe` is pure (no wasm, no I/O), so this runs
// entirely in the "unit" vitest project against hand-built synthetic
// snapshots/watermarks — no wasm init needed, mirroring
// `scheduler.test.ts`'s "scheduler.ts — tick planner" describe block.

import { describe, expect, it } from "vitest";
import { FORKS_PREFIX } from "../src/events";
import {
  RESPONDED_EVENT_ID_CAP,
  type CommitMeta,
  type ObserverSnapshot,
  type ObserverWatermark,
  type RealEvent,
  initialObserverWatermark,
  observe,
} from "../src/observer";

const SYNTH_A = "aa".repeat(32);
const SYNTH_B = "bb".repeat(32);
const REAL_ALICE = "11".repeat(32);
const REAL_BOB = "22".repeat(32);

const SYNTHETIC = new Set([SYNTH_A, SYNTH_B]);

function commit(overrides: Partial<CommitMeta> & { hash: string; authorPubkeyHex: string }): CommitMeta {
  return { parent: "", kind: "commit", ...overrides };
}

function snapshot(refs: ObserverSnapshot["refs"], newCommitsByRef: ObserverSnapshot["newCommitsByRef"] = {}): ObserverSnapshot {
  return { refs, newCommitsByRef };
}

/** A watermark that already tracks `main` at `mainHead` (and nothing else) — the smallest possible "already enabled" watermark, used by most non-fresh-path tests. */
function trackingWatermark(mainHead: string, extra: Partial<ObserverWatermark> = {}): ObserverWatermark {
  return { refHeads: { main: mainHead }, knownForkRefs: [], respondedEventIds: [], initialized: true, ...extra };
}

describe("observer.ts — fresh watermark (first enable)", () => {
  it("initializes refHeads/knownForkRefs from the snapshot and yields zero events", () => {
    const snap = snapshot(
      [
        { name: "main", headHex: "m1" },
        { name: "feature/x", headHex: "f1" },
        { name: `${FORKS_PREFIX}m0-11111111111`, headHex: "fk1" },
      ],
      {
        main: [commit({ hash: "m1", authorPubkeyHex: REAL_ALICE })],
        "feature/x": [commit({ hash: "f1", authorPubkeyHex: REAL_ALICE })],
        [`${FORKS_PREFIX}m0-11111111111`]: [commit({ hash: "fk1", authorPubkeyHex: REAL_ALICE })],
      },
    );

    const { realEvents, nextWatermark } = observe(initialObserverWatermark(), snap, SYNTHETIC);

    expect(realEvents).toEqual([]);
    expect(nextWatermark.refHeads).toEqual({
      main: "m1",
      "feature/x": "f1",
      [`${FORKS_PREFIX}m0-11111111111`]: "fk1",
    });
    expect(nextWatermark.knownForkRefs).toEqual([`${FORKS_PREFIX}m0-11111111111`]);
    expect(nextWatermark.respondedEventIds).toEqual([]);
    expect(nextWatermark.initialized).toBe(true);
  });

  it("treats an uninitialized watermark as fresh regardless of what refHeads/respondedEventIds already hold", () => {
    const stale: ObserverWatermark = {
      refHeads: { main: "stale-head" },
      knownForkRefs: [],
      respondedEventIds: ["commit:stale"],
      initialized: false,
    };
    const snap = snapshot([{ name: "main", headHex: "m1" }], { main: [commit({ hash: "m1", authorPubkeyHex: REAL_ALICE })] });
    const { realEvents, nextWatermark } = observe(stale, snap, SYNTHETIC);
    expect(realEvents).toEqual([]);
    expect(nextWatermark.refHeads).toEqual({ main: "m1" });
    expect(nextWatermark.initialized).toBe(true);
    // Carried through unchanged, not reset — see `initializeFreshWatermark`'s doc comment.
    expect(nextWatermark.respondedEventIds).toEqual(["commit:stale"]);
  });

  it("does NOT treat an initialized watermark as fresh just because refHeads is empty (the bug this fixes)", () => {
    // An already-initialized watermark for a room that had zero refs at
    // enable time. The OLD code inferred freshness from `refHeads` having
    // zero keys, so it would have kept taking the fresh path forever here —
    // silently re-adopting state instead of diffing. The explicit
    // `initialized` flag means this now goes through the normal per-ref
    // diff, exactly like any other already-enabled watermark.
    const emptyRoomWatermark: ObserverWatermark = { refHeads: {}, knownForkRefs: [], respondedEventIds: [], initialized: true };
    const snap = snapshot([{ name: "main", headHex: "m1" }], { main: [commit({ hash: "m1", parent: "", authorPubkeyHex: REAL_ALICE })] });

    const { realEvents, nextWatermark } = observe(emptyRoomWatermark, snap, SYNTHETIC);

    expect(realEvents).toEqual<RealEvent[]>([{ kind: "commit", ref: "main", targetIdHex: "m1", authorPubkeyHex: REAL_ALICE }]);
    expect(nextWatermark.refHeads).toEqual({ main: "m1" });
  });

  it("initializing on a truly empty room, then observing its first-ever real commit, yields that commit event (not silent adoption)", () => {
    // End-to-end version of the fix: enable on a room with zero refs at all
    // (nothing has ever been pushed), then the room gets its first real
    // commit on `main`. The old emptiness-as-freshness inference would have
    // kept treating every poll as "first enable" until a ref finally
    // appeared, silently adopting that first commit as baseline instead of
    // reporting it.
    const enableSnapshot = snapshot([], {});
    const { realEvents: enableEvents, nextWatermark: afterEnable } = observe(initialObserverWatermark(), enableSnapshot, SYNTHETIC);
    expect(enableEvents).toEqual([]);
    expect(afterEnable.refHeads).toEqual({});
    expect(afterEnable.initialized).toBe(true);

    const firstCommitSnapshot = snapshot([{ name: "main", headHex: "m1" }], {
      main: [commit({ hash: "m1", parent: "", authorPubkeyHex: REAL_ALICE })],
    });
    const { realEvents, nextWatermark } = observe(afterEnable, firstCommitSnapshot, SYNTHETIC);

    expect(realEvents).toEqual<RealEvent[]>([{ kind: "commit", ref: "main", targetIdHex: "m1", authorPubkeyHex: REAL_ALICE }]);
    expect(nextWatermark.refHeads).toEqual({ main: "m1" });
  });
});

describe("observer.ts — commit detection on main", () => {
  it("detects a new non-synthetic commit on main", () => {
    const watermark = trackingWatermark("m0");
    const snap = snapshot([{ name: "main", headHex: "m1" }], {
      main: [commit({ hash: "m1", parent: "m0", authorPubkeyHex: REAL_ALICE })],
    });

    const { realEvents, nextWatermark } = observe(watermark, snap, SYNTHETIC);

    expect(realEvents).toEqual<RealEvent[]>([
      { kind: "commit", ref: "main", targetIdHex: "m1", authorPubkeyHex: REAL_ALICE },
    ]);
    expect(nextWatermark.refHeads.main).toBe("m1");
    expect(nextWatermark.respondedEventIds).toEqual(["commit:m1"]);
  });

  it("detects a new non-synthetic commit on a non-main, non-forks branch identically", () => {
    const watermark: ObserverWatermark = { refHeads: { main: "m0", "feature/x": "f0" }, knownForkRefs: [], respondedEventIds: [], initialized: true };
    const snap = snapshot(
      [
        { name: "main", headHex: "m0" },
        { name: "feature/x", headHex: "f1" },
      ],
      { "feature/x": [commit({ hash: "f1", parent: "f0", authorPubkeyHex: REAL_BOB })] },
    );

    const { realEvents } = observe(watermark, snap, SYNTHETIC);

    expect(realEvents).toEqual<RealEvent[]>([
      { kind: "commit", ref: "feature/x", targetIdHex: "f1", authorPubkeyHex: REAL_BOB },
    ]);
  });

  it("filters synthetic-authored commits on any ref", () => {
    const watermark: ObserverWatermark = { refHeads: { main: "m0", "feature/x": "f0" }, knownForkRefs: [], respondedEventIds: [], initialized: true };
    const snap = snapshot(
      [
        { name: "main", headHex: "m1" },
        { name: "feature/x", headHex: "f1" },
      ],
      {
        main: [commit({ hash: "m1", parent: "m0", authorPubkeyHex: SYNTH_A })],
        "feature/x": [commit({ hash: "f1", parent: "f0", authorPubkeyHex: SYNTH_B })],
      },
    );

    const { realEvents, nextWatermark } = observe(watermark, snap, SYNTHETIC);

    expect(realEvents).toEqual([]);
    // Watermark still advances even though nothing was emitted.
    expect(nextWatermark.refHeads).toEqual({ main: "m1", "feature/x": "f1" });
  });

  it("yields one commit event per new commit when multiple real commits land on a ref in one poll", () => {
    const watermark = trackingWatermark("m0");
    const snap = snapshot([{ name: "main", headHex: "m2" }], {
      // newest-first, as list_commits walks the chain.
      main: [
        commit({ hash: "m2", parent: "m1", authorPubkeyHex: REAL_BOB }),
        commit({ hash: "m1", parent: "m0", authorPubkeyHex: REAL_ALICE }),
      ],
    });

    const { realEvents } = observe(watermark, snap, SYNTHETIC);

    expect(realEvents).toEqual<RealEvent[]>([
      { kind: "commit", ref: "main", targetIdHex: "m2", authorPubkeyHex: REAL_BOB },
      { kind: "commit", ref: "main", targetIdHex: "m1", authorPubkeyHex: REAL_ALICE },
    ]);
  });
});

describe("observer.ts — fork-ref detection", () => {
  const forkRef = `${FORKS_PREFIX}abcdefabcdef-111111111111`;

  it("detects a new forks/ ref created by a real author as a single fork event", () => {
    const watermark = trackingWatermark("m0");
    const snap = snapshot(
      [
        { name: "main", headHex: "m0" },
        { name: forkRef, headHex: "fk1" },
      ],
      { [forkRef]: [commit({ hash: "fk1", parent: "", authorPubkeyHex: REAL_ALICE, kind: "remix" })] },
    );

    const { realEvents, nextWatermark } = observe(watermark, snap, SYNTHETIC);

    expect(realEvents).toEqual<RealEvent[]>([{ kind: "fork", ref: forkRef, targetIdHex: "fk1", authorPubkeyHex: REAL_ALICE }]);
    expect(nextWatermark.knownForkRefs).toEqual([forkRef]);
    expect(nextWatermark.respondedEventIds).toEqual([`fork:${forkRef}`]);
  });

  it("does NOT also emit a commit event for the new fork ref's head", () => {
    const watermark = trackingWatermark("m0");
    const snap = snapshot([{ name: forkRef, headHex: "fk1" }], {
      [forkRef]: [commit({ hash: "fk1", authorPubkeyHex: REAL_ALICE, kind: "remix" })],
    });

    const { realEvents } = observe(watermark, snap, SYNTHETIC);

    expect(realEvents).toHaveLength(1);
    expect(realEvents[0]!.kind).toBe("fork");
  });

  it("filters a new forks/ ref created by a synthetic author, but still tracks it", () => {
    const watermark = trackingWatermark("m0");
    const snap = snapshot([{ name: forkRef, headHex: "fk1" }], {
      [forkRef]: [commit({ hash: "fk1", authorPubkeyHex: SYNTH_A, kind: "remix" })],
    });

    const { realEvents, nextWatermark } = observe(watermark, snap, SYNTHETIC);

    expect(realEvents).toEqual([]);
    // The fork-of-fork feature (#851) needs synthetic forks tracked too.
    expect(nextWatermark.knownForkRefs).toEqual([forkRef]);
  });

  it("defensively records a new fork ref with no matching commit metadata (missing newCommitsByRef entry) without emitting an event", () => {
    const watermark = trackingWatermark("m0");
    // No `newCommitsByRef[forkRef]` entry at all — shouldn't happen in
    // practice (the DO always pages at least the head commit for a newly
    // discovered ref), but `observe` stays defensive rather than throwing.
    const snap = snapshot([{ name: forkRef, headHex: "fk1" }], {});

    const { realEvents, nextWatermark } = observe(watermark, snap, SYNTHETIC);

    expect(realEvents).toEqual([]);
    expect(nextWatermark.knownForkRefs).toEqual([forkRef]);
  });

  it("treats a follow-up push to an ALREADY-known fork ref as an ordinary commit event, not another fork event", () => {
    const watermark: ObserverWatermark = { refHeads: { main: "m0", [forkRef]: "fk1" }, knownForkRefs: [forkRef], respondedEventIds: [`fork:${forkRef}`], initialized: true };
    const snap = snapshot([{ name: forkRef, headHex: "fk2" }], {
      [forkRef]: [commit({ hash: "fk2", parent: "fk1", authorPubkeyHex: REAL_ALICE, kind: "remix" })],
    });

    const { realEvents } = observe(watermark, snap, SYNTHETIC);

    expect(realEvents).toEqual<RealEvent[]>([{ kind: "commit", ref: forkRef, targetIdHex: "fk2", authorPubkeyHex: REAL_ALICE }]);
  });
});

describe("observer.ts — per-ref watermark advance / dedup", () => {
  it("never yields the same event twice across calls, even if the snapshot re-reports it", () => {
    const watermark = trackingWatermark("m0");
    const snap = snapshot([{ name: "main", headHex: "m1" }], {
      main: [commit({ hash: "m1", parent: "m0", authorPubkeyHex: REAL_ALICE })],
    });

    const first = observe(watermark, snap, SYNTHETIC);
    expect(first.realEvents).toHaveLength(1);

    // Re-observe with the SAME snapshot against the updated watermark (e.g. a
    // re-poll that still reports the same "new" commit due to a paging quirk).
    const second = observe(first.nextWatermark, snap, SYNTHETIC);
    expect(second.realEvents).toEqual([]);
  });

  it("advances refHeads per-ref independently, so an untouched ref's watermark is unaffected by another ref's activity", () => {
    const watermark: ObserverWatermark = { refHeads: { main: "m0", "feature/x": "f0" }, knownForkRefs: [], respondedEventIds: [], initialized: true };
    const snap = snapshot(
      [
        { name: "main", headHex: "m1" },
        { name: "feature/x", headHex: "f0" },
      ],
      { main: [commit({ hash: "m1", parent: "m0", authorPubkeyHex: REAL_ALICE })] },
    );

    const { nextWatermark } = observe(watermark, snap, SYNTHETIC);
    expect(nextWatermark.refHeads).toEqual({ main: "m1", "feature/x": "f0" });
  });
});

describe("observer.ts — ref deletion pruning", () => {
  it("drops a ref missing from the snapshot out of nextWatermark.refHeads", () => {
    const watermark: ObserverWatermark = {
      refHeads: { main: "m0", "feature/gone": "g0" },
      knownForkRefs: [],
      respondedEventIds: [],
      initialized: true,
    };
    const snap = snapshot([{ name: "main", headHex: "m0" }], {});

    const { nextWatermark } = observe(watermark, snap, SYNTHETIC);

    expect(nextWatermark.refHeads).toEqual({ main: "m0" });
    expect(nextWatermark.refHeads).not.toHaveProperty("feature/gone");
  });

  it("does NOT prune a known fork ref from knownForkRefs even if a later snapshot omits it", () => {
    const forkRef = `${FORKS_PREFIX}abcabcabcabc-222222222222`;
    const watermark: ObserverWatermark = { refHeads: { main: "m0", [forkRef]: "fk1" }, knownForkRefs: [forkRef], respondedEventIds: [], initialized: true };
    const snap = snapshot([{ name: "main", headHex: "m0" }], {});

    const { nextWatermark } = observe(watermark, snap, SYNTHETIC);

    expect(nextWatermark.knownForkRefs).toEqual([forkRef]);
    // refHeads, unlike knownForkRefs, does prune.
    expect(nextWatermark.refHeads).not.toHaveProperty(forkRef);
  });
});

describe("observer.ts — bounded responded-event LRU", () => {
  it("stays capped at RESPONDED_EVENT_ID_CAP under many events, evicting oldest first", () => {
    let watermark = trackingWatermark("m0");
    const totalCommits = RESPONDED_EVENT_ID_CAP + 50;

    let prevHead = "m0";
    for (let i = 0; i < totalCommits; i++) {
      const hash = `m${i + 1}`;
      const snap = snapshot([{ name: "main", headHex: hash }], {
        main: [commit({ hash, parent: prevHead, authorPubkeyHex: REAL_ALICE })],
      });
      const { nextWatermark } = observe(watermark, snap, SYNTHETIC);
      watermark = nextWatermark;
      prevHead = hash;
    }

    expect(watermark.respondedEventIds).toHaveLength(RESPONDED_EVENT_ID_CAP);
    // The earliest events were evicted; the most recent ones remain.
    expect(watermark.respondedEventIds).not.toContain("commit:m1");
    expect(watermark.respondedEventIds).toContain(`commit:m${totalCommits}`);
  });
});

describe("observer.ts — purity", () => {
  it("does not mutate its inputs and is deterministic for the same inputs", () => {
    const watermark = trackingWatermark("m0");
    const watermarkCopy = JSON.parse(JSON.stringify(watermark));
    const snap = snapshot([{ name: "main", headHex: "m1" }], {
      main: [commit({ hash: "m1", parent: "m0", authorPubkeyHex: REAL_ALICE })],
    });
    const snapCopy = JSON.parse(JSON.stringify(snap));

    const a = observe(watermark, snap, SYNTHETIC);
    const b = observe(watermark, snap, SYNTHETIC);

    expect(watermark).toEqual(watermarkCopy);
    expect(snap).toEqual(snapCopy);
    expect(a.realEvents).toEqual(b.realEvents);
    expect(a.nextWatermark).toEqual(b.nextWatermark);
  });
});
