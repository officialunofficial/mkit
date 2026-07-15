// Pure observer (issue #849, part of #848's PRD — "The observer seam").
//
// `observe` is the worker's read side: it diffs polled room state against a
// persisted watermark and yields *real-user* events (a commit or fork-ref
// creation authored by a pubkey outside the synthetic pool) on ANY ref, not
// only `main`. It deliberately mirrors `scheduler.ts`'s `planTick` design
// contract — pure, no I/O, no clock, no randomness, plain JSON-serializable
// state — because no existing module here reads room state at all; this is
// the one genuinely new seam #848 calls for. Everything else in the
// AI-reaction feature extends an existing module.
//
// The DO (#854) owns all I/O: it calls `list_refs`/`list_commits` against the
// vendored `mkit-repo-client` wasm surface
// (`rust/crates/mkit-repo-client/src/lib.rs`), shapes the results into an
// `ObserverSnapshot`, calls `observe(watermark, snapshot, syntheticPubkeys)`,
// emits `realEvents` (build step for #850/#852), and persists `nextWatermark`
// verbatim to DO storage — exactly the same round-trip `SchedulerState`
// already does. This module never touches SQLite, `fetch`, or `Date.now`.

import { FORKS_PREFIX } from "./events";

/**
 * One commit/remix row as reported by `list_commits`
 * (`mkit-repo-client::list_commits`, `rust/crates/mkit-repo-client/src/lib.rs`).
 * Named `CommitMeta` (not `Commit`) because it is metadata straight from the
 * server's index — no object bytes, no decode — mirroring the wasm binding's
 * own comment ("Metadata straight from the DO index"). Only the fields the
 * observer's logic actually reads are required; `message`/`createdAtUnix`/
 * `sourcesJson` are carried through as optional so a caller building this
 * from the raw `list_commits` row doesn't need to drop them, but `observe`
 * itself never inspects them.
 */
export type CommitMeta = {
  hash: string;
  /** Parent commit hash, `""` for a root (first-on-ref) commit. */
  parent: string;
  authorPubkeyHex: string;
  /** Raw `object_kind` string from the server — `"commit"` or `"remix"` today. Not used to classify real-events (ref shape does that — see `observe`'s doc comment), carried through for completeness/future use. */
  kind: string;
  message?: string;
  createdAtUnix?: number;
  sourcesJson?: string;
};

/** One ref as reported by `list_refs` (`{ name, objectIdHex }`), renamed `headHex` here to match this module's "current head" vocabulary. */
export type RefEntry = {
  name: string;
  headHex: string;
};

/**
 * Everything one `observe` call needs about current room state. The DO polls
 * `list_refs` for the full ref listing and pages `list_commits` (per moved
 * ref, back to that ref's watermark head) to build `newCommitsByRef` — see
 * this file's top comment. `observe` does no I/O itself: it only ever reads
 * this plain data.
 */
export type ObserverSnapshot = {
  /** Every ref currently in the room (ALL of them — `main`, feature branches, `forks/…`), not just the ones that moved. Used to detect ref creation/deletion and to advance `nextWatermark.refHeads`. */
  refs: RefEntry[];
  /**
   * Per-ref list of commits newer than `watermark.refHeads[ref]`, **newest
   * first** (the order `list_commits` walks a chain from its head). A ref
   * with nothing new, or absent from the room entirely, may simply be
   * missing its key here (treated the same as an empty array).
   */
  newCommitsByRef: Record<string, CommitMeta[]>;
};

/**
 * Everything `observe` carries from one call to the next. Plain,
 * JSON-serializable data (a couple of `Record`/array fields, no `Map`/`Set`)
 * so the DO can round-trip it through storage verbatim — same shape
 * discipline as `scheduler.ts`'s `SchedulerState`.
 */
export type ObserverWatermark = {
  /** Last-observed head (`objectIdHex`) per ref name, for EVERY ref (not just `main`) — the generalization from a single `lastMainHead` that makes "any ref" possible. A ref absent from the latest snapshot is dropped from here (see `observe`'s doc comment) rather than left to grow unboundedly across renames/deletions. */
  refHeads: Record<string, string>;
  /**
   * Every `forks/…` ref name ever observed, **including ones created by
   * synthetic authors**. This is intentionally NOT filtered to real-author
   * forks: #851's fork-of-fork ambient-remix selection needs to pick among
   * ALL known fork refs (synthetic ones included) as upstream candidates,
   * and this watermark is the natural place to keep that inventory current
   * without a second polling pass. Monotonically grows — a fork ref, once
   * seen, is never pruned even if a later snapshot's ref listing omits it
   * (unlike `refHeads`, which tracks presence; this tracks history).
   */
  knownForkRefs: string[];
  /**
   * Bounded LRU (oldest first) of already-emitted event ids, capped at
   * {@link RESPONDED_EVENT_ID_CAP}. Prevents the SAME event (e.g. a commit
   * the snapshot happens to re-report, or a fork ref seen again next poll)
   * from ever yielding a second `realEvents` entry across calls. 512 is
   * generous headroom over any plausible per-poll event burst (§848's
   * bundle design queues a handful of responses per real event, and polls
   * are ~5s apart) while keeping the persisted watermark small.
   */
  respondedEventIds: string[];
  /**
   * Whether this watermark has ever been through `observe`'s fresh-baseline
   * path. `false` only for exactly what {@link initialObserverWatermark}
   * produces; `observe` sets it `true` on every watermark it returns
   * thereafter, INCLUDING the very first fresh-path call even when the room
   * had zero refs at that moment. Freshness is a stated fact carried on the
   * watermark, not something inferred from `refHeads` being empty — a room
   * can legitimately have zero refs at enable time (nothing has ever been
   * pushed yet), and inferring "not yet initialized" from that emptiness
   * would make `observe` keep re-adopting the room's later state as baseline
   * on every poll, silently swallowing the room's first-ever real commit
   * instead of detecting it. Enabling on an empty room IS being initialized:
   * the room's current (empty) state is the baseline, and any ref that
   * appears afterward is real activity.
   */
  initialized: boolean;
};

/** Cap on {@link ObserverWatermark.respondedEventIds}'s length — see that field's doc comment. */
export const RESPONDED_EVENT_ID_CAP = 512;

/** A real (non-synthetic) commit or fork-ref-creation event `observe` detected. */
export type RealEvent = {
  kind: "commit" | "fork";
  /** The ref the event happened on — the ref that moved (`"main"`, a feature branch, or a `forks/…` ref). */
  ref: string;
  /** The commit/remix hash the event points at — for a `"fork"` event this is the new fork ref's head. */
  targetIdHex: string;
  authorPubkeyHex: string;
};

/**
 * A fresh watermark: no refs tracked, no fork refs known, empty LRU,
 * `initialized: false`. The DO seeds a newly-enabled instance with exactly
 * this — see `observe`'s "first enable" behavior below. `initialized: false`
 * is what makes `observe` take the fresh path on the very next call; every
 * watermark `observe` returns from then on has `initialized: true`.
 */
export function initialObserverWatermark(): ObserverWatermark {
  return { refHeads: {}, knownForkRefs: [], respondedEventIds: [], initialized: false };
}

/** Deterministic dedup id for a `"commit"` event — see `ObserverWatermark.respondedEventIds`. */
function commitEventId(hash: string): string {
  return `commit:${hash}`;
}

/** Deterministic dedup id for a `"fork"` event. Keyed by ref name (not head hash): a fork ref can only ever be "newly created" once, and later pushes to that same ref are ordinary `"commit"` events (see `observe`'s doc comment), so the ref name alone is enough to make this id unique per fork-creation. */
function forkEventId(ref: string): string {
  return `fork:${ref}`;
}

/**
 * Diff `snapshot` against `watermark`, filtering out `syntheticPubkeys`
 * (the caller's merge of the 64 deterministic pool pubkeys plus any config
 * allowlist — see `identities.ts`'s `getIdentityPool` and #848's "small,
 * empty-by-default config allowlist"), and return the real-user events plus
 * the watermark to persist for next time. Pure: no I/O, no `Date.now`, no
 * randomness — same inputs always yield the same outputs.
 *
 * **First enable (fresh watermark).** `watermark.initialized === false` is
 * treated as "never observed before" (exactly what
 * {@link initialObserverWatermark} produces): every ref's head and every
 * `forks/…` ref name in `snapshot` is recorded into `nextWatermark`
 * immediately, `nextWatermark.initialized` is set `true`, and `realEvents`
 * is empty. This is the ONLY branch that skips per-ref diffing — it exists
 * so a freshly-enabled (or freshly-redeployed) instance can never
 * replay-respond to a room's entire backlog (#848 user story:
 * "restart/redeploy safety ... the first watermark is 'now' across every
 * ref, never empty history"). Freshness is judged ONLY by the explicit
 * `initialized` flag, never by `refHeads` being empty: a room can
 * legitimately have zero refs at enable time, and that snapshot's emptiness
 * IS the baseline — `nextWatermark.initialized` still flips to `true`, so
 * the room's first-ever real commit (which creates the first ref) is
 * diffed and detected on the next call instead of being silently adopted as
 * baseline forever. A watermark that is already `initialized` (e.g. one
 * tracking only `main`, because that is the only ref that has ever existed,
 * or even one tracking zero refs because the room was empty at enable time)
 * always goes through the normal per-ref diff below, even for a ref it has
 * never seen before — a brand-new branch appearing after enable is real
 * activity worth detecting, not backlog.
 *
 * **Per-ref diff (normal case).** For every ref in `snapshot.refs`:
 * - `nextWatermark.refHeads[ref.name]` is set to the snapshot's current
 *   head. Iterating `snapshot.refs` (rather than merging with
 *   `watermark.refHeads`) is what makes ref deletion self-pruning: a ref
 *   missing from `snapshot.refs` simply never gets re-added to
 *   `nextWatermark.refHeads`, so a deleted/renamed ref's entry disappears
 *   instead of accumulating forever.
 * - A ref under `forks/` (see `events.ts`'s `FORKS_PREFIX`) that was NOT
 *   already in `watermark.knownForkRefs` is a brand-new fork. Its whole
 *   commit history in `snapshot.newCommitsByRef[ref.name]` collapses to AT
 *   MOST ONE `"fork"` event (targeting the ref's head), never one
 *   `"commit"` event per queued-up commit on that ref — per #848/#849: "A
 *   brand-new forks/ ref by a real author yields ONE fork event ... not
 *   additional commit events for the same head." The event's author is the
 *   head commit's author; if that commit is missing from the snapshot (it
 *   shouldn't be, but this stays defensive) no event is emitted, though the
 *   ref is still recorded as known. A synthetic-authored new fork ref
 *   yields no event but is still added to `knownForkRefs` (needed for
 *   #851's fork-of-fork upstream selection, which must see synthetic forks
 *   too).
 * - Every OTHER ref — `main`, any other non-`forks/` branch, or a
 *   `forks/…` ref already in `knownForkRefs` — is diffed commit-by-commit:
 *   each entry in `snapshot.newCommitsByRef[ref.name]` authored by a
 *   non-synthetic pubkey yields one `"commit"` event.
 * - Every event id (`commit:<hash>` / `fork:<refName>`) is checked against
 *   `watermark.respondedEventIds` before being emitted, so a snapshot that
 *   re-reports something already responded to (e.g. the DO re-polls a page
 *   boundary) never yields a duplicate. Newly emitted ids are appended to
 *   the LRU, which is then truncated to {@link RESPONDED_EVENT_ID_CAP}
 *   entries (oldest dropped first).
 */
export function observe(
  watermark: ObserverWatermark,
  snapshot: ObserverSnapshot,
  syntheticPubkeys: ReadonlySet<string>,
): { realEvents: RealEvent[]; nextWatermark: ObserverWatermark } {
  if (!watermark.initialized) {
    return initializeFreshWatermark(snapshot, watermark);
  }

  const responded = new Set(watermark.respondedEventIds);
  const nextRefHeads: Record<string, string> = {};
  const forkRefOrder = watermark.knownForkRefs.slice();
  const forkRefSet = new Set(forkRefOrder);
  const realEvents: RealEvent[] = [];
  const newlyEmitted: string[] = [];

  const emit = (event: RealEvent, eventId: string) => {
    if (responded.has(eventId)) return;
    realEvents.push(event);
    newlyEmitted.push(eventId);
    responded.add(eventId);
  };

  for (const ref of snapshot.refs) {
    nextRefHeads[ref.name] = ref.headHex;
    const commits = snapshot.newCommitsByRef[ref.name] ?? [];
    const isForkRef = ref.name.startsWith(FORKS_PREFIX);

    if (isForkRef && !forkRefSet.has(ref.name)) {
      // Brand-new fork ref: record it (synthetic authors included — see
      // `knownForkRefs`'s doc comment) and, if headed by a real author,
      // yield exactly one "fork" event — never per-commit "commit" events.
      forkRefSet.add(ref.name);
      forkRefOrder.push(ref.name);

      const headCommit = commits.find((c) => c.hash === ref.headHex) ?? commits[0];
      if (headCommit && !syntheticPubkeys.has(headCommit.authorPubkeyHex)) {
        emit(
          { kind: "fork", ref: ref.name, targetIdHex: ref.headHex, authorPubkeyHex: headCommit.authorPubkeyHex },
          forkEventId(ref.name),
        );
      }
      continue;
    }

    if (isForkRef) {
      // Already-known fork ref: further pushes onto it are ordinary commits.
      forkRefSet.add(ref.name);
    }

    for (const commit of commits) {
      if (syntheticPubkeys.has(commit.authorPubkeyHex)) continue;
      emit(
        { kind: "commit", ref: ref.name, targetIdHex: commit.hash, authorPubkeyHex: commit.authorPubkeyHex },
        commitEventId(commit.hash),
      );
    }
  }

  const mergedResponded = watermark.respondedEventIds.concat(newlyEmitted);
  const boundedResponded =
    mergedResponded.length > RESPONDED_EVENT_ID_CAP
      ? mergedResponded.slice(mergedResponded.length - RESPONDED_EVENT_ID_CAP)
      : mergedResponded;

  return {
    realEvents,
    nextWatermark: {
      refHeads: nextRefHeads,
      knownForkRefs: forkRefOrder,
      respondedEventIds: boundedResponded,
      initialized: true,
    },
  };
}

/**
 * First-enable path (see `observe`'s doc comment): adopt the snapshot's
 * current state as the baseline with zero events, and mark the returned
 * watermark `initialized: true` — even when `snapshot.refs` is empty. A room
 * with zero refs at enable time is still a valid baseline (there is simply
 * nothing to diff against yet); what matters is that this call happened, so
 * the NEXT call goes through the normal per-ref diff instead of re-adopting
 * whatever the room looks like by then. `watermark.respondedEventIds` is
 * carried through unchanged (expected empty for a truly fresh watermark, but
 * not asserted — this function only needs `refHeads`/`knownForkRefs` to be
 * authoritatively rebuilt from the snapshot).
 */
function initializeFreshWatermark(
  snapshot: ObserverSnapshot,
  watermark: ObserverWatermark,
): { realEvents: RealEvent[]; nextWatermark: ObserverWatermark } {
  const refHeads: Record<string, string> = {};
  const knownForkRefs: string[] = [];
  for (const ref of snapshot.refs) {
    refHeads[ref.name] = ref.headHex;
    if (ref.name.startsWith(FORKS_PREFIX)) knownForkRefs.push(ref.name);
  }
  return {
    realEvents: [],
    nextWatermark: {
      refHeads,
      knownForkRefs,
      respondedEventIds: watermark.respondedEventIds.slice(),
      initialized: true,
    },
  };
}
