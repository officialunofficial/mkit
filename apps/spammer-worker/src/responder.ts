// Pure glue between the observer (#849), the scheduler's fork-of-fork input
// (#851), and the AI-content reply-template pool (#853) — everything DECIDABLE
// about wiring the responder into the `Spammer` DO (#854), factored out of
// `spammer.ts` so the DO itself stays thin (no I/O, no clock, no wasm handle
// in this file — same "pure glue module" discipline `observer.ts` and
// `scheduler.ts` already follow). `spammer.ts` owns every actual `list_refs`/
// `list_commits` call, `Date.now()` read, and DO-storage read/write; this
// module only ever transforms the plain data those calls produce.

import type { ContentPools, ReplySlots } from "./ai-content";
import { fillReplyTemplate } from "./ai-content";
import { REPLY_TEMPLATES } from "./content";
import { MAIN_REF } from "./events";
import type { Identity } from "./identities";
import type { CommitMeta, ObserverWatermark, RefEntry } from "./observer";
import type { ForkUpstreamRef } from "./scheduler";

// -----------------------------------------------------------------------------
// refsNeedingFetch — which refs the DO should page `list_commits` for
// -----------------------------------------------------------------------------

/**
 * Which of `refs` (the full `list_refs` listing for this poll) have moved (or
 * are brand new) relative to `watermark.refHeads`, and therefore need a
 * `list_commits` page — the DO's per-poll "what do I actually have to fetch"
 * filter. A ref whose head is unchanged since the last poll needs nothing:
 * `observe` (#849) only ever looks at `newCommitsByRef` entries for refs it
 * diffs commit-by-commit, and an unmoved ref contributes zero real events by
 * construction.
 *
 * Returns `[]` outright when `!watermark.initialized` — the exact same
 * "fresh watermark" test `observe`'s own doc comment uses for its
 * first-enable short-circuit (#849's explicit `initialized` flag, not
 * `refHeads` emptiness — a room can legitimately have zero refs and still be
 * initialized). That branch adopts the snapshot's ref heads as the baseline
 * WITHOUT ever inspecting commit data (see `observer.ts`), so paging commits
 * for every ref on a freshly-enabled (or freshly-redeployed) instance would
 * be pure waste — worse, it would be wasted I/O in the exact moment #848's
 * "restart/redeploy safety" story cares most about staying cheap and inert.
 */
export function refsNeedingFetch(watermark: ObserverWatermark, refs: readonly RefEntry[]): RefEntry[] {
  if (!watermark.initialized) {
    return [];
  }
  return refs.filter((ref) => watermark.refHeads[ref.name] !== ref.headHex);
}

// -----------------------------------------------------------------------------
// forkUpstreamsFromWatermark — feeds planTick's optional third parameter
// -----------------------------------------------------------------------------

/**
 * The known fork refs' current heads, in `scheduler.ts`'s `planTick`
 * `forkUpstreams` shape (issue #851) — `watermark.knownForkRefs ∩
 * watermark.refHeads`. `knownForkRefs` (an append-only, never-pruned
 * inventory — see `observer.ts`'s doc comment) can outlive a ref's presence
 * in `refHeads` (which self-prunes on ref deletion), so a fork ref missing
 * from `refHeads` is silently skipped rather than offered as a remix upstream
 * with a stale or nonexistent head.
 *
 * This is the deliberate coupling #854 documents: fork-of-fork ambient
 * remixes (#851) only ever have candidates once the responder's polling has
 * populated `watermark.knownForkRefs` at least once — with the responder
 * disabled (the default), this always returns `[]`, and `planTick`'s
 * `forkUpstreams` parameter being empty makes fork-of-fork selection
 * entirely inert (every ambient remix forks `main`'s tip, exactly as it did
 * before #851). The observer is the ONLY fork-ref source in this codebase;
 * there is no independent tracking of fork refs anywhere else.
 */
export function forkUpstreamsFromWatermark(watermark: ObserverWatermark): ForkUpstreamRef[] {
  const result: ForkUpstreamRef[] = [];
  for (const ref of watermark.knownForkRefs) {
    const headHex = watermark.refHeads[ref];
    if (headHex !== undefined) result.push({ ref, headHex });
  }
  return result;
}

// -----------------------------------------------------------------------------
// buildSnapshot — assembles the ObserverSnapshot from raw poll results
// -----------------------------------------------------------------------------

/**
 * Cap on how many commits from one ref's `list_commits` page are accepted
 * into `ObserverSnapshot.newCommitsByRef` per poll for a ref `observe` has
 * already watermarked. `list_commits` walks newest-first from the ref's
 * current head; a burst (many real commits landing on one ref between two
 * ~5s polls) could otherwise hand `observe` an unbounded run of "new"
 * commits, each of which can enqueue its own response bundle
 * (`enqueueResponseBundle` in `scheduler.ts`) — 10 is generous headroom over
 * any plausible per-poll burst at the polling cadence (#854's
 * `POLL_EVERY_N_TICKS`) while keeping a single pathological ref from
 * exploding the response queue. Truncation is log-worthy (the caller can
 * detect it by noticing a ref's accepted count hit this cap) but the cap
 * itself is just data — this module has no I/O to log through.
 *
 * A ref with NO watermark head yet (brand new since the last poll) does not
 * use this cap at all — see {@link buildSnapshot}'s doc comment for why it
 * instead accepts exactly one commit (the ref's head).
 */
export const MAX_ACCEPTED_COMMITS_PER_REF = 10;

/**
 * Assemble an `ObserverSnapshot` (`observer.ts`) from the DO's raw
 * `list_refs` result and the `list_commits` pages it fetched for
 * {@link refsNeedingFetch}'s output. For each ref with a fetched page, walks
 * the page (newest-first, as `list_commits` returns it) and keeps only
 * commits strictly NEWER than `watermark.refHeads[ref.name]`: it stops (and
 * does NOT include) at the first commit whose hash equals the watermark head
 * — that commit was already observed on a prior poll — and stops earlier
 * still if {@link MAX_ACCEPTED_COMMITS_PER_REF} is reached first.
 *
 * A ref with no watermark head yet (brand new since the last poll) accepts
 * ONLY the page's first entry — the ref's current head — regardless of how
 * many older commits came back on the same page. A real user pointing a
 * brand-new branch at existing history (e.g. branching off an old commit)
 * must not replay that history's ancestors as if they just landed; the new
 * ref is acknowledged once, at its head, symmetric with how `observe`
 * already collapses a brand-new `forks/…` ref to a single `"fork"` event
 * regardless of the commits behind it.
 *
 * `refs` is carried straight through as `ObserverSnapshot.refs` (needed by
 * `observe` for ref-presence/deletion tracking even for refs that didn't
 * need a commits page). Pure: no I/O, no clock — same discipline as every
 * other function in this module.
 */
export function buildSnapshot(
  refs: readonly RefEntry[],
  fetchedCommitPagesByRef: Readonly<Record<string, readonly CommitMeta[]>>,
  watermark: ObserverWatermark,
): { refs: RefEntry[]; newCommitsByRef: Record<string, CommitMeta[]> } {
  const newCommitsByRef: Record<string, CommitMeta[]> = {};

  for (const ref of refs) {
    const page = fetchedCommitPagesByRef[ref.name];
    if (!page || page.length === 0) continue;

    const watermarkHead = watermark.refHeads[ref.name];
    const accepted: CommitMeta[] = [];
    if (watermarkHead === undefined) {
      // New ref: acknowledge only its head, never the ancestors behind it.
      accepted.push(page[0]);
    } else {
      for (const commitMeta of page) {
        if (commitMeta.hash === watermarkHead) break;
        if (accepted.length >= MAX_ACCEPTED_COMMITS_PER_REF) break;
        accepted.push(commitMeta);
      }
    }
    if (accepted.length > 0) newCommitsByRef[ref.name] = accepted;
  }

  return { refs: refs.slice(), newCommitsByRef };
}

// -----------------------------------------------------------------------------
// chooseReplyText — deterministic template-pool fallback for a response chat
// -----------------------------------------------------------------------------

/** The subset of `ResponsePayload` (`scheduler.ts`) {@link chooseReplyText} needs — targeting facts, not scheduler bookkeeping. */
export type ReplyIntent = {
  targetIdHex: string;
  ref: string;
  realAuthorPubkeyHex: string;
};

/**
 * Hardcoded, slot-minimal ultimate fallback — used ONLY if every entry in
 * `pools?.reply ?? REPLY_TEMPLATES` fails to fill (see {@link chooseReplyText}'s
 * doc comment for when that can happen). Carries no `{branch}` token, so it
 * always fills regardless of `intent.ref`, keeping this function's "always
 * returns a string" contract true unconditionally.
 */
const FALLBACK_REPLY_TEMPLATE = "gm {author} — {hash} just landed, signed and verified";

/**
 * Deterministically pick a reply-template entry from `pools?.reply ??
 * REPLY_TEMPLATES` (`content.ts`'s curated fallback — see `ai-content.ts`'s
 * `ContentPools.reply` doc comment for why it's optional) and fill it via
 * `fillReplyTemplate`, starting the search at `counter` and wrapping across
 * the whole pool at most once — same "counter selects deterministically,
 * wrapping" idiom as `content.ts`'s `pick`, generalized here to skip entries
 * that fail to fill instead of accepting whatever index lands.
 *
 * `intent.ref !== MAIN_REF` is what makes `slots.branch` defined; a template
 * containing `{branch}` only ever fills when `slots.branch` is defined (see
 * `fillReplyTemplate`'s own contract), so a `main` push structurally can
 * never select a branch-slotted template — not because this function
 * excludes them, but because `fillReplyTemplate` rejects them and the search
 * moves on to the next candidate. This is exactly "picks a `{branch}`-slotted
 * template only when `intent.ref !== 'main'`."
 *
 * Never returns `null`: `content.ts`'s own `REPLY_TEMPLATES` always has a mix
 * of branch-carrying and branch-less entries (see that pool's own test
 * coverage), so a branch-less entry is always reachable for a `main` push and
 * ANY entry is reachable for a non-`main` push. An AI-refreshed pool
 * (`ai-content.ts`) is only guaranteed to validate slot SYNTAX, not to
 * contain a branch-less entry, so the pathological case (every refreshed
 * template requires `{branch}` and `intent.ref === MAIN_REF`) falls through
 * to {@link FALLBACK_REPLY_TEMPLATE}, which always fills.
 */
export function chooseReplyText(pools: ContentPools | undefined, intent: ReplyIntent, counter: number): string {
  const pool = pools?.reply ?? REPLY_TEMPLATES;
  const branch = intent.ref === MAIN_REF ? undefined : intent.ref;
  const slots: ReplySlots = { hash: intent.targetIdHex, author: intent.realAuthorPubkeyHex, branch };

  for (let step = 0; step < pool.length; step++) {
    const idx = (((counter + step) % pool.length) + pool.length) % pool.length;
    const filled = fillReplyTemplate(pool[idx]!, slots);
    if (filled !== null) return filled;
  }

  // Unreachable against every pool this codebase ships (see doc comment
  // above) but kept as a real fallback, not a thrown assertion, since a
  // future AI-refreshed pool is untrusted input.
  return fillReplyTemplate(FALLBACK_REPLY_TEMPLATE, { hash: intent.targetIdHex, author: intent.realAuthorPubkeyHex })!;
}

// -----------------------------------------------------------------------------
// mergedSyntheticPubkeys — structural loop-prevention set
// -----------------------------------------------------------------------------

/**
 * The full set of pubkeys `observe` (#849) must treat as "not a real user":
 * every identity in `pool` (the 64 deterministic synthetic identities —
 * `identities.ts`'s `getIdentityPool`) plus `allowlistCsv`'s entries — a
 * comma-separated config allowlist of additional known-non-human pubkeys
 * (e.g. legacy seeded demo authors, per #848's "small config allowlist ...
 * empty by default"). Every entry is trimmed and lowercased before joining
 * the set, matching the lowercase-hex convention every pubkey crossing the
 * wasm boundary already uses (`mkit-repo-client`'s own doc comment: "All ids
 * cross the wasm boundary as lowercase hex strings") — so a config typo in
 * casing or stray whitespace can never accidentally leave a non-human author
 * misclassified as real.
 *
 * `allowlistCsv` being `undefined` or empty contributes nothing beyond the
 * pool — the documented empty-by-default posture.
 */
export function mergedSyntheticPubkeys(pool: readonly Identity[], allowlistCsv: string | undefined): Set<string> {
  const result = new Set<string>(pool.map((identity) => identity.pubkeyHex.toLowerCase()));
  for (const raw of (allowlistCsv ?? "").split(",")) {
    const trimmed = raw.trim().toLowerCase();
    if (trimmed.length > 0) result.add(trimmed);
  }
  return result;
}
