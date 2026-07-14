// Event builders over `wasm.ts` (PLAN.md build step 4 — chat path; steps 5/6
// add `emitCommit`/`emitRemix` on top of this same `EmitContext`).
//
// Every emit* function drives the SAME wasm surfaces the web app's
// `WasmRepoBackend` does (`apps/web/src/lib/repo/backend.ts`): `envelope.ts`'s
// `makeSignFn` builds the per-procedure sign callback, and `mkit-repo-client`'s
// exported async fns (`post_message`, `put_object`, `update_ref`, …) take that
// callback and do the actual signed ConnectRPC call over `globalThis.fetch`.
// Nothing here talks to the network directly or reimplements any part of the
// envelope/transport contract.

import type { ContentPools } from "./ai-content";
import { CHAT_PHRASES, COMMIT_MESSAGE_PHRASES, REACTION_EMOJI, REMIX_MESSAGE_PHRASES, pick } from "./content";
import { makeSignFn, procedures } from "./envelope";
import type { Identity } from "./identities";
import type { WasmApi } from "./wasm";

/** Everything an emit* function needs beyond the per-call arguments. */
export type EmitContext = {
  wasm: WasmApi;
  /** `REPO_BASE_URL` — e.g. `https://api.mkit.sh`, or the staging/test equivalent. */
  baseUrl: string;
  /**
   * AI-refreshed chat/commit/remix phrase pools (`ai-content.ts`), when
   * `spammer.ts` has one in DO storage. `undefined` — no refresh has
   * succeeded yet, or Workers AI is unavailable — falls back to `content.ts`'s
   * static pools per-category (see each emit* function below). Reactions are
   * NOT included here on purpose: their emoji must stay pinned to the closed,
   * server-verified `REACTION_EMOJI` allowlist — AI has no business inventing
   * new ones.
   */
  contentPools?: ContentPools;
};

/** CAS precondition carried on `UpdateRef` — mirrors `apps/web/src/lib/repo/backend.ts`'s `RefExpectation`. */
export type RefExpectation = "ANY" | "MISSING" | "MATCH";

export type EmitChatResult = { messageIdHex: string; accepted: boolean; rateLimited: boolean };

/**
 * Post one signed chat message as `identity` into `room`. `counter` deterministically
 * selects the phrase from {@link CHAT_PHRASES} (see that module's doc comment) —
 * pass e.g. a per-tick or per-identity post count for tick-over-tick variety
 * without any randomness.
 *
 * Mirrors `WasmRepoBackend.postMessage` (`apps/web/src/lib/repo/backend.ts`)
 * exactly: sign over the `PostMessage` procedure, let `mkit-repo-client`'s
 * `post_message` serialize the request, BLAKE3-digest the raw body, and call
 * `sign` back for the envelope headers. The verified pubkey (derived from
 * `identity.seedHex`) becomes the message's author — there is no separate
 * "author" field to set.
 *
 * `rateLimited: true` (with `accepted: false`) means the author posted inside
 * `chat.rs`'s `MIN_POST_INTERVAL_MS` floor — the caller (the scheduler) is
 * expected to keep every identity well clear of that floor, so a `true` here
 * in production would indicate a scheduling bug, not a Worker-side failure.
 */
export async function emitChat(
  ctx: EmitContext,
  room: string,
  identity: Identity,
  counter: number,
): Promise<EmitChatResult> {
  const text = pick(ctx.contentPools?.chat ?? CHAT_PHRASES, counter);
  const sign = makeSignFn(ctx.wasm.mkit, identity.seedHex, procedures.PostMessage);
  return ctx.wasm.repo.post_message(ctx.baseUrl, room, text, sign);
}

// ---------------------------------------------------------------------------
// Commit path (build step 5)
// ---------------------------------------------------------------------------

/**
 * The ref every commit pushes onto — the front-page feed's linear walk
 * (PLAN.md "Feed visibility"). Exported (not module-private) because
 * `spammer.ts` (build step 8) also needs it: a "remix" or "reaction" tick
 * reads the CURRENT `main` head first (via `get_ref`) to have something real
 * to point at, rather than duplicating the literal `"main"` string.
 */
export const MAIN_REF = "main";

export type EmitCommitResult =
  | { committed: true; commitHash: string; parentHash: string | null; ref: string }
  /**
   * Both CAS attempts hit a conflict (a real visitor pushed to `main` between
   * our re-read and our retry). Per PLAN.md's "CAS on `main`" section, this is
   * logged and skipped — NOT thrown — because the next tick will simply try
   * again against the (by-then-current) head. `commitHash`/`currentIdHex`
   * are the losing attempt's values, useful for diagnostics only.
   */
  | { committed: false; commitHash: string; currentIdHex: string | null; ref: string };

/**
 * Build (empty-tree, PLAN.md "Empty-tree realism") + sign one commit as
 * `identity`, parented on `parentHex` (`""` = root commit). Pure wasm calls,
 * no I/O — split out so {@link emitCommit}'s retry can rebuild a fresh,
 * re-parented (and hence re-hashed) commit without duplicating the
 * tree/encode/sign incantation.
 */
function buildSignedCommit(
  ctx: EmitContext,
  identity: Identity,
  message: string,
  parentHex: string,
): { bytes: Uint8Array; hashHex: string } {
  const tree = ctx.wasm.mkit.tree_encode("[]");
  const nowSecs = BigInt(Math.floor(Date.now() / 1000));
  const commit = ctx.wasm.mkit.commit_encode_and_sign(tree.hash_hex, parentHex, message, nowSecs, identity.seedHex);
  return { bytes: commit.bytes, hashHex: commit.hash_hex };
}

/**
 * Push one commit onto `room`'s `main` ref as `identity`: empty-tree sign →
 * `put_object` → CAS `update_ref` (MISSING for the first-ever commit, MATCH
 * otherwise), with ONE re-read-head-and-retry on a CAS conflict — exactly
 * PLAN.md's "CAS on `main`" section. `counter` deterministically selects the
 * commit message from {@link COMMIT_MESSAGE_PHRASES} (see `content.ts`).
 *
 * Mirrors the web app's push path (`pushCommitMutationOptions`,
 * `apps/web/src/lib/repo/hooks.ts`): `PutObject` is content-addressed and
 * idempotent (safe to resend the same bytes across a retry — it never
 * conflicts, only `UpdateRef` can), and the expectation is `MISSING` when
 * there is no parent yet, `MATCH` on the parent hash otherwise.
 */
export async function emitCommit(
  ctx: EmitContext,
  room: string,
  identity: Identity,
  counter: number,
): Promise<EmitCommitResult> {
  const message = pick(ctx.contentPools?.commit ?? COMMIT_MESSAGE_PHRASES, counter);

  const pushOnce = async (parentHead: string | null) => {
    const parentHex = parentHead ?? "";
    const commit = buildSignedCommit(ctx, identity, message, parentHex);

    const signPut = makeSignFn(ctx.wasm.mkit, identity.seedHex, procedures.PutObject);
    await ctx.wasm.repo.put_object(ctx.baseUrl, room, commit.hashHex, commit.bytes, signPut);

    const expectation: RefExpectation = parentHead ? "MATCH" : "MISSING";
    const signUpdate = makeSignFn(ctx.wasm.mkit, identity.seedHex, procedures.UpdateRef);
    const updateResult = await ctx.wasm.repo.update_ref(
      ctx.baseUrl,
      room,
      MAIN_REF,
      commit.hashHex,
      expectation,
      parentHead ?? undefined,
      signUpdate,
    );
    return { commit, updateResult };
  };

  // `get_ref` returns `string | undefined` (absent ref) across the wasm
  // boundary; normalize to `string | null` so `pushOnce`'s "no parent yet"
  // check (`parentHead ? … : …`) and the returned `parentHash` field have one
  // unambiguous "no ref yet" representation.
  const head0 = (await ctx.wasm.repo.get_ref(ctx.baseUrl, room, MAIN_REF)) ?? null;
  const attempt0 = await pushOnce(head0);
  if (!attempt0.updateResult.conflict) {
    return { committed: true, commitHash: attempt0.commit.hashHex, parentHash: head0, ref: MAIN_REF };
  }

  // One retry: re-read the (by-now-current) head and rebuild a freshly
  // re-parented (and hence re-hashed) commit against it.
  const head1 = (await ctx.wasm.repo.get_ref(ctx.baseUrl, room, MAIN_REF)) ?? null;
  const attempt1 = await pushOnce(head1);
  if (!attempt1.updateResult.conflict) {
    return { committed: true, commitHash: attempt1.commit.hashHex, parentHash: head1, ref: MAIN_REF };
  }

  console.warn(
    `[spammer-worker] emitCommit: CAS conflict on ${room}/${MAIN_REF} persisted through the retry — skipping this tick (identity #${identity.index})`,
  );
  return {
    committed: false,
    commitHash: attempt1.commit.hashHex,
    currentIdHex: attempt1.updateResult.currentIdHex,
    ref: MAIN_REF,
  };
}

// ---------------------------------------------------------------------------
// Remix path (build step 6)
// ---------------------------------------------------------------------------

const TEXT_ENCODER = new TextEncoder();

/** Prefix every fork ref lands under (PLAN.md "Feed visibility" — remixes surface via the refs panel, not `main`). */
export const FORKS_PREFIX = "forks/";

/**
 * Fork ref name for a remix of `upstreamCommitHash` by the forker whose pubkey
 * is `forkerPubkeyHex` — mirrors `forkRefName`
 * (`apps/web/src/lib/repo/backend.ts:274-278`) EXACTLY (same scheme: first-12-hex
 * of the upstream commit hash + first-12-hex of the forker's pubkey), re-implemented
 * here rather than imported since this worker is a separate deployable package
 * with no shared-code boundary to `apps/web` (same reasoning as this file's own
 * `RefExpectation` mirror above). Unlike the web helper, `forkerPubkeyHex` is
 * required here — every synthetic identity always has a pubkey, so there is no
 * "legacy seeded demo data" case to fall back from.
 */
export function forkRefName(upstreamCommitHash: string, forkerPubkeyHex: string): string {
  return `${FORKS_PREFIX}${upstreamCommitHash.slice(0, 12)}-${forkerPubkeyHex.slice(0, 12)}`;
}

export type EmitRemixResult =
  | { committed: true; remixHash: string; parentHash: string | null; ref: string }
  /** Both CAS attempts hit a conflict — logged and skipped, same rationale as {@link EmitCommitResult}. */
  | { committed: false; remixHash: string; currentIdHex: string | null; ref: string };

/**
 * Build (empty-tree) + sign one remix object as `identity`, forking
 * `upstreamCommitHash` (a commit hash — this build step never remixes another
 * remix), parented on `parentHex` (`""` = first push to this fork ref). Split
 * out so {@link emitRemix}'s retry can rebuild a fresh, re-parented (and hence
 * re-hashed) remix without duplicating the encode/sign incantation — mirrors
 * {@link buildSignedCommit} one section up.
 *
 * Mirrors `useDerive.remix` (`apps/web/src/components/multiplayer/compose.tsx:314-348`)
 * exactly: the `sources` array carries exactly ONE entry, and `upstream_id_hex`
 * is an OPAQUE per-room provenance tag (`blake3_hex(room)`) — NOT the upstream
 * commit hash, which lives separately as `commit_hash_hex`.
 */
function buildSignedRemix(
  ctx: EmitContext,
  room: string,
  identity: Identity,
  upstreamCommitHash: string,
  message: string,
  parentHex: string,
): { bytes: Uint8Array; hashHex: string } {
  const tree = ctx.wasm.mkit.tree_encode("[]");
  const upstreamIdHex = ctx.wasm.mkit.blake3_hex(TEXT_ENCODER.encode(room));
  const sourcesJson = JSON.stringify([{ upstream_id_hex: upstreamIdHex, commit_hash_hex: upstreamCommitHash }]);
  const nowSecs = BigInt(Math.floor(Date.now() / 1000));
  const remix = ctx.wasm.mkit.remix_encode_and_sign(
    tree.hash_hex,
    parentHex,
    sourcesJson,
    message,
    nowSecs,
    identity.seedHex,
  );
  return { bytes: remix.bytes, hashHex: remix.hash_hex };
}

/**
 * Push one remix of `upstreamCommitHash` as `identity` onto `identity`'s own
 * fork ref ({@link forkRefName}) — DISTINCT from {@link emitCommit}'s shared
 * `main` ref. Every (upstream commit, forker) pair gets its own ref, so unlike
 * `main` there is no cross-identity contention on it: only THIS identity,
 * remixing THIS exact upstream, ever writes to this exact ref. The CAS
 * re-read-and-retry below exists for symmetry with `emitCommit` and to
 * tolerate a repeat remix of the same upstream by the same identity (which
 * legitimately chains onto its own prior head via `MATCH`) rather than to
 * guard against real contention. `counter` deterministically selects the
 * remix message from {@link REMIX_MESSAGE_PHRASES}.
 *
 * Per PLAN.md's "Feed visibility": this lands on a `forks/…` ref, so it
 * surfaces via the refs/branches panel + `WatchRefs` broadcast — it will NOT
 * appear in the linear `main` feed (`emitCommit`'s ref), by design.
 */
export async function emitRemix(
  ctx: EmitContext,
  room: string,
  identity: Identity,
  upstreamCommitHash: string,
  counter: number,
): Promise<EmitRemixResult> {
  const message = pick(ctx.contentPools?.remix ?? REMIX_MESSAGE_PHRASES, counter);
  const ref = forkRefName(upstreamCommitHash, identity.pubkeyHex);

  const pushOnce = async (parentHead: string | null) => {
    const parentHex = parentHead ?? "";
    const remix = buildSignedRemix(ctx, room, identity, upstreamCommitHash, message, parentHex);

    const signPut = makeSignFn(ctx.wasm.mkit, identity.seedHex, procedures.PutObject);
    await ctx.wasm.repo.put_object(ctx.baseUrl, room, remix.hashHex, remix.bytes, signPut);

    const expectation: RefExpectation = parentHead ? "MATCH" : "MISSING";
    const signUpdate = makeSignFn(ctx.wasm.mkit, identity.seedHex, procedures.UpdateRef);
    const updateResult = await ctx.wasm.repo.update_ref(
      ctx.baseUrl,
      room,
      ref,
      remix.hashHex,
      expectation,
      parentHead ?? undefined,
      signUpdate,
    );
    return { remix, updateResult };
  };

  const head0 = (await ctx.wasm.repo.get_ref(ctx.baseUrl, room, ref)) ?? null;
  const attempt0 = await pushOnce(head0);
  if (!attempt0.updateResult.conflict) {
    return { committed: true, remixHash: attempt0.remix.hashHex, parentHash: head0, ref };
  }

  // One retry: re-read the (by-now-current) head and rebuild a freshly
  // re-parented (and hence re-hashed) remix against it.
  const head1 = (await ctx.wasm.repo.get_ref(ctx.baseUrl, room, ref)) ?? null;
  const attempt1 = await pushOnce(head1);
  if (!attempt1.updateResult.conflict) {
    return { committed: true, remixHash: attempt1.remix.hashHex, parentHash: head1, ref };
  }

  console.warn(
    `[spammer-worker] emitRemix: CAS conflict on ${room}/${ref} persisted through the retry — skipping this tick (identity #${identity.index})`,
  );
  return {
    committed: false,
    remixHash: attempt1.remix.hashHex,
    currentIdHex: attempt1.updateResult.currentIdHex,
    ref,
  };
}

// ---------------------------------------------------------------------------
// Reaction path (build step 8 — the "optional" `emitReaction` PLAN.md's file
// table calls out for `spammer.ts`'s occasional reaction pick)
// ---------------------------------------------------------------------------

export type EmitReactionResult = { active: boolean; count: number };

/**
 * Toggle one signed emoji reaction (from the closed {@link REACTION_EMOJI}
 * allowlist) as `identity` onto `targetIdHex` — a feed item that must already
 * exist (the caller, `spammer.ts`, always passes the current `main` head
 * commit hash, since that is guaranteed to exist by the time a reaction tick
 * fires). Unlike {@link emitCommit}/{@link emitRemix} there is no CAS/retry
 * here: `React` is a plain idempotent toggle
 * (`apps/repo-worker/src/chat.rs`), not a ref update, so there is nothing to
 * conflict with.
 *
 * Mirrors the web app's reaction path (`WasmRepoBackend.react`,
 * `apps/web/src/lib/repo/backend.ts`) exactly: sign over the `React`
 * procedure and let `mkit-repo-client`'s `react` do the call.
 */
export async function emitReaction(
  ctx: EmitContext,
  room: string,
  identity: Identity,
  targetIdHex: string,
  counter: number,
): Promise<EmitReactionResult> {
  const emoji = pick(REACTION_EMOJI, counter);
  const sign = makeSignFn(ctx.wasm.mkit, identity.seedHex, procedures.React);
  return ctx.wasm.repo.react(ctx.baseUrl, room, targetIdHex, emoji, sign);
}
