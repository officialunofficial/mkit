// Synthetic content pools for the events the `Spammer` DO emits (PLAN.md
// build step 4).
//
// Every pool below is a FIXED array — no RNG anywhere in this file. Variety
// tick-over-tick comes from `pick(pool, counter)` indexing by an
// ever-incrementing counter the caller already tracks (e.g. the scheduler's
// tick number, or a per-identity post count), not from randomness. That keeps
// a run fully reproducible: the same `(pool, counter)` pair always yields the
// same string, which matters for tests and for reasoning about what a given
// tick will post before it posts it.
//
// Only `CHAT_PHRASES` is exercised by this build step (`emitChat`); the rest
// are scaffolded now because later steps (`emitCommit` — step 5, `emitRemix`
// — step 6) need them and there is no reason to split one small content file
// across three PRs.

/**
 * Chat phrases posted via `emitChat`/`post_message`. Kept under
 * `apps/repo-worker/src/chat.rs`'s `MAX_MESSAGE_CHARS` (280 chars) by a wide
 * margin — every entry here is a short, demo-appropriate line in the same
 * voice as the web app's own seeded demo chat (`WasmRepoBackend.seedDemoChat`,
 * `apps/web/src/lib/repo/backend.ts`).
 */
export const CHAT_PHRASES: readonly string[] = [
  "gm — every message here is ed25519-signed",
  "just pushed a commit, say hi 👋",
  "content-addressed and loving it",
  "BLAKE3 hashes go brrr",
  "who else is exploring the live feed right now?",
  "signed writes only, no funny business",
  "watching the refs panel update in real time",
  "this whole lobby is one big content-addressed log",
  "anyone remixed a commit yet? try it",
  "mkit: git-shaped, signed, content-addressed",
  "the feed never lies — every entry verifies",
  "small commits, signed commits",
  "forks show up over on the refs/branches panel",
  "no accounts, no passwords — just an Ed25519 key",
  "this message is a first-class signed object too",
  "every hash in this feed is checkable, go verify one",
  "the refs panel is the fun part, click around",
  "pushed from a browser, verified by the server, no trust required",
  "same protocol the CLI speaks, just in a lobby",
  "each of these commits is an empty tree — the signature is the point",
  "try the fork button on any commit, attribution comes along for free",
  "one shared repo, everyone signs their own writes",
  "the log only ever grows — that's the whole idea",
  "passkey in, signed commits out",
] as const;

/**
 * Commit-message phrases for `emitCommit` (build step 5). The live demo signs
 * every commit over an EMPTY tree (PLAN.md "Empty-tree realism") — a push here
 * really is "a signed message", so these read the same way `compose.tsx`'s
 * default message does (`'gm, multiplayer mkit'`).
 */
export const COMMIT_MESSAGE_PHRASES: readonly string[] = [
  "gm, multiplayer mkit",
  "tree ∅ — a signed message",
  "pushing to main, business as usual",
  "another signed commit lands",
  "keeping the log warm",
  "synthetic activity, real signatures",
  "one push closer to a lively feed",
  "content-addressed, as always",
  "no files, just a verified vibe",
  "history keeps growing",
] as const;

/**
 * Remix-message phrases for `emitRemix` (build step 6) — the message carried
 * on the remix object itself (the commit it wraps still carries its own
 * `COMMIT_MESSAGE_PHRASES` entry).
 */
export const REMIX_MESSAGE_PHRASES: readonly string[] = [
  "remixing this one",
  "forked it — see forks/ for the branch",
  "riffing on the upstream commit",
  "attribution built in, not bolted on",
  "a remix is just a signed pointer back",
  "branching off to try something else",
] as const;

/**
 * Reply-template phrases for {@link fillReplyTemplate} in `ai-content.ts` —
 * the curated fallback for the new "reply" category (see that module's doc
 * comment). Unlike the other pools, entries here carry substitution slots
 * (`{hash}`, `{author}`, `{branch}` — see `ai-content.ts`'s `ALLOWED_REPLY_SLOTS`)
 * filled in deterministically at emit time, so a real user's push is
 * acknowledged by name without ever needing a per-event AI call.
 *
 * Same empty-tree honesty voice as the other pools: every line acknowledges
 * the ACT of signing/pushing/forking, never invents a claim about content
 * that doesn't exist, and never addresses anyone by an invented name — only
 * the short hash/author-key/branch slots a real event actually supplies.
 * Mixed deliberately: some entries use `{branch}` (only ever picked by a
 * caller when the push landed on a non-`main` branch — see
 * `fillReplyTemplate`'s doc comment), most don't (so `main` pushes, the
 * common case, always have plenty of eligible templates).
 */
export const REPLY_TEMPLATES: readonly string[] = [
  "gm {author} — saw that signed push, {hash} landed clean",
  "{hash} verified and in the log, nice one {author}",
  "another signed commit from {author} — {hash} checks out",
  "welcome to the feed {author}, {hash} is officially content-addressed",
  "{author} pushed to {branch} — {hash} is live over there",
  "nice fork {author}, {branch} now has its own signed history",
  "{hash} on {branch} — good to see activity off main too",
  "spotted {hash} — signed, verified, no funny business {author}",
  "{author}'s {hash} just joined the log, gm",
  "solid push {author}, {hash} is a real signed object now",
] as const;

/**
 * The closed emoji allowlist a reaction may use — MUST match
 * `apps/repo-worker/src/chat.rs::REACTION_EMOJI` exactly (the server rejects
 * anything outside this set), which itself must match the web client's
 * picker. Kept here (not re-derived) so `emitReaction` (optional, PLAN.md
 * step 8) has one place to pick from.
 */
export const REACTION_EMOJI: readonly string[] = ["👍", "❤️", "😂", "🎉", "🚀", "👀", "✅", "🔥"] as const;

/**
 * Deterministically pick an entry from `pool` by `counter`, wrapping with
 * modulo. `counter` is expected to be a non-negative integer (a tick number,
 * a per-identity post count, …); any integer works since JS `%` on two
 * non-negative operands is already in range, and `pool` is asserted non-empty
 * by every pool above.
 */
export function pick<T>(pool: readonly T[], counter: number): T {
  const idx = ((counter % pool.length) + pool.length) % pool.length;
  return pool[idx]!;
}
