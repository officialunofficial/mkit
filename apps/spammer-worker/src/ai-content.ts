// Periodic Workers AI content refresh for content.ts's static phrase pools.
//
// This is the ONLY impure/non-deterministic corner of the content story —
// everything else (`content.ts`'s `pick`, the scheduler) is a pure function
// on purpose. This module is called rarely (every ~20 minutes, gated by
// `spammer.ts`'s `CONTENT_REFRESH_EVERY_N_TICKS`, never on the hot 1s alarm
// tick) and its failure mode is ALWAYS "keep using whatever pool is already
// in DO storage" (which itself started as `content.ts`'s static pool) —
// never throw, never block a tick, never let a malformed model response
// reach `pick()`.
//
// Free-tier math (see wrangler.jsonc's own comment): a synchronous call on
// every emitted event would need ~259,000 requests/day at the target ~3
// events/s — about 1000x the entire 10,000-neuron/day free allowance even at
// the cheapest model. One batched call every ~20 minutes (asking for a
// whole pool's worth of phrases in one response) costs a few dozen to a few
// hundred requests/day — comfortably inside budget.

import { CHAT_PHRASES, COMMIT_MESSAGE_PHRASES, REMIX_MESSAGE_PHRASES, REPLY_TEMPLATES } from "./content";

/** Cheapest Workers AI text model (~50-200 neurons/request) — quality doesn't matter much for short demo phrases, and staying cheap is what keeps a 20-minute refresh cadence sustainable on the free tier. */
const MODEL = "@cf/mistral/mistral-7b-instruct-v0.1";

const MAX_CHAT_CHARS = 100;
const MAX_COMMIT_CHARS = 60;
const MAX_REMIX_CHARS = 80;
/** Same cap as chat — reply templates are a one-line acknowledgment, same register as a chat message. */
const MAX_REPLY_CHARS = 100;

/**
 * The only substitution slots {@link fillReplyTemplate} understands. A reply
 * template containing any `{other}`-shaped token outside this set fails
 * validation (`validateReplyTemplates` below) rather than being emitted
 * verbatim with a literal unfilled `{whatever}` in it — see #853/#848's
 * honesty constraint: replies may reference the act + these three real,
 * caller-supplied facts about the event, and nothing else.
 */
export const ALLOWED_REPLY_SLOTS = ["hash", "author", "branch"] as const;
export type ReplySlotName = (typeof ALLOWED_REPLY_SLOTS)[number];

const SLOT_TOKEN_RE = /\{([a-zA-Z]+)\}/g;

const PROMPT = `You generate short sample text for mkit, a live cryptographically-signed, content-addressed version-control demo (like git, but every commit/message/remix is Ed25519-signed and BLAKE3 content-addressed). Respond with ONLY a single JSON object, no prose, no markdown code fences, matching EXACTLY this shape:
{"chat": ["...", ...], "commit": ["...", ...], "remix": ["...", ...], "reply": ["...", ...]}

CRITICAL CONSTRAINT: every commit in this demo has an EMPTY tree — there is NO real file, NO real diff, NO real code change behind any commit. Never invent a specific fake code change (e.g. never write things like "add prop X to component Y" or "fix bug in Z") — that describes work that doesn't exist and misleads anyone reading the feed. Instead, commit/remix/reply messages should read as honest, self-aware signed placeholder messages — about the act of signing/pushing/forking itself, not about invented feature work.

Rules:
- "chat": 15 short chat-style lines (max ${MAX_CHAT_CHARS} characters each), casual and friendly, about THIS demo's real properties: Ed25519 signing, BLAKE3 content-addressing, the live feed, forking/remixing, no accounts needed. No hashtags, no emoji-only lines, no profanity, no invented person names or fictional conversations between characters.
- "commit": 10 short lines (max ${MAX_COMMIT_CHARS} characters each) in the voice of a real git commit message, but honest about being a signed placeholder over an empty tree — e.g. referencing "signed", "content-addressed", "no files", "a verified vibe" — never a specific invented feature/bugfix.
- "remix": 6 short lines (max ${MAX_REMIX_CHARS} characters each) about the act of remixing/forking another commit — attribution, branching, signed provenance — never an invented feature description.
- "reply": 8 short lines (max ${MAX_REPLY_CHARS} characters each) that ACKNOWLEDGE A REAL PERSON'S PUSH OR FORK, addressed to them using ONLY the substitution slots {hash}, {author}, and {branch} — literally those tokens, e.g. "gm {author}, {hash} just landed". Use {branch} in roughly half the lines (for a push that was NOT to "main") and omit it in the rest (for a push that WAS to "main"). NEVER invent a name for the person (always use the literal {author} token, never a fictional name) and NEVER invent what they pushed (no fake file names, no fake feature descriptions) — only reference the act of signing/pushing/forking plus the {hash}/{author}/{branch} tokens themselves. Do not use any other {curly-brace} token.
Output strictly valid JSON. No trailing commas. No commentary before or after the JSON.`;

/**
 * The four phrase pools `events.ts`'s emit* functions pick from — either
 * AI-refreshed (this module) or `content.ts`'s static fallback.
 *
 * `reply` is OPTIONAL — this is a load-bearing backward-compat detail, not
 * an oversight. A production DO may already have an OLD-SHAPE `ContentPools`
 * value (`{chat, commit, remix}`, no `reply` key) sitting in its durable
 * storage from before this category existed. That stored value is still a
 * perfectly valid `ContentPools` under this type (an absent optional field
 * satisfies it), so nothing about adding this category can make a
 * previously-persisted value invalid or crash a consumer that reads it back
 * — every reader must do `pools?.reply ?? <static fallback>` (see
 * `REPLY_TEMPLATES` / `FALLBACK_POOLS.reply` in `content.ts`) rather than
 * assuming the key exists. `parseAndValidate` below, by contrast, DOES
 * require all four categories in a FRESH model response — a refresh that
 * can't produce valid replies returns `null` and the DO keeps whatever pool
 * (old- or new-shape) it already had, consistent with this module's existing
 * all-or-nothing validation for chat/commit/remix.
 */
export type ContentPools = {
  chat: readonly string[];
  commit: readonly string[];
  remix: readonly string[];
  reply?: readonly string[];
};

/** `content.ts`'s original static pools, exposed here so callers have one canonical "known good" fallback value without importing `content.ts` themselves. */
export const FALLBACK_POOLS: ContentPools = {
  chat: CHAT_PHRASES,
  commit: COMMIT_MESSAGE_PHRASES,
  remix: REMIX_MESSAGE_PHRASES,
  reply: REPLY_TEMPLATES,
};

/**
 * Ask Workers AI for a fresh batch of phrases. Returns `null` on ANY failure
 * — network/quota error, malformed JSON, wrong shape, an entry that's not a
 * non-empty string, an entry over its category's length cap — never throws.
 * Callers (`spammer.ts`) are expected to keep the previously-stored pool (or
 * {@link FALLBACK_POOLS} if none exists yet) when this returns `null`.
 */
export async function refreshContentPools(ai: Ai): Promise<ContentPools | null> {
  let raw: unknown;
  try {
    raw = await ai.run(MODEL, { messages: [{ role: "user", content: PROMPT }] });
  } catch (err) {
    console.warn("[spammer-worker] ai-content: Workers AI call failed, keeping current pool:", err);
    return null;
  }

  const text = extractResponseText(raw);
  if (text === null) {
    console.warn("[spammer-worker] ai-content: unexpected Workers AI response shape, keeping current pool");
    return null;
  }

  const parsed = parseAndValidate(text);
  if (parsed === null) {
    console.warn("[spammer-worker] ai-content: model output failed validation, keeping current pool");
    return null;
  }
  return parsed;
}

function extractResponseText(raw: unknown): string | null {
  if (raw && typeof raw === "object" && "response" in raw && typeof (raw as { response: unknown }).response === "string") {
    return (raw as { response: string }).response;
  }
  return null;
}

/**
 * Exported for tests — pure parse+validate over a raw model response string,
 * no network involved. Requires ALL FOUR categories (chat/commit/remix/reply)
 * to individually validate, same all-or-nothing contract the original three
 * categories already had: a fresh refresh either produces a fully-valid pool
 * or `null` (keep the old one) — there's no partial-pool state. This does NOT
 * conflict with `reply` being optional on the `ContentPools` TYPE (see that
 * type's doc comment) — that optionality exists solely so an old value
 * already sitting in storage remains valid to READ, not to relax what a NEW
 * refresh must produce.
 */
export function parseAndValidate(text: string): ContentPools | null {
  const jsonSlice = extractJsonObject(text);
  if (jsonSlice === null) return null;

  let candidate: unknown;
  try {
    candidate = JSON.parse(jsonSlice);
  } catch {
    return null;
  }
  if (!candidate || typeof candidate !== "object") return null;

  const record = candidate as Record<string, unknown>;
  const chat = validateStringArray(record.chat, MAX_CHAT_CHARS);
  const commit = validateStringArray(record.commit, MAX_COMMIT_CHARS);
  const remix = validateStringArray(record.remix, MAX_REMIX_CHARS);
  const reply = validateReplyTemplates(record.reply, MAX_REPLY_CHARS);
  if (!chat || !commit || !remix || !reply) return null;

  return { chat, commit, remix, reply };
}

/**
 * Models routinely wrap JSON in prose or markdown fences despite instructions
 * not to — take the substring from the first `{` to the last `}` rather than
 * requiring the whole response to be bare JSON. Still just a heuristic:
 * `JSON.parse` below is the real validation gate, so a false-positive slice
 * simply fails to parse and this returns `null` upstream.
 */
function extractJsonObject(text: string): string | null {
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start === -1 || end === -1 || end <= start) return null;
  return text.slice(start, end + 1);
}

function validateStringArray(value: unknown, maxChars: number): string[] | null {
  if (!Array.isArray(value) || value.length === 0) return null;
  const cleaned: string[] = [];
  for (const item of value) {
    if (typeof item !== "string") return null;
    const trimmed = item.trim();
    if (trimmed.length === 0 || trimmed.length > maxChars) return null;
    cleaned.push(trimmed);
  }
  return cleaned;
}

const ALLOWED_REPLY_SLOTS_SET = new Set<string>(ALLOWED_REPLY_SLOTS);

/**
 * Same shape/length validation as {@link validateStringArray} PLUS a reply-
 * specific rule: reject any template referencing a `{slot}` token outside
 * {@link ALLOWED_REPLY_SLOTS}. A model that hallucinates, say, `{feature}` or
 * `{filename}` would otherwise either leak a literal unfilled `{feature}`
 * into a live reply, or (worse) tempt a future caller into inventing content
 * to fill it — both violate the empty-tree honesty constraint, so this
 * category fails validation entirely (→ the caller keeps the old pool) the
 * same way an over-length or non-string entry would.
 */
function validateReplyTemplates(value: unknown, maxChars: number): string[] | null {
  const cleaned = validateStringArray(value, maxChars);
  if (!cleaned) return null;
  for (const template of cleaned) {
    if (!templateUsesOnlyAllowedSlots(template)) return null;
  }
  return cleaned;
}

function templateUsesOnlyAllowedSlots(template: string): boolean {
  for (const match of template.matchAll(SLOT_TOKEN_RE)) {
    if (!ALLOWED_REPLY_SLOTS_SET.has(match[1]!)) return false;
  }
  return true;
}

/** First N hex characters used as the "short form" of a hash/pubkey in a filled reply — 8 chars (32 bits), long enough to be visually distinct between two different real events in the same feed, short enough to keep a ~100-char reply line readable. Distinct from `events.ts`'s `forkRefName`, which uses 12 chars for a different purpose (collision-avoidance in a ref NAME, not human readability in a chat line). */
export const REPLY_SHORT_HEX_LEN = 8;

function shortHex(hex: string): string {
  return hex.slice(0, REPLY_SHORT_HEX_LEN);
}

/** The real event facts a reply template may be filled with. `branch` is present only when the push landed on a non-`main` ref — see {@link fillReplyTemplate}'s doc comment. */
export type ReplySlots = {
  hash: string;
  author: string;
  branch?: string;
};

/**
 * Pure, deterministic slot substitution — no I/O, no randomness. Fills
 * `{hash}`/`{author}` with their {@link REPLY_SHORT_HEX_LEN}-char short forms
 * and `{branch}` verbatim (a branch name isn't a hex value to shorten).
 *
 * Returns `null` (never throws) when:
 *   - `template` references a `{slot}` outside {@link ALLOWED_REPLY_SLOTS} —
 *     should already be unreachable for anything that passed
 *     `validateReplyTemplates`/came from {@link REPLY_TEMPLATES}, but this
 *     function re-checks independently since it's a public, pure entry point
 *     that must never emit a literal unfilled `{token}` into a live reply.
 *   - `template` references `{branch}` but `slots.branch` is `undefined` —
 *     this is the caller contract, not an error state: a caller picks a
 *     `{branch}`-carrying template ONLY when the real push was to a ref
 *     other than `main` (i.e. `slots.branch !== undefined`); for a `main`
 *     push it must restrict its template choice to entries without
 *     `{branch}` in the first place. Returning `null` here is a defensive
 *     backstop against a caller that picks the wrong template, not the
 *     expected way branch-less templates get chosen.
 */
export function fillReplyTemplate(template: string, slots: ReplySlots): string | null {
  const tokens = new Set<string>();
  for (const match of template.matchAll(SLOT_TOKEN_RE)) tokens.add(match[1]!);

  for (const token of tokens) {
    if (!ALLOWED_REPLY_SLOTS_SET.has(token)) return null;
  }
  if (tokens.has("branch") && slots.branch === undefined) return null;

  let filled = template.replaceAll("{hash}", shortHex(slots.hash));
  filled = filled.replaceAll("{author}", shortHex(slots.author));
  if (slots.branch !== undefined) filled = filled.replaceAll("{branch}", slots.branch);
  return filled;
}

// ---------------------------------------------------------------------------
// Optional per-event AI personalization (gated by `reply-budget.ts`'s ledger
// in the DO — see #854; this module only provides the generator + its
// validation, never decides WHEN to call it)
// ---------------------------------------------------------------------------

/** The facts a personalized reply may reference — same shape as {@link ReplySlots}, renamed here since a prompt (not a template) consumes it. */
export type PersonalizedReplyEvent = {
  shortHash: string;
  shortAuthor: string;
  branch?: string;
};

/**
 * Ask Workers AI for ONE personalized reply line acknowledging a specific
 * real event. Same never-throw + validate contract as
 * {@link refreshContentPools}: a network/quota error, an unexpected response
 * shape, an empty line, an over-length line, or a line containing a newline
 * (this must stay a single line — a multi-line "reply" would look like a
 * pasted essay, not a chat acknowledgment) all return `null`. Callers (the
 * DO, behind `reply-budget.ts`'s ledger) MUST fall back to
 * {@link fillReplyTemplate} over the template pool on `null`, exactly like
 * `refreshContentPools`'s callers fall back to the last-known-good pool on
 * its `null`.
 *
 * The prompt carries the exact same honesty constraints as the batched
 * refresh's "reply" category: acknowledge the act of signing/pushing/forking
 * plus the caller-supplied short hash/author key/branch, never invent a
 * content claim, never invent a name for the person.
 */
export async function generatePersonalizedReply(ai: Ai, event: PersonalizedReplyEvent): Promise<string | null> {
  let raw: unknown;
  try {
    raw = await ai.run(MODEL, { messages: [{ role: "user", content: buildPersonalizedReplyPrompt(event) }] });
  } catch (err) {
    console.warn("[spammer-worker] ai-content: personalized reply call failed, falling back to template:", err);
    return null;
  }

  const text = extractResponseText(raw);
  if (text === null) {
    console.warn("[spammer-worker] ai-content: unexpected personalized-reply response shape, falling back to template");
    return null;
  }

  return validatePersonalizedReplyText(text);
}

function buildPersonalizedReplyPrompt(event: PersonalizedReplyEvent): string {
  const branchClause = event.branch
    ? ` They pushed to the "${event.branch}" branch (not main) — you may reference the branch name.`
    : ` They pushed to "main".`;
  return `You are replying, in ONE short line (max ${MAX_REPLY_CHARS} characters, no line breaks), to a real person who just signed and pushed a commit in mkit, a live cryptographically-signed, content-addressed version-control demo (like git, but every commit is Ed25519-signed and BLAKE3 content-addressed). Their commit's short hash is "${event.shortHash}" and their short author key is "${event.shortAuthor}".${branchClause}

CRITICAL CONSTRAINT: every commit in this demo has an EMPTY tree — there is NO real file, NO real diff, NO real code change behind it. Never invent a claim about what they changed (no fake file names, no fake feature/bugfix descriptions) — describe only the act of signing/pushing itself, referencing the exact hash/author key above (and the branch name only if given). Never invent a name for them; never echo back any text as if it were theirs.

Respond with ONLY the single reply line — no surrounding quotes, no prose before or after, no markdown.`;
}

/** Pure validation of a personalized-reply response string — split out from {@link generatePersonalizedReply} so it's directly unit-testable without a fake `Ai` object. */
export function validatePersonalizedReplyText(text: string): string | null {
  const trimmed = text.trim();
  if (trimmed.length === 0 || trimmed.length > MAX_REPLY_CHARS) return null;
  if (/[\r\n]/.test(trimmed)) return null;
  return trimmed;
}
