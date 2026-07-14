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

import { CHAT_PHRASES, COMMIT_MESSAGE_PHRASES, REMIX_MESSAGE_PHRASES } from "./content";

/** Cheapest Workers AI text model (~50-200 neurons/request) — quality doesn't matter much for short demo phrases, and staying cheap is what keeps a 20-minute refresh cadence sustainable on the free tier. */
const MODEL = "@cf/mistral/mistral-7b-instruct-v0.1";

const MAX_CHAT_CHARS = 100;
const MAX_COMMIT_CHARS = 60;
const MAX_REMIX_CHARS = 80;

const PROMPT = `You generate short, upbeat sample text for a live developer-tools demo chat feed. Respond with ONLY a single JSON object, no prose, no markdown code fences, matching EXACTLY this shape:
{"chat": ["...", ...], "commit": ["...", ...], "remix": ["...", ...]}

Rules:
- "chat": 15 short chat-style lines (max ${MAX_CHAT_CHARS} characters each) about a live, cryptographically-signed, content-addressed collaborative coding demo called mkit. Casual and friendly, no hashtags, no emoji-only lines, no profanity.
- "commit": 10 short git-commit-message-style lines (max ${MAX_COMMIT_CHARS} characters each) for trivial demo commits.
- "remix": 6 short lines (max ${MAX_REMIX_CHARS} characters each) about remixing/forking someone else's commit.
Output strictly valid JSON. No trailing commas. No commentary before or after the JSON.`;

/** The three phrase pools `events.ts`'s emit* functions pick from — either AI-refreshed (this module) or `content.ts`'s static fallback. */
export type ContentPools = {
  chat: readonly string[];
  commit: readonly string[];
  remix: readonly string[];
};

/** `content.ts`'s original static pools, exposed here so callers have one canonical "known good" fallback value without importing `content.ts` themselves. */
export const FALLBACK_POOLS: ContentPools = {
  chat: CHAT_PHRASES,
  commit: COMMIT_MESSAGE_PHRASES,
  remix: REMIX_MESSAGE_PHRASES,
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

/** Exported for tests — pure parse+validate over a raw model response string, no network involved. */
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
  if (!chat || !commit || !remix) return null;

  return { chat, commit, remix };
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
