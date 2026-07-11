// The `title` query param reaches this worker straight from an unauthenticated,
// public request — nothing upstream caps its length. Left unbounded, it flows
// directly into Satori's layout + font-shaping pass (via `renderOgImage`) on
// every hit, so an adversarial or accidental huge `title` would pay full
// render cost repeatedly. Sanitize/cap it here, before it reaches the renderer.

/**
 * Generous enough for any real social-card headline (mkit's own titles top out well
 * under this), short enough that a pathological `title` can't blow up render cost.
 */
export const MAX_TITLE_LENGTH = 120;

/**
 * Trim and cap a raw `title` query value, falling back to `fallback` when the
 * input is missing or blank after trimming. Never returns a string longer than
 * {@link MAX_TITLE_LENGTH}.
 */
export function sanitizeTitle(raw: string | null | undefined, fallback: string): string {
  const trimmed = (raw ?? "").trim();
  if (trimmed.length === 0) return fallback;
  return trimmed.slice(0, MAX_TITLE_LENGTH);
}
