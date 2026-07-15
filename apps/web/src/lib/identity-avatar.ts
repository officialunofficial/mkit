// Deterministic avatars for an Ed25519 pubkey (design note §6).
//
// The key IS the identity, so the avatar is derived from it too — no uploads,
// no accounts, no lookup. A soft MESH GRADIENT: three radial colour blooms at
// key-derived hues + positions over a base tint, so the same key always renders
// the same mark and the raw hex stays the source of truth. Pure + wasm-free so
// it runs in SSR and is unit-testable.

import { leadingBytes } from './identity-name'

/**
 * A deterministic mesh-gradient `background-image` value for a pubkey hex (three radial blooms over a base tint).
 * Returns null for empty / invalid / too-short hex (fewer than 8 bytes) so the caller can render a neutral
 * placeholder.
 */
export function avatarMesh(pubkeyHex: string): string | null {
  const b = leadingBytes(pubkeyHex, 8)
  if (!b) return null

  const hue = (i: number) => Math.round((b[i]! / 255) * 360)
  const pct = (i: number) => Math.round((b[i]! / 255) * 100)
  // Three distinct-but-related hues; positions come from other key bytes.
  const h0 = hue(0)
  const h1 = (hue(1) + 35) % 360
  const h2 = (hue(2) + 200) % 360

  const blooms = [
    `radial-gradient(circle at ${pct(3)}% ${pct(4)}%, hsl(${h0} 85% 66%) 0%, transparent 55%)`,
    `radial-gradient(circle at ${pct(5)}% ${pct(6)}%, hsl(${h1} 80% 60%) 0%, transparent 55%)`,
    `radial-gradient(circle at ${100 - pct(3)}% ${100 - pct(4)}%, hsl(${h2} 78% 56%) 0%, transparent 60%)`,
  ]
  // Base tint fills the corners the blooms don't reach. It MUST be a gradient,
  // not a bare colour — `background-image` rejects a bare `hsl(...)`, which would
  // invalidate the whole declaration. A constant-colour linear-gradient is the
  // valid way to lay down a solid base layer.
  const base = `linear-gradient(hsl(${h0} 55% 50%) 0%, hsl(${h2} 50% 46%) 100%)`
  return `${blooms.join(', ')}, ${base}`
}

/**
 * A deterministic Twitch-style username COLOR for a pubkey hex — same key, same color, no lookup, no accounts. Shares
 * {@link avatarMesh}'s first hue byte, so a player's username color and their avatar's dominant hue always agree (reads
 * as "the same person's color"), while the saturation/lightness are tuned separately for TEXT legibility rather than a
 * background bloom. Returns `{ light, dark }` — this codebase's `dark:` variant keys off an explicit `[data-theme]`
 * attribute (see `styles.css`), not `prefers-color-scheme` or a `.dark` class, so a single CSS `light-dark()` value
 * wouldn't track theme toggles here; callers apply both via Tailwind's `dark:` variant instead (see `PlayerLabel`).
 * `null` for empty / invalid / too-short hex, so the caller can fall back to the default text color.
 */
export function usernameColor(pubkeyHex: string): { light: string; dark: string } | null {
  const b = leadingBytes(pubkeyHex, 1)
  if (!b) return null
  const hue = Math.round((b[0]! / 255) * 360)
  return {
    // Light background: darker/more saturated so text stays readable on white.
    light: `hsl(${hue} 72% 38%)`,
    // Dark background: lighter so it doesn't sink into near-black.
    dark: `hsl(${hue} 85% 72%)`,
  }
}
