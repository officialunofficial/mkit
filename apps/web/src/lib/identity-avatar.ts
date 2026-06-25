// Deterministic identicon avatars for an Ed25519 pubkey (design note §6).
//
// The key IS the identity, so the avatar is derived from it too — no uploads,
// no accounts, no lookup. A 5×5 horizontally-symmetric grid (GitHub-identicon
// style, echoing mkit's grid logo): the hue comes from the first key byte and
// the fill pattern from a fold of the rest, so the same key always renders the
// same mark and the raw hex stays the source of truth. Pure + wasm-free so it
// runs in SSR and is unit-testable.

import { leadingBytes } from './identity-name'

/** Grid is 5×5; the left 3 columns are mirrored to the right 2 for symmetry. */
export const IDENTICON_GRID = 5

export type Identicon = {
  /** 0–360 hue for the filled cells (fixed saturation/lightness in the view). */
  hue: number
  /** 25 booleans, row-major (row*5 + col), horizontally symmetric. */
  cells: boolean[]
}

/**
 * Deterministic identicon for a pubkey hex. Uses the first 8 bytes: byte 0 →
 * hue, bytes 1–7 folded → the 15-bit pattern for the left/centre columns
 * (mirrored). Returns null for empty / invalid / too-short hex (fewer than 8
 * bytes) so the caller can render a neutral placeholder.
 */
export function identicon(pubkeyHex: string): Identicon | null {
  if (!pubkeyHex) return null
  const b = leadingBytes(pubkeyHex, 8)
  if (!b) return null

  const hue = Math.round((b[0]! / 255) * 360)

  // Fold bytes 1..7 into a 32-bit accumulator; take 15 bits for the 15 unique
  // cells (5 rows × 3 columns). `>>> 0` keeps it an unsigned 32-bit int.
  let acc = 0
  for (let i = 1; i < b.length; i++) acc = (acc * 131 + b[i]!) >>> 0

  const cells = Array.from<boolean>({ length: IDENTICON_GRID * IDENTICON_GRID }).fill(false)
  let bit = 0
  for (let row = 0; row < IDENTICON_GRID; row++) {
    for (let col = 0; col < 3; col++) {
      const on = ((acc >>> bit) & 1) === 1
      bit++
      cells[row * IDENTICON_GRID + col] = on
      cells[row * IDENTICON_GRID + (IDENTICON_GRID - 1 - col)] = on
    }
  }
  return { hue, cells }
}
