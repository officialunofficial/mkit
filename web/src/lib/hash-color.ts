/**
 * Map a hex hash to a stable HSL colour. Uses the first two bytes (8 bits) as the hue, with fixed saturation +
 * lightness — same palette logic as the gradient favicon. BLAKE3's avalanche property means visually different inputs
 * always produce visually different colours, so a tiny change anywhere in the tree shows up as a hue shift on every
 * ancestor's chip.
 */
export function hashColor(hex: string): string {
  return hueColor(parseInt(hex.slice(0, 2), 16) * (360 / 256))
}

/**
 * Same palette as `hashColor`, keyed by an arbitrary string instead of a hex hash. FNV-1a folds the string to a hue, so
 * the colour is stable per label across builds — used for the /performance bars, where each benchmark id gets its own
 * hue. Full 360 buckets (not 256) so the current benchmark ids stay collision-free.
 */
export function labelColor(label: string): string {
  let h = 0x811c9dc5
  for (let i = 0; i < label.length; i++) {
    h ^= label.charCodeAt(i)
    h = Math.imul(h, 0x01000193) >>> 0
  }
  return hueColor(h % 360)
}

/** The single source of the brand palette projection: any hue, fixed 70% saturation / 60% lightness. */
function hueColor(hue: number): string {
  return `hsl(${Math.round(hue)} 70% 60%)`
}

/**
 * A hash-derived _mesh_ gradient: two hues pulled from different bytes of the hash, layered as soft radial blooms over
 * a linear base. Shares `hashColor`'s avalanche property — a one-byte change reshuffles the whole mesh — but reads with
 * more texture than a flat fill. Used for the file bar on /push.
 */
export function hashMesh(hex: string): string {
  const h1 = Math.round(parseInt(hex.slice(0, 2), 16) * (360 / 256))
  const h2 = Math.round(parseInt(hex.slice(2, 4), 16) * (360 / 256))
  return [
    `radial-gradient(at 18% 28%, hsl(${h1} 80% 64%), transparent 62%)`,
    `radial-gradient(at 82% 72%, hsl(${h2} 80% 58%), transparent 62%)`,
    `linear-gradient(110deg, hsl(${h1} 70% 60%), hsl(${h2} 70% 58%))`,
  ].join(', ')
}
