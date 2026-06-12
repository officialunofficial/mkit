/**
 * Map a hex hash to a stable HSL colour. Uses the first two bytes (8 bits) as the hue, with fixed saturation +
 * lightness — same palette logic as the gradient favicon. BLAKE3's avalanche property means visually different inputs
 * always produce visually different colours, so a tiny change anywhere in the tree shows up as a hue shift on every
 * ancestor's chip.
 */
export function hashColor(hex: string): string {
  const hue = parseInt(hex.slice(0, 2), 16) * (360 / 256)
  return `hsl(${Math.round(hue)} 70% 60%)`
}

/**
 * Same palette as `hashColor`, keyed by an arbitrary string instead of a hex hash. FNV-1a folds the string to a byte of
 * hue, so the colour is stable per label across builds — used for the /performance bars, where each benchmark id gets
 * its own hue.
 */
export function labelColor(label: string): string {
  let h = 0x811c9dc5
  for (let i = 0; i < label.length; i++) {
    h ^= label.charCodeAt(i)
    h = Math.imul(h, 0x01000193) >>> 0
  }
  return `hsl(${Math.round((h % 256) * (360 / 256))} 70% 60%)`
}
