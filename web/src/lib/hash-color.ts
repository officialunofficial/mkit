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
