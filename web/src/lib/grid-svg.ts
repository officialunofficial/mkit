/**
 * Deterministic 32-bit PRNG. Same seed always produces the same sequence — used where render output must match across
 * server/client to avoid a hydration mismatch.
 */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

/**
 * Render an N×N grid of coloured squares as an SVG string. Caller passes a RNG — seeded mulberry32 for deterministic
 * output (e.g. SSR-safe default image), `Math.random` for a fresh grid each call (e.g. per-load favicon).
 */
export function renderGridSvg(rand: () => number, n = 8, cell = 12): string {
  const total = n * cell
  let cells = ''
  for (let y = 0; y < n; y++) {
    for (let x = 0; x < n; x++) {
      const hue = Math.floor(rand() * 360)
      cells += `<rect x="${x * cell}" y="${y * cell}" width="${cell}" height="${cell}" fill="hsl(${hue} 70% 60%)"/>`
    }
  }
  return `<svg width="${total}" height="${total}" viewBox="0 0 ${total} ${total}" xmlns="http://www.w3.org/2000/svg">${cells}</svg>`
}
