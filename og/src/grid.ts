// Vendored from apps/web/src/lib/grid-svg.ts. mkit is not a workspace, so this OG
// worker can't import across the apps/web/ package boundary — the grid renderer is a
// pure ~15-line function, copied here verbatim so the package stays self-contained.

/**
 * Deterministic 32-bit PRNG. Same seed always produces the same sequence — used
 * here so the OG card's brand mark is stable across every render.
 */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Render an N×N grid of coloured squares as an SVG string (caller supplies the RNG). */
export function renderGridSvg(rand: () => number, n = 8, cell = 12): string {
  const total = n * cell;
  let cells = "";
  for (let y = 0; y < n; y++) {
    for (let x = 0; x < n; x++) {
      const hue = Math.floor(rand() * 360);
      cells += `<rect x="${x * cell}" y="${y * cell}" width="${cell}" height="${cell}" fill="hsl(${hue} 70% 60%)"/>`;
    }
  }
  return `<svg width="${total}" height="${total}" viewBox="0 0 ${total} ${total}" xmlns="http://www.w3.org/2000/svg">${cells}</svg>`;
}

// "mkit" as a 32-bit seed (m=0x6d k=0x6b i=0x69 t=0x74) — the same value the web
// app uses for its SSR-safe fallback grid, so og.mkit.sh and mkit.sh share a mark.
export const MKIT_SEED = 0x6d6b6974;
