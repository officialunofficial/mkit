import { mulberry32 } from './grid-svg'

// `source` lets the auto-edit loop pick the right mutator: defaults regenerate via canvas+PPM so a single grid-cell
// edit produces a single localised byte-range change, uploads get random byte flips.
export type FileAsset = { name: string; bytes: Uint8Array; source: 'default' | 'upload' }

const DEFAULT_NAME = 'grid.ppm'

// Build a 512×512 PPM (NetPBM P6) from a deterministic mulberry32 noise grid (256×256 cells × 2 px each), with
// optional hue overrides on specific cells. PPM rather than PNG so a single-cell edit produces a contiguous
// byte-range change (~12 bytes per cell at 2px×2px×3bytes) instead of zlib-cascading the change across the entire
// compressed stream — which is the whole point of demonstrating content-defined chunking. PPM picked over BMP for
// the smaller, format-agnostic header (`P6 width height 255` in ASCII) and natural RGB byte order.
export type CellOverride = { x: number; y: number; hue: number }

// 512×512 raster (256 cells × 2 px) keeps ~12 FastCDC chunks (above the 4-chunk min that makes the strip readable)
// while cutting wasm bandwidth-bound work — chunker, ChunkedBlob, delta, Bao — by 2.25× vs the prior 768-pixel grid.
// Per-tick wasm budget drops below ~70 ms which restores 500 ms cadence with main-thread headroom.
const GRID_CELLS = 256
const GRID_CELL_PX = 2
const GRID_SIZE = GRID_CELLS * GRID_CELL_PX

// Module-scoped cache of the unmutated baseline RGBA grid, keyed by seed. The 65k `fillRect` baseline draw is the
// dominant cost in the per-tick auto-edit loop; once we've computed the base for a given seed, every subsequent drift
// tick just copies this buffer and writes the override pixels directly into the copy. Reset the cache by reloading
// the page (the seed never changes during a session).
const baselineCache = new Map<number, Uint8ClampedArray>()

function buildBaseline(seed: number): Uint8ClampedArray {
  const cached = baselineCache.get(seed)
  if (cached) return cached
  const canvas = document.createElement('canvas')
  canvas.width = GRID_SIZE
  canvas.height = GRID_SIZE
  const ctx = canvas.getContext('2d')
  if (!ctx) throw new Error('canvas 2d unavailable')
  const rand = mulberry32(seed)
  for (let y = 0; y < GRID_CELLS; y++) {
    for (let x = 0; x < GRID_CELLS; x++) {
      const hue = Math.floor(rand() * 360)
      ctx.fillStyle = `hsl(${hue} 70% 60%)`
      ctx.fillRect(x * GRID_CELL_PX, y * GRID_CELL_PX, GRID_CELL_PX, GRID_CELL_PX)
    }
  }
  const data = ctx.getImageData(0, 0, GRID_SIZE, GRID_SIZE).data
  baselineCache.set(seed, data)
  return data
}

// Resolve `hsl(h 70% 60%)` to packed RGBA (4 bytes) once per override so the per-pixel write loop is straight integer
// stores rather than a string parse + canvas state shuffle.
function hueToRgba(hue: number): [number, number, number] {
  // HSL → RGB at S=70%, L=60%. Math straight from the CSS-color spec.
  const s = 0.7
  const l = 0.6
  const c = (1 - Math.abs(2 * l - 1)) * s
  const hp = (((hue % 360) + 360) % 360) / 60
  const x = c * (1 - Math.abs((hp % 2) - 1))
  let r1 = 0
  let g1 = 0
  let b1 = 0
  if (hp < 1) {
    r1 = c
    g1 = x
  } else if (hp < 2) {
    r1 = x
    g1 = c
  } else if (hp < 3) {
    g1 = c
    b1 = x
  } else if (hp < 4) {
    g1 = x
    b1 = c
  } else if (hp < 5) {
    r1 = x
    b1 = c
  } else {
    r1 = c
    b1 = x
  }
  const m = l - c / 2
  return [Math.round((r1 + m) * 255), Math.round((g1 + m) * 255), Math.round((b1 + m) * 255)]
}

export function generateDefaultPpm(seed: number, overrides: CellOverride[]): FileAsset {
  const base = buildBaseline(seed)
  const data = new Uint8ClampedArray(base) // copy so mutations don't pollute the cached baseline
  for (const o of overrides) {
    const [r, g, b] = hueToRgba(o.hue)
    const x0 = o.x * GRID_CELL_PX
    const y0 = o.y * GRID_CELL_PX
    for (let dy = 0; dy < GRID_CELL_PX; dy++) {
      for (let dx = 0; dx < GRID_CELL_PX; dx++) {
        const i = ((y0 + dy) * GRID_SIZE + (x0 + dx)) * 4
        data[i] = r
        data[i + 1] = g
        data[i + 2] = b
        // alpha stays 255 from the canvas baseline
      }
    }
  }
  const bytes = encodePpm(data, GRID_SIZE, GRID_SIZE)
  return { name: DEFAULT_NAME, bytes, source: 'default' }
}

// Push one new override onto the running list and re-render. Cell coordinate is uniformly random across the grid.
export function driftDefaultPpm(seed: number, overrides: CellOverride[]): FileAsset {
  overrides.push({
    x: Math.floor(Math.random() * GRID_CELLS),
    y: Math.floor(Math.random() * GRID_CELLS),
    hue: Math.floor(Math.random() * 360),
  })
  return generateDefaultPpm(seed, overrides)
}

// Flip 1–3 bytes outside any recognised image header. Header preservation keeps a real PNG/JPEG/PPM upload still
// readable as that format if the user opens it elsewhere; the chunker doesn't care either way but the courtesy
// matters when a user drops in their own file.
export function mutateRandomBytes(asset: FileAsset): FileAsset {
  const bytes = new Uint8Array(asset.bytes)
  const headerSkip = detectHeaderSize(bytes)
  const range = bytes.length - headerSkip
  if (range <= 0) return asset
  const flips = 1 + Math.floor(Math.random() * 3)
  for (let i = 0; i < flips; i++) {
    const offset = headerSkip + Math.floor(Math.random() * range)
    // XOR with a non-zero mask so the byte definitely changes.
    bytes[offset] = ((bytes[offset] ?? 0) ^ (1 + Math.floor(Math.random() * 255))) & 0xff
  }
  return { ...asset, bytes }
}

// Walk the three ASCII whitespace-separated tokens after the `P6` magic, returning width/height and the byte offset
// where pixel data starts. Tolerates `#` comments per the spec. Returns null on anything else.
export function decodePpmHeader(bytes: Uint8Array): { width: number; height: number; pixelStart: number } | null {
  if (bytes.length < 11 || bytes[0] !== 0x50 || bytes[1] !== 0x36) return null
  let p = 2
  const readToken = (): string | null => {
    // Skip whitespace and `#`-prefixed comment lines.
    while (p < bytes.length) {
      const b = bytes[p]!
      if (b === 0x20 || b === 0x09 || b === 0x0a || b === 0x0d) {
        p++
        continue
      }
      if (b === 0x23) {
        while (p < bytes.length && bytes[p] !== 0x0a) p++
        continue
      }
      break
    }
    const start = p
    while (p < bytes.length) {
      const b = bytes[p]!
      if (b === 0x20 || b === 0x09 || b === 0x0a || b === 0x0d) break
      p++
    }
    if (p === start) return null
    return new TextDecoder().decode(bytes.subarray(start, p))
  }
  const widthTok = readToken()
  const heightTok = readToken()
  const maxvalTok = readToken()
  if (!widthTok || !heightTok || !maxvalTok) return null
  // Spec: exactly one whitespace char follows maxval before the binary pixel block starts.
  if (p < bytes.length) p++
  const width = Number(widthTok)
  const height = Number(heightTok)
  if (!Number.isFinite(width) || !Number.isFinite(height) || width <= 0 || height <= 0) return null
  if (bytes.length < p + width * height * 3) return null
  return { width, height, pixelStart: p }
}

function detectHeaderSize(bytes: Uint8Array): number {
  if (bytes.length < 8) return 0
  // PNG: 89 50 4E 47 0D 0A 1A 0A
  if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) return 8
  // PPM (P6): "P6\n<width> <height>\n255\n" — three ASCII lines, length varies. Walk until we've passed three
  // newlines so a random byte flip lands strictly in the pixel body.
  if (bytes[0] === 0x50 && bytes[1] === 0x36) {
    let nl = 0
    for (let i = 2; i < Math.min(bytes.length, 64); i++) {
      if (bytes[i] === 0x0a) {
        nl++
        if (nl === 3) return i + 1
      }
    }
    return 0
  }
  // JPEG: FF D8 ... start; conservative skip of first 4 bytes (SOI + first marker)
  if (bytes[0] === 0xff && bytes[1] === 0xd8) return 4
  return 0
}

// Encode RGBA pixels to a NetPBM P6 (binary PPM) blob. Header is three ASCII lines — magic `P6`, dimensions, and
// max-component value 255 — followed by raw RGB triplets in scanline order. No row padding, no endian-flipped bytes,
// no quirks. ~15-byte header for our 512×512 grid.
function encodePpm(rgba: Uint8ClampedArray, width: number, height: number): Uint8Array {
  const headerStr = `P6\n${width} ${height}\n255\n`
  const headerBytes = new TextEncoder().encode(headerStr)
  const pixelBytes = width * height * 3
  const out = new Uint8Array(headerBytes.length + pixelBytes)
  out.set(headerBytes, 0)
  let p = headerBytes.length
  const total = width * height
  for (let i = 0; i < total; i++) {
    const j = i * 4
    out[p++] = rgba[j]!
    out[p++] = rgba[j + 1]!
    out[p++] = rgba[j + 2]!
  }
  return out
}
