import { mulberry32 } from './grid-svg'

// `source` records how the bytes were produced — the default grid render, or a user upload.
export type FileAsset = { name: string; bytes: Uint8Array; source: 'default' | 'upload' }

const DEFAULT_NAME = 'grid.ppm'

// Build a 512×512 PPM (NetPBM P6) from a deterministic mulberry32 noise grid (256×256 cells × 2 px each). PPM rather
// than PNG so the byte layout stays a flat, uncompressed grid — the whole point of demonstrating content-defined
// chunking on something format-agnostic. PPM picked over BMP for the smaller, format-agnostic header
// (`P6 width height 255` in ASCII) and natural RGB byte order.

// 512×512 raster (256 cells × 2 px) keeps chunk counts and wasm bandwidth-bound work (chunker, Bao) modest so the
// demo page stays responsive.
const GRID_CELLS = 256
const GRID_CELL_PX = 2
const GRID_SIZE = GRID_CELLS * GRID_CELL_PX

// Render the deterministic grid and encode it as a PPM. Called once per session — the caller (`StreamingDemo`'s
// `generatedRef`) caches the result across the strict-mode double mount, so there's no need for a module-level cache
// here.
export function generateDefaultPpm(seed: number): FileAsset {
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
  const bytes = encodePpm(data, GRID_SIZE, GRID_SIZE)
  return { name: DEFAULT_NAME, bytes, source: 'default' }
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
