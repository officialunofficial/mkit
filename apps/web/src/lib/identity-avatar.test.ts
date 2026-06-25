import { describe, expect, it } from 'vitest'
import { IDENTICON_GRID, identicon } from './identity-avatar'

describe('identicon', () => {
  it('is deterministic — same hex maps to the same icon twice', () => {
    const hex = 'a3'.repeat(32)
    expect(identicon(hex)).toEqual(identicon(hex))
  })

  it('returns a 25-cell grid with a 0–360 hue', () => {
    const ic = identicon('a3'.repeat(32))
    expect(ic).not.toBeNull()
    expect(ic?.cells).toHaveLength(IDENTICON_GRID * IDENTICON_GRID)
    expect(ic?.hue).toBeGreaterThanOrEqual(0)
    expect(ic?.hue).toBeLessThanOrEqual(360)
  })

  it('is horizontally symmetric (col c mirrors col 4-c)', () => {
    const ic = identicon('deadbeef'.repeat(8))
    expect(ic).not.toBeNull()
    const g = IDENTICON_GRID
    for (let row = 0; row < g; row++) {
      for (let col = 0; col < g; col++) {
        expect(ic!.cells[row * g + col]).toBe(ic!.cells[row * g + (g - 1 - col)])
      }
    }
  })

  it('two distinct keys produce different icons', () => {
    expect(identicon('00'.repeat(32))).not.toEqual(identicon('ff'.repeat(32)))
    expect(identicon('a3'.repeat(32))).not.toEqual(identicon('b5'.repeat(32)))
  })

  it('tolerates a 0x prefix (same icon as without)', () => {
    expect(identicon(`0x${'a3'.repeat(32)}`)).toEqual(identicon('a3'.repeat(32)))
  })

  it('returns null for empty / invalid / too-short hex', () => {
    expect(identicon('')).toBeNull()
    expect(identicon('abcd')).toBeNull() // 2 bytes, < 8
    expect(identicon('zz'.repeat(8))).toBeNull() // not hex
  })
})
