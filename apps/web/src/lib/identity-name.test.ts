import { describe, expect, it } from 'vitest'
import { ADJECTIVE_COUNT, ANIMAL_COUNT, playerName } from './identity-name'

describe('playerName', () => {
  it('is deterministic — same hex maps to the same name twice', () => {
    const hex = 'deadbeef'.padEnd(64, '0')
    expect(playerName(hex)).toBe(playerName(hex))
  })

  it('renders as lowercase adjective-animal', () => {
    expect(playerName('00'.repeat(32))).toMatch(/^[a-z]+-[a-z]+$/)
    expect(playerName('ff'.repeat(32))).toMatch(/^[a-z]+-[a-z]+$/)
    expect(playerName('a3'.repeat(32))).toMatch(/^[a-z]+-[a-z]+$/)
  })

  it('returns "anonymous" for empty / invalid / too-short hex', () => {
    expect(playerName('')).toBe('anonymous')
    expect(playerName('ab')).toBe('anonymous') // only one byte
    expect(playerName('abcdef')).toBe('anonymous') // three bytes, still < 4
    expect(playerName('zzzzzzzz')).toBe('anonymous') // not hex
  })

  it('tolerates a 0x prefix', () => {
    expect(playerName(`0x${'00'.repeat(32)}`)).toBe(playerName('00'.repeat(32)))
  })

  it('has curated ~64-word lists', () => {
    expect(ADJECTIVE_COUNT).toBe(64)
    expect(ANIMAL_COUNT).toBe(64)
  })

  // Pinned golden vectors — recompute and update ONLY when the wordlists change
  // intentionally; they guard against a silent drift in the byte→index mapping.
  it('matches pinned golden vectors', () => {
    expect(playerName('00'.repeat(32))).toBe('amber-unicorn')
    expect(playerName('ff'.repeat(32))).toBe('lucky-wren')
    expect(playerName('7'.repeat(64))).toBe('wheat-tiger')
    expect(playerName('a3'.repeat(32))).toBe('mint-osprey')
    expect(playerName('b5'.repeat(32))).toBe('turquoise-tapir')
    expect(playerName(`deadbeef${'00'.repeat(28)}`)).toBe('sand-salmon')
  })
})
