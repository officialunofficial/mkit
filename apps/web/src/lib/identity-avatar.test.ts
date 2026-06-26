import { describe, expect, it } from 'vitest'
import { avatarMesh } from './identity-avatar'

describe('avatarMesh', () => {
  it('is deterministic — same hex maps to the same mesh twice', () => {
    const hex = 'a3'.repeat(32)
    expect(avatarMesh(hex)).toBe(avatarMesh(hex))
  })

  it('produces a layered radial-gradient background string', () => {
    const mesh = avatarMesh('a3'.repeat(32))
    expect(mesh).not.toBeNull()
    // three radial blooms + a base hsl tint
    expect((mesh!.match(/radial-gradient/g) ?? []).length).toBe(3)
    expect(mesh).toMatch(/hsl\(/)
  })

  it('two distinct keys produce different meshes', () => {
    expect(avatarMesh('00'.repeat(32))).not.toBe(avatarMesh('ff'.repeat(32)))
    expect(avatarMesh('a3'.repeat(32))).not.toBe(avatarMesh('b5'.repeat(32)))
  })

  it('tolerates a 0x prefix (same mesh as without)', () => {
    expect(avatarMesh(`0x${'a3'.repeat(32)}`)).toBe(avatarMesh('a3'.repeat(32)))
  })

  it('returns null for empty / invalid / too-short hex', () => {
    expect(avatarMesh('')).toBeNull()
    expect(avatarMesh('abcd')).toBeNull() // 2 bytes, < 8
    expect(avatarMesh('zz'.repeat(8))).toBeNull() // not hex
  })
})
