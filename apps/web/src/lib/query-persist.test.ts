import { describe, expect, it } from 'vitest'
import { shouldPersistQuery } from './query-persist'

describe('shouldPersistQuery', () => {
  it('persists keys.mkit.sh handle queries', () => {
    expect(shouldPersistQuery(['keys', 'name', 'ab12cd'])).toBe(true)
  })

  it('does NOT persist mutable repo queries (ref / log / refs-list)', () => {
    expect(shouldPersistQuery(['repo', 'lobby', 'ref', 'main'])).toBe(false)
    expect(shouldPersistQuery(['repo', 'lobby', 'log', 'main'])).toBe(false)
    expect(shouldPersistQuery(['repo', 'lobby', 'refs', ''])).toBe(false)
  })

  it('does NOT persist immutable object bytes (binary is unsafe for JSON storage)', () => {
    expect(shouldPersistQuery(['repo', 'lobby', 'object', 'deadbeef'])).toBe(false)
  })

  it('does NOT persist an empty / unknown key', () => {
    expect(shouldPersistQuery([])).toBe(false)
    expect(shouldPersistQuery(['something-else'])).toBe(false)
  })
})
