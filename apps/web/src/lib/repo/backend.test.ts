import { describe, expect, it } from 'vitest'
import { parseSourcesJson } from './backend'

describe('parseSourcesJson', () => {
  it('returns [] for a plain commit ("[]" / empty)', () => {
    expect(parseSourcesJson('[]')).toEqual([])
    expect(parseSourcesJson('')).toEqual([])
  })

  it('parses remix source pairs', () => {
    const up = 'aa'.repeat(32)
    const c = 'bb'.repeat(32)
    expect(parseSourcesJson(`[["${up}","${c}"]]`)).toEqual([{ upstreamIdHex: up, commitHashHex: c }])
  })

  it('is tolerant of malformed input', () => {
    expect(parseSourcesJson('not json')).toEqual([])
    expect(parseSourcesJson('{"a":1}')).toEqual([])
    expect(parseSourcesJson('[["only-one"]]')).toEqual([])
  })
})
