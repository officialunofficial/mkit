import { describe, expect, it } from 'vitest'
import { bytesToHex, hexToBytes } from './use-mkit'

describe('hexToBytes (canonical hex decoder)', () => {
  it('decodes a plain even-length hex string', () => {
    expect(hexToBytes('00ff10')).toEqual(new Uint8Array([0x00, 0xff, 0x10]))
  })

  it('strips a leading 0x / 0X prefix', () => {
    expect(hexToBytes('0xdeadbeef')).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))
    expect(hexToBytes('0Xdeadbeef')).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))
  })

  it('left-pads an odd-length string with a single 0', () => {
    expect(hexToBytes('f')).toEqual(new Uint8Array([0x0f]))
    expect(hexToBytes('abc')).toEqual(new Uint8Array([0x0a, 0xbc]))
    // 0x prefix + odd remainder still pads the remainder, not the prefix.
    expect(hexToBytes('0xabc')).toEqual(new Uint8Array([0x0a, 0xbc]))
  })

  it('round-trips with bytesToHex for arbitrary bytes', () => {
    const bytes = new Uint8Array([0, 1, 2, 127, 128, 254, 255])
    expect(hexToBytes(bytesToHex(bytes))).toEqual(bytes)
  })

  it('round-trips a 32-byte seed through bytesToHex', () => {
    const seed = new Uint8Array(32)
    for (let i = 0; i < seed.length; i++) seed[i] = (i * 7 + 3) & 0xff
    expect(bytesToHex(hexToBytes(bytesToHex(seed)))).toBe(bytesToHex(seed))
  })
})
