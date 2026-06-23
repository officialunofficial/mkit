/** Lowercase 64-char hex (a 32-byte BLAKE3 hash or Ed25519 public key). */
export const HEX64 = /^[a-f0-9]{64}$/;

/** Lowercase 128-char hex (a 64-byte Ed25519 signature). */
export const HEX128 = /^[a-f0-9]{128}$/;

const HEX_CHARS = "0123456789abcdef";

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    out += HEX_CHARS[b >> 4] + HEX_CHARS[b & 0x0f];
  }
  return out;
}

/**
 * Strict lowercase-hex decode. Throws on odd length or any non-hex byte
 * (including uppercase) — mkit forbids uppercase hex on the wire
 * (SPEC-REFS §1).
 */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("hex: odd length");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const hi = hexNibble(hex.charCodeAt(i * 2));
    const lo = hexNibble(hex.charCodeAt(i * 2 + 1));
    if (hi < 0 || lo < 0) throw new Error("hex: invalid character");
    out[i] = (hi << 4) | lo;
  }
  return out;
}

function hexNibble(code: number): number {
  if (code >= 48 && code <= 57) return code - 48; // 0-9
  if (code >= 97 && code <= 102) return code - 87; // a-f (lowercase only)
  return -1;
}

/** Normalize an incoming hex header: strip an optional `0x`, lowercase. */
export function normalizeHex(value: string): string {
  const v = value.trim();
  return (v.startsWith("0x") || v.startsWith("0X") ? v.slice(2) : v).toLowerCase();
}
