// Hex <-> bytes helpers.
//
// Copied verbatim from `apps/web/src/components/use-mkit.ts` (`bytesToHex` /
// `hexToBytes`). Relocated here — not re-imported from that file — because
// this Worker has no `components/use-mkit` (that module is `'use client'`
// React and pulls in `../lib/mkit`'s browser wasm-init path, neither of which
// belong in a Worker). The function bodies are unchanged; see that file for
// the full contract docs this mirrors.

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Canonical hex -> bytes decoder, the inverse of {@link bytesToHex}. A
 * leading `0x`/`0X` is stripped; an odd number of hex digits is left-padded
 * with a single `0`; each two-char group is parsed as base-16 (a non-hex
 * group yields `NaN` coerced to `0` by `Uint8Array` assignment — no throw).
 * Round-trips with `bytesToHex` for any even-length, lowercase hex string.
 */
export function hexToBytes(hex: string): Uint8Array {
  const stripped = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  const clean = stripped.length % 2 === 0 ? stripped : `0${stripped}`;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}
