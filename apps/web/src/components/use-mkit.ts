'use client'

import { use } from 'react'
import { mkit, type MkitApi } from '../lib/mkit'

/**
 * Read the wasm module synchronously, suspending through `<Suspense>` while it loads and throwing through
 * `<ErrorBoundary>` if init fails. React 19 caches the settled promise, so once resolved every subsequent render is
 * synchronous with zero flash.
 */
export function useMkit(): MkitApi {
  return use(mkit())
}

/** Single demo seed used across every interactive component. */
export const DEMO_SEED = '0101010101010101010101010101010101010101010101010101010101010101'

/** Shared encoder — allocated once. `TextEncoder` is stateless in the browser, safe to reuse. */
export const TEXT_ENCODER = new TextEncoder()

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Canonical hex → bytes decoder, the inverse of {@link bytesToHex}. Contract: - A leading `0x` / `0X` prefix is stripped
 * if present. - An odd number of hex digits is left-padded with a single `0` (so `"f"` decodes as the byte `0x0f`),
 * matching the most lenient existing callers. - Each two-char group is parsed as base-16; a non-hex group yields `NaN`
 * coerced to `0` by `Uint8Array` assignment (the historical behavior — no throw), so callers must pass valid hex.
 * Round-trips with `bytesToHex` for any even-length, lowercase hex string.
 */
export function hexToBytes(hex: string): Uint8Array {
  const stripped = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex
  const clean = stripped.length % 2 === 0 ? stripped : `0${stripped}`
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  return out
}

/** First `limit` bytes as hex with a trailing ellipsis when truncated. */
export function previewBytes(bytes: Uint8Array, limit = 48): string {
  const hex = bytesToHex(bytes.subarray(0, Math.min(bytes.length, limit)))
  return bytes.length > limit ? `${hex}…` : hex
}

/** Human-readable byte count in IEC binary units (B / KiB / MiB / GiB), shared across the interactive demos. */
export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(2)} MiB`
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GiB`
}

/**
 * Normalise a proposed tree-entry name to what `mkit-core::object::TreeEntry::validate_name` accepts: no `/ \ "`, no
 * control chars, printable-ASCII only, ≤255 bytes. The regex deliberately skips `\0` (oxlint no-control-regex) because
 * the printable-ASCII sweep below catches it anyway.
 */
export function sanitizeTreeName(name: string, fallback = 'entry'): string {
  const cleaned = name
    .replace(/["/\\]/g, '_')
    .replace(/[^ -~]/g, '_')
    .slice(0, 255)
    .trim()
  return cleaned || fallback
}
