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

/** First `limit` bytes as hex with a trailing ellipsis when truncated. */
export function previewBytes(bytes: Uint8Array, limit = 48): string {
  const hex = bytesToHex(bytes.subarray(0, Math.min(bytes.length, limit)))
  return bytes.length > limit ? `${hex}…` : hex
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
