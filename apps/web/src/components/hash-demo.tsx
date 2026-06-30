'use client'

import { useMemo, useRef, useState } from 'react'
import { mulberry32, renderGridSvg } from '../lib/grid-svg'
import { INPUT_CLASSES, ObjectRow } from './result-panel'
import { TEXT_ENCODER, formatBytes, useMkit } from './use-mkit'

// Fixed seed so the default grid is identical on every render — no hydration mismatch, reliable baseline hash.
const DEFAULT_SVG = renderGridSvg(mulberry32(0xc0de_cafe))

type ImageAsset = {
  name: string
  mime: string
  bytes: Uint8Array
}

// Stable default reference — `resetImage` restores the same identity so `customised` can be a derived `image !==
// DEFAULT_IMAGE` check instead of a tracked state flag.
const DEFAULT_IMAGE: ImageAsset = {
  name: 'grid.svg',
  mime: 'image/svg+xml',
  bytes: TEXT_ENCODER.encode(DEFAULT_SVG),
}

// Demo/browser cap. This demo builds an ArrayBuffer, WASM blob, and base64 data URL for preview, so keep this much
// lower than the streaming demo and reject before allocating the file bytes.
const MAX_IMAGE_BYTES = 8 * 1024 * 1024

export function HashDemo() {
  const api = useMkit()
  const [text, setText] = useState('hello, mkit')
  const [image, setImage] = useState<ImageAsset>(DEFAULT_IMAGE)
  const [tooLarge, setTooLarge] = useState<{ name: string; size: number } | null>(null)
  const customised = image !== DEFAULT_IMAGE

  // Data URL for the <img> preview. Object URLs would be cheaper but React strict-mode double-mount revokes them
  // before the image loads, flashing the broken-image icon; data URLs carry no lifecycle.
  const previewUrl = useMemo(() => `data:${image.mime};base64,${bytesToBase64(image.bytes)}`, [image])

  const fileRef = useRef<HTMLInputElement>(null)

  // The whole demo: bytes → BLAKE3. Encode the text and the image as blobs and
  // read back their content-addressed names — no tree, no commit. Composing
  // many of these into one signed root is the `tree` demo's job; here a hash is
  // simply the name of a single object's bytes.
  const hashes = useMemo(() => {
    try {
      const textBytes = TEXT_ENCODER.encode(text)
      const textBlob = api.blob_encode(textBytes)
      const imageBlob = api.blob_encode(image.bytes)
      return {
        textHash: textBlob.hash_hex,
        textSize: textBytes.byteLength,
        imageHash: imageBlob.hash_hex,
        imageSize: image.bytes.byteLength,
      }
    } catch (e) {
      return { error: e instanceof Error ? e.message : String(e) }
    }
  }, [api, text, image])

  if ('error' in hashes) return <p className='text-red-600 dark:text-red-400'>{hashes.error}</p>

  const handleFile = async (file: File) => {
    const name = file.name || 'image'
    if (file.size > MAX_IMAGE_BYTES) {
      setTooLarge({ name, size: file.size })
      return
    }
    const buf = await file.arrayBuffer()
    setTooLarge(null)
    setImage({
      name,
      mime: file.type || 'application/octet-stream',
      bytes: new Uint8Array(buf),
    })
  }

  const resetImage = () => {
    setTooLarge(null)
    setImage(DEFAULT_IMAGE)
  }

  return (
    // Full-width, one object per block: the file's content-addressed name on top,
    // its editor directly beneath, so editing and the name it produces read as one
    // unit. Edit either and watch the name above it change.
    <div className='space-y-10'>
      {/* README.md — a text object. */}
      <div className='space-y-3'>
        <ObjectRow hash={hashes.textHash} label='README.md' meta={`${formatBytes(hashes.textSize)} · UTF-8 text`} />
        <textarea
          className={INPUT_CLASSES}
          rows={4}
          value={text}
          onChange={(e) => setText(e.target.value)}
          aria-label='README.md contents'
        />
        <p className='text-xs text-muted'>Edit the text — the name above changes.</p>
      </div>

      {/* The image — any bytes get a name, not just text. */}
      <div className='space-y-3'>
        <ObjectRow
          hash={hashes.imageHash}
          label={image.name}
          meta={`${formatBytes(hashes.imageSize)} · ${image.mime || 'application/octet-stream'}`}
        />
        <div className='flex items-center gap-4'>
          {/* 1px pure-black inset outline per the image-outline design rule — reads as a consistent edge on any
              surface colour. */}
          <div
            className='size-16 shrink-0 overflow-hidden bg-white'
            style={{ boxShadow: 'inset 0 0 0 1px rgba(0,0,0,0.1)' }}
          >
            <img src={previewUrl} alt='' className='size-full object-cover' />
          </div>
          <div className='space-y-2'>
            <div className='flex items-center gap-2'>
              <button
                type='button'
                onClick={() => fileRef.current?.click()}
                className='inline-flex h-10 shrink-0 items-center justify-center rounded-lg border border-hairline bg-transparent px-3 text-sm font-medium transition-all duration-200 hover:border-blue-500/50 active:translate-y-px sm:h-9'
              >
                Replace image
              </button>
              <button
                type='button'
                onClick={resetImage}
                disabled={!customised}
                className='inline-flex h-10 shrink-0 items-center justify-center rounded-lg px-2 text-sm text-muted transition-opacity duration-200 hover:opacity-70 active:translate-y-px disabled:pointer-events-none disabled:opacity-30 sm:h-9'
              >
                Reset
              </button>
            </div>
            <p className='text-xs text-muted'>
              Swap the image — the name above changes. Demo cap {formatBytes(MAX_IMAGE_BYTES)}.
            </p>
          </div>
        </div>
        {tooLarge ? (
          <p className='rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-700 dark:border-red-900 dark:bg-red-950/40 dark:text-red-400'>
            <span className='font-medium'>{tooLarge.name}</span> is {formatBytes(tooLarge.size)}. This demo previews
            files as data URLs and rejects anything over {formatBytes(MAX_IMAGE_BYTES)} before reading it. The streaming
            tab handles larger files.
          </p>
        ) : null}
        <input
          ref={fileRef}
          type='file'
          accept='image/*'
          className='hidden'
          onChange={(e) => {
            const f = e.target.files?.[0]
            if (f) void handleFile(f)
            e.target.value = ''
          }}
        />
      </div>
    </div>
  )
}

// Chunked base64 encoding — `btoa(String.fromCharCode(...bytes))` blows
// the call-stack on large files, so we slice into 8 KiB windows and
// concatenate. Works for anything up to browser Blob URL limits.
function bytesToBase64(bytes: Uint8Array): string {
  const CHUNK = 0x2000
  let binary = ''
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK))
  }
  return btoa(binary)
}
