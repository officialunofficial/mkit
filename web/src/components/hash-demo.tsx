'use client'

import { useMemo, useRef, useState } from 'react'
import { mulberry32, renderGridSvg } from '../lib/grid-svg'
import { INPUT_CLASSES, Row, Section } from './result-panel'
import { DEMO_SEED, previewBytes, TEXT_ENCODER, sanitizeTreeName, useMkit } from './use-mkit'

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

export function HashDemo() {
  const api = useMkit()
  const [text, setText] = useState('hello, mkit')
  const [message, setMessage] = useState('first commit')
  const [image, setImage] = useState<ImageAsset>(DEFAULT_IMAGE)
  const customised = image !== DEFAULT_IMAGE

  // Data URL for the <img> preview. Object URLs would be cheaper but React strict-mode double-mount revokes them
  // before the image loads, flashing the broken-image icon; data URLs carry no lifecycle.
  const previewUrl = useMemo(() => `data:${image.mime};base64,${bytesToBase64(image.bytes)}`, [image])

  const fileRef = useRef<HTMLInputElement>(null)

  // Split the pipeline so commit-message keystrokes don't re-run `blob_encode`/`tree_encode` on the image payload.
  const tree = useMemo(() => {
    try {
      const textBlob = api.blob_encode(TEXT_ENCODER.encode(text))
      const imageBlob = api.blob_encode(image.bytes)
      const safeImageName = sanitizeTreeName(image.name, 'image')
      const treeObj = api.tree_encode(
        `[["README.md","blob","${textBlob.hash_hex}"],["${safeImageName}","blob","${imageBlob.hash_hex}"]]`,
      )
      return {
        textHash: textBlob.hash_hex,
        textPreview: previewBytes(textBlob.bytes),
        imageHash: imageBlob.hash_hex,
        imageSize: image.bytes.byteLength,
        imagePreview: previewBytes(imageBlob.bytes),
        treeHash: treeObj.hash_hex,
        treePreview: previewBytes(treeObj.bytes),
      }
    } catch (e) {
      return { error: e instanceof Error ? e.message : String(e) }
    }
  }, [api, text, image])

  const commit = useMemo(() => {
    if ('error' in tree) return null
    const c = api.commit_encode_and_sign(tree.treeHash, '', message, 0n, DEMO_SEED)
    return { hash: c.hash_hex, verified: api.commit_verify(c.bytes) }
  }, [api, tree, message])

  if ('error' in tree) return <p className='text-red-600'>{tree.error}</p>
  if (!commit) return null

  const handleFile = async (file: File) => {
    const buf = await file.arrayBuffer()
    setImage({
      name: file.name || 'image',
      mime: file.type || 'application/octet-stream',
      bytes: new Uint8Array(buf),
    })
  }

  const resetImage = () => setImage(DEFAULT_IMAGE)

  return (
    <div className='grid gap-10 lg:grid-cols-[minmax(0,20rem)_1fr] lg:gap-12'>
      <div className='space-y-6 lg:sticky lg:top-24 lg:self-start'>
        <label className='block'>
          <span className='mb-2 block text-sm text-[--color-muted]'>Commit message</span>
          <input className={INPUT_CLASSES} value={message} onChange={(e) => setMessage(e.target.value)} />
        </label>

        <label className='block'>
          <span className='mb-2 block text-sm text-[--color-muted]'>Text blob (README.md)</span>
          <textarea className={INPUT_CLASSES} rows={3} value={text} onChange={(e) => setText(e.target.value)} />
        </label>

        <div>
          <span className='block text-sm text-[--color-muted]'>Image blob</span>
          <p className='mb-3 text-xs text-[--color-muted]'>
            {image.name} · {image.mime || 'application/octet-stream'} · {formatBytes(image.bytes.byteLength)}
          </p>
          <div className='space-y-3'>
            {/* 1px pure-black inset outline per the image-outline design rule — reads as a consistent edge on any
                surface colour. */}
            <div
              className='size-16 shrink-0 overflow-hidden bg-white'
              style={{ boxShadow: 'inset 0 0 0 1px rgba(0,0,0,0.1)' }}
            >
              <img src={previewUrl} alt='' className='size-full object-cover' />
            </div>
            <div className='flex items-center gap-2'>
              <button
                type='button'
                onClick={() => fileRef.current?.click()}
                className='inline-flex h-9 shrink-0 items-center justify-center rounded-lg border border-[--color-hairline] bg-transparent px-3 text-sm font-medium transition-all duration-200 hover:border-[--color-fg] active:translate-y-px'
              >
                Replace image
              </button>
              <button
                type='button'
                onClick={resetImage}
                disabled={!customised}
                className='inline-flex h-9 shrink-0 items-center justify-center rounded-lg px-2 text-sm text-[--color-muted] transition-opacity duration-200 hover:opacity-70 active:translate-y-px disabled:pointer-events-none disabled:opacity-30'
              >
                Reset
              </button>
            </div>
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
      </div>

      <div className='divide-y-2 divide-[--color-hairline] border-y-2 border-[--color-hairline]'>
        <Section title='Commit' description='BLAKE3(mkit.commit\0 || signing bytes) signed with an Ed25519 demo key.'>
          <Row label='Hash (signed)' value={commit.hash} />
          <div className='space-y-1.5 py-1'>
            <div className='text-xs text-[--color-muted]'>Verify under the demo key</div>
            <div className={commit.verified ? 'text-green-700' : 'text-red-600'}>
              {commit.verified ? 'yes ✓' : 'no ✗'}
            </div>
          </div>
        </Section>
        <Section title='Tree' description='A single lex-sorted list wrapping README.md + the image.'>
          <Row label='Hash' value={tree.treeHash} />
          <Row label='Bytes (first 48)' value={tree.treePreview} />
        </Section>
        <Section title='Text blob' description='README.md body bytes, wrapped in a v1 blob object.'>
          <Row label='Hash' value={tree.textHash} />
          <Row label='Bytes (first 48)' value={tree.textPreview} />
        </Section>
        <Section title='Image blob' description='The image file bytes, wrapped in the same v1 blob envelope as text.'>
          <Row label='Hash' value={tree.imageHash} />
          <Row label={`Bytes (first 48 of ${formatBytes(tree.imageSize)})`} value={tree.imagePreview} />
        </Section>
      </div>
    </div>
  )
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(2)} MB`
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
