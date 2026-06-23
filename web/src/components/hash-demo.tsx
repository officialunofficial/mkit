'use client'

import { useMemo, useRef, useState } from 'react'
import { mulberry32, renderGridSvg } from '../lib/grid-svg'
import { MerkleTree, type MerkleNode } from './merkle-tree'
import { INPUT_CLASSES, ObjectRow, Section } from './result-panel'
import { DEMO_SEED, TEXT_ENCODER, formatBytes, sanitizeTreeName, useMkit } from './use-mkit'

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
  const [message, setMessage] = useState('first commit')
  const [image, setImage] = useState<ImageAsset>(DEFAULT_IMAGE)
  const [tooLarge, setTooLarge] = useState<{ name: string; size: number } | null>(null)
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
        textSize: TEXT_ENCODER.encode(text).byteLength,
        imageHash: imageBlob.hash_hex,
        imageSize: image.bytes.byteLength,
        treeHash: treeObj.hash_hex,
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

  const merkle = useMemo<MerkleNode | null>(() => {
    if ('error' in tree || !commit) return null
    return {
      hash: commit.hash,
      label: 'commit',
      children: [
        {
          hash: tree.treeHash,
          label: '/',
          children: [
            { hash: tree.textHash, label: 'README.md' },
            { hash: tree.imageHash, label: image.name },
          ],
        },
      ],
    }
  }, [tree, commit, image.name])

  if ('error' in tree) return <p className='text-red-600 dark:text-red-400'>{tree.error}</p>
  if (!commit) return null

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
    // Mobile-first ordering: outputs above controls. `flex-col-reverse` reverses sidebar/main below `lg`, then
    // `lg:grid` takes over for the desktop two-column where source order doesn't matter.
    <div className='flex flex-col-reverse gap-10 lg:grid lg:grid-cols-[minmax(0,20rem)_1fr] lg:gap-12'>
      <div className='space-y-6 lg:sticky lg:top-24 lg:self-start'>
        <label className='block'>
          <span className='mb-2 block text-sm text-muted'>Commit message</span>
          <input className={INPUT_CLASSES} value={message} onChange={(e) => setMessage(e.target.value)} />
        </label>

        <label className='block'>
          <span className='mb-2 block text-sm text-muted'>README.md</span>
          <textarea className={INPUT_CLASSES} rows={3} value={text} onChange={(e) => setText(e.target.value)} />
        </label>

        <div>
          <span className='block text-sm text-muted'>Image</span>
          <p className='mb-3 text-xs text-muted'>
            {image.name} · {image.mime || 'application/octet-stream'} · {formatBytes(image.bytes.byteLength)} · demo cap{' '}
            {formatBytes(MAX_IMAGE_BYTES)}
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
                className='inline-flex h-10 shrink-0 items-center justify-center rounded-lg border border-hairline bg-transparent px-3 text-sm font-medium transition-all duration-200 hover:border-fg active:translate-y-px sm:h-9'
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
            {tooLarge ? (
              <p className='rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-700 dark:border-red-900 dark:bg-red-950/40 dark:text-red-400'>
                <span className='font-medium'>{tooLarge.name}</span> is {formatBytes(tooLarge.size)}. This demo previews
                files as data URLs, so it rejects files over {formatBytes(MAX_IMAGE_BYTES)} before reading them. The
                streaming tab handles larger files.
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
      </div>

      <div className='divide-y-2 divide-hairline border-y-2 border-hairline'>
        {merkle ? (
          <Section title='Merkle tree' description='Each square is the BLAKE3 of everything beneath it.'>
            <MerkleTree root={merkle} />
          </Section>
        ) : null}
        <Section title='Objects' description='Every hash in this commit. Edit any input and they all change.'>
          <div className='divide-y divide-hairline'>
            <ObjectRow
              hash={commit.hash}
              label='commit'
              meta='signed'
              trailing={
                <span
                  className={`text-xs ${commit.verified ? 'text-green-700 dark:text-green-400' : 'text-red-600 dark:text-red-400'}`}
                >
                  {commit.verified ? 'verified ✓' : 'invalid ✗'}
                </span>
              }
            />
            <ObjectRow hash={tree.treeHash} label='/' meta='folder' />
            <ObjectRow hash={tree.textHash} label='README.md' meta={formatBytes(tree.textSize)} />
            <ObjectRow hash={tree.imageHash} label={image.name} meta={formatBytes(tree.imageSize)} />
          </div>
        </Section>
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
