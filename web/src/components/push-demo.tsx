'use client'

import { useMemo, useState } from 'react'
import { hashColor } from '../lib/hash-color'
import { PUSH_MESH } from '../lib/mesh'
import { ChunkStrip, type StripChunk } from './chunk-strip'
import { HashChip } from './result-panel'
import { formatBytes, useMkit } from './use-mkit'

// A demo "file": ~384 KB of varied bytes so FastCDC v1 cuts it into several
// content-defined chunks (avg 64 KB). Deterministic so the view is stable
// across renders; an edit XORs one sub-chunk region so the chunk covering it
// changes — the point of chunked storage.
const FILE_SIZE = 384 * 1024
const FILE_SEED = 0x6b697421

function makeRng(seed: number): () => number {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

function generateFile(): Uint8Array {
  const rng = makeRng(FILE_SEED)
  const out = new Uint8Array(FILE_SIZE)
  for (let i = 0; i < out.length; i++) out[i] = (rng() * 256) | 0
  return out
}

function editOneRegion(src: Uint8Array, tick: number): Uint8Array {
  const out = src.slice()
  const start = Math.floor(out.length * 0.45)
  const end = Math.min(out.length, start + 24 * 1024)
  const mask = (tick * 37 + 11) & 0xff
  for (let i = start; i < end; i++) out[i] = (out[i] ?? 0) ^ mask
  return out
}

type Chunked = { root: string; bytesLen: number; chunks: StripChunk[] }

const BTN = 'rounded-md border border-hairline px-3 py-1.5 text-sm transition-opacity duration-300 hover:opacity-70'

export function PushDemo() {
  const api = useMkit()
  const [bytes, setBytes] = useState<Uint8Array>(generateFile)
  const [prevBytes, setPrevBytes] = useState<Uint8Array | null>(null)
  const [edits, setEdits] = useState(0)
  const edited = prevBytes !== null

  // Whole-file storage: the file as one object — a single Blob id.
  const wholeId = useMemo(() => api.blob_encode(bytes).hash_hex, [api, bytes])

  // Chunked storage: split, then fold the chunks into a ChunkedBlob BMT root.
  const chunked = useMemo<Chunked>(() => {
    const r = api.chunked_blob_encode(bytes)
    const chunks: StripChunk[] = Array.from({ length: r.chunk_count }, (_, i) => {
      const c = r.chunk(i)!
      return { offset: c.offset, len: c.len, hash_hex: c.hash_hex }
    })
    return { root: r.root_hash_hex, bytesLen: r.bytes_len, chunks }
  }, [api, bytes])
  const prevRoot = useMemo(
    () => (prevBytes ? api.chunked_blob_encode(prevBytes).root_hash_hex : null),
    [api, prevBytes],
  )
  const prevHashes = useMemo<Set<string>>(() => {
    if (!prevBytes) return new Set()
    const r = api.chunked_blob_encode(prevBytes)
    return new Set(Array.from({ length: r.chunk_count }, (_, i) => r.chunk(i)!.hash_hex))
  }, [api, prevBytes])

  // Which chunks changed since the previous push (by hash). Chunked storage
  // ships only these; whole-file storage always re-ships the entire file.
  const changedIdx = edited ? chunked.chunks.flatMap((c, i) => (prevHashes.has(c.hash_hex) ? [] : [i])) : []
  const dimSet = edited ? new Set(chunked.chunks.flatMap((c, i) => (prevHashes.has(c.hash_hex) ? [i] : []))) : undefined
  const changedBytes = changedIdx.reduce((a, i) => a + (chunked.chunks[i]?.len ?? 0), 0)

  const onEdit = () => {
    setPrevBytes(bytes)
    setBytes(editOneRegion(bytes, edits + 1))
    setEdits(edits + 1)
  }
  const onReset = () => {
    setPrevBytes(null)
    setBytes(generateFile())
    setEdits(0)
  }

  return (
    <div className='space-y-6'>
      <div className='flex flex-wrap items-center gap-3'>
        <button type='button' onClick={onEdit} className={BTN}>
          Edit a region
        </button>
        <button type='button' onClick={onReset} className={`${BTN} text-muted`}>
          Reset
        </button>
        <span className='text-sm text-muted'>
          {formatBytes(bytes.length)} · {chunked.chunks.length} chunks{edits > 0 ? ` · edit #${edits}` : ''}
        </span>
      </div>

      <div className='grid gap-4 md:grid-cols-2'>
        {/* Whole-file storage */}
        <div className='space-y-3 rounded-md border border-hairline p-4'>
          <div className='font-mono text-xs uppercase tracking-wide text-subtle'>Store the whole file</div>
          <div
            className='h-6 w-full rounded-sm border border-hairline'
            style={{ backgroundColor: hashColor(wholeId) }}
          />
          <IdLine label='file id' hash={wholeId} />
          <Wire label='pushed on this edit' detail='the whole file, re-hashed' bytes={bytes.length} />
        </div>

        {/* Chunked storage */}
        <div className='space-y-3 rounded-md border border-hairline p-4' style={{ backgroundImage: PUSH_MESH }}>
          <div className='font-mono text-xs uppercase tracking-wide text-subtle'>Chunk and pack</div>
          <ChunkStrip
            chunks={chunked.chunks}
            totalLen={chunked.bytesLen}
            ariaLabel='content-defined chunks'
            highlightIndex={changedIdx[0]}
            dimSet={dimSet}
          />
          <div className='text-center text-xs text-subtle'>↓ fold chunks into a Merkle root ↓</div>
          <IdLine label='BMT root = ChunkedBlob id' hash={chunked.root} />
          <Wire
            label='pushed on this edit'
            detail={
              edited ? `${changedIdx.length} of ${chunked.chunks.length} chunks — a delta` : 'only the missing chunks'
            }
            bytes={edited ? changedBytes : chunked.bytesLen}
          />
        </div>
      </div>

      {/* Settle — advance the head pointer */}
      <div className='space-y-2 rounded-md border border-hairline p-4'>
        <div className='font-mono text-xs uppercase tracking-wide text-subtle'>Settle — advance the head (CAS)</div>
        {edited && prevRoot ? (
          <div className='flex flex-wrap items-center gap-2 font-mono text-xs'>
            <HashChip hash={prevRoot} />
            <code className='text-muted'>{prevRoot.slice(0, 12)}…</code>
            <span aria-hidden className='text-subtle'>
              →
            </span>
            <HashChip hash={chunked.root} />
            <code>{chunked.root.slice(0, 12)}…</code>
            <span className='text-subtle'>advanced atomically — all of it, or none</span>
          </div>
        ) : (
          <div className='flex items-center gap-2 font-mono text-xs text-muted'>
            <HashChip hash={chunked.root} />
            head → {chunked.root.slice(0, 12)}…<span className='text-subtle'>· edit to settle a new root</span>
          </div>
        )}
      </div>
    </div>
  )
}

// One id line: chip, label, truncated hash.
function IdLine({ label, hash }: { label: string; hash: string }) {
  return (
    <div className='flex items-center gap-2 text-xs'>
      <HashChip hash={hash} />
      <span className='text-muted'>{label}</span>
      <code className='font-mono break-all text-fg'>{hash.slice(0, 16)}…</code>
    </div>
  )
}

// Bytes-on-the-wire stat — the whole-file vs chunked punchline.
function Wire({ label, detail, bytes }: { label: string; detail: string; bytes: number }) {
  return (
    <div className='flex items-baseline justify-between gap-3 border-t border-hairline pt-2'>
      <span className='text-xs text-muted'>{label}</span>
      <span className='text-right'>
        <span className='font-mono text-sm font-semibold text-fg'>{formatBytes(bytes)}</span>
        <span className='block text-[11px] text-subtle'>{detail}</span>
      </span>
    </div>
  )
}
