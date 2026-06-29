'use client'

import { useCallback, useMemo, useState } from 'react'
import { hashMesh } from '../lib/hash-color'
import { PUSH_MESH } from '../lib/mesh'
import { ChunkStrip, type StripChunk } from './chunk-strip'
import { HashChip } from './result-panel'
import { formatBytes, useMkit } from './use-mkit'

// A demo "file": ~384 KB of varied bytes so FastCDC v1 cuts it into several
// content-defined chunks (avg 64 KB). Deterministic so the walkthrough reads
// the same every time; the "edit" XORs one sub-chunk region so exactly the
// chunk covering it changes.
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

function editOneRegion(src: Uint8Array): Uint8Array {
  const out = src.slice()
  const start = Math.floor(out.length * 0.45)
  const end = Math.min(out.length, start + 24 * 1024)
  for (let i = start; i < end; i++) out[i] = (out[i] ?? 0) ^ 0x5a
  return out
}

type Encoded = { wholeId: string; root: string; bytesLen: number; chunks: StripChunk[] }

const STEPS = [
  { title: 'Your file', next: 'Chunk it' },
  { title: 'mkit chunks it', next: 'Edit it' },
  { title: 'You edit it', next: 'Ship it' },
  { title: 'Ship & settle', next: 'Start over' },
] as const

const BTN = 'rounded-md border border-hairline px-3 py-1.5 text-sm transition-opacity duration-300 hover:opacity-70'

export function PushDemo() {
  const api = useMkit()
  const [step, setStep] = useState(0)

  const base = useMemo(() => generateFile(), [])
  const edited = useMemo(() => editOneRegion(base), [base])

  const encode = useCallback(
    (b: Uint8Array): Encoded => {
      const r = api.chunked_blob_encode(b)
      const chunks: StripChunk[] = Array.from({ length: r.chunk_count }, (_, i) => {
        const c = r.chunk(i)!
        return { offset: c.offset, len: c.len, hash_hex: c.hash_hex }
      })
      return { wholeId: api.blob_encode(b).hash_hex, root: r.root_hash_hex, bytesLen: r.bytes_len, chunks }
    },
    [api],
  )
  const before = useMemo(() => encode(base), [encode, base])
  const after = useMemo(() => encode(edited), [encode, edited])

  // The chunks that changed (by hash) — only these ship.
  const beforeHashes = useMemo(() => new Set(before.chunks.map((c) => c.hash_hex)), [before])
  const changedIdx = after.chunks.flatMap((c, i) => (beforeHashes.has(c.hash_hex) ? [] : [i]))
  const dimSet = new Set(after.chunks.flatMap((c, i) => (beforeHashes.has(c.hash_hex) ? [i] : [])))
  const changedBytes = changedIdx.reduce((a, i) => a + (after.chunks[i]?.len ?? 0), 0)
  const savedPct = Math.round((1 - changedBytes / edited.length) * 100)

  const back = () => setStep((s) => Math.max(0, s - 1))
  const next = () => setStep((s) => (s + 1) % STEPS.length)

  return (
    <div
      className='space-y-5 rounded-md border border-hairline p-5'
      style={step === 3 ? { backgroundImage: PUSH_MESH } : undefined}
    >
      <div className='flex items-center justify-between gap-3'>
        <div className='font-mono text-xs text-subtle'>
          {STEPS[step]?.title} · step {step + 1} of {STEPS.length}
        </div>
        <div className='flex gap-1.5'>
          {STEPS.map((s, i) => (
            <span
              key={s.title}
              aria-hidden
              className={`h-1.5 w-1.5 rounded-full ${i <= step ? 'bg-fg' : 'bg-hairline'}`}
            />
          ))}
        </div>
      </div>

      <div className='min-h-[7.5rem] space-y-4'>
        {step === 0 ? (
          <>
            <div
              className='h-8 w-full rounded-sm border border-hairline'
              style={{ backgroundImage: hashMesh(before.wholeId) }}
            />
            <p className='max-w-prose text-sm text-muted'>
              A file you want to push, {formatBytes(base.length)}. To start, mkit treats it as one object, named by its
              hash.
            </p>
          </>
        ) : null}

        {step === 1 ? (
          <>
            <ChunkStrip chunks={before.chunks} totalLen={before.bytesLen} ariaLabel='content-defined chunks' />
            <p className='max-w-prose text-sm text-muted'>
              mkit splits it into {before.chunks.length} content-defined chunks (FastCDC) and names each by its BLAKE3
              hash. Identical chunks, across files or versions, are stored only once.
            </p>
          </>
        ) : null}

        {step === 2 ? (
          <>
            <ChunkStrip
              chunks={after.chunks}
              totalLen={after.bytesLen}
              ariaLabel='content-defined chunks after an edit'
              highlightIndex={changedIdx[0]}
              dimSet={dimSet}
            />
            <p className='max-w-prose text-sm text-muted'>
              You changed a few bytes. Only the chunk covering them gets a new hash (outlined); every other chunk stays
              byte-identical, so mkit already has it.
            </p>
          </>
        ) : null}

        {step === 3 ? (
          <>
            <div className='grid grid-cols-2 gap-3'>
              <Stat label='git resends' value={formatBytes(edited.length)} detail='the whole file' />
              <Stat label='mkit resends' value={formatBytes(changedBytes)} detail={`one chunk · ${savedPct}% less`} />
            </div>
            <p className='max-w-prose text-sm text-muted'>
              Only the changed chunk ships. The chunks fold into a Merkle root, the file&rsquo;s new id, and mkit
              advances the head to it atomically. Read it back: re-deriving the root proves every chunk intact.
            </p>
            <div className='flex items-center gap-2 font-mono text-xs text-muted'>
              <HashChip hash={after.root} />
              head → {after.root.slice(0, 12)}…
            </div>
          </>
        ) : null}
      </div>

      <div className='flex items-center justify-between border-t border-hairline pt-4'>
        <button type='button' onClick={back} disabled={step === 0} className={`${BTN} disabled:opacity-40`}>
          ← back
        </button>
        <button type='button' onClick={next} className={BTN}>
          {STEPS[step]?.next} {step < STEPS.length - 1 ? '→' : '↺'}
        </button>
      </div>
    </div>
  )
}

// A single bytes-on-the-wire figure: label, big value, one-line detail.
function Stat({ label, value, detail }: { label: string; value: string; detail: string }) {
  return (
    <div className='space-y-0.5 rounded-md border border-hairline bg-bg/40 p-3'>
      <div className='text-xs text-muted'>{label}</div>
      <div className='font-mono text-xl font-semibold text-fg'>{value}</div>
      <div className='text-[11px] text-subtle'>{detail}</div>
    </div>
  )
}
