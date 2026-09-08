'use client'

import { useCallback, useMemo, useState } from 'react'
import { ChunkStrip, type StripChunk } from './chunk-strip'
import { formatBytes, useMkit } from './use-mkit'

// Compute chunk and delta sizes from the same deterministic 2 MiB sample.
// The comparison shows payload bytes only; it excludes protocol metadata.
const FILE_SIZE = 2 * 1024 * 1024
const FILE_SEED = 0x6b697421
const FILE_LABEL = '2 MiB'

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

// Flip a SINGLE byte at `at` (XOR 0x5a always changes it). The user drives `at`
// with the slider in the edit step; only the chunk covering it gets a new hash.
function flipByte(src: Uint8Array, at: number): Uint8Array {
  const out = src.slice()
  const i = Math.max(0, Math.min(out.length - 1, at))
  out[i] = (out[i] ?? 0) ^ 0x5a
  return out
}

/** Two-digit uppercase hex for a byte value. */
function hexByte(b: number): string {
  return b.toString(16).padStart(2, '0').toUpperCase()
}

type Encoded = { root: string; bytesLen: number; chunks: StripChunk[] }

const STEPS = [
  { title: 'Start with a large file', next: 'Chunk it' },
  { title: 'Split it into chunks', next: 'Edit a byte' },
  { title: 'Change one byte', next: 'Push it' },
  { title: 'Push only what changed', next: 'Start over' },
] as const

const BTN = 'btn btn--outlined'

export function PushDemo() {
  const api = useMkit()
  const [step, setStep] = useState(0)

  // The byte the user chooses to flip (drag the slider in the edit step).
  const [editByte, setEditByte] = useState(Math.floor(FILE_SIZE * 0.45))

  const base = useMemo(() => generateFile(), [])
  const edited = useMemo(() => flipByte(base, editByte), [base, editByte])
  const oldByte = base[editByte] ?? 0
  const newByte = oldByte ^ 0x5a

  const encode = useCallback(
    (b: Uint8Array): Encoded => {
      const r = api.chunked_blob_encode(b)
      const chunks: StripChunk[] = Array.from({ length: r.chunk_count }, (_, i) => {
        const c = r.chunk(i)!
        return { offset: c.offset, len: c.len, hash_hex: c.hash_hex }
      })
      return { root: r.root_hash_hex, bytesLen: r.bytes_len, chunks }
    },
    [api],
  )
  const before = useMemo(() => encode(base), [encode, base])
  const after = useMemo(() => encode(edited), [encode, edited])

  // The chunks that changed (by hash). Unchanged chunks dedupe — they never ship.
  const beforeHashes = useMemo(() => new Set(before.chunks.map((c) => c.hash_hex)), [before])
  const changedIdx = after.chunks.flatMap((c, i) => (beforeHashes.has(c.hash_hex) ? [] : [i]))
  const dimSet = new Set(after.chunks.flatMap((c, i) => (beforeHashes.has(c.hash_hex) ? [i] : [])))

  // What mkit ACTUALLY puts on the wire for the changed chunk: a delta against
  // the previous version of that chunk (same boundaries for an in-place flip),
  // via the same delta encoder the real push path uses (mkit-core delta.rs).
  // Far smaller than the whole chunk. Falls back to the chunk length if no base.
  const deltaBytes = useMemo(() => {
    const beforeSet = new Set(before.chunks.map((c) => c.hash_hex))
    const ci = after.chunks.findIndex((c) => !beforeSet.has(c.hash_hex))
    if (ci < 0) return 0
    const tgt = after.chunks[ci]!
    const baseC = before.chunks.length === after.chunks.length ? before.chunks[ci] : undefined
    if (!baseC) return tgt.len
    try {
      const summary = api.delta_encode(
        base.slice(baseC.offset, baseC.offset + baseC.len),
        edited.slice(tgt.offset, tgt.offset + tgt.len),
      )
      return summary.bytes_on_wire
    } catch {
      return tgt.len
    }
  }, [api, base, edited, before, after])
  // Compare the encoded delta payload with resending the complete sample.
  const savedPct = 100 - (deltaBytes / FILE_SIZE) * 100
  const savedLabel = savedPct >= 99.99 ? '>99.99% smaller' : `${savedPct.toFixed(1)}% smaller`

  const back = () => setStep((s) => Math.max(0, s - 1))
  const next = () => setStep((s) => (s + 1) % STEPS.length)

  return (
    <div className='space-y-5 rounded-md border border-hairline p-5'>
      <div className='flex items-center justify-between gap-3'>
        <h2 className='ds-h2'>{STEPS[step]?.title}</h2>
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

      {/* min-height holds the tallest step (the final comparison) so navigating
          steps doesn't shift the controls below. */}
      <div className='min-h-[11rem]'>
        <div className='space-y-4'>
          {step === 0 ? (
            <>
              {/* Neutral gray: the file is still ONE object, not yet chunked. Colour
                  only appears once it's split into chunks (each chunk is coloured by
                  its hash). Same height as the chunk strip so the next step doesn't jump. */}
              <div className='h-6 w-full rounded-sm border border-hairline bg-muted/25' />
              <p className='max-w-prose text-sm text-muted'>A {FILE_LABEL} file, named by its hash.</p>
            </>
          ) : null}

          {step === 1 ? (
            <>
              <ChunkStrip chunks={before.chunks} totalLen={before.bytesLen} ariaLabel='content-defined chunks' />
              <p className='max-w-prose text-sm text-muted'>
                mkit splits files over 1 MiB into content-defined chunks (~64 KiB), each named by its hash. Identical
                chunks are stored once.
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
                markerByte={editByte}
              />
              <div className='space-y-2'>
                <input
                  type='range'
                  min={0}
                  max={FILE_SIZE - 1}
                  step={4096}
                  value={editByte}
                  onChange={(e) => setEditByte(Number(e.target.value))}
                  aria-label='Byte to flip'
                  className='w-full accent-fg'
                />
                <p className='font-mono text-sm'>
                  Byte <span className='tabular-nums text-fg'>{editByte.toLocaleString()}</span>:{' '}
                  <span className='text-fg'>0x{hexByte(oldByte)}</span> →{' '}
                  <span className='text-fg'>0x{hexByte(newByte)}</span>
                </p>
                <p className='max-w-prose text-sm text-muted'>
                  Only the chunk containing the changed byte gets a new hash.
                </p>
              </div>
            </>
          ) : null}

          {step === 3 ? (
            <>
              {/* Same scale, what each sends. git = one solid whole-file bar (no
                  chunking); mkit = the chunk strip, deduped to the one changed chunk. */}
              <div className='space-y-2'>
                <CompareBar
                  name='Whole file'
                  detail={`${FILE_LABEL} · whole file`}
                  solid
                  ariaLabel='Resending the whole file'
                />
                <CompareBar
                  name='mkit'
                  detail={`${formatBytes(deltaBytes)} · delta of 1 chunk · ${savedLabel}`}
                  chunks={after.chunks}
                  totalLen={after.bytesLen}
                  dimSet={dimSet}
                  highlightIndex={changedIdx[0]}
                  ariaLabel='mkit sends only a delta of the changed chunk'
                />
              </div>
              <p className='max-w-prose text-sm text-muted'>
                Compare resending the whole file with the delta of the changed chunk.
              </p>
              <p className='max-w-prose text-xs text-subtle'>
                These payload sizes come from the 2 MiB sample above. A complete push also includes object and protocol
                metadata. See the{' '}
                <a href='/performance' className='ds-link'>
                  performance benchmarks
                </a>{' '}
                for measured command timings and transfer sizes.
              </p>
            </>
          ) : null}
        </div>
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

// One labelled comparison bar with a name + size detail above it. `solid` draws
// the complete sample as a filled bar; otherwise it shows the changed chunk.
function CompareBar({
  name,
  detail,
  ariaLabel,
  solid = false,
  chunks,
  totalLen,
  dimSet,
  highlightIndex,
}: {
  name: string
  detail: string
  ariaLabel: string
  solid?: boolean
  chunks?: StripChunk[] | undefined
  totalLen?: number | undefined
  dimSet?: Set<number> | undefined
  highlightIndex?: number | undefined
}) {
  return (
    <div className='space-y-1'>
      <div className='flex items-baseline justify-between gap-3 text-xs'>
        <span className='font-medium text-fg'>{name}</span>
        <span className='text-muted'>{detail}</span>
      </div>
      {solid || !chunks ? (
        <div className='h-6 w-full rounded-sm border border-hairline bg-muted/50' role='img' aria-label={ariaLabel} />
      ) : (
        <ChunkStrip
          chunks={chunks}
          totalLen={totalLen ?? 0}
          ariaLabel={ariaLabel}
          dimSet={dimSet}
          highlightIndex={highlightIndex}
        />
      )}
    </div>
  )
}
