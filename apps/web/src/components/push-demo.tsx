'use client'

import { useCallback, useMemo, useState } from 'react'
import { ChunkStrip, type StripChunk } from './chunk-strip'
import { HashChip } from './result-panel'
import { formatBytes, useMkit } from './use-mkit'

// A demo "file": 2 MiB of varied bytes. mkit only chunks files OVER 1 MiB
// (CHUNK_THRESHOLD in mkit-core), so this is comfortably above that and FastCDC
// v1 cuts it into several content-defined chunks (avg 64 KB). Deterministic so
// the walkthrough reads the same every time; the "edit" flips one byte so
// exactly the chunk covering it changes.
const FILE_SIZE = 2 * 1024 * 1024
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
  { title: 'Your file', next: 'Chunk it' },
  { title: 'mkit chunks it', next: 'Edit it' },
  { title: 'You edit it', next: 'Ship it' },
  { title: 'Ship & settle', next: 'Start over' },
] as const

const BTN = 'rounded-md border border-hairline px-3 py-1.5 text-sm transition-opacity duration-300 hover:opacity-70'

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
  const savedPct = edited.length > 0 ? Math.round((1 - deltaBytes / edited.length) * 100) : 0

  const back = () => setStep((s) => Math.max(0, s - 1))
  const next = () => setStep((s) => (s + 1) % STEPS.length)

  return (
    <div className='space-y-5 rounded-md border border-hairline p-5'>
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

      {/* min-height holds the tallest step (the final comparison) so navigating
          steps doesn't shift the controls below. */}
      <div className='min-h-[11rem]'>
        {/* Keyed on `step` so it remounts on change, replaying the cross-step fade
            (see .step-fade-in in styles.css). */}
        <div key={step} className='step-fade-in space-y-4'>
          {step === 0 ? (
            <>
              {/* Neutral gray: the file is still ONE object, not yet chunked. Colour
                  only appears once it's split into chunks (each chunk is coloured by
                  its hash). Same height as the chunk strip so the next step doesn't jump. */}
              <div className='h-6 w-full rounded-sm border border-hairline bg-muted/25' />
              <p className='max-w-prose text-sm text-muted'>
                A file you want to push, {formatBytes(base.length)}. To start, mkit treats it as one object, named by
                its hash.
              </p>
            </>
          ) : null}

          {step === 1 ? (
            <>
              <ChunkStrip chunks={before.chunks} totalLen={before.bytesLen} ariaLabel='content-defined chunks' />
              <p className='max-w-prose text-sm text-muted'>
                Because it&rsquo;s over 1 MiB, mkit splits it into {before.chunks.length} content-defined chunks
                (FastCDC) and names each by its BLAKE3 hash. Identical chunks — across files or versions — are stored
                only once.
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
              <div className='space-y-1.5'>
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
                <p className='max-w-prose text-sm text-muted'>
                  Drag to flip any byte. Byte <span className='tabular-nums text-fg'>{editByte.toLocaleString()}</span>:{' '}
                  <code className='font-mono text-fg'>0x{hexByte(oldByte)}</code> →{' '}
                  <code className='font-mono text-fg'>0x{hexByte(newByte)}</code>. Only the chunk covering it (outlined)
                  gets a new hash; every other chunk stays byte-identical, so mkit already has it.
                </p>
              </div>
            </>
          ) : null}

          {step === 3 ? (
            <>
              {/* Same file, same scale, what each actually puts on the wire. */}
              <div className='space-y-2'>
                <CompareBar
                  name='git'
                  detail={`${formatBytes(edited.length)} · the whole file`}
                  chunks={after.chunks}
                  totalLen={after.bytesLen}
                  ariaLabel='git resends the whole file'
                />
                <CompareBar
                  name='mkit'
                  detail={`${formatBytes(deltaBytes)} · delta of 1 chunk · ${savedPct}% less`}
                  chunks={after.chunks}
                  totalLen={after.bytesLen}
                  dimSet={dimSet}
                  highlightIndex={changedIdx[0]}
                  ariaLabel='mkit ships only a delta of the changed chunk'
                />
              </div>
              <p className='max-w-prose text-sm text-muted'>
                For a large or binary file — above git&rsquo;s 512 MiB delta threshold (
                <code className='font-mono'>core.bigFileThreshold</code>) or under git-LFS — git resends the whole file.
                mkit dedupes the unchanged chunks and ships only a <span className='text-fg'>delta</span> of the one
                that changed, then folds the chunks into a new Merkle root — the file&rsquo;s new id.
              </p>
              <div className='flex items-center gap-2 font-mono text-xs text-muted'>
                <HashChip hash={after.root} />
                head → {after.root.slice(0, 12)}…
              </div>
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

// One labelled comparison bar: the file at full scale as a chunk strip, with a
// name + size detail above it. git fills the whole bar; mkit dims the deduped
// chunks and highlights only the one that shipped a delta — so the filled area
// reads as "what went over the wire" in the same visual language as the rest.
function CompareBar({
  name,
  detail,
  chunks,
  totalLen,
  dimSet,
  highlightIndex,
  ariaLabel,
}: {
  name: string
  detail: string
  chunks: StripChunk[]
  totalLen: number
  dimSet?: Set<number> | undefined
  highlightIndex?: number | undefined
  ariaLabel: string
}) {
  return (
    <div className='space-y-1'>
      <div className='flex items-baseline justify-between gap-3 text-xs'>
        <span className='font-medium text-fg'>{name}</span>
        <span className='text-muted'>{detail}</span>
      </div>
      <ChunkStrip
        chunks={chunks}
        totalLen={totalLen}
        ariaLabel={ariaLabel}
        dimSet={dimSet}
        highlightIndex={highlightIndex}
      />
    </div>
  )
}
