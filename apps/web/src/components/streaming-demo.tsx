'use client'

import { useEffect, useRef, useState } from 'react'
import { type FileAsset, decodePpmHeader, generateDefaultPpm } from '../lib/ppm'
import { ChunkStrip, type StripChunk } from './chunk-strip'
import { formatBytes, useMkit } from './use-mkit'

// The wasm results expose their chunk lists via an index getter; materialise once into the shape ChunkStrip renders.
function stripChunks(r: {
  chunk_count: number
  chunk(i: number): { offset: number; len: number; hash_hex: string } | undefined
}): StripChunk[] {
  return Array.from({ length: r.chunk_count }, (_, i) => {
    const c = r.chunk(i)!
    return { offset: c.offset, len: c.len, hash_hex: c.hash_hex }
  })
}

// Blit rows [from, to) of `src` (bytes assembled at their file offsets) onto `ctx` at row `from`, converting the PPM's
// packed RGB triples into RGBA.
function paintRows(
  ctx: CanvasRenderingContext2D,
  src: Uint8Array,
  ppm: { width: number; pixelStart: number },
  from: number,
  to: number,
) {
  const { width, pixelStart } = ppm
  const bytesPerRow = width * 3
  const rowSpan = to - from
  const rgba = new Uint8ClampedArray(width * rowSpan * 4)
  let p = pixelStart + from * bytesPerRow
  for (let i = 0; i < width * rowSpan; i++) {
    rgba[i * 4] = src[p++]!
    rgba[i * 4 + 1] = src[p++]!
    rgba[i * 4 + 2] = src[p++]!
    rgba[i * 4 + 3] = 255
  }
  ctx.putImageData(new ImageData(rgba, width, rowSpan), 0, from)
}

const DEFAULT_SEED = 0xc0de_cafe

export function StreamingDemo() {
  const [currentFile, setCurrentFile] = useState<FileAsset | null>(null)
  // React strict-mode mounts twice; cache the generated default bytes so we don't burn the canvas pipeline twice on
  // first paint. Ref survives the remount.
  const generatedRef = useRef<FileAsset | null>(null)

  useEffect(() => {
    if (generatedRef.current) {
      setCurrentFile(generatedRef.current)
      return
    }
    const asset = generateDefaultPpm(DEFAULT_SEED)
    generatedRef.current = asset
    setCurrentFile(asset)
  }, [])

  if (!currentFile) {
    return <p className='text-sm text-muted'>Generating default file…</p>
  }

  return (
    // Mobile-first ordering: live sections above the file sidebar so a phone landing on the streaming demo sees the
    // download running immediately, then scrolls down to the file controls. See `hash-demo.tsx` for the same pattern.
    <div className='flex flex-col-reverse gap-10 lg:grid lg:grid-cols-[minmax(0,20rem)_1fr] lg:gap-12'>
      <div className='space-y-6 lg:sticky lg:top-24 lg:self-start'>
        <FileSidebar current={currentFile} />
      </div>
      <div className='space-y-12'>
        <StreamingVerifiedDownload file={currentFile} />
      </div>
    </div>
  )
}

// --- sidebar -----------------------------------------------------------------

function FileSidebar({ current }: { current: FileAsset }) {
  return (
    <div className='flex items-start gap-3'>
      <FilePreview asset={current} />
      <div className='min-w-0 flex-1'>
        <span className='block text-sm text-muted'>Current file</span>
        <p className='mt-1 text-sm font-medium break-all'>{current.name}</p>
        <p className='text-xs text-muted'>{formatBytes(current.bytes.byteLength)}</p>
      </div>
    </div>
  )
}

// --- verified download ---------------------------------------------

// Everything the stream needs, captured once when the user presses Start. Streaming a snapshot (not the live file)
// keeps playback stable across a fresh Start. `ppm` is non-null in practice — the only file here is the generated
// grid PPM — and gates the progressive canvas paint, but stays nullable: decodePpmHeader still returns null on
// malformed bytes, and the guard is cheap.
type DownloadSnapshot = {
  bytes: Uint8Array
  chunks: StripChunk[]
  rootHex: string
  outboard: Uint8Array
  ppm: { width: number; height: number; pixelStart: number } | null
}

type DownloadState = {
  phase: 'idle' | 'streaming' | 'done'
  cursor: number // next chunk index to fetch
  retryPending: boolean // chunk at `cursor` failed verification last tick; next fetch is the clean retry
  verified: Set<number>
  verifiedBytes: number // payload bytes that passed verification
  wireBytes: number // everything sent: payloads + proofs, including rejected slices
  wastedBytes: number // slices that failed verification and were thrown away
  rejected: number // count of rejected slices
}

// Factory, not a shared constant: DownloadState holds a Set, and a module-level instance would alias the same Set
// into every reset. Every caller gets fresh state.
function freshDownloadState(): DownloadState {
  return {
    phase: 'idle',
    cursor: 0,
    retryPending: false,
    verified: new Set(),
    verifiedBytes: 0,
    wireBytes: 0,
    wastedBytes: 0,
    rejected: 0,
  }
}

// Nominal stream length regardless of chunk count: delay between ticks is clamp(6000 / chunkCount, 100, 600) ms and
// chunks fetched per tick is max(1, ceil(chunkCount / 60)). The floor keeps a much larger file from taking minutes;
// the ceiling keeps the 9-chunk default slow enough to actually watch chunks light up one at a time.
const STREAM_TARGET_MS = 6000

function StreamingVerifiedDownload({ file }: { file: FileAsset }) {
  const api = useMkit()
  const [snapshot, setSnapshot] = useState<DownloadSnapshot | null>(null)
  const [dl, setDl] = useState<DownloadState>(freshDownloadState)
  const [corrupt, setCorrupt] = useState(false)
  const corruptRef = useRef(corrupt) // read by the tick so toggling mid-stream applies to the next fetch
  corruptRef.current = corrupt
  // Verified payload bytes assembled at their file offsets — the paint source. Allocated only for PPM snapshots.
  const assembledRef = useRef<Uint8Array | null>(null)
  const canvasRef = useRef<HTMLCanvasElement>(null)
  // Rows already blitted to the canvas, so a tick only draws the newly-completed span instead of repainting from
  // scratch.
  const paintedRowsRef = useRef(0)
  // React strict-mode mounts twice; without this guard the auto-start effect would fire `start()` twice on first
  // load, discarding the first snapshot. Ref survives the remount, so only the first real mount starts the stream.
  const autoStartedRef = useRef(false)

  // Clear the canvas to the same placeholder fill `FilePreview` uses for undecodable bytes, once per fresh snapshot.
  // Keyed on `snapshot` (a new object every Start), never on `file` — see the tick effect below for why that split
  // matters.
  useEffect(() => {
    if (!snapshot?.ppm) return
    const canvas = canvasRef.current
    const ctx = canvas?.getContext('2d')
    if (!canvas || !ctx) return
    // clearRect first: the placeholder fill is translucent, and on a restart it would otherwise just tint the
    // previous run's image instead of erasing it.
    ctx.clearRect(0, 0, canvas.width, canvas.height)
    ctx.fillStyle = 'rgba(0,0,0,0.04)'
    ctx.fillRect(0, 0, canvas.width, canvas.height)
  }, [snapshot])

  // No effect keyed on `file`. The live file drifting under a running stream is by design — the stream downloads a
  // snapshot taken at Start, and the copy below says so.
  const start = () => {
    const bytes = file.bytes
    const r = api.chunk_boundaries(bytes)
    const chunks = stripChunks(r)
    const enc = api.bao_encode(bytes)
    const ppm = decodePpmHeader(bytes)
    assembledRef.current = ppm ? new Uint8Array(bytes.byteLength) : null
    paintedRowsRef.current = 0
    setSnapshot({ bytes, chunks, rootHex: enc.hash_hex, outboard: enc.outboard, ppm })
    setDl({ ...freshDownloadState(), phase: 'streaming' })
  }

  // Auto-start on mount so the page demos itself on load, without waiting for a click.
  useEffect(() => {
    if (autoStartedRef.current) return
    autoStartedRef.current = true
    start()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const reset = () => {
    setDl(freshDownloadState())
    setSnapshot(null)
    assembledRef.current = null
    paintedRowsRef.current = 0
  }

  // The tick: fetch `perTick` chunks as bao slices and verify each against the root as it lands. Sequential and
  // single-flight by construction — the timeout only re-arms once `setDl` has landed a new `dl`, so there's no
  // stacking even if a tick runs long. Corruption (when armed) hits only the first attempt at a chunk; the retry
  // that follows a rejection always arrives clean, as if from a different mirror.
  useEffect(() => {
    if (dl.phase !== 'streaming' || !snapshot) return
    const delayMs = Math.max(100, Math.min(600, Math.round(STREAM_TARGET_MS / snapshot.chunks.length)))
    const perTick = Math.max(1, Math.ceil(snapshot.chunks.length / 60))
    const t = setTimeout(() => {
      const next: DownloadState = { ...dl, verified: new Set(dl.verified) }
      let verifiedAny = false
      for (let slot = 0; slot < perTick; slot++) {
        if (next.cursor >= snapshot.chunks.length) {
          next.phase = 'done'
          break
        }
        const idx = next.cursor
        const chunk = snapshot.chunks[idx]!
        try {
          const slice = api.bao_slice(snapshot.outboard, snapshot.bytes, chunk.offset, chunk.len)
          next.wireBytes += slice.length
          const isRetry = next.retryPending
          const buf = new Uint8Array(slice)
          // Corrupt fresh fetches only; a retry after a rejection arrives clean, as if from a different mirror.
          if (!isRetry && corruptRef.current) buf[buf.length - 1] = (buf[buf.length - 1] ?? 0) ^ 0x01

          const v = api.bao_verify_slice(snapshot.rootHex, buf, chunk.offset, chunk.len)
          if (v.ok) {
            if (assembledRef.current && v.bytes) assembledRef.current.set(v.bytes, chunk.offset)
            next.verified.add(idx)
            next.verifiedBytes += chunk.len
            next.cursor += 1
            next.retryPending = false
            verifiedAny = true
          } else {
            next.wastedBytes += slice.length
            next.rejected += 1
            next.retryPending = true
            break // the rejection consumes the rest of this tick — a visible stall at the corrupted chunk
          }
        } catch {
          // Slice extraction can only throw on internal errors; treat it like a failed verification rather than
          // letting it kill the stream.
          next.rejected += 1
          next.retryPending = true
          break
        }
      }

      // Verified bytes form a contiguous prefix (the stream is sequential), so paint only the newly-completed rows.
      if (snapshot.ppm && verifiedAny) {
        const ctx = canvasRef.current?.getContext('2d')
        const assembled = assembledRef.current
        if (ctx && assembled) {
          const { width, pixelStart } = snapshot.ppm
          const prefixBytes =
            next.cursor < snapshot.chunks.length ? snapshot.chunks[next.cursor]!.offset : snapshot.bytes.byteLength
          const rowsDone = Math.floor(Math.max(0, prefixBytes - pixelStart) / (width * 3))
          const painted = paintedRowsRef.current
          if (rowsDone > painted) {
            paintRows(ctx, assembled, snapshot.ppm, painted, rowsDone)
            paintedRowsRef.current = rowsDone
          }
        }
      }

      // Stall band on the verified canvas: marks the row where the rejected chunk would have painted. The next
      // tick's clean retry paints starting at `paintedRowsRef.current` (unchanged since this tick, because the
      // rejection broke the loop before advancing it) via the block above, overwriting this band.
      if (snapshot.ppm && next.retryPending) {
        const ctx = canvasRef.current?.getContext('2d')
        if (ctx) {
          ctx.fillStyle = 'rgba(220,38,38,0.85)'
          ctx.fillRect(0, paintedRowsRef.current, snapshot.ppm.width, 2)
        }
      }

      setDl(next)
    }, delayMs)
    return () => clearTimeout(t)
  }, [dl, snapshot, api])

  const total = snapshot?.bytes.byteLength ?? 0
  const proofBytes = dl.wireBytes - dl.wastedBytes - dl.verifiedBytes
  const startLabel =
    dl.phase === 'streaming' ? 'Downloading…' : dl.phase === 'done' ? 'Download again' : 'Start download'

  // Arming the toggle while idle would otherwise be invisible until the next Start — restart so the effect is
  // immediate. corruptRef is written by the render this setCorrupt triggers, and the first tick fires no sooner than
  // `delayMs` (>=100ms) later, so start()'s fresh snapshot is in place well before corruptRef is read.
  const toggleCorrupt = () => {
    const next = !corrupt
    setCorrupt(next)
    if (next && dl.phase !== 'streaming') start()
  }

  return (
    <Section id='bao' title='Verified download (Bao)'>
      {snapshot ? (
        <p className='text-xs text-muted font-mono break-all'>
          Bao root: {snapshot.rootHex.slice(0, 16)}… · outboard {formatBytes(snapshot.outboard.length)} (~6% of the
          file) · streams the file as it was at Start
        </p>
      ) : null}
      {snapshot ? (
        <p className='text-xs text-muted'>
          {snapshot.chunks.length} content-defined chunks (FastCDC) · avg {formatBytes(total / snapshot.chunks.length)}
        </p>
      ) : null}
      {snapshot?.ppm ? (
        <canvas
          ref={canvasRef}
          width={snapshot.ppm.width}
          height={snapshot.ppm.height}
          role='img'
          aria-label='Verified download preview — the image fills in as chunks verify'
          className='size-40 rounded-sm bg-white'
          style={{ boxShadow: 'inset 0 0 0 1px rgba(0,0,0,0.1)' }}
        />
      ) : null}
      {snapshot ? (
        <ChunkStrip
          chunks={snapshot.chunks}
          totalLen={snapshot.bytes.byteLength}
          ariaLabel='Verified download chunks'
          verifiedSet={dl.verified}
          pendingSet={dl.phase === 'streaming' && !dl.retryPending ? new Set([dl.cursor]) : undefined}
          failedSet={dl.retryPending ? new Set([dl.cursor]) : undefined}
        />
      ) : null}
      {dl.retryPending ? (
        <p role='status' className='text-xs text-red-700 dark:text-red-400'>
          Chunk {dl.cursor} arrived corrupted — rejected by the verifier (hash mismatch). Re-fetching…
        </p>
      ) : null}
      {snapshot ? (
        <>
          <CorruptSwitch checked={corrupt} onToggle={toggleCorrupt} />
          <div className='flex flex-wrap items-center gap-3'>
            <button
              type='button'
              onClick={start}
              disabled={dl.phase === 'streaming'}
              className='inline-flex h-10 items-center justify-center rounded-lg border border-hairline px-3 text-sm font-medium transition-colors hover:border-blue-500/50 active:translate-y-px disabled:opacity-40 sm:h-9'
            >
              {startLabel}
            </button>
            <button
              type='button'
              onClick={reset}
              className='inline-flex h-10 items-center justify-center rounded-lg px-3 text-sm text-muted transition-opacity hover:opacity-70 active:translate-y-px sm:h-9'
            >
              Reset
            </button>
          </div>
        </>
      ) : (
        <button
          type='button'
          onClick={start}
          className='inline-flex h-11 items-center justify-center rounded-lg border border-fg bg-fg px-6 text-base font-medium text-bg transition-opacity hover:opacity-90 active:translate-y-px'
        >
          Start download
        </button>
      )}
      {snapshot ? (
        <p className='text-xs text-muted tabular-nums'>
          Verified {formatBytes(dl.verifiedBytes)} of {formatBytes(total)} · {formatBytes(dl.wireBytes)} on the wire ·{' '}
          {formatBytes(proofBytes)} proof · {dl.rejected} rejected ({formatBytes(dl.wastedBytes)} wasted)
        </p>
      ) : null}
      {dl.phase === 'done' ? (
        <p className='text-xs text-muted'>Complete — every byte verified before it was shown.</p>
      ) : null}
    </Section>
  )
}

// --- helpers -----------------------------------------------------------------

function Section({
  id,
  title,
  description,
  children,
}: {
  id: string
  title: string
  description?: string
  children: React.ReactNode
}) {
  return (
    <section id={id} className='space-y-4 scroll-mt-24'>
      <header className='space-y-1'>
        <h2 className='text-sm font-semibold'>{title}</h2>
        {description ? <p className='text-sm text-subtle'>{description}</p> : null}
      </header>
      {children}
    </section>
  )
}

// Minimal accessible switch — no switch component exists elsewhere in the codebase (theme-toggle is a plain button).
// `role='switch'` + `aria-checked` gives it the right semantics; the pill track and sliding thumb are plain divs.
function CorruptSwitch({ checked, onToggle }: { checked: boolean; onToggle: () => void }) {
  return (
    // Track, thumb, and label all live inside the switch button: the visible text is the accessible name, and
    // clicking the label toggles — a bare unnamed pill fails both.
    <button
      type='button'
      role='switch'
      aria-checked={checked}
      onClick={onToggle}
      className='group flex items-center gap-2'
    >
      <span
        className={`inline-flex h-5 w-9 shrink-0 items-center rounded-full p-0.5 transition-colors ${
          checked ? 'bg-red-600' : 'bg-hairline'
        }`}
      >
        <span
          aria-hidden
          className={`size-4 rounded-full bg-white transition-transform ${checked ? 'translate-x-4' : 'translate-x-0'}`}
        />
      </span>
      <span className='text-sm transition-opacity group-hover:opacity-80'>Corrupt the connection</span>
    </button>
  )
}

// 96 px square preview of the current file. The file here is always our generated PPM: parsed and blitted directly
// via putImageData on an offscreen canvas, then downscaled with `drawImage`. Falls back to a hairline placeholder if
// decoding fails.
function FilePreview({ asset }: { asset: FileAsset }) {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const ppm = decodePpmHeader(asset.bytes)
    if (!ppm) {
      ctx.fillStyle = 'rgba(0,0,0,0.04)'
      ctx.fillRect(0, 0, canvas.width, canvas.height)
      ctx.fillStyle = 'rgba(0,0,0,0.3)'
      ctx.font = '10px ui-monospace, monospace'
      ctx.textAlign = 'center'
      ctx.textBaseline = 'middle'
      ctx.fillText('binary', canvas.width / 2, canvas.height / 2)
      return
    }
    const { width, height, pixelStart } = ppm
    const rgba = new Uint8ClampedArray(width * height * 4)
    const src = asset.bytes
    for (let i = 0, p = pixelStart; i < width * height; i++) {
      rgba[i * 4] = src[p++]!
      rgba[i * 4 + 1] = src[p++]!
      rgba[i * 4 + 2] = src[p++]!
      rgba[i * 4 + 3] = 255
    }
    const off = document.createElement('canvas')
    off.width = width
    off.height = height
    off.getContext('2d')?.putImageData(new ImageData(rgba, width, height), 0, 0)
    ctx.imageSmoothingEnabled = true
    ctx.imageSmoothingQuality = 'low'
    ctx.drawImage(off, 0, 0, canvas.width, canvas.height)
  }, [asset])

  return (
    <canvas
      ref={canvasRef}
      width={96}
      height={96}
      className='size-16 shrink-0 rounded-sm bg-white'
      style={{ boxShadow: 'inset 0 0 0 1px rgba(0,0,0,0.1)' }}
    />
  )
}
