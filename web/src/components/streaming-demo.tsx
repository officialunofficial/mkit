'use client'

import { useDeferredValue, useEffect, useMemo, useRef, useState } from 'react'
import { mulberry32 } from '../lib/grid-svg'
import { ChunkStrip, type StripChunk } from './chunk-strip'
import { ObjectRow } from './result-panel'
import { useMkit } from './use-mkit'

// `source` lets the auto-edit loop pick the right mutator: defaults regenerate via canvas+PPM so a single grid-cell
// edit produces a single localised byte-range change, uploads get random byte flips.
type FileAsset = { name: string; bytes: Uint8Array; source: 'default' | 'upload' }

const DEFAULT_NAME = 'grid.ppm'
const DEFAULT_SEED = 0xc0de_cafe
// Demo-only hard cap. At 64 KB avg FastCDC chunks, 16 MB → ~256 chunks — still readable on the strip and fast through
// the wasm. Above this we'd freeze the tab building thousands of DOM nodes (and risk OOM in wasm32 well before a
// gigabyte). Real mkit has no such limit; see issue tracker for the un-cap plan.
const MAX_FILE_BYTES = 16 * 1024 * 1024
// Auto-edit cadence. 500 ms is the visible target — the user perceives a continuously changing chunker. The
// `tickRunning` guard naturally throttles to whatever rate the wasm pass actually completes at on the host machine,
// so a slow device falls back to "as fast as possible" instead of stacking ticks.
const AUTO_EDIT_INTERVAL_MS = 500
// Bao re-encode is the heaviest wasm pass in the demo (full outboard tree) — well above the chunker/blob/delta cost.
// Run it on a slower cadence (every Nth tick) so the chunker can stay snappy at 500 ms while the Bao section still
// re-roots often enough to feel live. ~2 s is below the threshold where the user notices a "stale" Bao root.
const BAO_THROTTLE_TICKS = 4

export function StreamingDemo() {
  const [currentFile, setCurrentFile] = useState<FileAsset | null>(null)
  // `baoFile` lags `currentFile` and only updates every `BAO_THROTTLE_TICKS` auto-edit ticks. Lets the heavy
  // bao_encode pass run on a slower cadence than the chunker / ChunkedBlob / delta sections.
  const [baoFile, setBaoFile] = useState<FileAsset | null>(null)
  const [previousFile, setPreviousFile] = useState<FileAsset | null>(null)
  const baoTickRef = useRef(0)
  const [tooLarge, setTooLarge] = useState<{ name: string; size: number } | null>(null)
  const [autoEdit, setAutoEdit] = useState(true)
  // React strict-mode mounts twice; cache the generated default bytes so we don't burn the canvas pipeline twice on
  // first paint. Ref survives the remount.
  const generatedRef = useRef<FileAsset | null>(null)
  // Accumulated cell-hue overrides for the default PPM so each auto-edit tick adds one drifted square on top of the
  // running mutation history, instead of replacing the whole image. Reset whenever the file is replaced.
  const overridesRef = useRef<CellOverride[]>([])
  // Mirror of `currentFile` so the auto-edit interval can read the latest bytes without re-binding on every render.
  const currentFileRef = useRef<FileAsset | null>(null)
  currentFileRef.current = currentFile

  useEffect(() => {
    if (generatedRef.current) {
      setCurrentFile(generatedRef.current)
      return
    }
    const asset = generateDefaultPpm(DEFAULT_SEED, [])
    generatedRef.current = asset
    setCurrentFile(asset)
    setBaoFile(asset)
  }, [])

  // Reject oversized files *before* reading the ArrayBuffer — saves the browser from allocating hundreds of MB just
  // to throw it away. Real mkit has no cap; this is purely to keep the demo page responsive.
  const tryReplaceFile = async (file: File) => {
    const name = file.name || 'file'
    if (file.size > MAX_FILE_BYTES) {
      setTooLarge({ name, size: file.size })
      return
    }
    const buf = await file.arrayBuffer()
    setTooLarge(null)
    setAutoEdit(false)
    overridesRef.current = []
    baoTickRef.current = 0
    const next: FileAsset = { name, bytes: new Uint8Array(buf), source: 'upload' }
    setPreviousFile(currentFile)
    setCurrentFile(next)
    setBaoFile(next)
  }

  // Auto-edit loop: snapshot the current file as the delta baseline once when toggled on, then mutate `currentFile`
  // every tick. Default file → grow `overridesRef` and re-render the PPM (localised byte-range change). Uploaded file
  // → flip 1–3 random bytes outside any image header. The interval reads the latest file via the functional updater
  // so we don't restart it on every state change.
  useEffect(() => {
    if (!autoEdit) return
    setPreviousFile(currentFile)
    let cancelled = false
    let tickRunning = false
    const id = window.setInterval(() => {
      if (cancelled || tickRunning) return
      tickRunning = true
      try {
        const captured = currentFileRef.current
        if (!captured || cancelled) {
          tickRunning = false
          return
        }
        const next: FileAsset =
          captured.source === 'default'
            ? driftDefaultPpm(DEFAULT_SEED, overridesRef.current)
            : mutateRandomBytes(captured)
        if (cancelled) return
        setCurrentFile(next)
        baoTickRef.current = (baoTickRef.current + 1) % BAO_THROTTLE_TICKS
        if (baoTickRef.current === 0) setBaoFile(next)
      } finally {
        tickRunning = false
      }
    }, AUTO_EDIT_INTERVAL_MS)
    return () => {
      cancelled = true
      window.clearInterval(id)
    }
    // We deliberately depend only on autoEdit. The interval reads currentFile via the setter callback so it stays
    // current without restarting on every tick.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoEdit])

  if (!currentFile) {
    return <p className='text-sm text-[--color-muted]'>Generating default file…</p>
  }

  return (
    <div className='grid gap-10 lg:grid-cols-[minmax(0,20rem)_1fr] lg:gap-12'>
      <div className='space-y-6 lg:sticky lg:top-24 lg:self-start'>
        <FileSidebar
          current={currentFile}
          previous={previousFile}
          onReplace={tryReplaceFile}
          rejected={tooLarge}
          autoEdit={autoEdit}
          onToggleAutoEdit={() => setAutoEdit((v) => !v)}
        />
      </div>
      <div className='space-y-12'>
        <StreamingChunker file={currentFile} />
        <StreamingChunkedBlob file={currentFile} />
        <StreamingDelta current={currentFile} previous={previousFile} />
        <StreamingBaoVerify file={baoFile ?? currentFile} />
      </div>
    </div>
  )
}

// --- sidebar -----------------------------------------------------------------

function FileSidebar({
  current,
  previous,
  onReplace,
  rejected,
  autoEdit,
  onToggleAutoEdit,
}: {
  current: FileAsset
  previous: FileAsset | null
  onReplace: (file: File) => void | Promise<void>
  rejected: { name: string; size: number } | null
  autoEdit: boolean
  onToggleAutoEdit: () => void
}) {
  const fileRef = useRef<HTMLInputElement>(null)
  const [dragOver, setDragOver] = useState(false)

  return (
    <div className='space-y-4'>
      <div className='flex items-start gap-3'>
        <FilePreview asset={current} />
        <div className='min-w-0 flex-1'>
          <span className='block text-sm text-[--color-muted]'>Current file</span>
          <p className='mt-1 text-sm font-medium break-all'>{current.name}</p>
          <p className='text-xs text-[--color-muted]'>{formatBytes(current.bytes.byteLength)}</p>
          {previous ? (
            <p className='mt-1 text-xs text-[--color-muted]'>
              (prev: {previous.name}, {formatBytes(previous.bytes.byteLength)})
            </p>
          ) : null}
        </div>
      </div>
      {rejected ? (
        <p className='text-xs text-amber-700'>
          <span className='font-medium'>{rejected.name}</span> is {formatBytes(rejected.size)} — demo cap is{' '}
          {formatBytes(MAX_FILE_BYTES)} to keep the page snappy. Real mkit handles GBs; the cap only applies to this
          interactive page.
        </p>
      ) : null}

      <div
        onDragOver={(e) => {
          e.preventDefault()
          setDragOver(true)
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault()
          setDragOver(false)
          const f = e.dataTransfer.files?.[0]
          if (f) void onReplace(f)
        }}
        className={`rounded-md border border-dashed p-3 text-xs text-[--color-muted] transition-colors ${
          dragOver ? 'border-[--color-fg] text-[--color-fg]' : 'border-[--color-hairline]'
        }`}
      >
        Drop a file here, or
        <button
          type='button'
          onClick={() => fileRef.current?.click()}
          className='ml-1 underline underline-offset-4 transition-opacity hover:opacity-70'
        >
          choose one
        </button>
        .
      </div>
      <input
        ref={fileRef}
        type='file'
        className='hidden'
        onChange={(e) => {
          const f = e.target.files?.[0]
          if (f) void onReplace(f)
          e.target.value = ''
        }}
      />
      <p className='text-xs text-[--color-muted]'>
        Replace the file to see the delta section come alive — the prior version is captured automatically. Demo cap:{' '}
        {formatBytes(MAX_FILE_BYTES)}.
      </p>

      <div className='space-y-2 border-t border-[--color-hairline] pt-4'>
        <button
          type='button'
          onClick={onToggleAutoEdit}
          aria-pressed={autoEdit}
          className={`inline-flex h-9 w-full items-center justify-center gap-2 rounded-lg border px-3 text-sm font-medium transition-all duration-200 active:scale-[0.96] ${
            autoEdit
              ? 'border-[--color-fg] bg-[--color-fg] text-[--color-bg]'
              : 'border-[--color-hairline] hover:border-[--color-fg]'
          }`}
        >
          <span
            aria-hidden
            className={`size-1.5 rounded-full ${autoEdit ? 'animate-pulse bg-[--color-bg]' : 'bg-[--color-muted]'}`}
          />
          {autoEdit ? 'Auto-editing' : 'Auto-edit'}
        </button>
        <p className='text-xs text-[--color-muted]'>
          {current.source === 'default'
            ? 'Drifts one grid cell per tick — watch FastCDC keep most chunks stable while the edited region’s chunk re-hashes.'
            : 'Flips 1–3 random bytes per tick (skipping any image header) so you can see how the chunker reacts to small edits.'}
        </p>
      </div>
    </div>
  )
}

// --- section 1: chunker ------------------------------------------------------

function StreamingChunker({ file }: { file: FileAsset }) {
  const api = useMkit()
  const result = useMemo(() => {
    const r = api.chunk_boundaries(file.bytes)
    const chunks: StripChunk[] = Array.from({ length: r.chunk_count }, (_, i) => {
      const c = r.chunk(i)!
      return { offset: c.offset, len: c.len, hash_hex: c.hash_hex }
    })
    return { chunks, avg: r.avg, min: r.min, max: r.max, count: r.chunk_count }
  }, [api, file])

  const [tamperByte, setTamperByte] = useState(Math.floor(file.bytes.byteLength / 2))
  // Re-anchor when file changes so the slider stays in range.
  useEffect(() => {
    setTamperByte(Math.floor(file.bytes.byteLength / 2))
  }, [file])

  const deferredByte = useDeferredValue(tamperByte)
  const highlightIndex = useMemo(() => {
    return findChunkAtOffset(result.chunks, deferredByte)
  }, [result.chunks, deferredByte])

  return (
    <Section
      id='chunker'
      title='Chunker (FastCDC)'
      description='Content-defined boundaries — chunks shift, but only locally, when bytes change.'
    >
      <p className='text-sm text-[--color-muted]'>
        {result.count} chunks · avg {formatBytes(result.avg)} ({formatBytes(result.min)}–{formatBytes(result.max)})
      </p>
      <ChunkStrip
        chunks={result.chunks}
        totalLen={file.bytes.byteLength}
        ariaLabel='FastCDC chunks'
        highlightIndex={highlightIndex ?? undefined}
        markerByte={deferredByte}
      />
      <div className='space-y-2'>
        <label className='block text-xs text-[--color-muted]'>
          Tamper byte: {tamperByte.toLocaleString()} of {(file.bytes.byteLength - 1).toLocaleString()}
        </label>
        <input
          type='range'
          min={0}
          max={Math.max(0, file.bytes.byteLength - 1)}
          step={1}
          value={tamperByte}
          onChange={(e) => setTamperByte(Number(e.target.value))}
          className='w-full'
          aria-label='Tamper byte offset'
        />
        <p className='text-xs text-[--color-muted]'>
          Edit byte {tamperByte.toLocaleString()} — only chunk {highlightIndex !== null ? highlightIndex : '–'} would
          change. FastCDC's rolling hash keeps the rest stable.
        </p>
      </div>
    </Section>
  )
}

// --- section 2: chunked blob -------------------------------------------------

function StreamingChunkedBlob({ file }: { file: FileAsset }) {
  const api = useMkit()
  const blob = useMemo(() => {
    const r = api.chunked_blob_encode(file.bytes)
    const chunks: StripChunk[] = Array.from({ length: r.chunk_count }, (_, i) => {
      const c = r.chunk(i)!
      return { offset: c.offset, len: c.len, hash_hex: c.hash_hex }
    })
    return { rootHash: r.root_hash_hex, bytesLen: r.bytes_len, count: r.chunk_count, chunks }
  }, [api, file])

  return (
    <Section
      id='chunked-blob'
      title='ChunkedBlob'
      description='Manifest object: the root hash commits to the list of chunk hashes.'
    >
      <div className='divide-y divide-[--color-hairline] border-y border-[--color-hairline]'>
        <ObjectRow hash={blob.rootHash} label='ChunkedBlob root' meta={formatBytes(blob.bytesLen)} />
        {blob.chunks.map((c, i) => (
          <ObjectRow
            key={`${c.offset}-${c.hash_hex}`}
            hash={c.hash_hex}
            label={`chunk ${i.toString().padStart(2, '0')}`}
            meta={`offset ${c.offset.toLocaleString()} · ${formatBytes(c.len)}`}
          />
        ))}
      </div>
    </Section>
  )
}

// --- section 3: delta --------------------------------------------------------

function StreamingDelta({ current, previous }: { current: FileAsset; previous: FileAsset | null }) {
  const api = useMkit()

  const data = useMemo(() => {
    if (!previous) return null
    const prev = api.chunk_boundaries(previous.bytes)
    const curr = api.chunk_boundaries(current.bytes)
    const prevChunks: StripChunk[] = Array.from({ length: prev.chunk_count }, (_, i) => {
      const c = prev.chunk(i)!
      return { offset: c.offset, len: c.len, hash_hex: c.hash_hex }
    })
    const currChunks: StripChunk[] = Array.from({ length: curr.chunk_count }, (_, i) => {
      const c = curr.chunk(i)!
      return { offset: c.offset, len: c.len, hash_hex: c.hash_hex }
    })
    const prevHashes = new Set(prevChunks.map((c) => c.hash_hex))
    const currHashes = new Set(currChunks.map((c) => c.hash_hex))
    const prevDim = new Set<number>()
    prevChunks.forEach((c, i) => {
      if (currHashes.has(c.hash_hex)) prevDim.add(i)
    })
    const currDim = new Set<number>()
    currChunks.forEach((c, i) => {
      if (prevHashes.has(c.hash_hex)) currDim.add(i)
    })
    const summary = api.delta_encode(previous.bytes, current.bytes)
    return {
      prevChunks,
      currChunks,
      prevDim,
      currDim,
      bytesOnWire: summary.bytes_on_wire,
      fullSize: summary.full_size,
    }
  }, [api, previous, current])

  return (
    <Section
      id='delta'
      title='Delta'
      description='Wire format that ships only the new + changed chunks against a known base.'
    >
      {!data ? (
        <p className='text-sm text-[--color-muted]'>Replace the file above to see the delta.</p>
      ) : (
        <>
          <div className='space-y-1'>
            <p className='text-xs text-[--color-muted]'>Previous</p>
            <ChunkStrip
              chunks={data.prevChunks}
              totalLen={previous!.bytes.byteLength}
              ariaLabel='Previous file chunks'
              dimSet={data.prevDim}
            />
          </div>
          <div className='space-y-1'>
            <p className='text-xs text-[--color-muted]'>Current</p>
            <ChunkStrip
              chunks={data.currChunks}
              totalLen={current.bytes.byteLength}
              ariaLabel='Current file chunks'
              dimSet={data.currDim}
            />
          </div>
          <DeltaStat bytesOnWire={data.bytesOnWire} fullSize={data.fullSize} />
        </>
      )}
    </Section>
  )
}

function DeltaStat({ bytesOnWire, fullSize }: { bytesOnWire: number; fullSize: number }) {
  const savings = fullSize > 0 ? (1 - bytesOnWire / fullSize) * 100 : 0
  const positive = savings > 0
  return (
    <div className='rounded-lg border border-[--color-hairline] bg-[--color-hairline]/40 p-4 text-center'>
      {positive ? (
        <>
          <div className='text-3xl font-semibold tabular-nums'>{Math.round(savings)}% saved</div>
          <div className='text-sm text-[--color-muted]'>
            {formatBytes(bytesOnWire)} sent · {formatBytes(fullSize)} for a full re-upload
          </div>
        </>
      ) : (
        <>
          <div className='text-base font-medium'>No shared chunks — full upload wins</div>
          <div className='mt-1 text-sm text-[--color-muted]'>
            Delta is {formatBytes(bytesOnWire)} vs {formatBytes(fullSize)} full. Two files with no overlapping content
            (e.g. unrelated images) ship the whole payload either way. Edit the same file to see savings.
          </div>
        </>
      )}
    </div>
  )
}

// --- section 4: bao verify ---------------------------------------------------

type StreamState = {
  pending: Set<number>
  verified: Set<number>
  failed: Set<number>
  cursor: number
}
const EMPTY_STREAM: StreamState = { pending: new Set(), verified: new Set(), failed: new Set(), cursor: 0 }

function StreamingBaoVerify({ file }: { file: FileAsset }) {
  const api = useMkit()
  const baoData = useMemo(() => {
    const enc = api.bao_encode(file.bytes)
    const r = api.chunk_boundaries(file.bytes)
    const chunks: StripChunk[] = Array.from({ length: r.chunk_count }, (_, i) => {
      const c = r.chunk(i)!
      return { offset: c.offset, len: c.len, hash_hex: c.hash_hex }
    })
    return {
      hashHex: enc.hash_hex,
      outboard: enc.outboard,
      chunks,
      bytesLen: file.bytes.byteLength,
    }
  }, [api, file])

  const [streamState, setStreamState] = useState<StreamState>(EMPTY_STREAM)
  const [tamperedIndex, setTamperedIndex] = useState<number | null>(null)
  const [playing, setPlaying] = useState(false)

  // Reset state when the file changes.
  useEffect(() => {
    setStreamState(EMPTY_STREAM)
    setTamperedIndex(null)
    setPlaying(false)
  }, [file])

  // Stream tick: once playing, advance one chunk every 200 ms. Pull the slice
  // from the outboard, optionally corrupt one byte if we're at the tampered
  // index, then verify.
  useEffect(() => {
    if (!playing) return
    if (streamState.cursor >= baoData.chunks.length) {
      setPlaying(false)
      return
    }
    const idx = streamState.cursor
    const chunk = baoData.chunks[idx]!
    setStreamState((s) => ({
      ...s,
      pending: new Set(s.pending).add(idx),
    }))
    const t = setTimeout(() => {
      try {
        const slice = api.bao_slice(baoData.outboard, file.bytes, chunk.offset, chunk.len)
        const buf = new Uint8Array(slice)
        if (tamperedIndex === idx && buf.length > 0) {
          // Flip the last byte — Bao verifier reads slice format end-to-end so any payload mutation trips it.
          buf[buf.length - 1] = (buf[buf.length - 1] ?? 0) ^ 0x01
        }
        const result = api.bao_verify_slice(baoData.hashHex, buf, chunk.offset, chunk.len)
        setStreamState((s) => {
          const pending = new Set(s.pending)
          pending.delete(idx)
          const verified = new Set(s.verified)
          const failed = new Set(s.failed)
          if (result.ok) verified.add(idx)
          else failed.add(idx)
          return { pending, verified, failed, cursor: s.cursor + 1 }
        })
      } catch {
        setStreamState((s) => {
          const pending = new Set(s.pending)
          pending.delete(idx)
          const failed = new Set(s.failed)
          failed.add(idx)
          return { ...s, pending, failed, cursor: s.cursor + 1 }
        })
      }
    }, 200)
    return () => clearTimeout(t)
  }, [playing, streamState.cursor, baoData, api, file.bytes, tamperedIndex])

  const start = () => {
    setStreamState(EMPTY_STREAM)
    setPlaying(true)
  }
  const reset = () => {
    setPlaying(false)
    setStreamState(EMPTY_STREAM)
  }

  return (
    <Section
      id='bao'
      title='Bao streaming verify'
      description='Each chunk verifies against the root as it lands — no need to wait for the full file.'
    >
      <p className='text-xs text-[--color-muted] font-mono break-all'>
        Bao root: {baoData.hashHex.slice(0, 16)}… · outboard {formatBytes(baoData.outboard.length)} for a{' '}
        {formatBytes(baoData.bytesLen)} file
      </p>
      <ChunkStrip
        chunks={baoData.chunks}
        totalLen={baoData.bytesLen}
        ariaLabel='Bao stream chunks'
        verifiedSet={streamState.verified}
        pendingSet={streamState.pending}
        failedSet={streamState.failed}
        tamperIndex={tamperedIndex ?? undefined}
      />
      <div className='flex flex-wrap items-center gap-3'>
        <button
          type='button'
          onClick={start}
          disabled={playing}
          className='inline-flex h-9 items-center justify-center rounded-lg border border-[--color-hairline] px-3 text-sm font-medium transition-colors hover:border-[--color-fg] active:translate-y-px disabled:opacity-40'
        >
          {playing ? 'Streaming…' : 'Start stream'}
        </button>
        <button
          type='button'
          onClick={reset}
          className='inline-flex h-9 items-center justify-center rounded-lg px-3 text-sm text-[--color-muted] transition-opacity hover:opacity-70 active:translate-y-px'
        >
          Reset
        </button>
        <label className='ml-2 flex items-center gap-2 text-xs text-[--color-muted]'>
          <span>Tamper chunk</span>
          <select
            value={tamperedIndex ?? ''}
            onChange={(e) => setTamperedIndex(e.target.value === '' ? null : Number(e.target.value))}
            className='rounded-md border border-[--color-hairline] bg-transparent px-2 py-1 font-mono text-xs'
          >
            <option value=''>none</option>
            {baoData.chunks.map((_, i) => (
              <option key={i} value={i}>
                {i}
              </option>
            ))}
          </select>
        </label>
        {tamperedIndex !== null ? (
          <span className='rounded-full border border-red-300 bg-red-50 px-2 py-0.5 text-xs text-red-700'>
            Will tamper chunk {tamperedIndex}
          </span>
        ) : null}
      </div>
      <p className='text-xs text-[--color-muted]'>
        Verified {streamState.verified.size} · failed {streamState.failed.size} · {baoData.chunks.length} total
      </p>
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
  description: string
  children: React.ReactNode
}) {
  return (
    <section id={id} className='space-y-4 scroll-mt-24'>
      <header className='space-y-1'>
        <h2 className='text-sm font-medium'>{title}</h2>
        <p className='text-sm text-[--color-subtle]'>{description}</p>
      </header>
      {children}
    </section>
  )
}

function findChunkAtOffset(chunks: StripChunk[], offset: number): number | null {
  for (let i = 0; i < chunks.length; i++) {
    const c = chunks[i]!
    if (offset >= c.offset && offset < c.offset + c.len) return i
  }
  return chunks.length > 0 ? chunks.length - 1 : null
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(2)} MB`
}

// Build a 768×768 PPM (NetPBM P6) from a deterministic mulberry32 noise grid (256×256 cells × 3 px each), with
// optional hue overrides on specific cells. PPM rather than PNG so a single-cell edit produces a contiguous
// byte-range change (~9 bytes per cell at 3px×3px×3bytes) instead of zlib-cascading the change across the entire
// compressed stream — which is the whole point of demonstrating content-defined chunking. PPM picked over BMP for
// the smaller, format-agnostic header (`P6 width height 255` in ASCII) and natural RGB byte order.
type CellOverride = { x: number; y: number; hue: number }

// 512×512 raster (256 cells × 2 px) keeps ~12 FastCDC chunks (above the 4-chunk min that makes the strip readable)
// while cutting wasm bandwidth-bound work — chunker, ChunkedBlob, delta, Bao — by 2.25× vs the prior 768-pixel grid.
// Per-tick wasm budget drops below ~70 ms which restores 500 ms cadence with main-thread headroom.
const GRID_CELLS = 256
const GRID_CELL_PX = 2
const GRID_SIZE = GRID_CELLS * GRID_CELL_PX

// Module-scoped cache of the unmutated baseline RGBA grid, keyed by seed. The 65k `fillRect` baseline draw is the
// dominant cost in the per-tick auto-edit loop; once we've computed the base for a given seed, every subsequent drift
// tick just copies this buffer and writes the override pixels directly into the copy. Reset the cache by reloading
// the page (the seed never changes during a session).
const baselineCache = new Map<number, Uint8ClampedArray>()

function buildBaseline(seed: number): Uint8ClampedArray {
  const cached = baselineCache.get(seed)
  if (cached) return cached
  const canvas = document.createElement('canvas')
  canvas.width = GRID_SIZE
  canvas.height = GRID_SIZE
  const ctx = canvas.getContext('2d')
  if (!ctx) throw new Error('canvas 2d unavailable')
  const rand = mulberry32(seed)
  for (let y = 0; y < GRID_CELLS; y++) {
    for (let x = 0; x < GRID_CELLS; x++) {
      const hue = Math.floor(rand() * 360)
      ctx.fillStyle = `hsl(${hue} 70% 60%)`
      ctx.fillRect(x * GRID_CELL_PX, y * GRID_CELL_PX, GRID_CELL_PX, GRID_CELL_PX)
    }
  }
  const data = ctx.getImageData(0, 0, GRID_SIZE, GRID_SIZE).data
  baselineCache.set(seed, data)
  return data
}

// Resolve `hsl(h 70% 60%)` to packed RGBA (4 bytes) once per override so the per-pixel write loop is straight integer
// stores rather than a string parse + canvas state shuffle.
function hueToRgba(hue: number): [number, number, number] {
  // HSL → RGB at S=70%, L=60%. Math straight from the CSS-color spec.
  const s = 0.7
  const l = 0.6
  const c = (1 - Math.abs(2 * l - 1)) * s
  const hp = (((hue % 360) + 360) % 360) / 60
  const x = c * (1 - Math.abs((hp % 2) - 1))
  let r1 = 0
  let g1 = 0
  let b1 = 0
  if (hp < 1) {
    r1 = c
    g1 = x
  } else if (hp < 2) {
    r1 = x
    g1 = c
  } else if (hp < 3) {
    g1 = c
    b1 = x
  } else if (hp < 4) {
    g1 = x
    b1 = c
  } else if (hp < 5) {
    r1 = x
    b1 = c
  } else {
    r1 = c
    b1 = x
  }
  const m = l - c / 2
  return [Math.round((r1 + m) * 255), Math.round((g1 + m) * 255), Math.round((b1 + m) * 255)]
}

function generateDefaultPpm(seed: number, overrides: CellOverride[]): FileAsset {
  const base = buildBaseline(seed)
  const data = new Uint8ClampedArray(base) // copy so mutations don't pollute the cached baseline
  for (const o of overrides) {
    const [r, g, b] = hueToRgba(o.hue)
    const x0 = o.x * GRID_CELL_PX
    const y0 = o.y * GRID_CELL_PX
    for (let dy = 0; dy < GRID_CELL_PX; dy++) {
      for (let dx = 0; dx < GRID_CELL_PX; dx++) {
        const i = ((y0 + dy) * GRID_SIZE + (x0 + dx)) * 4
        data[i] = r
        data[i + 1] = g
        data[i + 2] = b
        // alpha stays 255 from the canvas baseline
      }
    }
  }
  const bytes = encodePpm(data, GRID_SIZE, GRID_SIZE)
  return { name: DEFAULT_NAME, bytes, source: 'default' }
}

// Push one new override onto the running list and re-render. Cell coordinate is uniformly random across the grid.
function driftDefaultPpm(seed: number, overrides: CellOverride[]): FileAsset {
  overrides.push({
    x: Math.floor(Math.random() * GRID_CELLS),
    y: Math.floor(Math.random() * GRID_CELLS),
    hue: Math.floor(Math.random() * 360),
  })
  return generateDefaultPpm(seed, overrides)
}

// Flip 1–3 bytes outside any recognised image header. Header preservation keeps a real PNG/JPEG/PPM upload still
// readable as that format if the user opens it elsewhere; the chunker doesn't care either way but the courtesy
// matters when a user drops in their own file.
function mutateRandomBytes(asset: FileAsset): FileAsset {
  const bytes = new Uint8Array(asset.bytes)
  const headerSkip = detectHeaderSize(bytes)
  const range = bytes.length - headerSkip
  if (range <= 0) return asset
  const flips = 1 + Math.floor(Math.random() * 3)
  for (let i = 0; i < flips; i++) {
    const offset = headerSkip + Math.floor(Math.random() * range)
    // XOR with a non-zero mask so the byte definitely changes.
    bytes[offset] = ((bytes[offset] ?? 0) ^ (1 + Math.floor(Math.random() * 255))) & 0xff
  }
  return { ...asset, bytes }
}

// 96 px square preview of the current file. PPM is parsed and blitted directly via putImageData on an offscreen
// canvas, then downscaled with `drawImage`; everything else is rendered through a Blob URL `<img>` decode. Both paths
// fall back to a hairline placeholder if decoding fails (e.g. non-image upload). Small enough to redraw on every
// auto-edit tick without breaking the budget.
function FilePreview({ asset }: { asset: FileAsset }) {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return
    let cancelled = false

    const drawPlaceholder = () => {
      ctx.fillStyle = 'rgba(0,0,0,0.04)'
      ctx.fillRect(0, 0, canvas.width, canvas.height)
      ctx.fillStyle = 'rgba(0,0,0,0.3)'
      ctx.font = '10px ui-monospace, monospace'
      ctx.textAlign = 'center'
      ctx.textBaseline = 'middle'
      ctx.fillText('binary', canvas.width / 2, canvas.height / 2)
    }

    const ppm = decodePpmHeader(asset.bytes)
    if (ppm) {
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
      return
    }

    // Decode anything <Image> can handle — PNG, JPEG, GIF, WebP, BMP. Copy into a fresh ArrayBuffer-backed view so
    // the Blob constructor's BlobPart type (which rejects Uint8Array<SharedArrayBuffer>) is satisfied.
    const owned = new Uint8Array(asset.bytes.byteLength)
    owned.set(asset.bytes)
    const blob = new Blob([owned.buffer])
    const url = URL.createObjectURL(blob)
    const img = new Image()
    img.onload = () => {
      if (cancelled) return
      ctx.clearRect(0, 0, canvas.width, canvas.height)
      ctx.imageSmoothingEnabled = true
      ctx.imageSmoothingQuality = 'low'
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height)
      URL.revokeObjectURL(url)
    }
    img.onerror = () => {
      if (!cancelled) drawPlaceholder()
      URL.revokeObjectURL(url)
    }
    img.src = url

    return () => {
      cancelled = true
      URL.revokeObjectURL(url)
    }
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

// Walk the three ASCII whitespace-separated tokens after the `P6` magic, returning width/height and the byte offset
// where pixel data starts. Tolerates `#` comments per the spec. Returns null on anything else.
function decodePpmHeader(bytes: Uint8Array): { width: number; height: number; pixelStart: number } | null {
  if (bytes.length < 11 || bytes[0] !== 0x50 || bytes[1] !== 0x36) return null
  let p = 2
  const readToken = (): string | null => {
    // Skip whitespace and `#`-prefixed comment lines.
    while (p < bytes.length) {
      const b = bytes[p]!
      if (b === 0x20 || b === 0x09 || b === 0x0a || b === 0x0d) {
        p++
        continue
      }
      if (b === 0x23) {
        while (p < bytes.length && bytes[p] !== 0x0a) p++
        continue
      }
      break
    }
    const start = p
    while (p < bytes.length) {
      const b = bytes[p]!
      if (b === 0x20 || b === 0x09 || b === 0x0a || b === 0x0d) break
      p++
    }
    if (p === start) return null
    return new TextDecoder().decode(bytes.subarray(start, p))
  }
  const widthTok = readToken()
  const heightTok = readToken()
  const maxvalTok = readToken()
  if (!widthTok || !heightTok || !maxvalTok) return null
  // Spec: exactly one whitespace char follows maxval before the binary pixel block starts.
  if (p < bytes.length) p++
  const width = Number(widthTok)
  const height = Number(heightTok)
  if (!Number.isFinite(width) || !Number.isFinite(height) || width <= 0 || height <= 0) return null
  if (bytes.length < p + width * height * 3) return null
  return { width, height, pixelStart: p }
}

function detectHeaderSize(bytes: Uint8Array): number {
  if (bytes.length < 8) return 0
  // PNG: 89 50 4E 47 0D 0A 1A 0A
  if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) return 8
  // PPM (P6): "P6\n<width> <height>\n255\n" — three ASCII lines, length varies. Walk until we've passed three
  // newlines so a random byte flip lands strictly in the pixel body.
  if (bytes[0] === 0x50 && bytes[1] === 0x36) {
    let nl = 0
    for (let i = 2; i < Math.min(bytes.length, 64); i++) {
      if (bytes[i] === 0x0a) {
        nl++
        if (nl === 3) return i + 1
      }
    }
    return 0
  }
  // JPEG: FF D8 ... start; conservative skip of first 4 bytes (SOI + first marker)
  if (bytes[0] === 0xff && bytes[1] === 0xd8) return 4
  return 0
}

// Encode RGBA pixels to a NetPBM P6 (binary PPM) blob. Header is three ASCII lines — magic `P6`, dimensions, and
// max-component value 255 — followed by raw RGB triplets in scanline order. No row padding, no endian-flipped bytes,
// no quirks. ~16-byte header for our 768×768 grid.
function encodePpm(rgba: Uint8ClampedArray, width: number, height: number): Uint8Array {
  const headerStr = `P6\n${width} ${height}\n255\n`
  const headerBytes = new TextEncoder().encode(headerStr)
  const pixelBytes = width * height * 3
  const out = new Uint8Array(headerBytes.length + pixelBytes)
  out.set(headerBytes, 0)
  let p = headerBytes.length
  const total = width * height
  for (let i = 0; i < total; i++) {
    const j = i * 4
    out[p++] = rgba[j]!
    out[p++] = rgba[j + 1]!
    out[p++] = rgba[j + 2]!
  }
  return out
}
