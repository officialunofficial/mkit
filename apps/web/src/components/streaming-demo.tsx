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

const DEFAULT_SEED = 0xc0de_cafe
// Demo-only hard cap. At 64 KiB avg FastCDC chunks, 128 MiB → ~2,048 chunks — the strip stays readable (each chip is
// still visible at typical viewport widths) and the wasm passes finish in a few seconds on a modest laptop. Above this
// we'd risk OOM in wasm32 (the linear memory ceiling is 4 GiB and our passes hold multiple copies — input, chunker
// state, Bao outboard) and start freezing the tab while building tens of thousands of DOM nodes. Real mkit has no
// such limit; the cap only applies to this interactive page.
const MAX_FILE_BYTES = 128 * 1024 * 1024

export function StreamingDemo() {
  const [currentFile, setCurrentFile] = useState<FileAsset | null>(null)
  const [tooLarge, setTooLarge] = useState<{ name: string; size: number } | null>(null)
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

  // Reject oversized files *before* reading the ArrayBuffer — saves the browser from allocating hundreds of MiB just
  // to throw it away. Real mkit has no cap; this is purely to keep the demo page responsive.
  const tryReplaceFile = async (file: File) => {
    const name = file.name || 'file'
    if (file.size > MAX_FILE_BYTES) {
      setTooLarge({ name, size: file.size })
      return
    }
    const buf = await file.arrayBuffer()
    setTooLarge(null)
    const next: FileAsset = { name, bytes: new Uint8Array(buf), source: 'upload' }
    setCurrentFile(next)
  }

  if (!currentFile) {
    return <p className='text-sm text-muted'>Generating default file…</p>
  }

  return (
    // Mobile-first ordering: live sections above the file sidebar so a phone landing on the streaming demo sees the
    // download running immediately, then scrolls down to the file controls. See `hash-demo.tsx` for the same pattern.
    <div className='flex flex-col-reverse gap-10 lg:grid lg:grid-cols-[minmax(0,20rem)_1fr] lg:gap-12'>
      <div className='space-y-6 lg:sticky lg:top-24 lg:self-start'>
        <FileSidebar current={currentFile} onReplace={tryReplaceFile} rejected={tooLarge} />
      </div>
      <div className='space-y-12'>
        <StreamingVerifiedDownload file={currentFile} />
      </div>
    </div>
  )
}

// --- sidebar -----------------------------------------------------------------

function FileSidebar({
  current,
  onReplace,
  rejected,
}: {
  current: FileAsset
  onReplace: (file: File) => void | Promise<void>
  rejected: { name: string; size: number } | null
}) {
  const fileRef = useRef<HTMLInputElement>(null)
  const [dragOver, setDragOver] = useState(false)

  return (
    <div className='space-y-4'>
      <div className='flex items-start gap-3'>
        <FilePreview asset={current} />
        <div className='min-w-0 flex-1'>
          <span className='block text-sm text-muted'>Current file</span>
          <p className='mt-1 text-sm font-medium break-all'>{current.name}</p>
          <p className='text-xs text-muted'>{formatBytes(current.bytes.byteLength)}</p>
        </div>
      </div>
      {rejected ? (
        <p className='text-xs text-amber-700 dark:text-amber-400'>
          <span className='font-medium'>{rejected.name}</span> is {formatBytes(rejected.size)}. The demo cap is{' '}
          {formatBytes(MAX_FILE_BYTES)} to keep this page responsive. mkit handles gigabytes; the cap only applies to
          this interactive page.
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
        className={`rounded-md border border-dashed p-3 text-xs transition-colors ${
          // text-muted must live in the else branch: both .text-* classes set the same property, so
          // stylesheet order (not className order) would decide and text-fg loses to a later text-muted.
          dragOver ? 'border-fg text-fg' : 'border-hairline text-muted'
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
      <p className='text-xs text-muted'>
        Drop in your own file and stream it back verified. Demo cap: {formatBytes(MAX_FILE_BYTES)}.
      </p>
    </div>
  )
}

// --- verified download ---------------------------------------------

// Everything the stream needs, captured once when the user presses Start. Streaming a snapshot (not the live file)
// keeps playback stable regardless of later file replacement. `ppm` is non-null only for the default grid file (or a
// user-supplied raw PPM), and gates the progressive canvas paint; compressed uploads can't be painted from a byte
// prefix.
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
// chunks fetched per tick is max(1, ceil(chunkCount / 60)). The floor keeps huge uploads from taking minutes; the
// ceiling keeps the 9-chunk default slow enough to actually watch chunks light up one at a time.
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
  // stacking even if a tick runs long (the 128 MiB cap can take longer than `delayMs`; see the guide's measured
  // numbers). Corruption (when armed) hits only the first attempt at a chunk; the retry that follows a rejection
  // always arrives clean, telling the "different mirror" story the toggle's helper copy promises.
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
        const canvas = canvasRef.current
        const ctx = canvas?.getContext('2d')
        const assembled = assembledRef.current
        if (ctx && assembled) {
          const { width, pixelStart } = snapshot.ppm
          const prefixBytes =
            next.cursor < snapshot.chunks.length ? snapshot.chunks[next.cursor]!.offset : snapshot.bytes.byteLength
          const bytesPerRow = width * 3
          const rowsDone = Math.floor(Math.max(0, prefixBytes - pixelStart) / bytesPerRow)
          const painted = paintedRowsRef.current
          if (rowsDone > painted) {
            const rowSpan = rowsDone - painted
            const rgba = new Uint8ClampedArray(width * rowSpan * 4)
            let p = pixelStart + painted * bytesPerRow
            for (let i = 0; i < width * rowSpan; i++) {
              rgba[i * 4] = assembled[p++]!
              rgba[i * 4 + 1] = assembled[p++]!
              rgba[i * 4 + 2] = assembled[p++]!
              rgba[i * 4 + 3] = 255
            }
            ctx.putImageData(new ImageData(rgba, width, rowSpan), 0, painted)
            paintedRowsRef.current = rowsDone
          }
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

  return (
    <Section
      id='bao'
      title='Verified download (Bao)'
      description='Download the file chunk by chunk, content-defined chunks (FastCDC) verified against a Bao root as they land — corruption is caught mid-stream, not after.'
    >
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
        <button
          type='button'
          onClick={() => setCorrupt((v) => !v)}
          aria-pressed={corrupt}
          className={`inline-flex h-10 items-center justify-center rounded-lg border px-3 text-sm font-medium transition-all duration-200 active:scale-[0.96] sm:h-9 ${
            corrupt ? 'border-red-600 bg-red-600 text-white' : 'border-hairline hover:border-red-500/50'
          }`}
        >
          Corrupt the connection
        </button>
      </div>
      {corrupt ? (
        <p className='text-xs text-muted'>
          Every fresh chunk arrives tampered; the verifier rejects it and the re-fetch comes in clean.
        </p>
      ) : null}
      {snapshot ? (
        <p className='text-xs text-muted tabular-nums'>
          Verified {formatBytes(dl.verifiedBytes)} of {formatBytes(total)} · {formatBytes(dl.wireBytes)} on the wire ·{' '}
          {formatBytes(proofBytes)} proof · {dl.rejected} rejected ({formatBytes(dl.wastedBytes)} wasted)
        </p>
      ) : (
        <p className='text-xs text-muted'>
          Press Start download to stream the current file back, verifying every chunk against its Bao root.
        </p>
      )}
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
  description: string
  children: React.ReactNode
}) {
  return (
    <section id={id} className='space-y-4 scroll-mt-24'>
      <header className='space-y-1'>
        <h2 className='text-sm font-semibold'>{title}</h2>
        <p className='text-sm text-subtle'>{description}</p>
      </header>
      {children}
    </section>
  )
}

// 96 px square preview of the current file. PPM is parsed and blitted directly via putImageData on an offscreen
// canvas, then downscaled with `drawImage`; everything else is rendered through a Blob URL `<img>` decode. Both paths
// fall back to a hairline placeholder if decoding fails (e.g. non-image upload).
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
