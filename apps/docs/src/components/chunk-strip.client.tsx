'use client'

import { memo } from 'react'
import { hashColor } from '../lib/hash-color'

export type StripChunk = { offset: number; len: number; hash_hex: string }

// Memo'd per-chunk button. Auto-edit re-runs the chunker every ~500 ms but most chunk hashes are stable across ticks
// (FastCDC keeps everything outside the edited region byte-identical), so this skip-render saves ~75% of the
// reconciliation cost on the strip — empirically the dominant cost outside the wasm passes themselves.
type ButtonProps = {
  index: number
  hashHex: string
  offset: number
  len: number
  widthPct: number
  ring: boolean
  opacityClass: string
  animateClass: string
  clickable: boolean
  showVerifiedBar: boolean
  showFailedOverlay: boolean
  onClick?: ((i: number) => void) | undefined
}

const ChunkButton = memo(
  ({
    index,
    hashHex,
    offset,
    len,
    widthPct,
    ring,
    opacityClass,
    animateClass,
    clickable,
    showVerifiedBar,
    showFailedOverlay,
    onClick,
  }: ButtonProps) => {
    const title = `${offset.toLocaleString()}–${(offset + len).toLocaleString()} (${len} B) · ${hashHex.slice(0, 8)}…`
    return (
      <button
        type='button'
        disabled={!onClick}
        onClick={onClick ? () => onClick(index) : undefined}
        title={title}
        aria-label={`chunk ${index}: ${len} bytes`}
        className={`relative h-full shrink-0 border-r border-[--color-hairline]/40 last:border-r-0 transition-opacity ${opacityClass} ${animateClass} ${ring ? 'outline outline-2 outline-[--color-fg] z-10' : ''} ${clickable ? 'cursor-pointer' : ''}`}
        style={{
          width: `max(2px, ${widthPct}%)`,
          minWidth: '2px',
          backgroundColor: hashColor(hashHex),
        }}
      >
        {showVerifiedBar ? <span aria-hidden className='absolute inset-x-0 top-0 h-0.5 bg-[--color-fg]' /> : null}
        {showFailedOverlay ? (
          <span
            aria-hidden
            className='absolute inset-0 flex items-center justify-center text-[10px] font-bold text-white'
            style={{ backgroundColor: 'rgba(220, 38, 38, 0.7)' }}
          >
            ×
          </span>
        ) : null}
      </button>
    )
  },
)
ChunkButton.displayName = 'ChunkButton'

type Props = {
  chunks: StripChunk[]
  totalLen: number
  ariaLabel: string
  highlightIndex?: number | undefined
  tamperIndex?: number | null | undefined
  verifiedSet?: Set<number> | undefined
  pendingSet?: Set<number> | undefined
  failedSet?: Set<number> | undefined
  dimSet?: Set<number> | undefined
  onChunkClick?: ((i: number) => void) | undefined
  className?: string | undefined
  // Byte offset to draw a vertical position marker at (e.g. tamper-slider cursor). Rendered as a 2 px line on top of
  // the strip, anchored to the byte's percentage of `totalLen`.
  markerByte?: number | undefined
}

/**
 * Horizontal strip of chunk tiles, one per chunk, sized in proportion to chunk length. Each tile is coloured by the
 * BLAKE3 of its bytes — same palette as `HashChip` so a re-chunk that produces a different hash visibly shifts the
 * colour. Width is shared across the whole row via flex; tiles are clamped to a 2px minimum so very small chunks remain
 * visible.
 *
 * Decorations (verified ring, pending pulse, tamper overlay) are layered on top of the base tile so the underlying
 * colour stays legible.
 */
export function ChunkStrip({
  chunks,
  totalLen,
  ariaLabel,
  highlightIndex,
  tamperIndex,
  verifiedSet,
  pendingSet,
  failedSet,
  dimSet,
  onChunkClick,
  className = '',
  markerByte,
}: Props) {
  const total = totalLen > 0 ? totalLen : 1
  const markerPct = markerByte != null ? Math.max(0, Math.min(100, (markerByte / total) * 100)) : null
  return (
    <div className={`relative w-full ${className}`}>
      <div
        role='group'
        aria-label={ariaLabel}
        className='flex h-6 w-full overflow-x-auto rounded-sm border border-[--color-hairline]'
      >
        {chunks.map((c, i) => {
          const pending = pendingSet?.has(i) ?? false
          const dim = dimSet?.has(i) ?? false
          return (
            <ChunkButton
              key={`${c.offset}-${c.hash_hex}`}
              index={i}
              hashHex={c.hash_hex}
              offset={c.offset}
              len={c.len}
              widthPct={(c.len / total) * 100}
              ring={highlightIndex === i}
              opacityClass={pending ? 'opacity-50' : dim ? 'opacity-40' : 'opacity-100'}
              animateClass={pending ? 'animate-pulse' : ''}
              clickable={!!onChunkClick}
              showVerifiedBar={verifiedSet?.has(i) ?? false}
              showFailedOverlay={(failedSet?.has(i) ?? false) || tamperIndex === i}
              onClick={onChunkClick}
            />
          )
        })}
      </div>
      {markerPct != null ? (
        <span
          aria-hidden
          className='pointer-events-none absolute -top-1 -bottom-1 z-20 w-0.5 bg-[--color-fg]'
          style={{ left: `calc(${markerPct}% - 1px)` }}
        />
      ) : null}
    </div>
  )
}
