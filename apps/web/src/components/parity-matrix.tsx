import { categories, inherentDivergences, legend, nonGoals, safetyDivergences } from '../lib/parity-data'
import type { ParityCategory, ParityStatus } from '../lib/parity-data'

/**
 * Status glyph encoding git-alignment on two axes: green = on the git track (filled = exact parity, outline = works but
 * divergent), slate dash = deliberately off the track (non-goal). Drawn as inline SVG with explicit colors so they read
 * the same in light and dark, independent of the theme tokens.
 */
function StatusIcon({ status }: { status: ParityStatus }) {
  switch (status) {
    case 'parity':
      return (
        <svg width='10' height='10' viewBox='0 0 10 10' aria-hidden className='shrink-0'>
          <circle cx='5' cy='5' r='4' fill='#16a34a' />
        </svg>
      )
    case 'divergent':
      return (
        <svg width='10' height='10' viewBox='0 0 10 10' aria-hidden className='shrink-0'>
          <circle cx='5' cy='5' r='3.6' fill='none' stroke='#16a34a' strokeWidth='1.5' />
        </svg>
      )
    case 'non-goal':
      return (
        <svg width='10' height='10' viewBox='0 0 10 10' aria-hidden className='shrink-0'>
          <line x1='1.5' y1='5' x2='8.5' y2='5' stroke='#64748b' strokeWidth='1.6' strokeLinecap='round' />
        </svg>
      )
  }
}

function statusLabel(s: ParityStatus): string {
  switch (s) {
    case 'parity':
      return 'parity'
    case 'divergent':
      return 'divergent'
    case 'non-goal':
      return 'non-goal'
  }
}

/** Small asterisk glyph used as the bullet for the non-goals list. Three strokes crossing at the center. */
function AsteriskBullet() {
  return (
    <svg
      width='8'
      height='8'
      viewBox='0 0 10 10'
      fill='none'
      stroke='currentColor'
      strokeWidth='1.4'
      strokeLinecap='round'
      aria-hidden
      className='shrink-0'
    >
      <path d='M5 1 L5 9 M1.54 3 L8.46 7 M8.46 3 L1.54 7' />
    </svg>
  )
}

/** One dense row: glyph at the left, command and note flowing together as a single line that wraps cleanly. */
function Row({ cmd, status, note }: { cmd: string; status: ParityStatus; note: string }) {
  return (
    <div className='flex items-start gap-2 py-1.5'>
      <span className='flex h-4 shrink-0 items-center'>
        <StatusIcon status={status} />
      </span>
      <span className='sr-only'>{statusLabel(status)}: </span>
      <p className='text-[11px] leading-snug'>
        <code className='font-mono text-fg'>{cmd}</code> <span className='text-[11px] text-muted'>{note}</span>
      </p>
    </div>
  )
}

function Category({ cat }: { cat: ParityCategory }) {
  return (
    <section className='mb-6 break-inside-avoid space-y-1'>
      <h2 className='text-sm font-semibold'>{cat.name}</h2>
      {cat.blurb ? <p className='max-w-prose text-xs text-subtle'>{cat.blurb}</p> : null}
      <div className='divide-y divide-hairline border-y border-hairline'>
        {cat.items.map((item) => (
          <Row key={item.cmd} cmd={item.cmd} status={item.status} note={item.note} />
        ))}
      </div>
    </section>
  )
}

function NoteBlock({ label, body }: { label: string; body: string }) {
  return (
    <div className='py-1.5 text-xs'>
      <span className='font-medium text-fg'>{label}.</span> <span className='text-subtle'>{body}</span>
    </div>
  )
}

/**
 * Static mkit-vs-git parity matrix: a legend, command categories, the two permanent (BLAKE3-inherent) divergences, the
 * deliberate safety divergences, and the v1 non-goals. Categories flow into two columns on wide screens to keep the
 * page scannable rather than a long single-column scroll.
 */
export function ParityMatrix() {
  return (
    <div className='space-y-12'>
      <div className='flex flex-wrap items-center gap-x-5 gap-y-1.5 text-xs text-muted'>
        {legend.map((l) => (
          <span key={l.status} className='inline-flex items-center gap-1.5'>
            <StatusIcon status={l.status} />
            <span className='font-medium text-fg'>{l.label}</span>
            <span>{l.meaning}</span>
          </span>
        ))}
      </div>

      <div className='gap-x-10 lg:columns-2'>
        {categories.map((cat) => (
          <Category key={cat.name} cat={cat} />
        ))}
      </div>

      <div className='grid gap-x-10 gap-y-6 border-t border-hairline border-dashed pt-12 lg:grid-cols-2'>
        <section className='space-y-1'>
          <h2 className='font-semibold'>Different on purpose, and permanent</h2>
          <p className='max-w-prose text-xs text-subtle'>
            These fall out of choosing BLAKE3 over SHA-1. They cannot change without dropping content addressing.
          </p>
          <div className='divide-y divide-hairline border-y border-hairline'>
            {inherentDivergences.map((n) => (
              <NoteBlock key={n.label} label={n.label} body={n.body} />
            ))}
          </div>
        </section>

        <section className='space-y-1'>
          <h2 className='font-semibold'>Safer than git on purpose</h2>
          <p className='max-w-prose text-xs text-subtle'>
            Where mkit refuses git&rsquo;s silent-data-loss defaults. Features, not gaps.
          </p>
          <div className='divide-y divide-hairline border-y border-hairline'>
            {safetyDivergences.map((n) => (
              <NoteBlock key={n.label} label={n.label} body={n.body} />
            ))}
          </div>
        </section>
      </div>

      <section className='space-y-2 '>
        <h2 className='font-semibold'>Out of scope for v1</h2>
        <ul className='columns-2 gap-x-8 text-xs text-muted sm:columns-3 lg:columns-4'>
          {nonGoals.map((g) => (
            <li key={g} className='flex break-inside-avoid items-start gap-2 py-0.5'>
              <span className='flex h-4 shrink-0 items-center'>
                <AsteriskBullet />
              </span>
              <span>{g}</span>
            </li>
          ))}
        </ul>
      </section>
    </div>
  )
}
