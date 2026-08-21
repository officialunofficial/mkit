import { CheckCircleIcon, MinusCircleIcon, WarningCircleIcon } from '@phosphor-icons/react/ssr'
import { categories, inherentDivergences, legend, safetyDivergences } from '../lib/parity-data'
import type { ParityCategory, ParityStatus } from '../lib/parity-data'

/**
 * Status glyph per §3.10: an outline icon carrying the hue while the label carries the meaning. Parity is a success,
 * divergent a warning, non-goal a neutral state — deliberately off the git track, not a failure.
 */
function StatusIcon({ status }: { status: ParityStatus }) {
  switch (status) {
    case 'parity':
      return (
        <CheckCircleIcon size={12} aria-hidden className='shrink-0' style={{ color: 'var(--status-success-fg)' }} />
      )
    case 'divergent':
      return (
        <WarningCircleIcon size={12} aria-hidden className='shrink-0' style={{ color: 'var(--status-warning-fg)' }} />
      )
    case 'non-goal':
      return (
        <MinusCircleIcon size={12} aria-hidden className='shrink-0' style={{ color: 'var(--status-neutral-fg)' }} />
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

/** One dense row: status glyph at the left, command and note flowing together as a single line that wraps cleanly. */
function Row({ cmd, status, note }: { cmd: string; status: ParityStatus; note: string }) {
  return (
    <div className='flex items-start gap-1 px-2 py-1.5'>
      <span className='flex h-4 shrink-0 items-center'>
        <StatusIcon status={status} />
      </span>
      <span className='sr-only'>{statusLabel(status)}: </span>
      <p className='text-xs leading-4'>
        <code>{cmd}</code> <span>{note}</span>
      </p>
    </div>
  )
}

function Category({ cat }: { cat: ParityCategory }) {
  return (
    <section>
      <h2 className='ds-h2 rule-square pb-2'>{cat.name}</h2>
      {cat.blurb ? <p className='ds-note mt-1'>{cat.blurb}</p> : null}
      <div className='data-frame mt-2'>
        {cat.items.map((item) => (
          <Row key={item.cmd} cmd={item.cmd} status={item.status} note={item.note} />
        ))}
      </div>
    </section>
  )
}

function NoteBlock({ label, body }: { label: string; body: string }) {
  return (
    <div className='px-2 py-1.5 text-xs leading-4'>
      <span className='font-medium'>{label}.</span> <span>{body}</span>
    </div>
  )
}

/**
 * Static mkit-vs-git parity matrix: a legend, command categories, the two permanent (BLAKE3-inherent) divergences, and
 * the deliberate safety divergences. Categories flow into two columns on wide screens.
 */
export function ParityMatrix() {
  return (
    <div className='space-y-8'>
      <div className='grid grid-cols-1 gap-1.5 text-xs leading-4 sm:grid-cols-3 sm:gap-3'>
        {legend.map((l) => (
          <span key={l.status} className='inline-flex items-start gap-1'>
            <span className='flex h-4 shrink-0 items-center'>
              <StatusIcon status={l.status} />
            </span>
            <span>
              <span className='font-medium'>{l.label}</span> <span className='text-secondary'>{l.meaning}</span>
            </span>
          </span>
        ))}
      </div>

      <div className='space-y-8'>
        {categories.map((cat) => (
          <Category key={cat.name} cat={cat} />
        ))}
      </div>

      <div className='space-y-8 border-t pt-8' style={{ borderColor: 'var(--border-color-default)' }}>
        <section>
          <h2 className='ds-h2 rule-square pb-2'>Different, and Permanent</h2>
          <p className='ds-note mt-1'>
            These fall out of choosing BLAKE3 over SHA-1. They cannot change without dropping content addressing.
          </p>
          <div className='data-frame mt-2'>
            {inherentDivergences.map((n) => (
              <NoteBlock key={n.label} label={n.label} body={n.body} />
            ))}
          </div>
        </section>

        <section>
          <h2 className='ds-h2 rule-square pb-2'>Safer Than Git</h2>
          <p className='ds-note mt-1'>Where mkit refuses git&rsquo;s silent-data-loss defaults. Features, not gaps.</p>
          <div className='data-frame mt-2'>
            {safetyDivergences.map((n) => (
              <NoteBlock key={n.label} label={n.label} body={n.body} />
            ))}
          </div>
        </section>
      </div>
    </div>
  )
}
