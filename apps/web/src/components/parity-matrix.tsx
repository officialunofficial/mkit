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

/**
 * §3.2 rule 10: an identifier named in prose renders as inline code. Notes arrive as prose with backtick spans; render
 * them as mono instead of shipping the backticks.
 */
function renderInlineCode(text: string) {
  return text.split('`').map((part, i) => (i % 2 === 1 ? <code key={i}>{part}</code> : part))
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
      <span className='flex h-4 shrink-0 items-center' title={statusLabel(status)}>
        <StatusIcon status={status} />
      </span>
      <span className='sr-only'>{statusLabel(status)}: </span>
      <p className='text-xs leading-4'>
        <code>{cmd}</code> <span className='text-secondary'>{renderInlineCode(note)}</span>
      </p>
    </div>
  )
}

function Category({ cat }: { cat: ParityCategory }) {
  return (
    <section className='mb-6 break-inside-avoid'>
      <div className='rule-square pb-2'>
        <h2 className='ds-h2'>{cat.name}</h2>
        {cat.blurb ? <p className='ds-note mt-1'>{cat.blurb}</p> : null}
      </div>
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
 * The status legend as a vertical stack — rendered beside the page intro (copy 4 of the 6 root columns, legend the
 * other 2).
 */
export function ParityLegend() {
  return (
    <div className='space-y-1.5 text-xs leading-4'>
      {legend.map((l) => (
        <span key={l.status} className='flex items-start gap-1'>
          <span className='flex h-4 shrink-0 items-center'>
            <StatusIcon status={l.status} />
          </span>
          <span>
            <span className='font-medium'>{l.label}</span> <span className='text-secondary'>{l.meaning}</span>
          </span>
        </span>
      ))}
    </div>
  )
}

/**
 * Static mkit-vs-git parity matrix: command categories, the two permanent (BLAKE3-inherent) divergences, and the
 * deliberate safety divergences. Categories flow into two columns on wide screens; the legend renders separately in the
 * page header (ParityLegend).
 */
export function ParityMatrix() {
  return (
    <div className='space-y-8'>
      <div className='gap-x-10 lg:columns-2'>
        {categories.map((cat) => (
          <Category key={cat.name} cat={cat} />
        ))}
      </div>

      <div
        className='grid grid-cols-1 gap-x-10 gap-y-6 border-t pt-8 lg:grid-cols-2'
        style={{ borderColor: 'var(--border-color-default)' }}
      >
        <section>
          <div className='rule-square pb-2'>
            <h2 className='ds-h2'>Different and Permanent</h2>
            <p className='ds-note mt-1'>
              These fall out of choosing BLAKE3 over SHA-1. They cannot change without dropping content addressing.
            </p>
          </div>
          <div className='data-frame mt-2'>
            {inherentDivergences.map((n) => (
              <NoteBlock key={n.label} label={n.label} body={n.body} />
            ))}
          </div>
        </section>

        <section>
          <div className='rule-square pb-2'>
            <h2 className='ds-h2'>Safer Than Git</h2>
            <p className='ds-note mt-1'>
              Where mkit refuses git&rsquo;s silent-data-loss defaults. These are deliberate choices, not missing git behavior.
            </p>
          </div>
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
