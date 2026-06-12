import type { ReactNode } from 'react'
import { hashColor } from '../lib/hash-color'

/** Canonical input/textarea class string. `text-sm` by default; swap in `text-xs` variant for dense hex inputs. */
export const INPUT_CLASSES =
  'w-full border border-hairline bg-paper p-2.5 font-mono text-sm outline-none transition-colors focus:border-fg'
export const INPUT_CLASSES_XS = INPUT_CLASSES.replace('text-sm', 'text-xs')

/** Canonical button: square, mono, uppercase; fills with ink on hover. The document's only "control" idiom. */
export const BUTTON_CLASSES =
  'inline-flex h-10 shrink-0 cursor-pointer items-center justify-center border border-fg bg-transparent px-4 font-mono text-xs font-medium tracking-[0.1em] uppercase transition-all duration-200 hover:bg-fg hover:text-bg active:translate-y-px disabled:pointer-events-none disabled:opacity-40 sm:h-9'

/** Quiet companion to BUTTON_CLASSES — borderless, for reset/secondary actions. */
export const GHOST_BUTTON_CLASSES =
  'inline-flex h-10 shrink-0 cursor-pointer items-center justify-center px-2 font-mono text-xs font-medium tracking-[0.1em] uppercase text-muted transition-colors duration-200 hover:text-fg active:translate-y-px disabled:pointer-events-none disabled:opacity-30 sm:h-9'

/**
 * Solid square coloured by the first byte of `hash` — same palette as the favicon. Edit anything below an object and
 * its hash changes, so the chip changes too: the Merkle property made visible. Inline-block keeps it on the title
 * line.
 */
export function HashChip({ hash, size = 12 }: { hash: string; size?: number }) {
  return (
    <span
      aria-hidden
      className='inline-block shrink-0 align-[-1px]'
      style={{
        width: size,
        height: size,
        background: hashColor(hash),
      }}
    />
  )
}

/**
 * Category block: heavy rule above (via the parent's `divide-y-2`), a title line, a muted description, then the rows
 * inside. Internal rows have no dividers — grouping comes from the block, not the row.
 */
/** Stable DOM id for a section anchored by its content-addressed hash. The Merkle visualisation scrolls to this. */
export function sectionAnchor(hash: string): string {
  return `hash-${hash}`
}

/**
 * Dense one-row representation of a hashed object — chip, label, meta, full hash inline. Replaces a stack of `Section`s
 * when the same shape repeats many times (every blob/tree on /tree, every leaf on /hash). Carries the same
 * `sectionAnchor` id so Merkle-tree clicks land on the right row.
 */
export function ObjectRow({
  hash,
  label,
  meta,
  trailing,
}: {
  hash: string
  label: string
  meta?: string
  trailing?: ReactNode
}) {
  return (
    <div
      id={sectionAnchor(hash)}
      className='flex scroll-mt-24 items-center gap-3 py-2.5 transition-colors duration-300'
    >
      <HashChip hash={hash} size={14} />
      <div className='min-w-0 flex-1'>
        <div className='flex items-baseline gap-2'>
          <span className='truncate text-sm font-medium'>{label}</span>
          {meta ? <span className='shrink-0 text-xs text-muted'>{meta}</span> : null}
        </div>
        <code className='block font-mono text-xs break-all text-muted'>{hash}</code>
      </div>
      {trailing ? <div className='shrink-0'>{trailing}</div> : null}
    </div>
  )
}

export function Section({
  title,
  description,
  hash,
  children,
}: {
  title: string
  description: string
  hash?: string
  children: ReactNode
}) {
  return (
    <section className='py-6 scroll-mt-24' id={hash ? sectionAnchor(hash) : undefined}>
      <header className='mb-5 space-y-1'>
        <h2 className='flex items-center gap-2 text-sm font-semibold'>
          {hash ? <HashChip hash={hash} /> : null}
          <span>{title}</span>
        </h2>
        <p className='text-sm text-subtle'>{description}</p>
      </header>
      <div className='space-y-4'>{children}</div>
    </section>
  )
}

/**
 * Labelled value row: tiny muted label above a monospace value. `break-all` lets long hashes wrap inside narrow columns
 * without overflowing the layout.
 */
export function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className='space-y-1.5'>
      <div className='microlabel text-muted'>{label}</div>
      <code className='block font-mono text-sm break-all'>{value}</code>
    </div>
  )
}

/**
 * Label / value row inside a dashed `<dl>` — keeps sign/attest tables legible at narrow widths by stacking below sm and
 * going two-column above it. Children render into the value slot so a row can host code, a verdict pill, or plain
 * text.
 */
export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className='grid gap-1 py-4 sm:grid-cols-[minmax(0,14rem),1fr] sm:gap-6'>
      <dt className='microlabel pt-1 text-muted'>{label}</dt>
      <dd className='min-w-0 break-all'>{children}</dd>
    </div>
  )
}

/** Dashed-rule `<dl>` wrapping a stack of `<Field>`s. Used for every results table in sign/attest. */
export function FieldList({ children }: { children: ReactNode }) {
  return <dl className='divide-y divide-dashed divide-hairline border-y border-dashed border-hairline'>{children}</dl>
}
