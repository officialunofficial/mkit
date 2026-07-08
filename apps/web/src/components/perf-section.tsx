import * as Collapsible from '@radix-ui/react-collapsible'
import type { ReactNode } from 'react'
import { labelColor } from '../lib/hash-color'
import { methodology, sizeBenchmarks, timingBenchmarks, transferBenchmarks } from '../lib/perf-data'
import type { SizeBenchmark, Theme, TimingBenchmark, TransferBenchmark } from '../lib/perf-data'

/** `13.4628 → "13.5 s"`, `0.3108 → "311 ms"`, `0.0134 → "13.4 ms"`. Sub-second values read better in ms. */
function fmtSeconds(s: number): string {
  if (s >= 10) return `${s.toFixed(1)} s`
  if (s >= 1) return `${s.toFixed(2)} s`
  return `${(s * 1000).toFixed(s >= 0.1 ? 0 : 1)} ms`
}

/** `105036 → "102.6 MiB"`, `1148 → "1.1 MiB"`, `92 → "92 KiB"`. Sizes come from `du -k` so the base unit is KiB. */
function fmtKiB(kib: number): string {
  if (kib >= 1024) return `${(kib / 1024).toFixed(1)} MiB`
  return `${kib} KiB`
}

/** `72704 → "71.0 KiB"`, `1536 → "1.5 KiB"`, `93 → "93 B"`. Wire bytes are exact, so the base unit is bytes. */
function fmtBytes(bytes: number): string {
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KiB`
  return `${bytes} B`
}

/** Multiplier between the two means, e.g. "6.9× faster". Below 1.15× the honest label is a tie. */
function speedupLabel(mkit: number, git: number): string {
  const ratio = mkit > git ? mkit / git : git / mkit
  if (ratio < 1.15) return 'about even'
  const who = mkit > git ? 'git' : 'mkit'
  return `${who} ${ratio.toFixed(1)}× faster`
}

/**
 * One horizontal bar, width proportional to `value / max`. mkit bars carry the benchmark's hash-hue (`color`); git bars
 * are muted — the shorter bar wins (lower is better throughout). Pure CSS, no chart library: the site's hairline
 * aesthetic carries over via the bordered track.
 */
function Bar({
  label,
  value,
  max,
  display,
  color,
}: {
  label: string
  value: number
  max: number
  display: string
  /** Fill colour for the bar; omitted → muted neutral (the git baseline). */
  color?: string
}) {
  const pct = Math.max(0.75, (value / max) * 100)
  return (
    <div className='flex items-center gap-3'>
      <span className='w-9 shrink-0 font-mono text-xs text-muted'>{label}</span>
      <div className='h-4 flex-1'>
        <div
          className={`h-full rounded-xs ${color ? '' : 'bg-muted/40'}`}
          style={{ width: `${pct}%`, ...(color ? { backgroundColor: color } : null) }}
        />
      </div>
      <span className='w-20 shrink-0 text-right font-mono text-xs'>{display}</span>
    </div>
  )
}

function TimingBlock({ b }: { b: TimingBenchmark }) {
  const max = Math.max(b.mkit.mean, b.git.mean)
  return (
    <div className='space-y-3 py-6'>
      <div className='flex items-baseline justify-between gap-4'>
        <h4 className='text-sm font-semibold'>{b.name}</h4>
        <span className='shrink-0 text-xs text-muted'>{speedupLabel(b.mkit.mean, b.git.mean)}</span>
      </div>
      <p className='max-w-prose text-sm text-subtle'>{b.description}</p>
      <div className='space-y-1.5'>
        <Bar label='mkit' value={b.mkit.mean} max={max} display={fmtSeconds(b.mkit.mean)} color={labelColor(b.id)} />
        <Bar label='git' value={b.git.mean} max={max} display={fmtSeconds(b.git.mean)} />
      </div>
      {b.note ? <p className='max-w-prose text-xs text-muted'>{b.note}</p> : null}
    </div>
  )
}

function SizeBlock({ b }: { b: SizeBenchmark }) {
  const max = Math.max(b.mkitKiB, b.gitKiB)
  return (
    <div className='space-y-3 py-6'>
      <h4 className='text-sm font-semibold'>{b.name}</h4>
      <p className='max-w-prose text-sm text-subtle'>{b.description}</p>
      <div className='space-y-1.5'>
        <Bar label='mkit' value={b.mkitKiB} max={max} display={fmtKiB(b.mkitKiB)} color={labelColor(b.id)} />
        <Bar label='git' value={b.gitKiB} max={max} display={fmtKiB(b.gitKiB)} />
      </div>
      {b.note ? <p className='max-w-prose text-xs text-muted'>{b.note}</p> : null}
    </div>
  )
}

function TransferBlock({ b }: { b: TransferBenchmark }) {
  const max = Math.max(b.wholeChunkBytes, b.deltaBytes)
  const ratio = b.wholeChunkBytes / b.deltaBytes
  return (
    <div className='space-y-3 py-6'>
      <div className='flex items-baseline justify-between gap-4'>
        <h4 className='text-sm font-semibold'>{b.name}</h4>
        <span className='shrink-0 text-xs text-muted'>{ratio.toFixed(0)}× smaller push</span>
      </div>
      <p className='max-w-prose text-sm text-subtle'>{b.description}</p>
      <div className='space-y-1.5'>
        <Bar label='whole' value={b.wholeChunkBytes} max={max} display={fmtBytes(b.wholeChunkBytes)} />
        <Bar label='delta' value={b.deltaBytes} max={max} display={fmtBytes(b.deltaBytes)} color={labelColor(b.id)} />
      </div>
      {b.note ? <p className='max-w-prose text-xs text-muted'>{b.note}</p> : null}
    </div>
  )
}

/**
 * A labelled cluster of benchmark rows within a workload section — keeps the "lower is better" unit note attached to
 * the rows it applies to, since a single workload section mixes seconds, KiB, and wire bytes.
 */
function MeasureGroup({ heading, hint, children }: { heading: string; hint: ReactNode; children: ReactNode }) {
  return (
    <div className='space-y-1'>
      <h3 className='text-xs font-semibold uppercase tracking-wide text-muted'>{heading}</h3>
      <p className='max-w-prose text-sm text-subtle'>{hint}</p>
      <div className='divide-y divide-hairline border-y border-hairline'>{children}</div>
    </div>
  )
}

/**
 * The workload sections, keyed by `Theme` so the compiler forces an entry for every union member — add a variant and
 * this stops compiling until it has a title and blurb, rather than the row silently dropping off the page. Iteration
 * order is the insertion order below. Copy states each section's thesis honestly.
 */
const THEMES: Record<Theme, { title: string; blurb: string }> = {
  'large-files': {
    title: 'Large files & media',
    blurb:
      'The workload mkit is built for: big, incompressible files and small edits to them. Content-defined chunking ' +
      'means a small edit costs the changed chunk, not the whole file — on disk, on the wire, and in wall-clock time.',
  },
  everyday: {
    title: 'Everyday operations',
    blurb:
      'The routine git operations on ordinary trees, where the honest verdict is roughly even. mkit keeps pace while ' +
      'signing every commit and flushing every object to disk, neither of which git does by default.',
  },
}

/**
 * Static benchmark comparison: every number was measured once on a real machine (see `perf-data.ts` for the exact
 * commands) and baked in at build time. Bars are plain divs — lower is better everywhere, and git's wins are shown as
 * plainly as mkit's. Rows are grouped by workload theme, then by what they measure (time / disk / wire).
 */
export function PerfSection() {
  return (
    <div className='space-y-10'>
      {(Object.keys(THEMES) as Theme[]).map((key) => {
        const { title, blurb } = THEMES[key]
        const timings = timingBenchmarks.filter((b) => b.theme === key)
        const sizes = sizeBenchmarks.filter((b) => b.theme === key)
        const transfers = transferBenchmarks.filter((b) => b.theme === key)
        return (
          <section key={key} className='space-y-4'>
            <div className='space-y-1'>
              <h2 className='text-base font-semibold'>{title}</h2>
              <p className='max-w-prose text-sm text-subtle'>{blurb}</p>
            </div>
            {timings.length > 0 ? (
              <MeasureGroup
                heading='Time, end to end'
                hint='Wall-clock time for whole CLI invocations, mean of repeated runs. Lower is better.'
              >
                {timings.map((b) => (
                  <TimingBlock key={b.id} b={b} />
                ))}
              </MeasureGroup>
            ) : null}
            {sizes.length > 0 ? (
              <MeasureGroup
                heading='Bytes on disk'
                hint={
                  <>
                    Repository directory size (<code className='font-mono text-xs'>du -k .mkit</code> vs{' '}
                    <code className='font-mono text-xs'>.git</code>) after the same operations. Lower is better.
                  </>
                }
              >
                {sizes.map((b) => (
                  <SizeBlock key={b.id} b={b} />
                ))}
              </MeasureGroup>
            ) : null}
            {transfers.length > 0 ? (
              <MeasureGroup
                heading='Bytes on the wire'
                hint={
                  <>
                    What a <code className='font-mono text-xs'>push</code> sends after a small edit to a large file the
                    remote already holds. Delta-on-the-wire encodes the changed chunk against the version the remote
                    has, instead of re-uploading it whole. Lower is better.
                  </>
                }
              >
                {transfers.map((b) => (
                  <TransferBlock key={b.id} b={b} />
                ))}
              </MeasureGroup>
            ) : null}
          </section>
        )
      })}

      <section className='space-y-3'>
        <h2 className='text-sm font-semibold'>Methodology &amp; caveats</h2>
        <dl className='space-y-1 font-mono text-xs text-muted'>
          <div>date: {methodology.date}</div>
          <div>machine: {methodology.machine}</div>
          <div>versions: {methodology.versions}</div>
          <div>harness: {methodology.harness}</div>
          <div>workload: {methodology.workload}</div>
        </dl>
        <ul className='max-w-prose list-disc space-y-1.5 pl-4 text-xs text-muted'>
          {methodology.caveats.map((c) => (
            <li key={c}>{c}</li>
          ))}
        </ul>
        <Collapsible.Root className='text-xs text-muted'>
          <Collapsible.Trigger className='select-none transition-colors hover:text-fg'>
            Exact commands
          </Collapsible.Trigger>
          <Collapsible.Content>
            <pre className='mt-2 overflow-x-auto rounded-md border border-hairline p-3 font-mono text-[11px] leading-relaxed'>
              {methodology.commands.join('\n')}
            </pre>
          </Collapsible.Content>
        </Collapsible.Root>
      </section>
    </div>
  )
}
