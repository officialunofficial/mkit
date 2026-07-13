import { categories, specUrl } from '../lib/spec-data'
import type { SpecCategory, SpecItem } from '../lib/spec-data'

/** One spec row: the document name linked to GitHub, its verbatim status token, and a one-line description. */
function Row({ item }: { item: SpecItem }) {
  return (
    <div className='space-y-0.5 py-2.5'>
      <p className='text-sm leading-snug'>
        <a
          href={specUrl(item.name)}
          target='_blank'
          rel='noreferrer'
          className='font-mono text-fg underline underline-offset-4 transition-opacity duration-300 hover:opacity-70'
        >
          {item.name}
        </a>{' '}
        <span className='font-mono text-[11px] text-muted'>{item.status}</span>
      </p>
      <p className='max-w-prose text-xs leading-relaxed text-subtle'>{item.description}</p>
    </div>
  )
}

function Category({ cat }: { cat: SpecCategory }) {
  return (
    <section className='space-y-1'>
      <h2 className='font-semibold'>{cat.name}</h2>
      <p className='max-w-prose text-xs text-subtle'>{cat.blurb}</p>
      <div className='divide-y divide-hairline border-y border-hairline'>
        {cat.items.map((item) => (
          <Row key={item.name} item={item} />
        ))}
      </div>
    </section>
  )
}

/**
 * Static index of the SPEC-*.md corpus: a status-vocabulary note, then one section per category. Single column on
 * purpose — each row carries a full sentence of description, unlike the parity matrix's terse command notes, so two
 * columns would wrap badly. Data lives in `lib/spec-data.ts`.
 */
export function SpecIndex() {
  return (
    <div className='space-y-10'>
      <p className='max-w-prose text-xs text-muted'>
        Each status token comes verbatim from the document&rsquo;s front matter and combines two axes (defined in
        SPEC-CONVENTIONS): maturity &mdash; <span className='font-mono text-fg'>draft</span> behavior is still changing
        or has a called-out gap, <span className='font-mono text-fg'>stable</span> behavior changes only with a version
        bump &mdash; and bindingness &mdash; <span className='font-mono text-fg'>normative</span> means interop depends
        on conforming, <span className='font-mono text-fg'>advisory</span> means local-only guidance.
      </p>
      {categories.map((cat) => (
        <Category key={cat.name} cat={cat} />
      ))}
    </div>
  )
}
