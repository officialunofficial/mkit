import { ArrowUpRightIcon } from '@phosphor-icons/react/ssr'
import { categories, specUrl } from '../lib/spec-data'
import type { SpecCategory, SpecItem } from '../lib/spec-data'

/**
 * One spec row: the document name linked to GitHub, its verbatim status token in mono (§3.2 rule 10), and a one-line
 * description.
 */
function Row({ item }: { item: SpecItem }) {
  return (
    <div className='px-2 py-1.5'>
      <p className='text-xs leading-4'>
        <a
          href={specUrl(item.name)}
          target='_blank'
          rel='noreferrer'
          className='ds-link font-mono inline-flex items-center gap-0.5'
        >
          {item.name}
          <ArrowUpRightIcon size={12} aria-hidden className='text-secondary' />
          <span className='sr-only'>(opens in a new tab)</span>
        </a>{' '}
        <span className='font-mono'>{item.status}</span>
      </p>
      <p className='mt-0.5 max-w-prose text-xs leading-4 text-secondary'>{item.description}</p>
    </div>
  )
}

function Category({ cat }: { cat: SpecCategory }) {
  return (
    <section className='mb-6 break-inside-avoid'>
      <div className='rule-square pb-2'>
        <h2 className='ds-h2'>{cat.name}</h2>
        <p className='ds-note mt-1'>{cat.blurb}</p>
      </div>
      {/* §4.9: a list shares the table's border grammar — heavy left border,
          light frame, square-dot row separators. */}
      <div className='data-frame mt-2'>
        {cat.items.map((item) => (
          <Row key={item.name} item={item} />
        ))}
      </div>
    </section>
  )
}

/**
 * Static index of the SPEC-*.md corpus: a status-vocabulary note, then one section per category. Single column on
 * purpose — each row carries a full sentence of description. Data lives in `lib/spec-data.ts`.
 */
export function SpecIndex() {
  return (
    <div className='space-y-8'>
      <div className='space-y-2 max-w-prose'>
        <p>
          Each document declares its status in front matter. SPEC-CONVENTIONS defines two maturity terms:{' '}
          <code>draft</code> content may change or have documented gaps; <code>stable</code> behavior changes only with
          a version change.
        </p>
        <p>
          The requirement level is separate. <code>normative</code> content defines requirements for compatible
          implementations. <code>advisory</code> content provides local guidance.
        </p>
      </div>
      <div className='gap-x-10 lg:columns-2'>
        {categories.map((cat) => (
          <Category key={cat.name} cat={cat} />
        ))}
      </div>
    </div>
  )
}
