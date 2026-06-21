import type { ReactNode } from 'react'
import { Link } from 'waku'
import { Seo } from '../components/seo'
import { WithToc } from '../components/with-toc'
import { PUSH_MESH } from '../lib/mesh'

export default function PushPage() {
  return (
    <WithToc>
      <div className='space-y-10'>
        <Seo
          title='mkit — push'
          description='A push does not copy files into a bucket one for one. mkit chunks them, folds every piece into a Merkle root, packs the new pieces, and settles by advancing one content-addressed pointer.'
          path='/push'
          card='How a push settles'
        />
        <header className='space-y-3'>
          <h1 className='text-4xl font-semibold tracking-tight'>How a push settles</h1>
          <p className='max-w-prose text-base text-fg'>
            A push doesn&rsquo;t copy your files into a bucket one for one. mkit cuts each file into content-defined
            chunks, folds every piece into a Merkle root, packs only the pieces the remote is missing, and settles the
            result by advancing a single content-addressed pointer. Here&rsquo;s the road not taken, the road taken, and
            why.
          </p>
        </header>

        <section className='space-y-4'>
          <h2 className='text-2xl font-semibold tracking-tight'>Two roads</h2>
          <p className='max-w-prose text-base text-fg'>
            There are two ways to put a repository into a bucket. They lead to very different stores.
          </p>
          <div className='grid grid-cols-1 gap-4 sm:grid-cols-2'>
            <Road
              tag='Road A'
              title='One object, one file.'
              tone='muted'
              points={[
                'Every file — and every version of it — lands in the bucket as its own object.',
                'The bucket reads like a folder tree: human-browsable, obvious.',
                'But each version is stored whole, and nothing is shared between them.',
              ]}
            />
            <Road
              tag='Road B'
              title='Chunk + pack.'
              tone='accent'
              points={[
                'Split each file into content-defined chunks; hash every chunk.',
                'Fold the chunk hashes into a Merkle (BMT) root — that root is the object’s id.',
                'Ship only the new chunks, batched together into one pack.',
              ]}
            />
          </div>
          <p className='max-w-prose text-base text-fg'>
            <strong className='font-semibold'>We chose B.</strong>{' '}
            <a
              href='https://x.com/makechainnet'
              target='_blank'
              rel='noreferrer'
              className='underline underline-offset-4 transition-opacity duration-300 hover:opacity-70'
            >
              @makechainnet
            </a>
            &rsquo;s projects store packed, hashed blobs. You give up a browsable bucket; in return you get dedup, cheap
            deltas, file integrity, and signed history.
          </p>
        </section>

        <section className='space-y-4'>
          <h2 className='text-2xl font-semibold tracking-tight'>Why packed, not browsable</h2>
          <p className='max-w-prose text-base text-fg'>
            We did this because we don&rsquo;t think buckets will need to be human-browsable in the future. Four things
            you get for that trade:
          </p>
          <div className='max-w-prose space-y-4'>
            <Labeled term='Dedup'>
              Identical chunks are stored once — across files and across versions. Move a folder, copy a file, commit
              the same asset twice: the bytes land in the bucket a single time.
            </Labeled>
            <Labeled term='Cheap deltas'>
              A one-byte edit to a huge file pushes only the chunks that changed, encoded as a delta against a base the
              remote already holds — not the whole file again (see <DocLink to='/streaming'>streaming</DocLink>).
            </Labeled>
            <Labeled term='File integrity'>
              Every object is named by its hash. A merkelized object&rsquo;s id <em>is</em> its BMT root, so reading it
              back re-derives the root and proves its whole child set is intact — a free completeness check on anything
              pulled out of the bucket (see <DocLink to='/tree'>tree</DocLink>).
            </Labeled>
            <Labeled term='Signed history'>
              Every commit carries an Ed25519 signature, so the chain of Merkle roots is also a chain of attestations:
              who changed what, provable by anyone with the key (see <DocLink to='/sign'>sign</DocLink>).
            </Labeled>
          </div>
        </section>

        <section className='space-y-4'>
          <h2 className='text-2xl font-semibold tracking-tight'>What a push actually does</h2>
          <p className='max-w-prose text-base text-fg'>
            Four stages turn a working tree into a settled push. The first three build content; the last one makes it
            visible, atomically.
          </p>
          <ol className='max-w-prose space-y-4'>
            <Step n={1} term='Chunk'>
              FastCDC splits each file at content-defined boundaries, so inserting a byte shifts only the boundaries
              around the edit — everything else stays byte-identical and re-usable.
            </Step>
            <Step n={2} term='Hash & merkelize'>
              Each chunk is BLAKE3-hashed. The chunk hashes — plus a leaf that binds the file&rsquo;s size — fold into a
              BMT root that becomes the object&rsquo;s id. A folder folds its entries into a root the same way; a commit
              names that folder&rsquo;s root and signs it.
            </Step>
            <Step n={3} term='Pack'>
              Only the objects the remote doesn&rsquo;t already have are serialized into a single pack. Large unchanged
              bases stay put; edits ride along as chunk deltas, so the bytes on the wire track what actually changed
              (see <DocLink to='/performance'>performance</DocLink>).
            </Step>
            <Step n={4} term='Settle'>
              The pack is uploaded as a content-addressed blob, chained onto the branch&rsquo;s packmap, and the head
              pointer is advanced with a compare-and-swap. Either the whole push becomes visible at once, or none of it
              does — no half-written state.
            </Step>
          </ol>
        </section>

        <section className='space-y-4'>
          <h2 className='text-2xl font-semibold tracking-tight'>What ends up in the bucket</h2>
          <p className='max-w-prose text-base text-fg'>
            Content-addressed blobs — packs and the packlist nodes that thread them — each keyed by the hash of its own
            bytes, written once and never mutated. The only thing that ever moves is a single branch-head pointer,
            advanced atomically. That&rsquo;s an object store, not a filesystem, which is exactly what makes it safe to
            keep on something like an object bucket: immutable keys, deterministic ids, and no in-place edits to race.
          </p>
        </section>

        <Link
          to='/'
          className='-mx-2 inline-block px-2 py-2 text-sm underline underline-offset-4 transition-opacity duration-300 hover:opacity-70'
        >
          ← back
        </Link>
      </div>
    </WithToc>
  )
}

// Inline prose link to another doc page. Carries the site's standard link
// affordance (underline + opacity transition) in one place — the cross-links
// previously inlined a shorter variant that dropped the transition.
type DocRoute = '/streaming' | '/tree' | '/sign' | '/performance'
function DocLink({ to, children }: { to: DocRoute; children: ReactNode }) {
  return (
    <Link to={to} className='underline underline-offset-4 transition-opacity duration-300 hover:opacity-70'>
      {children}
    </Link>
  )
}

// A bold term over muted body text — the shared row shape for both the "Why
// packed" list and the numbered pipeline stages, so their typography is
// defined once.
function Labeled({ term, children }: { term: ReactNode; children: ReactNode }) {
  return (
    <div className='space-y-1'>
      <div className='text-base font-medium'>{term}</div>
      <div className='text-sm text-muted'>{children}</div>
    </div>
  )
}

// One of the two "roads" — a bordered card. `accent` (Road B, the chosen one)
// gets the shared brand mesh ground so it reads as the answer; `muted` (Road
// A) stays plain white.
function Road({
  tag,
  title,
  points,
  tone,
}: {
  tag: string
  title: string
  points: string[]
  tone: 'muted' | 'accent'
}) {
  return (
    <div
      className='space-y-3 rounded-md border border-hairline p-5'
      style={tone === 'accent' ? { backgroundImage: PUSH_MESH } : undefined}
    >
      <div className='font-mono text-xs uppercase tracking-wide text-subtle'>{tag}</div>
      <div className='text-base font-medium'>{title}</div>
      <ul className='space-y-1.5 text-sm text-muted'>
        {points.map((p, i) => (
          <li key={i} className='flex gap-2'>
            <span aria-hidden className='select-none text-subtle'>
              —
            </span>
            <span>{p}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

// A numbered stage in the push pipeline: a badge plus a shared `Labeled` block.
function Step({ n, term, children }: { n: number; term: ReactNode; children: ReactNode }) {
  return (
    <li className='flex gap-3'>
      <span
        aria-hidden
        className='mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-hairline font-mono text-xs text-subtle'
      >
        {n}
      </span>
      <Labeled term={term}>{children}</Labeled>
    </li>
  )
}

export const getConfig = async () => {
  return {
    render: 'static',
  } as const
}
