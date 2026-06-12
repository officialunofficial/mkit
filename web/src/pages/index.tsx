import type { CSSProperties } from 'react'
import { Link } from 'waku'

/** Inline helper for the staggered page-load reveal — `--reveal` indexes the animation delay. */
const reveal = (i: number): CSSProperties => ({ '--reveal': i }) as CSSProperties

export default function HomePage() {
  return (
    <div className='space-y-14'>
      <title>mkit demo</title>
      <section className='space-y-6 pt-6'>
        <p className='microlabel reveal text-accent' style={reveal(0)}>
          A content-addressed VCS · Rust / WASM · alpha
        </p>
        <h1 className='reveal max-w-[16ch] text-6xl font-light sm:text-7xl' style={reveal(1)}>
          Every byte has a <em className='font-normal'>name</em>.
        </h1>
        <p className='reveal max-w-prose text-lg' style={reveal(2)}>
          Content-addressed means the name of a thing <em>is</em> the BLAKE3 hash of its bytes — every file, folder, and
          commit. Change one byte, get a new name. Every commit is signed with an Ed25519 key, and any claim about a
          commit — reviewed, tested, deployed — travels as a signed statement anyone can verify. Written in Rust; here
          it runs in your browser.
        </p>
        <p className='reveal max-w-prose text-sm text-muted' style={reveal(3)}>
          mkit is git-like where it can be — add, commit, branch, push — and different where it counts: one hash
          algorithm, signatures on every commit, attestations as first-class objects. Alpha, open source:{' '}
          <a
            href='https://github.com/officialunofficial/mkit'
            target='_blank'
            rel='noreferrer'
            className='underline underline-offset-4 transition-colors duration-200 hover:text-fg'
          >
            officialunofficial/mkit
          </a>{' '}
          on GitHub, <code className='font-mono text-[0.85em]'>cargo install mkit-cli</code> to try it.
        </p>
      </section>

      <section className='reveal' style={reveal(4)}>
        <div className='microlabel flex items-baseline justify-between border-b-2 border-fg pb-2 text-muted'>
          <span>Table of contents</span>
          <span aria-hidden>Folio</span>
        </div>
        <ul className='divide-y divide-hairline'>
          <Demo
            n={1}
            to='/hash'
            title='hash'
            body='Edit a file and watch the BLAKE3 hashes of every container that holds it — folder, parent folder, commit — rewrite live.'
          />
          <Demo
            n={2}
            to='/sign'
            title='sign'
            body='Generate a key, sign a message, flip a character, watch the verifier reject it.'
          />
          <Demo
            n={3}
            to='/tree'
            title='tree'
            body='A Merkle tree of BLAKE3 hashes — edit any file and the hashes ripple up to the commit at the root.'
          />
          <Demo
            n={4}
            to='/streaming'
            title='streaming'
            body='Edit a 2 GB video and git stores it again, whole. mkit cuts it into chunks, ships only the changed ones, and verifies each chunk as it streams in.'
          />
          <Demo
            n={5}
            to='/performance'
            title='performance'
            body='Hashing, committing, packing — mkit measured against git on real operations.'
          />
          <Demo
            n={6}
            to='/attest'
            title='attest'
            body='Attach a signed statement to a commit so anyone with your public key can verify it later.'
          />
        </ul>
      </section>
    </div>
  )
}

// `to` is narrowed to the concrete route literals Waku emits — a plain
// `string` is too wide for Waku's typed Link.
type DemoRoute = '/hash' | '/sign' | '/attest' | '/tree' | '/streaming' | '/performance'

function Demo({ n, to, title, body }: { n: number; to: DemoRoute; title: string; body: string }) {
  return (
    <li className='reveal' style={reveal(4 + n)}>
      <Link to={to} className='group block py-5'>
        {/* TOC row: folio number, entry title, dot leader out to the
            arrow — the classic contents-page idiom. */}
        <div className='flex items-baseline gap-4'>
          <span className='microlabel w-7 shrink-0 text-subtle transition-colors duration-200 group-hover:text-accent'>
            {String(n).padStart(2, '0')}
          </span>
          <span className='text-2xl tracking-tight transition-colors duration-200 group-hover:text-accent'>
            {title}
          </span>
          <span className='toc-leader group-hover:border-accent' aria-hidden />
          <span
            aria-hidden
            className='shrink-0 font-mono text-base transition-all duration-300 ease-[cubic-bezier(0.2,0,0,1)] group-hover:translate-x-1 group-hover:text-accent'
          >
            →
          </span>
        </div>
        <p className='mt-1 max-w-prose pl-11 text-sm text-muted'>{body}</p>
      </Link>
    </li>
  )
}

export const getConfig = async () => {
  return {
    render: 'static',
  } as const
}
