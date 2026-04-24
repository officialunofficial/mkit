import { Link } from 'waku'

export default function HomePage() {
  return (
    <div className='space-y-10'>
      <title>mkit demo</title>
      <section className='space-y-5'>
        <h1 className='text-5xl font-semibold tracking-tight'>A content-addressed VCS.</h1>
        <p className='max-w-prose text-lg text-[--color-fg]'>
          Every object BLAKE3-addressed. Every commit Ed25519-signed. Every review a DSSE attestation. Written in Rust —
          here it runs in your browser.
        </p>
      </section>

      <ul className='divide-y divide-[--color-hairline] border-y border-[--color-hairline]'>
        <Demo
          to='/hash'
          title='hash'
          body='Edit a blob. Watch its BLAKE3 id and the enclosing tree and commit hashes rewrite live.'
        />
        <Demo to='/sign' title='sign' body='Generate an Ed25519 key, sign a message, flip a byte, watch verify fail.' />
        <Demo
          to='/attest'
          title='attest'
          body='Wrap a commit hash in an in-toto Statement, seal it in a DSSE envelope, verify it back.'
        />
        <Demo
          to='/tree'
          title='tree'
          body='Nest a tree inside a tree; watch the parent hash rewrite as children shuffle and rename.'
        />
      </ul>
    </div>
  )
}

// `to` is narrowed to the concrete route literals Waku emits — a plain
// `string` is too wide for Waku 1.0.0-alpha.8's typed Link.
type DemoRoute = '/hash' | '/sign' | '/attest' | '/tree'

function Demo({ to, title, body }: { to: DemoRoute; title: string; body: string }) {
  return (
    <li>
      <Link
        to={to}
        className='group flex items-start justify-between gap-6 py-5 transition-opacity duration-300 hover:opacity-70'
      >
        <div className='space-y-1'>
          <div className='text-base font-medium'>{title}</div>
          <p className='max-w-prose text-sm text-[--color-muted]'>{body}</p>
        </div>
        <span
          aria-hidden
          className='mt-0.5 shrink-0 text-base transition-transform duration-300 ease-[cubic-bezier(0.2,0,0,1)] group-hover:translate-x-1'
        >
          →
        </span>
      </Link>
    </li>
  )
}

export const getConfig = async () => {
  return {
    render: 'static',
  } as const
}
