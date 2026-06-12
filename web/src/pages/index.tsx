import { Link } from 'waku'

export default function HomePage() {
  return (
    <div className='space-y-10'>
      <title>mkit demo</title>
      <section className='space-y-5'>
        <h1 className='text-5xl font-semibold tracking-tight'>A content-addressed VCS.</h1>
        <p className='max-w-prose text-lg text-[--color-fg]'>
          Content-addressed means the name of a thing <em>is</em> the BLAKE3 hash of its bytes — every file, folder, and
          commit. Change one byte, get a new name. Every commit is signed with an Ed25519 key, and any claim about a
          commit — reviewed, tested, deployed — travels as a signed statement anyone can verify. Written in Rust; here
          it runs in your browser.
        </p>
        <p className='max-w-prose text-sm text-[--color-muted]'>
          mkit is git-like where it can be — add, commit, branch, push — and different where it counts: one hash
          algorithm, signatures on every commit, attestations as first-class objects. Alpha, open source:{' '}
          <a
            href='https://github.com/officialunofficial/mkit'
            target='_blank'
            rel='noreferrer'
            className='underline underline-offset-4 transition-opacity duration-300 hover:opacity-70'
          >
            officialunofficial/mkit
          </a>{' '}
          on GitHub, <code className='font-mono'>cargo install mkit-cli</code> to try it.
        </p>
      </section>

      <ul className='divide-y divide-[--color-hairline] border-y border-[--color-hairline]'>
        <Demo
          to='/hash'
          title='hash'
          body='Edit a file and watch the BLAKE3 hashes of every container that holds it — folder, parent folder, commit — rewrite live.'
        />
        <Demo
          to='/sign'
          title='sign'
          body='Generate a key, sign a message, flip a character, watch the verifier reject it.'
        />
        <Demo
          to='/attest'
          title='attest'
          body='Attach a signed statement to a commit so anyone with your public key can verify it later.'
        />
        <Demo
          to='/tree'
          title='tree'
          body='A Merkle tree of BLAKE3 hashes — edit any file and the hashes ripple up to the commit at the root.'
        />
        <Demo
          to='/streaming'
          title='streaming'
          body='Edit a 2 GB video and git stores it again, whole. mkit cuts it into chunks, ships only the changed ones, and verifies each chunk as it streams in.'
        />
        <Demo
          to='/performance'
          title='performance'
          body='Hashing, committing, packing — mkit measured against git on real operations.'
        />
      </ul>
    </div>
  )
}

// `to` is narrowed to the concrete route literals Waku emits — a plain
// `string` is too wide for Waku 1.0.0-alpha.8's typed Link.
type DemoRoute = '/hash' | '/sign' | '/attest' | '/tree' | '/streaming' | '/performance'

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
