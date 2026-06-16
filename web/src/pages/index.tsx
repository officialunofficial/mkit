import { Link } from 'waku'
import { CopyButton } from '../components/copy-button'

export default function HomePage() {
  return (
    <div className='space-y-10'>
      <title>mkit demo</title>
      <section className='space-y-5'>
        <h1 className='text-5xl font-semibold tracking-tight'>Version control that signs itself.</h1>
        <p className='max-w-prose text-lg text-fg'>
          Every commit is signed with an Ed25519 key, so the history carries its own proof of who changed what. mkit
          names by content, too: every file, folder, and commit <em>is</em> the BLAKE3 hash of its bytes. Change one
          byte, get a new name. Any claim about a commit rides along as a signed statement anyone can verify: reviewed,
          tested, deployed. It&rsquo;s written in Rust, so it runs just about anywhere. Right now, that&rsquo;s your
          browser.
        </p>
        <div className='max-w-prose space-y-3'>
          <p className='text-sm text-muted'>
            mkit is git-like{' '}
            <Link
              to='/parity'
              className='underline underline-offset-4 transition-opacity duration-300 hover:opacity-70'
            >
              where it can be
            </Link>
            , and different where it counts: one hash algorithm, signatures on every commit, and attestations as
            first-class objects.
          </p>
          <p className='text-sm text-muted'>
            open source (alpha):{' '}
            <a
              href='https://github.com/officialunofficial/mkit'
              target='_blank'
              rel='noreferrer'
              className='underline underline-offset-4 transition-opacity duration-300 hover:opacity-70'
            >
              officialunofficial/mkit
            </a>{' '}
            on GitHub.
          </p>
          <div className='inline-flex items-center gap-3 rounded-md border border-hairline bg-muted/10 px-3 py-2'>
            <code className='font-mono text-sm'>
              <span className='select-none text-muted'>$ </span>cargo install mkit-cli
            </code>
            <CopyButton text='cargo install mkit-cli' />
          </div>
        </div>
      </section>

      <ul className='divide-y divide-hairline border-y border-hairline'>
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
        <Demo
          to='/attest'
          title='attest'
          body='Attach a signed statement to a commit so anyone with your public key can verify it later.'
        />
        <Demo
          to='/parity'
          title='parity'
          body='Which git commands mkit matches, where it diverges on purpose, and why it will never share bytes with a .git repo.'
        />
      </ul>
    </div>
  )
}

// `to` is narrowed to the concrete route literals Waku emits — a plain
// `string` is too wide for Waku 1.0.0-alpha.8's typed Link.
type DemoRoute = '/hash' | '/sign' | '/attest' | '/tree' | '/streaming' | '/performance' | '/parity'

function Demo({ to, title, body }: { to: DemoRoute; title: string; body: string }) {
  return (
    <li>
      <Link
        to={to}
        className='group flex items-start justify-between gap-6 py-5 transition-opacity duration-300 hover:opacity-70'
      >
        <div className='space-y-1'>
          <div className='text-base font-medium'>{title}</div>
          <p className='max-w-prose text-sm text-muted'>{body}</p>
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
