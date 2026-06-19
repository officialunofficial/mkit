import { Link } from 'waku'
import { CopyButton } from '../components/copy-button'
import { Seo } from '../components/seo'

export default function HomePage() {
  return (
    <div className='space-y-10'>
      <Seo
        title='mkit — version control that signs itself'
        description='Version control that signs itself. Every commit carries an Ed25519 signature; every file, folder, and commit is named by its BLAKE3 hash; attestations are first-class objects. Written in Rust.'
        path='/'
        card='Version control that signs itself.'
      />
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
          <div className='flex flex-col items-start gap-2'>
            {/* Primary install: the hosted one-liner. Bare `mkit.sh` sniffs the
                curl User-Agent and serves the signed installer (see
                src/install-route.ts); it detects your platform, verifies the
                cosign signature, and drops `mkit` into ~/.local/bin. */}
            <div className='inline-flex items-center gap-3 rounded-md border border-hairline bg-muted/10 px-3 py-2'>
              <code className='font-mono text-sm'>
                <span className='select-none text-muted'>$ </span>curl mkit.sh | sh
              </code>
              <CopyButton text='curl mkit.sh | sh' />
            </div>
            {/* Install the mkit agent skill (SKILL.md at the repo root) into
                Claude Code / Cursor / etc. via the vercel-labs `skills` CLI. */}
            <div className='inline-flex max-w-full items-center gap-3 overflow-x-auto rounded-md border border-hairline bg-muted/10 px-3 py-2'>
              <code className='whitespace-nowrap font-mono text-sm'>
                <span className='select-none text-muted'>$ </span>npx skills add officialunofficial/mkit
              </code>
              <CopyButton text='npx skills add officialunofficial/mkit' />
            </div>
          </div>
        </div>
      </section>

      <ul className='grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4'>
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

// Soft per-tile mesh gradients: layered low-alpha radial blooms over the
// white card so text stays legible while each tile reads distinct.
const MESH: Record<DemoRoute, string> = {
  '/hash':
    'radial-gradient(at 18% 22%, rgba(99,102,241,0.10), transparent 55%), radial-gradient(at 82% 12%, rgba(56,189,248,0.08), transparent 55%)',
  '/sign':
    'radial-gradient(at 20% 18%, rgba(244,114,182,0.09), transparent 55%), radial-gradient(at 85% 80%, rgba(251,191,36,0.08), transparent 55%)',
  '/tree':
    'radial-gradient(at 15% 25%, rgba(45,212,191,0.10), transparent 55%), radial-gradient(at 80% 15%, rgba(132,204,22,0.08), transparent 55%)',
  '/streaming':
    'radial-gradient(at 22% 20%, rgba(56,189,248,0.09), transparent 55%), radial-gradient(at 78% 82%, rgba(167,139,250,0.08), transparent 55%)',
  '/performance':
    'radial-gradient(at 18% 18%, rgba(251,146,60,0.09), transparent 55%), radial-gradient(at 82% 80%, rgba(248,113,113,0.08), transparent 55%)',
  '/attest':
    'radial-gradient(at 20% 22%, rgba(52,211,153,0.09), transparent 55%), radial-gradient(at 80% 14%, rgba(45,212,191,0.08), transparent 55%)',
  '/parity':
    'radial-gradient(at 16% 20%, rgba(167,139,250,0.09), transparent 55%), radial-gradient(at 84% 80%, rgba(96,165,250,0.08), transparent 55%)',
}

// Per-tile accent colour (solid hue echoing each tile's mesh) for the header shape.
const SHAPE_COLOR: Record<DemoRoute, string> = {
  '/hash': 'rgb(99,102,241)',
  '/sign': 'rgb(244,114,182)',
  '/tree': 'rgb(20,184,166)',
  '/streaming': 'rgb(56,189,248)',
  '/performance': 'rgb(249,115,22)',
  '/attest': 'rgb(16,185,129)',
  '/parity': 'rgb(139,92,246)',
}

// A small distinct geometric mark per tile, drawn in the tile's accent colour.
function TileShape({ to }: { to: DemoRoute }) {
  const common = {
    width: 16,
    height: 16,
    viewBox: '0 0 16 16',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.5,
  } as const
  const shape = (() => {
    switch (to) {
      case '/hash':
        return <rect x='3' y='3' width='10' height='10' rx='2' />
      case '/sign':
        return <path d='M8 3 L13 13 L3 13 Z' strokeLinejoin='round' />
      case '/tree':
        return <circle cx='8' cy='8' r='5' />
      case '/streaming':
        return <path d='M8 2 L14 8 L8 14 L2 8 Z' strokeLinejoin='round' />
      case '/performance':
        return <path d='M3 13 V9 M8 13 V4 M13 13 V7' strokeLinecap='round' />
      case '/attest':
        return <path d='M8 2 L13.2 5 V11 L8 14 L2.8 11 V5 Z' strokeLinejoin='round' />
      case '/parity':
        return (
          <>
            <circle cx='6' cy='8' r='4' />
            <circle cx='10' cy='8' r='4' />
          </>
        )
    }
  })()
  return (
    <svg {...common} aria-hidden style={{ color: SHAPE_COLOR[to] }} className='shrink-0'>
      {shape}
    </svg>
  )
}

function Demo({ to, title, body }: { to: DemoRoute; title: string; body: string }) {
  return (
    <li>
      <Link
        to={to}
        style={{ backgroundImage: MESH[to] }}
        className='group flex aspect-square flex-col justify-between gap-4 overflow-hidden rounded-md border border-hairline p-5 transition-transform duration-300 ease-[cubic-bezier(0.2,0,0,1)] hover:scale-95'
      >
        <div className='space-y-1'>
          <div className='flex items-center gap-2 text-base font-medium'>
            <TileShape to={to} />
            {title}
          </div>
          <p className='text-sm text-muted'>{body}</p>
        </div>
        <span
          aria-hidden
          className='shrink-0 self-end text-base transition-transform duration-300 ease-[cubic-bezier(0.2,0,0,1)] group-hover:-translate-y-1 group-hover:translate-x-1'
        >
          ↗
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
