import { Link } from 'waku'
import { CopyButton } from '../components/copy-button'
import { DemoBoundary } from '../components/demo-boundary'
import { SignedLobby } from '../components/lobby/signed-lobby'
import { Seo } from '../components/seo'
import { PUSH_MESH } from '../lib/mesh'

export default function HomePage() {
  return (
    <div className='space-y-10'>
      <Seo
        title='mkit — version control that signs every commit'
        description='Version control that signs every commit. Every commit carries an Ed25519 signature; every file, folder, and commit is named by its BLAKE3 hash; attestations are first-class objects. Written in Rust.'
        path='/'
        card='Version control that signs every commit.'
      />
      <section className='space-y-5'>
        <h1 className='text-5xl font-semibold tracking-tight'>Version control that signs every commit.</h1>
        <p className='max-w-prose text-lg text-fg'>
          mkit signs every commit and names every file, folder, and commit by its BLAKE3 hash. Change a byte, get a new
          name. Claims about a commit — reviewed, tested, deployed — travel as signed statements anyone can verify.
        </p>
        <p className='max-w-prose text-lg text-fg'>
          It&rsquo;s written in Rust, so it runs anywhere, including this browser.
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
            , and divergent where it counts: one hash algorithm, a signature on every commit, and attestations as
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
            <InstallCommand command='curl mkit.sh | sh' />
            {/* Install the mkit agent skill (repo-root SKILL.md) into Claude Code
                / Cursor / etc. via the vercel-labs `skills` CLI. */}
            <InstallCommand command='npx skills add officialunofficial/mkit' />
          </div>
        </div>
      </section>

      <ul className='grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-4'>
        <Demo
          to='/tree'
          title='tree'
          body='A Merkle tree of BLAKE3 hashes — edit any file and the hashes ripple up to the commit at the root.'
        />
        <Demo
          to='/performance'
          title='performance'
          body='Hashing, committing, packing — mkit measured against git on real operations.'
        />
        <Demo
          to='/parity'
          title='parity'
          body='Which git commands mkit matches, where it diverges on purpose, and why it will never share bytes with a .git repo.'
        />
        <Demo
          to='/push'
          title='push'
          body='Push a file and watch mkit chunk and hash it. Why a small edit on any size file ships only the bytes that changed.'
        />
        <Demo
          to='/demos'
          title='demos'
          body='Hashing, signatures, chunked streaming, and attestations. Four primitives, each a live wasm demo.'
        />
      </ul>

      {/* Signed lobby: a live, public feed that merges chat messages and
          /multiplayer commits — both Ed25519-signed by the same passkey-derived
          identity. Reading is open; posting unlocks the same identity the
          multiplayer demo uses. Wrapped in DemoBoundary so the static prerender
          emits a fallback and hydrates the wasm-backed client on the client. */}
      <section className='space-y-3'>
        <p className='max-w-prose text-sm text-muted text-pretty'>
          The same key signs your chat and your commits alike. Both land on the feed below — messages and{' '}
          <Link
            to='/multiplayer'
            className='underline underline-offset-4 transition-opacity duration-300 hover:opacity-70'
          >
            multiplayer
          </Link>{' '}
          commits together, every entry signed.
        </p>
        <DemoBoundary>
          <SignedLobby />
        </DemoBoundary>
      </section>
    </div>
  )
}

// A copyable shell command, rendered as a `$`-prefixed code chip. Long commands
// scroll horizontally rather than wrapping.
function InstallCommand({ command }: { command: string }) {
  return (
    <div className='inline-flex max-w-full items-center gap-3 overflow-x-auto rounded-md border border-hairline bg-muted/5 px-3 py-2'>
      <code className='whitespace-nowrap font-mono text-sm'>
        <span className='select-none text-muted'>$ </span>
        {command}
      </code>
      <CopyButton text={command} />
    </div>
  )
}

// `to` is narrowed to the concrete route literals Waku emits — a plain
// `string` is too wide for Waku 1.0.0-alpha.8's typed Link.
type DemoRoute = '/tree' | '/performance' | '/parity' | '/push' | '/demos'

// Soft per-tile mesh gradients: layered low-alpha radial blooms over the
// white card so text stays legible while each tile reads distinct.
const MESH: Record<DemoRoute, string> = {
  '/tree':
    'radial-gradient(at 15% 25%, rgba(45,212,191,0.10), transparent 55%), radial-gradient(at 80% 15%, rgba(132,204,22,0.08), transparent 55%)',
  '/performance':
    'radial-gradient(at 18% 18%, rgba(251,146,60,0.09), transparent 55%), radial-gradient(at 82% 80%, rgba(248,113,113,0.08), transparent 55%)',
  '/parity':
    'radial-gradient(at 16% 20%, rgba(167,139,250,0.09), transparent 55%), radial-gradient(at 84% 80%, rgba(96,165,250,0.08), transparent 55%)',
  '/push': PUSH_MESH,
  '/demos':
    'radial-gradient(at 18% 22%, rgba(99,102,241,0.10), transparent 55%), radial-gradient(at 82% 12%, rgba(56,189,248,0.08), transparent 55%)',
}

// Per-tile accent colour (solid hue echoing each tile's mesh) for the header shape.
const SHAPE_COLOR: Record<DemoRoute, string> = {
  '/tree': 'rgb(20,184,166)',
  '/performance': 'rgb(249,115,22)',
  '/parity': 'rgb(139,92,246)',
  '/push': 'rgb(202,138,4)',
  '/demos': 'rgb(99,102,241)',
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
      case '/tree':
        return <circle cx='8' cy='8' r='5' />
      case '/performance':
        return <path d='M3 13 V9 M8 13 V4 M13 13 V7' strokeLinecap='round' />
      case '/parity':
        return (
          <>
            <circle cx='6' cy='8' r='4' />
            <circle cx='10' cy='8' r='4' />
          </>
        )
      case '/push':
        return (
          <>
            <rect x='3' y='3.5' width='10' height='2.5' rx='0.8' />
            <rect x='3' y='6.75' width='10' height='2.5' rx='0.8' />
            <rect x='3' y='10' width='10' height='2.5' rx='0.8' />
          </>
        )
      case '/demos':
        return (
          <>
            <rect x='3' y='3' width='4' height='4' rx='1' />
            <rect x='9' y='3' width='4' height='4' rx='1' />
            <rect x='3' y='9' width='4' height='4' rx='1' />
            <rect x='9' y='9' width='4' height='4' rx='1' />
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
