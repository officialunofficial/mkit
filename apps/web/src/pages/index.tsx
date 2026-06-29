import { Link } from 'waku'
import { CopyButton } from '../components/copy-button'
import { DemoBoundary } from '../components/demo-boundary'
import { SignedLobby } from '../components/lobby/signed-lobby'
import { Seo } from '../components/seo'

export default function HomePage() {
  return (
    <div className='space-y-10'>
      <Seo
        title='mkit — version control that signs every commit'
        description='Version control that signs every commit. Every commit carries an Ed25519 signature; every file, folder, and commit is named by its BLAKE3 hash; attestations are first-class objects. Written in Rust.'
        path='/'
        card='Version control that signs every commit.'
      />

      {/* Above-the-fold: the live lobby beside the hero. Two columns on lg+
          (lobby left, hero right); stacks to one column below that with the
          LOBBY on top, then the hero. `items-start` so each column sizes to its
          own content instead of stretching to match the taller one. */}
      <div className='grid grid-cols-1 gap-8 lg:grid-cols-2 lg:items-start'>
        {/* Signed lobby — a live, public feed merging chat, /multiplayer commits,
            and emoji reactions, all Ed25519-signed by the same passkey identity.
            Reading is open; posting/reacting unlock that identity. DemoBoundary
            lets the static prerender emit a fallback and hydrate the wasm-backed
            client. */}
        <section>
          <DemoBoundary>
            <SignedLobby />
          </DemoBoundary>
        </section>

        <section className='space-y-5'>
          <h1 className='text-5xl font-semibold tracking-tight'>Sign every commit. Know every contributor.</h1>
          <p className='max-w-prose text-lg text-fg'>
            Every commit is cryptographically signed, so anyone can contribute and everyone can verify who did what.
          </p>
          <p className='max-w-prose text-sm text-muted'>
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
        </section>
      </div>

      {/* Full-width "get started" band beneath the split hero: the two install
          paths side by side, with the open-source note. Pulled out of the hero's
          right column so the install commands aren't cramped against the lobby. */}
      <section className='space-y-5'>
        <h2 className='text-2xl font-semibold tracking-tight'>Get started with mkit</h2>
        <div className='grid gap-4 sm:grid-cols-2'>
          <div className='space-y-2'>
            <p className='text-sm font-medium'>Install the CLI</p>
            {/* Primary install: the hosted one-liner. Bare `mkit.sh` sniffs the
              curl User-Agent and serves the signed installer (see
              src/install-route.ts); it detects your platform, verifies the
              cosign signature, and drops `mkit` into ~/.local/bin. */}
            <InstallCommand command='curl mkit.sh | sh' />
            <p className='text-sm text-muted'>
              Detects your platform, verifies the cosign signature, and drops <code className='font-mono'>mkit</code>{' '}
              into <code className='font-mono'>~/.local/bin</code>.
            </p>
          </div>
          <div className='space-y-2'>
            <p className='text-sm font-medium'>Add the agent skill</p>
            {/* Install the mkit agent skill (repo-root SKILL.md) into Claude Code
              / Cursor / etc. via the vercel-labs `skills` CLI. */}
            <InstallCommand command='npx skills add officialunofficial/mkit' />
            <p className='text-sm text-muted'>Teaches Claude Code, Cursor, and other coding agents to drive mkit.</p>
          </div>
        </div>
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
      </section>

      <ul className='grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-4'>
        <Demo
          to='/demos'
          title='demos'
          body='Six playgrounds in one: hashing, the Merkle tree, signatures, chunked streaming, pushes, and attestations — each one live, right in your browser.'
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
          to='/multiplayer'
          title='multiplayer'
          body='Set up a passkey, sign a commit in your browser, and push to a shared repo — then watch everyone else’s commits arrive live.'
        />
      </ul>
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
type DemoRoute = '/demos' | '/performance' | '/parity' | '/multiplayer'

// Soft per-tile mesh gradients: layered low-alpha radial blooms over the
// white card so text stays legible while each tile reads distinct.
const MESH: Record<DemoRoute, string> = {
  '/demos':
    'radial-gradient(at 18% 22%, rgba(99,102,241,0.10), transparent 55%), radial-gradient(at 82% 12%, rgba(56,189,248,0.08), transparent 55%)',
  '/performance':
    'radial-gradient(at 18% 18%, rgba(251,146,60,0.09), transparent 55%), radial-gradient(at 82% 80%, rgba(248,113,113,0.08), transparent 55%)',
  '/parity':
    'radial-gradient(at 16% 20%, rgba(167,139,250,0.09), transparent 55%), radial-gradient(at 84% 80%, rgba(96,165,250,0.08), transparent 55%)',
  '/multiplayer':
    'radial-gradient(at 20% 20%, rgba(236,72,153,0.10), transparent 55%), radial-gradient(at 80% 78%, rgba(99,102,241,0.08), transparent 55%)',
}

// Per-tile accent colour (solid hue echoing each tile's mesh) for the header shape.
const SHAPE_COLOR: Record<DemoRoute, string> = {
  '/demos': 'rgb(99,102,241)',
  '/performance': 'rgb(249,115,22)',
  '/parity': 'rgb(139,92,246)',
  '/multiplayer': 'rgb(236,72,153)',
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
      case '/demos':
        return (
          <>
            <rect x='3' y='3' width='4' height='4' rx='1' />
            <rect x='9' y='3' width='4' height='4' rx='1' />
            <rect x='3' y='9' width='4' height='4' rx='1' />
            <rect x='9' y='9' width='4' height='4' rx='1' />
          </>
        )
      case '/performance':
        return <path d='M3 13 V9 M8 13 V4 M13 13 V7' strokeLinecap='round' />
      case '/parity':
        return (
          <>
            <circle cx='6' cy='8' r='4' />
            <circle cx='10' cy='8' r='4' />
          </>
        )
      case '/multiplayer':
        return (
          <>
            <circle cx='6' cy='6.5' r='2.5' />
            <circle cx='11' cy='10' r='2.5' />
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
