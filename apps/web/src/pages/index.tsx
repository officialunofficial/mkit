import { ArrowUpRightIcon, FlaskIcon, GaugeIcon, GitDiffIcon, UsersThreeIcon } from '@phosphor-icons/react/ssr'
import { Link } from 'waku'
import { CopyButton } from '../components/copy-button'
import { NavCardLink } from '../components/nav-card'
import { DemoBoundary } from '../components/demo-boundary'
import { SignedLobby } from '../components/lobby/signed-lobby'
import { LobbySkeleton } from '../components/loading'
import { Seo } from '../components/seo'

export default function HomePage() {
  return (
    <div className='space-y-8'>
      <Seo
        title='mkit — version control that signs every commit'
        description='Version control that signs every commit. Every commit carries an Ed25519 signature; every file, folder, and commit is named by its BLAKE3 hash; attestations record signed statements about commits. Written in Rust.'
        path='/'
        card='Version control that signs every commit.'
      />

      {/* Above the fold: the claim beside the live lobby. Two columns at lg
          (claim left, lobby right); stacks below with the claim on top so a
          reader meets the thesis before the demo. */}
      <div className='grid grid-cols-1 gap-x-3 gap-y-8 lg:grid-cols-2 lg:items-start'>
        <section>
          <h1 className='ds-h1'>Version control with signed commits</h1>
          <p className='ds-note mt-1'>A content-addressed version control toolkit, written in Rust.</p>
          <p className='mt-2 max-w-prose'>
            Every commit has an Ed25519 signature that you can verify against the signing key. mkit supports{' '}
            <Link to='/parity' className='ds-link'>
              familiar Git commands
            </Link>
            . It uses BLAKE3 object IDs and stores signed attestations about commits.
          </p>

          <h2 className='ds-h2 rule-square mt-8 pb-2'>Get started</h2>
          <div className='mt-2 space-y-6'>
            <div>
              <h3 className='ds-h3'>Install the CLI</h3>
              {/* Bare `mkit.sh` sniffs the curl User-Agent and serves the signed
                  installer (see src/install-route.ts). */}
              <InstallCommand command='curl mkit.sh | sh' label='Copy CLI install command' />
              <p className='mt-2 max-w-prose text-xs leading-4'>
                Detects your platform, verifies the cosign signature, and installs <code>mkit</code> into{' '}
                <code>~/.local/bin</code>.
              </p>
            </div>
            <div>
              <h3 className='ds-h3'>Add the agent skill</h3>
              <InstallCommand command='npx skills add officialunofficial/mkit' label='Copy skill install command' />
              <p className='mt-2 max-w-prose text-xs leading-4'>
                Teaches Claude Code, Cursor, and other coding agents to use mkit.
              </p>
            </div>
            <p className='ds-note'>
              <a
                href='https://github.com/officialunofficial/mkit'
                target='_blank'
                rel='noreferrer'
                className='ds-link inline-flex items-center gap-0.5'
              >
                View source on GitHub
                <ArrowUpRightIcon size={12} aria-hidden />
                <span className='sr-only'>(opens in a new tab)</span>
              </a>
            </p>
          </div>
        </section>

        {/* Signed lobby — a live, public feed merging chat, /multiplayer
            commits, and emoji reactions, all Ed25519-signed by the same
            passkey identity. DemoBoundary lets the static prerender emit a
            fallback and hydrate the wasm-backed client. */}
        <section>
          <DemoBoundary fallback={<LobbySkeleton />}>
            <SignedLobby />
          </DemoBoundary>
        </section>
      </div>

      <section>
        <h2 className='ds-h2 rule-square pb-2'>Explore</h2>
        <ul className='mt-2 grid grid-cols-1 gap-3 sm:grid-cols-2'>
          <NavCardLink
            to='/concepts'
            title='Concepts'
            icon={<FlaskIcon size={12} aria-hidden />}
            body='Try hashing, Merkle trees, signatures, chunked streaming, pushes, and attestations in your browser.'
          />
          <NavCardLink
            to='/performance'
            title='Performance'
            icon={<GaugeIcon size={12} aria-hidden />}
            body='Compare mkit and Git command timings, storage use, and transfer sizes.'
          />
          <NavCardLink
            to='/parity'
            title='Parity'
            icon={<GitDiffIcon size={12} aria-hidden />}
            body='Compare supported Git commands and flags, documented differences, and repository formats.'
          />
          <NavCardLink
            to='/multiplayer'
            title='Multiplayer'
            icon={<UsersThreeIcon size={12} aria-hidden />}
            body='Create a passkey, sign a commit, and push to a shared repository. See other contributions as they arrive.'
          />
        </ul>
      </section>
    </div>
  )
}

/**
 * A copyable shell command, rendered per §4.29: surface-code fill, solid light border, square corners, mono at text-sm.
 * The copy control is the head band's trailing control (§4.29 rules 7–8) — a block with a copy control and no label
 * still draws the band, so the control has somewhere to sit.
 */
function InstallCommand({ command, label }: { command: string; label: string }) {
  return (
    <div className='code-region mt-2 max-w-full p-0'>
      <div
        className='flex items-center justify-between border-b px-2 py-1'
        style={{ borderColor: 'var(--border-color-default)' }}
      >
        <span className='font-sans text-xs leading-4 font-semibold tracking-(--header-tracking)'>sh</span>
        <CopyButton text={command} label={label} />
      </div>
      <code className='block overflow-x-auto px-2 py-1.5 whitespace-nowrap'>
        <span className='select-none text-secondary'>$ </span>
        {command}
      </code>
    </div>
  )
}

export const getConfig = async () => {
  return {
    render: 'static',
  } as const
}
