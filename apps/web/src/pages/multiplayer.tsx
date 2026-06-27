import { Link } from 'waku'
import { DemoBoundary } from '../components/demo-boundary'
import { MultiplayerDemo } from '../components/multiplayer-demo'
import { Seo } from '../components/seo'

export default function MultiplayerPage() {
  return (
    <div className='space-y-8'>
      <Seo
        title='mkit — multiplayer'
        description='Set up a passkey, sign a commit right in your browser, and push it to a shared room — then watch other players’ commits arrive live. Anonymous, no accounts: your passkey is your identity.'
        path='/multiplayer'
        card='Multiplayer mkit'
      />
      <header className='space-y-3'>
        <h1 className='text-4xl font-semibold tracking-tight'>Multiplayer mkit</h1>
        <p className='max-w-prose text-base text-fg'>
          Set up a passkey, then sign commits and push them to a shared room — one prompt, no accounts, no further
          sign-ins. Anyone can push; the signature proves the same person made these commits, not who you are. Watch
          other players&rsquo; commits arrive live below.
        </p>
      </header>
      <DemoBoundary>
        <MultiplayerDemo />
      </DemoBoundary>
      <div className='max-w-prose space-y-3 text-sm text-muted'>
        <p>
          Your passkey is synced by your device&rsquo;s platform and anchors your identity; the signing key is rebuilt
          from it each session and never written to disk. Same passkey → same player, on every device.
        </p>
        <p>
          Every push is signed, and updates apply one at a time so concurrent pushes never clobber each other. It talks
          to a small server that stores the commits and tracks where each room&rsquo;s history points; with no server
          configured it runs against an in-browser stand-in, so the flow still works offline.
        </p>
        <p>
          Curious how the signing works? See the{' '}
          <a
            href='/demos#sign'
            className='underline underline-offset-4 transition-opacity duration-300 hover:opacity-70'
          >
            sign
          </a>{' '}
          demo.
        </p>
      </div>
      <Link
        to='/'
        className='-mx-2 inline-block px-2 py-2 text-sm underline underline-offset-4 transition-opacity duration-300 hover:opacity-70'
      >
        ← back
      </Link>
    </div>
  )
}

export const getConfig = async () => {
  return {
    render: 'static',
  } as const
}
