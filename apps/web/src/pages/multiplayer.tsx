import { Link } from 'waku'
import { DemoBoundary } from '../components/demo-boundary'
import { MultiplayerDemo } from '../components/multiplayer-demo'
import { Seo } from '../components/seo'

export default function MultiplayerPage() {
  return (
    <div className='space-y-8'>
      <Seo
        title='mkit — multiplayer'
        description='Set up a passkey, sign a commit right in your browser, and push it to a shared repo — then watch other players’ commits arrive live. Anonymous, no accounts: your passkey is your identity.'
        path='/multiplayer'
        card='Multiplayer mkit'
      />
      <header className='space-y-3'>
        <h1 className='text-4xl font-semibold tracking-tight'>Multiplayer mkit</h1>
      </header>
      <DemoBoundary>
        <MultiplayerDemo />
      </DemoBoundary>
      <div className='max-w-prose space-y-3 text-sm text-muted'>
        <p>
          Your passkey anchors your identity and rebuilds your signing key each session without ever writing it to disk,
          so the same passkey is the same player on every device.
        </p>
        <p>
          Every push is signed and updates apply one at a time, so concurrent pushes never clobber each other — and with
          no server it runs against an in-browser stand-in that still works offline.
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
