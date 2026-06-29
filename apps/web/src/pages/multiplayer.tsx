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
        <p className='max-w-prose text-base text-muted'>
          Everyone shares one repository. Contribute alongside others by pushing commits to a branch (or starting a new
          one).
        </p>
      </header>
      <DemoBoundary>
        <MultiplayerDemo />
      </DemoBoundary>
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
