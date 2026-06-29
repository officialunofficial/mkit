import { Link } from 'waku'
import { DemoBoundary } from '../components/demo-boundary'
import { MultiplayerDemo } from '../components/multiplayer-demo'
import { Seo } from '../components/seo'

export default function MultiplayerPage() {
  return (
    <div className='space-y-8'>
      <Seo
        title='mkit — multiplayer'
        description='Enroll a passkey, derive an Ed25519 signing key from it in your browser, sign an mkit commit in wasm, and push it to a shared repository — then watch other players’ commits arrive live. Anonymous, no accounts: the key is the identity.'
        path='/multiplayer'
        card='Multiplayer mkit'
      />
      <header className='space-y-3'>
        <h1 className='text-4xl font-semibold tracking-tight'>Multiplayer mkit</h1>
        <p className='max-w-prose text-base text-fg'>
          Create a passkey identity — one prompt derives an Ed25519 signing key from it via the WebAuthn PRF extension —
          then sign commits in wasm and push them to a shared repository with no further prompts. Anyone can push; the
          signature proves “the same key made these commits,” not who you are. Watch other players&rsquo; commits arrive
          live below.
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
