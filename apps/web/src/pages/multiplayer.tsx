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
          Create a passkey identity. A single prompt derives an Ed25519 signing key from it via the WebAuthn PRF
          extension. From then on you sign commits in wasm and push them to a shared repository with no further prompts.
        </p>
        <p className='max-w-prose text-base text-fg'>
          Anyone can push, and the signature proves the same key made these commits, not who you are. Other
          players&rsquo; commits arrive live below.
        </p>
      </header>
      <DemoBoundary>
        <MultiplayerDemo />
      </DemoBoundary>
      <div className='max-w-prose space-y-3 text-sm text-muted'>
        <p>
          The passkey is a P-256 identity anchor your platform syncs. The Ed25519 signing key is re-derived from it each
          session and held only in memory, so there is no key file to lose. Same passkey → same Ed25519 public key → the
          same anonymous player no matter the device.
        </p>
        <p>
          Every push carries a signed request envelope (Ed25519 over a BLAKE3 digest of the canonical request), and the
          branch advances under a compare-and-set so concurrent pushes serialize cleanly. The wasm ConnectRPC client
          talks to a Cloudflare Worker (R2 objects + a Durable Object ref store); with no backend configured it falls
          back to an in-memory mock so the flow still runs offline.
        </p>
        <p>
          Curious about the underlying signature primitive? See the{' '}
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
