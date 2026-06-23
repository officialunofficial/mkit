import { Link } from 'waku'
import { DemoBoundary } from '../components/demo-boundary'
import { PushDemo } from '../components/push-demo'
import { Seo } from '../components/seo'

export default function PushPage() {
  return (
    <div className='space-y-8'>
      <Seo
        title='mkit — push'
        description='Watch what mkit does with a file you push: it splits the file into content-defined chunks named by their hashes, ships only the chunks that changed, and folds them into a Merkle root that becomes the new id.'
        path='/push'
        card='Push a file, any file'
      />
      <header className='space-y-3'>
        <h1 className='text-4xl font-semibold tracking-tight'>Push a file, any file</h1>
        <p className='max-w-prose text-base text-fg'>
          When you push a file, mkit splits it into chunks and names each by its hash. Change the file, and only the
          changed chunks get new names — so the push ships just those. Step through it below.
        </p>
      </header>
      <DemoBoundary>
        <PushDemo />
      </DemoBoundary>
      <div className='max-w-prose space-y-3 text-sm text-muted'>
        <p>
          Why address a file by its Merkle root? Because the root <em>is</em> the id. Read the file back, re-derive the
          root, and you&rsquo;ve proven every chunk intact — integrity lives in the name, not in a separate checksum.
        </p>
        <p>
          The same root lets a client verify that one chunk belongs to the file without fetching the rest. And a{' '}
          {/* Raw <a>, not Waku's <Link>: the typed Link only accepts the bare route literals it emits ("/demos"),
              with no `#fragment`. A full document load to /demos#sign is fine here — demos-tabs reads the hash on
              mount to open the sign tab. */}
          <a
            href='/demos#sign'
            className='underline underline-offset-4 transition-opacity duration-300 hover:opacity-70'
          >
            signature
          </a>{' '}
          on the commit that names the file covers every chunk beneath it.
        </p>
        <p>
          It&rsquo;s the same Merkle fold the{' '}
          <Link to='/tree' className='underline underline-offset-4 transition-opacity duration-300 hover:opacity-70'>
            tree
          </Link>{' '}
          uses to roll a whole repository up to one signed hash.
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
