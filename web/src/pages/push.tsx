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
          Watch what mkit does with a file you push. It splits the file into content-defined chunks and names each by
          its BLAKE3 hash; when the file changes, only the chunks that changed get new names, so a push ships just those
          — then folds them into a Merkle root that becomes the file&rsquo;s new id. Step through it below.
        </p>
      </header>
      <DemoBoundary>
        <PushDemo />
      </DemoBoundary>
      <p className='max-w-prose text-sm text-muted'>
        Why address a file by its Merkle root? Because the root <em>is</em> the id, reading the file back re-derives the
        root and proves every chunk intact — integrity lives in the name, not in a separate checksum. The same root lets
        a client verify that one chunk belongs to the file without fetching the rest, and a{' '}
        <a href='/demos#sign' className='underline underline-offset-4 transition-opacity duration-300 hover:opacity-70'>
          signature
        </a>{' '}
        on the commit that names the file then covers every chunk beneath it — the same Merkle fold the{' '}
        <Link to='/tree' className='underline underline-offset-4 transition-opacity duration-300 hover:opacity-70'>
          tree
        </Link>{' '}
        uses to roll a whole repository up to one signed hash.
      </p>
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
