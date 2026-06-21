import { Link } from 'waku'
import { DemoBoundary } from '../components/demo-boundary'
import { PushDemo } from '../components/push-demo'
import { Seo } from '../components/seo'

export default function PushPage() {
  return (
    <div className='space-y-8'>
      <Seo
        title='mkit — push'
        description='Two ways to store a file in a bucket: as one whole object, or split into content-defined chunks. Edit a file and watch whole-file storage re-upload everything while chunked storage ships only the changed chunk, folds it into a Merkle root, and settles the head pointer.'
        path='/push'
        card='How a push settles'
      />
      <header className='space-y-3'>
        <h1 className='text-4xl font-semibold tracking-tight'>How a push settles</h1>
        <p className='max-w-prose text-base text-fg'>
          There are two ways to store a file in a bucket. You can store each file as one object — but editing it
          re-uploads the whole thing. Or you can split each file into content-defined chunks, fold the chunks into a
          Merkle root, ship only what changed, and settle by advancing a single content-addressed pointer. Edit the file
          below to compare the two.
        </p>
      </header>
      <DemoBoundary>
        <PushDemo />
      </DemoBoundary>
      <p className='max-w-prose text-sm text-muted'>
        mkit takes the second approach. Like{' '}
        <a
          href='https://x.com/makechainnet'
          target='_blank'
          rel='noreferrer'
          className='underline underline-offset-4 transition-opacity duration-300 hover:opacity-70'
        >
          @makechainnet
        </a>
        &rsquo;s projects, it stores packed, hashed blobs: dedup, cheap deltas, file integrity, and signed history. It
        does this because a bucket doesn&rsquo;t need to be human-browsable.
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
