import { Link } from 'waku'
import { DemoBoundary } from '../components/demo-boundary'
import { PushDemo } from '../components/push-demo'
import { Seo } from '../components/seo'

export default function PushPage() {
  return (
    <div className='space-y-8'>
      <Seo
        title='mkit — push'
        description='Two roads into a bucket: one object per file, or chunk-and-pack. Edit a file and watch Road A re-upload everything while Road B ships only the changed chunk, folds it into a Merkle root, and settles the head pointer.'
        path='/push'
        card='How a push settles'
      />
      <header className='space-y-3'>
        <h1 className='text-4xl font-semibold tracking-tight'>How a push settles</h1>
        <p className='max-w-prose text-base text-fg'>
          Two roads into a bucket. <strong className='font-semibold'>Road A</strong> stores one object per file — edit
          it and you re-upload the whole thing. <strong className='font-semibold'>Road B</strong> chunks the file at
          content-defined boundaries, folds the chunks into a Merkle root, ships only what changed, and settles by
          advancing a single content-addressed pointer. Edit the file and watch the difference.
        </p>
      </header>
      <DemoBoundary>
        <PushDemo />
      </DemoBoundary>
      <p className='max-w-prose text-sm text-muted'>
        We chose B.{' '}
        <a
          href='https://x.com/makechainnet'
          target='_blank'
          rel='noreferrer'
          className='underline underline-offset-4 transition-opacity duration-300 hover:opacity-70'
        >
          @makechainnet
        </a>
        &rsquo;s projects store packed, hashed blobs: dedup, cheap deltas, file integrity, and signed history. We did
        this because we don&rsquo;t think buckets will need to be human-browsable in the future.
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
