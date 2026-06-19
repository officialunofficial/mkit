import { Link } from 'waku'
import { HashDemo } from '../components/hash-demo'
import { DemoBoundary } from '../components/demo-boundary'
import { Seo } from '../components/seo'

export default function HashPage() {
  return (
    <div className='space-y-8'>
      <Seo
        title='mkit — hash'
        description='Every file, folder, and commit is named by its BLAKE3 hash — change one byte and the name changes. Edit text and watch every hash rewrite live.'
        path='/hash'
        card='What’s in a hash?'
      />
      <header className='space-y-3'>
        <h1 className='text-4xl font-semibold tracking-tight'>What&rsquo;s in a hash?</h1>
        <p className='max-w-prose text-base text-fg'>
          Every file, folder, and commit is named by the BLAKE3 hash of its bytes — change a single character and the
          name changes too. git does the same with SHA-1; mkit uses BLAKE3, one algorithm everywhere, fast enough to
          re-hash on every keystroke. This page builds a tiny commit out of two files: edit the text or swap the image
          and watch every hash along the way rewrite.
        </p>
      </header>
      <DemoBoundary>
        <HashDemo />
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
