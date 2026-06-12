import { Link } from 'waku'
import { HashDemo } from '../components/hash-demo'
import { DemoBoundary } from '../components/demo-boundary'

export default function HashPage() {
  return (
    <div className='space-y-8'>
      <title>mkit — hash</title>
      <header className='space-y-3 pt-4'>
        <p className='microlabel text-[--color-accent]'>Demo Nº 01 — hash</p>
        <h1 className='text-5xl font-light'>What&rsquo;s in a hash?</h1>
        <p className='max-w-prose text-base text-[--color-fg]'>
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
        className='microlabel -mx-2 inline-block px-2 py-2 text-[--color-muted] transition-colors duration-200 hover:text-[--color-fg]'
      >
        ← Index
      </Link>
    </div>
  )
}

export const getConfig = async () => {
  return {
    render: 'static',
  } as const
}
