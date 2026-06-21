import { Link } from 'waku'
import { ParityMatrix } from '../components/parity-matrix'
import { Seo } from '../components/seo'
import { WithToc } from '../components/with-toc'

export default function ParityPage() {
  return (
    <WithToc>
      <div className='space-y-8'>
        <Seo
          title='mkit — parity'
          description='mkit aims for CLI parity with git — same commands and flags — while keeping BLAKE3 addressing and a signature on every commit. Parity of behavior, not wire interop with .git.'
          path='/parity'
          card='How much of git is here?'
        />
        <header className='space-y-3'>
          <h1 className='text-4xl font-semibold tracking-tight'>How much of git is here?</h1>
          <p className='max-w-prose text-base text-fg'>
            mkit aims for CLI parity with git: the commands and flags you would type behave the way git&rsquo;s do,
            while mkit keeps its own improvements — BLAKE3 content addressing, a signature on every commit, and guards
            against silent data loss. What it does not do is share bytes with a{' '}
            <code className='font-mono text-sm'>.git</code> repo. The two object stores are different, so this is parity
            of behavior, not wire interoperability. Here is the whole matrix, git&rsquo;s wins and mkit&rsquo;s
            divergences included.
          </p>
        </header>
        <ParityMatrix />
        <Link
          to='/'
          className='-mx-2 inline-block px-2 py-2 text-sm underline underline-offset-4 transition-opacity duration-300 hover:opacity-70'
        >
          ← back
        </Link>
      </div>
    </WithToc>
  )
}

export const getConfig = async () => {
  return {
    render: 'static',
  } as const
}
