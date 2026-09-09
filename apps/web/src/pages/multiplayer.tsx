import { DemoBoundary } from '../components/demo-boundary'
import { MultiplayerDemo } from '../components/multiplayer-demo'
import { MultiplayerSkeleton } from '../components/loading'
import { Seo } from '../components/seo'

export default function MultiplayerPage() {
  return (
    <div className='space-y-8'>
      <Seo
        title='mkit — multiplayer'
        description='Create a passkey, sign a commit in your browser, and push it to a shared repository. View other contributions as they arrive. No account registration required.'
        path='/multiplayer'
        card='Multiplayer mkit'
      />
      <header>
        <h1 className='ds-h1'>Multiplayer mkit</h1>
        <p className='ds-note mt-1'>
          Everyone shares one repository. Contribute alongside others by pushing commits to a branch, or starting a new
          one.
        </p>
        <p className='mt-2 text-sm'>
          <Link to='/create' className='ds-link'>
            Remix this demo
          </Link>{' '}
          into your own public project with files, a terminal, and nanocodex.
        </p>
      </header>
      <DemoBoundary fallback={<MultiplayerSkeleton />}>
        <MultiplayerDemo />
      </DemoBoundary>
    </div>
  )
}

export const getConfig = async () => {
  return {
    render: 'static',
  } as const
}
import { Link } from 'waku'
