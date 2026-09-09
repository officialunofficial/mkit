import { DemoBoundary } from '../components/demo-boundary'
import { CodingWorkspace } from '../components/workspace/workspace'
import { Seo } from '../components/seo'

export default function CreatePage() {
  return (
    <div>
      <Seo
        title='mkit — create'
        description='Remix a public project, edit files, and work with nanocodex in a shared terminal. Save signed versions with your passkey identity.'
        path='/create'
        card='Create with mkit'
      />
      <h1 className='sr-only'>Create with mkit</h1>
      <DemoBoundary fallback={<p className='text-sm text-muted'>Loading workspace…</p>}>
        <CodingWorkspace />
      </DemoBoundary>
    </div>
  )
}
export const getConfig = async () => ({ render: 'static' }) as const
