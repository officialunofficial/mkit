import { DemoBoundary } from '../components/demo-boundary'
import { MultiplayerDemo } from '../components/multiplayer-demo'
import { Seo } from '../components/seo'

export default function MultiplayerPage() {
  return (
    <div className='space-y-8'>
      <Seo
        title='mkit — multiplayer'
        description='Set up a passkey, sign a commit right in your browser, and push it to a shared repo — then watch other players’ commits arrive live. Anonymous, no accounts: your passkey is your identity.'
        path='/multiplayer'
        card='Multiplayer mkit'
      />
      <header>
        <h1 className='ds-h1'>Multiplayer mkit</h1>
        <p className='ds-note mt-1'>
          Everyone shares one repository. Contribute alongside others by pushing commits to a branch, or starting a new
          one.
        </p>
      </header>
      <DemoBoundary>
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
