import { DemosTabs } from '../components/demos-tabs'
import { Seo } from '../components/seo'

export default function DemosPage() {
  return (
    <div className='space-y-8'>
      <Seo
        title='mkit — concepts'
        description='Browser demos of BLAKE3 content hashes, Merkle trees, Ed25519 signatures, chunk verification, incremental pushes, and signed attestations.'
        path='/concepts'
        card='Concept demos'
      />
      <DemosTabs />
    </div>
  )
}

export const getConfig = async () => {
  return {
    render: 'static',
  } as const
}
