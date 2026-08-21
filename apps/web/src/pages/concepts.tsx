import { DemosTabs } from '../components/demos-tabs'
import { Seo } from '../components/seo'

export default function DemosPage() {
  return (
    <div className='space-y-8'>
      <Seo
        title='mkit — concepts'
        description='Six interactive concepts of mkit in one place: BLAKE3 content addressing, the Merkle tree, Ed25519 signatures, content-defined chunked streaming, pushes, and signed attestations — all running right in your browser.'
        path='/concepts'
        card='See it work'
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
