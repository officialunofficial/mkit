import { DemosTabs } from '../components/demos-tabs'
import { Seo } from '../components/seo'

export default function DemosPage() {
  return (
    <div className='space-y-8'>
      <Seo
        title='mkit — concepts'
        description='Explore BLAKE3 content addressing, Merkle trees, Ed25519 signatures, chunked streaming, pushes, and attestations with browser demos.'
        path='/concepts'
        card='Interactive concepts'
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
