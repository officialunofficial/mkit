import { Link } from 'waku'
import { DemosTabs } from '../components/demos-tabs'
import { Seo } from '../components/seo'

export default function DemosPage() {
  return (
    <div className='space-y-8'>
      <Seo
        title='mkit — demos'
        description='Four interactive demos of mkit in one place: BLAKE3 content addressing, Ed25519 signatures, content-defined chunked streaming, and signed attestations — all running right in your browser.'
        path='/demos'
        card='See it work'
      />
      <DemosTabs />
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
