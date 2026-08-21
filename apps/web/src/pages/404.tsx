import { Link } from 'waku'
import { Seo } from '../components/seo'

// Waku's fsRouter renders this page (src/pages/404.tsx convention) whenever a
// request doesn't match a known route. Prerendered as static like every other
// page so the Cloudflare Assets binding can serve it directly.
export default function NotFoundPage() {
  return (
    <div className='space-y-8'>
      <Seo
        title='mkit — not found'
        description='The page you’re looking for doesn’t exist.'
        path='/404'
        card='Not found'
      />
      <header>
        <h1 className='ds-h1'>Not Found</h1>
        <p className='ds-note mt-1'>This page doesn&rsquo;t exist — it may have moved, or the link may be wrong.</p>
      </header>
      <p>
        <Link to='/' className='ds-link'>
          Back to the overview
        </Link>
      </p>
    </div>
  )
}

export const getConfig = async () => {
  return {
    render: 'static',
  } as const
}
