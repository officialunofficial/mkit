import { Link } from 'waku'
import { Seo } from '../components/seo'

// Waku's fsRouter renders this page (src/pages/404.tsx convention) whenever a
// request doesn't match a known route. Prerendered as static like every other
// page so the Cloudflare Assets binding can serve it directly.
export default function NotFoundPage() {
  return (
    <div className='space-y-8'>
      <Seo title='mkit — page not found' description='No page exists at this URL.' path='/404' card='Page not found' />
      <header>
        <h1 className='ds-h1'>Page not found</h1>
        <p className='ds-note mt-1'>No page exists at this URL. Check it for typos, or go to the overview.</p>
      </header>
      <p>
        <Link to='/' className='ds-link'>
          Go to the overview
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
