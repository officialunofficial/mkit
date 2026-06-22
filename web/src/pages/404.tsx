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
      <header className='space-y-3'>
        <h1 className='text-4xl font-semibold tracking-tight'>Not found</h1>
        <p className='max-w-prose text-base text-fg'>
          The page you&rsquo;re looking for doesn&rsquo;t exist — it may have moved, or the link may be wrong.
        </p>
      </header>
      <Link
        to='/'
        className='-mx-2 inline-block px-2 py-2 text-sm underline underline-offset-4 transition-opacity duration-300 hover:opacity-70'
      >
        ← back home
      </Link>
    </div>
  )
}

export const getConfig = async () => {
  return {
    render: 'static',
  } as const
}
