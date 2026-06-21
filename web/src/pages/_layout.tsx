import '../styles.css'

import type { ReactNode } from 'react'
import { AgentationToolbar } from '../components/agentation-toolbar'
import { Footer } from '../components/footer'
import { Header } from '../components/header'
import { MkitPreloader } from '../components/mkit-preloader'
import { PointerTracker } from '../components/pointer-tracker'

type RootLayoutProps = { children: ReactNode }

export default async function RootLayout({ children }: RootLayoutProps) {
  const data = await getData()

  return (
    <div>
      {/* Per-page <title>, description, and Open Graph / Twitter tags are set by
          <Seo> in each page (components/seo.tsx). */}
      <link rel='icon' type='image/png' href={data.icon} />
      <link rel='preconnect' href='https://fonts.googleapis.com' />
      <link rel='preconnect' href='https://fonts.gstatic.com' crossOrigin='' />
      {/* Geist + Geist Mono. */}
      <link
        rel='stylesheet'
        href='https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700&family=Geist+Mono:wght@400;500&display=swap'
        precedence='font'
      />
      {/* Header and footer span edge-to-edge; the middle column lives
          inside `<main>` so every page shares the same width. Pages
          don't re-apply `max-w-*` themselves. */}
      <PointerTracker />
      <MkitPreloader />
      <AgentationToolbar />
      <Header />
      {/* Slightly wider container than editorial default (48rem →
          64rem) so pages that benefit from a two-column layout have
          room, while prose-heavy sections re-constrain themselves
          via `max-w-prose` at the page level. */}
      <main className='mx-auto w-full max-w-5xl px-6 pt-8 pb-24'>{children}</main>
      <Footer />
    </div>
  )
}

const getData = async () => {
  const data = {
    icon: '/images/favicon.png',
  }

  return data
}

export const getConfig = async () => {
  return {
    render: 'static',
  } as const
}
