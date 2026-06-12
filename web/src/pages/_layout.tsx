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
      <meta name='description' content={data.description} />
      <link rel='icon' type='image/png' href={data.icon} />
      <link rel='preconnect' href='https://fonts.googleapis.com' />
      <link rel='preconnect' href='https://fonts.gstatic.com' crossOrigin='' />
      {/* Fraunces (variable: italic + optical size 9..144) for document
          text and display; IBM Plex Mono for labels, hashes, folios. */}
      <link
        rel='stylesheet'
        href='https://fonts.googleapis.com/css2?family=Fraunces:ital,opsz,wght@0,9..144,300..700;1,9..144,300..700&family=IBM+Plex+Mono:wght@400;500;600&display=swap'
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
    description: 'A content-addressed VCS in Rust — mkit demos in your browser.',
    icon: '/images/favicon.png',
  }

  return data
}

export const getConfig = async () => {
  return {
    render: 'static',
  } as const
}
