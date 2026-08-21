import '../styles.css'

import type { ReactNode } from 'react'
import { AgentationToolbar } from '../components/agentation-toolbar'
import { Footer } from '../components/footer'
import { Header } from '../components/header'
import { MkitPreloader } from '../components/mkit-preloader'
import { QueryProvider } from '../components/query-provider'
import { SiteRail } from '../components/site-nav'

type RootLayoutProps = { children: ReactNode }

export default async function RootLayout({ children }: RootLayoutProps) {
  const data = await getData()

  return (
    <div className='flex min-h-dvh flex-col'>
      {/* Per-page <title>, description, and Open Graph / Twitter tags are set by
          <Seo> in each page (components/seo.tsx). */}
      <link rel='icon' type='image/svg+xml' href={data.icon} />
      <MkitPreloader />
      <AgentationToolbar />
      <Header />
      {/* §2.7 / §4.27: a central content column with an offset left column for
          navigation at `wide` (≥1024px). The rail sits outside the content
          measure; below `wide` it collapses to the masthead trigger and the
          content takes the full width. */}
      <div className='mx-auto grid w-full max-w-6xl flex-1 grid-cols-1 content-start px-6 lg:grid-cols-[10rem_minmax(0,1fr)] lg:gap-x-10'>
        <SiteRail />
        <main className='min-w-0 pt-8 pb-24'>
          <QueryProvider>{children}</QueryProvider>
        </main>
      </div>
      <Footer />
    </div>
  )
}

const getData = async () => {
  const data = {
    icon: '/images/grid-fallback.svg',
  }

  return data
}

export const getConfig = async () => {
  return {
    render: 'static',
  } as const
}
