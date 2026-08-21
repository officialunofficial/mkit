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
      {/* Polychrome's PageChrome shape: one central content column
          (`--page-column`), with the primary nav hanging as a fixed rail in
          the left page margin at wide viewports — outside the content measure
          (§2.7, §4.27 rule 1) — and collapsing into the masthead trigger
          below the rail breakpoint. */}
      <SiteRail />
      <div className='mx-auto w-full max-w-(--page-column) flex-1 px-6'>
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
