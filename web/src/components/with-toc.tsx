import type { ReactNode } from 'react'
import { OnThisPage } from './on-this-page'

// Two-column documentation layout: page content on the left, a sticky
// "On this page" table of contents on the right. The TOC column only
// appears at lg and up; narrower screens render a single column. Demo
// pages don't use this wrapper — only the doc-style pages (performance,
// parity) that have section headers worth navigating.
export function WithToc({ children }: { children: ReactNode }) {
  return (
    <div className='lg:grid lg:grid-cols-[minmax(0,1fr)_11rem] lg:gap-12'>
      <div className='min-w-0'>{children}</div>
      <aside className='hidden lg:block'>
        <div className='sticky top-20'>
          <OnThisPage />
        </div>
      </aside>
    </div>
  )
}
