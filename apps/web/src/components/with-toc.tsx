import type { ReactNode } from 'react'
import { OnThisPage } from './on-this-page'

// Doc-page wrapper: the "On This Page" rail (§4.40) hangs fixed in the RIGHT
// page margin — the trailing edge of the content column, mirroring the
// primary nav's rail on the left — and disappears below the rail breakpoint
// rather than collapsing to a trigger (§4.40 rule 6). The content column
// keeps its measure either way.
export function WithToc({ children }: { children: ReactNode }) {
  return (
    <>
      <div className='min-w-0'>{children}</div>
      <aside
        className='fixed top-24 hidden w-40 min-[1440px]:block'
        style={{ left: 'calc(50% + (var(--page-column) / 2) + 2rem)' }}
      >
        <OnThisPage />
      </aside>
    </>
  )
}
