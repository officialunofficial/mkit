// @vitest-environment jsdom
import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ReactNode } from 'react'
import { afterEach, expect, it, vi } from 'vitest'
import { Header } from './header'

const router = vi.hoisted(() => ({ path: '/' }))
vi.mock('waku', () => ({
  useRouter: () => router,
  Link: ({ children, to }: { children: ReactNode; to: string }) => <a href={to}>{children}</a>,
}))
vi.mock('./grid-logo', () => ({ GridLogo: () => null }))
vi.mock('./theme-toggle', () => ({ ThemeToggle: () => null }))
vi.mock('./site-nav', () => ({ NavList: () => <span>Navigation links</span> }))

afterEach(() => {
  cleanup()
  router.path = '/'
})

it('closes expanded navigation on a route change and allows reopening', async () => {
  const user = userEvent.setup()
  const view = render(<Header />)
  await user.click(screen.getByRole('button', { name: 'Open navigation' }))
  expect(screen.getByRole('navigation', { name: 'Primary' })).toBeInTheDocument()

  router.path = '/concepts'
  view.rerender(<Header />)
  expect(screen.queryByRole('navigation', { name: 'Primary' })).not.toBeInTheDocument()

  await user.click(screen.getByRole('button', { name: 'Open navigation' }))
  expect(screen.getByRole('navigation', { name: 'Primary' })).toBeInTheDocument()
  view.rerender(<Header />)
  expect(screen.getByRole('navigation', { name: 'Primary' })).toBeInTheDocument()
})
