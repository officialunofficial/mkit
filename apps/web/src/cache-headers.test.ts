import { describe, expect, it } from 'vitest'
import { cacheHeadersMiddleware } from './cache-headers'

function ctx(method: string, res: Response) {
  return { req: { raw: new Request('https://mkit.sh/', { method }) }, res }
}

describe('cacheHeadersMiddleware', () => {
  it('stamps Cache-Control onto a GET 200 page render with none', async () => {
    const mw = cacheHeadersMiddleware()
    const c = ctx('GET', new Response('placeholder'))
    const next = async () => {
      c.res = new Response('<html>page</html>', { status: 200, headers: { 'Content-Type': 'text/html' } })
    }

    await mw(c, next)

    expect(c.res.headers.get('Cache-Control')).toBe('public, max-age=3600, stale-while-revalidate=300')
    expect(c.res.headers.get('Content-Type')).toBe('text/html')
    await expect(c.res.text()).resolves.toBe('<html>page</html>')
  })

  it('stamps HEAD 200 responses too', async () => {
    const mw = cacheHeadersMiddleware()
    const c = ctx('HEAD', new Response(null))
    const next = async () => {
      c.res = new Response(null, { status: 200 })
    }

    await mw(c, next)

    expect(c.res.headers.get('Cache-Control')).toBe('public, max-age=3600, stale-while-revalidate=300')
  })

  it('does not overwrite an existing Cache-Control (e.g. the installer no-store response)', async () => {
    const mw = cacheHeadersMiddleware()
    const c = ctx('GET', new Response('placeholder'))
    const next = async () => {
      c.res = new Response('script', { status: 200, headers: { 'Cache-Control': 'no-store' } })
    }

    await mw(c, next)

    expect(c.res.headers.get('Cache-Control')).toBe('no-store')
  })

  it('leaves a redirect response untouched', async () => {
    const mw = cacheHeadersMiddleware()
    const c = ctx('GET', new Response('placeholder'))
    const next = async () => {
      c.res = new Response(null, { status: 301, headers: { Location: '/demos#hash' } })
    }

    await mw(c, next)

    expect(c.res.headers.has('Cache-Control')).toBe(false)
    expect(c.res.status).toBe(301)
  })

  it('does not cache a non-GET/HEAD method', async () => {
    const mw = cacheHeadersMiddleware()
    const c = ctx('POST', new Response('placeholder'))
    const next = async () => {
      c.res = new Response('ok', { status: 200 })
    }

    await mw(c, next)

    expect(c.res.headers.has('Cache-Control')).toBe(false)
  })
})
