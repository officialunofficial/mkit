import { describe, expect, it } from 'vitest'
import { redirectMiddleware, resolveRedirect } from './redirects'

describe('resolveRedirect', () => {
  it.each([
    ['/hash', '/demos#hash'],
    ['/sign', '/demos#sign'],
    ['/streaming', '/demos#streaming'],
    ['/attest', '/demos#attest'],
  ])('maps deleted route %s to %s', (from, to) => {
    expect(resolveRedirect(from)).toBe(to)
  })

  it('tolerates a single trailing slash', () => {
    expect(resolveRedirect('/sign/')).toBe('/demos#sign')
  })

  it('leaves live and unknown routes alone', () => {
    expect(resolveRedirect('/')).toBeNull()
    expect(resolveRedirect('/demos')).toBeNull()
    expect(resolveRedirect('/push')).toBeNull()
    expect(resolveRedirect('/hash/extra')).toBeNull()
  })
})

async function run(path: string) {
  const mw = redirectMiddleware()
  let nextCalled = false
  const c = { req: { raw: new Request(`https://mkit.sh${path}`) } }
  const res = await mw(c, async () => {
    nextCalled = true
  })
  return { res, nextCalled }
}

describe('redirectMiddleware', () => {
  it('301s a deleted route to its anchor without calling next', async () => {
    const { res, nextCalled } = await run('/streaming')
    expect(nextCalled).toBe(false)
    expect(res).toBeInstanceOf(Response)
    expect((res as Response).status).toBe(301)
    expect((res as Response).headers.get('Location')).toBe('/demos#streaming')
  })

  it('delegates to next for a live route', async () => {
    const { res, nextCalled } = await run('/demos')
    expect(nextCalled).toBe(true)
    expect(res).toBeUndefined()
  })
})
