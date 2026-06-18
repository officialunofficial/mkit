import { describe, expect, it, vi } from 'vitest'
import { tryServeInstaller } from './install-route'

const SCRIPT = '#!/bin/sh\n# mkit installer\n'

// Minimal ASSETS stub: serves the staged install.sh for /install.sh, 404s else.
function makeEnv() {
  const fetch = vi.fn(async (input: Request | URL | string) => {
    const url = new URL(typeof input === 'string' ? input : input.toString())
    if (url.pathname === '/install.sh') {
      return new Response(SCRIPT, { headers: { 'Content-Type': 'application/octet-stream' } })
    }
    return new Response('not found', { status: 404 })
  })
  return { ASSETS: { fetch } }
}

function req(path: string, ua: string, method = 'GET') {
  return new Request(`https://mkit.sh${path}`, { method, headers: { 'user-agent': ua } })
}

describe('tryServeInstaller', () => {
  it('serves the install script to curl at the root path', async () => {
    const res = await tryServeInstaller(req('/', 'curl/8.4.0'), makeEnv())
    expect(res).not.toBeNull()
    expect(res!.status).toBe(200)
    expect(res!.headers.get('Content-Type')).toBe('text/x-shellscript; charset=utf-8')
    expect(res!.headers.get('Vary')).toBe('User-Agent')
    expect(res!.headers.get('Cache-Control')).toContain('max-age=600')
    await expect(res!.text()).resolves.toBe(SCRIPT)
  })

  it('also matches wget and other CLI fetchers', async () => {
    for (const ua of ['Wget/1.21.4', 'libcurl/8.0', 'HTTPie/3.2.2']) {
      const res = await tryServeInstaller(req('/', ua), makeEnv())
      expect(res, ua).not.toBeNull()
    }
  })

  it('falls through (null) for browsers so the homepage still renders', async () => {
    const ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
    expect(await tryServeInstaller(req('/', ua), makeEnv())).toBeNull()
  })

  it('falls through for a curl request to a non-root path', async () => {
    expect(await tryServeInstaller(req('/hash', 'curl/8.4.0'), makeEnv())).toBeNull()
  })

  it('falls through for non-GET/HEAD methods', async () => {
    expect(await tryServeInstaller(req('/', 'curl/8.4.0', 'POST'), makeEnv())).toBeNull()
  })

  it('serves on HEAD as well', async () => {
    const res = await tryServeInstaller(req('/', 'curl/8.4.0', 'HEAD'), makeEnv())
    expect(res).not.toBeNull()
  })

  it('falls through when no User-Agent is present', async () => {
    const bare = new Request('https://mkit.sh/', { method: 'GET' })
    expect(await tryServeInstaller(bare, makeEnv())).toBeNull()
  })
})
