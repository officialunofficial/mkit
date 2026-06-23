import { describe, expect, it, vi } from 'vitest'
import { tryServeInstaller } from './install-route'

const SCRIPT = '#!/bin/sh\n# mkit installer\n'

// Minimal ASSETS stub: serves the staged install.sh for /install.sh, 404s else.
function makeEnv() {
  const fetch = vi.fn(async (input: Request | URL | string) => {
    const url = new URL(typeof input === 'string' ? input : input.toString())
    if (url.pathname === '/install.sh') {
      // Include headers the static-asset layer would set (ETag/Content-Type) so
      // tests prove tryServeInstaller does not let them leak into its response.
      return new Response(SCRIPT, {
        headers: { 'Content-Type': 'application/octet-stream', ETag: '"abc123"' },
      })
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
    // `/` must never be cached: shared caches ignore Vary: User-Agent and would
    // cross the script and the homepage between CLI fetchers and browsers.
    expect(res!.headers.get('Cache-Control')).toBe('no-store')
    expect(res!.headers.get('Vary')).toBeNull()
    // Inherited asset headers must not leak through after the Content-Type relabel.
    expect(res!.headers.get('ETag')).toBeNull()
    await expect(res!.text()).resolves.toBe(SCRIPT)
  })

  it('never forwards a Content-Encoding header and emits a decoded body', async () => {
    // If the asset layer ever returned a body labelled Content-Encoding, the
    // rebuilt response must not pass that header (or compressed bytes) through —
    // otherwise `curl mkit.sh | sh` would pipe gzip/br into the shell. We read
    // the asset to text, so the response carries identity bytes and no encoding.
    const env = {
      ASSETS: {
        fetch: vi.fn(
          async () =>
            new Response(SCRIPT, {
              headers: { 'Content-Type': 'application/octet-stream', 'Content-Encoding': 'gzip' },
            }),
        ),
      },
    }
    const res = await tryServeInstaller(req('/', 'curl/8.4.0'), env)
    expect(res).not.toBeNull()
    expect(res!.headers.get('Content-Encoding')).toBeNull()
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

  it('falls through (null) when ASSETS.fetch throws — never 500s the homepage', async () => {
    const env = {
      ASSETS: {
        fetch: vi.fn(async () => {
          throw new Error('ASSETS binding unavailable')
        }),
      },
    }
    await expect(tryServeInstaller(req('/', 'curl/8.4.0'), env)).resolves.toBeNull()
  })

  it('falls through (null) when the install.sh asset is missing (non-200)', async () => {
    const env = {
      ASSETS: { fetch: vi.fn(async () => new Response('nope', { status: 404 })) },
    }
    expect(await tryServeInstaller(req('/', 'curl/8.4.0'), env)).toBeNull()
  })
})
