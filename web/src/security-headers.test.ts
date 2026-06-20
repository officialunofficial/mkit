import { describe, expect, it } from 'vitest'
import { securityHeadersMiddleware, withSecurityHeaders } from './security-headers'

describe('withSecurityHeaders', () => {
  it('adds conservative hardening headers without enforcing CSP yet', async () => {
    const input = new Response('ok', {
      headers: { 'Content-Type': 'text/plain' },
      status: 201,
    })

    const output = withSecurityHeaders(input)

    expect(output.status).toBe(201)
    expect(output.headers.get('Content-Type')).toBe('text/plain')
    expect(output.headers.get('X-Content-Type-Options')).toBe('nosniff')
    expect(output.headers.get('X-Frame-Options')).toBe('DENY')
    expect(output.headers.get('Referrer-Policy')).toBe('no-referrer')
    expect(output.headers.get('Permissions-Policy')).toContain('camera=()')
    expect(output.headers.get('Content-Security-Policy')).toBeNull()

    const reportOnly = output.headers.get('Content-Security-Policy-Report-Only')
    expect(reportOnly).toContain("default-src 'self'")
    expect(reportOnly).toContain("script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'")
    expect(reportOnly).toContain('https://fonts.googleapis.com')
    expect(reportOnly).toContain('https://fonts.gstatic.com')
    expect(reportOnly).toContain("img-src 'self' data: blob:")
    await expect(output.text()).resolves.toBe('ok')
  })
})

describe('securityHeadersMiddleware', () => {
  it('stamps the headers onto the response produced by next()', async () => {
    const mw = securityHeadersMiddleware()
    const c = { res: new Response('placeholder') }
    const next = async () => {
      c.res = new Response('page', { status: 200, headers: { 'Content-Type': 'text/html' } })
    }

    await mw(c, next)

    expect(c.res.headers.get('X-Frame-Options')).toBe('DENY')
    expect(c.res.headers.get('X-Content-Type-Options')).toBe('nosniff')
    expect(c.res.headers.get('Content-Type')).toBe('text/html')
    await expect(c.res.text()).resolves.toBe('page')
  })
})
