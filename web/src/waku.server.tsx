import { fsRouter } from 'waku'
import adapter from 'waku/adapters/cloudflare'
import { withSecurityHeaders } from './security-headers'

const server = adapter(fsRouter(import.meta.glob('./**/*.{tsx,ts}', { base: './pages' })))

export default {
  ...server,
  async fetch(req, ...args) {
    return withSecurityHeaders(await server.fetch(req, ...args))
  },
} satisfies typeof server
