// Regression tests for the gzip-Content-Encoding-stripping bug: repo-worker's
// `connectrpc` gzip-compresses any response over 1 KiB and correctly sets
// `Content-Encoding: gzip` server-side, but something between there and this
// client strips the header while leaving the body compressed — a
// spec-compliant fetch client (this one) then fails to decompress and chokes
// trying to parse gzip bytes as JSON. Confirmed live against
// `https://api.mkit.sh`'s `ListCommits` (see PLAN.md / the session that
// diagnosed this) before this fix existed: `ConnectError: Failed to parse
// JSON`. `gzipAwareFetch` sniffs the gzip magic number directly (never
// trusting the — already broken — Content-Encoding header) and decompresses
// itself via `DecompressionStream`, mirroring the existing, already-shipped
// workaround in `rust/crates/mkit-repo-client/src/transport.rs`'s `is_gzip`.

import { describe, expect, it, vi } from 'vitest'
import { gzipAwareFetch, isGzip, listRefs, type RepoConnectClient } from './connect-client'

// `Uint8Array` return types below are annotated `<ArrayBuffer>` (not the
// default `<ArrayBufferLike>`) purely to satisfy `BlobPart`/`BodyInit`'s DOM
// lib typing — `arrayBuffer()` always returns a real `ArrayBuffer` at
// runtime, so this is a type-only correction, not a behavior change.
async function gzipCompress(bytes: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  const stream = new Blob([bytes as BlobPart]).stream().pipeThrough(new CompressionStream('gzip'))
  const buf = await new Response(stream).arrayBuffer()
  return new Uint8Array(buf)
}

describe('connect-client.ts — isGzip', () => {
  it('detects the gzip magic number', () => {
    expect(isGzip(new Uint8Array([0x1f, 0x8b, 0x08, 0x00]))).toBe(true)
  })

  it('rejects plain JSON bytes', () => {
    expect(isGzip(new TextEncoder().encode('{"exists":true}'))).toBe(false)
  })

  it('rejects a too-short buffer without throwing', () => {
    expect(isGzip(new Uint8Array([0x1f]))).toBe(false)
    expect(isGzip(new Uint8Array([]))).toBe(false)
  })
})

describe('connect-client.ts — gzipAwareFetch', () => {
  it('decompresses a gzip body missing its Content-Encoding header (the exact live bug)', async () => {
    const original = { commits: [{ hash: 'abc123', message: 'gm, multiplayer mkit' }] }
    const plainBytes = new TextEncoder().encode(JSON.stringify(original))
    const gzipped = await gzipCompress(plainBytes)

    const fetchStub = vi.fn(
      async () =>
        // Reproduces the live bug exactly: gzip-compressed body, NO
        // content-encoding header (that's what got stripped in transit).
        new Response(gzipped, { status: 200, headers: { 'content-type': 'application/json' } }),
    )
    vi.stubGlobal('fetch', fetchStub)

    const res = await gzipAwareFetch('https://api.mkit.sh/mkit.repo.v1.RepoService/ListCommits')
    const decoded = JSON.parse(await res.text())

    expect(decoded).toEqual(original)
    expect(res.headers.get('content-encoding')).toBeNull()
    expect(res.status).toBe(200)
    vi.unstubAllGlobals()
  })

  it('passes a plain (non-gzip) JSON response through unchanged', async () => {
    const body = { exists: true, objectId: 'deadbeef' }
    const bytes = new TextEncoder().encode(JSON.stringify(body))

    const fetchStub = vi.fn(
      async () =>
        new Response(bytes, { status: 200, statusText: 'OK', headers: { 'content-type': 'application/json' } }),
    )
    vi.stubGlobal('fetch', fetchStub)

    const res = await gzipAwareFetch('https://api.mkit.sh/mkit.repo.v1.RepoService/GetRef')
    const decoded = JSON.parse(await res.text())

    expect(decoded).toEqual(body)
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toBe('application/json')
    vi.unstubAllGlobals()
  })

  it('preserves status and non-content-encoding headers on the gzip path', async () => {
    const gzipped = await gzipCompress(new TextEncoder().encode('{"ok":true}'))
    const fetchStub = vi.fn(
      async () =>
        new Response(gzipped, {
          status: 200,
          headers: { 'content-type': 'application/json', 'x-custom-header': 'preserved' },
        }),
    )
    vi.stubGlobal('fetch', fetchStub)

    const res = await gzipAwareFetch('https://api.mkit.sh/x')

    expect(res.headers.get('x-custom-header')).toBe('preserved')
    expect(res.headers.get('content-type')).toBe('application/json')
    vi.unstubAllGlobals()
  })

  it('still decompresses correctly even if a (unreliable) content-encoding header IS present', async () => {
    // Belt-and-braces: the fix must not depend on trusting this header either
    // way — sniff the magic number regardless of what's declared.
    const original = { hello: 'world' }
    const gzipped = await gzipCompress(new TextEncoder().encode(JSON.stringify(original)))
    const fetchStub = vi.fn(
      async () =>
        new Response(gzipped, {
          status: 200,
          headers: { 'content-type': 'application/json', 'content-encoding': 'gzip' },
        }),
    )
    vi.stubGlobal('fetch', fetchStub)

    const res = await gzipAwareFetch('https://api.mkit.sh/x')
    expect(JSON.parse(await res.text())).toEqual(original)
    vi.unstubAllGlobals()
  })
})

// `listRefs`'s request/response mapping mirrors `listCommits`'s (see the doc
// comment on `listRefs` in connect-client.ts): the wire request carries
// `room`/`prefix`/`startAfter`/`pageSize` straight through, and the wire
// response's `objectId` bytes + `nextCursor`/`total` fields are mapped to the
// app's hex-string shape (`objectIdHex`/`nextCursorName`/`total`).
describe('connect-client.ts — listRefs wire mapping', () => {
  it('passes room/prefix/startAfter/pageSize onto the wire request and maps the response to hex + nextCursorName', async () => {
    let capturedReq: unknown
    const client = {
      listRefs: async (req: unknown) => {
        capturedReq = req
        return {
          refs: [
            { name: 'refs/heads/main', objectId: new Uint8Array([0xaa, 0xbb]) },
            { name: 'refs/heads/feature', objectId: new Uint8Array(0) }, // absent id -> ''
          ],
          nextCursor: 'refs/heads/feature',
          total: 5,
        }
      },
    } as unknown as RepoConnectClient

    const res = await listRefs(client, 'room-1', 'refs/heads/', 'refs/heads/a', 25)

    expect(capturedReq).toEqual({ room: 'room-1', prefix: 'refs/heads/', startAfter: 'refs/heads/a', pageSize: 25 })
    expect(res.refs).toEqual([
      { name: 'refs/heads/main', objectIdHex: 'aabb' },
      { name: 'refs/heads/feature', objectIdHex: '' },
    ])
    expect(res.nextCursorName).toBe('refs/heads/feature')
    expect(res.total).toBe(5)
  })

  it("defaults prefix/startAfter/pageSize to ''/''/0 when omitted (the legacy unpaginated request)", async () => {
    let capturedReq: unknown
    const client = {
      listRefs: async (req: unknown) => {
        capturedReq = req
        return { refs: [], nextCursor: '', total: 0 }
      },
    } as unknown as RepoConnectClient

    const res = await listRefs(client, 'room-1')

    expect(capturedReq).toEqual({ room: 'room-1', prefix: '', startAfter: '', pageSize: 0 })
    expect(res).toEqual({ refs: [], nextCursorName: '', total: 0 })
  })
})
