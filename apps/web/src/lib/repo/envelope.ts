// Signed envelope (Connect-flavored) + the per-procedure sign callback.
//
// Moved verbatim out of the former monolithic `repo-api.ts`; re-exported by the
// `repo-api` barrel so existing `from '../lib/repo-api'` imports keep working.

import type { DescMethod } from '@bufbuild/protobuf'
import { RepoService } from 'mkit-repo-proto'
import { bytesToHex, hexToBytes } from '../../components/use-mkit'
import type { MkitApi } from '../mkit'

const TEXT_ENCODER = new TextEncoder()

/**
 * Fully-qualified Connect procedure path for a generated RPC method — `/{service.typeName}/{method.name}`, the exact
 * string the Connect protocol puts on the wire and the server reconstructs into its canonical signed string (see README
 * §"The write envelope"). Derived from the generated `RepoService` descriptor (not hand-listed) so a `repo.proto`
 * rename is a compile error here, not a silent signature mismatch.
 */
function procedurePath(method: DescMethod): string {
  return `/${method.parent.typeName}/${method.name}`
}

/** Fully-qualified Connect procedure paths — also the `procedure` field of the envelope. */
export const procedures = {
  PutObject: procedurePath(RepoService.method.putObject),
  GetObject: procedurePath(RepoService.method.getObject),
  GetRef: procedurePath(RepoService.method.getRef),
  UpdateRef: procedurePath(RepoService.method.updateRef),
  ListRefs: procedurePath(RepoService.method.listRefs),
  WatchRefs: procedurePath(RepoService.method.watchRefs),
  PostMessage: procedurePath(RepoService.method.postMessage),
  ListMessages: procedurePath(RepoService.method.listMessages),
  React: procedurePath(RepoService.method.react),
  ListReactions: procedurePath(RepoService.method.listReactions),
  ListCommits: procedurePath(RepoService.method.listCommits),
} as const

// ---------------------------------------------------------------------------
// Signed envelope (Connect-flavored)
// ---------------------------------------------------------------------------

export type EnvelopeParts = {
  audience: string
  repository: string
  procedure: string
  bodyDigest: string
  createdAt: string
  expiresAt: string
  idempotencyKey: string
}

const component = (value: string, max: number) =>
  value.length > 0 && value.length <= max && /^[\x21-\x7e]+$/.test(value)
const hex = (value: string) => /^[0-9a-f]{64}$/.test(value)

/** Auth v2 canonical encoding, shared with mkit-core/write_auth.rs. */
export function canonicalString(p: EnvelopeParts): string {
  const origin = new URL(p.audience)
  if (!['https:', 'http:'].includes(origin.protocol) || origin.origin !== p.audience || origin.hostname.endsWith('.')) {
    throw new Error('Noncanonical signing audience')
  }
  if (
    !component(p.repository, 255) ||
    !component(p.procedure, 512) ||
    !p.procedure.startsWith('/') ||
    !hex(p.bodyDigest) ||
    !hex(p.idempotencyKey)
  )
    throw new Error('Invalid signed operation')
  const created = Number(p.createdAt),
    expires = Number(p.expiresAt)
  if (
    !Number.isSafeInteger(created) ||
    !Number.isSafeInteger(expires) ||
    created < 0 ||
    String(created) !== p.createdAt ||
    String(expires) !== p.expiresAt ||
    expires <= created ||
    expires - created > 300_000
  ) {
    throw new Error('Invalid signed validity interval')
  }
  return [
    'mkit-write:v2',
    p.audience,
    p.repository,
    p.procedure,
    `body:${p.bodyDigest}`,
    p.createdAt,
    p.expiresAt,
    p.idempotencyKey,
  ].join('\n')
}

export type SignedEnvelope = EnvelopeParts & {
  publicKeyHex: string
  signatureHex: string
  /** Digest of canonical signed bytes; distinct from the raw body digest. */
  digestHex: string
  commitment: string
  canonical: string
}

export function blake3OfString(api: MkitApi, s: string): string {
  return api.blake3_hex(TEXT_ENCODER.encode(s))
}

function nonce(): string {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(32)))
}

/** Sign exact body bytes for an explicitly configured service and repository. */
export function buildSignedEnvelope(
  api: MkitApi,
  seedHex: string,
  parts: Pick<EnvelopeParts, 'audience' | 'repository' | 'procedure' | 'bodyDigest'> &
    Partial<Pick<EnvelopeParts, 'createdAt' | 'expiresAt' | 'idempotencyKey'>>,
): SignedEnvelope {
  const createdAt = parts.createdAt ?? String(Date.now())
  const expiresAt = parts.expiresAt ?? String(Number(createdAt) + 300_000)
  const idempotencyKey = parts.idempotencyKey ?? nonce()
  const complete = { ...parts, createdAt, expiresAt, idempotencyKey }
  const canonical = canonicalString(complete)
  const digestHex = blake3OfString(api, canonical)
  const seed = hexToBytes(seedHex)
  return {
    ...complete,
    publicKeyHex: bytesToHex(api.ed25519_pubkey_from_seed(seed)),
    signatureHex: bytesToHex(api.ed25519_sign(hexToBytes(digestHex), seed)),
    commitment: `body:${parts.bodyDigest}`,
    digestHex,
    canonical,
  }
}

export function envelopeHeaders(env: SignedEnvelope): Record<string, string> {
  return {
    'X-Envelope-Version': '2',
    'X-Audience': env.audience,
    'X-Repository': env.repository,
    'X-Content-Commitment': env.commitment,
    'X-Expires-At': env.expiresAt,
    'X-Public-Key': env.publicKeyHex,
    'X-Signature': env.signatureHex,
    'X-Digest': env.bodyDigest,
    'X-Created-At': env.createdAt,
    'Idempotency-Key': env.idempotencyKey,
  }
}

export type RepoSignFn = (bodyDigestHex: string) => {
  publicKeyHex: string
  signatureHex: string
  audience: string
  repository: string
  commitment: string
  createdAt: string
  expiresAt: string
  idempotencyKey: string
  digestHex: string
}

/** One callback per logical operation; all transport retries reuse its nonce. */
export function makeSignFn(
  api: MkitApi,
  seedHex: string,
  procedure: string,
  endpoint: string,
  repository: string,
): RepoSignFn {
  const audience = new URL(endpoint).origin
  const createdAt = String(Date.now())
  const expiresAt = String(Number(createdAt) + 300_000)
  const idempotencyKey = nonce()
  let firstDigest: string | undefined
  return (bodyDigestHex: string) => {
    if (firstDigest !== undefined && firstDigest !== bodyDigestHex)
      throw new Error('Signing callback reused for another operation')
    const env = buildSignedEnvelope(api, seedHex, {
      audience,
      repository,
      procedure,
      bodyDigest: bodyDigestHex,
      createdAt,
      expiresAt,
      idempotencyKey,
    })
    firstDigest = bodyDigestHex
    return { ...env, digestHex: env.bodyDigest }
  }
}
