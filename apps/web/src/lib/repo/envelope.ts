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
  /** Connect procedure path, e.g. `/mkit.repo.v1.RepoService/UpdateRef`. */
  procedure: string
  /** BLAKE3 hex of the raw (serialized) request body. */
  bodyDigest: string
  createdAt: string
  idempotencyKey: string
}

/** Canonical string the server reconstructs + verifies (Connect-flavored envelope). */
export function canonicalString(p: EnvelopeParts): string {
  return ['mkit-write:v1', p.procedure, p.bodyDigest, p.createdAt, p.idempotencyKey].join('\n')
}

export type SignedEnvelope = {
  publicKeyHex: string
  signatureHex: string
  /** BLAKE3 hex of the RAW request body — the `X-Digest` header the server recomputes. */
  bodyDigest: string
  /** BLAKE3 hex of the canonical string (the bytes that are Ed25519-signed). */
  digestHex: string
  /** Epoch-millis string (`String(Date.now())`) — the `X-Created-At` header. */
  createdAt: string
  idempotencyKey: string
  canonical: string
}

/** BLAKE3 hex of a UTF-8 string (via WASM). */
export function blake3OfString(api: MkitApi, s: string): string {
  return api.blake3_hex(TEXT_ENCODER.encode(s))
}

/**
 * Build + sign the request envelope. `bodyDigest` is the BLAKE3 of the raw (serialized) request body. The signature is
 * raw Ed25519 over the BLAKE3 digest of the canonical string — what the server's `ed25519_verify` checks. The real
 * Connect client attaches `publicKeyHex` / `signatureHex` / `createdAt` / `idempotencyKey` as the X-* call headers.
 */
export function buildSignedEnvelope(
  api: MkitApi,
  seedHex: string,
  parts: Pick<EnvelopeParts, 'procedure' | 'bodyDigest'> & Partial<Pick<EnvelopeParts, 'createdAt' | 'idempotencyKey'>>,
): SignedEnvelope {
  // `createdAt` MUST be epoch-ms (`String(Date.now())`) to match the server's
  // `String(epoch ms)` canonical field — see apps/repo-worker/src/lib/envelope.ts.
  const createdAt = parts.createdAt ?? String(Date.now())
  const idempotencyKey = parts.idempotencyKey ?? crypto.randomUUID()
  const canonical = canonicalString({ ...parts, createdAt, idempotencyKey })
  const digestHex = blake3OfString(api, canonical)
  const seed = hexToBytes(seedHex)
  const sig = api.ed25519_sign(hexToBytes(digestHex), seed)
  const pubkey = api.ed25519_pubkey_from_seed(seed)
  return {
    publicKeyHex: bytesToHex(pubkey),
    signatureHex: bytesToHex(sig),
    bodyDigest: parts.bodyDigest,
    digestHex,
    createdAt,
    idempotencyKey,
    canonical,
  }
}

export function envelopeHeaders(env: SignedEnvelope): Record<string, string> {
  return {
    'X-Public-Key': env.publicKeyHex,
    'X-Signature': env.signatureHex,
    // Client-claimed BLAKE3 of the raw request body; server rejects on mismatch.
    'X-Digest': env.bodyDigest,
    'X-Created-At': env.createdAt,
    'Idempotency-Key': env.idempotencyKey,
  }
}

// ---------------------------------------------------------------------------
// Per-procedure sign callback (used by the wasm backend)
// ---------------------------------------------------------------------------

/**
 * The sign-callback the wasm client invokes per write. It receives the BLAKE3 hex of the RAW (serialized protobuf)
 * request body — the EXACT bytes the transport sends and the server re-hashes — and returns the signed-write envelope.
 * Computing the digest wasm-side (not in JS) is what guarantees `X-Digest` matches `BLAKE3(actualBody)` on the server;
 * JS could not reproduce the protobuf bytes. See rust/crates/mkit-repo-client/README.md.
 *
 * The returned object's keys match what `SigningFetchTransport` reads: `publicKeyHex`, `signatureHex`, `createdAt`,
 * `idempotencyKey` (+ optional `digestHex` echo, which must equal the supplied digest).
 */
export type RepoSignFn = (bodyDigestHex: string) => {
  publicKeyHex: string
  signatureHex: string
  createdAt: string
  idempotencyKey: string
  digestHex: string
}

/** Build a per-procedure sign-callback bound to the active identity seed. */
export function makeSignFn(api: MkitApi, seedHex: string, procedure: string): RepoSignFn {
  return (bodyDigestHex: string) => {
    const env = buildSignedEnvelope(api, seedHex, { procedure, bodyDigest: bodyDigestHex })
    return {
      publicKeyHex: env.publicKeyHex,
      signatureHex: env.signatureHex,
      createdAt: env.createdAt,
      idempotencyKey: env.idempotencyKey,
      digestHex: env.bodyDigest,
    }
  }
}
