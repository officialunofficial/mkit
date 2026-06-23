import { blake3Hex, ed25519VerifyHex } from "./crypto";
import { HEX64, HEX128 } from "./hex";

/**
 * Signed-write envelope (DEMO MODE — open write, verify-only, no allow-list).
 *
 * The wire protocol is ConnectRPC; the envelope rides in request metadata
 * (headers), not in the proto message, so one guard covers every procedure
 * uniformly. The client signs a canonical request string with its Ed25519 key;
 * the server recomputes the string, BLAKE3-hashes it, and strict-verifies the
 * signature. A valid signature proves request integrity + "same author"; it
 * grants NO authority — any valid key may write any ref (design note §3).
 *
 * THE CANONICAL STRING — both client and server MUST build it byte-for-byte:
 *
 *   [ "mkit-write:v1",
 *     procedure,        // fully-qualified RPC, e.g. "/mkit.repo.v1.RepoService/UpdateRef"
 *     bodyDigest,       // lowercase hex BLAKE3 of the RAW request body bytes
 *                       //   (the serialized protobuf request message;
 *                       //    BLAKE3("") for an empty body)
 *     createdAt,        // String(epoch ms)
 *     idempotencyKey ]  // the Idempotency-Key value, or "" if absent
 *   .join("\n")
 *
 * Then: signing_digest = BLAKE3(utf8(canonical))   (lowercase hex)
 *       valid          = ed25519_verify_strict(pubkey, signing_digest, signature)
 *
 * This is a plain envelope digest — NOT an mkit commit signature, so the
 * SPEC-SIGNING commit/remix/tag domain prefixes do NOT apply: it is
 * BLAKE3(canonical-bytes) then strict Ed25519 verify.
 */

export const ENVELOPE_PREFIX = "mkit-write:v1";

export interface CanonicalEnvelopeInput {
  procedure: string;
  bodyDigest: string;
  createdAt: number | string;
  idempotencyKey: string;
}

/** Build the canonical string. Order and field set are part of the contract. */
export function canonicalEnvelope(input: CanonicalEnvelopeInput): string {
  return [ENVELOPE_PREFIX, input.procedure, input.bodyDigest, String(input.createdAt), input.idempotencyKey].join(
    "\n",
  );
}

const ENCODER = new TextEncoder();

/** BLAKE3 digest (lowercase hex) of the canonical string — the signed message. */
export function envelopeSigningDigest(input: CanonicalEnvelopeInput): string {
  return blake3Hex(ENCODER.encode(canonicalEnvelope(input)));
}

export interface EnvelopeHeaders {
  publicKey: string | undefined; // X-Public-Key
  signature: string | undefined; // X-Signature
  digest: string | undefined; // X-Digest (client-claimed raw-body digest)
  createdAt: string | undefined; // X-Created-At
  idempotencyKey: string | undefined; // Idempotency-Key
}

export type VerifyEnvelopeResult =
  | { ok: true; publicKey: string; bodyDigest: string; idempotencyKey: string }
  | { ok: false; status: 400 | 401; error: string };

/** ±5 minutes, in milliseconds. */
export const FRESHNESS_WINDOW_MS = 5 * 60_000;

/**
 * Verify a write envelope. Pure given `now` and the actual raw-body digest:
 *
 *  - all four signature headers present,
 *  - X-Public-Key / X-Digest are 64-hex, X-Signature is 128-hex,
 *  - the client-claimed X-Digest equals the server-computed raw-body digest,
 *  - X-Created-At finite and within ±5 min of `now`,
 *  - strict Ed25519 verify of the signature over BLAKE3(canonical string).
 *
 * Hex headers should already be normalized (0x-stripped, lowercased).
 */
export function verifyEnvelope(args: {
  procedure: string;
  actualBodyDigest: string; // server-computed BLAKE3 hex of the raw request body
  now: number;
  headers: EnvelopeHeaders;
}): VerifyEnvelopeResult {
  const { headers } = args;

  if (!headers.publicKey || !headers.signature || !headers.digest || !headers.createdAt) {
    return { ok: false, status: 401, error: "missing signature headers" };
  }
  if (!HEX64.test(headers.publicKey) || !HEX64.test(headers.digest) || !HEX128.test(headers.signature)) {
    return { ok: false, status: 400, error: "malformed signature headers" };
  }

  if (headers.digest !== args.actualBodyDigest) {
    return { ok: false, status: 400, error: "body digest mismatch" };
  }

  const createdAt = Number(headers.createdAt);
  if (!Number.isFinite(createdAt) || Math.abs(args.now - createdAt) > FRESHNESS_WINDOW_MS) {
    return { ok: false, status: 401, error: "stale or future signature" };
  }

  const idempotencyKey = headers.idempotencyKey ?? "";
  const signingDigest = envelopeSigningDigest({
    procedure: args.procedure,
    bodyDigest: headers.digest,
    createdAt,
    idempotencyKey,
  });

  if (!ed25519VerifyHex(headers.publicKey, headers.signature, signingDigest)) {
    return { ok: false, status: 401, error: "invalid signature" };
  }

  return { ok: true, publicKey: headers.publicKey, bodyDigest: headers.digest, idempotencyKey };
}
