/// <reference types="@cloudflare/workers-types" />
// Documentation example; API reviewed against mppx commit dcf15895.
import { CURVE, etc, Point, verifyAsync } from '@noble/ed25519';
import { blake3 } from '@noble/hashes/blake3';
import { Challenge, Credential, Errors } from 'mppx';
import { Mppx, Store, tempo } from 'mppx/server';
import { createClient, decodeFunctionData, http, keccak256, parseEventLogs, TransactionReceiptNotFoundError } from 'viem';
import { getTransactionReceipt, sendRawTransaction } from 'viem/actions';
import { tempoModerato } from 'viem/chains';
import { Abis, Transaction } from 'viem/tempo';

const ADMIT = '/mkit.server.hooks.v1.HooksService/Admit';
const OUTCOME = '/mkit.server.hooks.v1.HooksService/Outcome';
const encoder = new TextEncoder();
// EXAMPLE RATE: one token atomic unit per declared byte; six token decimals.
const EXAMPLE_ATOMIC_UNITS_PER_BYTE = 1n;
const EXAMPLE_MINIMUM_ATOMIC_UNITS = 1n; // Covers zero-byte ref-only writes.
const EXAMPLE_CHALLENGE_LIFETIME_MS = 24 * 60 * 60 * 1000;

type Header = { name: string; value: string };
type Operation = {
  audience: string; repository: string; procedure: string;
  principal: {
    signer?: { ed25519PublicKey: string }; anonymous?: {};
    bearerHolder?: {}; transportPeer?: { ed25519PublicKey: string };
    sshForcedCommand?: { ed25519PublicKey?: string };
  };
  idempotencyKey?: string; refs?: unknown[]; owner?: boolean;
  grant?: { grantId: string; epoch: string };
};
type AdmitRequest = {
  operation: Operation; declaredBytes?: string; packId?: string;
  createsNamespace?: boolean; createsRepo?: boolean; newToRepoBytes?: string;
  // WP-3.6b: repeated Header credential_headers = 7, proto JSON lowerCamelCase.
  credentialHeaders?: Header[];
};
type OutcomeRequest = {
  outcome: {
    reservationId: string; audience: string; repository: string; occurredUnixMs: string;
    committed?: { bytesStored?: string; newToRepo?: string; newToStore?: string; refs?: unknown[] };
    aborted?: { reason?: string; detail?: string }; expired?: {};
    readServed?: { object: string; bytesServed: string };
  };
};
type VerifyOptions = NonNullable<Parameters<ReturnType<typeof Mppx.create>['validateCredential']>[1]>;
type Reservation = {
  audience: string; repository: string; credential?: string; options?: VerifyOptions;
  signedTransaction?: `0x${string}`; transactionHash: `0x${string}`;
  expectedPayment?: { currency: `0x${string}`; from: `0x${string}`; to: `0x${string}`; amount: string; memo: `0x${string}` };
  state: 'reserved' | 'settling' | 'settled' | 'released';
  terminalKind?: 'committed' | 'aborted' | 'expired';
};
interface Env {
  RESERVATIONS: DurableObjectNamespace;
  MPP_SECRET_KEY: string; PAYMENT_CURRENCY: `0x${string}`; PAYMENT_RECIPIENT: `0x${string}`;
  TEMPO_RPC_URL: string; PAYMENT_REALM: string; MKIT_AUDIENCE: string;
  BEARER_AUTHENTICATED: string; HOOK_HTTP_SIGNATURES: string;
  HOOK_AUDIENCE: string; HOOK_KEY_LIST_JSON?: string;
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}
function failure(code: string, status: number): Response {
  // Never include SDK exceptions: they may contain credential headers or receipts.
  return json({ code, message: 'Hook request could not be processed.' }, status);
}
function deny(): Response {
  return json({ deny: { code: 'permission_denied', message: 'Payment credential is invalid or already reserved.' } });
}
function uint64(value: string): bigint {
  if (!/^(0|[1-9][0-9]*)$/.test(value)) throw new Error('Invalid uint64');
  const result = BigInt(value);
  if (result > (1n << 64n) - 1n) throw new Error('Invalid uint64');
  return result;
}
function price(bytes: bigint): string {
  const calculated = bytes * EXAMPLE_ATOMIC_UNITS_PER_BYTE;
  const units = calculated > EXAMPLE_MINIMUM_ATOMIC_UNITS ? calculated : EXAMPLE_MINIMUM_ATOMIC_UNITS;
  return `${units / 1000000n}.${(units % 1000000n).toString().padStart(6, '0')}`;
}
function binding(input: AdmitRequest, env: Env) {
  const op = input.operation;
  if (op.audience !== env.MKIT_AUDIENCE || !op.repository || !op.procedure || !op.principal)
    throw new Error('Invalid operation');
  const bytes = uint64(input.declaredBytes ?? '0');
  const meta = {
    audience: op.audience, repository: op.repository,
    signer: op.principal.signer?.ed25519PublicKey ?? JSON.stringify(op.principal),
    packId: input.packId ?? '', declaredBytes: bytes.toString(), procedure: op.procedure,
  };
  return {
    request: { amount: price(bytes), currency: env.PAYMENT_CURRENCY, recipient: env.PAYMENT_RECIPIENT, feePayer: false },
    meta, realm: env.PAYMENT_REALM,
    scope: hex(blake3(encoder.encode(JSON.stringify(meta)))),
  };
}
function paymentHeader(input: AdmitRequest, env: Env): string | undefined {
  const headers = input.credentialHeaders ?? [];
  if (!Array.isArray(headers) || headers.length > 8) throw new Error('Invalid credential headers');
  const acceptedName = env.BEARER_AUTHENTICATED === 'true' ? 'payment-authorization' : 'authorization';
  let found: string | undefined;
  for (const header of headers) {
    if (typeof header.name !== 'string' || typeof header.value !== 'string' ||
        header.value.length > 8192 || !/^[\x20-\x7e]*$/.test(header.value))
      throw new Error('Invalid credential header');
    if (header.name.toLowerCase() !== acceptedName) continue;
    if (found !== undefined || !/^Payment /i.test(header.value)) throw new Error('Invalid payment header');
    found = header.value;
  }
  return found;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const path = new URL(request.url).pathname;
    if (request.method !== 'POST' || ![ADMIT, OUTCOME].includes(path))
      return failure('unimplemented', 501);
    if (request.headers.get('Content-Type')?.split(';')[0].trim() !== 'application/json')
      return failure('invalid_argument', 400);
    // Default: service binding only; wrangler disables public and preview URLs.
    return env.RESERVATIONS.get(env.RESERVATIONS.idFromName('mppx-reference')).fetch(request);
  },
};

// One object serializes admission claims, outcomes, and HTTP nonce claims.
// KV cannot atomically claim a credential or exclude concurrent settlement.
export class Reservations {
  private tail: Promise<unknown> = Promise.resolve();
  constructor(private ctx: DurableObjectState, private env: Env) {}

  fetch(request: Request): Promise<Response> {
    const result = this.tail.then(() => this.handle(request));
    this.tail = result.catch(() => undefined);
    return result;
  }

  private store(): Store.AtomicStore {
    const storage = this.ctx.storage;
    return {
      get: async key => (await storage.get(key)) ?? null,
      put: async (key, value) => { await storage.put(key, value); },
      delete: async key => { await storage.delete(key); },
      update: async (key, fn) => storage.transaction(async txn => {
        const change = fn((await txn.get(key)) ?? null);
        if (change.op === 'set') await txn.put(key, change.value);
        if (change.op === 'delete') await txn.delete(key);
        return change.result;
      }),
    };
  }

  private client() {
    return createClient({ chain: tempoModerato, transport: http(this.env.TEMPO_RPC_URL) });
  }
  private payment() {
    return Mppx.create({
      methods: [tempo.charge({
        testnet: true, currency: this.env.PAYMENT_CURRENCY, recipient: this.env.PAYMENT_RECIPIENT,
        decimals: 6, supportedModes: ['pull'], store: this.store(),
        getClient: () => this.client(),
        // No sponsor: canonical transaction bytes stay fixed through retries.
      })],
      realm: this.env.PAYMENT_REALM, secretKey: this.env.MPP_SECRET_KEY,
      requiresAuth: this.env.BEARER_AUTHENTICATED === 'true',
    });
  }

  private async handle(request: Request): Promise<Response> {
    try {
      if (this.env.HOOK_HTTP_SIGNATURES === 'true') {
        try {
          const verifyHookSignature = createHookVerifier({
            audience: this.env.HOOK_AUDIENCE,
            consumeNonce: (nonce, expires, now) => this.claimNonce(nonce, expires, now),
          });
          await verifyHookSignature(request, JSON.parse(this.env.HOOK_KEY_LIST_JSON ?? ''));
        } catch { return failure('unauthenticated', 401); }
      }
      // Do not log the request, credentialHeaders, SDK exceptions, or payment receipts.
      const input = await request.json();
      return new URL(request.url).pathname === ADMIT
        ? await this.admit(input as AdmitRequest)
        : await this.outcome(input as OutcomeRequest);
    } catch { return failure('unavailable', 503); }
  }

  private async admit(input: AdmitRequest): Promise<Response> {
    const options = binding(input, this.env);
    let credential: string | undefined;
    try { credential = paymentHeader(input, this.env); } catch { return deny(); }
    const payment = this.payment();
    if (!credential) {
      // No reservation state is written on a challenge.
      const challenge = await payment.challenge.tempo.charge({
        ...options.request, meta: options.meta, scope: options.scope,
        description: 'Example payment for declared storage bytes',
        expires: new Date(Date.now() + EXAMPLE_CHALLENGE_LIFETIME_MS).toISOString(),
      });
      const value = Challenge.serialize(challenge); // Complete "Payment …" value.
      if (value.length > 8192 || !/^[\x20-\x7e]*$/.test(value)) throw new Error('Challenge limit');
      return json({ challenge: {
        challenges: [{ scheme: 'payment', value }],
        description: 'Authorize payment for the declared storage bytes; settlement follows commit.',
        responseHeaders: [{ name: 'WWW-Authenticate', value }],
      } });
    }
    let validation: Awaited<ReturnType<typeof payment.validateCredential>>;
    // Decode syntax separately; transport/RPC failures must remain retryable.
    let decoded: ReturnType<typeof Credential.deserialize>;
    try { decoded = Credential.deserialize(credential); } catch { return deny(); }
    try { validation = await payment.validateCredential(decoded, options); }
    catch (error) {
      if (error instanceof Errors.PaymentError && !(error instanceof Errors.InternalPaymentError)) return deny();
      if (error instanceof Error && error.name === 'ZodError') return deny();
      throw error;
    }
    const payload = validation.credential.payload as { type?: string; signature?: string };
    // Push/hash credentials already paid; zero-amount proofs do not fund storage.
    if (payload.type !== 'transaction' || typeof payload.signature !== 'string') return deny();
    const signedTransaction = await Transaction.serialize(Transaction.deserialize(
      payload.signature as Transaction.TransactionSerializedTempo,
    ));
    const transactionHash = keccak256(signedTransaction);
    const transaction = Transaction.deserialize(signedTransaction as Transaction.TransactionSerializedTempo);
    const amount = String(validation.request.amount); // SDK-normalized atomic units.
    let expectedPayment: Reservation['expectedPayment'];
    for (const call of transaction.calls) {
      if (call.to?.toLowerCase() !== this.env.PAYMENT_CURRENCY.toLowerCase() || !call.data) continue;
      try {
        const decoded = decodeFunctionData({ abi: Abis.tip20, data: call.data });
        if (decoded.functionName !== 'transferWithMemo') continue;
        const [to, units, memo] = decoded.args;
        if (to.toLowerCase() !== this.env.PAYMENT_RECIPIENT.toLowerCase() || units.toString() !== amount) continue;
        // validateCredential has already checked this call's challenge-bound memo.
        expectedPayment = { currency: this.env.PAYMENT_CURRENCY, from: transaction.from!, to, amount, memo };
        break;
      } catch { continue; }
    }
    if (!expectedPayment) return deny();
    if (await this.receipt(transactionHash)) return deny();
    const reservationId = `mppx:${crypto.randomUUID()}`; // Never use idempotencyKey.
    const row: Reservation = {
      audience: input.operation.audience, repository: input.operation.repository,
      credential, options, signedTransaction, transactionHash, expectedPayment, state: 'reserved',
    };
    const accepted = await this.ctx.storage.transaction(async txn => {
      const challengeKey = `challenge:${validation.challenge.id}`;
      const transactionKey = `transaction:${transactionHash}`;
      if (await txn.get(challengeKey) || await txn.get(transactionKey)) return false;
      await txn.put(challengeKey, reservationId);
      await txn.put(transactionKey, reservationId);
      await txn.put(`reservation:${reservationId}`, row);
      return true;
    });
    return accepted ? json({ allow: { reservationId } }) : deny();
  }

  private async receipt(hash: `0x${string}`) {
    try { return await getTransactionReceipt(this.client(), { hash }); }
    catch (error) {
      if (error instanceof TransactionReceiptNotFoundError) return null;
      throw error; // RPC failure is not evidence of absence.
    }
  }

  private async outcome(input: OutcomeRequest): Promise<Response> {
    const out = input.outcome;
    const kinds = ['committed', 'aborted', 'expired', 'readServed'] as const;
    const selected = kinds.filter(kind => out[kind] !== undefined);
    if (selected.length !== 1 || selected[0] === 'readServed' ||
        !/^[A-Za-z0-9._:-]{1,128}$/.test(out.reservationId))
      return failure('invalid_argument', 400);
    const kind = selected[0] as 'committed' | 'aborted' | 'expired';
    const key = `reservation:${out.reservationId}`;
    const row = await this.ctx.storage.get<Reservation>(key);
    if (!row || row.audience !== out.audience || row.repository !== out.repository)
      return failure('failed_precondition', 400);
    if (row.terminalKind && row.terminalKind !== kind) return failure('failed_precondition', 400);
    if (row.state === 'settled' || row.state === 'released') return json({});
    if (kind !== 'committed') {
      // Validation held no funds: release our local reservation, discard the secret.
      await this.ctx.storage.put(key, {
        audience: row.audience, repository: row.repository, transactionHash: row.transactionHash,
        state: 'released', terminalKind: kind,
      } satisfies Reservation);
      return json({});
    }
    const recovering = row.state === 'settling';
    row.state = 'settling';
    row.terminalKind = 'committed';
    await this.ctx.storage.put(key, row); // Durable before any external effect.
    let receipt = await this.receipt(row.transactionHash);
    if (!receipt) {
      if (!recovering) {
        // SDK revalidates before settling. An ambiguous result leaves "settling".
        await this.payment().broadcastCredential(row.credential!, row.options!);
      } else {
        // The SDK retains replay claims after an ambiguous broadcast. Recovery
        // resends ONLY the persisted canonical signed bytes (Charge.ts:633–638).
        // Their immutable hash and chain nonce prevent another transfer.
        const expiry = Transaction.deserialize(row.signedTransaction! as Transaction.TransactionSerializedTempo).validBefore;
        if (expiry !== undefined && BigInt(expiry) <= BigInt(Math.floor(Date.now() / 1000)))
          return failure('unavailable', 503); // Keep reconciling; operator action may be needed.
        const hash = await sendRawTransaction(this.client(), { serializedTransaction: row.signedTransaction! });
        if (hash !== row.transactionHash) throw new Error('Settlement hash mismatch');
      }
      receipt = await this.receipt(row.transactionHash);
    }
    if (!receipt || receipt.status !== 'success') return failure('unavailable', 503);
    // Recovery must prove the transfer too, matching the SDK's receipt checks
    // for this single-recipient, non-sponsored, memo-bound payment.
    const expected = row.expectedPayment!;
    const matched = parseEventLogs({ abi: Abis.tip20, eventName: 'TransferWithMemo', logs: receipt.logs }).some(log =>
      log.address.toLowerCase() === expected.currency.toLowerCase() &&
      log.args.from.toLowerCase() === expected.from.toLowerCase() &&
      log.args.to.toLowerCase() === expected.to.toLowerCase() &&
      log.args.amount.toString() === expected.amount &&
      log.args.memo.toLowerCase() === expected.memo.toLowerCase());
    if (!matched) return failure('unavailable', 503);
    // Keep a tombstone for all redeliveries; remove credentials and signed bytes.
    await this.ctx.storage.put(key, {
      audience: row.audience, repository: row.repository, transactionHash: row.transactionHash,
      state: 'settled', terminalKind: 'committed',
    } satisfies Reservation);
    return json({});
  }

  private async claimNonce(nonce: string, expires: bigint, now: bigint): Promise<boolean> {
    return this.ctx.storage.transaction(async txn => {
      const key = `hook-nonce:${nonce}`;
      const previous = await txn.get<string>(key);
      if (previous !== undefined && BigInt(previous) > now) return false;
      await txn.put(key, expires.toString());
      return true;
    });
  }
}

// Optional HTTP channel authentication, separate from payment verification.
export type HookKeyList = {
  version: 1;
  keys: { keyId: string; alg: 'ed25519'; publicKey: string; notBeforeMs?: string; notAfterMs?: string }[];
};
type SignaturePolicy = {
  audience: string;
  consumeNonce: (nonce: string, expires: bigint, now: bigint) => Promise<boolean>;
  nowMs?: bigint; // Fixed clock only for golden-vector checks.
};
function hex(bytes: Uint8Array): string {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}
function unhex(value: string): Uint8Array {
  return Uint8Array.from(value.match(/../g)!, byte => Number.parseInt(byte, 16));
}
function timestamp(value: string, signed = false): bigint {
  if (!(signed ? /^-?(0|[1-9][0-9]*)$/ : /^(0|[1-9][0-9]*)$/).test(value))
    throw new Error('Invalid timestamp');
  const result = BigInt(value);
  if (result < -(1n << 63n) || result > (1n << 63n) - 1n) throw new Error('Timestamp overflow');
  return result;
}

// keyList has the exact §7.2 JSON shape; policy supplies trusted deployment
// origin and an atomic, durable nonce cache. Never derive that origin from Host.
export function createHookVerifier(policy: SignaturePolicy) {
  return async function verifyHookSignature(request: Request, keyList: HookKeyList) {
    const header = (name: string): string => {
      const value = request.headers.get(`X-Mkit-Hook-${name}`);
      if (value === null) throw new Error('Missing hook header');
      return value;
    };
    if (header('Version') !== '1') throw new Error('Unsupported hook version');
    // Require every header before reading any body bytes (§7.1).
    const keyId = header('Key-Id'), audience = header('Audience'), created = header('Created-At');
    const expires = header('Expires-At'), nonce = header('Nonce'), digest = header('Digest');
    const signature = header('Signature');
    const procedure = new URL(request.url).pathname;
    if (![ADMIT, OUTCOME].includes(procedure) || !/^[A-Za-z0-9._-]{1,64}$/.test(keyId) ||
        !/^[0-9a-f]{64}$/.test(nonce) || !/^body:[0-9a-f]{64}$/.test(digest) ||
        !/^[0-9a-f]{128}$/.test(signature)) throw new Error('Invalid hook envelope');
    const origin = new URL(policy.audience);
    if (origin.origin !== policy.audience || origin.username || origin.password ||
        (origin.protocol !== 'https:' && !(origin.protocol === 'http:' &&
          ['localhost', '127.0.0.1', '[::1]'].includes(origin.hostname))) || audience !== policy.audience)
      throw new Error('Hook audience mismatch');
    const start = timestamp(created), end = timestamp(expires), now = policy.nowMs ?? BigInt(Date.now());
    if (end <= start || end - start > 300000n || start > now + 30000n || end <= now)
      throw new Error('Hook validity window');
    if (keyList.version !== 1 || !Array.isArray(keyList.keys)) throw new Error('Invalid key list');
    const candidates = keyList.keys.filter(key => key.keyId === keyId);
    if (candidates.length !== 1) throw new Error('Unknown or duplicate key id');
    const key = candidates[0];
    if (key.alg !== 'ed25519' || !/^[0-9a-f]{64}$/.test(key.publicKey) ||
        (key.notBeforeMs !== undefined && now < timestamp(key.notBeforeMs, true)) ||
        (key.notAfterMs !== undefined && now >= timestamp(key.notAfterMs, true)))
      throw new Error('Hook key validity');
    const body = new Uint8Array(await request.clone().arrayBuffer());
    const bodyDigest = `body:${hex(blake3(body))}`;
    if (digest !== bodyDigest) throw new Error('Hook body digest mismatch');
    const canonical = ['mkit-hook:v1', keyId, audience, procedure, bodyDigest, created, expires, nonce].join('\n');
    const hash = blake3(encoder.encode(canonical));
    const publicKey = unhex(key.publicKey), sig = unhex(signature);
    // Dalek verify_strict: reject small-order A/R and noncanonical encodings/S.
    const a = Point.fromHex(publicKey, false), r = Point.fromHex(sig.slice(0, 32), false);
    if (a.isSmallOrder() || r.isSmallOrder() ||
        !await verifyAsync(sig, hash, publicKey, { zip215: false })) throw new Error('Hook signature invalid');
    // noble 2.3 still uses a cofactored verification equation. Check the exact
    // uncofactored equation too, matching Rust's dalek verify_strict.
    const littleEndian = (bytes: Uint8Array) => BigInt(`0x${hex(bytes.slice().reverse())}`);
    const s = littleEndian(sig.slice(32));
    const k = littleEndian(await etc.sha512Async(sig.slice(0, 32), publicKey, hash)) % CURVE.n;
    const multiply = (point: Point, scalar: bigint) => scalar === 0n ? Point.ZERO : point.multiply(scalar, false);
    if (!multiply(Point.BASE, s).equals(r.add(multiply(a, k)))) throw new Error('Hook signature invalid');
    if (!await policy.consumeNonce(nonce, end, now)) throw new Error('Hook nonce replay');
    return { bodyDigest, canonical, canonicalBlake3: hex(hash), verified: true };
  };
}
