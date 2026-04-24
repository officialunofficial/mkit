"use client";

import { useMemo, useState } from "react";
import { useMkit } from "./use-mkit";

const DEFAULT_SEED = "0101010101010101010101010101010101010101010101010101010101010101";

export function AttestDemo() {
  const m = useMkit();
  const [commitHash, setCommitHash] = useState(
    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
  );
  const [predicateType, setPredicateType] = useState("https://example.com/Review/v1");
  const [predicateJcs, setPredicateJcs] = useState('{"approved":true}');
  const [seed, setSeed] = useState(DEFAULT_SEED);

  const built = useMemo(() => {
    if (m.status !== "ready") return null;
    try {
      const att = m.api.attest_build(
        commitHash.trim(),
        predicateType.trim(),
        new TextEncoder().encode(predicateJcs.trim()),
        seed.trim(),
      );
      return { ok: true as const, att };
    } catch (e) {
      return {
        ok: false as const,
        error: e instanceof Error ? e.message : String(e),
      };
    }
  }, [m, commitHash, predicateType, predicateJcs, seed]);

  const verdict = useMemo(() => {
    if (m.status !== "ready" || !built || !built.ok) return null;
    const kp = m.api.keypair_from_seed(seed.trim());
    return m.api.attest_verify(built.att.envelope_json, kp.pubkey_hex);
  }, [m, built, seed]);

  if (m.status === "loading") return <p className="text-[--color-muted]">Loading wasm…</p>;
  if (m.status === "error")
    return <p className="text-red-600">wasm init failed: {m.error.message}</p>;

  const input =
    "w-full rounded-md border border-[--color-hairline] bg-transparent p-2.5 font-mono text-xs outline-none transition-colors focus:border-[--color-fg]";

  return (
    <div className="space-y-6">
      <label className="block">
        <span className="mb-2 block text-sm text-[--color-muted]">
          Subject commit hash (64 hex)
        </span>
        <input
          className={input}
          value={commitHash}
          onChange={(e) => setCommitHash(e.target.value)}
        />
      </label>
      <label className="block">
        <span className="mb-2 block text-sm text-[--color-muted]">predicateType URI</span>
        <input
          className={input}
          value={predicateType}
          onChange={(e) => setPredicateType(e.target.value)}
        />
      </label>
      <label className="block">
        <span className="mb-2 block text-sm text-[--color-muted]">
          Predicate body (must be JCS-canonical JSON object)
        </span>
        <textarea
          className={input}
          rows={3}
          value={predicateJcs}
          onChange={(e) => setPredicateJcs(e.target.value)}
        />
      </label>
      <label className="block">
        <span className="mb-2 block text-sm text-[--color-muted]">Signer seed</span>
        <input className={input} value={seed} onChange={(e) => setSeed(e.target.value)} />
      </label>

      {!built ? null : built.ok ? (
        <dl className="divide-y divide-[--color-hairline] border-y border-[--color-hairline]">
          <Field label="keyid">
            <code className="font-mono text-sm break-all">{built.att.keyid}</code>
          </Field>
          <Field label="attestation_id (BLAKE3 of envelope bytes)">
            <code className="font-mono text-sm break-all">{built.att.attestation_id_hex}</code>
          </Field>
          <Field label="DSSE envelope (JCS-canonical)">
            <code className="block font-mono text-xs break-all whitespace-pre-wrap">
              {pretty(built.att.envelope_json)}
            </code>
          </Field>
          <Field label="verify_envelope verdict">
            {verdict === null ? null : (
              <span className={verdict ? "text-green-700" : "text-red-600"}>
                {verdict ? "signature valid ✓" : "signature rejected ✗"}
              </span>
            )}
          </Field>
        </dl>
      ) : (
        <p className="text-red-600">{built.error}</p>
      )}
    </div>
  );
}

function pretty(json: string): string {
  return json
    .replace(/,"payloadType":/, ',\n"payloadType":')
    .replace(/,"signatures":/, ',\n"signatures":');
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid gap-1 py-4 sm:grid-cols-[minmax(0,14rem),1fr] sm:gap-6">
      <dt className="text-sm text-[--color-muted]">{label}</dt>
      <dd className="min-w-0 break-all">{children}</dd>
    </div>
  );
}
