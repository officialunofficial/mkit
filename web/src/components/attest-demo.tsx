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

  if (m.status === "loading") return <p>Loading wasm…</p>;
  if (m.status === "error")
    return <p className="text-red-600">wasm init failed: {m.error.message}</p>;

  return (
    <div className="space-y-4">
      <label className="block">
        <span className="mb-1 block text-sm font-medium">Subject commit hash (64 hex)</span>
        <input
          className="w-full rounded-sm border border-gray-300 p-2 font-mono text-xs"
          value={commitHash}
          onChange={(e) => setCommitHash(e.target.value)}
        />
      </label>
      <label className="block">
        <span className="mb-1 block text-sm font-medium">predicateType URI</span>
        <input
          className="w-full rounded-sm border border-gray-300 p-2 font-mono text-xs"
          value={predicateType}
          onChange={(e) => setPredicateType(e.target.value)}
        />
      </label>
      <label className="block">
        <span className="mb-1 block text-sm font-medium">
          Predicate body (must be JCS-canonical JSON object)
        </span>
        <textarea
          className="w-full rounded-sm border border-gray-300 p-2 font-mono text-xs"
          rows={3}
          value={predicateJcs}
          onChange={(e) => setPredicateJcs(e.target.value)}
        />
      </label>
      <label className="block">
        <span className="mb-1 block text-sm font-medium">Signer seed</span>
        <input
          className="w-full rounded-sm border border-gray-300 p-2 font-mono text-xs"
          value={seed}
          onChange={(e) => setSeed(e.target.value)}
        />
      </label>

      {!built ? null : built.ok ? (
        <>
          <Field label="keyid">
            <Mono>{built.att.keyid}</Mono>
          </Field>
          <Field label="attestation_id (BLAKE3 of envelope bytes)">
            <Mono>{built.att.attestation_id_hex}</Mono>
          </Field>
          <Field label="DSSE envelope (JCS-canonical)">
            <Mono>{pretty(built.att.envelope_json)}</Mono>
          </Field>
          <Field label="verify_envelope verdict">
            {verdict === null ? null : (
              <span className={verdict ? "text-green-700" : "text-red-600"}>
                {verdict ? "signature valid ✓" : "signature rejected ✗"}
              </span>
            )}
          </Field>
        </>
      ) : (
        <p className="text-red-600">{built.error}</p>
      )}
    </div>
  );
}

function pretty(json: string): string {
  // The envelope is already canonical (no spaces); soft-wrap long lines
  // by injecting newlines after commas at the top level.
  return json
    .replace(/,"payloadType":/, ',\n"payloadType":')
    .replace(/,"signatures":/, ',\n"signatures":');
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="mb-1 text-sm font-medium text-gray-700">{label}</div>
      <div className="break-all">{children}</div>
    </div>
  );
}

function Mono({ children }: { children: React.ReactNode }) {
  return (
    <code className="block whitespace-pre-wrap rounded-sm bg-gray-100 p-2 font-mono text-xs">
      {children}
    </code>
  );
}
