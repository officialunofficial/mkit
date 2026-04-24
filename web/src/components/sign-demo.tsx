"use client";

import { useMemo, useState } from "react";
import { useMkit } from "./use-mkit";

const DEFAULT_SEED = "0101010101010101010101010101010101010101010101010101010101010101";

export function SignDemo() {
  const m = useMkit();
  const [seed, setSeed] = useState(DEFAULT_SEED);
  const [message, setMessage] = useState("attest this commit");
  const [sig, setSig] = useState<string | null>(null);
  const [tamper, setTamper] = useState(false);

  const keypair = useMemo(() => {
    if (m.status !== "ready") return null;
    try {
      return m.api.keypair_from_seed(seed);
    } catch (e) {
      return { error: e instanceof Error ? e.message : String(e) };
    }
  }, [m, seed]);

  const verdict = useMemo(() => {
    if (m.status !== "ready" || !keypair || "error" in keypair || !sig) {
      return null;
    }
    const probed = new TextEncoder().encode(
      tamper ? message.replace(/.$/, (c) => String.fromCharCode(c.charCodeAt(0) ^ 1)) : message,
    );
    return m.api.verify_bytes_commit_domain(keypair.pubkey_hex, probed, sig);
  }, [m, keypair, sig, message, tamper]);

  if (m.status === "loading") return <p>Loading wasm…</p>;
  if (m.status === "error")
    return <p className="text-red-600">wasm init failed: {m.error.message}</p>;

  const fresh = () => {
    if (m.status !== "ready") return;
    const kp = m.api.keypair_generate();
    setSeed(kp.seed_hex);
    setSig(null);
    setTamper(false);
  };

  const doSign = () => {
    if (m.status !== "ready") return;
    const bytes = new TextEncoder().encode(message);
    setSig(m.api.sign_bytes_commit_domain(seed, bytes));
    setTamper(false);
  };

  return (
    <div className="space-y-4">
      <label className="block">
        <span className="mb-1 block text-sm font-medium">
          Ed25519 seed (32 bytes, 64 hex chars)
        </span>
        <input
          className="w-full rounded-sm border border-gray-300 p-2 font-mono text-xs"
          value={seed}
          onChange={(e) => setSeed(e.target.value.trim())}
        />
      </label>
      <button
        type="button"
        className="rounded-xs bg-black px-2 py-0.5 text-sm text-white"
        onClick={fresh}
      >
        Generate fresh seed
      </button>

      <Field label="Derived public key">
        {keypair && "error" in keypair ? (
          <span className="text-red-600">{keypair.error}</span>
        ) : keypair ? (
          <Mono>{keypair.pubkey_hex}</Mono>
        ) : null}
      </Field>

      <label className="block">
        <span className="mb-1 block text-sm font-medium">
          Message to sign (signed under `mkit.commit\0` domain)
        </span>
        <input
          className="w-full rounded-sm border border-gray-300 p-2 font-mono text-sm"
          value={message}
          onChange={(e) => {
            setMessage(e.target.value);
            setSig(null);
          }}
        />
      </label>
      <button
        type="button"
        className="rounded-xs bg-black px-2 py-0.5 text-sm text-white"
        onClick={doSign}
        disabled={!keypair || "error" in (keypair ?? {})}
      >
        Sign
      </button>

      {sig ? (
        <>
          <Field label="Signature (Ed25519, 64 bytes hex)">
            <Mono>{sig}</Mono>
          </Field>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={tamper} onChange={(e) => setTamper(e.target.checked)} />
            Tamper last byte of message before verify
          </label>
          <Field label="Verify verdict">
            {verdict === null ? null : (
              <span className={verdict ? "text-green-700" : "text-red-600"}>
                {verdict ? "signature valid ✓" : "signature rejected ✗"}
              </span>
            )}
          </Field>
        </>
      ) : null}
    </div>
  );
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
  return <code className="block rounded-sm bg-gray-100 p-2 font-mono text-xs">{children}</code>;
}
