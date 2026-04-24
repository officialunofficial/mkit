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

  if (m.status === "loading") return <p className="text-[--color-muted]">Loading wasm…</p>;
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
    <div className="space-y-6">
      <label className="block">
        <span className="mb-2 block text-sm text-[--color-muted]">
          Ed25519 seed (32 bytes, 64 hex chars)
        </span>
        <input
          className="w-full rounded-md border border-[--color-hairline] bg-transparent p-2.5 font-mono text-xs outline-none transition-colors focus:border-[--color-fg]"
          value={seed}
          onChange={(e) => setSeed(e.target.value.trim())}
        />
      </label>
      <Button onClick={fresh}>Generate fresh seed</Button>

      <dl className="divide-y divide-[--color-hairline] border-y border-[--color-hairline]">
        <Field label="Derived public key">
          {keypair && "error" in keypair ? (
            <span className="text-red-600">{keypair.error}</span>
          ) : keypair ? (
            <code className="font-mono text-sm">{keypair.pubkey_hex}</code>
          ) : null}
        </Field>
      </dl>

      <label className="block">
        <span className="mb-2 block text-sm text-[--color-muted]">
          Message to sign (under <code className="font-mono text-xs">mkit.commit\0</code> domain)
        </span>
        <input
          className="w-full rounded-md border border-[--color-hairline] bg-transparent p-2.5 font-mono text-sm outline-none transition-colors focus:border-[--color-fg]"
          value={message}
          onChange={(e) => {
            setMessage(e.target.value);
            setSig(null);
          }}
        />
      </label>
      <Button onClick={doSign} disabled={!keypair || "error" in (keypair ?? {})}>
        Sign
      </Button>

      {sig ? (
        <>
          <dl className="divide-y divide-[--color-hairline] border-y border-[--color-hairline]">
            <Field label="Signature (Ed25519, 64 bytes hex)">
              <code className="font-mono text-xs break-all">{sig}</code>
            </Field>
          </dl>
          <label className="flex cursor-pointer items-center gap-2 py-2 text-sm">
            <input
              type="checkbox"
              className="accent-[--color-fg]"
              checked={tamper}
              onChange={(e) => setTamper(e.target.checked)}
            />
            Tamper last byte of message before verify
          </label>
          <dl className="divide-y divide-[--color-hairline] border-y border-[--color-hairline]">
            <Field label="Verify verdict">
              {verdict === null ? null : (
                <span className={verdict ? "text-green-700" : "text-red-600"}>
                  {verdict ? "signature valid ✓" : "signature rejected ✗"}
                </span>
              )}
            </Field>
          </dl>
        </>
      ) : null}
    </div>
  );
}

/**
 * Flat button in the searchartwith.art style: rounded-lg, h-8, 14px
 * medium, transparent bg, thin border that appears on hover, subtle
 * `translate-y-px` press feedback instead of scale.
 */
function Button({
  children,
  onClick,
  disabled,
}: {
  children: React.ReactNode;
  onClick: () => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="inline-flex h-9 shrink-0 items-center justify-center rounded-lg border border-[--color-hairline] bg-transparent px-3 text-sm font-medium transition-all duration-200 hover:border-[--color-fg] active:translate-y-px disabled:pointer-events-none disabled:opacity-50"
    >
      {children}
    </button>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid gap-1 py-4 sm:grid-cols-[minmax(0,14rem),1fr] sm:gap-6">
      <dt className="text-sm text-[--color-muted]">{label}</dt>
      <dd className="min-w-0 break-all">{children}</dd>
    </div>
  );
}
