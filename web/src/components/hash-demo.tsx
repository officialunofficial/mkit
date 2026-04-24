"use client";

import { useMemo, useState } from "react";
import { bytesToHex, useMkit } from "./use-mkit";

const DEMO_SEED = "0101010101010101010101010101010101010101010101010101010101010101";

export function HashDemo() {
  const m = useMkit();
  const [text, setText] = useState("hello, mkit");
  const [message, setMessage] = useState("first commit");

  const output = useMemo(() => {
    if (m.status !== "ready") return null;
    try {
      const blob = m.api.blob_encode(new TextEncoder().encode(text));
      const tree = m.api.tree_encode(`[["README.md","blob","${blob.hash_hex}"]]`);
      const commit = m.api.commit_encode_and_sign(tree.hash_hex, "", message, 0n, DEMO_SEED);
      return {
        blobHash: blob.hash_hex,
        blobPreview: previewBytes(blob.bytes),
        treeHash: tree.hash_hex,
        treePreview: previewBytes(tree.bytes),
        commitHash: commit.hash_hex,
        commitVerified: m.api.commit_verify(commit.bytes),
      };
    } catch (e) {
      return { error: e instanceof Error ? e.message : String(e) };
    }
  }, [m, text, message]);

  if (m.status === "loading") return <p className="text-[--color-muted]">Loading wasm…</p>;
  if (m.status === "error")
    return <p className="text-red-600">wasm init failed: {m.error.message}</p>;
  if (!output) return null;
  if ("error" in output) return <p className="text-red-600">{output.error}</p>;

  return (
    <div className="space-y-6">
      <label className="block">
        <span className="mb-2 block text-sm text-[--color-muted]">Blob contents</span>
        <textarea
          className="w-full rounded-md border border-[--color-hairline] bg-transparent p-2.5 font-mono text-sm outline-none focus:border-[--color-fg] transition-colors"
          rows={3}
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
      </label>
      <label className="block">
        <span className="mb-2 block text-sm text-[--color-muted]">Commit message</span>
        <input
          className="w-full rounded-md border border-[--color-hairline] bg-transparent p-2.5 font-mono text-sm outline-none focus:border-[--color-fg] transition-colors"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
        />
      </label>

      <dl className="divide-y divide-[--color-hairline] border-y border-[--color-hairline]">
        <Field label="Blob hash (BLAKE3 of v1 bytes)">
          <Mono>{output.blobHash}</Mono>
        </Field>
        <Field label="Blob bytes (first 48)">
          <Mono>{output.blobPreview}</Mono>
        </Field>
        <Field label="Tree hash (wrapping README.md → blob)">
          <Mono>{output.treeHash}</Mono>
        </Field>
        <Field label="Tree bytes (first 48)">
          <Mono>{output.treePreview}</Mono>
        </Field>
        <Field label="Commit hash (signed)">
          <Mono>{output.commitHash}</Mono>
        </Field>
        <Field label="Commit verifies under the demo key">
          <span className={output.commitVerified ? "text-green-700" : "text-red-600"}>
            {output.commitVerified ? "yes ✓" : "no ✗"}
          </span>
        </Field>
      </dl>
    </div>
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

function Mono({ children }: { children: React.ReactNode }) {
  return <code className="font-mono text-sm">{children}</code>;
}

function previewBytes(bytes: Uint8Array): string {
  const limit = Math.min(bytes.length, 48);
  const hex = bytesToHex(bytes.subarray(0, limit));
  return bytes.length > limit ? `${hex}…` : hex;
}
