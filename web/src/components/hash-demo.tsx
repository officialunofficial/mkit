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

  if (m.status === "loading") return <p>Loading wasm…</p>;
  if (m.status === "error")
    return <p className="text-red-600">wasm init failed: {m.error.message}</p>;
  if (!output) return null;
  if ("error" in output) return <p className="text-red-600">{output.error}</p>;

  return (
    <div className="space-y-4">
      <label className="block">
        <span className="mb-1 block text-sm font-medium">Blob contents</span>
        <textarea
          className="w-full rounded-sm border border-gray-300 p-2 font-mono text-sm"
          rows={3}
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
      </label>
      <label className="block">
        <span className="mb-1 block text-sm font-medium">Commit message</span>
        <input
          className="w-full rounded-sm border border-gray-300 p-2 font-mono text-sm"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
        />
      </label>
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

function previewBytes(bytes: Uint8Array): string {
  const limit = Math.min(bytes.length, 48);
  const hex = bytesToHex(bytes.subarray(0, limit));
  return bytes.length > limit ? `${hex}…` : hex;
}
