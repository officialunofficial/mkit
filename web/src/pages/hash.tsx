import { Link } from "waku";
import { HashDemo } from "../components/hash-demo";

export default function HashPage() {
  return (
    <div className="mx-auto max-w-3xl space-y-8 py-8">
      <title>mkit — content-addressed objects</title>
      <header className="space-y-3">
        <p className="text-sm text-[--color-muted]">/hash</p>
        <h1 className="text-4xl font-semibold tracking-tight">Content-addressed objects</h1>
        <p className="max-w-prose text-base text-[--color-fg]">
          Every mkit object starts with the same prologue:{" "}
          <code className="font-mono text-sm">type || "MKT1" || 0x01</code>. The object id is the
          BLAKE3 of its serialized bytes — nothing more. Edit the blob below and watch the hashes
          for the blob, its enclosing tree, and the signed commit rewrite themselves.
        </p>
      </header>
      <HashDemo />
      <Link
        to="/"
        className="-mx-2 inline-block px-2 py-2 text-sm underline underline-offset-4 transition-opacity duration-300 hover:opacity-70"
      >
        ← back
      </Link>
    </div>
  );
}

export const getConfig = async () => {
  return {
    render: "static",
  } as const;
};
