import { Link } from "waku";
import { HashDemo } from "../components/hash-demo";

export default function HashPage() {
  return (
    <div className="max-w-prose space-y-6">
      <title>mkit — content-addressed objects</title>
      <h1 className="text-3xl font-bold tracking-tight">Content-addressed objects</h1>
      <p>
        Every mkit object starts with the same prologue: <code>type || "MKT1" || 0x01</code>. The
        object id is the BLAKE3 of its serialized bytes — nothing more. Edit the blob below and
        watch the hashes for the blob, its enclosing tree, and the signed commit rewrite themselves.
      </p>
      <HashDemo />
      <Link to="/" className="inline-block underline">
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
