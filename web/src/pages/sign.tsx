import { Link } from "waku";
import { SignDemo } from "../components/sign-demo";

export default function SignPage() {
  return (
    <div className="mx-auto max-w-3xl space-y-8 py-8">
      <title>mkit — signing</title>
      <header className="space-y-3">
        <p className="text-sm text-[--color-muted]">/sign</p>
        <h1 className="text-4xl font-semibold tracking-tight">Ed25519 signing + verify</h1>
        <p className="max-w-prose text-base text-[--color-fg]">
          mkit signs with ZIP-215 / RFC 8032 strict Ed25519 over{" "}
          <code className="font-mono text-sm">BLAKE3(domain || signing_bytes)</code>. The{" "}
          <code className="font-mono text-sm">mkit.commit\0</code> domain is prepended to commit
          payloads; the domain byte string keeps commit signatures from replaying as remix
          signatures.
        </p>
      </header>
      <SignDemo />
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
