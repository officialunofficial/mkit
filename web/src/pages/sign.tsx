import { Link } from "waku";
import { SignDemo } from "../components/sign-demo";

export default function SignPage() {
  return (
    <div className="max-w-prose space-y-6">
      <title>mkit — signing</title>
      <h1 className="text-3xl font-bold tracking-tight">Ed25519 signing + verify</h1>
      <p>
        mkit signs with ZIP-215 / RFC 8032 strict Ed25519 over{" "}
        <code>BLAKE3(domain || signing_bytes)</code>. The <code>mkit.commit\0</code> domain is
        prepended to commit payloads; the domain byte string keeps commit signatures from replaying
        as remix signatures.
      </p>
      <SignDemo />
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
