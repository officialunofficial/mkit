import { Link } from "waku";
import { AttestDemo } from "../components/attest-demo";

export default function AttestPage() {
  return (
    <div className="mx-auto max-w-3xl space-y-8 py-8">
      <title>mkit — attestations</title>
      <header className="space-y-3">
        <p className="text-sm text-[--color-muted]">/attest</p>
        <h1 className="text-4xl font-semibold tracking-tight">Attestations (in-toto v1 + DSSE)</h1>
        <p className="max-w-prose text-base text-[--color-fg]">
          mkit's attestation primitive is the industry-standard combination: an{" "}
          <a
            href="https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md"
            className="underline underline-offset-4 transition-opacity duration-300 hover:opacity-70"
          >
            in-toto v1 Statement
          </a>{" "}
          naming the commit as its subject, wrapped in a{" "}
          <a
            href="https://github.com/secure-systems-lab/dsse/blob/master/envelope.md"
            className="underline underline-offset-4 transition-opacity duration-300 hover:opacity-70"
          >
            DSSE envelope
          </a>
          . The encoder is hand-rolled per RFC 8785 (JCS) because{" "}
          <code className="font-mono text-sm">serde_json::to_string</code> does not satisfy JCS's
          sort + number format rules.
        </p>
      </header>
      <AttestDemo />
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
