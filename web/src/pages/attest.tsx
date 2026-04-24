import { Link } from "waku";
import { AttestDemo } from "../components/attest-demo";

export default function AttestPage() {
  return (
    <div className="max-w-prose space-y-6">
      <title>mkit — attestations</title>
      <h1 className="text-3xl font-bold tracking-tight">Attestations (in-toto v1 + DSSE)</h1>
      <p>
        mkit's attestation primitive is the industry-standard combination: an{" "}
        <a
          href="https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md"
          className="underline"
        >
          in-toto v1 Statement
        </a>{" "}
        naming the commit as its subject, wrapped in a{" "}
        <a
          href="https://github.com/secure-systems-lab/dsse/blob/master/envelope.md"
          className="underline"
        >
          DSSE envelope
        </a>
        . The encoder is hand-rolled per RFC 8785 (JCS) because <code>serde_json::to_string</code>{" "}
        does not satisfy JCS's sort + number format rules.
      </p>
      <AttestDemo />
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
