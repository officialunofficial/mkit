import { Link } from "waku";

export default function HomePage() {
  return (
    <div className="max-w-prose space-y-6">
      <title>mkit demo</title>
      <h1 className="text-4xl font-bold tracking-tight">mkit, in a browser</h1>
      <p>
        <a href="https://github.com/officialunofficial/mkit" className="underline">
          mkit
        </a>{" "}
        is a content-addressed version control toolkit written in Rust. This site takes the pure
        portions of <code>mkit-core</code> and <code>mkit-attest</code>, compiles them to
        WebAssembly, and exposes three interactive demos so you can poke at the mechanics without
        installing anything.
      </p>
      <p className="text-sm text-gray-600">
        The site itself is a{" "}
        <a href="https://waku.gg/" className="underline">
          Waku
        </a>{" "}
        React app served by Cloudflare Workers Static Assets. All wasm calls run client-side.
      </p>

      <ul className="space-y-3">
        <Demo
          to="/hash"
          title="Content-addressed objects"
          body="Encode a blob, wrap it in a tree, sign a commit — watch the BLAKE3 hashes fall out of the canonical v1 byte format."
        />
        <Demo
          to="/sign"
          title="Ed25519 signing"
          body="Generate a keypair, sign a message under mkit's commit domain, verify it. Flip a bit and watch the verdict flip."
        />
        <Demo
          to="/attest"
          title="Attestations"
          body="Wrap a commit hash in an in-toto v1 Statement, sign it into a DSSE envelope, and verify it back against the signer's public key."
        />
      </ul>
    </div>
  );
}

function Demo({ to, title, body }: { to: string; title: string; body: string }) {
  return (
    <li>
      <Link to={to} className="block rounded-sm border border-gray-300 p-3 hover:border-black">
        <span className="block font-semibold">{title} →</span>
        <span className="text-sm text-gray-700">{body}</span>
      </Link>
    </li>
  );
}

export const getConfig = async () => {
  return {
    render: "static",
  } as const;
};
