import { Link } from "waku";

export default function HomePage() {
  return (
    <div className="mx-auto max-w-3xl space-y-10 py-8">
      <title>mkit demo</title>
      <section className="space-y-4">
        <h1 className="text-5xl font-semibold tracking-tight">mkit, in a browser</h1>
        <p className="text-base text-[--color-fg]">
          <a
            href="https://github.com/officialunofficial/mkit"
            className="underline underline-offset-4 transition-opacity duration-300 hover:opacity-70"
          >
            mkit
          </a>{" "}
          is a content-addressed version control toolkit written in Rust. This page compiles the
          pure portions of <code className="font-mono text-sm">mkit-core</code> and{" "}
          <code className="font-mono text-sm">mkit-attest</code> to WebAssembly and exposes three
          interactive demos you can poke at without installing anything.
        </p>
        <p className="text-sm text-[--color-muted]">
          The site is a{" "}
          <a
            href="https://waku.gg/"
            className="underline underline-offset-4 transition-opacity duration-300 hover:opacity-70"
          >
            Waku
          </a>{" "}
          React app served by Cloudflare Workers Static Assets. All wasm calls run client-side.
        </p>
      </section>

      <ul className="divide-y divide-[--color-hairline] border-y border-[--color-hairline]">
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
      {/* Editorial row, inspired by the searchartwith.art card style:
          flat, thin-divider separated, opacity on hover — no shadows,
          no radius. Arrow nudges right on hover as tactile affordance. */}
      <Link
        to={to}
        className="group flex items-start justify-between gap-6 py-5 transition-opacity duration-300 hover:opacity-70"
      >
        <div className="space-y-1">
          <div className="text-base font-medium">{title}</div>
          <p className="max-w-prose text-sm text-[--color-muted]">{body}</p>
        </div>
        <span
          aria-hidden
          className="mt-0.5 shrink-0 text-base transition-transform duration-300 ease-[cubic-bezier(0.2,0,0,1)] group-hover:translate-x-1"
        >
          →
        </span>
      </Link>
    </li>
  );
}

export const getConfig = async () => {
  return {
    render: "static",
  } as const;
};
