'use client';

// Landing-page demo grid. Mirrors the divider-separated list from the
// existing site at `web/src/pages/index.tsx` — title + description on
// the left, a right-arrow that nudges on hover. Color tokens are Vocs
// CSS variables so the component follows the framework's dark/light
// mode automatically.

import type { CSSProperties } from "react";

type Demo = {
  href: string;
  title: string;
  body: string;
};

const demos: readonly Demo[] = [
  {
    href: "/demos/hash",
    title: "hash",
    body: "Edit a file and watch the BLAKE3 hashes of every container that holds it — folder, parent folder, commit — rewrite live.",
  },
  {
    href: "/demos/sign",
    title: "sign",
    body: "Generate a key, sign a message, flip a character, watch the verifier reject it.",
  },
  {
    href: "/demos/attest",
    title: "attest",
    body: "Attach a signed statement to a commit so anyone with your public key can verify it later.",
  },
  {
    href: "/demos/tree",
    title: "tree",
    body: "A Merkle tree of BLAKE3 hashes — edit any file and the hashes ripple up to the commit at the root.",
  },
  {
    href: "/demos/streaming",
    title: "streaming",
    body: "Why git stops working on a 2 GB video — and how mkit handles it in 40 KB.",
  },
] as const;

const listStyle: CSSProperties = {
  listStyle: "none",
  margin: "48px 0 0",
  padding: 0,
  borderTop: "1px solid var(--vocs-color_border)",
  borderBottom: "1px solid var(--vocs-color_border)",
};

const itemStyle: CSSProperties = {
  borderTop: "1px solid var(--vocs-color_border)",
};

// The first item picks up the list's top border, so suppress the
// duplicate. (`:first-child` is awkward without a stylesheet; we just
// override inline.)
const firstItemStyle: CSSProperties = {
  ...itemStyle,
  borderTop: "none",
};

const linkStyle: CSSProperties = {
  display: "flex",
  alignItems: "flex-start",
  justifyContent: "space-between",
  gap: "24px",
  padding: "20px 0",
  textDecoration: "none",
  color: "inherit",
  transition: "opacity 0.3s ease",
};

const titleStyle: CSSProperties = {
  fontSize: "16px",
  fontWeight: 500,
  color: "var(--vocs-color_text)",
  marginBottom: "4px",
};

const bodyStyle: CSSProperties = {
  fontSize: "14px",
  lineHeight: 1.5,
  color: "var(--vocs-color_text3)",
  maxWidth: "60ch",
  margin: 0,
};

const arrowStyle: CSSProperties = {
  flexShrink: 0,
  marginTop: "2px",
  fontSize: "16px",
  color: "var(--vocs-color_text2)",
  transition: "transform 0.3s cubic-bezier(0.2, 0, 0, 1)",
};

export function DemoCards(): React.ReactElement {
  return (
    <ul style={listStyle}>
      {demos.map((demo, i) => (
        <li key={demo.href} style={i === 0 ? firstItemStyle : itemStyle}>
          <a
            href={demo.href}
            className="mkit-demo-card"
            style={linkStyle}
          >
            <div>
              <div style={titleStyle}>{demo.title}</div>
              <p style={bodyStyle}>{demo.body}</p>
            </div>
            <span aria-hidden="true" style={arrowStyle} className="mkit-demo-card__arrow">
              →
            </span>
          </a>
        </li>
      ))}
    </ul>
  );
}
