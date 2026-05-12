import type { CSSProperties } from "react";

const linkStyle: CSSProperties = {
  color: "var(--vocs-color_text3)",
  textDecoration: "none",
};

const footerLinks = [
  {
    href: "https://github.com/officialunofficial/mkit",
    label: "GitHub",
    external: true,
  },
  { href: "/docs", label: "Docs" },
  { href: "/docs/spec/objects", label: "Spec" },
] as const;

export function Footer(): React.ReactElement {
  return (
    <div
      style={{
        borderTop: "1px solid var(--vocs-color_border)",
        padding: "24px 0",
        marginTop: "48px",
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        flexWrap: "wrap",
        gap: "16px",
        fontSize: "13px",
        color: "var(--vocs-color_text3)",
      }}
    >
      <span style={{ fontWeight: 500, color: "var(--vocs-color_text2)" }}>mkit</span>
      <div
        style={{
          display: "flex",
          gap: "20px",
          alignItems: "center",
          flexWrap: "wrap",
        }}
      >
        {footerLinks.map((link) => (
          <a
            key={link.href}
            href={link.href}
            style={linkStyle}
            {...("external" in link ? { target: "_blank", rel: "noopener noreferrer" } : {})}
          >
            {link.label}
          </a>
        ))}
      </div>
    </div>
  );
}

export function OutlineFooter(): null {
  return null;
}

export function SidebarHeader(): null {
  return null;
}

export default function SlotsPage(): null {
  return null;
}
