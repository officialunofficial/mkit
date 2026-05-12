import { defineConfig } from "vocs/config";

// TODO(brand): replace iconUrl with real mkit favicon + add logoUrl
// once brand SVGs land under apps/docs/public/. Until then the
// title text "mkit" stands in for the wordmark.
export default defineConfig({
  title: "mkit",
  description:
    "A content-addressed VCS in Rust. Git-like commits, refs, and transports, with a native attestation subsystem (in-toto v1 + DSSE).",
  renderStrategy: "full-static",
  rootDir: "src",
  baseUrl: "https://mkit.makechain.net",
  ogImageUrl: "https://og.makechain.net/?title=%title&description=%description",
  colorScheme: "dark",
  accentColor: "light-dark(black, white)",
  iconUrl: "/images/favicon.png",
  editLink: {
    link: "https://github.com/officialunofficial/mkit/edit/main/apps/docs/src/pages/:path",
    text: "Edit this page on GitHub",
  },
  socials: [
    { icon: "github", link: "https://github.com/officialunofficial/mkit" },
  ],
  topNav: [
    { text: "Docs", link: "/", match: "/" },
    { text: "Demos", link: "/demos/hash", match: "/demos" },
    { text: "Spec", link: "/docs/spec/objects", match: "/docs/spec" },
  ],
  twoslash: {
    // Rust hovers via @vocs/twoslash-rust, pointed at the Cargo workspace.
    // Enable once Cargo metadata stabilizes in CI.
    // experimental_rust: Twoslash.experimental_rust({
    //   cargoToml: "../../rust/Cargo.toml",
    //   cacheOnly: true,
    // }),
  },
  sidebar: {
    "/": [
      {
        text: "Overview",
        items: [
          { text: "Introduction", link: "/" },
          { text: "Install", link: "/docs/install" },
          { text: "CLI", link: "/docs/cli" },
          { text: "Architecture", link: "/docs/architecture" },
        ],
      },
      {
        text: "Specifications",
        items: [
          { text: "Objects", link: "/docs/spec/objects" },
          { text: "Staging index", link: "/docs/spec/staging-index" },
          { text: "Refs", link: "/docs/spec/refs" },
          { text: "Packfile", link: "/docs/spec/packfile" },
          { text: "Delta", link: "/docs/spec/delta" },
          { text: "FastCDC", link: "/docs/spec/fastcdc" },
          { text: "Transport", link: "/docs/spec/transport" },
          { text: "RPC", link: "/docs/spec/rpc" },
          { text: "Signing", link: "/docs/spec/signing" },
          { text: "Attestations", link: "/docs/spec/attestations" },
          { text: "External signer", link: "/docs/spec/external-signer" },
        ],
      },
      {
        text: "Operations",
        items: [
          { text: "Release", link: "/docs/release" },
          { text: "Fuzz", link: "/docs/fuzz" },
          { text: "SSH security", link: "/docs/ssh-security" },
          { text: "Threat model", link: "/docs/threat-model" },
        ],
      },
      {
        text: "Advisories",
        collapsed: true,
        items: [
          { text: "Overview", link: "/docs/advisories" },
          { text: "GHSA-001 — per-repo config", link: "/docs/advisories/ghsa-001-per-repo-config" },
          { text: "GHSA-002 — trust roots scope", link: "/docs/advisories/ghsa-002-trust-roots-scope" },
          { text: "GHSA-003 — key file handling", link: "/docs/advisories/ghsa-003-key-file-handling" },
        ],
      },
      {
        text: "Contributors",
        collapsed: true,
        items: [
          { text: "Writing style guide", link: "/docs/style-guide" },
        ],
      },
    ],
    "/demos": [
      {
        text: "Browser demos",
        items: [
          { text: "Hash", link: "/demos/hash" },
          { text: "Sign", link: "/demos/sign" },
          { text: "Attest", link: "/demos/attest" },
          { text: "Tree", link: "/demos/tree" },
          { text: "Streaming", link: "/demos/streaming" },
        ],
      },
    ],
  },
});
