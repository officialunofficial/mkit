import { describe, expect, it } from "vitest";
import { parseCommands, parseCrateInfo, parseWorkspaceVersion } from "../scripts/parse.mjs";

describe("parseCrateInfo", () => {
  it("reads name + description from [package] only", () => {
    const toml = `[package]
name = "mkit-attest"
description = "in-toto/DSSE attestations"

[dependencies]
name = "not-this"
`;
    expect(parseCrateInfo(toml, "fallback")).toEqual({
      name: "mkit-attest",
      description: "in-toto/DSSE attestations",
    });
  });
  it("falls back when fields are absent", () => {
    expect(parseCrateInfo("[package]\n", "rust/crates/x")).toEqual({
      name: "rust/crates/x",
      description: "No description available",
    });
  });
});

describe("parseWorkspaceVersion", () => {
  it("prefixes the workspace.package version with v", () => {
    const toml = `[workspace.package]
version = "0.2.0"
edition = "2024"
`;
    expect(parseWorkspaceVersion(toml)).toBe("v0.2.0");
  });
  it("throws when no version is present", () => {
    expect(() => parseWorkspaceVersion("[workspace]\n")).toThrow();
  });
});

describe("parseCommands", () => {
  const md = `# mkit — CLI reference

## Subcommand reference

Working-tree commands:

- \`mkit init\` — create a new repository in \`.mkit/\`.
- \`mkit add [-A|-u] <path>...\` / \`mkit add .\` — stage files for the next
  commit. Multiple pathspecs may be given.
  - \`-A\`/\`--all\` stages every change.

Attestation:

- \`mkit attest [--commit <hash>]\` — produce a signed DSSE attestation.

### Resolving conflicts

This is not a command and must be ignored.

## Ignore files

Out of the reference section.
`;

  it("extracts commands, merges alternate-form bullets, folds sub-bullets", () => {
    const cmds = parseCommands(md);
    const names = cmds.map((c) => c.name);
    expect(names).toEqual(["init", "add", "attest"]);

    const add = cmds.find((c) => c.name === "add")!;
    expect(add.summary).toContain("stage files");
    expect(add.body).toContain("mkit add ."); // alternate form merged
    expect(add.body).toContain("--all"); // nested sub-bullet folded in
  });

  it("stops at the next ## header and ignores ### subsections", () => {
    const cmds = parseCommands(md);
    expect(cmds.map((c) => c.name)).not.toContain("Resolving");
    expect(cmds.find((c) => c.body.includes("Out of the reference"))).toBeUndefined();
    expect(cmds.find((c) => c.body.includes("not a command"))).toBeUndefined();
  });

  it("returns [] when the section is missing", () => {
    expect(parseCommands("# no reference here")).toEqual([]);
  });
});
