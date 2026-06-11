// Pure parsing helpers for the deploy-time indexer. Kept dependency-free and
// side-effect-free so they can be unit-tested without touching the filesystem.

/** Parse [package] name + description from a Cargo.toml string. */
export function parseCrateInfo(cargoToml, fallbackPath) {
  const pkg = cargoToml.match(/\[package\]([\s\S]*?)(?=\n\[|$)/);
  const section = pkg ? pkg[1] : "";
  const name = section.match(/name\s*=\s*"([^"]+)"/)?.[1] ?? fallbackPath;
  const description =
    section.match(/description\s*=\s*"([^"]+)"/)?.[1] ?? "No description available";
  return { name, description };
}

/** Parse the workspace package.version from rust/Cargo.toml content. */
export function parseWorkspaceVersion(rustCargoToml) {
  const ws = rustCargoToml.match(/\[workspace\.package\]([\s\S]*?)(?=\n\[|$)/);
  const v = (ws ? ws[1] : rustCargoToml).match(/version\s*=\s*"([^"]+)"/)?.[1];
  if (!v) throw new Error("could not parse workspace version from rust/Cargo.toml");
  return `v${v}`;
}

/**
 * Split docs/CLI.md's "## Subcommand reference" section into per-command
 * entries. Commands are top-level bullets of the form `- \`mkit <name> …\` — …`,
 * with indented continuation lines and nested sub-bullets folded in. Multiple
 * bullets for the same command (e.g. `mkit add` and `mkit add .`) are merged.
 */
export function parseCommands(cliMd) {
  const start = cliMd.indexOf("## Subcommand reference");
  if (start === -1) return [];
  const after = cliMd.slice(start + "## Subcommand reference".length);
  const end = after.search(/\n## /);
  const section = end === -1 ? after : after.slice(0, end);

  const byName = new Map();
  const order = [];
  let cur = null;
  for (const line of section.split("\n")) {
    const m = line.match(/^- `mkit ([a-z][a-z-]*)/);
    if (m) {
      const name = m[1];
      const dash = line.indexOf("—");
      const summary = dash === -1 ? "" : line.slice(dash + 1).trim();
      cur = name;
      const prev = byName.get(name);
      if (prev) {
        prev.body += "\n" + line;
        if (!prev.summary && summary) prev.summary = summary;
      } else {
        byName.set(name, { summary, body: line });
        order.push(name);
      }
      continue;
    }
    if (/^#{1,6}\s/.test(line)) {
      cur = null;
      continue;
    }
    if (/^\S.*:$/.test(line)) {
      cur = null; // group label like "Branches / refs:"
      continue;
    }
    if (cur) byName.get(cur).body += "\n" + line;
  }

  return order.map((name) => {
    const v = byName.get(name);
    return { name, summary: deriveSummary(v.summary, v.body), body: v.body.trim() };
  });
}

/**
 * The one-line summary. Prefer the text after the em-dash on the command's
 * first line; if the signature wraps so the em-dash lands on a continuation
 * line (e.g. attest, diff, push), find the first em-dash anywhere in the folded
 * body and take its sentence. Only if there's no em-dash at all do we fall back
 * to a raw slice (which would otherwise echo the backticked command itself).
 */
function deriveSummary(firstLineSummary, body) {
  if (firstLineSummary) return firstLineSummary;
  const dash = body.indexOf("—");
  if (dash !== -1) {
    const after = body.slice(dash + 1).replace(/\s+/g, " ").trim();
    const period = after.indexOf(". ");
    return period !== -1 && period < 160 ? after.slice(0, period + 1) : after.slice(0, 160).trim();
  }
  return body.replace(/\s+/g, " ").slice(0, 160).trim();
}
