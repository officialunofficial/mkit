// Type declarations for the dependency-free parsers in parse.mjs.
export function parseCrateInfo(
  cargoToml: string,
  fallbackPath: string,
): { name: string; description: string };

export function parseWorkspaceVersion(rustCargoToml: string): string;

export function parseCommands(
  cliMd: string,
): Array<{ name: string; summary: string; body: string }>;
