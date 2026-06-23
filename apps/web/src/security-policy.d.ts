// Types for the plain-JS security-policy module (src/security-policy.js). The
// module is JS so the Node build scripts can import it without TS type-stripping;
// these declarations give the TypeScript Worker code full typing.

export const CSP_DIRECTIVES: readonly string[]
export const CONTENT_SECURITY_POLICY: string
export const SECURITY_HEADERS: ReadonlyArray<readonly [string, string]>
