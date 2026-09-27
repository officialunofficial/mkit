---
spec: SPEC-HTTP-OBJECTS
version: 1
status: draft-normative
audience: implementers of HTTP object servers, caches, browsers, and disclosure verifiers
---

# SPEC-HTTP-OBJECTS &mdash; HTTP object serving and proofs

Status: **Draft, normative.** The contract is pinned by the golden vectors;
HTTP adapters and the span verifier follow in WP-4.12–4.16.
Scope: repository selection, URL parsing, published-content resolution,
HTTP representations, read authorization and admission, URL-token carriage,
and browser access. This document changes no protobuf schema.

Authority: this document specifies the plain HTTP contract for issue #1088,
WP-4.11. [SPEC-CONVENTIONS](SPEC-CONVENTIONS.md) supplies normative keywords.
[SPEC-TRANSPORT-CONNECT](SPEC-TRANSPORT-CONNECT.md), abbreviated STC, owns
repository identities and payment headers. [SPEC-SERVER](SPEC-SERVER.md)
owns indexed mode, the published view, hooks, and durable outcomes.

## 1. Purpose and rationale

An object URL identifies immutable content. A ref-path URL follows a
published ref and must revalidate. Both authorize within the selected
repository before returning content, including on cache validation requests.
A content digest alone grants no access to another repository's content.

User decision M4-a (2026-09-27) deliberately reinterprets PRD §6.6's
statement that a Range request can include a byte-range disclosure proof:
a proof range is selected by `?proof=1&range=a-b`, never by `Range`.
The proof is a separate representation with its own validator and media type.
This lets a verifier request the complete proof without HTTP slicing it.
User decision M4-b uses the MKDS container of existing MKDP v2 bundles
([SPEC-DISCLOSURE](SPEC-DISCLOSURE.md), multi-chunk span section).
MKDP payload kind 3 remains reserved; MKDP v2 bytes are unchanged.

## 2. Routes and URL syntax

Indexed mode is REQUIRED. An opaque deployment MUST NOT mount these routes;
its normal missing-route response applies. The rules below apply to mounted
HTTP serving routes. A single-repository deployment MAY omit the repository
prefix. An explicit prefix MUST obey STC §7.4, including the bare-name
restriction. HTTP selects the repository only by this path and MUST ignore
`X-Repository`, Host, and forwarded headers as repository selectors.

```abnf
http-path    = repo-prefix "/-/" ( objects-form / refs-form )
repo-prefix  = "/" repository / ""   ; empty only in single-repository mode
repository   = <STC section 7.4 grammar>
objects-form = "objects/" object-id
object-id    = 64HEXLC
HEXLC        = DIGIT / %x61-66
refs-form    = ref-name "/-/" [ file-path ]
ref-name     = "refs/" ref-seg *( "/" ref-seg )
ref-seg      = <SPEC-REFS section 3 segment, excluding the delimiter "-">
file-path    = path-seg *( "/" path-seg )
path-seg     = 1*( unreserved / pct-encoded )
unreserved   = ALPHA / DIGIT / "-" / "." / "_" / "~"
pct-encoded  = "%" HEXDIG HEXDIG
pct-path     = [ file-path ]
url-token    = *<query-value octet other than "&" or "#">
query        = param *( "&" param )
param        = "proof=1" / "range=" 1*DIGIT "-" 1*DIGIT
             / "commit=" 64HEXLC / "path=" pct-path / "token=" url-token
```

Route and parameter literals above MUST match case-sensitively. Object and
commit ids MUST use lowercase hexadecimal. A query is absent or nonempty;
a trailing `?`, empty parameter, unknown parameter, or repeated parameter
MUST produce 400. Parameter names MUST NOT be percent-encoded. A token value
is opaque at this stage: its token-format validation belongs to §3 step 5,
so even an empty or malformed token MUST NOT cause a token-derived 400.
Token-bearing vectors are deferred to WP-2.11/4.15.

A ref MUST satisfy [SPEC-REFS §3](SPEC-REFS.md#3-ref-name-grammar), occupy at
most 512 bytes, and begin `refs/`. Percent-encoding in a ref MUST produce
400. The ref ends at the first segment exactly `-`; the second `/-/` is
mandatory, even for the root tree. A valid stored ref with a `-` segment is
not addressable by this grammar. For example, `/-/refs/heads/-/topic/-/x`
addresses ref `refs/heads` and path `topic/-/x`, never `refs/heads/-/topic`.
A `-` in a file path is an ordinary entry name.

Each file-path segment MUST be percent-decoded exactly once to one entry
name under [SPEC-OBJECTS §4.1](SPEC-OBJECTS.md#41-entry-name-rules).
Invalid escapes, decoded separators, NUL, invalid names, empty segments,
and leading or trailing path slashes MUST produce 400. Implementations MUST
preserve decoded bytes, including non-UTF-8 bytes, with no Unicode
normalization. `%25`, `%3F`, `%23`, and `%20` represent literal percent,
question mark, hash, and interior space. `+` MUST NOT stand for space.
The joined decoded path, including separating `/` bytes, MUST be 1–1024
bytes; the empty path selects the root tree. A `path=` proof context uses
the same encoding and permits an empty root path.

`range=a-b` selects inclusive content offsets. Both integers MUST fit u64,
and `a <= b`; failures MUST produce 400. `range` requires `proof=1`.
On an object URL, `proof=1` requires both `commit` and `path`, including
`path=` for the root. `commit` and `path` supply that object's proof context;
on a ref URL they do not override the ref's resolution. Without `proof=1`
they do not change the object representation. Bounds against content size,
selector applicability, and proof caps are checked later as 416, not 400.
Every 400 MUST depend only on URL text and the deployment's route grammar,
never on stored state. An HTTP `Range` parse failure MUST NOT produce 400.

The mandatory `/-/` distinguishes this namespace from `/.well-known/`,
`/mkit.transport.v1.*`, and `/grpc.*`; their first segments cannot be a
repository identity followed by `/-/`. The key document in §6 is a separate
well-known route. Routers MUST retain the original escaped path until this
parser runs; framework path decoding MUST NOT reinterpret delimiters.

## 3. Response precedence

The server MUST apply these steps in order, taking the first terminal result.
HEAD follows the same checks as GET but MUST send no body on every status.

| Step | Condition and required result |
|---|---|
| 1 | OPTIONS preflight: 204, no authentication, authorization, or payment required. |
| 2 | Method other than GET or HEAD: 405, `Allow: GET, HEAD, OPTIONS`. |
| 3 | URL or query syntax fails §2: 400. |
| 4 | Bearer-gated deployment: require the same bearer gate as RPCs; missing or invalid bearer yields 401. OPTIONS and the key document are exempt. |
| 5 | If a token is present, check its syntax and signature against the key set before repository lookup. Then check repository existence and private-token validity under §6. Missing repository, or missing/invalid private token: the same 404 response. A public repository ignores the token's result. |
| 6 | Run the Authorizer for every read. Deny: 403, except 404 for a private repository or a hook `not_found`. A URL token does not bypass this hook. |
| 7 | Resolve in the published view under §4. Missing ref, non-tree intermediate component, missing entry, unreachable proof commit, leaf/id mismatch, nonmember id, or unreachable id: 404. |
| 8 | 451 is reserved for M5 tombstones, after the preceding 404 checks. M4 MUST NOT return 451. Reachability MUST NOT descend through tombstoned objects. |
| 9 | Matching `If-None-Match`: 304, no admission or charge. |
| 10 | Unsatisfiable ordinary byte Range, or out-of-bounds/unsupported/over-cap proof range: 416. Ordinary byte ranges include `Content-Range: bytes */N`, where N is the full representation size. |
| 11 | Read Admission, when configured: challenge yields 402 under §7; deny yields 403. |
| 12 | Serve 200 or ordinary-range 206; proofs always use 200. An enabled eligible redirect uses 302 under §8. |

All errors MUST carry `Cache-Control: no-store`. The missing-repository and
missing/invalid-private-token 404s MUST be byte-identical in status, headers,
and body for otherwise equivalent requests (including CORS and HEAD).
Their response MUST NOT identify which check failed. Hooks and storage
failures MUST fail closed under SPEC-SERVER; an infrastructure failure is
503, never a fabricated success or content-dependent 400.

## 4. Published resolution and reachability

The caller's view for these requests MUST always be the **published view**
(SPEC-SERVER, published view contract). Signed-read HTTP GETs are deferred.
Pending content MUST NOT be served over HTTP, even to a writer or a token
holder. Ref-path resolution MUST peel tags to a commit or remix and walk
its tree by exact decoded entry bytes. Symlinks MUST be served as blob
content; they MUST NOT be followed as filesystem paths.

A ref path is reachable by construction. For an id URL, the server MUST
check repository membership first, with a cheap uniform 404 on a miss,
then prove reachability from a published ref value. The walk follows
repository-local object references, including parents and chunk manifests;
it MUST NOT follow foreign remix sources or pack-only delta bases.
It MUST NOT consult the global content store to resolve a missing member.
Extracted copies keyed by object id (SPEC-SERVER §9.6) MUST NOT constitute
authorization, membership, reachability, or observable delta bases.

A rewind or ref deletion MUST invalidate reachability within a configured
`reachability_lag` bound. Tombstones MUST take effect immediately, including
on cached walks. Informative: external CDN copies of orphaned public
objects persist until their max-age expires; purges occur on takedown,
suspension, and visibility change, not every rewind or deletion.

For an object proof URL, `commit` MUST be reachable in the published view,
and its decoded `path` MUST resolve to the requested object id. Either
failure is 404. A ref proof uses its resolved commit. Informative: an
MKDP/MKDS proof authenticates the path through trees to the commit and its
signature; the ref-to-commit binding is the server's claim until M5 receipts.

## 5. Representations, validators, and headers

### 5.1 Object content and ordinary ranges

Blob responses MUST carry raw content; ChunkedBlob responses MUST carry
concatenated chunk content in manifest order, not the manifest. Both use
`Content-Type: application/octet-stream`. Other object types MUST carry
canonical object bytes with `Content-Type: application/vnd.mkit.object`.
Pack-only Delta objects MUST NOT be served (SPEC-OBJECTS §1).

200 and 206 MUST carry `ETag: "<64hex leaf id>"`, `Accept-Ranges: bytes`,
`X-Mkit-Object: <64hex leaf id>`, and `X-Mkit-Object-Type` using the
SPEC-OBJECTS §1 lowercase type name. Ref-path responses MUST also carry
`X-Mkit-Commit: <64hex resolved commit id>`. Content-Length MUST describe
the selected body, including for HEAD (the GET body length).

An ordinary single byte range MUST produce 206 with
`Content-Range: bytes a-b/N`. Open-ended and suffix byte ranges follow
HTTP byte-range semantics. A multi-range request MUST be served as 200
with the full representation; multipart responses are not supported.
An invalid or unsupported Range header MUST be ignored. The server MUST
honor `If-Range`: only a matching strong ETag enables slicing; a weak,
nonmatching, or unsupported date validator yields the full 200 response.
`If-None-Match` uses HTTP weak comparison, including `*`, against the selected
representation's ETag, after authorization and resolution and before Range.

### 5.2 Proof selection

`?proof=1` MUST return an MKDP Object bundle, including canonical manifest
bytes for a ChunkedBlob and canonical tree bytes for an empty root path.
`?proof=1&range=a-b` MUST return an MKDP Range bundle when the inclusive
range lies within one chunk or a plain blob; otherwise it MUST return MKDS.
The server MUST prove absolute offsets for chunked MKDP ranges with the
complete preceding chunk-length proof set. Query ranges MUST NOT be
clipped: any endpoint outside content is 416. The inclusive query becomes
`offset=a, len=b-a+1` using checked arithmetic; overflow is 416.
Non-blob leaves do not support proof ranges and yield 416.

MKDP uses `application/vnd.mkit.disclosure`; MKDS uses
`application/vnd.mkit.disclosure-span`. Proofs MUST carry
`Accept-Ranges: none`, MUST ignore every HTTP Range/If-Range header, and
MUST use 200 rather than 206. The 64 MiB encoded bundle cap applies.
A deployment SHOULD configure a lower requested-content cap, for example
8 MiB; exceeding either proof cap yields 416 before Admission.

The proof ETag MUST be `"<commit>.<leaf>.<selector>"`, with lowercase
64hex ids and selector `object` or `range-a-b` (minimal decimal inclusive
endpoints). It is distinct from the ordinary object ETag. The object and
commit metadata headers from §5.1 also identify proof responses.

### 5.3 Cache and security headers

The server MUST emit the following Cache-Control directives. Privacy
requirements compose: private visibility, running Admission, or carrying
a receipt overrides a public directive. Error no-store takes precedence.

| Representation | Cache-Control |
|---|---|
| Public object id | `public, max-age=31536000, immutable` |
| Public ref path | `public, no-cache` |
| Private object id | `private, max-age=n, immutable`, with integer seconds n no greater than the token's remaining lifetime (rounded down, never negative) |
| Private ref path | `private, no-cache` |
| Public commit-pinned proof | `public, immutable` |
| Public ref-path proof | `public, no-cache` |
| Private commit-pinned proof | `private, max-age=n, immutable`, bounded by token lifetime as above |
| Private ref-path proof | `private, no-cache` |
| Any success where read Admission ran, or a receipt is returned | MUST be `private`; retain applicable no-cache and lifetime limits |
| 402 and every error | `no-store` |
| 304 | MUST repeat the selected 200's ETag and Cache-Control; use the private policy when read Admission is configured, without actually calling it |

Every serving response MUST carry `X-Content-Type-Options: nosniff`,
`Content-Security-Policy: sandbox; default-src 'none'`, and
`Referrer-Policy: no-referrer`. A deployment SHOULD serve repository
content from a dedicated origin. This prevents attacker-controlled blob
bytes from becoming active content under a privileged application origin.

## 6. URL tokens and key publication

[SPEC-WRITE-GRANTS §9.4](SPEC-WRITE-GRANTS.md#94-signed-url-tokens) owns
`mkit-url-token:v1` statements, signatures, audience, epoch, expiry, and
key retirement. A token MUST appear only in the `token=` query parameter.
Header and cookie carriage is deferred (a future `X-Mkit-Url-Token`).
Implementations MUST redact the token parameter from logs and traces,
including raw request URLs and redirect/error diagnostics.

An id route maps to `object:<hex>`; a ref path maps to
`path:<ref>:<unpadded base64url joined decoded path>`. An empty path maps
to the root tree with an empty final field. The existing token contract
requires UTF-8 paths; non-UTF-8 HTTP paths remain valid URL syntax but
cannot match such a path token. Query proof selectors do not alter the
token target. Tokens MUST resolve in the published view.

Step 5 prechecks syntax, key id, and signature before repository lookup,
retaining the result until repository visibility is known. For a private
repository the server MUST also verify every §9.4 request binding,
audience, epoch, and expiry rule. Every verification failure on a private
repository, including an unknown key, MUST produce the uniform 404. Public
repositories MUST ignore the precheck result and all other token claims,
and MUST still redact the supplied token.

The deployment MUST publish `GET /.well-known/mkit-url-token-keys.json`
using SPEC-SERVER §7.2's key-list JSON shape (`version`, `keys`, `keyId`,
`alg`, `publicKey`, `notBeforeMs`, `notAfterMs`). Here `keyId` MUST be the
32hex URL-token key id from SPEC-WRITE-GRANTS §9.4, and `alg` is `ed25519`.
The document MUST carry `Content-Type: application/json` and
`Cache-Control: public, max-age=300`, MUST require neither bearer nor
URL-token authentication nor payment, and MUST include the active and
retained verification keys. The read CORS policy applies to this document.

## 7. Authorization, admission, and durable read outcomes

For both Authorizer and Admission, the principal MUST be `anonymous`,
including bearer and URL-token holders. `procedure` MUST be
`/mkit.http.v1/GetObject` or `/mkit.http.v1/GetRefPath` according to route.
The operation MUST identify the selected repository and audience; it MUST
NOT manufacture a signer, write grant, ref change, or idempotency key.
No object-id field or token principal is added to the hook schema here.

When reads are configured for Admission, GET and HEAD MUST be admitted
alike. `declared_bytes` MUST be the selected GET body byte count after
ordinary Range or proof selection; `pack_id` MUST be empty. HEAD declares
the GET count but records `ReadServed` with zero bytes served. Payment
credential forwarding and redaction MUST follow STC §5.1 and SPEC-SERVER
§6.3/§6.6, including bearer/Payment header separation.

A challenge MUST return 402, pass through `WWW-Authenticate` and
`PAYMENT-REQUIRED`, and carry `Cache-Control: no-store`. Its body MUST be
the `AdmissionChallenge` message using canonical protobuf JSON, with
`Content-Type: application/json` (HEAD omits the body). A success MUST pass
through `Payment-Receipt` and `PAYMENT-RESPONSE` when supplied and MUST
be private. Challenge and deny MUST allocate no reservation or replay state.

An allowance with a reservation id MUST durably record the pending read
before sending the first byte, as SPEC-SERVER §5 requires. `ReadServed`
MUST record actual body bytes sent, including a partially sent response.
A failure before the first byte MUST record `Aborted(INTERNAL)`.
A successful HEAD MUST record `ReadServed{bytes_served: 0}`. Conditional
terminal replacement, crash reconciliation, and at-least-once delivery
MUST follow SPEC-SERVER §5's HTTP read rule. 304 and 416 MUST NOT run
Admission. Reads MUST NOT allocate auth v2 replay state.

## 8. Redirects and CORS

The server MUST serve directly by default. An option MAY enable 302 for a
public ref-path GET or HEAD without `proof`. The redirect MUST use a
relative object-id URL with the same explicit repository prefix, if any,
and `Cache-Control: no-cache` (private when Admission ran). It MUST occur
only after §3's earlier checks. Private and proof requests MUST NOT redirect.

Default CORS MUST use `Access-Control-Allow-Origin: *`. With configured
origins, an allowed origin MUST be echoed. Every response under that
configuration MUST carry `Vary: Origin`; disallowed origins MUST NOT
receive Allow-Origin.
`Access-Control-Allow-Credentials` MUST NOT be emitted. CORS MUST cover
errors and 304 as well as success, so browsers can observe challenges.
Preflight MUST use 204 without auth or payment and allow these values:

| Header | Value |
|---|---|
| `Access-Control-Allow-Methods` | `GET, HEAD, OPTIONS` |
| `Access-Control-Allow-Headers` | `Range, If-None-Match, If-Range, Payment-Authorization, PAYMENT-SIGNATURE, Authorization, Accept-Payment` |
| `Access-Control-Expose-Headers` | `ETag, Content-Range, Accept-Ranges, Content-Length, X-Mkit-Commit, X-Mkit-Object, X-Mkit-Object-Type, WWW-Authenticate, Payment-Receipt, PAYMENT-REQUIRED, PAYMENT-RESPONSE` |

## 9. Vectors and deferred work

[`rust/tests/golden/http-objects/`](../../rust/tests/golden/http-objects/)
pins versioned JSON tables (`schema_version: 1`, `cases`) for URL parsing
and response expectations, MKDP proof bodies, and MKDS accept/reject
bodies with sidecars. In response rows, `expect.headers` is the required
header subset and `absent_headers` lists forbidden headers. URL rows use
status 200 to mean syntax accepted and continued, not that stored content
exists. `MANIFEST.txt` pins BLAKE3 digests for every artifact.
The independent test-local MKDS encoder and reference verifier are in
[`golden_http_objects.rs`](../../rust/crates/mkit-core/tests/golden_http_objects.rs).
`MKIT_WRITE_GOLDEN=1` regenerates the artifacts; check mode reads committed
vectors. Reject sidecars name the exact span rejection reason.

Token-bearing URL vectors follow WP-2.11/4.15. Tombstone response bodies
follow M5. The product MKDS verifier, boundary-aware builder, and verifier
bindings follow WP-4.14. Signed-read HTTP GETs and schema extensions for an
object-id admission field or token principal require separate work.

Version history: document version 1 introduces this HTTP contract and
selects MKDP v2 or MKDS v1 without changing either object bytes or protobuf.

## 10. Invariants

| Invariant | Enforced by |
|---|---|
| Syntax never probes stored state | URL-only 400 checks before repository lookup (§2–§3) |
| Private existence is concealed | uniform token/missing-repository 404 and Authorizer mapping (§3) |
| A global extracted copy grants no read access | repository membership and published reachability (§4) |
| Pending content never escapes through HTTP | published view for all callers (§4) |
| A proof cannot be sliced by HTTP Range | separate query-selected representation (§5.2) |
| Cached private or paid content never becomes public | composing privacy overrides (§5.3) |
| A reservation has one durable terminal result | conditional read outcomes and reconciliation (§7; SPEC-SERVER §5) |
| Token credentials do not enter observability output | query redaction (§6) |
