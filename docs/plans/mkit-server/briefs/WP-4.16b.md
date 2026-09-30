## Purpose

Today every file response is `application/octet-stream` with no filename. Browsers can't preview images at a direct
URL, and downloads have no name. Uno (UNO-420) needs both. The information is already in the URL for ref-path routes.

## A. Fixed

- The existing security headers stay on every response: `nosniff`, `Content-Security-Policy: sandbox; default-src
  'none'`, and `Referrer-Policy: no-referrer`.
- Byte identity, ETag, ranges, 304 rules, caching policy, payment/admission, proofs, token binding and the no-oracle
  rules are unchanged. Native and Worker share this code, so there is one implementation.

## B. Decided

1. **Scope: only successful (200/206) and HEAD responses on the ref-path form**
   (`/<ns>/<repo>/-/refs/.../-/<file-path>`) whose target is a `Blob` or a `ChunkedBlob`. The rules:
   - **Unchanged:** object-id routes (`/-/objects/<id>`), proof responses (`?proof=1`), non-file objects
     (`application/vnd.mkit.object`) and all error, 304 and 402 responses.
   - **304 exception:** a 304 need not repeat `Content-Type` or `Content-Disposition`, per the existing 304 list.
     Don't change that list unless the spec requires it.
2. **Content-Type:** take it from the **last path segment's extension**, case-insensitive, via a small fixed
   allowlist of inline-safe types:
   - `png` → `image/png`;
   - `jpg`/`jpeg` → `image/jpeg`;
   - `gif` → `image/gif`;
   - `webp` → `image/webp`;
   - `avif` → `image/avif`;
   - `txt` → `text/plain; charset=utf-8`;
   - `json` → `application/json`;
   - `pdf` → `application/pdf`.

   Everything else, including `svg`, `html`, `htm`, `xhtml`, `xml`, `js`, `mjs` and `css`, and no extension at all,
   stays `application/octet-stream`. **SVG and HTML are never served with their real type.** There is no content
   sniffing: the extension alone decides.
3. **Content-Disposition:**
   - `inline` for the image types plus `txt` and `pdf`;
   - `attachment` for everything else.
   - Always add `filename*=UTF-8''<RFC 5987 percent-encoded last path segment>`. Encode every octet outside RFC 5987
     `attr-char`, so the header value contains **no raw request text**. That keeps the `mod.rs` injection invariant:
     document it as "derived and fully percent-encoded".
   - Also add an ASCII `filename="..."` fallback, using only `[A-Za-z0-9._-]` with other characters replaced by `_`,
     capped at 255 bytes.
4. **Private and token responses** get the same headers. The disposition doesn't change any caching or token rule.
5. **Spec:**
   - amend SPEC-HTTP-OBJECTS §5.1: the ref-path file rule, the allowlist table and the disposition and filename
     encoding;
   - add a version-history row;
   - update or add conformance vectors (native and Worker wire cases).
6. **Docs:**
   - R-201 row in `00-plan.md` ("WP-4.16b: ref-path file Content-Type allowlist and filename, for UNO-420");
   - a registry row with deps on 4.16;
   - CHANGELOG;
   - update the `apps/vcs-worker/README.md` HTTP note if it mentions octet-stream only. **4.18 is editing that README
     in parallel:** keep your edit to one or two lines so the merge is trivial.

## C. Your decisions

The helper placement, table representation and test layout.

## D. Escalate

Only if a spec rule (caching, 304, no-oracle) conflicts with adding these headers.

## Tests

- **Content-Type:** each allowlisted extension, the uppercase variant, the dangerous types (svg, html, js),
  no-extension and multi-dot names.
- **Filenames:** a unicode filename is percent-encoded, a filename containing quotes, CR/LF or `;` is encoded, and
  there is no header injection.
- **Unchanged responses:** object-id routes, proof responses and tree/non-file objects.
- **HEAD and 206** carry the headers.
- **A private token response** carries the headers.
- **Security headers** are still present.
- **The wire conformance cases pass** on native and Worker.

## Gates

- the common gates;
- `just ci-server`;
- wasm32 clippy;
- the vcs-worker default conformance on a free port.

Do the self-review, then open the PR.
