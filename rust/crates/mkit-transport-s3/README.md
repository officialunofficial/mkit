# mkit-transport-s3

S3-compatible transport for mkit, with `SigV4` signing over rustls, tuned for
Cloudflare R2.

Implements the 7-verb `Transport` trait (`docs/specs/SPEC-TRANSPORT.md`) on top of
a `reqwest` blocking client with an in-crate `SigV4` signer (`sigv4`). Designed
for Cloudflare R2 &mdash; plain AWS S3 also works, but CAS semantics only match
R2's behavior of returning the body MD5 as the `ETag` on `PUT`.

URL shape: `mkit+s3://<endpoint>/<bucket>[/prefix]`. Credentials are pulled
from `MKIT_R2_ACCESS_KEY_ID` / `MKIT_R2_SECRET_ACCESS_KEY` at `connect` time;
an unset pair does not fail construction &mdash; the first signed call surfaces
`TransportError::AccessDenied`.

Retry policy mirrors SPEC-TRANSPORT §7 via
`mkit_core::protocol::BackoffIterator`: `5xx` and HTTP `429` retry up to 5
attempts; `412 Precondition Failed` never retries, so CAS writes can't
silently turn into duplicate `PUT`s.
