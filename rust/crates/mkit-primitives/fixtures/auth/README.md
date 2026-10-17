# Auth fixtures

The unary, read, and part JSON files are unchanged copies of the shared
**rust/tests/golden/auth-v2/** vectors. They pin raw canonical fields, signed
bytes, signing digest, strict signature, and typed commitments under
SPEC-TRANSPORT-CONNECT §7.1 and §7.6. The read vectors include the framed
DownloadPack request bytes.

The validator uses the core grammar and limits. Creation and expiry are
canonical nonnegative `i64` decimals; expiry exceeds creation by at most
300,000 ms. Ingress accepts creation at exactly 30,000 ms ahead and accepts
`now == expires_at`. Pack lengths fit `u64`; part indexes fit `u32` and part
lengths are positive `u64`. No new encoding or signing domain is introduced.

Claims fixtures describe in-memory equality bindings only. Hosts authenticate
and decode their own opaque tokens before calling the validator. No token
format, MAC, secret, or rotation policy is specified by these fixtures.

Component ceilings are 512 bytes for audience, 255 for repository, and 512 for
procedure. Repository and procedure are nonempty bytes from `0x21` through
`0x7e`; procedure starts with `/`. Audience additionally follows the core
canonical-origin grammar. Timestamp decimals range from 0 through
9,223,372,036,854,775,807. Pack byte counts range from 0 through
18,446,744,073,709,551,615. Part indexes range from 0 through 4,294,967,295;
part lengths range from 1 through 18,446,744,073,709,551,615. The commas in
these explanatory bounds are not part of a decimal field.

The header-presence semantic vectors count raw occurrences in this order:
`x-envelope-version`, `x-audience`, `x-repository`, `x-public-key`,
`x-signature`, `x-digest`, `x-content-commitment`, `x-created-at`,
`x-expires-at`, and `idempotency-key`. `x-repository` is addressing and
`idempotency-key` alone does not mark a signature. Any of the other eight
fields marks an envelope; once marked, any count above one refuses it.
Without a trigger, addressing and unsigned replay metadata remain host
obligations. Every required count is one, with `x-digest` optional only for
upload streams. Values still require full core validation. These count vectors
describe in-memory inputs and do not define a header or token encoding.
