# keys-worker (keys.mkit.sh)

A per-key SQLite Durable Object registry mapping an **Ed25519 pubkey → display handle**
(for example `slate-badger`) for the mkit multiplayer demo. The pubkey is the real
identity; the name is a non-unique label.

## API

| Method | Path             | Auth        | Body/Result |
|--------|------------------|-------------|---------------|
| `GET`  | `/name/<pubkey>` | none        | → `NameRecord` JSON, or `404` |
| `PUT`  | `/name/<pubkey>` | signed      | `{ "name": "slate-badger" }` → `NameRecord` |
| `POST` | `/resolve`       | none        | `{ "pubkeys": [...] }` → `{ "names": { "<pubkey>": "name" } }` |
| `GET`  | `/` · `/health`  | none        | liveness |

`NameRecord` = `{ "pubkey": "<64-hex>", "name": "...", "updated_at": <epoch-ms> }`.

### Signed writes (owner-only)

`PUT /name/<pubkey>` carries the **same signed envelope** the web app builds for
repo writes (`apps/web/src/lib/repo/envelope.ts`):

Auth v2 signs eight newline-separated fields: `mkit-write:v2`, canonical
service origin, repository (`keys`), full procedure, `body:<BLAKE3(body)>`,
created-at milliseconds, expiry milliseconds, and a 32-byte lowercase-hex nonce.
The Ed25519 signature covers BLAKE3 of that canonical string. The headers are
`X-Envelope-Version: 2`, `X-Audience`, `X-Repository`, `X-Content-Commitment`,
`X-Created-At`, `X-Expires-At`, `Idempotency-Key`, `X-Public-Key`, `X-Signature`
and `X-Digest` (the raw body hash). v1 is rejected.

`AUTH_AUDIENCE` comes from deployment configuration; request Host and forwarded
headers cannot change it. The procedure is `/mkit.keys.v1.Keys/SetName`, and the
signer must equal the named pubkey. Validity is at most five minutes with at most
30 seconds of sender clock lead. The shared `mkit-core::write_auth` verifier
checks every binding before effects.

Each pubkey routes to its own `NameStore`. The name, nonce and exact response
commit in one SQLite transaction. An identical retry returns the first response
without overwriting a later name; a nonce reused for different signed fields
fails. Replay records survive through expiry and eviction. SQLite is the only
name store; an unset key returns 404 and is omitted from batch resolution.

The Wrangler class declaration creates `NameStore` on initial deployment.
Deployment configs specify their own expected audiences. Only the current auth
format and SQLite state are supported; no older state is imported.

## Develop

```sh
# one-time: install the workers-rs build tool + wasm target
cargo install worker-build
rustup target add wasm32-unknown-unknown

# build + run locally with SQLite Durable Objects
worker-build --release
wrangler dev -c wrangler.dev.jsonc --local --port 8789
```

## Deploy

`wrangler deploy` (needs an authenticated Cloudflare token for the Official
Unofficial account, `CLOUDFLARE_ACCOUNT_ID=0bc82bff…`), or wire a Cloudflare
Workers Build that runs `worker-build --release` on merge to `main` &mdash; the same
mechanism the other mkit workers use. `keys.mkit.sh` is auto-provisioned via the
`custom_domain` route on the `mkit.sh` zone.

## Staging

`wrangler.jsonc` also declares an `env.staging` block: an isolated deployment
(`mkit-keys-staging`, with its own Durable Object namespace) fronted by
`staging-keys.mkit.sh`.

```sh
# validate the config without deploying (no resources touched)
wrangler deploy --env staging --dry-run

# deploy for real (needs an authenticated wrangler / CLOUDFLARE_API_TOKEN)
wrangler deploy --env staging
```

## Replay regression

With the local Worker running on port 8789, run
`node tests/replay.mjs http://localhost:8789`. This uses real Wasm signatures and
SQLite storage to check retry-after-later-update, nonce conflicts, destination
isolation, unsupported-version rejection, unset keys and consistent single/batch
reads without a KV binding.

To exercise rollback boundaries, build locally with
`worker-build --dev --features test-faults`, restart Wrangler, and add `--fault`
to the regression command. The feature injects an error after the name write
or after recording the response; both must roll back and permit a retry.
Default builds omit this hook. Rebuild without the feature after testing.

For eviction/restart coverage, run the test with
`--prepare /tmp/keys-replay.json`, restart Wrangler using the same
`--persist-to` directory, then run with `--resume /tmp/keys-replay.json` within
five minutes. The saved old response must survive while the newer name stays
current. Both rollback boundaries and this full restart sequence passed in the
local Workers runtime during the auth v2 remediation.
