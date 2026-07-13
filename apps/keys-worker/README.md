# keys-worker (keys.mkit.sh)

A tiny KV-backed registry mapping an **Ed25519 pubkey → display handle**
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

- `X-Public-Key`, `X-Signature`, `X-Digest`, `X-Created-At`, `Idempotency-Key`
- canonical string `mkit-write:v1\n<procedure>\n<body_digest>\n<created_at>\n<idempotency_key>`,
  signed as Ed25519 over `BLAKE3(canonical)` and `verify_strict`'d.
- `procedure` is `/mkit.keys.v1.Keys/SetName`.

Two extra checks beyond repo-worker's verify: the request is rejected unless the
**signer equals the pubkey being named** (you can only name your own key), and
`X-Digest` must equal `BLAKE3(body)`. Freshness window is ±5 minutes.

Verification logic is a self-contained copy of `apps/repo-worker/src/envelope.rs`
(no mkit-core dep &mdash; just `blake3` and `ed25519-dalek`).

## Develop

```sh
# one-time: install the workers-rs build tool + wasm target
cargo install worker-build
rustup target add wasm32-unknown-unknown

# create the KV namespaces and paste the ids into wrangler.jsonc
wrangler kv namespace create NAMES
wrangler kv namespace create NAMES --preview

# build + run locally (in-memory KV)
worker-build --release
wrangler dev -c wrangler.dev.jsonc --local
```

## Deploy

`wrangler deploy` (needs an authenticated Cloudflare token for the Official
Unofficial account, `CLOUDFLARE_ACCOUNT_ID=0bc82bff…`), or wire a Cloudflare
Workers Build that runs `worker-build --release` on merge to `main` &mdash; the same
mechanism the other mkit workers use. `keys.mkit.sh` is auto-provisioned via the
`custom_domain` route on the `mkit.sh` zone.

## Staging

`wrangler.jsonc` also declares an `env.staging` block: an isolated deployment
(`mkit-keys-staging`, its own `NAMES` KV namespace) fronted by
`staging-keys.mkit.sh` &mdash; writes there never touch the production
`mkit-keys-NAMES` namespace.

```sh
# validate the config without deploying (no resources touched)
wrangler deploy --env staging --dry-run

# deploy for real (needs an authenticated wrangler / CLOUDFLARE_API_TOKEN)
wrangler deploy --env staging
```
