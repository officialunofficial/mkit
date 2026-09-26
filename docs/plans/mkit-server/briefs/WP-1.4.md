## Purpose

Today `Addressing::resolve` ignores `X-Repository`. Every request resolves to the one configured repository
(`mkit-server/src/repo.rs`), and auth v2 verifies against the configured repository string. This WP implements
SPEC-TRANSPORT-CONNECT v2 §7.4:
- validate `X-Repository` on single-repository deployments;
- add a multi-repository mode that routes each RPC to `namespace/name`, with auth v2 bound to the request's repository.

Namespace policy and write policy (§7.5) are WP-1.5, not this WP. D34 sharding is WP-1.22. Pack membership is
WP-1.7/1.10.

## A. Fixed by the plan and specs (do not change)

1. **Normative source:** `docs/specs/SPEC-TRANSPORT-CONNECT.md` §7.4 (read all of it): grammar, carriage,
   single-repository rules, multi-repository rules, isolation, creation. Also §7.1 (the auth v2 `<repository>` field)
   and §5 (the error table).
2. **The grammar implementation already exists:** `mkit_core::repo_identity` (from WP-2.4a):
   - `RepositoryIdentity::parse` for the `ns/name` form only;
   - `RepositoryIdentity::parse_bare_allowed` to also accept a bare name;
   - `Namespace`.

   Use it; don't write a second parser. The longest identity is 173 bytes.
3. **Storage layout is unchanged:**
   - ref keys are `r 00 <repo> 00 <refname>` (`store/keys.rs`), and the partition is `Partition::Namespace(ns)` under
     `SinglePartition` (`pipeline/shard.rs`);
   - no key-layout or partition changes, and no data migration;
   - single-repository deployments keep `NamespaceKey::deployment_default()` (`"root"`) and their configured name
     byte-for-byte, so existing M0 data stays addressable.
4. **The signed repository is the header.** Auth v2's signed `<repository>` field IS the `x-repository` request header
   (`auth_v2.rs` `HEADER_NAMES`). So "`X-Repository` must equal the signed `<repository>`" holds by construction once
   the envelope is verified against the header's own value.
5. **Wire compatibility for single-repository deployments:**
   - 0.4.x clients send no `x-repository` on reads (G5), and send the configured identity on signed writes.
   - Those flows MUST keep working unchanged, including vcs-worker (`AUTH_REPOSITORY = "default"`) and the
     `mkit-server` binary.
   - The ssh path and the enc listener (`AuthMode::TransportIdentity`) carry no header: they resolve to the configured
     repository, unchanged.
6. **Isolation (§7.4):** no RPC on one repository may read or change another's state, and no response may act as an
   existence oracle.

## B. Decided by the orchestrator (do not change)

1. **Types** (in `mkit-server/src/repo.rs`, where `Addressing` already lives; no new top-level module):
   - Add the variant `Addressing::Multi(MultiAddressing)`.
   - `MultiAddressing` is a `#[non_exhaustive]` struct with a `pub fn new() -> Self` and no fields yet. WP-1.5 adds the
     namespace policy to it.
   - `Addressing` stays `#[non_exhaustive]`.
   - Keep `RepoId { namespace: NamespaceKey, name: RepoName }` as is.
   - A multi-repository `RepoId` is `namespace = NamespaceKey` of the identity's namespace string (`ed25519-…` /
     `0x…`), `name = RepoName` of the name part.
   - Add a crate-private constructor for `NamespaceKey` from a parsed `Namespace`.
2. **Resolution API.** Replace `Addressing::resolve(&self, x_repository: Option<&str>)` with:
   ```rust
   pub fn resolve(&self, x_repository: Option<&str>, signed: bool) -> Result<ResolvedRepo, ServerError>
   pub struct ResolvedRepo { pub repo: RepoId, pub identity: String /* the wire identity, byte-exact */ }
   ```
   `ResolvedRepo` is `#[non_exhaustive]`, Debug/Clone/PartialEq/Eq. The rules, exactly §7.4:

   | Deployment | `X-Repository` | Result |
   |---|---|---|
   | Single | absent, unsigned | the configured repo |
   | Single | absent, signed | `unauthenticated` |
   | Single | fails `parse_bare_allowed` | `invalid_argument` |
   | Single | well-formed, byte-equal to the configured identity | the configured repo |
   | Single | any other well-formed identity | `not_found` |
   | Multi | absent (signed or not) | `invalid_argument` |
   | Multi | bare name | `invalid_argument` |
   | Multi | fails `RepositoryIdentity::parse` | `invalid_argument` |
   | Multi | valid `ns/name` | that repo |

   An empty header value counts as absent. Header lookup is by lowercase name, as `RequestMeta.header` already does.
3. **Where resolution runs:** at stage 0.
   - `Pipeline::authenticate_inner` (`pipeline/mod.rs`) has `self.cfg`. It resolves the repository first, via
     `self.cfg.addressing.resolve(meta header "x-repository", signed)`, where
     `signed = matches!(self.cfg.auth, AuthMode::AuthV2(_)) && meta.procedure.is_write()`.
   - It then passes the resolved identity into the crate-private `auth::authenticate(mode, meta, now_ms, …)` (add the
     parameter there) for B.4.
   - The result is stored in `Authenticated` as a new field `repo: ResolvedRepo`, with a `pub fn repo(&self) ->
     &ResolvedRepo` accessor, crate-private construction as today.
   - The public `Pipeline::authenticate(&self, meta: &RequestMeta)` signature and `RequestMeta` are UNCHANGED.
     Adapters, the connect interceptor, `ssh/verbs.rs` and tests call it as today.
   - `identify()` (`pipeline/mod.rs`, currently `self.cfg.addressing.resolve(None)?.clone()`) uses `a.repo().repo`.
     Grep confirms that is the only `resolve` call site today. Keep it that way: every read and write path gets its
     `RepoId` from `Authenticated`.
   - `outcome_for` (`pipeline/mod.rs`, which matches `Addressing::Single` for the span's `repo` field) takes the repo
     label as a parameter:
     - after authentication, `a.repo().identity`;
     - on the authentication-failure path (no resolved repo), the literal `"-"`.

     Metrics are unchanged. The repo appears only in the tracing span, never as a metrics label (unbounded
     cardinality in Multi).
   - A resolution error surfaces at stage 0 with its code, recorded like any other stage-0 failure, before replay,
     authorization or any store access.
   - Transport-identity callers (ssh `Verbs::auth`, the enc listener) send no headers. In Single mode that resolves to
     the configured repo, unchanged. In Multi mode it is `invalid_argument`, which is correct: those adapters only
     build `Addressing::Single` (`mkit-cli` `serve`, and `mkit-server-native/src/server.rs:448`, which already rejects
     non-Single).
4. **Auth v2 per request:**
   - `AuthV2Config` keeps its constructor and `repository()` accessor, so config and wire are unchanged for single.
   - Add `pub fn verify_unary_for(&self, repository: &str, …)` / `verify_stream_for(…)`, or equivalently a
     crate-private way to verify against an explicit expected repository.
   - Single: verify against the configured repository, as today.
   - Multi: verify against `resolved.identity`.
   - In multi mode `AuthV2Config`'s own repository field is ignored. Document that, and construct it with an empty or
     sentinel repository in tests.
5. **Configured identity validation (single):**
   - At config time, the configured identity is validated with `RepositoryIdentity::parse_bare_allowed` in:
     - the native binary: `mkit-server-native/src/config.rs`, where `--repository` is turned into
       `RepoName::new(args.repository)` near line 990;
     - the Worker adapter: `WorkerConfig::from_vars` in `mkit-server-worker/src/adapter.rs`, for `AUTH_REPOSITORY`.
   - An invalid identity gives:
     - in the binary, a `ConfigError::new(exit::USAGE, …)` (exit 64), like the other flag errors there;
     - in the Worker, a `ConfigError` from `from_vars`, which takes the same path as a missing `AUTH_REPOSITORY`
       today.
   - `"default"` stays valid.
   - Record this as a CHANGELOG behaviour change: previously any printable ASCII was accepted.
6. **Repository existence in Multi mode:**
   - A repo exists iff it has at least one ref row: a `scan` of `keys::ref_prefix_range(&repo.name, "")` with limit 1
     in the repo's namespace partition (`Partition::Namespace(repo.namespace)`).
   - Ref keys carry only the repo *name*. Isolation across namespaces comes from the partition, because
     `NamespaceStore` partitions are disjoint and vcs-worker gives each partition its own DO (`naming.rs`). So every
     Multi read and write MUST go through the `ShardMap`, never a hardcoded partition.
   - The test `ed25519-<a>/same` vs `0x<b>/same` (same name, different namespaces) must prove it: add it to the
     isolation tests.
   - Reads of a nonexistent repo give `not_found`: `ListRefs` → `not_found`; `ReadRef` → `not_found` (not
     `exists = false`, which is only for an absent ref in an existing repo).
   - Writes create the repo implicitly (§7.4 "Creation").
   - This replaces nothing in Single mode, where reads behave exactly as today.
   - Add `// TODO(WP-1.22): replace with the coordinator repo registry (rr)`.
7. **Packs in Multi mode:**
   - Membership does not exist yet (WP-1.7/1.10), so in Multi mode `PackExists`, `DownloadPack` and `UploadPack` return
     `unimplemented` "pack RPCs need repository membership", with `// TODO(WP-1.10)`.
   - This is required: answering from the global blob store would be an existence oracle across repositories (A.6).
   - Single-mode pack RPCs are unchanged.
8. **Exposure:**
   - Multi mode is NOT wired into the `mkit-server` binary's flags or the Worker config in this WP. It's reachable only
     by constructing `PipelineConfig` with `Addressing::Multi`, in tests and for embedders.
   - `mkit-server-native/src/server.rs:448` keeps rejecting non-Single addressing.
   - The existing `Addressing::Single { repo }` construction sites (native config, the worker adapter, `mkit-cli`
     `serve`, and the tests) keep compiling unchanged.
   - Replace the test `single_addressing_ignores_header_in_m0` (`repo.rs`), which pins the old behaviour.
   - Document on `Addressing::Multi`: "not deployable until WP-1.10 lands pack membership".
9. **Error messages** (public, safe to echo):
   - "invalid X-Repository" for `invalid_argument`;
   - "repository not found" for `not_found`;
   - "missing X-Repository on a signed request" for `unauthenticated`.

   They never echo the header value.

## C. Your decisions (record each in the PR under "Executor decisions")

- The exact name and shape of the per-request auth v2 verification API (B.4), within the constraints.
- How the existence check (B.6) is factored, e.g. a helper on the pipeline's read path.
- The golden file format for `rust/tests/golden/transport/repository-grammar.json`. It is a list of
  `{identity, single_ok, multi_ok}` cases, including the 173-byte maximum, 174 bytes, uppercase hex, a trailing `/`,
  `ed25519-` with 63 hex digits, `0x` with 41 hex digits, a leading `.`, `..`, and names at the 100-byte limit and
  over it. Pin it with a BLAKE3 in a `MANIFEST.txt` like the other golden dirs.

## Tests (required)

1. **Unit tests, `Addressing::resolve`:** every row of the B.2 table, plus the golden grammar file driving both modes.
2. **Pipeline:**
   - Single mode: 0.4.x-shaped requests (reads without the header, signed writes with the configured identity) are
     unchanged.
   - A signed write without the header gives `unauthenticated`.
   - A read with another well-formed identity gives `not_found`.
3. **Multi-repository isolation** (in-process pipeline over the memory stores and the SQLite store):
   - two repos, `ed25519-<a>/one` and `0x<b>/two`, each written with signed writes under their own identity;
   - `ListRefs` and `ReadRef` of one never show the other's refs;
   - a write signed for repo A but sent with `X-Repository: B` gives `unauthenticated` (signature mismatch);
   - a nonexistent repo's reads give `not_found`;
   - pack RPCs give `unimplemented`.
4. **Wire suite** (black-box, `mkit-server-conformance`):
   - Add cases under a declared feature `multi-repo` (`Feature::MultiRepo`, already exists): the isolation cases above over the wire.
   - Add unconditional single-repo cases: header mismatch gives `not_found`, malformed gives `invalid_argument`, and a
     signed write without the header gives `unauthenticated`.
   - The in-process pipeline baseline declares `multi-repo` and runs in Multi mode for those cases.
   - The spawned-binary baseline does not declare `multi-repo` (B.8) but must pass every single-repo case.
   - vcs-worker: run `scripts/vcs-worker-conformance.sh` locally if wrangler is available (the M0-17 executor had it).
     The single-repo cases must pass. If wrangler isn't available, say so.
5. **Unchanged behaviour:**
   - all existing mkit-server, native, worker and conformance tests pass;
   - the ssh goldens (`serve_golden`) pass unchanged.

## D. Escalate (stop and report, do not improvise) if

- Resolving at stage 0 would require changing an adapter-facing public signature, i.e. how native or the Worker call
  into the pipeline.
- A 0.4.x client flow (A.5) breaks under B.2's single-mode rules.
- `mkit_core::repo_identity` disagrees with §7.4's ABNF on any golden case. Report the case; don't patch mkit-core
  silently.

## Gate additions

- `just ci-server`
- `cargo nextest run --locked -p mkit-server-conformance -p mkit-server-native --all-features`
- the wasm32 check of mkit-server and the build of mkit-server-worker
- `scripts/vcs-worker-conformance.sh`, if wrangler is available
