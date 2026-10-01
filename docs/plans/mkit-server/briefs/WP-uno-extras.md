# Executor prompt: two small launch extras for embedders (R-204, R-205), one PR

Run locally in `<repo>`.

**Definition of done:** an open PR into `feat/mkit-server`. Don't merge it.

**Read first:**
- `<local notes>`;
- SPEC-WRITE-GRANTS §9.1 (visibility) and §9.4 (URL tokens);
- `rust/crates/mkit-server/src/url_token/mod.rs` (`UrlTokenConfig::mint`);
- the merged 4.16c reader, `rust/crates/mkit-server/src/pipeline/object_reader.rs`, and its embedding constructor;
- the `IssueObjectUrl` handler (`connect/service.rs`).

**Setup:**
- **Worktree:** `.claude/worktrees/wp-uno-extras`, from a fresh `origin/feat/mkit-server`.
- **Branch:** `mkit-server/wp-uno-extras`.
- **PR title:** `feat(server): embedder batch URL issuance and deployment default visibility`.
- **Cap:** 450 non-test Rust lines in total.
- **Parallel lanes:** 4.18 is editing Worker config parsing and the embedding README. Keep your config change to one
  `WorkerConfig` field plus one env var, and your README edit to a few lines, so the merge is trivial. Merge the base
  before opening the PR.

## 1. R-204: batch URL-token issuance on the in-process reader

The Uno Kit viewer shows many files of a private kit. Today each needs a signed `IssueObjectUrl` RPC.
- Add `ObjectReader::issue_urls(&self, targets: &[UrlTarget], ttl_s: u32) -> Result<Vec<Option<IssuedUrl>>>`.
- The rules are **exactly** those of `IssueObjectUrl` for the reader's view: the same authorization (an Owner view
  built from a verified owner/grant envelope; a Public view only for public repositories), the same reachability,
  published-view and global-denial checks, the same epoch read, TTL clamping and audience. Reuse the RPC's internal
  code path; don't duplicate it.
- Bounded batch (document the size). Denied or unreachable targets give `None`, with no oracle.
- `URL_TOKEN_KEYS` is required; without it, return a config error.
- **Tests:** batch parity with N individual `IssueObjectUrl` calls (identical token validity and claims apart from
  timestamps), a denied target, a private repo under a Public view, batch bounds, and Worker wasm builds.

## 2. R-205: deployment default visibility for new repositories

Uno Kit wants every kit private by default. Today it must remember a `SetRepoVisibility` call before each first push.
- Add an optional deployment setting: `WorkerConfig.default_repo_visibility` (programmatic) and the env var
  `DEFAULT_REPO_VISIBILITY=public|private` (default `public`, today's behavior), plus a native config flag.
- It applies when a repository has **no stored visibility**. An explicit `SetRepoVisibility` always wins.
- **Amend SPEC-WRITE-GRANTS §9.1:** "public unless changed" becomes "the deployment's default visibility (public
  unless configured) unless changed". Add a version-history row.
- **Document the operational caveat:** changing the default later changes every repository that has never had an
  explicit visibility. Recommend setting it at deployment creation.
- Every read path that consults visibility uses the same resolver: Connect reads, HTTP serving, URL tokens, the 4.16c
  reader and snapshots. Search for every visibility lookup and route it through one function.
- **Tests:** with `private` default, a fresh repo is unreadable anonymously over Connect and HTTP until set public; an
  explicit public wins; the `public` default leaves the existing tests unchanged; parity on native and Worker.

## Docs, rules and gates

- **Docs:** R-204 and R-205 rows in `00-plan.md`, registry rows, CHANGELOG, a short embedding README note for
  `issue_urls`, and the config docs for `DEFAULT_REPO_VISIBILITY`.
- **Rules:** no new tag, timer or wire. Escalate if visibility lookups are scattered such that one resolver would
  touch more than about 15 call sites, or if a visibility cache would need invalidation on a default change.
- **Gates:**
  - the common gates;
  - `just ci-server`;
  - wasm32 clippy;
  - the vcs-worker default conformance on a free port.

  Do the self-review, then open the PR.
