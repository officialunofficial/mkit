# WP-1.15 + WP-1.30 (bundle `1-15-1-30`): multi-repository serving on every transport

Bundle of two WPs of the MKIT-29 mkit-server epic, delivered as one PR:
- **Part 1, WP-1.30:** adapters serve Multi addressing, with the policy configuration (native and Worker). R-96.
- **Part 2, WP-1.15:** ssh and enc multi-repository addressing, `--principal`, and implicit session tickets.

## Purpose

Today every adapter serves one repository. After this bundle:
- **Native, and the Worker:** each serves Multi-addressed deployments (`X-Repository`, namespace policy, owner write
  policy).
- **ssh:** `mkit serve --root` serves a tree of repositories by `<ns>/<name>` path.
- **enc:** a listener binds to one repository of a Multi deployment.

Pushes over ssh and enc to a Multi deployment get pack membership through implicit session tickets, without admission
payments.

## A. Fixed (do not change)

1. **STC §7.4:**
   - repository identity grammar (`namespace "/" name`, lowercase);
   - an enc listener serves one repository.
   - **STC §7.5:** namespace policy and the owner write rule (rule 1).
2. **R-96:**
   - the native flags `--addressing multi`, `--namespace-policy`, `--namespace-allowlist <file>` and
     `--unsafe-open-namespaces`;
   - the Worker vars `ADDRESSING`, `NAMESPACE_POLICY`, `NAMESPACE_ALLOWLIST` and `UNSAFE_OPEN_NAMESPACES`.
3. **The existing pipeline startup refusals stay:**
   - Owner with Single on a bare name;
   - Open with Multi;
   - Multi with auth v2 but no ticket keys (R-113).
4. **STC §7.7:** one outcome per reservation. A packmap CAS conflict consumes nothing. Ticketed consumption runs no
   admission.
5. **The ssh CLI stays server-free** (`scripts/check-cli-baseline.sh`): no SQLite, axum or `mkit-server-native` in
   `mkit-cli`.
6. **Plain `mkit serve <repo-path>`** is byte-identical to today (`serve_golden.rs`).
7. **The ticket cap per consuming write is 7** (`MAX_TICKETS_PER_ADVANCE`), and the batch budget is R-122's.

## B. Decided (do not change)

### Part 1: WP-1.30 (adapters)

- **B1. Native.**
  - Add the R-96 flags. Remove the "only single-repo addressing is served" refusal (`server.rs:~522`) for Connect.
  - Multi requires auth v2 with ticket keys, and refuses `--write-policy open`.
  - The allowlist file is one namespace per line, `#` comments allowed; it is validated at startup.
  - Add `--enc-repository <ns>/<name>` (Part 2's B8).
- **B2. Worker.**
  - Add the R-96 vars, in place of the hard-coded `Addressing::Single` (`adapter.rs:~165`), with the same validation.
  - Wire the vars through `wrangler.toml` examples and `apps/vcs-worker`.
- **B3. Conformance.**
  - A native Multi profile and a Worker Multi phase run the existing Multi wire cases, which today run only in the
    in-process harness (`baseline_pipeline_memory.rs`).
  - Add the Multi phase to `scripts/vcs-worker-conformance.sh`. It is opt-in, so the default phase is unchanged.
- **B4. Plan.**
  - Add **WP-1.30** to `registry.json` and the 00-plan tables: "Adapters: Multi addressing mode and policy flags",
    deps 1.5 and 1.10.
  - Add **WP-1.30b** ("Adapters: grant flags and relying-party config", deps 1.30 and 2.6).
  - R-136 records both.
  - Note in R-136 that WP-1.26b can now exercise the namespace cap on the Worker.

### Part 2: WP-1.15 (ssh and enc)

- **B5. ssh root mode.**
  - `mkit serve --root <DIR>`. The path argument, with `/` trimmed at both ends, must parse as a
    `RepositoryIdentity`, and bare names are refused in root mode.
  - The repository lives at `<root>/<ns>/<name>/`. Canonicalize it, and require it to start with the canonical root
    (refuse symlink escapes). Keep the `MKIT_SERVE_ROOT` check.
  - Each repository directory keeps its own `serve.lock` and upload sweep.
  - A missing repository exits `NOINPUT`; there is no auto-create in M1.
  - The pipeline is `Addressing::Single` with a namespaced `RepoId`, over that directory's `FsLayoutStore`.
    `ResolvedRepo.identity` is `ns/name`.
  - When the positional path is omitted in root mode, parse `SSH_ORIGINAL_COMMAND`. Accept exactly
    `mkit serve <path>`: three tokens, in the `validate_ssh_path` charset. Any flag, quoting, NUL or CRLF is refused.
- **B6. `--principal <64 lowercase hex>`.**
  - It sets `SshForcedCommand { key: Some(k) }`. A malformed value is `USAGE` and exits before `Hello`.
  - It never comes from the environment or from `SSH_ORIGINAL_COMMAND`.
  - **Root mode:** write policy owner.
    - `ed25519-<k>/…` is writable only by `k`.
    - `0x` namespaces are denied until WP-2.12.
    - No `--principal` means every write is denied.
    - Reads are allowed.
  - **Plain mode:** the principal is recorded for logs and hooks, and the policy stays open.
- **B7. The owner check lives in the core `authorize()`.**
  - `WritePolicy::Owner` is allowed on Single when the repository's namespace is self-certifying.
  - It reuses the Multi rule-1 code without the allowlist, and sets `op.authz.owner`.
  - Owner on a bare-name Single is still refused at startup.
- **B8. enc binding.**
  - Under Multi, `--enc-repository <ns>/<name>` is required. The session config carries it, and `Verbs::auth`
    answers `x-repository` with it, so resolve, `require_repository`, creation facts and the owner rule run
    unchanged.
  - The peer key is the principal.
  - `--unsafe-allow-any-enc-peer` together with Multi is refused at startup.
- **B9. Implicit session tickets** (ssh and enc sessions against a Multi or namespaced pipeline):
  - A successful `UploadPack` adds `(pack_id, bytes)` to a per-session pending set, deduplicated by pack. At most 7
    are pending: an 8th upload is refused at its header with a fixed error frame.
    [Executor note: the eighth upload is decided at its header, and its error frame is sent after its bounded drain.]
  - The next `UpdateRef` of `refs/mkit/packmap/<x>` with a new value consumes **all** pending packs, with no
    admission:
    - the packmap CAS;
    - `plan_membership` rows for each pending pack (a blob head check; no upload marker);
    - relay rows;
    - **no outcome rows.** There is no reservation on ssh or enc.
  - A CAS conflict keeps the pending set.
  - Head, tag and delete `UpdateRef`s consume nothing and run admission as today.
  - The pending set dies with the session.
  - **Admission on ssh and enc** still runs where §7.7 says it does. An `Allow` carrying a reservation, or a
    `Challenge`, fails closed. WP-3.4 maps it to "use mkit+https".
  - Lift the `mod.rs:~351-357` refusal for `TransportIdentity`. Exempt `TransportIdentity` from the threshold refusal
    (the R-113 carry-forward).
  - Add a planner test for the maximal consuming batch against `MAX_BATCH_OPS`.
- **B10. The reconnect check (orchestrator decision; amends R-122 for transport identity only).**
  - On the consuming packmap write, decode the new packmap value's MKPL node with `decode_packlist`.
  - Refuse, with a fixed error frame and nothing written, unless the node itself and every pack it lists are either
    pending in this session or already members of the repository.
  - The check only **refuses**. It never adds membership for packs that weren't uploaded in this session.
  - This closes the hole where a reconnect loses the pending set and the packmap then names non-member packs.
- **B11. Error frames.**
  - Add one pinned row, `INVALID_REQUEST "write not permitted"`, for `permission_denied` over ssh and enc, with a
    golden under `rust/tests/golden/ssh-serve/`.
  - The other frames are unchanged.
- **B12. Docs and spec.**
  - STC §7.4 "ssh and enc" (root mode and the enc binding); SPEC-TRANSPORT §4 forced-command text.
  - `docs/SSH-SECURITY.md`: `--principal` is a trust assertion by the sshd configuration; the serving account has no
    login shell; the `AuthorizedKeysCommand` recipe converts `%k` to raw hex.
  - `docs/CLI.md`, and the native and Worker READMEs.
  - **R-137:**
    - B5–B11;
    - "one outcome per reservation" is vacuous on ssh and enc;
    - B10 amends R-122 for transport identity.
  - A CHANGELOG line per WP.

## C. Your decisions

- The allowlist file format details, as long as they are documented and validated.
- The pipeline entry for the consuming write: a flag on `update_ref`, or a new `OpKind`.
- How the per-session pending set is stored.
- Test harness shapes: enc Multi at the `serve_session` level over a memory or SQLite Multi pipeline.

## D. Escalate (stop and report) if

- The ssh CLI can't stay server-free.
- The consuming batch cannot fit `MAX_BATCH_OPS` at 7 packs.
- Worker Multi mode needs a Durable Object class or migration change. Stop before making it.
- Production code passes 3,000 lines. Then open the PR with the finished part, and list the rest as not done.

## Tests (required)

**Part 1:**
1. Native and Worker flag and var parsing, and every startup refusal.
2. Allowlist file parsing.
3. The Multi wire cases pass on native, and in the Worker Multi phase.
4. The default phases are unchanged.

**Part 2:**
5. **`--principal` parsing:** accepted and refused forms.
6. **Root-mode resolution:** `/ns/name/`, a bare name, uppercase, `..`, extra components, a symlink escape, and the
   `MKIT_SERVE_ROOT` interplay.
7. **`SSH_ORIGINAL_COMMAND`:** the exact form is accepted; flags, `sh -c`, quotes, NUL and CRLF are refused.
8. **Pipeline (Single namespaced plus Owner):**
   - the owner writes;
   - a non-owner, a missing key or `0x` gets `permission_denied`, with nothing written and admission not called;
   - reads are allowed;
   - the authorizer sees `owner`;
   - a bare Single is still open.
9. **CLI end-to-end:**
   - the owner pushes, then clones;
   - a non-owner's push fails with the pinned frame;
   - root mode without a principal: push fails, clone works;
   - two repositories are isolated (`PackExists`, `DownloadPack`, refs);
   - the plain-mode goldens are unchanged;
   - the help snapshot is updated.
10. **Implicit tickets:**
    - data pack plus MKPL, then packmap, then head: `m` rows exist and are relayed, and admission is not called on
      the consuming write (spy);
    - a CAS conflict keeps the pending set;
    - a head-only write consumes nothing;
    - the 8th upload is refused;
    - a reservation-returning admission fails closed;
    - no `o` rows.
11. **Reconnect (B10):**
    - packs uploaded in session 1, then the packmap in session 2, is refused and writes nothing;
    - the same flow in one session succeeds;
    - an MKPL that lists a pack neither pending nor a member is refused.
12. **enc:**
    - a peer writes to its own namespace;
    - a foreign namespace and a non-allowlisted namespace are denied, with nothing allocated;
    - allow-any together with Multi is refused.
13. **Isolation:** repository B sees none of A's implicit packs, and `PackExists` gives no oracle.

## Gates

- `just ci-server`, `just ci-scripts` (including `check-cli-baseline.sh`), and `just ci-security`
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-conformance -p mkit-server-worker -p mkit-cli --all-features`
- the ssh e2e suite
- the wasm32 check and the worker build
- `scripts/vcs-worker-conformance.sh`, in the default phase and the new Multi phase
