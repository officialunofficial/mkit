---
spec: SPEC-GIT-IMPORT
version: 1
status: draft
audience: implementers of the git→mkit import bridge and its verifiers
---

# SPEC-GIT-IMPORT — importer-signed git→mkit translation (v1)

Status: **Normative** for the git→mkit import direction.
Scope: the mapping from git objects to mkit v1 objects under the
importer-signed policy, the refusal matrix, provenance, per-remote
state and key binding, canonical remote identity, and pull/divergence
semantics. Shared byte-level encodings (hex/base64 forms, ref
grammars, chunking parameters) are defined by
[SPEC-GIT-BRIDGE](SPEC-GIT-BRIDGE.md), SPEC-OBJECTS, SPEC-SIGNING,
SPEC-REFS, and SPEC-FASTCDC; this spec only adds the inbound rules.

Import is **not** the inverse of export. Export round-trips mkit
objects losslessly through carrier headers; import is a *signed
translation across a trust boundary*: every imported commit and tag
is a new mkit object signed by the **importer**, attributing the
original author and binding the original git bytes as provenance.
The result is a **downstream fork** — its mkit hashes are a function
of the importer's signing key, and two importers of the same upstream
produce unrelated mkit histories by design (§6).

---

## 1. Model

### 1.1 Direction and trust

```
git blob                  → mkit blob (≤ 1 MiB) or chunk blobs +
                            manifest (> 1 MiB, pinned FastCDC)
git tree                  → mkit tree (re-sorted; names validated)
git commit                → mkit commit, SIGNED BY THE IMPORTER
git annotated/signed tag  → mkit tag, SIGNED BY THE IMPORTER
git lightweight tag       → bare refs/tags/<name> ref
git gitlink (160000)      → REFUSED (per-ref)
```

The importer's Ed25519 signature asserts exactly: *"I vouch that
these bytes are my translator's faithful output for the named
upstream object."* It is never an authorship claim — original
authorship rides in the `author`/`tagger` Identity (§3.2), and
SPEC-SIGNING §6 already separates attribution from the verification
key. A git GPG/SSH signature on the source commit/tag is **carried in
the retained raw bytes** (§5) and is not representable as an mkit
signature.

### 1.2 Version keying and determinism

The mapping is defined for mkit object schema `0x01` and is pinned by
an **import-spec version** recorded in the per-remote state (§6).
Implementations MUST refuse to incrementally extend an import whose
recorded import-spec version they do not implement (forcing an
explicit re-import) — translation-rule drift between versions would
silently fork hashes for the same key.

Import is a pure function of *(upstream git bytes, importer signing
key, import-spec version)*. mkit signing is deterministic
(RFC 8032), so re-running an import reproduces byte-identical mkit
objects, the sha1↔blake3 map is a rebuildable cache **under the same
key**, and a crashed import is resumed by re-running it.

### 1.3 Non-goals (v1)

- Bidirectional sync (permanent — restating SPEC-GIT-BRIDGE §1.3).
- SHA-256 git repositories (whole-import refusal).
- Shallow import: structurally impossible — an mkit parent hash is
  the BLAKE3 of the translated parent, which requires the full
  closure. The staging mirror is always a full clone.
- Escaping schemes for git-legal/mkit-illegal names or refs
  (refusals are reversible; a wrong escape is forever).
- `refs/notes`, `refs/replace`, grafts.
- Re-exporting imported history toward its origin except in
  passthrough/fork mode (SPEC-GIT-BRIDGE §14; see also §8).

---

## 2. Reading the upstream

Implementations SHOULD obtain upstream objects via a full
`git clone --mirror` into the per-remote staging repository (§6) and
read objects with `git cat-file --batch` (git owns wire protocol,
auth, and pack storage; the bridge owns only translation). Commit
order MUST be a topological parents-first order (`git rev-list
--reverse --topo-order`). The inbound parser MUST be tolerant of
everything git accepts — multi-line continuation headers (`gpgsig`,
`mergetag`), unknown headers, the `encoding` header, malformed
person lines in historic commits — because this is an
untrusted-input boundary; tolerance means *parse and carry or refuse
loudly*, never crash or silently alter.

`objectFormat = sha256` upstreams MUST be refused at clone time.

---

## 3. Inbound object mapping

### 3.1 Blobs

git blob bytes map verbatim. Content at or below the 1 MiB chunking
threshold becomes one mkit blob; above it, the pinned FastCDC
chunker (SPEC-FASTCDC) produces chunk blobs + a `chunk_size = 0`
manifest — exactly the writer-side rule, so imported stores are
exportable (SPEC-GIT-BRIDGE §4 refusals never trigger on them).
SPEC-FASTCDC leaves the threshold an implementer choice; for
importers `CHUNK_THRESHOLD = 1 MiB` is **normative** (a different
threshold would fork hashes across implementations).
Blobs over `worktree::MAX_FILE_BYTES` (1 GiB, the per-file cap)
refuse per-ref.

### 3.2 Commits

```
mkit field        ← git source
tree_hash         ← translated tree
parents           ← translated parents, order preserved
author            ← Identity::Opaque(author name + " <" + email + ">")
signer            ← the importer key (§4)
message           ← message bytes VERBATIM (no UTF-8 constraint;
                    `encoding` header tolerated and dropped)
timestamp         ← git COMMITTER epoch seconds
message_hash      ← zero
content_digest    ← BLAKE3(framed raw git commit bytes) (§5; advisory)
signature         ← Ed25519 by the importer under COMMIT_DOMAIN
```

Pinned rules:

- The author Identity payload is a verbatim BYTE SLICE of the git
  author line, pinned byte-exactly as: the bytes from the first byte
  after the `author ` keyword+space through **the last `>` byte that
  is preceded anywhere on the line by a `<`** (interior spacing,
  doubled spaces, missing space before `<`, and stray `<`/`>` inside
  the slice all preserved — no recomposition, so historic
  malformations hash identically across implementations). Lines with
  no such byte (no `<` at all, or `<` with no closing `>` anywhere
  after it) use the bracket-less rule: the remainder after `author `,
  with one trailing match of the pattern *space, decimal seconds,
  space, `+` or `-`, four digits* stripped. A person line from which
  no timestamp can be parsed (no token after the identity slice, or
  no trailing pattern on a bracket-less line) refuses the ref —
  commits and tags always need a timestamp. Payloads that would be
  empty or exceed 4096 bytes refuse per-ref.
- The committer line, both timezones, the author timestamp, `gpgsig`,
  `mergetag`, `encoding`, and any unknown headers are **not**
  represented in the mkit commit; they are recoverable from the
  retained raw bytes (§5).
- Negative (pre-1970) committer timestamps refuse per-ref (mkit
  timestamps are u64).
- More than 1000 parents refuses per-ref (`MAX_PARENTS`).
- The importer signs under `COMMIT_DOMAIN` — **no new signing domain**.
  Commits carry no domain marker and `verify_commit` hardcodes the
  commit domain; a separate import domain would make imported commits
  unverifiable everywhere. Distinguishability comes from the
  git-import/v1 predicate, the DSSE keyid, and the dedicated import
  key (§4) — the same principle SPEC-GIT-BRIDGE §11 pins for export.

### 3.3 Trees

Entries re-sort from git order (directories keyed `name + "/"`) to
mkit byte-lex order. Canonical modes map `100644→0x01`, `40000→0x02`,
`120000→0x03`, `100755→0x04`. Historic non-canonical mode SPELLINGS
normalize to their canonical equivalent's mkit mode, enumerated
exhaustively: `100664→0x01`, `100640→0x01`, `100600→0x01`,
`040000→0x02` (zero-padded directory). Any other mode string refuses
per-ref. Normalization is declared-lossy (warned once per ref) —
except in a state dir whose recorded `direction` is `fork` (§6),
where a normalized tree could not reproduce its original sha1 and
the affected ref MUST refuse instead.
`160000` (gitlink/submodule) refuses per-ref with an actionable
message. Two structural refusals close gaps git can represent but
mkit cannot decode: entry names that collide byte-equal after the
re-sort (a file and a directory of one name) refuse per-ref, and
trees nesting beyond 128 levels (mkit's `MAX_TREE_DEPTH` defense)
refuse per-ref. Entry names are validated by SPEC-OBJECTS §4.1
(deserialize-time rules — non-negotiable): names that are `.git`/
`.mkit` case-insensitive, end in dot/space, are Windows device stems
(`aux.c`-class), exceed 255 bytes, or contain backslash refuse the
ref.

### 3.4 Tags

Annotated and signed git tags map to mkit tag objects **signed by the
importer under `TAG_DOMAIN`** (same vouch semantics as commits; the
original `tagger` line maps to the tagger Identity by the §3.2 rule
and the mkit tag `timestamp` is the tagger epoch, negative-refused
like commits; git tag GPG signatures ride in the retained raw bytes
only). Historic tagger-less tags (git v0.99 era) take the PINNED
sentinel `Identity::Opaque("(no tagger)")` and timestamp `0` — any
other choice would fork tag hashes across implementations. The tag
name must satisfy the mkit single-segment tag grammar
(SPEC-GIT-BRIDGE §7.1) or the tag refuses. Lightweight tags map to
bare refs. Tag targets follow the object mapping; tag→tag chains are
bounded at 16. The mkit tag object has no annotation slots, so tag
provenance lives only in §5's retained bytes + attestation.

### 3.5 Refs

Upstream `refs/heads/*` and `refs/tags/*` map to
`refs/remotes/<remote>/<branch>` tracking refs and `refs/tags/<name>`
respectively (fresh-clone form also sets `refs/heads/<default>` and
HEAD). Ref names outside the SPEC-REFS §3 grammar (`@`, `+`,
unicode, `.lock` suffix, `HEAD` final segment) refuse per-ref. The
refusal UX matches export: skip-and-warn per ref, non-zero exit when
everything was skipped.

---

## 4. The importer key

- Implementations MUST default to a **dedicated import key**
  (offering to generate one), distinct from the user's personal
  commit key, and MUST print which key an import will sign with.
  Rationale: bounds the non-repudiation blast radius (the key signs
  attacker-influenceable upstream content), and makes "imported-by"
  legible by keyid.
- The importing key's public key is **pinned in the per-remote state**
  at first import. Import and pull MUST refuse under a different
  available key, naming the pinned key and the designated-importer
  model (§6). Key rotation means a fresh import under a new remote
  name (new hashes — a new fork), never a silent re-derive.
- Collaborative tracking of one upstream REQUIRES sharing the import
  key (an org/bot key): teammates otherwise produce unrelated forks.
  Cross-machine discovery of "someone already imported this" is
  impossible by architecture (state and attestations do not travel
  over mkit transport); the in-store probe (§6.1) covers the
  same-store case, and this requirement covers the rest.

---

## 5. Provenance

Three layers, from authoritative to advisory:

1. **git-import/v1 attestation** (authoritative): one DSSE/in-toto
   attestation per imported ref head per fetch, signed with the
   importer's configured signer. `predicateType` =
   `https://github.com/officialunofficial/mkit/spec/predicate/git-import/v1`.
   `subject[0]` = `{name: <full mkit ref>, digest: {blake3: <mkit
   head hash>}}`. Predicate (JCS key order):

   ```json
   {
     "gitCommit": "<40hex sha1 of the upstream head>",
     "refName": "<full mkit ref name>",
     "remoteUrl": "<canonical remote identity, §8>",
     "schemaVersion": 1,
     "specVersion": 1
   }
   ```

   Because parents are inside signed commit bytes, a head attestation
   transitively pins the imported closure. Envelopes are stored like
   any attestation (`.mkit/attestations/<commit>/…`). Importers
   SHOULD skip re-minting for a head whose recorded imported state is
   unchanged (mirroring SPEC-GIT-BRIDGE §11's guidance).
2. **Retained raw bytes**: the original git commit and tag object
   bytes in their FRAMED form — `"<type> <len>\0" + body`, the sha1
   preimage (this framing is normative for both retention and the
   `content_digest` input; body-only would fork digests across
   implementations) — sha1-addressed, under the per-remote state dir. Small
   (commits/tags only — trees/blobs are recoverable from the staging
   mirror and re-derivable from the mkit twins). These are what make
   the lossy field mapping (§3.2) recoverable and the translation
   byte-auditable.
3. **`content_digest` = BLAKE3(raw git commit bytes)** (advisory):
   in the hashed commit bytes but excluded from signing bytes
   (SPEC-OBJECTS §5.1), therefore **malleable in isolation** — a
   signature-preserving sibling with a forged slot is constructible.
   Verifiers MUST treat it as a hint; the attestation and retained
   bytes are the proof surface.

---

## 6. Per-remote state and guardrails

State lives in `.mkit/git/<remote>/` (layout implementation-defined,
non-normative except for the binding semantics below):

- `dest` (export-direction dirs)/`source`: the canonical remote
  identity (§8), immutable after first use. One state dir = one
  upstream. Fork-direction dirs record `dest` informationally only
  (last push target) — fork pushes lease against a fresh observation
  per SPEC-GIT-BRIDGE §14.1, so they are not destination-bound.
- `direction`: `import`, `export`, or `fork` (passthrough-enabled).
  A state dir MUST NOT serve import and plain export simultaneously;
  mixed use is refused at open. (`fork` combines an import source
  with passthrough export per SPEC-GIT-BRIDGE §14.)
- `signer`: the pinned importer pubkey (§4).
- `import-spec-version` (§1.2).
- The staging mirror (`repo.git`): for import it is **durable
  state**, not a disposable cache — it is the byte-perfect original
  archive backing §5.2 and the passthrough object source. Deleting
  it forces a re-clone but loses nothing else.
- The sha1↔blake3 map: rebuildable cache under the pinned key, exact
  same format and torn-tail semantics as export (SPEC-GIT-BRIDGE
  §12.3).

### 6.1 In-store divergence probe

Before translating, an import MUST run two checks:

1. **State-dir identity check** (structural): if any state dir in
   this repository records the same canonical remote identity (§8),
   refuse unless it is the one being used — this catches re-imports
   regardless of how far upstream has advanced.
2. **Content probe** (best-effort): walking back from each upstream
   head through first parents (bounded; until the first hit or the
   walk ends), if a commit whose `content_digest ==
   BLAKE3(candidate's raw bytes)` exists in the store but was signed
   by a **different** key, refuse with guidance ("this upstream is
   already imported here under key <hex8>; pull from the designated
   importer over mkit transport, or install that key"). A linear
   store scan is an acceptable lookup mechanism (imports are rare,
   interactive operations); an index is permitted but not required.

The probe is best-effort (content_digest is advisory) — it catches
the realistic accident, not an adversary.

---

## 7. Pull, divergence, and rewrites

- `fetch` semantics: `git fetch` in the staging mirror, translate the
  new closure under the pinned key (incremental: map hits skip
  subgraphs), advance `refs/remotes/<remote>/*`. Tracking refs are
  not user work: an upstream **force-push** moves them with a loud
  warning naming the rewound ref and old/new tips; map entries for
  abandoned commits stay valid forever (determinism).
- `pull` = fetch + fast-forward of the current branch from its
  tracking ref, reusing the native FF machinery and guards.
  Divergence refuses with the executable hint
  (`mkit merge <remote>/<branch>` / `mkit rebase`); integration is
  **native** — imported commits are ordinary mkit objects.
- Local work on top of imported history merges/rebases natively;
  replays preserve original authorship (the native replay rule).

---

## 8. Canonical remote identity

All bindings, guards, and attestation `remoteUrl` fields use one
normalization, `remote_identity(dest)`:

1. scp-style `[user@]host:path` rewrites to `ssh://host/path`
   (honesty note: a home-relative scp path and an absolute ssh:// path
   can be different repos on a generic server; the conflation only
   widens the guard — fail-closed). IPv6 literals keep their
   brackets: `[::1]:path` → `ssh://[::1]/path`;
2. scheme and host lowercase; userinfo dropped; default ports
   stripped per scheme (`ssh` 22, `https` 443, `http` 80, `git`
   9418);
3. exactly one trailing `/` and one trailing `.git` stripped from the
   path;
4. local paths AND `file://` URLs (`file:///p`, `file://localhost/p`)
   collapse to the symlink-resolved absolute local path.

Equivalence examples (all one identity):
`git@github.com:org/repo.git` ≡ `ssh://github.com/org/repo` ≡
`ssh://GIT@GITHUB.COM:22/org/repo/`. The **origin guard**
(SPEC-GIT-BRIDGE §14.2) compares canonical identities: plain
(non-passthrough) export MUST refuse a destination whose identity
matches any recorded import source. This is a safety net against
accidents, not a security boundary — mirrors and redirects are
undetectable; the push lease remains the backstop.

---

## 9. Test vectors (implementer MUST produce)

Pinned under `rust/tests/golden/git-import/` with the standard
MANIFEST convention; each vector records the source git object bytes,
the imported mkit object bytes under the fixed test key, and both
ids. Single exception: vector 9's > 1 MiB content is regenerated
deterministically by the golden test rather than committed; its two
ids are pinned like every other vector (same carve-out as
SPEC-GIT-BRIDGE §13's chunked vector). Refusal vectors (gitlink tree,
reserved tree-entry name, negative timestamp, out-of-grammar tag
name) pin their TYPED refusal in `REFUSALS.txt` alongside the
success vectors.

1. **Plain commit** (author == committer, UTC) — the baseline.
2. **Committer ≠ author with non-UTC zones** — committer-timestamp
   rule + provenance recovery.
3. **gpgsig commit** (multi-line continuation header) — tolerant
   parse, signature in retained bytes only.
4. **latin-1 message with `encoding` header** — verbatim bytes.
5. **Historic mode `100664` tree** — normalize-declared-lossy.
6. **Octopus merge** (≥3 parents) — order preserved.
7. **Annotated tag** (tagger, message) — TAG_DOMAIN importer
   signature.
8. **Signed git tag** — GPG block in retained bytes; mkit tag
   verifies under the importer key.
9. **> 1 MiB blob** — FastCDC manifest equals the writer-side rule.

Refusal vectors (assert the typed refusal, not bytes): gitlink tree,
`aux.c` tree name, negative timestamp, `v1.0+build` ref name,
sha256 repo marker.

Every vector MUST be byte-stable across two runs (determinism) and
MUST `verify_commit`/`verify_tag` under the test key.

---

## 10. Version history

| Version | Changes |
|---------|---------|
| 1 | Initial importer-signed mapping: blobs/trees/commits/tags, refusal matrix, dedicated-key + pinning model, three-layer provenance, canonical remote identity, fetch/pull semantics, golden vectors. |
