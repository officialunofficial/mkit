# POSITIONING — the storage model is a choice, not an accident

Status: **Informative**. Audience: contributors, integrators, and
anyone deciding whether mkit fits a use case.

This document records *why* mkit stores what it stores the way it
does. It is not a spec — it argues the mentality. Normative shape
lives in `SPEC-OBJECTS.md`, `SPEC-PACKFILE.md`, `SPEC-FASTCDC.md`,
and `SPEC-DELTA.md`.

---

## 1. The two roads

Any system that puts versioned files on an object store (S3, R2, or a
plain filesystem) faces one fork in the road early, and the choice
colors everything downstream.

**Road A — one object per file.** Store each file as its own object,
under its real name. The bucket is then a faithful mirror of the
working tree: anything that speaks S3/HTTP can `GET` a file directly,
the bucket is human-browsable, and an existing bucket of data can be
adopted in place with no migration.

**Road B — chunk and pack.** Cut files into content-defined chunks,
bundle many chunks and objects into packfiles, and name every stored
artifact by a cryptographic hash of its contents. The bucket becomes
an opaque set of hash-named blobs that only the tool can reassemble.

**mkit takes Road B, deliberately and without apology.** This note
exists so that the trade is stated out loud rather than discovered
later as a surprise.

---

## 2. What Road B buys

The packed, content-addressed model is not a performance hack bolted
onto a file store — it is load-bearing. It is what makes the
properties mkit exists to provide *possible at all*:

- **Dedup.** Identical chunks are stored once, across files and across
  history. (`SPEC-FASTCDC`, `SPEC-OBJECTS §7`.)
- **Cheap deltas.** A small edit ships a small diff, not the whole
  file again. (`SPEC-DELTA`, `SPEC-PACKFILE §3.2`.)
- **Integrity.** Every object is re-hashed on read; corruption or
  tampering anywhere in the chain is detected, not served.
  (`SPEC-OBJECTS §2`.)
- **Signed, verifiable history.** Content addressing is the foundation
  the signing and attestation chain stands on — a commit id *is* a
  hash of its contents. (`SPEC-SIGNING`, `SPEC-ATTESTATIONS`.)
- **Transport portability.** Because every artifact is named by its
  digest, the same object graph moves across
  `mkit+{file,https,s3,ssh,enc}://` with no rewrite. The store you
  push to is a runtime choice, not a format commitment. (`SPEC-TRANSPORT`.)

None of these survive intact on Road A. One-object-per-file gives up
dedup and cheap deltas, and it makes whole-graph integrity and signed
history something you bolt on rather than something the format
guarantees.

---

## 3. What Road B costs

Stating the bill honestly:

- **The bucket is not human-browsable.** Open it in a console and you
  see hash-named packs, not `README.md` and `src/`. Only mkit, reading
  its index, can reassemble the real files.
- **mkit cannot adopt an arbitrary existing bucket as a repo.** There
  is no "point it at your S3 data and go." mkit owns its layout;
  adoption means importing, not mounting.
- **Bytes served from the bucket are packs, not files.** This matters
  most when the object store doubles as a distribution channel (see
  §4).

These are not gaps to be closed in a future release. They are the
direct, intended price of §2. A change that made the bucket browsable
or readable-in-place would, by construction, give up the properties in
§2 — so it is out of scope by design, not by omission.

---

## 4. Consequence: the bucket is a transport, not a public file store

A common and reasonable setup is to push to an object store (e.g. R2)
and lean on cheap or free egress to distribute repositories. This
works — but only for clients that speak mkit. They fetch packs and
reassemble files locally.

What it is **not** is a public file CDN. A browser, a bare `curl`, an
`<img src=...>`, or a partner who just wants to download one file from
the bucket URL gets an opaque blob, not a usable file. The object
store is a cheap distribution channel for the mkit object graph; it is
not a mirror of the working tree.

If both are ever wanted at once — packed history for the tool **and** a
browsable or directly-linkable mirror for everyone else — that is a
separate "export to plain objects" capability layered on top. It is
not a change to how mkit stores history, and it must not be allowed to
weaken §2.

---

## 5. The mentality, in one line

mkit optimizes for **verifiable, deduplicated, signed history** over
**direct object access and zero-migration adoption of existing data**.
When those two pull in opposite directions, the first wins. Anyone
weighing a feature, a transport, or a customer ask against this should
start here: if the request is really "make the bucket behave like Road
A," the answer is no — and the reason is this document, not an
oversight.

---

## 6. Cross-references

- `ARCHITECTURE.md` — code map; object → pack → ref → transport flow
- `SPEC-OBJECTS.md` — on-disk object format, BLAKE3 verify on read
- `SPEC-PACKFILE.md` — packfile wire format
- `SPEC-FASTCDC.md` — content-defined chunking
- `SPEC-DELTA.md` — delta encoding
- `SPEC-TRANSPORT.md` — transport verbs and schemes
- `SPEC-SIGNING.md` / `SPEC-ATTESTATIONS.md` — what content addressing makes possible
