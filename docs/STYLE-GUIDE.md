# mkit documentation writing style guide

The mkit documentation is the single source of truth for the on-disk
and wire formats, the CLI, the Rust crates, and the attestation
subsystem. It evolves continuously with new features and crates.

This style guide provides editorial guidelines for writing clear and
consistent mkit documentation. Aim for clarity, accuracy, and
completeness when contributing improvements. Use this guide as a
reference document for specific questions.

This page is divided into two main sections:

- [Writing general documentation](#writing-general-documentation)
- [Writing API documentation](#writing-api-documentation)

# Writing general documentation

The "general" documentation covers the mechanics and formatting
guidelines that apply across mkit prose — the README, `docs/`,
`CONTRIBUTING.md`, advisories, release notes, and any other narrative
text in the repository.

> All mkit prose documentation is written in [Markdown](https://en.wikipedia.org/wiki/Markdown).
> Rust API docs are written as rustdoc comments inside the crate
> sources; see [Writing API documentation](#writing-api-documentation).

## Spelling and word choices

Developers reading the mkit docs shouldn't trip over obvious mistakes
and lose confidence in the project. Write with correct grammar,
punctuation, and spelling.

Always **show and don't tell**. Instead of explaining a concept to the
reader, give them an example. Providing examples helps grab the
reader's attention.

Some words have multiple legitimate spellings. Prefer the shorter,
single-`l` American forms: "canceled" and "canceling", but
"cancellation". Prefer "behavior" over "behaviour".

### Voice and tone

Developers read documentation to find answers to their problems.
Documentation exists because it can translate complex information
into easily digestible pieces. Voice and tone directly influence that
translation and remove friction.

Write clearly and concisely using plain American English. Aim for
clarity for all English speakers, not only native ones.

### Write in the second person

Generally, write in the second rather than the first person. Use
"you" instead of "we".

Reserve "we" for the rare cases when the mkit maintainers are
directly addressing the reader to convey an important message (for
example, a security advisory or a deprecation notice).

### Use present tense

Writing in the present tense tells the reader what the system does
right now. Developers already weigh complex tradeoffs when choosing a
VCS or a signing stack; the docs should not add tense ambiguity to
that list.

### Use active voice

Avoid the passive voice. Common passive constructions use "was" or
"by". Use a tool such as [Hemingway](https://hemingwayapp.com/) or
Grammarly to spot passive voice in your drafts.

### Write and edit for clarity

Write short sentences. One thought per sentence is punchier and
pithier. Cramming multiple thoughts into one sentence makes the copy
painful to read.

Use action verbs and subject-verb-object construction, cut clunky
phrases, and avoid jargon. Remove any adjectives or adverbs that
don't change the meaning of a sentence.

If you have to write a long sentence, follow it up with a short one.
The contrast snaps the reader back to attention. Don't repeat the
same word inside a single sentence, and don't start or end a sentence
with the same word you used to start or end the previous one.

### Use gender-neutral terms

Use "they" as a singular pronoun. When necessary, address a group of
readers as "developers", "operators", "maintainers", or "callers"
(for an API).

### Symbols as words

When it is correct to use words instead of symbols:

- **Ampersands (&)**: Don't use "&" instead of "and" in headings,
  text, navigation, or tables of contents. Spell out "and".
- **Plus (+)**: Don't use "+" instead of "plus" in text, navigation,
  or tables of contents. Spell out "plus".
  - An exception to this rule is when [referencing keyboard
    shortcuts](#referencing-keyboard-shortcuts).

### Referencing operating systems and platforms

mkit targets Linux, macOS, and Windows. When you list them, order
them alphabetically: **"Linux, macOS, and Windows"**.

Capitalize platform names as the vendors do: Linux, macOS, Windows,
FreeBSD. Spell "macOS" with a lowercase "m" and capital "OS".

### Referencing transports

mkit ships several transport schemes — `mkit+file://`, `mkit+https://`,
`mkit+s3://`, `mkit+ssh://`. Reference them by their full scheme,
formatted as inline code, the first time they appear on a page. After
that, "the SSH transport" or "the S3 transport" is acceptable.

### Referencing the on-disk layout

Before a working tree has any mkit state, it is a directory. Once
`mkit init` runs, it is a **repository**, and its state lives in the
`.mkit/` directory. The CLI also speaks of **objects**, **packs**,
**refs**, the **index**, and the **working tree**; use those terms
consistently and link to the relevant SPEC document on first use.

### Referencing hashes and identifiers

mkit uses BLAKE3 as its content-address primitive. Refer to a full
hash as a **digest** or **object ID**, and to a shortened form as a
**short hash**. When showing examples, use `b3:` as the canonical
prefix and a realistic-looking digest, not `xxxxxxxx`.

### Abbreviations

On first use on an individual documentation page, expand an
abbreviation in parentheses. For example, "Distinguished Encoding
Rules (DER)" or "Trusted Platform Module (TPM)".

The following abbreviations are acceptable in their shortened form
without expansion:

- HTML, HTTP, HTTPS, URL, SSH, JSON, CBOR, TLS, mTLS, CI, CLI, API,
  RPC, OS, npm, JPEG, PNG, CSV.

Avoid Latin abbreviations such as "i.e." or "e.g.". Spell them out:
"that is" or "for example".

### Follow external product casing

Use external product names the same way the industry does. For
example: BLAKE3, Ed25519, secp256k1, P-256, SHA-256, in-toto, DSSE,
SLSA, libgit2, GitHub, GitLab, S3, MinIO, Linux, macOS, Windows,
Rust, Cargo, rustup, Clippy, rustdoc, Tokio, Hyper, OpenSSH,
PKCS#11, TPM 2.0, WebAssembly.

### Referencing bytes and bits

Always use a capital "B" for bytes. Write "bit" or a lowercase "b"
for bits. For example:

- Decimal byte units: kB, MB, GB, TB
- Binary byte units: kiB, MiB, GiB, TiB
- Decimal bit units: kbit, Mbit, Gbit, Tbit
- Binary bit units: kibit, Mibit, Gibit, Tibit

For an in-depth reference, see [Kilobytes, kibibytes, and
kilobits](#kilobytes-kb-kibibytes-kib-and-kilobits-kbit-kb) in the
API documentation section.

## Punctuation

### Use double quotes in prose

- Correct: Set the field named "name" to your remote's identifier.
- Incorrect: Set the field named 'name' to your remote's identifier.

### Use Oxford commas

Generally, use Oxford commas. If a sentence ends up with too many
commas, refactor it — split it in two, swap a comma for an em dash
or a colon, or simplify the structure — rather than dropping the
Oxford comma.

One exception is in section headings, where you may omit it for
brevity.

### Using the possessive form

The possessive of a singular noun is formed by adding an apostrophe
and an `s`. This holds no matter the final consonant. The
possessive of a plural noun that ends in `s` is formed by adding
just the apostrophe.

- Example: mkit's content-address primitive is BLAKE3.

Exceptions:

- Pronoun possessives use no apostrophe (its, hers, yours, theirs,
  ours), but indefinite pronouns do (one's own opinions).
- Ancient names that end in "-es" or "-is" take just an apostrophe
  (Osiris' burial rites). You are unlikely to need this in technical
  writing.

### Do not add a space around "/"

Do not pad a slash with extra space for emphasis.

- Correct: working-tree/index state
- Incorrect: working-tree / index state

### Splitting phrases

Prefer splitting a phrase into two separate sentences. The goal is
documentation that reads easily.

In rare cases when you need to keep the structure, [use em
dashes](#use-mdash) (—) or connecting words ("then", "however",
"so") rather than commas to glue two independent clauses together.

- Correct: BLAKE3 is parallelizable. The benches reflect a single
  core, so multi-core throughput is higher.
- Incorrect: BLAKE3 is parallelizable, the benches reflect a single
  core.

## Formatting

Guidelines for formatting in different situations, such as file
names, inline code, and headings.

### Headings

On a page, top-level section headers are H2 (`##`). The page title
is the H1 (`#`). Do not skip heading levels just to emphasize a
sub-section.

Use sentence case for section and sub-section headings, except where
a heading begins with a product or proper name (mkit, BLAKE3,
in-toto, DSSE, GitHub). Developers are used to those names; keeping
their canonical casing makes the docs more scannable.

- Correct: Verifying a signed commit
- Incorrect: Verifying A Signed Commit

If a heading refers to a product or component name, capitalize that
name as the vendor does:

- Correct: Creating your first DSSE envelope
- Incorrect: Creating your first dsse envelope

### Buttons and call-outs

Use title case for any text rendered as a button or other clickable
UI element. The rule of thumb is to not capitalize articles,
prepositions, or conjunctions inside a title-cased phrase.

- Correct: Run the SSH Transport Demo
- Incorrect: Run the ssh transport demo

### File names, directory names, file extensions as bold text

File names, directory names, and file extensions are rendered as
**bold** text in Markdown.

- Correct: The repository state lives in **.mkit/**.
- Incorrect: The repository state lives in `.mkit/`.

- Correct: Commit and tree objects are encoded as **.cbor**.
- Incorrect: Commit and tree objects are encoded as `.cbor`.

- Correct: The fuzz harness lives at **rust/fuzz/**.
- Incorrect: The fuzz harness lives at `rust/fuzz/`.

### Capitalization

Do not use capitalized words for emphasis.

Exception: always capitalize product phrases as the project does.

- Correct: in-toto v1 Statement, DSSE envelope, GitHub Security
  Advisory.
- Incorrect: GitHub security advisory.

### Linking to other docs

Link the appropriate noun phrase rather than using the word "here".
The linked text should describe the destination and act as a Call to
Action (CTA).

- Correct: See the [pack file specification](SPEC-PACKFILE.md) for
  the byte-level layout.
- Incorrect: The pack file specification is available [here](SPEC-PACKFILE.md).

Use **relative links** when referencing another file in the
repository (`./SPEC-OBJECTS.md`, `../README.md`). When linking from
prose into the Rust API docs, prefer a stable docs.rs URL or an
intra-doc rustdoc link inside the source — not a path into
`rust/target/doc/`.

### Accessibility

An accessible document is created to be as easily readable by a
sighted reader as by a low-vision or non-sighted one. The most
common thing to get right is alternative ("alt") text for images and
videos.

When embedding an image or video in Markdown, add a meaningful alt
text inside the square brackets.

```markdown
![BLAKE3 throughput chart at 1 MiB chunk size](benchmarks/charts/hashing-1_mib.svg)
```

Alt text should describe what the image conveys, not what it looks
like. "Hash throughput chart" is fine; "blue and orange bar chart"
is not.

### Using inline code

Apply inline code formatting (back-ticks) only to programming words,
identifiers, paths inside source trees, command invocations, or
literal CLI output. Do not use inline code as a substitute for
emphasis.

- Correct: Pass `--porcelain` to make `mkit status` write to stdout.
- Incorrect: Click the `File` menu, then `Save As`.

### Use `&mdash;`

When you want an em dash, write `&mdash;` instead of `-`, `--`, or
the literal `—` character. Markdown renders the entity reliably; the
hyphen variants render as plain hyphens, and the literal `—`
character is the most common variant inserted by AI-assisted
writing — flag it during review.

### Referencing keyboard shortcuts

Render keyboard shortcuts with the `<kbd>` element. Wrap each key in
its own tag, and keep the plus sign outside the tags.

- Correct: Open a new terminal with <kbd>Cmd ⌘</kbd> + <kbd>T</kbd>
  or <kbd>Ctrl</kbd> + <kbd>T</kbd>.
- Incorrect: Open a new terminal with `⌘+t` or `ctrl+t`.

Rules:

- Add a space before and after each plus sign.
- For macOS, use the ⌘ symbol with the prefix `Cmd`.
- For Windows and Linux, use the spelled-out modifier (`Ctrl`,
  `Alt`, `Shift`).
- Capitalize the shortcut letter, for example <kbd>Ctrl</kbd> +
  <kbd>T</kbd>.

### Do not use emojis

Do not use emojis in the documentation. This includes prose,
headings, callouts, and changelog entries.

### Use Cargo, not third-party install scripts

When referencing how to install or run a Rust binary, use Cargo as
the canonical entry point. For mkit specifically, prefer the
documented install channels (`cargo install`, Homebrew, the
`install.sh` script, or a release binary) and link to
[`docs/INSTALL.md`](INSTALL.md) for the full set.

- Correct: `cargo install --git https://github.com/officialunofficial/mkit mkit-cli`
- Incorrect: A curl-piped install command from a third-party host.

### Collapsible components

When a collapsible component holds a single item or a single
paragraph, do not wrap it in a bullet point. The bullet adds no
information.

### Avoid outdated terminology

Avoid terms that describe deprecated or removed workflows. If a
command, flag, or format was renamed, use the current name and link
to the change in the CHANGELOG only when the deprecation window is
still active.

For instructions that require manually editing files outside the
mkit-managed area (for example, hand-editing keys or tweaking
transport-specific configuration), put those instructions inside a
collapsible block labeled "Manual setup" or "Advanced".

### Numbered lists

Any numbered list starts at `1`, not `0`. This keeps numbering
consistent across the docs.

### Crate version range callouts

When a feature is gated by a specific crate version, use _later_ or
_earlier_ to describe the range. Use the crate name and a SemVer
number.

- Correct: **info** Available in **mkit-core 0.4 and later**.
- Correct: **info** Available in **mkit-core 0.3 and earlier**.
- Incorrect: **info** Available in **mkit-core 0.4 and above**.
- Incorrect: **info** Available in **mkit-core 0.4 and below**.

## Tools for visualization and interactivity

When a topic is easier to grasp visually or interactively, reach for
the right tool:

- **Diagrams** communicate complex relationships. They let the
  reader digest the structure of an object graph, a pack layout, or
  a transport handshake faster than prose can. Existing diagrams
  live alongside the `README.md` charts and the `SPEC-*` docs.
- **Screenshots** let the reader confirm a visual artifact (a
  rendered chart, a CLI session, a CI output) matches what the docs
  describe.
- **Terminal transcripts** are often more useful than screenshots
  for a CLI tool. Use a fenced code block and label the language as
  `sh` or `console`, and prefix interactive commands with `$ `.

## Glossary

These terms are used consistently throughout the mkit
documentation. When in doubt, link to the canonical definition (the
relevant `SPEC-*.md` page) on first use.

- **Object** — a content-addressed unit stored in the repository.
  Subtypes are **blob**, **tree**, and **commit** (see
  [SPEC-OBJECTS](SPEC-OBJECTS.md)).
- **Digest** / **object ID** — the BLAKE3 hash that names an
  object. Always 32 bytes; rendered as `b3:` plus the lowercase hex
  encoding.
- **Pack** — a single-file container holding many objects, used
  for transport and on-disk storage (see
  [SPEC-PACKFILE](SPEC-PACKFILE.md)).
- **Index** — the staging area for the next commit, plus the
  cache of file metadata that tracks the working tree (see
  [SPEC-INDEX](SPEC-INDEX.md)).
- **Ref** — a named pointer into the object graph, usually
  resolving to a commit (see [SPEC-REFS](SPEC-REFS.md)).
- **Working tree** — the user-visible files on disk that the
  index and HEAD describe.
- **Transport** — the protocol that moves packs between
  repositories. mkit transports are `mkit+file`, `mkit+https`,
  `mkit+s3`, and `mkit+ssh` (see [SPEC-TRANSPORT](SPEC-TRANSPORT.md)).
- **Signer** — a component that produces a signature over a payload
  using a private key. Built-in signers live in `mkit-attest`;
  external signers (TPM, secure element, CTAP, file) live under
  `contrib/signers/` (see [SPEC-EXTERNAL-SIGNER](SPEC-EXTERNAL-SIGNER.md)).
- **Witness** — a third party that signs an attestation about a
  commit or another artifact. Witness signatures are attached as
  additional DSSE signatures on the same envelope.
- **Statement** — the in-toto v1 payload that an attestation
  describes (subject + predicate). See [SPEC-ATTESTATIONS](SPEC-ATTESTATIONS.md).
- **Envelope** — a Dead Simple Signing Envelope (DSSE) wrapping a
  Statement, carrying one or more signatures.
- **Predicate** — the payload type carried inside a Statement.
  mkit is predicate-agnostic: any in-toto predicate URI is allowed.
- **Crate** — a Rust compilation unit. mkit's Rust workspace
  publishes several crates under `rust/crates/`.
- **Library** — an overarching name for code that callers depend
  on as part of their applications. Examples: an mkit crate, an
  npm package, a system shared library.
- **Archive** — a compressed bundle of files (a `.tar.gz`,
  `.zip`, and so on). mkit release artifacts are archives.
- **Bundle** — a self-contained release artifact that includes
  one or more packs plus a manifest. Distinct from a JavaScript
  bundle, which mkit does not produce.
- **Golden vector** — a pinned input/output pair that locks a
  format. Golden vectors live under `rust/tests/golden/` and
  changing one is a breaking format change.

# Writing API documentation

Writing API documentation accurately and precisely helps callers
use mkit's crates correctly. The following sections cover the
mechanics of rustdoc, the tags to prefer, and the topics that
often trip up authors.

## General approach

- Inline docs into the source as [rustdoc](https://doc.rust-lang.org/rustdoc/)
  comments: `///` for items, `//!` for modules and crates.
- Document every `pub` item in `rust/crates/mkit-*`. CI enforces
  `#![warn(missing_docs)]` on the public crates.
- Prefer rustdoc's first-class sections over ad-hoc prose
  headings. They render consistently and integrate with `cargo
  doc`, docs.rs, and IDE tooltips.

| Section | Usage |
| ------- | ----- |
| `# Examples` | A self-contained code block, ideally as a doctest. Doctests run in CI; broken examples fail the build. |
| `# Errors` | Required on any function that returns a `Result`. Describes the error variants and the conditions that produce them. |
| `# Panics` | Required on any function that can panic. Describes the precondition the caller must uphold. |
| `# Safety` | Required on every `unsafe fn`. Describes the invariants the caller must uphold to avoid undefined behavior. |
| `# Returns` | Optional. Use only when the return value is non-obvious from the signature. |

mkit-specific conventions on top of stock rustdoc:

- **Intra-doc links**: link items with rustdoc's
  `` [`Type`] `` syntax (or `` [`crate::path::Type`] ``). Do not
  write raw `https://docs.rs/...` URLs when an intra-doc link
  works — they outlive renames and `cargo doc` validates them.
- **Cross-crate links**: from a crate, link sibling crates by
  their published name (`` [`mkit_core::Object`] ``). rustdoc
  resolves these at build time.
- **Hide test-only and internal items**: use `#[doc(hidden)]` or
  `pub(crate)` rather than `///` comments saying "do not use".
- **Deprecation**: prefer the `#[deprecated(since = "...", note =
  "...")]` attribute over prose in the docstring. The attribute
  shows up in rustdoc, in compiler warnings, and in IDE tooltips.
- **Stability and experimental APIs**: prefix the docstring with
  a rustdoc admonition: `> **Experimental:** ...`. Do not invent
  custom badges.
- **Platform conditioning**: when an item is gated by `#[cfg(...)]`,
  use `#[doc(cfg(...))]` so rustdoc renders the platform marker.

A few formatting notes:

- When linking another mkit crate or module in a comment, prefer
  the relative intra-doc form (`` [`super::Foo`] ``,
  `` [`crate::pack::Header`] ``) over an absolute path.
- For subscripts and superscripts inside a docstring, use the
  custom Markdown syntax that rustdoc accepts:
  ```rust
  /// H~2~O — the hydrogen oxide molecule
  /// 21^st^ century
  ```
- The rustdoc inline `[link][name]` syntax works, but intra-doc
  `` [`name`] `` is preferred for cross-references inside the
  workspace.

## Accuracy

These are topics that often come up in mkit development and need
precise wording.

### Concurrency and parallelism

**Concurrency** describes two tasks that logically run together.
Two concurrent tasks may each start before the other finishes.

**Parallelism** describes two tasks that physically run at the
same time. Two network requests, two threads on two CPU cores, or
two BLAKE3 chunk hashes on two cores are examples of parallelism.

It is possible, and very common with Rust async, to have
concurrency without parallelism: two `async fn`s polled on the
same single-threaded executor run concurrently but not in
parallel. Spawning them onto a multi-threaded runtime (for
example, Tokio's default runtime) lets them also run in parallel,
provided they are `Send`.

BLAKE3 is itself parallelizable: chunks of a large input can be
hashed on multiple cores. The benches in
`benchmarks/charts/hashing-*.svg` reflect single-core throughput
unless the chart caption says otherwise.

### Futures and async

In Rust, the unit of async work is a **future**. A future is
either:

- **Pending** — the task has not produced a value yet.
- **Ready** — the executor will, on the next poll, observe the
  final value.

On the receiving side:

- A future is **completed** when its `poll` method returns
  `Poll::Ready(value)`.
- `await` on a future blocks the current async task until the
  future is ready, then yields the inner value.

On the producing side:

- A future produced by an `async fn` is **inert**: it does
  nothing until polled by an executor.
- Spawning a future onto an executor (for example,
  `tokio::spawn`) starts driving it concurrently with the current
  task.

For API documentation, the caller usually wants to know:

- What the future resolves to.
- What `Send`/`Sync` bounds it carries, if relevant.
- Whether cancelling the future (dropping it before completion)
  is safe and what state it leaves behind.

Typically write:

> Returns a future that resolves to the parsed [`Commit`].

Avoid:

> Returns a `Future<Output = Commit>`.

The signature already says that; the prose should say something
useful on top.

When `Result` is involved, document the error cases under a
`# Errors` section rather than embedding them in the description.

### URLs and URIs

Unless you have a specific reason to use "URI", use "URL"
everywhere. This follows the goals of the
[WHATWG URL specification](https://url.spec.whatwg.org/#goals).

In mkit, transports are identified by URLs of the form
`mkit+<scheme>://...`. Refer to the full string as a **transport
URL**, and to the part after `mkit+` as the **inner scheme**.

### Kilobytes (kB), kibibytes (kiB), and kilobits (kbit, kb)

- A kilobyte sometimes refers to 1,000 bytes (`kB`) and other
  times refers to 1,024 bytes. Be explicit.
- A kibibyte always refers to 1,024 bytes and is abbreviated as
  `kiB`.
- Most mkit APIs work with powers of two, like pack chunk sizes,
  BLAKE3 chunk sizes, and on-disk buffers. Write `kiB`, `MiB`, and
  `GiB` to communicate clearly to callers.
- Some APIs, especially those describing disk storage capacity or
  transmission rates, use powers of 10. Write `kB`, `MB`, and `GB`
  **and** be explicit that the number refers to 1,000 bytes,
  1,000,000 bytes, and so on.
- Typically, write `kbit`, `Mbit`, and `Gbit` when referring to
  bits to remove the ambiguity between bits and bytes. Both
  `kbit/s` and `kbps` are acceptable for rates.
- Always use a capital `B` for bytes. Write `bit` or a lowercase
  `b` for bits.
- Insert a space between the number and unit, like `10 MiB`.
- Decimal byte units: kB, MB, GB, TB
- Binary byte units: kiB, MiB, GiB, TiB
- Decimal bit units: kbit, Mbit, Gbit, Tbit
- Binary bit units: kibit, Mibit, Gibit, Tibit

### Hashes, keys, and signatures

Be precise when describing cryptographic primitives.

- **Hash function**: name it explicitly (BLAKE3, SHA-256). Do not
  say "a hash" when the algorithm matters.
- **Digest**: the output of a hash function over a specific input.
- **Key**: an Ed25519, secp256k1, or P-256 private or public key.
  Use "signing key" for the private half and "verifying key" for
  the public half.
- **Signature**: the output of a signing operation. A DSSE
  envelope may carry several signatures from several keys over the
  same payload.
- **Verification**: the operation that checks a signature against
  a verifying key and a payload. The result is a boolean; the
  function should return `Result<(), VerifyError>`, not `bool`,
  so the caller can distinguish "definitely invalid" from "could
  not verify".

### Doc comments

Use `///` for item-level doc comments and `//!` for
module/crate-level ones. Format docstrings to fit the column
width of the file at hand; for most mkit Rust sources that is
100 columns. The `rustfmt` configuration in `rust/rustfmt.toml`
governs the formatter; rustdoc itself does not reflow text.

Write descriptions in the third-person declarative, not the
second-person imperative.

- Correct: Hashes the given bytes with BLAKE3 and writes the
  resulting object to the object store.
- Incorrect: Hash the given bytes with BLAKE3 and write the
  resulting object to the object store.

Explain the behavior of a function beyond its parameters and
return value. Those are easy to read off the signature; what's
less clear is the failure modes, the side effects, the
preconditions, and the concurrency safety. Document the parts of
the iceberg below the surface.

Write parameter and field descriptions that teach the caller
something. If you have nothing useful to add, leave the field
undocumented and rely on the name and type. Quality beats
quantity.

```rust
pub struct CommitMeta {
    // CORRECT:
    /// Total uncompressed size, in bytes, of all trees and blobs
    /// reachable from this commit. Computed lazily by
    /// [`Commit::stats`]; cached after the first call.
    pub reachable_bytes: u64,

    // INCORRECT:
    /// Total size
    pub reachable_bytes: u64,

    // ACCEPTABLE WHEN THE NAME AND TYPE SUFFICE:
    pub reachable_bytes: u64,
}
```

Leave off a period if the description of a function, parameter,
or return value is a single phrase. Use periods when writing
multiple sentences.

Example:

```rust
/// Stages the file at `path` for the next commit and returns its
/// BLAKE3 digest. The file is hashed and written to the object
/// store immediately; the index is updated to point at the new
/// object.
///
/// If `path` is outside the working tree, this returns
/// [`StageError::OutsideWorkingTree`] and leaves the index
/// untouched.
///
/// # Errors
///
/// Returns an error if the file cannot be read, if it is a
/// symlink that resolves outside the working tree, or if writing
/// the object to the store fails.
///
/// # Examples
///
/// ```no_run
/// # use mkit_core::Repository;
/// # fn main() -> anyhow::Result<()> {
/// let repo = Repository::open(".")?;
/// let digest = repo.stage("README.md")?;
/// println!("staged {digest}");
/// # Ok(()) }
/// ```
pub fn stage(&self, path: &str) -> Result<Digest, StageError> { /* ... */ }
```

---

## References and additional resources

- See [CONTRIBUTING.md](../CONTRIBUTING.md) for the local-dev
  setup, the CI gates, and the review bar.
- See the `SPEC-*.md` files in this directory for the on-disk and
  wire formats; link to them from prose when defining a term.
- This guide is not exhaustive. For questions it does not cover,
  fall back to widely used industry references such as the
  [Google developer documentation style
  guide](https://developers.google.com/style?hl=en) and the
  [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
  for Rust-specific naming and documentation conventions.
- For general guidance on what words to avoid in technical and
  educational writing, see [Words to Avoid in Educational
  Writing](https://css-tricks.com/words-avoid-educational-writing/).
