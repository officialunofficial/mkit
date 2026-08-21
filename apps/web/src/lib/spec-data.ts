/**
 * Static spec-index data — the single source of truth for the categorized specification list rendered at `/specs`.
 * Names and `status` tokens mirror each document's YAML front matter in `docs/specs/SPEC-*.md` verbatim; descriptions
 * are one-line summaries of the document body written for this page. When a spec is added, renamed, or changes status,
 * update the matching entry here (and `docs/specs/README.md`).
 */

/**
 * The `status` front-matter token, verbatim. Per SPEC-CONVENTIONS §2 it combines a maturity axis (`draft` / `stable`)
 * with a bindingness axis (`normative` / `advisory`); a bare token states one axis only.
 */
export type SpecStatus = 'draft' | 'draft-normative' | 'normative' | 'stable' | 'stable-advisory' | 'stable-normative'

export type SpecItem = {
  /** Document name without the `.md` extension, rendered in mono and linked to the file on GitHub. */
  name: string
  status: SpecStatus
  /** One-line, user-facing summary of what the document pins down. */
  description: string
}

export type SpecCategory = {
  name: string
  /** One-line framing shown under the category heading. */
  blurb: string
  items: SpecItem[]
}

export const SPECS_DIR_URL = 'https://github.com/officialunofficial/mkit/tree/main/docs/specs'

/** GitHub URL of one spec document. */
export function specUrl(name: string): string {
  return `https://github.com/officialunofficial/mkit/blob/main/docs/specs/${name}.md`
}

export const categories: SpecCategory[] = [
  {
    name: 'Objects and Hashing',
    blurb: 'How bytes become content-addressed objects: layouts, Merkle identity, chunking, and deltas.',
    items: [
      {
        name: 'SPEC-OBJECTS',
        status: 'stable',
        description:
          'The on-disk byte layout of every object type (blob, tree, commit, remix, chunked blob, delta, tag) over 32-byte BLAKE3 IDs. External tools can produce and consume these bytes from this document alone.',
      },
      {
        name: 'SPEC-MERKLE-OBJECTS',
        status: 'stable-normative',
        description:
          'The Binary Merkle Tree construction behind tree and chunked-blob object IDs: a matching root proves every child present and correctly ordered.',
      },
      {
        name: 'SPEC-FASTCDC',
        status: 'stable',
        description:
          'Deterministic content-defined chunking for large files: the gear table, chunking parameters, and the contract that keeps chunked-blob hashes identical across producers.',
      },
      {
        name: 'SPEC-DELTA',
        status: 'stable',
        description:
          'The byte layout of the delta instruction stream inside packfile delta entries, with a version byte so readers reject streams they do not understand.',
      },
    ],
  },
  {
    name: 'Repository State',
    blurb: 'What lives inside .mkit/: refs, the staging index, linked worktrees, lock order, and garbage collection.',
    items: [
      {
        name: 'SPEC-REFS',
        status: 'draft',
        description:
          'Ref names, the 65-byte ref wire format, on-disk storage, and the exact semantics of prefix listing and conditional (compare-and-swap) updates across transports.',
      },
      {
        name: 'SPEC-INDEX',
        status: 'stable-advisory',
        description:
          'The on-disk layout of the staging area: paths staged for the next commit, plus a stat cache that proves a worktree file unchanged without rereading it. Local-only, never exchanged between peers.',
      },
      {
        name: 'SPEC-WORKTREE',
        status: 'draft-normative',
        description:
          'Linked working trees: the split between shared and per-tree state, pointer files, the worktree registry, repository discovery, and cross-worktree locking.',
      },
      {
        name: 'SPEC-CONCURRENCY',
        status: 'draft-normative',
        description:
          'The one total acquisition order across every lock an mkit process takes, so two processes can never grab the same two locks in opposite order.',
      },
      {
        name: 'SPEC-GC',
        status: 'stable-normative',
        description:
          'Garbage collection and recovery: the complete retention-root set that makes pruning safe, and the recovery log that keeps amended or reset tips reachable for a grace period.',
      },
    ],
  },
  {
    name: 'Packs and Transport',
    blurb:
      'How objects move between repositories: the packfile container, erasure-coded delivery, and the transport protocols.',
    items: [
      {
        name: 'SPEC-PACKFILE',
        status: 'stable',
        description:
          'The packfile container for object exchange (v1 and v2): header framing, entry types, per-entry zstd compression, and a BLAKE3 trailer as defense against bit rot.',
      },
      {
        name: 'SPEC-PACK-SHARDS',
        status: 'stable-normative',
        description:
          'Reed-Solomon erasure coding over pack delivery: any N of N plus K shards reconstruct the pack, so lossy networks and partial caches still complete a transfer.',
      },
      {
        name: 'SPEC-TRANSPORT',
        status: 'stable-normative',
        description:
          'The cross-transport contract for the verbs every transport implements (memory, file, HTTP, S3, SSH): URL parsing, authentication, size caps, retry policy, and the error taxonomy.',
      },
      {
        name: 'SPEC-TRANSPORT-CONNECT',
        status: 'draft-normative',
        description:
          'The mkit.transport.v1 Connect service, the canonical remote protocol behind mkit+https: proto shape, verb-to-trait mapping, compare-and-swap semantics, and streaming pack transfer.',
      },
      {
        name: 'SPEC-TRANSPORT-ENC',
        status: 'draft',
        description:
          'A self-contained encrypted transport (mkit+enc) that exchanges the same frames as the SSH transport over an authenticated, encrypted TCP stream instead of an ssh child process.',
      },
      {
        name: 'SPEC-SPARSE-CHECKOUT',
        status: 'draft',
        description:
          'Verifiable server-side sparse checkout over HTTP and S3: the server ships only the requested subtree, and proofs let the client tell "filtered as asked" from "withheld".',
      },
    ],
  },
  {
    name: 'Security and Signing',
    blurb:
      'The signature and attestation machinery: signing bytes, key storage, config trust boundaries, and verifiable history.',
    items: [
      {
        name: 'SPEC-SIGNING',
        status: 'stable-normative',
        description:
          'The exact bytes an Ed25519 signature covers on a commit, remix, or tag, and the BLAKE3 domain separation that stops a signature in one domain from validating in another.',
      },
      {
        name: 'SPEC-KEYSTORE',
        status: 'stable-normative',
        description:
          'The signing-key vault behind mkit key: software, OS-native, and hardware-backed storage under one interface, with honest capability reporting throughout.',
      },
      {
        name: 'SPEC-CONFIG-SECURITY',
        status: 'normative',
        description:
          'The repo-vs-user config trust split: which keys a cloned repository may set and which stay user-only, so a hostile repo never reaches your signing identity or credentials.',
      },
      {
        name: 'SPEC-ATTESTATIONS',
        status: 'draft',
        description:
          'Native attestations as in-toto v1 Statements in DSSE envelopes: on-disk layout, wire envelope, signing contract, and CLI. Off-the-shelf in-toto tooling can consume the signed bytes.',
      },
      {
        name: 'SPEC-RELEASE-THRESHOLD',
        status: 'draft-normative',
        description:
          'BLS12-381 threshold signatures for releases: M-of-N maintainer shares recover a single signature that verifiers check against one aggregated public key.',
      },
      {
        name: 'SPEC-HISTORY-PROOF',
        status: 'draft-normative',
        description:
          'An append-only Merkle Mountain Range over each branch, with inclusion proofs so a light client verifies that a commit belongs to a branch without walking its history.',
      },
    ],
  },
  {
    name: 'Interop and Subprocess Protocols',
    blurb:
      'The wire contracts mkit speaks with other systems: git bridges in both directions, external signers, and the shared RPC framing.',
    items: [
      {
        name: 'SPEC-GIT-BRIDGE',
        status: 'draft-normative',
        description:
          'Deterministic mkit-to-git export: any two implementations translating the same history produce byte-identical git objects, with mkit-only fields carried in commit headers.',
      },
      {
        name: 'SPEC-GIT-IMPORT',
        status: 'draft-normative',
        description:
          'Importer-signed git-to-mkit translation: every imported commit is a new object signed by the importer, attributing the original author and binding the git bytes as provenance.',
      },
      {
        name: 'SPEC-EXTERNAL-SIGNER',
        status: 'draft',
        description:
          'The subprocess protocol for out-of-process signers (HSM, Secure Enclave, TPM, WebAuthn): invocation, capability discovery, authentication round-trips, and error semantics.',
      },
      {
        name: 'SPEC-RPC',
        status: 'stable-normative',
        description:
          'The length-prefixed protobuf framing shared by every mkit subprocess protocol; external signers and the SSH transport speak the same wire.',
      },
    ],
  },
  {
    name: 'Spec Conventions',
    blurb: 'How the corpus itself is written and read.',
    items: [
      {
        name: 'SPEC-CONVENTIONS',
        status: 'stable-normative',
        description:
          'Shared vocabulary for the corpus: RFC 2119 keywords, the status tokens shown on this page, wire-encoding notation, and golden-vector citation rules.',
      },
    ],
  },
]
