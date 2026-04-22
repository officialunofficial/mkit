# Notary — Library Extension Point

The `Notary` trait in `src/notary.zig` is a generic abstraction for witnessing
or attesting to an mkit push (a batch of commits plus a ref update). Core mkit
ships only `NullNotary` — a deterministic, no-op default. Downstream consumers
that depend on mkit as a Zig library provide their own `Notary` implementation.

The public `mkit` binary does NOT expose a notary surface in its CLI. There
are no notary-related flags, no notary config keys, and no notary-related
subcommands. This trait exists purely as a library extension point.

## Scope

A `Notary` is asked to do three things:

1. **Create a project** — mint an opaque 32-byte `ProjectId` from a human
   `ProjectSpec` (name, optional description, optional license).
2. **Attest** — witness a push described by `AttestInput` (commits + ref
   update + content digest + optional URL) and return an opaque `Receipt`.
3. **Verify a receipt** — determine whether a receipt previously produced by
   this notary (or a compatible peer) is still accepted as valid.

The trait is intentionally narrow. The notary decides how a `Receipt` is
structured, how `createProject` hashes its input, and what "valid" means for
`verifyReceipt`.

## VTable

`Notary` is a `*anyopaque` + `*const VTable` pair:

```zig
pub const Notary = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        attest: *const fn (*anyopaque, Allocator, AttestInput) anyerror!Receipt,
        verifyReceipt: *const fn (*anyopaque, Allocator, Receipt) anyerror!bool,
        createProject: *const fn (*anyopaque, Allocator, ProjectSpec) anyerror!ProjectId,
    };
};
```

Methods on `Notary` forward through the vtable, so call sites are identical
regardless of the concrete backend:

```zig
const receipt = try notary.attest(allocator, input);
defer receipt.deinit();
```

## Types

```zig
pub const ProjectId = [32]u8;

pub const ProjectSpec = struct {
    name: []const u8,
    description: []const u8 = "",
    license: []const u8 = "",
};

pub const CommitMeta = struct {
    hash: Hash,
    parents: []const Hash,
    tree_root: Hash,
    author: []const u8,   // opaque identity bytes
    author_timestamp: u64,
    title: []const u8,
    message_hash: Hash,
};

pub const RefUpdate = struct {
    project_id: Hash,
    ref_name: []const u8,
    old_hash: ?Hash,
    new_hash: Hash,
};

pub const AttestInput = struct {
    commits: []const CommitMeta,
    ref_update: RefUpdate,
    project_id: ProjectId,
    content_digest: ?Hash = null,
    url: []const u8 = "",
};

pub const Receipt = struct {
    bytes: []const u8,
    allocator: ?Allocator = null,

    pub fn deinit(self: *Receipt) void { ... }
};
```

`Hash` is the 32-byte BLAKE3 hash type from `src/hash.zig`. `CommitMeta.author`
is opaque bytes — each notary decides how to interpret an author identity.

## Method semantics

### `attest(allocator, input) !Receipt`

Witness a push. The notary may publish `input` to an external system, sign
it, write it to a local log, or ignore it entirely. The returned `Receipt`
holds bytes owned by `allocator` (when `receipt.allocator` is non-null);
callers MUST call `receipt.deinit()`.

Errors are propagated to the caller via `anyerror`. A notary that can fail for
domain reasons (rejected by a remote, connection lost, duplicate submission)
should define its own error set and document it separately.

### `verifyReceipt(allocator, receipt) !bool`

Given bytes previously returned by the same notary (or a compatible peer),
return `true` if the receipt is still considered valid. The function is free
to reach out to the network, check a local log, or decode the bytes purely
offline — that is an implementation detail.

`allocator` is supplied so the verifier can allocate scratch space; the
receipt bytes themselves are borrowed.

### `createProject(allocator, spec) !ProjectId`

Mint a 32-byte project identifier. Implementations should be deterministic on
`spec.name` when possible so that the same spec always yields the same id;
beyond that, the derivation is backend-specific.

## `NullNotary`

`NullNotary` is the default backend baked into mkit core. Its behavior:

- `attest` returns an empty `Receipt` (zero bytes).
- `verifyReceipt` returns `true` iff the receipt is empty.
- `createProject` returns `BLAKE3(spec.name)`.

Construct it with `NullNotary.init()`. It owns no heap state and needs no
`deinit`. It is safe to keep as a `comptime` singleton.

## Implementing a custom notary

1. Define a backing struct (any layout you like; it will be referred to by
   `*anyopaque`).
2. Write three free functions matching the vtable signatures. Cast the opaque
   pointer back to your struct at entry.
3. Expose a constructor (typically `init(...) Notary`) that returns a `Notary`
   wrapping a pointer to your struct and a `*const VTable` with your three
   functions.
4. Document your `Receipt` byte layout so peers can round-trip it.

Example vtable shape:

```zig
const MyNotary = struct {
    // ... your fields ...

    const vtable: Notary.VTable = .{
        .attest = attestImpl,
        .verifyReceipt = verifyReceiptImpl,
        .createProject = createProjectImpl,
    };

    pub fn init(self: *MyNotary) Notary {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    fn attestImpl(ptr: *anyopaque, allocator: Allocator, input: AttestInput) !Receipt {
        const self: *MyNotary = @ptrCast(@alignCast(ptr));
        _ = self; _ = allocator; _ = input;
        // ... your logic ...
        return .{ .bytes = &.{}, .allocator = null };
    }

    fn verifyReceiptImpl(ptr: *anyopaque, allocator: Allocator, receipt: Receipt) !bool {
        _ = ptr; _ = allocator; _ = receipt;
        return true;
    }

    fn createProjectImpl(ptr: *anyopaque, allocator: Allocator, spec: ProjectSpec) !ProjectId {
        _ = ptr; _ = allocator; _ = spec;
        return [_]u8{0} ** 32;
    }
};
```

## Stability

The trait, its types, and `NullNotary` are considered stable within a minor
release of mkit. Additive, backward-compatible changes (new optional fields
on `AttestInput`, new helper types) may appear in minor releases; the
existing vtable signatures will not change without a major bump.
