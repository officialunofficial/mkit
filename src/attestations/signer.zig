// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Signer trait — uniform interface for producing a DSSE signature.
//
// See docs/SPEC-ATTESTATIONS.md §6.1. A `Signer` is handed the DSSE
// Pre-Authentication Encoding (PAE) bytes by the envelope builder and
// returns the raw signature bytes — `envelope.encode` base64-wraps them
// on the way into the final JSON.
//
// The trait deliberately says nothing about *how* a signer produces its
// signature. Concrete implementations:
//
//     signer_repo_key.zig    Ed25519 over `.mkit/keys/default.key`.
//     signer_external.zig    JSON-over-stdin/stdout to a caller-supplied
//                            subprocess.
//     signer_sigstore.zig    Scaffold — Fulcio keyless, not yet wired.
//
// Verification lives separately (see `verify.zig` in a later commit
// series) because the verifier often has no knowledge of how the
// signature was produced (e.g. for Sigstore keyless the verifier is a
// Fulcio cert chain, which no signer owns).

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Dynamic-dispatch Signer. One vtable, two calls. See module doc-comment.
pub const Signer = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Return an allocator-owned identifier that the verifier registry
        /// uses to look up this signer's trust root. Conventions in
        /// SPEC-ATTESTATIONS §6.3 (e.g. `"blake3:<hex>"` for repo-key).
        keyid: *const fn (ptr: *anyopaque, allocator: Allocator) anyerror![]u8,

        /// Sign the DSSE PAE. Returns raw signature bytes — envelope.encode
        /// base64-wraps them. Ed25519 sigs are 64 bytes; other schemes are
        /// variable-length.
        signDsse: *const fn (ptr: *anyopaque, allocator: Allocator, pae: []const u8) anyerror![]u8,
    };

    pub fn keyid(self: Signer, allocator: Allocator) anyerror![]u8 {
        return self.vtable.keyid(self.ptr, allocator);
    }

    pub fn signDsse(self: Signer, allocator: Allocator, pae: []const u8) anyerror![]u8 {
        return self.vtable.signDsse(self.ptr, allocator, pae);
    }
};

test {
    // Smoke test: the trait compiles and dispatches through the vtable.
    const Stub = struct {
        pub fn keyidImpl(_: *anyopaque, allocator: Allocator) anyerror![]u8 {
            return allocator.dupe(u8, "stub:keyid");
        }
        pub fn signImpl(_: *anyopaque, allocator: Allocator, pae: []const u8) anyerror![]u8 {
            return allocator.dupe(u8, pae);
        }
        const vt: Signer.VTable = .{ .keyid = keyidImpl, .signDsse = signImpl };
    };

    var marker: u8 = 0;
    const s: Signer = .{ .ptr = @ptrCast(&marker), .vtable = &Stub.vt };

    const allocator = std.testing.allocator;

    const kid = try s.keyid(allocator);
    defer allocator.free(kid);
    try std.testing.expectEqualStrings("stub:keyid", kid);

    const sig = try s.signDsse(allocator, "DSSEv1 4 test 2 ok");
    defer allocator.free(sig);
    try std.testing.expectEqualStrings("DSSEv1 4 test 2 ok", sig);
}
