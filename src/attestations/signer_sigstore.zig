// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Not yet implemented. Will wrap Fulcio OIDC + Rekor. Tracked in
// docs/SPEC-ATTESTATIONS.md §6.2.
//
// The scaffold exists so the signer router in `mod.zig` can dispatch on
// signer kind and get a concrete `error.SigstoreNotImplemented` back
// instead of a compile-time branch.

const std = @import("std");
const Allocator = std.mem.Allocator;

const signer_mod = @import("signer.zig");
const Signer = signer_mod.Signer;

pub const SigstoreSigner = struct {
    pub fn init() SigstoreSigner {
        return .{};
    }

    pub fn asSigner(self: *SigstoreSigner) Signer {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    const vtable: Signer.VTable = .{
        .keyid = keyidImpl,
        .signDsse = signDsseImpl,
    };

    fn keyidImpl(_: *anyopaque, _: Allocator) anyerror![]u8 {
        return error.SigstoreNotImplemented;
    }

    fn signDsseImpl(_: *anyopaque, _: Allocator, _: []const u8) anyerror![]u8 {
        return error.SigstoreNotImplemented;
    }
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const testing = std.testing;

test "sigstore signer: both vtable methods return SigstoreNotImplemented" {
    var ss = SigstoreSigner.init();
    const s = ss.asSigner();

    try testing.expectError(error.SigstoreNotImplemented, s.keyid(testing.allocator));
    try testing.expectError(error.SigstoreNotImplemented, s.signDsse(testing.allocator, "pae"));
}
