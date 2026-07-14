#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Independent reference verifier for a DSSE envelope (see
# https://github.com/secure-systems-lab/dsse/blob/master/envelope.md),
# written from the spec using only the widely-used `cryptography` package
# — deliberately NOT any mkit code, and a different language ecosystem
# than mkit-attest's own Rust implementation. The point is to catch a
# shared misunderstanding of the DSSE spec (PAE construction, signed-bytes
# boundary) that a second Rust verifier using the same mental model as the
# signer wouldn't necessarily catch.
#
# Ed25519 only — matches the `algo-ed25519` golden vectors this is meant
# to cross-check (rust/crates/mkit-attest/tests/dsse_roundtrip.rs,
# golden_attest.rs).
#
# Usage:
#   python3 verify-dsse-envelope.py <envelope.json> <pubkey-hex>
#
# Exit 0 and prints "OK" if every signature in the envelope verifies
# against the given Ed25519 public key over the DSSE PAE. Exit 1 and
# prints a reason otherwise (missing dependency, bad envelope, signature
# mismatch).

import base64
import json
import sys


def pae(payload_type: bytes, payload: bytes) -> bytes:
    # DSSE Pre-Authentication Encoding:
    #   "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
    # LEN is the ASCII-decimal encoding of the byte length. SP is a
    # single 0x20 byte.
    return (
        b"DSSEv1 "
        + str(len(payload_type)).encode("ascii")
        + b" "
        + payload_type
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <envelope.json> <pubkey-hex>", file=sys.stderr)
        return 2

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError:
        print(
            "verify-dsse-envelope: the 'cryptography' package is not installed "
            "(pip install cryptography)",
            file=sys.stderr,
        )
        return 1

    envelope_path, pubkey_hex = sys.argv[1], sys.argv[2]

    with open(envelope_path, "rb") as f:
        envelope = json.load(f)

    payload_type = envelope["payloadType"].encode("utf-8")
    payload = base64.b64decode(envelope["payload"])
    signatures = envelope["signatures"]
    if not signatures:
        print("verify-dsse-envelope: envelope has no signatures", file=sys.stderr)
        return 1

    signed_bytes = pae(payload_type, payload)
    pubkey = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))

    for sig_entry in signatures:
        sig = base64.b64decode(sig_entry["sig"])
        try:
            pubkey.verify(sig, signed_bytes)
        except InvalidSignature:
            print(
                f"verify-dsse-envelope: signature from keyid "
                f"{sig_entry.get('keyid', '<none>')} does NOT verify",
                file=sys.stderr,
            )
            return 1

    print(f"OK: {len(signatures)} signature(s) verified over {len(payload)} payload byte(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
