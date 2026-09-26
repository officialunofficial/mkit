#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Independent reference check of the grant codec and verifier golden
# vectors (SPEC-WRITE-GRANTS §3, §4, §4.2, §5.1-§5.2, §7, §9.1;
# SPEC-TRANSPORT-CONNECT §7.4):
#   rust/tests/golden/grants/grant-statements.json
#   rust/tests/golden/grants/headers.json
#   rust/tests/golden/grants/{grant,epoch,visibility}-ed25519.json
#   rust/tests/golden/grants/{secp256k1-eip191,webauthn-p256}.json
#   rust/tests/golden/grants/reject/*.json (reject/verify-*: verification)
#   rust/tests/golden/grants/MANIFEST.txt
#
# Everything here is written from the spec text and shares no code with the
# Rust crates:
#   * a statement builder: join the eleven §3.2 fields with "\n", lists in
#     ascending byte order, canonical decimals;
#   * a validator that names the first §3.5 rule a statement breaks, with the
#     §7.4 identity grammar, the SPEC-REFS §3 ref-name grammar and the auth v2
#     origin rules (SPEC-WRITE-GRANTS §3.2) re-implemented here;
#   * the §4.2 header built with base64.urlsafe_b64encode(x).rstrip(b"=");
#   * BLAKE3 from the pure-Python transcription in blake3_subtree_ref.py
#     (WP-1.3), checked against `b3sum` (the official CLI) unless --no-b3sum;
#   * the signed fixtures: each epoch and visibility statement rebuilt from
#     its §5.1/§9.1 fields, every statement re-signed from the owner seed with
#     pycryptodome's RFC 8032 Ed25519 over BLAKE3(statement) (deterministic,
#     so signature and header bytes must be equal), and every accept, reject
#     and reject/verify-* context re-run through a stateless verifier written
#     here from §4, §5.2, §7 and §9.1. Signatures are checked with the
#     SPEC-SIGNING §1 strict predicate: canonical, non-small-order A and R
#     and S < L are enforced here, because pycryptodome's RFC 8032 verify
#     alone accepts, for example, the identity key with R = identity, s = 0.
#   * the ECDSA owner schemes (§4, §4.1, §4.3, §4.4), written from the spec
#     with other libraries than the Rust code uses:
#       - secp256k1-eip191: Keccak-256 from pycryptodome
#         (Crypto.Hash.keccak); public-key recovery written from SEC 1
#         §4.1.6 over python-ecdsa's curve arithmetic, cross-checked
#         against python-ecdsa's own from_public_key_recovery_with_digest
#         and verify_digest; statements re-signed with python-ecdsa's
#         RFC 6979 sign_digest_deterministic (HMAC-SHA-256) and low-s
#         normalization, which must give the fixture's bytes;
#       - webauthn-p256: points built with pycryptodome ECC.construct
#         (coordinates checked < p first), signatures verified with DSS
#         fips-186-3 and re-signed with DSS deterministic-rfc6979 then
#         normalized to low s; the §4.3 client-data rules with Python's
#         json module (object_pairs_hook for duplicate names at any depth,
#         parse_constant refusing NaN/Infinity, strict UTF-8, no unpaired
#         surrogate).
#     Self-tests: the web3.js "Some data" EIP-191 vector and the RFC 6979
#     §A.2.5 P-256/SHA-256 "sample" vector.
#
# The reject vectors are authored by the CASES table below: each case edits
# one field of the §3.4 example so that it breaks exactly one §3.5 rule, and
# names that rule and the expected `GrantError::reason`. `--write-rejects`
# (re)writes reject/*.json (other than reject/verify-*, which the Rust
# golden writer signs) from the table; the check mode asserts every file
# still equals its case, that the validator here rejects it for the stated
# rule, and prints the table.
#
# Usage:
#   python3 scripts/golden/grants_ref.py rust/tests/golden/grants [--no-b3sum]
#   python3 scripts/golden/grants_ref.py rust/tests/golden/grants --write-rejects
#
# Exit 0 and print "OK" when every check passes.

import argparse
import base64
import hashlib
import importlib.util
import ipaddress
import json
import math
import os
import re
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True  # keep scripts/golden free of __pycache__

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "blake3_subtree_ref", os.path.join(HERE, "blake3_subtree_ref.py")
)
_b3 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_b3)
blake3 = _b3.blake3

# §1.1 protocol constants.
GRANT_MAX_LIFETIME_MS = 2_592_000_000
MAX_AUDIENCES = 8
MAX_REF_SCOPES = 16
MAX_STATEMENT_BYTES = 4096
MAX_GRANT_HEADER_BYTES = 8192
DOMAIN = "mkit-write-grant:v1"
DOMAIN_EPOCH = "mkit-write-epoch:v1"
DOMAIN_VISIBILITY = "mkit-repo-visibility:v1"
EPOCH_STATEMENT_MAX_LIFETIME_MS = 2_592_000_000
MAX_EPOCH_STEP = 1024
MAX_CLOCK_LEAD_MS = 30_000
SCHEMES = ("ed25519", "secp256k1-eip191", "webauthn-p256")
U64_MAX = 2**64 - 1
I64_MAX = 2**63 - 1

# SPEC-TRANSPORT-CONNECT §7.4.
NAMESPACE_RE = re.compile(r"(ed25519-[0-9a-f]{64}|0x[0-9a-f]{40})\Z")
NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,99}\Z")
IDENTITY_RE = re.compile(
    r"(ed25519-[0-9a-f]{64}|0x[0-9a-f]{40})/[a-z0-9][a-z0-9._-]{0,99}\Z")
HEX64_RE = re.compile(r"[0-9a-f]{64}\Z")
DECIMAL_RE = re.compile(r"(0|[1-9][0-9]*)\Z")


class Reject(Exception):
    pass


def ref_name_ok(name):
    """SPEC-REFS §3."""
    if not name or name.startswith("/"):
        return False
    segments = name.split("/")
    for seg in segments:
        if not seg or seg.startswith(".") or seg.endswith(".lock"):
            return False
        if not re.fullmatch(r"[A-Za-z0-9._-]+", seg):
            return False
    return segments[-1] != "HEAD"


def origin_ok(origin):
    """Auth v2 audience rules as SPEC-WRITE-GRANTS §3.2 states them: a
    lowercase http:// or https:// origin, no userinfo, path, query, fragment,
    trailing dot or default port."""
    if len(origin) > 512 or any(not 0x21 <= ord(c) <= 0x7E for c in origin):
        return False
    for scheme, default in (("https://", "443"), ("http://", "80")):
        if origin.startswith(scheme):
            rest = origin[len(scheme):]
            break
    else:
        return False
    if not rest or rest != rest.lower() or any(c in rest for c in "/?#@\\"):
        return False
    if rest.startswith("["):
        end = rest.find("]")
        if end < 0:
            return False
        try:
            ipaddress.IPv6Address(rest[1:end])
        except ValueError:
            return False
        if "%" in rest[1:end]:
            return False
        tail = rest[end + 1:]
        if tail and not tail.startswith(":"):
            return False
        port = tail[1:] if tail else None
    else:
        host, sep, port = rest.partition(":")
        port = port if sep else None
        if not host or host.endswith(".") or not re.fullmatch(r"[a-z0-9.-]+", host):
            return False
    if port is not None:
        if not DECIMAL_RE.match(port) or not 1 <= int(port) <= 65535 or port == default:
            return False
    return True


def decimal(text, maximum):
    if not DECIMAL_RE.match(text):
        raise Reject("noncanonical decimal")
    value = int(text)
    if value > maximum:
        raise Reject("decimal out of range")
    return value


def hex64(text):
    if not HEX64_RE.match(text):
        raise Reject("noncanonical hex")
    return text


def validate_flags(flags):
    if not flags:
        raise Reject("noncanonical ref flags")
    for c in flags:
        if c not in "cufd":
            raise Reject("unknown ref flag")
    if "".join(c for c in "cufd" if c in flags) != flags:
        raise Reject("noncanonical ref flags")  # out of order or repeated


def validate_pattern(pattern):
    base = pattern[:-2] if pattern.endswith("/*") else pattern
    if not ref_name_ok(base):
        raise Reject("ref pattern")
    if pattern.startswith("refs/mkit/packmap/"):
        raise Reject("packmap pattern")


def validate_ref_scopes(capabilities, field):
    if capabilities == "read":
        if field != "-":
            raise Reject("ref scopes on read grant")
        return
    if field == "-":
        raise Reject("ref scopes missing")
    entries = field.split(";")
    if len(entries) > MAX_REF_SCOPES:
        raise Reject("ref scope count")
    patterns = []
    for entry in entries:
        if "=" not in entry:
            raise Reject("ref pattern")
        pattern, flags = entry.split("=", 1)
        validate_pattern(pattern)
        validate_flags(flags)
        patterns.append(pattern)
    raw = [e.encode() for e in entries]
    if any(a >= b for a, b in zip(raw, raw[1:])):
        raise Reject("ref scopes unordered")
    if len(set(patterns)) != len(patterns):
        raise Reject("duplicate ref pattern")


def validate_audiences(field):
    if "*" in field:
        raise Reject("audience wildcard")
    items = field.split(",")
    if len(items) > MAX_AUDIENCES:
        raise Reject("audience count")
    if not all(origin_ok(a) for a in items):
        raise Reject("audience")
    raw = [a.encode() for a in items]
    if any(a >= b for a, b in zip(raw, raw[1:])):
        raise Reject("audiences unordered")


def validate_grant(statement):
    """Return None if `statement` (bytes) is a canonical grant, otherwise the
    reason of the first §3.5 rule it breaks."""
    try:
        if len(statement) > MAX_STATEMENT_BYTES:
            raise Reject("statement too long")
        for b in statement:
            if b == 0x0D:
                raise Reject("carriage return")
            if b != 0x0A and not 0x21 <= b <= 0x7E:
                raise Reject("byte out of range")
        if statement.endswith(b"\n"):
            raise Reject("final line feed")
        f = statement.decode("ascii").split("\n")
        if len(f) != 11:
            raise Reject("field count")
        if "" in f:
            raise Reject("empty field")
        if f[0] != DOMAIN:
            raise Reject("domain")
        if not NAMESPACE_RE.match(f[1]):
            raise Reject("namespace")
        scope_ns, slash, scope_name = f[2].partition("/")
        if not slash or not NAMESPACE_RE.match(scope_ns):
            raise Reject("repository scope")
        if scope_name != "*" and not NAME_RE.match(scope_name):
            raise Reject("repository scope")
        if scope_ns != f[1]:
            raise Reject("scope namespace mismatch")
        hex64(f[3])
        if f[4] not in ("read", "read,write", "write"):
            raise Reject("capabilities")
        validate_audiences(f[5])
        validate_ref_scopes(f[4], f[6])
        decimal(f[7], U64_MAX)
        created = decimal(f[8], I64_MAX)
        expiry = decimal(f[9], I64_MAX)
        hex64(f[10])
        if expiry <= created:
            raise Reject("expiry not after created")
        if expiry - created > GRANT_MAX_LIFETIME_MS:
            raise Reject("lifetime too long")
    except Reject as r:
        return str(r)
    return None


def split_statement(statement, count):
    """The §3.1 byte rules and field count shared by every statement."""
    if len(statement) > MAX_STATEMENT_BYTES:
        raise Reject("statement too long")
    for b in statement:
        if b == 0x0D:
            raise Reject("carriage return")
        if b != 0x0A and not 0x21 <= b <= 0x7E:
            raise Reject("byte out of range")
    if statement.endswith(b"\n"):
        raise Reject("final line feed")
    f = statement.decode("ascii").split("\n")
    if len(f) != count:
        raise Reject("field count")
    if "" in f:
        raise Reject("empty field")
    return f


def timestamps(created_text, expiry_text):
    created = decimal(created_text, I64_MAX)
    expiry = decimal(expiry_text, I64_MAX)
    return created, expiry


def validate_epoch(statement):
    """None if `statement` is a canonical §5.1 epoch statement, else the
    reason of the first rule it breaks (the §3.5 rules, seven fields)."""
    try:
        f = split_statement(statement, 7)
        if f[0] != DOMAIN_EPOCH:
            raise Reject("domain")
        if not NAMESPACE_RE.match(f[1]):
            raise Reject("namespace")
        decimal(f[2], U64_MAX)
        validate_audiences(f[3])
        created, expiry = timestamps(f[4], f[5])
        hex64(f[6])
        if expiry <= created:
            raise Reject("expiry not after created")
        if expiry - created > EPOCH_STATEMENT_MAX_LIFETIME_MS:
            raise Reject("lifetime too long")
    except Reject as r:
        return str(r)
    return None


def validate_visibility(statement):
    """None if `statement` is a canonical §9.1 visibility statement, else the
    reason of the first rule it breaks."""
    try:
        f = split_statement(statement, 7)
        if f[0] != DOMAIN_VISIBILITY:
            raise Reject("domain")
        if not IDENTITY_RE.match(f[1]):
            raise Reject("repository")
        if f[2] not in ("public", "private"):
            raise Reject("visibility")
        validate_audiences(f[3])
        created, expiry = timestamps(f[4], f[5])
        hex64(f[6])
        if expiry <= created:
            raise Reject("expiry not after created")
        if expiry - created > EPOCH_STATEMENT_MAX_LIFETIME_MS:
            raise Reject("lifetime too long")
    except Reject as r:
        return str(r)
    return None


def build_epoch(fields):
    """§5.1: seven fields joined by "\n", audiences in ascending byte order."""
    return "\n".join([
        DOMAIN_EPOCH,
        fields["namespace"],
        str(int(fields["new_epoch"])),
        ",".join(sorted(fields["audiences"], key=str.encode)),
        str(int(fields["created"])),
        str(int(fields["expiry"])),
        fields["nonce"],
    ]).encode("ascii")


def build_visibility(fields):
    """§9.1: seven fields joined by "\n", audiences in ascending byte order."""
    return "\n".join([
        DOMAIN_VISIBILITY,
        fields["repository"],
        fields["visibility"],
        ",".join(sorted(fields["audiences"], key=str.encode)),
        str(int(fields["created"])),
        str(int(fields["expiry"])),
        fields["nonce"],
    ]).encode("ascii")


def build_statement(fields):
    """Build a grant from a field dict using only the §3.1/§3.2 text rules."""
    audiences = sorted(fields["audiences"], key=str.encode)
    assert len(set(audiences)) == len(audiences)
    if fields["ref_scopes"] is None:
        ref_scopes = "-"
    else:
        entries = [f"{p}={flags}" for p, flags in fields["ref_scopes"]]
        ref_scopes = ";".join(sorted(entries, key=str.encode))
    lines = [
        DOMAIN,
        fields["namespace"],
        fields["scope"],
        fields["grantee"],
        fields["capabilities"],
        ",".join(audiences),
        ref_scopes,
        str(int(fields["epoch"])),
        str(int(fields["created"])),
        str(int(fields["expiry"])),
        fields["nonce"],
    ]
    return "\n".join(lines).encode("ascii")


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64_canonical(segment):
    if not re.fullmatch(r"[A-Za-z0-9_-]+", segment) or len(segment) % 4 == 1:
        return False
    decoded = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    return b64url(decoded) == segment  # rejects non-zero trailing bits


def validate_header(value):
    if len(value.encode()) > MAX_GRANT_HEADER_BYTES:
        return "header too long"
    parts = value.split(".")
    if len(parts) != 3 or "" in parts:
        return "header format"
    if parts[1] not in SCHEMES:
        return "unknown scheme"
    if not (b64_canonical(parts[0]) and b64_canonical(parts[2])):
        return "header base64"
    return None


# ---------------------------------------------------------------------------
# Owner signatures (§4, ed25519 only) and the stateless verifier (§5.2 checks
# 1-5, §7 steps 1-10, §9.1), written from the spec text.


def eddsa_module():
    try:
        from Crypto.Signature import eddsa  # pycryptodome
    except ImportError:
        sys.exit("FAIL: pycryptodome not found (pip install pycryptodome)")
    return eddsa


def ed25519_public(seed):
    return eddsa_module().import_private_key(seed).public_key().export_key(format="raw")


def ed25519_sign(seed, statement):
    """§4 ed25519: RFC 8032 Ed25519 over the 32-byte BLAKE3 of the statement."""
    eddsa = eddsa_module()
    return eddsa.new(eddsa.import_private_key(seed), "rfc8032").sign(blake3(statement))


# Ed25519 arithmetic (RFC 8032 §5.1) for the SPEC-SIGNING §1 checks 1-3,
# which RFC 8032 leaves optional and pycryptodome does not enforce.
ED_P = 2**255 - 19
ED_L = 2**252 + 27742317777372353535851937790883648493
ED_D = -121665 * pow(121666, ED_P - 2, ED_P) % ED_P
ED_SQRT_M1 = pow(2, (ED_P - 1) // 4, ED_P)
ED_IDENTITY = (0, 1)


def ed_decode(encoded):
    """RFC 8032 §5.1.3 point decoding with the canonical rule of
    SPEC-SIGNING §1 check 1 (y < p, and no x = 0 with the sign bit set).
    None if the encoding is not a canonical curve point."""
    y = int.from_bytes(encoded, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    if y >= ED_P:
        return None
    x2 = (y * y - 1) * pow(ED_D * y * y + 1, ED_P - 2, ED_P) % ED_P
    x = pow(x2, (ED_P + 3) // 8, ED_P)
    if (x * x - x2) % ED_P:
        x = x * ED_SQRT_M1 % ED_P
    if (x * x - x2) % ED_P:
        return None
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = ED_P - x
    return (x, y)


def ed_add(p1, p2):
    """Affine twisted Edwards addition (a = -1); complete on Ed25519."""
    (x1, y1), (x2, y2) = p1, p2
    t = ED_D * x1 * x2 * y1 * y2 % ED_P
    x3 = (x1 * y2 + x2 * y1) * pow(1 + t, ED_P - 2, ED_P) % ED_P
    y3 = (y1 * y2 + x1 * x2) * pow(1 - t, ED_P - 2, ED_P) % ED_P
    return (x3, y3)


def ed_small_order(point):
    """SPEC-SIGNING §1 check 2: [8]P is the identity."""
    for _ in range(3):
        point = ed_add(point, point)
    return point == ED_IDENTITY


def ed25519_verify_strict(public, message, signature):
    """SPEC-SIGNING §1: canonical, non-small-order A and R; S < L; then the
    RFC 8032 equation (pycryptodome). True iff every check passes."""
    a = ed_decode(public)
    r = ed_decode(signature[:32])
    if a is None or r is None or ed_small_order(a) or ed_small_order(r):
        return False
    if int.from_bytes(signature[32:], "little") >= ED_L:
        return False
    eddsa = eddsa_module()
    try:
        eddsa.new(eddsa.import_public_key(encoded=public), "rfc8032").verify(message, signature)
    except ValueError:
        return False
    return True


def b64url_decode(segment):
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def owner_signature(schemes, scheme, statement, blob, namespace, rps=()):
    """§4: the scheme is advertised, valid for the namespace form, and the
    signature verifies with the namespace as owner. None or a reason."""
    if scheme not in schemes:
        return "scheme not advertised"
    if scheme == "ed25519":
        if not namespace.startswith("ed25519-"):
            return "scheme namespace mismatch"
        if len(blob) != 64:
            return "signature length"
        public = bytes.fromhex(namespace[len("ed25519-"):])
        if not ed25519_verify_strict(public, blake3(statement), blob):
            return "bad signature"
        return None
    if not namespace.startswith("0x"):
        return "scheme namespace mismatch"
    if scheme == "secp256k1-eip191":
        return verify_eip191(statement, blob, namespace)
    return verify_webauthn(statement, blob, namespace, rps)


# ---------------------------------------------------------------------------
# The ECDSA owner schemes (§4, §4.1, §4.3, §4.4).

K1_P = 2**256 - 2**32 - 977
K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
P256_P = 2**256 - 2**224 + 2**192 + 2**96 - 1
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
# §4.3 rule 2 limits on clientDataJSON.
MAX_CLIENT_DATA_DEPTH = 64


# Curve membership is decided here, from the curve equations, never by a
# library: pycryptodome encodes the point at infinity as (0, 0) and accepts
# it as a public key, and libraries may reduce coordinates >= p. A point
# must have 0 <= x, y < p, must not be (0, 0), and must satisfy the
# equation (SEC 1 §2.3.4, §3.2.2.1; SPEC-WRITE-GRANTS §4.1).


def on_k1(x, y):
    """(x, y) is an affine secp256k1 point: y^2 = x^3 + 7 (mod p)."""
    return (0 <= x < K1_P and 0 <= y < K1_P and (x, y) != (0, 0)
            and (y * y - (x * x * x + 7)) % K1_P == 0)


def on_p256(x, y):
    """(x, y) is an affine P-256 point: y^2 = x^3 - 3x + b (mod p)."""
    return (0 <= x < P256_P and 0 <= y < P256_P and (x, y) != (0, 0)
            and (y * y - (x * x * x - 3 * x + P256_B)) % P256_P == 0)


def xy_ints(xy):
    return int.from_bytes(xy[:32], "big"), int.from_bytes(xy[32:], "big")


def ecdsa_module():
    try:
        import ecdsa  # python-ecdsa
    except ImportError:
        sys.exit("FAIL: python-ecdsa not found (pip install ecdsa)")
    return ecdsa


def keccak256(data):
    """Keccak-256 (original Keccak, 0x01 padding; §4.1), pycryptodome."""
    from Crypto.Hash import keccak
    return keccak.new(digest_bits=256, data=data).digest()


def sha256(data):
    return hashlib.sha256(data).digest()


def address_of(xy):
    """§4.1: the last 20 bytes of Keccak-256(x || y)."""
    return keccak256(xy)[12:]


def eip191_digest(statement):
    """§4: Keccak-256 of the EIP-191 version 0x45 prefix, the statement's
    byte length in decimal ASCII, then the statement."""
    return keccak256(b"\x19Ethereum Signed Message:\n" + str(len(statement)).encode()
                     + statement)


def k1_recover(digest, r, s, recid):
    """SEC 1 §4.1.6 public-key recovery for recovery id 0 or 1 (x = r, the
    parity of R.y = recid), over python-ecdsa's curve arithmetic. The x || y
    bytes, or None when r is not the x-coordinate of a curve point."""
    ecdsa = ecdsa_module()
    from ecdsa.ellipticcurve import INFINITY, PointJacobi
    curve, g = ecdsa.SECP256k1.curve, ecdsa.SECP256k1.generator
    alpha = (r * r * r + 7) % K1_P
    beta = pow(alpha, (K1_P + 1) // 4, K1_P)
    if beta * beta % K1_P != alpha:
        return None
    y = beta if beta % 2 == recid else K1_P - beta
    assert on_k1(r, y)
    big_r = PointJacobi(curve, r, y, 1, K1_N)
    e = int.from_bytes(digest, "big") % K1_N
    q = (big_r * s + g * ((-e) % K1_N)) * pow(r, -1, K1_N)
    # The point at infinity is no public key (s·R = e·G). Decide it here,
    # not only through the library's INFINITY sentinel.
    if q == INFINITY:
        return None
    qx, qy = q.x(), q.y()
    if qx is None or qy is None or not on_k1(qx, qy):
        return None
    xy = qx.to_bytes(32, "big") + qy.to_bytes(32, "big")
    # Cross-check with python-ecdsa's own recovery and verification.
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    candidates = ecdsa.VerifyingKey.from_public_key_recovery_with_digest(
        sig, digest, ecdsa.SECP256k1, sigdecode=ecdsa.util.sigdecode_string)
    assert any(c.to_string() == xy for c in candidates), "python-ecdsa recovery disagrees"
    vk = ecdsa.VerifyingKey.from_string(xy, curve=ecdsa.SECP256k1)
    assert vk.verify_digest(sig, digest, sigdecode=ecdsa.util.sigdecode_string)
    return xy


def verify_eip191(statement, blob, namespace):
    """§4 secp256k1-eip191 with the §4.4 rules. None or the first reason."""
    if len(blob) != 65:
        return "signature length"
    v = blob[64]
    if v not in (27, 28):
        return "signature recovery id"
    r, s = int.from_bytes(blob[:32], "big"), int.from_bytes(blob[32:64], "big")
    if not (1 <= r < K1_N and 1 <= s < K1_N):
        return "signature scalar"
    if s > K1_N // 2:
        return "high s"
    xy = k1_recover(eip191_digest(statement), r, s, v - 27)
    if xy is None:
        return "bad signature"
    if "0x" + address_of(xy).hex() != namespace:
        return "owner mismatch"
    return None


def k1_public(secret):
    ecdsa = ecdsa_module()
    xy = ecdsa.SigningKey.from_string(secret, curve=ecdsa.SECP256k1) \
        .get_verifying_key().to_string()
    assert on_k1(*xy_ints(xy))
    return xy


def eip191_sign(secret, statement):
    """RFC 6979 (HMAC-SHA-256) over the EIP-191 digest, s normalized to the
    low half and v chosen by recovery (§4.4 client rules)."""
    ecdsa = ecdsa_module()
    digest = eip191_digest(statement)
    sk = ecdsa.SigningKey.from_string(secret, curve=ecdsa.SECP256k1)
    r_bytes, s_bytes = sk.sign_digest_deterministic(
        digest, hashfunc=hashlib.sha256, sigencode=ecdsa.util.sigencode_strings)
    r, s = int.from_bytes(r_bytes, "big"), int.from_bytes(s_bytes, "big")
    if s > K1_N // 2:
        s = K1_N - s
    public = k1_public(secret)
    recid = next(i for i in (0, 1) if k1_recover(digest, r, s, i) == public)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([27 + recid])


def lp_fields(blob, count):
    """SPEC-CONVENTIONS §3 [u32 LE length][bytes] fields, nothing after the
    last; None if the framing does not hold."""
    out = []
    for _ in range(count):
        if len(blob) < 4:
            return None
        n = int.from_bytes(blob[:4], "little")
        blob = blob[4:]
        if len(blob) < n:
            return None
        out.append(blob[:n])
        blob = blob[n:]
    return out if not blob else None


def lp_encode(*fields):
    return b"".join(len(f).to_bytes(4, "little") + f for f in fields)


class Duplicate(Exception):
    pass


def client_data(raw):
    """§4.3 rule 2 syntax: RFC 8259 JSON text (strict UTF-8, no NaN or
    Infinity, no unpaired surrogate) whose top level is an object, with no
    duplicate member name at any depth (compared after unescaping), nested
    at most MAX_CLIENT_DATA_DEPTH deep (the top-level object is 1), and
    every number finite as an IEEE 754 binary64 value. The decoded object,
    or None."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None

    def pairs(items):
        names = [k for k, _ in items]
        if len(set(names)) != len(names):
            raise Duplicate()
        return dict(items)

    def constant(name):
        raise ValueError(name)

    def number(text):
        value = float(text)  # correctly rounded; overflow gives inf
        if not math.isfinite(value):
            raise ValueError(text)
        return value

    def integer(text):
        float(int(text))  # raises OverflowError past the binary64 range
        return int(text)

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=constant,
                           parse_float=number, parse_int=integer)
    except (ValueError, OverflowError, RecursionError, Duplicate):
        return None

    def depth(v):
        if isinstance(v, dict):
            return 1 + max((depth(x) for x in v.values()), default=0)
        if isinstance(v, list):
            return 1 + max((depth(x) for x in v), default=0)
        return 0

    if depth(value) > MAX_CLIENT_DATA_DEPTH:
        return None

    def surrogate(v):
        if isinstance(v, str):
            return any(0xD800 <= ord(c) <= 0xDFFF for c in v)
        if isinstance(v, dict):
            return any(surrogate(k) or surrogate(x) for k, x in v.items())
        if isinstance(v, list):
            return any(surrogate(x) for x in v)
        return False

    if not isinstance(value, dict) or surrogate(value):
        return None
    return value


def p256_key(x, y):
    """A pycryptodome P-256 public key, or None if (x, y) is not a P-256
    point by `on_p256` (coordinates below p, not (0, 0), on the curve).
    pycryptodome alone would accept (0, 0), its encoding of the point at
    infinity, against which ECDSA is forgeable."""
    from Crypto.PublicKey import ECC
    if not on_p256(x, y):
        return None
    try:
        return ECC.construct(curve="P-256", point_x=x, point_y=y)
    except ValueError:
        return None


def webauthn_challenge(statement):
    return b64url(blake3(statement))


def verify_webauthn(statement, blob, namespace, rps):
    """§4 webauthn-p256 with §4.1, §4.3 and §4.4, in the order the Rust
    verifier documents (each failure yields the same code, so the order only
    fixes which reason a vector names). None or the first reason."""
    from Crypto.Hash import SHA256
    from Crypto.Signature import DSS
    fields = lp_fields(blob, 4)
    if fields is None or len(fields[0]) != 64 or len(fields[3]) != 64:
        return "webauthn blob"
    public, auth, raw_client_data, sig = fields
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if not (1 <= r < P256_N and 1 <= s < P256_N):
        return "signature scalar"
    if s > P256_N // 2:
        return "high s"
    key = p256_key(int.from_bytes(public[:32], "big"), int.from_bytes(public[32:], "big"))
    if key is None:
        return "invalid owner key"
    if "0x" + address_of(public).hex() != namespace:
        return "owner mismatch"
    if len(auth) < 37:
        return "authenticator data"
    if not auth[32] & 0x01:
        return "user not present"
    rp = next((rp for rp in rps if sha256(rp["id"].encode()) == auth[:32]), None)
    if rp is None:
        return "relying party mismatch"
    cd = client_data(raw_client_data)
    if cd is None:
        return "client data"
    if cd.get("type") != "webauthn.get":
        return "client data type"
    if cd.get("challenge") != webauthn_challenge(statement):
        return "challenge"
    if "crossOrigin" in cd and cd["crossOrigin"] is not False:
        return "cross origin"
    if "topOrigin" in cd:
        return "top origin"
    origin = cd.get("origin")
    if not isinstance(origin, str) or origin not in rp["origins"]:
        return "origin not allowed"
    try:
        DSS.new(key, "fips-186-3", encoding="binary").verify(
            SHA256.new(auth + sha256(raw_client_data)), sig)
    except ValueError:
        return "bad signature"
    return None


def p256_public(secret):
    from Crypto.PublicKey import ECC
    point = ECC.construct(curve="P-256", d=int.from_bytes(secret, "big")).pointQ
    assert on_p256(int(point.x), int(point.y))
    return int(point.x).to_bytes(32, "big") + int(point.y).to_bytes(32, "big")


def p256_sign(secret, message):
    """RFC 6979 P-256/SHA-256 (pycryptodome), then s normalized to the low
    half as §4.4 asks of the client."""
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import ECC
    from Crypto.Signature import DSS
    key = ECC.construct(curve="P-256", d=int.from_bytes(secret, "big"))
    sig = DSS.new(key, "deterministic-rfc6979", encoding="binary").sign(SHA256.new(message))
    r, s = sig[:32], int.from_bytes(sig[32:], "big")
    if s > P256_N // 2:
        s = P256_N - s
    return r + s.to_bytes(32, "big")


def ecdsa_self_test():
    """Anchor both signers and the recovery on public vectors."""
    # web3.js accounts.sign("Some data", key), also eth-primitives.json.
    key = bytes.fromhex("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
    sig = eip191_sign(key, b"Some data")
    assert sig.hex() == (
        "b91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd"
        "6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a0291c"), sig.hex()
    assert verify_eip191(b"Some data", sig,
                         "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23") is None
    # RFC 6979 §A.2.5, P-256 with SHA-256, message "sample" (already low s).
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import ECC
    from Crypto.Signature import DSS
    d = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    ref = DSS.new(ECC.construct(curve="P-256", d=d), "deterministic-rfc6979",
                  encoding="binary").sign(SHA256.new(b"sample"))
    assert ref.hex() == (
        "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
        "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"), ref.hex()
    assert p256_public(d.to_bytes(32, "big")).hex().startswith("60fed4ba255a9d31c961eb74")
    # Client data: duplicates at depth, via escapes, surrogates, constants.
    assert client_data(b'{"a":{"b":[1,{"c":null}]}}') is not None
    for bad in (b'{"a":1,"a":1}', b'{"x":[{"a":1,"a":2}]}', b'{"type":1,"\\u0074ype":1}',
                b'{"x":"\\ud800"}', b'{"x":NaN}', b'[]', b'{"x":"\xff"}', b"{} x"):
        assert client_data(bad) is None, bad
    # §4.3 rule 2 limits: depth 64 is the deepest (top-level object = 1),
    # numbers finite as binary64.
    at_limit = b'{"x":' + b"[" * 62 + b"{}" + b"]" * 62 + b"}"
    over = b'{"x":' + b"[" * 63 + b"{}" + b"]" * 63 + b"}"
    assert client_data(at_limit) is not None and client_data(over) is None
    max_int = str(2**1024 - 2**970 - 1).encode()  # rounds to the largest binary64
    tie_int = str(2**1024 - 2**970).encode()      # the midpoint: rounds to infinity
    for good in (b"1.7976931348623157e308", b"1.7976931348623158e308", max_int, b"-1e-400",
                 b"1" + b"0" * 300):
        assert client_data(b'{"x":' + good + b"}") is not None, good
    for bad in (b"1e400", b"-1e400", b"1" + b"0" * 400, b"1.7976931348623159e308", tie_int,
                b"Infinity", b"-Infinity"):
        assert client_data(b'{"x":' + bad + b"}") is None, bad
    # Curve membership: (0, 0) -- pycryptodome's point at infinity -- and
    # coordinates >= p are refused before any library sees them.
    from Crypto.PublicKey import ECC
    assert p256_key(0, 0) is None and not on_k1(0, 0)
    try:
        ECC.construct(curve="P-256", point_x=0, point_y=0)
        library_accepts_infinity = True
    except ValueError:
        library_accepts_infinity = False
    print(f"note: pycryptodome ECC.construct(P-256, 0, 0) accepted: {library_accepts_infinity}")
    y0 = 0x66485C780E2F83D72433BD5D84A06BB6541C2AF31DAE871728BF856A174F93F4  # x = 0
    assert on_p256(0, y0) and not on_p256(P256_P, y0) and p256_key(P256_P, y0) is None
    gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    assert on_k1(gx, gy) and not on_k1(gx + K1_P, gy) and not on_k1(gx, gy + 1)


def window(created, expiry, now):
    """§7 step 10, §5.2 check 5, §9.1: created <= now + 30 s and now < expiry
    (exclusive). A negative clock fails closed."""
    if now < 0 or created > now + MAX_CLOCK_LEAD_MS:
        return "not yet valid"
    if now >= expiry:
        return "expired"
    return None


def decode_header(value, validate):
    """§4.2 decode, then the statement parser. (statement, scheme, blob,
    fields) or a reason."""
    err = validate_header(value)
    if err:
        return err
    stmt, scheme, blob = value.split(".")
    statement = b64url_decode(stmt)
    err = validate(statement)
    if err:
        return err
    return statement, scheme, b64url_decode(blob), statement.decode("ascii").split("\n")


def verify_grant(value, schemes, audience, ctx, rps=()):
    """§7 steps 1-7, 9 and 10 in spec order. None or the first reason."""
    decoded = decode_header(value, validate_grant)
    if isinstance(decoded, str):
        return decoded
    statement, scheme, blob, f = decoded
    namespace = f[1]
    err = owner_signature(schemes, scheme, statement, blob, namespace, rps)
    if err:
        return err
    repository = ctx["repository"]
    repo_ns = repository.split("/", 1)[0] if "/" in repository else None
    if repo_ns != namespace:
        return "namespace mismatch"
    if audience not in f[5].split(","):
        return "audience not listed"
    if f[2] not in (f"{namespace}/*", repository):
        return "repository not in scope"
    if ctx["capability"] not in f[4].split(","):
        return "capability not granted"
    if f[3] != ctx["signer"]:
        return "grantee mismatch"
    return window(int(f[8]), int(f[9]), ctx["now"])


def verify_epoch(value, schemes, audience, now, rps=()):
    """§5.2 checks 1-5. None or the first reason."""
    decoded = decode_header(value, validate_epoch)
    if isinstance(decoded, str):
        return decoded
    statement, scheme, blob, f = decoded
    err = owner_signature(schemes, scheme, statement, blob, f[1], rps)
    if err:
        return err
    if audience not in f[3].split(","):
        return "audience not listed"
    return window(int(f[4]), int(f[5]), now)


def verify_visibility(value, schemes, audience, repository, now, rps=()):
    """§9.1 statement checks, with X-Repository == the statement's
    repository first. None or the first reason."""
    decoded = decode_header(value, validate_visibility)
    if isinstance(decoded, str):
        return decoded
    statement, scheme, blob, f = decoded
    if f[1] != repository:
        return "repository mismatch"
    err = owner_signature(schemes, scheme, statement, blob, f[1].split("/", 1)[0], rps)
    if err:
        return err
    if audience not in f[3].split(","):
        return "audience not listed"
    return window(int(f[4]), int(f[5]), now)


def epoch_transition(stored, new):
    """§5.2 check 7 and the retry rule."""
    if new == stored:
        return "retry"
    if stored < new <= stored + MAX_EPOCH_STEP:
        return "advance"
    return "reject"


def ed25519_self_test():
    """The strict predicate accepts a real signature and refuses the forms
    plain RFC 8032 verification tolerates."""
    seed = bytes([9] * 32)
    public = ed25519_public(seed)
    message = blake3(b"self-test")
    good = ed25519_sign(seed, b"self-test")  # signs BLAKE3(b"self-test") == message
    assert ed25519_verify_strict(public, message, good)
    identity = (1).to_bytes(32, "little")
    forged = identity + bytes(32)  # R = identity, s = 0
    # The cofactored equation holds for the identity key, so a lax
    # verifier accepts it; the strict predicate must not.
    assert not ed25519_verify_strict(identity, message, forged)
    order2 = (ED_P - 1).to_bytes(32, "little")
    assert ed_small_order(ed_decode(order2)) and ed_small_order(ed_decode(bytes(32)))
    assert not ed_small_order(ed_decode(public))
    assert not ed25519_verify_strict(public, message, identity + good[32:])
    high_s = good[:32] + (int.from_bytes(good[32:], "little") + ED_L).to_bytes(32, "little")
    assert not ed25519_verify_strict(public, message, high_s)
    assert ed_decode(ED_P.to_bytes(32, "little")) is None  # y = p: non-canonical


def check_signed_vector(v, seed, build, validate):
    """Rebuild, validate, re-sign and re-encode one signed vector."""
    statement = build(v["fields"])
    assert statement == v["statement"].encode("ascii"), v["name"]
    assert validate(statement) is None, (v["name"], validate(statement))
    assert blake3(statement).hex() == v["id"], v["name"]
    signature = ed25519_sign(seed, statement)
    assert signature.hex() == v["signature_hex"], v["name"]
    assert f"{b64url(statement)}.ed25519.{b64url(signature)}" == v["header"], v["name"]
    return v["header"]


def check_signed(root):
    """The {grant,epoch,visibility}-ed25519.json fixtures and
    reject/verify-*.json. Returns ([statements, contexts, verify rejects],
    table rows)."""
    counts = [0, 0, 0]
    files = {}
    for name in ("grant", "epoch", "visibility"):
        with open(os.path.join(root, f"{name}-ed25519.json"), encoding="utf-8") as fh:
            files[name] = json.load(fh)
        seed = bytes.fromhex(files[name]["owner_seed"])
        assert files[name]["namespace"] == "ed25519-" + ed25519_public(seed).hex()
        assert files[name]["accepted_schemes"] == ["ed25519"]
    schemes = ("ed25519",)

    grants = files["grant"]
    seed = bytes.fromhex(grants["owner_seed"])
    for v in grants["vectors"]:
        header = check_signed_vector(v, seed, build_statement, validate_grant)
        assert v["fields"]["namespace"] == grants["namespace"]
        counts[0] += 1
        for ctx in v["accept_contexts"]:
            got = verify_grant(header, schemes, ctx["audience"], ctx)
            assert got is None, (v["name"], ctx["name"], got)
            counts[1] += 1
        for ctx in v["reject_contexts"]:
            got = verify_grant(header, schemes, ctx["audience"], ctx)
            assert got == ctx["expected_error"], (v["name"], ctx["name"], got)
            counts[1] += 1

    epochs = files["epoch"]
    for v in epochs["vectors"]:
        header = check_signed_vector(v, bytes.fromhex(epochs["owner_seed"]),
                                     build_epoch, validate_epoch)
        counts[0] += 1
        for ctx in v["contexts"]:
            got = verify_epoch(header, schemes, ctx["audience"], ctx["now"])
            assert got == ctx["expected_error"], (v["name"], ctx["name"], got)
            counts[1] += 1
    for t in epochs["transitions"]:
        assert epoch_transition(t["stored"], t["new"]) == t["outcome"], t

    visibility = files["visibility"]
    for v in visibility["vectors"]:
        header = check_signed_vector(v, bytes.fromhex(visibility["owner_seed"]),
                                     build_visibility, validate_visibility)
        counts[0] += 1
        for ctx in v["contexts"]:
            got = verify_visibility(header, schemes, ctx["audience"], ctx["repository"],
                                    ctx["now"])
            assert got == ctx["expected_error"], (v["name"], ctx["name"], got)
            counts[1] += 1

    reject_dir = os.path.join(root, "reject")
    rows = []
    for f in sorted(os.listdir(reject_dir)):
        if not f.startswith("verify-"):
            continue
        with open(os.path.join(reject_dir, f), encoding="utf-8") as fh:
            r = json.load(fh)
        assert r["kind"] == "grant" and r["rule"], f
        got = verify_grant(r["header"], tuple(r["accepted_schemes"]), r["audience"],
                           r["context"], r.get("relying_parties", ()))
        assert got == r["expected_error"], (f, got)
        rows.append((f[:-5], r["expected_error"], r["rule"]))
        counts[2] += 1
    ed_rows = [row for row in rows if not row[0].startswith(ECDSA_REJECT_PREFIXES)]
    expected = {"scheme namespace mismatch", "scheme not advertised", "bad signature",
                "signature length", "expired", "not yet valid"}
    assert {row[1] for row in ed_rows} == expected, ed_rows
    ecdsa_rows = [row for row in rows if row[0].startswith(ECDSA_REJECT_PREFIXES)]
    assert {row[1] for row in ecdsa_rows} == ECDSA_REJECT_REASONS, ecdsa_rows
    for prefix in ECDSA_REJECT_PREFIXES:
        for reason in ("high s", "scheme namespace mismatch", "scheme not advertised",
                       "owner mismatch"):
            assert any(row[0].startswith(prefix) and row[1] == reason for row in rows), \
                (prefix, reason)
    assert any(row[0] == "verify-webauthn-user-not-present" for row in rows)
    for name in ("verify-small-order-key", "verify-small-order-r",
                 "verify-signature-s-not-canonical"):
        assert any(row[0] == name for row in rows), f"missing reject/{name}.json"
    return counts, rows


ECDSA_REJECT_PREFIXES = ("verify-secp256k1-", "verify-webauthn-")
ECDSA_REJECT_REASONS = {
    "high s", "signature recovery id", "signature scalar", "bad signature", "owner mismatch",
    "signature length", "scheme namespace mismatch", "scheme not advertised",
    "invalid owner key", "authenticator data", "user not present", "relying party mismatch",
    "origin not allowed", "client data type", "challenge", "cross origin", "top origin",
    "client data", "webauthn blob",
}
BUILDERS = {
    "grant": (build_statement, validate_grant),
    "epoch": (build_epoch, validate_epoch),
    "visibility": (build_visibility, validate_visibility),
}


def run_context(kind, header, schemes, rps, ctx):
    if kind == "grant":
        return verify_grant(header, schemes, ctx["audience"], ctx, rps)
    if kind == "epoch":
        return verify_epoch(header, schemes, ctx["audience"], ctx["now"], rps)
    return verify_visibility(header, schemes, ctx["audience"], ctx["repository"], ctx["now"],
                             rps)


def check_ecdsa(root):
    """secp256k1-eip191.json and webauthn-p256.json: rebuild each statement,
    re-sign it (deterministic RFC 6979 on both curves, so blobs and headers
    must be equal), and re-run every context. Returns (statements,
    contexts)."""
    statements = contexts = 0
    for scheme in ("secp256k1-eip191", "webauthn-p256"):
        with open(os.path.join(root, f"{scheme}.json"), encoding="utf-8") as fh:
            file = json.load(fh)
        assert file["scheme"] == scheme and file["accepted_schemes"] == [scheme]
        secret = bytes.fromhex(file["owner_private_key"])
        public = k1_public(secret) if scheme == "secp256k1-eip191" else p256_public(secret)
        assert public.hex() == file["owner_x"] + file["owner_y"], scheme
        assert file["namespace"] == "0x" + address_of(public).hex(), scheme
        rps = file["relying_parties"]
        schemes = (scheme,)
        kinds = set()
        for v in file["vectors"]:
            build, validate = BUILDERS[v["kind"]]
            kinds.add(v["kind"])
            statement = build(v["fields"])
            assert statement == v["statement"].encode("ascii"), v["name"]
            assert validate(statement) is None, v["name"]
            assert blake3(statement).hex() == v["id"], v["name"]
            if scheme == "secp256k1-eip191":
                assert eip191_digest(statement).hex() == v["eip191_digest"], v["name"]
                blob = eip191_sign(secret, statement)
            else:
                assert v["challenge"] == webauthn_challenge(statement), v["name"]
                auth = bytes.fromhex(v["authenticator_data_hex"])
                assert auth[:32] == sha256(v["rp_id"].encode()), v["name"]
                raw = v["client_data_json"].encode("utf-8")
                sig = p256_sign(secret, auth + sha256(raw))
                assert sig.hex() == v["signature_hex"], v["name"]
                blob = lp_encode(public, auth, raw, sig)
            assert blob.hex() == v["blob_hex"], v["name"]
            header = f"{b64url(statement)}.{scheme}.{b64url(blob)}"
            assert header == v["header"], v["name"]
            statements += 1
            for ctx in v["contexts"]:
                got = run_context(v["kind"], header, schemes, rps, ctx)
                assert got == ctx["expected_error"], (scheme, v["name"], ctx["name"], got)
                contexts += 1
        assert kinds == {"grant", "epoch", "visibility"}, scheme
    return statements, contexts


# ---------------------------------------------------------------------------
# Reject cases: the §3.4 example with one field edited.

EXAMPLE = [
    DOMAIN,
    "0x8ba1f109551bd432803012645ac136ddd64dba72",
    "0x8ba1f109551bd432803012645ac136ddd64dba72/website",
    "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
    "read,write",
    "https://git.example.com,https://git.example.org",
    "refs/heads/main=cu;refs/heads/wip/*=cufd",
    "0",
    "1790000000000",
    "1792592000000",
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
]
NS = EXAMPLE[1]
OTHER_NS = "0x0000000000000000000000000000000000000001"

R_TEXT = ("a field count other than eleven, an empty field, a final line feed, "
          "a carriage return, or a byte outside the §3.1 range")
R_DOMAIN = "a domain other than mkit-write-grant:v1"
R_IDENT = ("a namespace or repository identity outside the §7.4 grammar, or a "
           "repository scope in another namespace")
R_DEC = "a decimal with a sign, a leading zero, or a value out of range"
R_HEX = "uppercase or wrong-length hexadecimal"
R_CAP = "an unknown capability, or capabilities not in the canonical spelling"
R_AUD = ("an audience that fails the auth v2 origin rules, a * anywhere in the "
         "audience list, more than 8 audiences, or audiences out of order or duplicated")
R_REFS = ("ref scopes that are not - for a read grant, or - for a grant with write")
R_PAT = ("a pattern outside §3.3, a pattern under refs/mkit/packmap/, an unknown "
         "flag, flags out of the cufd order or repeated, more than 16 entries, "
         "entries out of order, or two entries with one pattern")
R_LIFE = "expiry <= created, or a lifetime above GRANT_MAX_LIFETIME_MS"
R_LEN = "a statement longer than MAX_STATEMENT_BYTES"


def edit(**changes):
    fields = list(EXAMPLE)
    for index, value in changes.items():
        fields[int(index[1:])] = value
    return "\n".join(fields)


def padded_to(length):
    """The example with 16 ref scopes, the last padded to `length` bytes."""
    entries = [f"refs/heads/b{i:02}=c" for i in range(16)]
    base = edit(f6=";".join(entries))
    entries[-1] = f"refs/heads/b15{'x' * (length - len(base))}=c"
    out = edit(f6=";".join(entries))
    assert len(out) == length
    return out


NINE = ",".join(f"https://a{i}.example" for i in range(1, 10))
SEVENTEEN = ";".join(f"refs/heads/b{i:02}=c" for i in range(17))

# name -> (rule, statement, expected GrantError::reason)
CASES = {
    "field-count-10": (R_TEXT, "\n".join(EXAMPLE[:10]), "field count"),
    "field-count-12": (R_TEXT, "\n".join(EXAMPLE + ["0"]), "field count"),
    "empty-field": (R_TEXT, "\n".join(EXAMPLE[:7] + [""] + EXAMPLE[8:]), "empty field"),
    "final-line-feed": (R_TEXT, "\n".join(EXAMPLE) + "\n", "final line feed"),
    "carriage-return": (R_TEXT, "\r\n".join(EXAMPLE), "carriage return"),
    "byte-0x20": (R_TEXT, edit(f5="https://git.example.com, https://git.example.org"), "byte out of range"),
    "byte-0x7f": (R_TEXT, edit(f7="0\x7f"), "byte out of range"),
    "domain-trailing-space": (R_TEXT, edit(f0=DOMAIN + " "), "byte out of range"),
    "domain-v2": (R_DOMAIN, edit(f0="mkit-write-grant:v2"), "domain"),
    "domain-epoch": (R_DOMAIN, edit(f0="mkit-write-epoch:v1"), "domain"),
    "namespace-uppercase-hex": (R_IDENT, edit(f1=NS.upper().replace("0X", "0x")), "namespace"),
    "namespace-39-hex": (R_IDENT, edit(f1=NS[:-1]), "namespace"),
    "namespace-unknown-form": (R_IDENT, edit(f1="root"), "namespace"),
    "repository-name-uppercase": (R_IDENT, edit(f2=f"{NS}/Website"), "repository scope"),
    "repository-name-leading-dot": (R_IDENT, edit(f2=f"{NS}/.website"), "repository scope"),
    "repository-bare-name": (R_IDENT, edit(f2="website"), "repository scope"),
    "repository-scope-partial-wildcard": (R_IDENT, edit(f2=f"{NS}/foo*"), "repository scope"),
    "repository-scope-other-namespace": (R_IDENT, edit(f2=f"{OTHER_NS}/website"), "scope namespace mismatch"),
    "namespace-scope-other-namespace": (R_IDENT, edit(f2=f"{OTHER_NS}/*"), "scope namespace mismatch"),
    "decimal-plus-sign": (R_DEC, edit(f7="+1"), "noncanonical decimal"),
    "decimal-leading-zero": (R_DEC, edit(f7="01"), "noncanonical decimal"),
    "epoch-2-pow-64": (R_DEC, edit(f7="18446744073709551616"), "decimal out of range"),
    "created-2-pow-63": (R_DEC, edit(f8="9223372036854775808"), "decimal out of range"),
    "grantee-uppercase": (R_HEX, edit(f3=EXAMPLE[3].upper()), "noncanonical hex"),
    "grantee-63-hex": (R_HEX, edit(f3=EXAMPLE[3][:63]), "noncanonical hex"),
    "nonce-uppercase": (R_HEX, edit(f10=EXAMPLE[10].upper()), "noncanonical hex"),
    "nonce-66-hex": (R_HEX, edit(f10=EXAMPLE[10] + "00"), "noncanonical hex"),
    "capability-unknown": (R_CAP, edit(f4="admin"), "capabilities"),
    "capabilities-write-read": (R_CAP, edit(f4="write,read"), "capabilities"),
    "audience-uppercase": (R_AUD, edit(f5="https://Git.example.com,https://git.example.org"), "audience"),
    "audience-default-port": (R_AUD, edit(f5="https://git.example.com:443,https://git.example.org"), "audience"),
    "audience-trailing-dot": (R_AUD, edit(f5="https://git.example.com.,https://git.example.org"), "audience"),
    "audience-path": (R_AUD, edit(f5="https://git.example.com/,https://git.example.org"), "audience"),
    "audience-userinfo": (R_AUD, edit(f5="https://u@git.example.com,https://git.example.org"), "audience"),
    "audience-wildcard": (R_AUD, edit(f5="*"), "audience wildcard"),
    "audience-wildcard-host": (R_AUD, edit(f5="https://*.example.com"), "audience wildcard"),
    "audiences-9": (R_AUD, edit(f5=NINE), "audience count"),
    "audiences-unsorted": (R_AUD, edit(f5="https://git.example.org,https://git.example.com"), "audiences unordered"),
    "audiences-duplicate": (R_AUD, edit(f5="https://git.example.com,https://git.example.com"), "audiences unordered"),
    "ref-scopes-on-read": (R_REFS, edit(f4="read"), "ref scopes on read grant"),
    "ref-scopes-missing-on-write": (R_REFS, edit(f4="write", f6="-"), "ref scopes missing"),
    "pattern-invalid-ref-name": (R_PAT, edit(f6="refs/heads/.main=cu"), "ref pattern"),
    "pattern-bare-star": (R_PAT, edit(f6="*=cu"), "ref pattern"),
    "pattern-star-suffix": (R_PAT, edit(f6="refs/heads/*x=cu"), "ref pattern"),
    "pattern-packmap-prefix": (R_PAT, edit(f6="refs/mkit/packmap/*=cu"), "packmap pattern"),
    "pattern-packmap-exact": (R_PAT, edit(f6="refs/mkit/packmap/main=cu"), "packmap pattern"),
    "flags-unknown": (R_PAT, edit(f6="refs/heads/main=cx"), "unknown ref flag"),
    "flags-out-of-order": (R_PAT, edit(f6="refs/heads/main=uc"), "noncanonical ref flags"),
    "flags-repeated": (R_PAT, edit(f6="refs/heads/main=cc"), "noncanonical ref flags"),
    "flags-empty": (R_PAT, edit(f6="refs/heads/main="), "noncanonical ref flags"),
    "ref-scopes-17": (R_PAT, edit(f6=SEVENTEEN), "ref scope count"),
    "ref-scopes-unsorted": (R_PAT, edit(f6="refs/heads/wip/*=cufd;refs/heads/main=cu"), "ref scopes unordered"),
    "ref-scopes-duplicate-pattern": (R_PAT, edit(f6="refs/heads/main=c;refs/heads/main=cu"), "duplicate ref pattern"),
    "expiry-equals-created": (R_LIFE, edit(f9=EXAMPLE[8]), "expiry not after created"),
    "expiry-before-created": (R_LIFE, edit(f9="1789999999999"), "expiry not after created"),
    "lifetime-30-days-plus-1ms": (R_LIFE, edit(f9=str(1790000000000 + GRANT_MAX_LIFETIME_MS + 1)), "lifetime too long"),
    "statement-4097-bytes": (R_LEN, padded_to(MAX_STATEMENT_BYTES + 1), "statement too long"),
}


def reject_json(name):
    rule, statement, expected = CASES[name]
    return json.dumps(
        {"rule": rule, "statement": statement, "expected_error": expected},
        indent=2,
        ensure_ascii=True,
    ) + "\n"


def write_rejects(root):
    out = os.path.join(root, "reject")
    os.makedirs(out, exist_ok=True)
    for name in CASES:
        with open(os.path.join(out, f"{name}.json"), "w", encoding="utf-8") as fh:
            fh.write(reject_json(name))
    print(f"wrote {len(CASES)} reject vectors")


def b3sum(data):
    out = subprocess.run(["b3sum", "--no-names"], input=data, capture_output=True, check=True)
    return out.stdout.decode().strip()


def check(root, use_b3sum):
    assert blake3(b"").hex() == (
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    ), "reference BLAKE3 self-test"
    if use_b3sum and shutil.which("b3sum") is None:
        sys.exit("FAIL: b3sum not found (install it, or pass --no-b3sum)")

    ed25519_self_test()
    ecdsa_self_test()

    # Sanity: the validator accepts the §3.4 example and one padded to the bound.
    assert validate_grant("\n".join(EXAMPLE).encode()) is None
    assert validate_grant(padded_to(MAX_STATEMENT_BYTES).encode()) is None

    with open(os.path.join(root, "grant-statements.json"), encoding="utf-8") as fh:
        grants = json.load(fh)
    for v in grants["vectors"]:
        statement = v["statement"].encode("ascii")
        assert build_statement(v["fields"]) == statement, v["name"]
        assert validate_grant(statement) is None, (v["name"], validate_grant(statement))
        assert blake3(statement).hex() == v["id"], v["name"]
        if use_b3sum:
            assert b3sum(statement) == v["id"], v["name"]
    example = next(v for v in grants["vectors"] if v["name"] == "spec-3.4-example")
    assert example["statement"] == "\n".join(EXAMPLE)

    with open(os.path.join(root, "headers.json"), encoding="utf-8") as fh:
        headers = json.load(fh)
    for v in headers["vectors"]:
        statement = v["statement"].encode("ascii")
        blob = bytes.fromhex(v["blob_hex"])
        header = f"{b64url(statement)}.{v['scheme']}.{b64url(blob)}"
        assert header == v["header"], v["name"]
        assert validate_header(header) is None, v["name"]
    assert {v["scheme"] for v in headers["vectors"]} == set(SCHEMES)
    for v in headers["rejects"]:
        assert validate_header(v["header"]) == v["expected_error"], (
            v["name"], validate_header(v["header"]))

    reject_dir = os.path.join(root, "reject")
    files = sorted(f[:-5] for f in os.listdir(reject_dir)
                   if f.endswith(".json") and not f.startswith("verify-"))
    assert files == sorted(CASES), "reject/ must hold exactly the CASES table (+ verify-*)"
    rows = []
    for name in files:
        with open(os.path.join(reject_dir, f"{name}.json"), encoding="utf-8") as fh:
            text = fh.read()
        assert text == reject_json(name), f"reject/{name}.json differs from its case"
        rule, statement, expected = CASES[name]
        got = validate_grant(statement.encode("latin-1"))
        assert got == expected, (name, got, expected)
        rows.append((name, expected, rule))

    listed = {}
    with open(os.path.join(root, "MANIFEST.txt"), encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("#") or not line.strip():
                continue
            path, digest = line.split()
            listed[path] = digest
    on_disk = set()
    for dirpath, _, names in os.walk(root):
        for n in names:
            rel = os.path.relpath(os.path.join(dirpath, n), root)
            if rel != "MANIFEST.txt":
                on_disk.add(rel)
    assert set(listed) == on_disk, "MANIFEST.txt must list every fixture file"
    for path, digest in listed.items():
        with open(os.path.join(root, path), "rb") as fh:
            assert blake3(fh.read()).hex() == digest, f"MANIFEST pin for {path}"

    signed_counts, verify_rows = check_signed(root)
    ecdsa_counts = check_ecdsa(root)

    print("| reject vector | expected_error | rule |")
    print("|---|---|---|")
    for name, expected, rule in rows + verify_rows:
        print(f"| {name} | {expected} | {rule} |")
    print(f"OK ({len(grants['vectors'])} statements, {len(headers['vectors'])} headers, "
          f"{len(headers['rejects'])} header rejects, {len(rows)} reject vectors, "
          f"{signed_counts[0]} signed statements with {signed_counts[1]} contexts, "
          f"{ecdsa_counts[0]} ECDSA-signed statements with {ecdsa_counts[1]} contexts, "
          f"{signed_counts[2]} verify rejects, {len(listed)} pinned files)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root", help="rust/tests/golden/grants")
    ap.add_argument("--no-b3sum", action="store_true")
    ap.add_argument("--write-rejects", action="store_true")
    args = ap.parse_args()
    if args.write_rejects:
        write_rejects(args.root)
    else:
        check(args.root, not args.no_b3sum)


if __name__ == "__main__":
    main()
