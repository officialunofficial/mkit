#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Independent reference check of the grant codec and verifier golden
# vectors (SPEC-WRITE-GRANTS §3, §4, §4.2, §5.1-§5.2, §7, §9.1;
# SPEC-TRANSPORT-CONNECT §7.4):
#   rust/tests/golden/grants/grant-statements.json
#   rust/tests/golden/grants/headers.json
#   rust/tests/golden/grants/{grant,epoch,visibility}-ed25519.json
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
import importlib.util
import ipaddress
import json
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


def owner_signature(schemes, scheme, statement, blob, namespace):
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
    return "scheme not implemented"  # the ECDSA schemes land in WP-2.5


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


def verify_grant(value, schemes, audience, ctx):
    """§7 steps 1-7, 9 and 10 in spec order. None or the first reason."""
    decoded = decode_header(value, validate_grant)
    if isinstance(decoded, str):
        return decoded
    statement, scheme, blob, f = decoded
    namespace = f[1]
    err = owner_signature(schemes, scheme, statement, blob, namespace)
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


def verify_epoch(value, schemes, audience, now):
    """§5.2 checks 1-5. None or the first reason."""
    decoded = decode_header(value, validate_epoch)
    if isinstance(decoded, str):
        return decoded
    statement, scheme, blob, f = decoded
    err = owner_signature(schemes, scheme, statement, blob, f[1])
    if err:
        return err
    if audience not in f[3].split(","):
        return "audience not listed"
    return window(int(f[4]), int(f[5]), now)


def verify_visibility(value, schemes, audience, repository, now):
    """§9.1 statement checks, with X-Repository == the statement's
    repository first. None or the first reason."""
    decoded = decode_header(value, validate_visibility)
    if isinstance(decoded, str):
        return decoded
    statement, scheme, blob, f = decoded
    if f[1] != repository:
        return "repository mismatch"
    err = owner_signature(schemes, scheme, statement, blob, f[1].split("/", 1)[0])
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
                           r["context"])
        assert got == r["expected_error"], (f, got)
        rows.append((f[:-5], r["expected_error"], r["rule"]))
        counts[2] += 1
    expected = {"scheme namespace mismatch", "scheme not advertised", "bad signature",
                "signature length", "expired", "not yet valid"}
    assert {row[1] for row in rows} == expected, rows
    for name in ("verify-small-order-key", "verify-small-order-r",
                 "verify-signature-s-not-canonical"):
        assert any(row[0] == name for row in rows), f"missing reject/{name}.json"
    return counts, rows


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

    print("| reject vector | expected_error | rule |")
    print("|---|---|---|")
    for name, expected, rule in rows + verify_rows:
        print(f"| {name} | {expected} | {rule} |")
    print(f"OK ({len(grants['vectors'])} statements, {len(headers['vectors'])} headers, "
          f"{len(headers['rejects'])} header rejects, {len(rows)} reject vectors, "
          f"{signed_counts[0]} signed statements with {signed_counts[1]} contexts, "
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
