#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Independent reference check of the grant codec golden vectors
# (SPEC-WRITE-GRANTS §3, §4.2; SPEC-TRANSPORT-CONNECT §7.4):
#   rust/tests/golden/grants/grant-statements.json
#   rust/tests/golden/grants/headers.json
#   rust/tests/golden/grants/reject/*.json
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
#     (WP-1.3), checked against `b3sum` (the official CLI) unless --no-b3sum.
#
# The reject vectors are authored by the CASES table below: each case edits
# one field of the §3.4 example so that it breaks exactly one §3.5 rule, and
# names that rule and the expected `GrantError::reason`. `--write-rejects`
# (re)writes reject/*.json from the table; the check mode asserts every file
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
SCHEMES = ("ed25519", "secp256k1-eip191", "webauthn-p256")
U64_MAX = 2**64 - 1
I64_MAX = 2**63 - 1

# SPEC-TRANSPORT-CONNECT §7.4.
NAMESPACE_RE = re.compile(r"(ed25519-[0-9a-f]{64}|0x[0-9a-f]{40})\Z")
NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,99}\Z")
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
    files = sorted(f[:-5] for f in os.listdir(reject_dir) if f.endswith(".json"))
    assert files == sorted(CASES), "reject/ must hold exactly the CASES table"
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

    print("| reject vector | expected_error | §3.5 rule |")
    print("|---|---|---|")
    for name, expected, rule in rows:
        print(f"| {name} | {expected} | {rule} |")
    print(f"OK ({len(grants['vectors'])} statements, {len(headers['vectors'])} headers, "
          f"{len(headers['rejects'])} header rejects, {len(rows)} reject vectors, "
          f"{len(listed)} pinned files)")


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
