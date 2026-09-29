#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Independent reference check of the URL-token golden vectors
# (SPEC-WRITE-GRANTS §3.1, §9.4; SPEC-SERVER §7.2; SPEC-HTTP-OBJECTS §6):
#   rust/tests/golden/url-token/tokens.json
#   rust/tests/golden/url-token/targets.json
#   rust/tests/golden/url-token/keyset.json
#   rust/tests/golden/url-token/reject/*.json
#   rust/tests/golden/url-token/MANIFEST.txt
#
# Everything here is written from the spec text and shares no code with the
# Rust crates:
#   * a statement builder and validator for the eight §9.4 fields, with the
#     §3.1 byte rules, the §7.4 identity grammar (namespaced or, here, bare),
#     the auth v2 origin rules (§3.2), the SPEC-REFS §3 ref-name grammar and
#     the §9.4 target grammar re-implemented below, each naming the first
#     rule a statement breaks with the `GrantError`/`UrlTokenError` reason
#     string;
#   * the §9.4 token encoding: `<unpadded base64url statement>.<unpadded
#     base64url 64-byte signature>`, decoded strictly (no padding, the
#     base64url alphabet only, zero trailing bits);
#   * BLAKE3 from the pure-Python transcription in blake3_subtree_ref.py
#     (WP-1.3), checked against `b3sum` unless --no-b3sum;
#   * the §7.2 key set: `active <seed>` / `retired <public> <ms>` key-file
#     lines, key ids `blake3(public)[..16]`, and the published JSON
#     re-rendered byte for byte;
#   * Ed25519 signing and the SPEC-SIGNING §1 strict predicate shared with
#     grants_ref.py (pycryptodome RFC 8032; canonical, non-small-order A and
#     R; S < L);
#   * the SPEC-HTTP-OBJECTS §6 two-phase verification: decode, statement,
#     key id and signature before any repository state is read; the request
#     binding (audience, repository, target, now < expiry, configured
#     lifetime) next; the stored-epoch read last — `read_epoch` must not
#     run for a token that fails an earlier phase.
#
# The reject vectors are authored by the Rust golden writer
# (`MKIT_WRITE_GOLDEN=1 cargo test -p mkit-server --all-features
# url_token`); this script rebuilds each token from its case table — the
# base statement of the first tokens.json vector with one rule broken —
# and asserts the file bytes, the stated reason, and that verification
# reaches the stated stage.
#
# Usage:
#   python3 scripts/golden/url_token_ref.py rust/tests/golden/url-token [--no-b3sum]
#
# Exit 0 and print "OK" when every check passes.

import argparse
import base64
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import unicodedata

sys.dont_write_bytecode = True  # keep scripts/golden free of __pycache__

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_b3 = _load("blake3_subtree_ref")
blake3 = _b3.blake3
_gr = _load("grants_ref")
origin_ok = _gr.origin_ok
ed25519_public = _gr.ed25519_public
ed25519_sign = _gr.ed25519_sign
ed25519_verify_strict = _gr.ed25519_verify_strict
b64url = _gr.b64url
b3sum = _gr.b3sum

# SPEC-WRITE-GRANTS §9.4 and §3.1; SPEC-REFS §3; §7.4 identity.
DOMAIN = "mkit-url-token:v1"
MAX_STATEMENT_BYTES = 4096
MAX_TOKEN_LEN = 8192
MAX_PATH_BYTES = 1024
MAX_TTL_MS = 24 * 60 * 60 * 1000
MAX_REF_NAME_BYTES = 512
MAX_IDENTITY_LEN = 173
MAX_NAME_LEN = 100
U64_MAX = 2**64 - 1
I64_MAX = 2**63 - 1
REJECTED = "invalid URL token"  # TokenRejected: the uniform verify failure
B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
DECIMAL_RE = re.compile(r"(0|[1-9][0-9]*)\Z")
NAMESPACE_RE = re.compile(r"(ed25519-[0-9a-f]{64}|0x[0-9a-f]{40})\Z")
NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]*\Z")


class Reject(Exception):
    pass


class StoreDown(Exception):
    """A read_epoch infrastructure failure: it propagates as its own
    error (SPEC-HTTP-OBJECTS §3 step 5: a 503, never a rejection)."""



# ---------------------------------------------------------------------------
# §3.1 statement text rules, in the parser's check order.


def split_fields(data, n):
    if len(data) > MAX_STATEMENT_BYTES:
        raise Reject("statement too long")
    for b in data:
        if b == 0x0D:
            raise Reject("carriage return")
        if b != 0x0A and not 0x21 <= b <= 0x7E:
            raise Reject("byte out of range")
    if data.endswith(b"\n"):
        raise Reject("final line feed")
    fields = data.decode("ascii").split("\n")
    if len(fields) != n:
        raise Reject("field count")
    if any(f == "" for f in fields):
        raise Reject("empty field")
    return fields


def decimal(text, maximum):
    """A canonical unsigned decimal (no sign, no leading zero)."""
    if not DECIMAL_RE.match(text):
        raise Reject("noncanonical decimal")
    if int(text) > maximum:
        raise Reject("decimal out of range")
    return int(text)


def is_hex(text, nbytes):
    return len(text) == 2 * nbytes and re.fullmatch(r"[0-9a-f]+\Z", text) is not None


def identity_ok(identity):
    """§7.4: `namespace "/" name`, or a bare `name` (a single-repository
    deployment; SPEC-WRITE-GRANTS §9.4 admits it here)."""
    if len(identity.encode("utf-8")) > MAX_IDENTITY_LEN:
        return False
    if "/" in identity:
        namespace, name = identity.split("/", 1)
        return NAMESPACE_RE.match(namespace) is not None and name_ok(name)
    return name_ok(identity)


def name_ok(name):
    return 0 < len(name.encode("utf-8")) <= MAX_NAME_LEN and NAME_RE.match(name) is not None


def ref_name_ok(name):
    """SPEC-REFS §3 with the 512-byte bound: nonempty `/`-joined segments,
    no segment starting with `.` or ending `.lock`, characters
    `[A-Za-z0-9._-]`, the last segment not `HEAD`."""
    if not name or len(name.encode("utf-8")) > MAX_REF_NAME_BYTES or name.startswith("/"):
        return False
    segments = name.split("/")
    for segment in segments:
        if (
            not segment
            or segment.startswith(".")
            or segment.endswith(".lock")
            or re.fullmatch(r"[A-Za-z0-9._-]+", segment) is None
        ):
            return False
    return segments[-1] != "HEAD"


def path_ok(path):
    """§9.4 path grammar: at most MAX_PATH_BYTES bytes; empty names the
    root tree; a nonempty path is `/`-joined entry names with no empty,
    `.` or `..` entry, and no control character (Unicode category Cc)."""
    if len(path.encode("utf-8")) > MAX_PATH_BYTES:
        return False
    if any(unicodedata.category(c) == "Cc" for c in path):
        return False
    return path == "" or all(
        entry not in ("", ".", "..") for entry in path.split("/")
    )


# ---------------------------------------------------------------------------
# The §9.4 token and target grammars.


def b64url_strict(segment):
    """Strict unpadded base64url: the alphabet only, a decodable length,
    and canonical trailing bits. The empty segment decodes to b""."""
    if not re.fullmatch(r"[A-Za-z0-9_-]*\Z", segment) or len(segment) % 4 == 1:
        raise Reject("bad encoding")
    decoded = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    if b64url(decoded) != segment:
        raise Reject("bad encoding")
    return decoded


def decode_token(token):
    """§9.4: `<b64url statement>.<b64url 64-byte signature>`."""
    if len(token.encode("utf-8")) > MAX_TOKEN_LEN:
        raise Reject("token too long")
    parts = token.split(".", 1)
    if len(parts) != 2 or parts[0] == "" or parts[1] == "" or "." in parts[1]:
        raise Reject("token format")
    try:
        statement = b64url_strict(parts[0])
        signature = b64url_strict(parts[1])
    except Reject:
        raise Reject("token encoding")
    if len(signature) != 64:
        raise Reject("signature length")
    return statement, signature


def encode_token(statement, signature):
    return b64url(statement) + "." + b64url(signature)


def parse_target(field):
    """§9.4 target: `object:<64 hex>` or `path:<ref>:<b64url path>`."""
    if field.startswith("object:"):
        rest = field[len("object:"):]
        if not is_hex(rest, 32):
            raise Reject("invalid target")
        return ("object", bytes.fromhex(rest))
    if not field.startswith("path:"):
        raise Reject("invalid target")
    rest = field[len("path:"):]
    if ":" not in rest:
        raise Reject("invalid target")
    reference, encoded = rest.split(":", 1)
    try:
        path = b64url_strict(encoded).decode("utf-8")
    except (Reject, UnicodeDecodeError):
        raise Reject("invalid target")
    if not ref_name_ok(reference) or not path_ok(path):
        raise Reject("invalid target")
    return ("path", reference, path)


def target_field(target):
    if target[0] == "object":
        return "object:" + target[1].hex()
    return "path:" + target[1] + ":" + b64url(target[2].encode("utf-8"))


def parse_statement(data):
    """The §9.4 statement: eight fields, each rule in parse order."""
    f = split_fields(data, 8)
    if f[0] != DOMAIN:
        raise Reject("domain")
    if not origin_ok(f[1]):
        raise Reject("audience")
    if not identity_ok(f[2]):
        raise Reject("repository")
    target = parse_target(f[3])
    epoch = decimal(f[4], U64_MAX)
    issued = decimal(f[5], I64_MAX)
    expiry = decimal(f[6], I64_MAX)
    if expiry <= issued:
        raise Reject("expiry not after created")
    if expiry - issued > MAX_TTL_MS:
        raise Reject("lifetime too long")
    if not is_hex(f[7], 16):
        raise Reject("noncanonical hex")
    return {
        "audience": f[1],
        "repository": f[2],
        "target": target,
        "epoch": epoch,
        "issued_ms": issued,
        "expiry_ms": expiry,
        "key_id": f[7],
    }


def build_statement(fields):
    """Rebuild the statement bytes from a tokens.json `fields` object."""
    return "\n".join(
        [
            DOMAIN,
            fields["audience"],
            fields["repository"],
            fields["target"],
            str(fields["epoch"]),
            str(fields["issued_ms"]),
            str(fields["expiry_ms"]),
            fields["key_id"],
        ]
    ).encode("ascii")


# ---------------------------------------------------------------------------
# §7.2 key set and the SPEC-HTTP-OBJECTS §6 two-phase verification.


def parse_key_file(text):
    """`active <64 hex seed>`, `retired <64 hex public> <retired_at_ms>`;
    blank lines and `#` comments are ignored."""
    seed = None
    retired = []
    for raw in text.split("\n"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if parts[0] == "active" and len(parts) == 2 and is_hex(parts[1], 32):
            if seed is not None:
                raise Reject("invalid URL token key configuration")
            seed = bytes.fromhex(parts[1])
        elif (
            parts[0] == "retired"
            and len(parts) == 3
            and is_hex(parts[1], 32)
            and DECIMAL_RE.match(parts[2])
            and int(parts[2]) <= U64_MAX
        ):
            retired.append((bytes.fromhex(parts[1]), int(parts[2])))
        else:
            raise Reject("invalid URL token key configuration")
    if seed is None:
        raise Reject("invalid URL token key configuration")
    return seed, retired


def key_id(public):
    return blake3(public)[:16].hex()


def key_set_json(seed, retired, ttl_ms):
    """The published key list (SPEC-SERVER §7.2), rendered exactly."""
    def entry(kid, public):
        return '"keyId":"%s","alg":"ed25519","publicKey":"%s"' % (kid, public.hex())

    active = ed25519_public(seed)
    out = '{"version":1,"keys":[{' + entry(key_id(active), active)
    for public, retired_at in retired:
        not_after = min(U64_MAX, retired_at + ttl_ms)
        out += '},{' + entry(key_id(public), public) + ',"notAfterMs":"%d"' % not_after
    return out + "}]}"


def verifying_key(seed, retired, id_hex, now_ms, ttl_ms):
    """The verification key for a statement's key id: the active key, or a
    retired key before `retired_at_ms + ttl_ms`."""
    active = ed25519_public(seed)
    if key_id(active) == id_hex:
        return active
    for public, retired_at in retired:
        if key_id(public) == id_hex and now_ms >= 0 and now_ms < min(U64_MAX, retired_at + ttl_ms):
            return public
    return None


def precheck(cfg, token, now_ms):
    """Phase 1 (SPEC-HTTP-OBJECTS §6): strict decode, statement rules, a
    key id in the verification set, the strict Ed25519 signature over
    blake3(statement). Any failure is the uniform REJECTED."""
    statement, signature = decode_token(token)
    parsed = parse_statement(statement)
    public = verifying_key(
        cfg["seed"], cfg["retired"], parsed["key_id"], now_ms, cfg["ttl_ms"]
    )
    if public is None:
        raise Reject(REJECTED)
    if not ed25519_verify_strict(public, blake3(statement), signature):
        raise Reject(REJECTED)
    return parsed


def check_binding(parsed, audience, repository, target, now_ms, ttl_ms):
    """Phase 2: audience, repository and target equal the request byte for
    byte; `now < expiry`; `expiry - issued <= ttl_ms`."""
    if (
        parsed["audience"] != audience
        or parsed["repository"] != repository
        or parsed["target"] != target
    ):
        raise Reject(REJECTED)
    if now_ms >= parsed["expiry_ms"]:
        raise Reject(REJECTED)
    if parsed["expiry_ms"] - parsed["issued_ms"] > ttl_ms:
        raise Reject(REJECTED)
    return parsed["epoch"]


def verify(cfg, token, binding, now_ms, read_epoch):
    """SPEC-HTTP-OBJECTS §6: precheck, then binding, then exactly one
    stored-epoch read and the epoch comparison. A `read_epoch` failure
    propagates as its own error, never as a Reject."""
    parsed = precheck(cfg, token, now_ms)
    epoch = check_binding(parsed, *binding, now_ms, cfg["ttl_ms"])
    if read_epoch() != epoch:
        raise Reject(REJECTED)


def first_rejection(cfg, token, now_ms):
    """The first stage's reason, as the Rust golden test computes it."""
    try:
        statement, signature = decode_token(token)
    except Reject as e:
        return str(e)
    try:
        parsed = parse_statement(statement)
    except Reject as e:
        return str(e)
    public = verifying_key(
        cfg["seed"], cfg["retired"], parsed["key_id"], now_ms, cfg["ttl_ms"]
    )
    if public is None or not ed25519_verify_strict(
        public, blake3(statement), signature
    ):
        return REJECTED
    return None


# ---------------------------------------------------------------------------
# The reject case table: one function per case, building the token from the
# first tokens.json vector's fields (`base`) by breaking exactly one rule.


def cases(base, good, seed, other_seed):
    """`base` is the eight statement field texts; `good` its valid token."""
    def sign(fields, k=seed):
        stmt = "\n".join(fields).encode("ascii")
        return encode_token(stmt, ed25519_sign(k, stmt))

    def edit(index, value):
        fields = list(base)
        fields[index] = value
        return fields

    def path_field(path):
        return "path:refs/heads/main:" + b64url(path.encode("utf-8"))

    # `+` for the first signature character, whatever it is.
    dot = good.index(".")
    standard = good[: dot + 1] + "+" + good[dot + 2:]
    # The last signature character with the same data bits and a nonzero
    # padding bit.
    trailing = good[:-1] + B64URL[(B64URL.index(good[-1]) & 0x30) | 1]

    return {
        "token-padding": (
            "a `=` anywhere in a token segment is outside the unpadded base64url alphabet",
            good + "=",
            "token encoding",
        ),
        "token-standard-alphabet": (
            "`+` and `/` are the standard base64 alphabet, not base64url",
            standard,
            "token encoding",
        ),
        "token-nonzero-trailing-bits": (
            "the last signature character must carry zero padding bits",
            trailing,
            "token encoding",
        ),
        "token-segment-count": (
            "exactly two `.`-joined nonempty segments",
            good + "." + good,
            "token format",
        ),
        "statement-field-count-7": (
            "the statement is exactly eight fields",
            sign(base[:7]),
            "field count",
        ),
        "statement-field-count-9": (
            "the statement is exactly eight fields",
            sign(edit(7, base[7] + "\nx")),
            "field count",
        ),
        "statement-domain": (
            "the domain is exactly mkit-url-token:v1",
            sign(edit(0, "mkit-url-token:v2")),
            "domain",
        ),
        "statement-key-id-uppercase": (
            "the key id is 32 lowercase hex digits",
            sign(edit(7, base[7].upper())),
            "noncanonical hex",
        ),
        "statement-issued-gte-expiry": (
            "issued is before expiry",
            sign(edit(5, base[6])),
            "expiry not after created",
        ),
        "statement-lifetime-over-max": (
            "expiry - issued is at most the 24 h statement bound",
            sign(edit(6, str(int(base[5]) + MAX_TTL_MS + 1))),
            "lifetime too long",
        ),
        "target-path-dot": (
            "a nonempty path is `/`-joined entry names with no empty, `.` or `..` entry",
            sign(edit(3, path_field("."))),
            "invalid target",
        ),
        "target-path-dotdot": (
            "a nonempty path is `/`-joined entry names with no empty, `.` or `..` entry",
            sign(edit(3, path_field(".."))),
            "invalid target",
        ),
        "target-path-double-slash": (
            "a nonempty path is `/`-joined entry names with no empty, `.` or `..` entry",
            sign(edit(3, path_field("a//b"))),
            "invalid target",
        ),
        "target-path-leading-slash": (
            "a nonempty path is `/`-joined entry names with no empty, `.` or `..` entry",
            sign(edit(3, path_field("/a"))),
            "invalid target",
        ),
        "target-path-trailing-slash": (
            "a nonempty path is `/`-joined entry names with no empty, `.` or `..` entry",
            sign(edit(3, path_field("a/"))),
            "invalid target",
        ),
        "target-path-1025-bytes": (
            "a nonempty path is `/`-joined entry names with no empty, `.` or `..` entry",
            sign(edit(3, path_field("x" * (MAX_PATH_BYTES + 1)))),
            "invalid target",
        ),
        "target-path-non-utf8": (
            "the base64url path decodes to UTF-8",
            sign(edit(3, "path:refs/heads/main:_w")),
            "invalid target",
        ),
        "verify-unknown-key-id": (
            "the key id is the active key or a still-valid retired key",
            sign(edit(7, "ee" * 16)),
            REJECTED,
        ),
        "verify-other-key-signature": (
            "the Ed25519 signature verifies strictly over blake3(statement)",
            sign(base, other_seed),
            REJECTED,
        ),
    }


def ed25519_self_test():
    """RFC 8032 test vector 1 (RFC 8032 §7.1 TEST 1): the empty message."""
    seed = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    public = ed25519_public(seed)
    assert public.hex() == (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    # ed25519_sign signs blake3(msg); the RFC 8032 vector signs msg itself.
    eddsa = _gr.eddsa_module()
    signature = eddsa.new(eddsa.import_private_key(seed), "rfc8032").sign(b"")
    assert signature.hex() == (
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    assert ed25519_verify_strict(public, b"", signature)


def reject_json(rule, token, expected):
    return (
        json.dumps(
            {"rule": rule, "token": token, "expected_error": expected},
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def check(root, use_b3sum):
    assert blake3(b"").hex() == (
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    ), "reference BLAKE3 self-test"
    if use_b3sum and shutil.which("b3sum") is None:
        sys.exit("FAIL: b3sum not found (install it, or pass --no-b3sum)")
    ed25519_self_test()

    with open(os.path.join(root, "tokens.json"), encoding="utf-8") as fh:
        tokens = json.load(fh)
    with open(os.path.join(root, "targets.json"), encoding="utf-8") as fh:
        targets = json.load(fh)
    with open(os.path.join(root, "keyset.json"), encoding="utf-8") as fh:
        keyset = json.load(fh)

    seed = bytes.fromhex(tokens["seed"])
    other_seed = bytes.fromhex("08" * 32)
    assert ed25519_public(seed).hex() == tokens["public_key"]
    assert key_id(bytes.fromhex(tokens["public_key"])) == tokens["key_id"]

    cfg_seed, cfg_retired = parse_key_file(keyset["key_file"])
    cfg = {"seed": cfg_seed, "retired": cfg_retired, "ttl_ms": keyset["ttl_ms"]}
    assert cfg_seed == seed, "keyset.json must publish the tokens' key"
    assert ed25519_public(cfg_seed).hex() == keyset["active_public_key"]
    assert key_id(ed25519_public(cfg_seed)) == keyset["active_key_id"]
    assert len(keyset["retired"]) == len(cfg_retired)
    for entry, (public, retired_at) in zip(keyset["retired"], cfg_retired):
        assert bytes.fromhex(entry["public_key"]) == public
        assert entry["retired_at_ms"] == retired_at
        assert entry["key_id"] == key_id(public)
    assert key_set_json(cfg_seed, cfg_retired, cfg["ttl_ms"]) == keyset["json"]

    # targets.json: every valid field parses to its parts and re-encodes;
    # every invalid field fails the grammar.
    for v in targets["valid"]:
        target = parse_target(v["field"])
        if "object_hex" in v:
            assert target == ("object", bytes.fromhex(v["object_hex"])), v["name"]
        else:
            assert target == ("path", v["reference"], v["path"]), v["name"]
        assert target_field(target) == v["field"], v["name"]
    for v in targets["invalid"]:
        try:
            parse_target(v["field"])
        except Reject as e:
            assert str(e) == v["reason"], (v["name"], str(e))
        else:
            raise AssertionError(f"{v['name']} unexpectedly parsed")

    # tokens.json: rebuild every statement and token, re-sign
    # deterministically, and run all three verification phases.
    rows = []
    for v in tokens["vectors"]:
        fields = v["fields"]
        statement = build_statement(fields)
        assert statement == v["statement"].encode("ascii"), v["name"]
        assert blake3(statement).hex() == v["blake3"], v["name"]
        if use_b3sum:
            assert b3sum(statement) == v["blake3"], v["name"]
        signature = ed25519_sign(seed, statement)
        assert signature.hex() == v["signature_hex"], v["name"]
        assert encode_token(statement, signature) == v["token"], v["name"]
        decoded_statement, decoded_signature = decode_token(v["token"])
        assert decoded_statement == statement and decoded_signature == signature, v["name"]
        parsed = parse_statement(statement)
        assert parsed["key_id"] == fields["key_id"], v["name"]
        binding = (
            fields["audience"],
            fields["repository"],
            parse_target(fields["target"]),
        )
        epoch = check_binding(
            parsed, *binding, parsed["issued_ms"], cfg["ttl_ms"]
        )
        assert epoch == fields["epoch"], v["name"]

        calls = []

        def read_epoch(_epoch=epoch, _calls=calls):
            _calls.append(1)
            return _epoch

        verify(cfg, v["token"], binding, parsed["issued_ms"], read_epoch)
        assert calls == [1], v["name"]

        def read_wrong():
            return (epoch + 1) % (U64_MAX + 1)

        try:
            verify(cfg, v["token"], binding, parsed["issued_ms"], read_wrong)
        except Reject as e:
            assert str(e) == REJECTED, v["name"]
        else:
            raise AssertionError(f"{v['name']} verified at a wrong epoch")

        def read_down():
            raise StoreDown()

        try:
            verify(cfg, v["token"], binding, parsed["issued_ms"], read_down)
        except StoreDown:
            pass
        else:
            raise AssertionError(f"{v['name']}: read error not propagated")
        rows.append(v["name"])

    # reject/*.json: the file set is exactly the case table, each file is
    # the case's bytes, and verification fails at the stated stage without
    # a stored-epoch read.
    base_vector = tokens["vectors"][0]
    base = build_statement(base_vector["fields"]).decode("ascii").split("\n")
    assert base_vector["statement"] == "\n".join(base)
    good = base_vector["token"]
    assert encode_token(base_vector["statement"].encode("ascii"),
                        bytes.fromhex(base_vector["signature_hex"])) == good
    table = cases(base, good, seed, other_seed)

    reject_dir = os.path.join(root, "reject")
    files = sorted(f[:-5] for f in os.listdir(reject_dir) if f.endswith(".json"))
    assert files == sorted(table), "reject/ must hold exactly the case table"
    rejects = []
    for name in files:
        with open(os.path.join(reject_dir, f"{name}.json"), encoding="utf-8") as fh:
            text = fh.read()
        rule, token, expected = table[name]
        assert text == reject_json(rule, token, expected), (
            f"reject/{name}.json differs from its case"
        )
        got = first_rejection(cfg, token, int(base[5]))
        assert got == expected, (name, got, expected)

        def read_epoch_never(_name=name):
            raise AssertionError(f"{_name}: stored epoch read before its phase")

        try:
            verify(cfg, token, (base[1], base[2], parse_target(base[3])),
                   int(base[5]), read_epoch_never)
        except Reject:
            pass
        rejects.append((name, expected, rule))

    # MANIFEST.txt pins every fixture file's BLAKE3.
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

    print("| reject vector | expected_error | rule |")
    print("|---|---|---|")
    for name, expected, rule in rejects:
        print(f"| {name} | {expected} | {rule} |")
    print(
        f"OK ({len(tokens['vectors'])} tokens, {len(targets['valid'])} valid targets, "
        f"{len(targets['invalid'])} invalid targets, {len(rejects)} reject vectors, "
        f"{len(listed)} pinned files)"
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root", help="rust/tests/golden/url-token")
    ap.add_argument("--no-b3sum", action="store_true")
    args = ap.parse_args()
    check(args.root, not args.no_b3sum)


if __name__ == "__main__":
    main()
