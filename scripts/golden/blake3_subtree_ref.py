#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Independent reference check of the part-upload golden vectors
# (SPEC-TRANSPORT-CONNECT §7.6):
#   rust/tests/golden/uploads/subtree-merge.json
#   rust/tests/golden/auth-v2/part.json
#
# BLAKE3 here is a pure-Python transcription of the BLAKE3 paper, §2
# (https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf): the
# IV, the G function and message permutation, the CHUNK_START / CHUNK_END /
# PARENT / ROOT flags, chunk chaining and parent nodes. It shares no code with
# the `blake3` crate. Part `i` is hashed as a non-root subtree whose first
# chunk counter is `offset / 1024`; part chaining values merge by the
# left-balanced rule, and only the top merge sets ROOT.
#
# Checks:
#   * the reference against the published BLAKE3 hash of the empty input;
#   * every part CV and root in subtree-merge.json;
#   * every root against `b3sum` (the official CLI) over the regenerated input
#     (skip with --no-b3sum);
#   * part.json: the canonical auth v2 string rebuilt from the spec's field
#     order, its BLAKE3 digest, and the Ed25519 public key and signature from
#     the seed with pycryptodome (`Crypto.Signature.eddsa`, 'rfc8032').
#
# Usage:
#   python3 scripts/golden/blake3_subtree_ref.py \
#       rust/tests/golden/uploads/subtree-merge.json \
#       [--part-json rust/tests/golden/auth-v2/part.json] \
#       [--only NAME[,NAME...]] [--small-only] [--no-b3sum] [--jobs N]
#
# Pure Python manages a few seconds per 8 MiB part. Part CVs depend only on
# (offset, len) under the input rule, so each distinct part is hashed once,
# spread over --jobs worker processes.
#
# Exit 0 and print "OK" when every check passes; exit 1 otherwise.

import argparse
import json
import os
import shutil
import struct
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor

MASK = 0xFFFFFFFF
CHUNK_LEN = 1024
BLOCK_LEN = 64
IV = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)
MSG_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
CHUNK_START = 1 << 0
CHUNK_END = 1 << 1
PARENT = 1 << 2
ROOT = 1 << 3

# Message word order for each of the 7 rounds (the permutation applied
# round after round).
SCHEDULE = []
_order = list(range(16))
for _ in range(7):
    SCHEDULE.append(tuple(_order))
    _order = [_order[i] for i in MSG_PERMUTATION]


def compress(cv, m, counter, block_len, flags):
    """The BLAKE3 compression function. Returns all 16 output words."""
    s = [
        cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
        IV[0], IV[1], IV[2], IV[3],
        counter & MASK, (counter >> 32) & MASK, block_len, flags,
    ]

    def g(a, b, c, d, x, y):
        s[a] = (s[a] + s[b] + x) & MASK
        t = s[d] ^ s[a]
        s[d] = ((t >> 16) | (t << 16)) & MASK
        s[c] = (s[c] + s[d]) & MASK
        t = s[b] ^ s[c]
        s[b] = ((t >> 12) | (t << 20)) & MASK
        s[a] = (s[a] + s[b] + y) & MASK
        t = s[d] ^ s[a]
        s[d] = ((t >> 8) | (t << 24)) & MASK
        s[c] = (s[c] + s[d]) & MASK
        t = s[b] ^ s[c]
        s[b] = ((t >> 7) | (t << 25)) & MASK

    for o in SCHEDULE:
        # Columns.
        g(0, 4, 8, 12, m[o[0]], m[o[1]])
        g(1, 5, 9, 13, m[o[2]], m[o[3]])
        g(2, 6, 10, 14, m[o[4]], m[o[5]])
        g(3, 7, 11, 15, m[o[6]], m[o[7]])
        # Diagonals.
        g(0, 5, 10, 15, m[o[8]], m[o[9]])
        g(1, 6, 11, 12, m[o[10]], m[o[11]])
        g(2, 7, 8, 13, m[o[12]], m[o[13]])
        g(3, 4, 9, 14, m[o[14]], m[o[15]])
    for i in range(8):
        s[i] ^= s[i + 8]
        s[i + 8] ^= cv[i]
    return s


def words(block):
    return struct.unpack("<16I", bytes(block).ljust(BLOCK_LEN, b"\0"))


def to_bytes(ws):
    return struct.pack("<8I", *ws[:8])


def chunk_cv(data, counter, root):
    """Chaining value (or root words) of one chunk of at most 1024 bytes."""
    cv = IV
    blocks = [data[i:i + BLOCK_LEN] for i in range(0, len(data), BLOCK_LEN)] or [b""]
    for n, block in enumerate(blocks):
        flags = 0
        if n == 0:
            flags |= CHUNK_START
        if n == len(blocks) - 1:
            flags |= CHUNK_END | (ROOT if root else 0)
        cv = compress(cv, words(block), counter, len(block), flags)[:8]
    return tuple(cv)


def parent_cv(left, right, root):
    return tuple(
        compress(IV, tuple(left) + tuple(right), 0, BLOCK_LEN, PARENT | (ROOT if root else 0))[:8]
    )


def left_len(n):
    """Left subtree length of an n-byte input (n > 1024): the largest power
    of two number of full chunks strictly below n bytes."""
    full_chunks = (n - 1) // CHUNK_LEN
    return CHUNK_LEN << (full_chunks.bit_length() - 1)


def subtree(data, offset, root=False):
    """BLAKE3 tree node over `data`, which starts at byte `offset`."""
    if len(data) <= CHUNK_LEN:
        return chunk_cv(data, offset // CHUNK_LEN, root)
    split = left_len(len(data))
    return parent_cv(
        subtree(data[:split], offset),
        subtree(data[split:], offset + split),
        root,
    )


def blake3(data):
    return to_bytes(subtree(data, 0, root=True))


def rule_input(start, length):
    """Bytes [start, start + length) of the input rule byte[i] = i % 251."""
    period = bytes(range(251))
    head = start % 251
    reps = (head + length) // 251 + 1
    return (period * reps)[head:head + length]


def part_cv(key):
    offset, length = key
    return key, to_bytes(subtree(memoryview(rule_input(offset, length)), offset))


def merge(cvs, part_size, total, lo, hi, root):
    if hi - lo == 1:
        return cvs[lo]
    length = min(hi * part_size, total) - lo * part_size
    mid = lo + left_len(length) // part_size
    return parent_cv(
        merge(cvs, part_size, total, lo, mid, False),
        merge(cvs, part_size, total, mid, hi, False),
        root,
    )


def b3sum(total):
    out = subprocess.run(
        ["b3sum", "--no-names"], input=rule_input(0, total), capture_output=True, check=True
    )
    return out.stdout.decode().strip()


def check_merge(path, only, small_only, use_b3sum, jobs):
    with open(path, encoding="utf-8") as f:
        fixture = json.load(f)
    vectors = [
        v for v in fixture["vectors"]
        if (not only or v["name"] in only) and (not small_only or v["test_geometry"])
    ]
    if only and len(vectors) != len(only):
        sys.exit(f"FAIL: unknown vector in --only: {sorted(only)}")
    keys = sorted({(p["offset"], p["len"]) for v in vectors for p in v["parts"]})
    print(f"hashing {len(keys)} distinct parts "
          f"({sum(k[1] for k in keys) / 2**20:.1f} MiB) with {jobs} jobs", flush=True)
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        cvs = dict(pool.map(part_cv, keys))
    for v in vectors:
        part_size, total = v["part_size"], v["total"]
        parts = v["parts"]
        count = -(-total // part_size)
        assert total > part_size and len(parts) == count, v["name"]
        got = []
        for i, p in enumerate(parts):
            offset = i * part_size
            assert (p["index"], p["offset"], p["len"]) == (
                i, offset, min(part_size, total - offset)), (v["name"], i)
            cv = cvs[(p["offset"], p["len"])]
            if cv.hex() != p["cv"]:
                sys.exit(f"FAIL: {v['name']} part {i}: {cv.hex()} != {p['cv']}")
            got.append(struct.unpack("<8I", cv))
        root = to_bytes(merge(got, part_size, total, 0, count, True)).hex()
        if root != v["root"]:
            sys.exit(f"FAIL: {v['name']} root: {root} != {v['root']}")
        official = b3sum(total) if use_b3sum else None
        if official is not None and official != root:
            sys.exit(f"FAIL: {v['name']} b3sum {official} != {root}")
        print(f"ok {v['name']}: {count} parts, root {root}"
              + (" == b3sum" if official else ""), flush=True)
    return fixture, len(vectors)


def check_part_json(path, merge_fixture):
    try:
        from Crypto.PublicKey import ECC
        from Crypto.Signature import eddsa
    except ImportError:
        sys.exit("FAIL: pycryptodome is required for the part.json check")
    with open(path, encoding="utf-8") as f:
        fx = json.load(f)
    source = next(v for v in merge_fixture["vectors"] if v["name"] == "8mib-2parts-last-1")
    assert fx["subtree"] == source["parts"][1]["cv"] and fx["len"] == source["parts"][1]["len"]
    commitment = f"part:{fx['ticket']}:{fx['index']}:{fx['subtree']}:{fx['len']}"
    assert commitment == fx["commitment"], commitment
    # SPEC-TRANSPORT-CONNECT §7.1: eight newline-separated fields, no final newline.
    canonical = "\n".join([
        "mkit-write:v2", fx["audience"], fx["repository"], fx["procedure"],
        commitment, str(fx["created_at"]), str(fx["expires_at"]), fx["nonce"],
    ])
    assert canonical == fx["canonical"], "canonical string"
    digest = blake3(canonical.encode())
    assert digest.hex() == fx["signing_digest"], "signing digest"
    key = ECC.construct(curve="Ed25519", seed=bytes.fromhex(fx["seed"]))
    public = key.public_key().export_key(format="raw").hex()
    assert public == fx["public_key"], "public key"
    assert fx["repository"] == f"ed25519-{public}/demo", "repository"
    signature = eddsa.new(key, "rfc8032").sign(digest)
    assert signature.hex() == fx["signature"], "signature"
    eddsa.new(key.public_key(), "rfc8032").verify(digest, bytes.fromhex(fx["signature"]))
    print(f"ok part.json: canonical, digest {digest.hex()}, signature")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("merge_json")
    ap.add_argument("--part-json")
    ap.add_argument("--only", help="comma-separated vector names")
    ap.add_argument("--small-only", action="store_true")
    ap.add_argument("--no-b3sum", action="store_true")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    args = ap.parse_args()

    # The published BLAKE3 hash of the empty input.
    assert blake3(b"").hex() == (
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    ), "reference BLAKE3 self-test"
    use_b3sum = not args.no_b3sum
    if use_b3sum and shutil.which("b3sum") is None:
        sys.exit("FAIL: b3sum not found (install it, or pass --no-b3sum)")
    if use_b3sum:
        # The reference agrees with the official CLI on a multi-level tree.
        assert blake3(rule_input(0, 5 * CHUNK_LEN + 7)).hex() == b3sum(5 * CHUNK_LEN + 7)

    only = set(args.only.split(",")) if args.only else None
    fixture, n = check_merge(args.merge_json, only, args.small_only, use_b3sum, args.jobs)
    part_json = args.part_json or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(args.merge_json))), "auth-v2", "part.json"
    )
    check_part_json(part_json, fixture)
    print(f"OK ({n} merge vectors)")


if __name__ == "__main__":
    main()
