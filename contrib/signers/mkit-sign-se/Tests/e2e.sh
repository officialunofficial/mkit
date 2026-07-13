#!/usr/bin/env bash
# e2e.sh — end-to-end smoke test for mkit-sign-se on the v1 protobuf
# `SignerFrame` wire.
#
# Exercises the full flow with no dependency on a built `mkit` binary:
#
#   1. `swift build -c release`
#   2. `mkit-sign-se keygen --tag <random>` — captures the keyid.
#   3. Build a `SignerFrame{Hello}` + `SignerFrame{SignRequest}` byte
#      stream using a small Python helper (because the wire is binary
#      protobuf — not shell-pasteable).
#   4. Pipe it into `mkit-sign-se sign --tag <random>`, parse the
#      stdout frames, extract the signature, and verify it with
#      `openssl` so we prove the wire format matches the spec without
#      mkit in the loop.
#   5. Reject path: send a SignRequest with `algorithm = ED25519` and
#      assert the response is an `Error` frame with
#      `ERROR_CODE_UNSUPPORTED_ALGORITHM`. The signer keeps running on
#      per-request errors (matches mkit-sign-file behaviour), so we
#      let it close stdin to exit cleanly with status 0.
#   6. `mkit-sign-se delete --tag <random>`.
#
# If the Secure Enclave is not available on this host, the script
# exits 0 with a skip message — CI on Intel Macs shouldn't fail.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PKG_DIR"

# -- 0. Detect Secure Enclave -----------------------------------------

probe=$(swift -e 'import CryptoKit; print(SecureEnclave.isAvailable ? "yes" : "no")' 2>/dev/null || echo "no")
if [ "$probe" != "yes" ]; then
  echo "e2e: Secure Enclave not available on this host — skipping"
  exit 0
fi

# -- 1. Build ---------------------------------------------------------

echo "e2e: building release binary"
swift build -c release > /dev/null

BIN="$PKG_DIR/.build/release/mkit-sign-se"
if [ ! -x "$BIN" ]; then
  echo "e2e: expected binary at $BIN" >&2
  exit 1
fi

TAG="mkit-sign-se-e2e-$(date +%s)-$RANDOM"
TMPDIR_LOCAL="$(mktemp -d)"
cleanup() {
  "$BIN" delete --tag "$TAG" >/dev/null 2>&1 || true
  rm -rf "$TMPDIR_LOCAL" 2>/dev/null || true
}
trap cleanup EXIT

# -- 2. keygen --------------------------------------------------------

echo "e2e: keygen --tag $TAG"
KEYID=$("$BIN" keygen --tag "$TAG")
echo "e2e: got keyid $KEYID"
case "$KEYID" in
  p256:*) ;;
  *) echo "e2e: keyid does not start with p256:"; exit 1;;
esac
PUBHEX="${KEYID#p256:}"
if [ "${#PUBHEX}" != 66 ]; then
  echo "e2e: keyid hex length ${#PUBHEX} != 66"; exit 1
fi

# -- 3. Build the request frame stream --------------------------------
#
# Hand-roll minimal protobuf encoding for the two frames we need
# (Hello + SignRequest). We deliberately do NOT bring in `protoc` or
# any Python protobuf runtime — keeps the script dependency-free and
# tests the wire bytes exactly. The schema is in
# `rust/crates/mkit-rpc/proto/mkit/rpc/v1/{common.proto,signer/signer.proto}`.

PAE='DSSEv1 28 application/vnd.in-toto+json 2 {}'
printf '%s' "$PAE" > "$TMPDIR_LOCAL/pae.bin"

# Use python3 to assemble the SignerFrame bytes. python3 ships with
# macOS so this stays a single-host dependency.
python3 - "$TAG" "$TMPDIR_LOCAL/pae.bin" "$TMPDIR_LOCAL/req.bin" \
  "$TMPDIR_LOCAL/bad_req.bin" <<'PY'
import struct
import sys

tag = sys.argv[1]
with open(sys.argv[2], "rb") as f:
    pae = f.read()
out_path = sys.argv[3]
bad_path = sys.argv[4]

# --- Minimal protobuf primitive encoders. We only need:
#   - varint
#   - tag = (field_number << 3) | wire_type  (wire_type: 0 varint, 2 len-delim)
#   - length-delimited (string / bytes / message)

def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)

# `tagfn` (not `tag`) to avoid shadowing the keychain tag argv string.
def tagfn(field: int, wire: int) -> bytes:
    return varint((field << 3) | wire)

def lenprefix(b: bytes) -> bytes:
    return varint(len(b)) + b

def enc_string(field: int, s: str) -> bytes:
    return tagfn(field, 2) + lenprefix(s.encode("utf-8"))

def enc_bytes(field: int, b: bytes) -> bytes:
    return tagfn(field, 2) + lenprefix(b)

def enc_varint(field: int, n: int) -> bytes:
    return tagfn(field, 0) + varint(n)

def enc_msg(field: int, body: bytes) -> bytes:
    return tagfn(field, 2) + lenprefix(body)

# Algorithm + KeyForm + ProtocolVersion enum values (from common.proto):
ALGO_ED25519 = 1
ALGO_P256 = 3
KF_OPAQUE_HANDLE = 3
PV_V1 = 1

# Hello message (Hello in signer.proto, fields 1..3):
#   1: ProtocolVersion protocol  (varint)
#   2: string caller_id          (len-delim)
#   3: bool want_capabilities    (varint, 0/1)
hello_body = (
    enc_varint(1, PV_V1)
    + enc_string(2, "e2e/0.1")
    + enc_varint(3, 1)
)

# SignerFrame oneof body: Hello is field 1, SignRequest is field 3.
hello_frame = enc_msg(1, hello_body)

def sign_request_body(algorithm: int) -> bytes:
    #   1: Algorithm algorithm  (varint)
    #   2: KeyForm key_form     (varint)
    #   3: bytes key_ref        (len-delim) — UTF-8 tag bytes
    #   4: bytes payload        (len-delim)
    return (
        enc_varint(1, algorithm)
        + enc_varint(2, KF_OPAQUE_HANDLE)
        + enc_bytes(3, tag.encode("utf-8"))
        + enc_bytes(4, pae)
    )

sign_request_frame = enc_msg(3, sign_request_body(ALGO_P256))
bad_request_frame = enc_msg(3, sign_request_body(ALGO_ED25519))

# Wire framing: 4-byte little-endian length prefix + body.
def frame(body: bytes) -> bytes:
    return struct.pack("<I", len(body)) + body

ok_stream = frame(hello_frame) + frame(sign_request_frame)
bad_stream = frame(hello_frame) + frame(bad_request_frame)

with open(out_path, "wb") as f:
    f.write(ok_stream)
with open(bad_path, "wb") as f:
    f.write(bad_stream)
PY

# -- 4. Run the signer and parse responses ----------------------------

echo "e2e: signing"
"$BIN" sign --tag "$TAG" < "$TMPDIR_LOCAL/req.bin" > "$TMPDIR_LOCAL/resp.bin"

# Parse out the two response frames. Frame[0] = HelloResponse,
# Frame[1] = SignResponse. We hunt for the wire bytes of the
# `signature` field (tag = (1<<3)|2 = 0x0A) and `public_key` (tag =
# (2<<3)|2 = 0x12) inside the second frame.

python3 - "$TMPDIR_LOCAL/resp.bin" "$KEYID" \
  "$TMPDIR_LOCAL/sig.raw" "$TMPDIR_LOCAL/pubkey.raw" <<'PY'
import struct
import sys

resp_path, expected_keyid, sig_out, pub_out = sys.argv[1:]
with open(resp_path, "rb") as f:
    raw = f.read()

# Iterate framed messages.
frames = []
i = 0
while i + 4 <= len(raw):
    n = struct.unpack_from("<I", raw, i)[0]
    i += 4
    assert i + n <= len(raw), "truncated body"
    frames.append(raw[i:i+n])
    i += n
assert i == len(raw), "trailing bytes"
assert len(frames) == 2, f"want 2 response frames, got {len(frames)}"

def parse_varint(buf, pos):
    out = 0
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        out |= (b & 0x7F) << shift
        if not (b & 0x80):
            return out, pos
        shift += 7

def parse_fields(buf):
    out = {}
    pos = 0
    while pos < len(buf):
        tag, pos = parse_varint(buf, pos)
        field = tag >> 3
        wire = tag & 7
        if wire == 0:
            v, pos = parse_varint(buf, pos)
            out[field] = v
        elif wire == 2:
            ln, pos = parse_varint(buf, pos)
            out[field] = buf[pos:pos+ln]
            pos += ln
        else:
            raise SystemExit(f"unsupported wire type {wire} for field {field}")
    return out

# SignerFrame.body oneof: HelloResponse=2, SignResponse=4, Error=7.
sf0 = parse_fields(frames[0])
assert 2 in sf0, f"frame[0] should contain HelloResponse (field 2); got fields {list(sf0)}"

sf1 = parse_fields(frames[1])
if 7 in sf1:
    err = parse_fields(sf1[7])
    raise SystemExit(f"signer returned Error: {err}")
assert 4 in sf1, f"frame[1] should contain SignResponse (field 4); got fields {list(sf1)}"

sign_resp = parse_fields(sf1[4])
# Fields: signature=1, public_key=2, algorithm=3, key_id=4, certificate_chain=5
sig = sign_resp[1]
pub = sign_resp[2]
keyid = sign_resp[4].decode("utf-8")

assert keyid == expected_keyid, f"keyid {keyid!r} != expected {expected_keyid!r}"
assert len(sig) == 64, f"signature should be 64 bytes, got {len(sig)}"
assert len(pub) == 33, f"public_key should be 33 bytes, got {len(pub)}"

with open(sig_out, "wb") as f:
    f.write(sig)
with open(pub_out, "wb") as f:
    f.write(pub)
PY

# -- 5. Verify the signature via openssl ------------------------------
#
# openssl wants a DER-encoded (r, s) signature and a PEM public key.

python3 - "$TMPDIR_LOCAL/sig.raw" "$TMPDIR_LOCAL/sig.der" \
  "$TMPDIR_LOCAL/pubkey.raw" "$TMPDIR_LOCAL/pubkey.pem" <<'PY'
import base64
import sys

sig_raw, sig_der, pub_raw, pub_pem = sys.argv[1:]
with open(sig_raw, "rb") as f:
    sig = f.read()
assert len(sig) == 64
r = sig[:32]
s = sig[32:]
def der_int(b):
    while len(b) > 1 and b[0] == 0:
        b = b[1:]
    if b[0] & 0x80:
        b = b"\x00" + b
    return bytes([0x02, len(b)]) + b
body = der_int(r) + der_int(s)
der = bytes([0x30, len(body)]) + body
with open(sig_der, "wb") as f:
    f.write(der)

with open(pub_raw, "rb") as f:
    pub = f.read()
assert len(pub) == 33 and pub[0] in (0x02, 0x03)
# SPKI prefix for id-ecPublicKey + prime256v1.
spki_prefix = bytes.fromhex(
    "3039301306072a8648ce3d020106082a8648ce3d030107032200"
)
spki = spki_prefix + pub
pem = b"-----BEGIN PUBLIC KEY-----\n" + base64.encodebytes(spki) + b"-----END PUBLIC KEY-----\n"
with open(pub_pem, "wb") as f:
    f.write(pem)
PY

echo "e2e: verifying signature with openssl"
if ! openssl dgst -sha256 \
  -verify "$TMPDIR_LOCAL/pubkey.pem" \
  -signature "$TMPDIR_LOCAL/sig.der" \
  "$TMPDIR_LOCAL/pae.bin" ; then
  echo "e2e: openssl verify FAILED"; exit 1
fi

# -- 6. Reject path: ed25519 must come back as ERROR_CODE_UNSUPPORTED_ALGORITHM ----

echo "e2e: rejecting non-p256 SignRequest"
"$BIN" sign --tag "$TAG" < "$TMPDIR_LOCAL/bad_req.bin" > "$TMPDIR_LOCAL/bad_resp.bin"

python3 - "$TMPDIR_LOCAL/bad_resp.bin" <<'PY'
import struct
import sys
with open(sys.argv[1], "rb") as f:
    raw = f.read()

frames = []
i = 0
while i + 4 <= len(raw):
    n = struct.unpack_from("<I", raw, i)[0]
    i += 4
    frames.append(raw[i:i+n])
    i += n
assert len(frames) == 2, f"want 2 frames, got {len(frames)}"

def parse_varint(buf, pos):
    out = 0
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        out |= (b & 0x7F) << shift
        if not (b & 0x80):
            return out, pos
        shift += 7

def parse_fields(buf):
    out = {}
    pos = 0
    while pos < len(buf):
        tag, pos = parse_varint(buf, pos)
        field = tag >> 3
        wire = tag & 7
        if wire == 0:
            v, pos = parse_varint(buf, pos)
            out[field] = v
        elif wire == 2:
            ln, pos = parse_varint(buf, pos)
            out[field] = buf[pos:pos+ln]
            pos += ln
        else:
            raise SystemExit(f"unsupported wire type {wire}")
    return out

# Second frame's SignerFrame.body should be Error (field 7).
sf1 = parse_fields(frames[1])
assert 7 in sf1, f"frame[1] should be Error (field 7); got {list(sf1)}"
err = parse_fields(sf1[7])
# Error.code is field 1 (varint). UNSUPPORTED_ALGORITHM = 2.
code = err.get(1, 0)
assert code == 2, f"want ERROR_CODE_UNSUPPORTED_ALGORITHM=2, got {code}"
print(f"e2e: rejected with ERROR_CODE_UNSUPPORTED_ALGORITHM (msg={err.get(2, b'').decode('utf-8', 'replace')!r})")
PY

# -- 7. Done ----------------------------------------------------------

echo "e2e: all checks passed"
