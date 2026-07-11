#!/usr/bin/env bash
# e2e.sh — end-to-end smoke test for mkit-sign-ctap on the v1 protobuf
# `SignerFrame` wire (SPEC-EXTERNAL-SIGNER / SPEC-RPC).
#
# Requires a physical FIDO2 roaming authenticator plugged into the host.
# If no authenticator is present, the script exits 0 with a skip message
# so CI on machines with no USB devices doesn't fail.
#
# Steps (when an authenticator is present):
#   1. `cargo build -p mkit-sign-ctap --release`.
#   2. `mkit-sign-ctap enroll --rp-id <rpid> --user-name <name>` —
#      captures the keyid and resolves the credential_id.
#   3. Build a `SignerFrame{Hello}` + `SignerFrame{SignRequest}` byte
#      stream with a small Python helper (the wire is binary protobuf,
#      not shell-pasteable). The SignRequest carries
#      `algorithm = ALGORITHM_P256` with an empty `key_ref` so the
#      signer falls back to the argv `--credential-id` default
#      (KEY_FORM_RAW_BYTES path, per SPEC-EXTERNAL-SIGNER §8.2).
#   4. Pipe it into `mkit-sign-ctap sign --credential-id <id>`, parse the
#      response frames, extract `signature`, `public_key`, and the
#      `webauthn` extension (authenticator_data + client_data_json), then
#      verify the WebAuthn assertion with `openssl` over
#      `authenticator_data || SHA-256(client_data_json)` — no built
#      `mkit` in the loop.
#   5. Reject path: send a SignRequest with `algorithm = ALGORITHM_ED25519`
#      and assert the response is an `Error` frame with
#      `ERROR_CODE_UNSUPPORTED_ALGORITHM`. The signer keeps running on
#      per-request errors, so it exits cleanly when stdin closes.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_DIR="$(dirname "$SCRIPT_DIR")"
WORKSPACE_DIR="$(cd "$PKG_DIR/../../../rust" && pwd)"
cd "$PKG_DIR"

# -- 0. Detect an attached authenticator ----------------------------

# Probe over USB. macOS: `ioreg -p IOUSB` + grep; Linux: `lsusb`.
# Skip cleanly if nothing plausibly FIDO-branded is attached.
probe_usb() {
  case "$(uname -s)" in
    Darwin)
      ioreg -p IOUSB 2>/dev/null | grep -iE 'yubikey|nitrokey|solokey|feitian|onlykey' || true
      ;;
    Linux)
      lsusb 2>/dev/null | grep -iE 'yubikey|nitrokey|solokey|feitian|onlykey' || true
      ;;
    *)
      ;;
  esac
}

if [ -z "$(probe_usb)" ]; then
  echo "e2e: no FIDO2 authenticator detected — skipping"
  exit 0
fi

# -- 1. Build -------------------------------------------------------

echo "e2e: building mkit-sign-ctap"
cargo build --manifest-path "$WORKSPACE_DIR/Cargo.toml" -p mkit-sign-ctap --release > /dev/null

BIN="$WORKSPACE_DIR/target/release/mkit-sign-ctap"
if [ ! -x "$BIN" ]; then
  echo "e2e: expected binary at $BIN" >&2
  exit 1
fi

TMPDIR_LOCAL="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_LOCAL"' EXIT

# -- 2. Enroll ------------------------------------------------------

RP_ID="mkit-ctap-e2e.local"
USER_NAME="e2e-user-$(date +%s)"
echo "e2e: enrolling — touch the authenticator when it flashes"
KEYID=$("$BIN" enroll --rp-id "$RP_ID" --user-name "$USER_NAME")
echo "e2e: got keyid $KEYID"
case "$KEYID" in
  p256:*|webauthn:*) ;;
  *) echo "e2e: unexpected keyid prefix: $KEYID"; exit 1;;
esac

# Pull the (base64url) credential id out of the metadata store.
STORE="$HOME/.mkit-sign-ctap/credentials.json"
if [ ! -f "$STORE" ]; then
  echo "e2e: credential store not written at $STORE"; exit 1
fi
CRED_ID=$("$BIN" list-credentials | grep "keyid=$KEYID" | head -n1 | sed -E 's/^credential_id=([^\t]+).*$/\1/')
if [ -z "$CRED_ID" ]; then
  echo "e2e: could not resolve credential_id for $KEYID"; exit 1
fi
echo "e2e: credential_id $CRED_ID"

# -- 3. Build the request frame stream ------------------------------
#
# Hand-roll minimal protobuf encoding for the two frames we need
# (Hello + SignRequest). No `protoc` / protobuf runtime dependency —
# the schema is in `rust/crates/mkit-rpc/proto/mkit/rpc/v1/{common.proto,signer/signer.proto}`.
# `key_ref` is left empty so the signer uses its argv `--credential-id`
# default (the KEY_FORM_RAW_BYTES fallback documented in the spec).

PAE='DSSEv1 28 application/vnd.in-toto+json 2 {}'
printf '%s' "$PAE" > "$TMPDIR_LOCAL/pae.bin"

python3 - "$TMPDIR_LOCAL/pae.bin" "$TMPDIR_LOCAL/req.bin" \
  "$TMPDIR_LOCAL/bad_req.bin" <<'PY'
import struct
import sys

with open(sys.argv[1], "rb") as f:
    pae = f.read()
out_path = sys.argv[2]
bad_path = sys.argv[3]

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

# Enum values (from common.proto).
ALGO_ED25519 = 1
ALGO_P256 = 3
KF_RAW_BYTES = 1
PV_V1 = 1

# Hello: protocol=1, caller_id=2, want_capabilities=3.
hello_body = enc_varint(1, PV_V1) + enc_string(2, "e2e/0.1") + enc_varint(3, 1)
hello_frame = enc_msg(1, hello_body)

def sign_request_body(algorithm: int) -> bytes:
    # algorithm=1, key_form=2, key_ref=3 (empty → argv default), payload=4.
    return (
        enc_varint(1, algorithm)
        + enc_varint(2, KF_RAW_BYTES)
        + enc_bytes(3, b"")
        + enc_bytes(4, pae)
    )

sign_request_frame = enc_msg(3, sign_request_body(ALGO_P256))
bad_request_frame = enc_msg(3, sign_request_body(ALGO_ED25519))

def frame(body: bytes) -> bytes:
    return struct.pack("<I", len(body)) + body

with open(out_path, "wb") as f:
    f.write(frame(hello_frame) + frame(sign_request_frame))
with open(bad_path, "wb") as f:
    f.write(frame(hello_frame) + frame(bad_request_frame))
PY

# -- 4. Run the signer and verify the WebAuthn assertion ------------

echo "e2e: signing — touch the authenticator when it flashes"
"$BIN" sign --credential-id "$CRED_ID" --rp-id "$RP_ID" \
  < "$TMPDIR_LOCAL/req.bin" > "$TMPDIR_LOCAL/resp.bin"

python3 - "$TMPDIR_LOCAL/resp.bin" "$TMPDIR_LOCAL/signed.bin" \
  "$TMPDIR_LOCAL/sig.der" "$TMPDIR_LOCAL/pubkey.pem" <<'PY'
import base64
import hashlib
import struct
import sys

resp_path, signed_out, sig_der_out, pub_pem_out = sys.argv[1:]
with open(resp_path, "rb") as f:
    raw = f.read()

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
assert 2 in sf0, f"frame[0] should contain HelloResponse (field 2); got {list(sf0)}"

sf1 = parse_fields(frames[1])
if 7 in sf1:
    err = parse_fields(sf1[7])
    raise SystemExit(f"signer returned Error: {err}")
assert 4 in sf1, f"frame[1] should contain SignResponse (field 4); got {list(sf1)}"

# SignResponse: signature=1, public_key=2, algorithm=3, key_id=4,
# certificate_chain=5, webauthn=6.
sign_resp = parse_fields(sf1[4])
sig = sign_resp[1]
pub = sign_resp[2]
assert len(sig) == 64, f"signature should be 64 bytes, got {len(sig)}"
assert len(pub) == 65 and pub[0] == 0x04, f"public_key should be 65-byte uncompressed SEC1, got {len(pub)}"
assert 6 in sign_resp, "SignResponse missing webauthn extension (field 6)"

# WebAuthnData: authenticator_data=1, client_data_json=2.
webauthn = parse_fields(sign_resp[6])
auth_data = webauthn[1]
client_data_json = webauthn[2]
assert len(auth_data) >= 37, f"authenticator_data too short: {len(auth_data)}"
assert b'"type":"webauthn.get"' in client_data_json.replace(b" ", b""), \
    f"client_data_json type is not webauthn.get: {client_data_json!r}"

# The WebAuthn signed input is authenticator_data || SHA-256(client_data_json).
signed = auth_data + hashlib.sha256(client_data_json).digest()
with open(signed_out, "wb") as f:
    f.write(signed)

# DER-encode the compact (r, s) signature for openssl.
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
with open(sig_der_out, "wb") as f:
    f.write(der)

# SPKI prefix for id-ecPublicKey + prime256v1 with a 65-byte
# uncompressed point.
spki_prefix = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
spki = spki_prefix + pub
pem = b"-----BEGIN PUBLIC KEY-----\n" + base64.encodebytes(spki) + b"-----END PUBLIC KEY-----\n"
with open(pub_pem_out, "wb") as f:
    f.write(pem)
PY

echo "e2e: verifying WebAuthn assertion with openssl"
if ! openssl dgst -sha256 \
  -verify "$TMPDIR_LOCAL/pubkey.pem" \
  -signature "$TMPDIR_LOCAL/sig.der" \
  "$TMPDIR_LOCAL/signed.bin" ; then
  echo "e2e: openssl verify FAILED"; exit 1
fi

# -- 5. Reject path: ed25519 must come back as ERROR_CODE_UNSUPPORTED_ALGORITHM ----

echo "e2e: rejecting non-p256 SignRequest"
"$BIN" sign --credential-id "$CRED_ID" --rp-id "$RP_ID" \
  < "$TMPDIR_LOCAL/bad_req.bin" > "$TMPDIR_LOCAL/bad_resp.bin"

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

sf1 = parse_fields(frames[1])
assert 7 in sf1, f"frame[1] should be Error (field 7); got {list(sf1)}"
err = parse_fields(sf1[7])
code = err.get(1, 0)
assert code == 2, f"want ERROR_CODE_UNSUPPORTED_ALGORITHM=2, got {code}"
print(f"e2e: rejected with ERROR_CODE_UNSUPPORTED_ALGORITHM (msg={err.get(2, b'').decode('utf-8', 'replace')!r})")
PY

echo "e2e: all checks passed"
