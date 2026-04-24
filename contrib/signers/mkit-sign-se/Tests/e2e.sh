#!/usr/bin/env bash
# e2e.sh — end-to-end smoke test for mkit-sign-se.
#
# Exercises the full flow with no dependency on a built `mkit` binary:
#
#   1. `swift build -c release`
#   2. `mkit-sign-se keygen --tag <random>` — captures the pubkey.
#   3. Pipe a known PAE into `mkit-sign-se sign --tag <random>`.
#   4. Verify the signature with `openssl` so we prove the wire format
#      matches SPEC-EXTERNAL-SIGNER §4 without mkit in the loop.
#   5. Reject path: pipe `{"algorithm":"ed25519"}` and assert exit 2.
#   6. `mkit-sign-se delete --tag <random>`.
#
# If the Secure Enclave is not available on this host, the script exits
# 0 with a skip message — CI on Intel Macs shouldn't fail on this.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PKG_DIR"

# -- 0. Detect Secure Enclave -----------------------------------------

# We ship a trivial probe: run the binary with no subcommand; we know
# it won't call SEP, so we can't detect availability that way. Use a
# short Swift script instead.
probe=$(swift -e 'import CryptoKit; print(SecureEnclave.isAvailable ? "yes" : "no")' 2>/dev/null || echo "no")
if [ "$probe" != "yes" ]; then
  echo "e2e: Secure Enclave not available on this host — skipping"
  exit 0
fi

# -- 1. Build -----------------------------------------------------

echo "e2e: building release binary"
swift build -c release > /dev/null

BIN="$PKG_DIR/.build/release/mkit-sign-se"
if [ ! -x "$BIN" ]; then
  echo "e2e: expected binary at $BIN" >&2
  exit 1
fi

# Unique tag so re-runs don't collide and we never touch a real user's keys.
TAG="mkit-sign-se-e2e-$(date +%s)-$RANDOM"
cleanup() {
  "$BIN" delete --tag "$TAG" >/dev/null 2>&1 || true
  rm -f "$TMPDIR_LOCAL/pae.bin" "$TMPDIR_LOCAL/pubkey.hex" \
        "$TMPDIR_LOCAL/sig.raw" "$TMPDIR_LOCAL/sig.der" \
        "$TMPDIR_LOCAL/pubkey.pem" 2>/dev/null || true
  rmdir "$TMPDIR_LOCAL" 2>/dev/null || true
}
TMPDIR_LOCAL="$(mktemp -d)"
trap cleanup EXIT

# -- 2. keygen ----------------------------------------------------

echo "e2e: keygen --tag $TAG"
KEYID=$("$BIN" keygen --tag "$TAG")
echo "e2e: got keyid $KEYID"
case "$KEYID" in
  p256:*) ;;
  *) echo "e2e: keyid does not start with p256:"; exit 1;;
esac

# Hex of the compressed pubkey (strip the prefix).
PUBHEX="${KEYID#p256:}"
if [ "${#PUBHEX}" != 66 ]; then
  echo "e2e: keyid hex length ${#PUBHEX} != 66"; exit 1
fi

# -- 3. sign ------------------------------------------------------

# Use the same PAE the SPEC worked examples use.
PAE='DSSEv1 28 application/vnd.in-toto+json 2 {}'
printf '%s' "$PAE" > "$TMPDIR_LOCAL/pae.bin"
PAE_B64=$(base64 -i "$TMPDIR_LOCAL/pae.bin" | tr -d '\n')

REQ="{\"pae_base64\":\"$PAE_B64\",\"algorithm\":\"p256\"}"
echo "e2e: request: $REQ"
RESP=$(printf '%s\n' "$REQ" | "$BIN" sign --tag "$TAG")
echo "e2e: response: $RESP"

# Parse out keyid + sig_base64 with a micro grep — no jq dependency.
RESP_KEYID=$(printf '%s' "$RESP" | sed -E 's/.*"keyid":"([^"]+)".*/\1/')
RESP_SIGB64=$(printf '%s' "$RESP" | sed -E 's/.*"sig_base64":"([^"]+)".*/\1/')

if [ "$RESP_KEYID" != "$KEYID" ]; then
  echo "e2e: response keyid '$RESP_KEYID' != keygen keyid '$KEYID'"; exit 1
fi

# Decode the compact signature (64 bytes).
printf '%s' "$RESP_SIGB64" | base64 -d > "$TMPDIR_LOCAL/sig.raw"
SIGLEN=$(wc -c < "$TMPDIR_LOCAL/sig.raw" | tr -d ' ')
if [ "$SIGLEN" != 64 ]; then
  echo "e2e: raw signature length $SIGLEN != 64"; exit 1
fi

# -- 4. Verify via openssl ----------------------------------------
#
# openssl wants a DER-encoded (r, s) signature and a PEM public key.
# Build both from the raw materials.

# Split r / s (each 32 bytes). Use Python to DER-encode because
# portable shell arithmetic for ASN.1 lengths is painful.
python3 - <<PY
import sys, binascii
sig = open("$TMPDIR_LOCAL/sig.raw","rb").read()
assert len(sig) == 64
r = sig[:32]
s = sig[32:]
def der_int(b):
    # Strip leading zero bytes, but keep at least one byte.
    while len(b) > 1 and b[0] == 0:
        b = b[1:]
    # Prepend 0x00 if high bit set (INTEGER must be non-negative).
    if b[0] & 0x80:
        b = b"\x00" + b
    return bytes([0x02, len(b)]) + b
body = der_int(r) + der_int(s)
der  = bytes([0x30, len(body)]) + body
open("$TMPDIR_LOCAL/sig.der","wb").write(der)
PY

# Build an SEC1 uncompressed pubkey from the compressed one. openssl
# `ec` can read SubjectPublicKeyInfo (SPKI) DER/PEM directly — easiest
# to hand-assemble the SPKI DER from the compressed bytes.
python3 - <<PY
import binascii, base64
pub_hex = "$PUBHEX"
pub = bytes.fromhex(pub_hex)
assert len(pub) == 33 and pub[0] in (0x02, 0x03)
# SPKI prefix for id-ecPublicKey + prime256v1, then BIT STRING with
# the raw SEC1-compressed key. DER bytes are standard.
spki_prefix = bytes.fromhex(
    "3039301306072a8648ce3d020106082a8648ce3d030107032200"
)  # SEQ len=0x39, AlgId SEQ len=0x13, OID ecPublicKey, OID prime256v1,
   # BIT STRING len=0x22 unusedbits=0x00.
spki = spki_prefix + pub
pem = b"-----BEGIN PUBLIC KEY-----\n" + base64.encodebytes(spki) + b"-----END PUBLIC KEY-----\n"
open("$TMPDIR_LOCAL/pubkey.pem","wb").write(pem)
PY

echo "e2e: verifying signature with openssl"
if ! openssl dgst -sha256 \
  -verify "$TMPDIR_LOCAL/pubkey.pem" \
  -signature "$TMPDIR_LOCAL/sig.der" \
  "$TMPDIR_LOCAL/pae.bin" ; then
  echo "e2e: openssl verify FAILED"; exit 1
fi

# -- 5. Reject wrong algorithm ------------------------------------

echo "e2e: rejecting non-p256 request"
BAD_REQ="{\"pae_base64\":\"$PAE_B64\",\"algorithm\":\"ed25519\"}"
set +e
printf '%s\n' "$BAD_REQ" | "$BIN" sign --tag "$TAG" >"$TMPDIR_LOCAL/stdout" 2>"$TMPDIR_LOCAL/stderr"
rc=$?
set -e
if [ "$rc" != 2 ]; then
  echo "e2e: expected exit 2 for bad algorithm, got $rc"; exit 1
fi
if [ -s "$TMPDIR_LOCAL/stdout" ]; then
  echo "e2e: stdout should be empty on error, got $(cat "$TMPDIR_LOCAL/stdout")"; exit 1
fi
if ! grep -q "P-256" "$TMPDIR_LOCAL/stderr"; then
  echo "e2e: stderr missing expected P-256 reject message: $(cat "$TMPDIR_LOCAL/stderr")"; exit 1
fi

# -- 6. Done ------------------------------------------------------

echo "e2e: all checks passed"
