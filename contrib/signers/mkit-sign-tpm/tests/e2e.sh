#!/usr/bin/env bash
# e2e.sh — end-to-end smoke test for mkit-sign-tpm.
#
# Exercises the full flow with no dependency on a built `mkit` binary:
#
#   1. Detect a TPM (kernel rm device OR `swtpm` available). If neither
#      is present, exit 0 with a skip message — macOS and TPM-less CI
#      shouldn't fail on this.
#   2. `cargo build --release -p mkit-sign-tpm --features tpm2`.
#   3. `mkit-sign-tpm keygen --handle 0x81010001` — captures the pubkey.
#   4. Pipe a known PAE into `mkit-sign-tpm sign --handle 0x81010001`.
#   5. Verify the signature with `openssl` so we prove the wire format
#      matches SPEC-EXTERNAL-SIGNER §4 without mkit in the loop.
#   6. Reject path: pipe `{"algorithm":"ed25519"}` and assert exit 2.
#   7. `mkit-sign-tpm delete --handle 0x81010001`.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_DIR="$(dirname "$SCRIPT_DIR")"
# Rust workspace root sits at <repo>/rust.
WORKSPACE_ROOT="$(cd "$PKG_DIR/../../../rust" && pwd)"

# -- 0. Detect TPM --------------------------------------------------

have_tpm_dev() {
  [ -e /dev/tpmrm0 ] || [ -e /dev/tpm0 ]
}
have_swtpm() {
  command -v swtpm >/dev/null 2>&1
}

if ! have_tpm_dev && ! have_swtpm; then
  echo "e2e: no TPM device (/dev/tpmrm0, /dev/tpm0) and no swtpm simulator — skipping"
  echo "e2e: to run on Linux, install libtss2-dev + tpm2-tools, or install swtpm"
  exit 0
fi

# -- 1. Build -------------------------------------------------------

echo "e2e: building release binary with --features tpm2"
(
  cd "$WORKSPACE_ROOT"
  cargo build --release -p mkit-sign-tpm --features tpm2 >/dev/null
)

BIN="$WORKSPACE_ROOT/target/release/mkit-sign-tpm"
if [ ! -x "$BIN" ]; then
  echo "e2e: expected binary at $BIN" >&2
  exit 1
fi

# Pick a handle unlikely to collide with anything the user has. Using
# a random low byte so parallel runs (CI shards) don't stomp each
# other.
HANDLE="0x810101$(printf '%02x' $((RANDOM % 256)))"
TMPDIR_LOCAL="$(mktemp -d)"
cleanup() {
  "$BIN" delete --handle "$HANDLE" >/dev/null 2>&1 || true
  rm -rf "$TMPDIR_LOCAL"
}
trap cleanup EXIT

# -- 2. keygen ------------------------------------------------------

echo "e2e: keygen --handle $HANDLE"
KEYID=$("$BIN" keygen --handle "$HANDLE")
echo "e2e: got keyid $KEYID"
case "$KEYID" in
  p256:*) ;;
  *) echo "e2e: keyid does not start with p256:"; exit 1;;
esac
PUBHEX="${KEYID#p256:}"
if [ "${#PUBHEX}" != 66 ]; then
  echo "e2e: keyid hex length ${#PUBHEX} != 66"; exit 1
fi

# -- 3. sign --------------------------------------------------------

PAE='DSSEv1 28 application/vnd.in-toto+json 2 {}'
printf '%s' "$PAE" > "$TMPDIR_LOCAL/pae.bin"
PAE_B64=$(base64 -w0 < "$TMPDIR_LOCAL/pae.bin" 2>/dev/null || base64 < "$TMPDIR_LOCAL/pae.bin" | tr -d '\n')

REQ="{\"pae_base64\":\"$PAE_B64\",\"algorithm\":\"p256\"}"
echo "e2e: request: $REQ"
RESP=$(printf '%s\n' "$REQ" | "$BIN" sign --handle "$HANDLE")
echo "e2e: response: $RESP"

RESP_KEYID=$(printf '%s' "$RESP" | sed -E 's/.*"keyid":"([^"]+)".*/\1/')
RESP_SIGB64=$(printf '%s' "$RESP" | sed -E 's/.*"sig_base64":"([^"]+)".*/\1/')

if [ "$RESP_KEYID" != "$KEYID" ]; then
  echo "e2e: response keyid '$RESP_KEYID' != keygen keyid '$KEYID'"; exit 1
fi

printf '%s' "$RESP_SIGB64" | base64 -d > "$TMPDIR_LOCAL/sig.raw"
SIGLEN=$(wc -c < "$TMPDIR_LOCAL/sig.raw" | tr -d ' ')
if [ "$SIGLEN" != 64 ]; then
  echo "e2e: raw signature length $SIGLEN != 64"; exit 1
fi

# -- 4. Verify via openssl -----------------------------------------

python3 - <<PY
sig = open("$TMPDIR_LOCAL/sig.raw","rb").read()
assert len(sig) == 64, len(sig)
r = sig[:32]
s = sig[32:]
def der_int(b):
    while len(b) > 1 and b[0] == 0:
        b = b[1:]
    if b[0] & 0x80:
        b = b"\x00" + b
    return bytes([0x02, len(b)]) + b
body = der_int(r) + der_int(s)
der  = bytes([0x30, len(body)]) + body
open("$TMPDIR_LOCAL/sig.der","wb").write(der)
PY

python3 - <<PY
import base64
pub = bytes.fromhex("$PUBHEX")
assert len(pub) == 33 and pub[0] in (0x02, 0x03)
# SPKI prefix for id-ecPublicKey + prime256v1, BIT STRING with the
# 33-byte SEC1-compressed key.
spki_prefix = bytes.fromhex("3039301306072a8648ce3d020106082a8648ce3d030107032200")
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

# -- 5. Reject wrong algorithm -------------------------------------

echo "e2e: rejecting non-p256 request"
BAD_REQ="{\"pae_base64\":\"$PAE_B64\",\"algorithm\":\"ed25519\"}"
set +e
printf '%s\n' "$BAD_REQ" | "$BIN" sign --handle "$HANDLE" \
  >"$TMPDIR_LOCAL/stdout" 2>"$TMPDIR_LOCAL/stderr"
rc=$?
set -e
if [ "$rc" != 2 ]; then
  echo "e2e: expected exit 2 for bad algorithm, got $rc"
  cat "$TMPDIR_LOCAL/stderr" >&2
  exit 1
fi
if [ -s "$TMPDIR_LOCAL/stdout" ]; then
  echo "e2e: stdout should be empty on error, got $(cat "$TMPDIR_LOCAL/stdout")"; exit 1
fi
if ! grep -q -i "p256\|p-256" "$TMPDIR_LOCAL/stderr"; then
  echo "e2e: stderr missing expected p256 reject message: $(cat "$TMPDIR_LOCAL/stderr")"; exit 1
fi

echo "e2e: all checks passed"
