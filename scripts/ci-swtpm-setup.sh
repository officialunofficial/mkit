#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Source this file (do not execute it) from a Cloud Build step that runs the
# TPM tests. It starts a software TPM, runs TPM2_Startup, exports TCTI, and
# sets MKIT_TEST_STRICT=1. The caller's shell stops the daemon on exit.
#
# TPM tests use disposable swtpm state, never the host's measured-boot
# /dev/tpm0. Wait for both simulator ports before initializing it below.
swtpm_state_dir=$(mktemp -d)
swtpm socket --tpmstate dir="$swtpm_state_dir" --tpm2 \
  --server type=tcp,port=2321 --ctrl type=tcp,port=2322 \
  --flags not-need-init &
swtpm_pid=$!
trap 'kill "$swtpm_pid" 2>/dev/null || true' EXIT
export TCTI="swtpm:host=localhost,port=2321"
# Wait for both swtpm ports to accept connections before poking them —
# the daemon above starts asynchronously.
for _ in $(seq 1 50); do
  (exec 3<>/dev/tcp/localhost/2321) 2>/dev/null && (exec 3<>/dev/tcp/localhost/2322) 2>/dev/null && break
  sleep 0.2
done

# A fresh swtpm instance is powered-on but not started — every TPM2
# command fails with TPM_RC_INITIALIZE until TPM2_Startup(CLEAR) runs
# once. No CLI tool for this is baked into the image (tpm2-tools isn't
# installed, only libtss2-dev), so send the fixed 12-byte command
# (TPM2 Part 3 §9.3, no session, no auth — deterministic wire bytes)
# directly to the command port and check for TPM_RC_SUCCESS:
#   tag=TPM_ST_NO_SESSIONS(0x8001) size=12 code=TPM2_Startup(0x144)
#   body=TPM_SU_CLEAR(0x0000)
exec 4<>/dev/tcp/localhost/2321
printf '\x80\x01\x00\x00\x00\x0c\x00\x00\x01\x44\x00\x00' >&4
startup_resp=$(head -c 10 <&4 | od -An -tx1 | tr -d ' \n')
exec 4<&- 4>&-
echo "TPM2_Startup response bytes: $startup_resp"
if [ "${startup_resp: -8}" != "00000000" ]; then
  echo "TPM2_Startup did not return TPM_RC_SUCCESS" >&2
  exit 1
fi

# #505 PR 2/5: this Linux lane provisions both `git` (baked into
# _CI_IMAGE) and a real TPM path (swtpm, above), so tests that would
# otherwise silently `return` green when their tool/feature is missing
# must instead fail loudly here.
export MKIT_TEST_STRICT=1
