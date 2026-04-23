#!/usr/bin/env bash
# mkit E2E test with ssh:// transport (mkit+ssh://)
#
# Proves the SSH transport rewrite in #8 actually works on the wire:
#   - std.process.spawn(io, …) correctly launches `ssh <host> mkit serve <path>`
#   - OP_HELLO handshake round-trips without losing bytes
#   - readStreaming-based pipe-read loop reaches EOF cleanly on close
#   - clone + push + pull cycle via ssh:// is symmetric with file://
#
# Intended to run INSIDE a Linux container that already has openssh-server
# installed and mkit bind-mounted at /src. See
# `container run ... debian:12-slim bash /src/tests/e2e-ssh.sh`.

set -euo pipefail

PASS=0
FAIL=0

green() { printf "\033[32m%s\033[0m\n" "$1"; }
red()   { printf "\033[31m%s\033[0m\n" "$1"; }
bold()  { printf "\033[1m%s\033[0m\n" "$1"; }

assert() {
    local desc="$1"
    if eval "$2"; then
        green "  ✓ $desc"
        PASS=$((PASS + 1))
    else
        red "  ✗ $desc"
        FAIL=$((FAIL + 1))
    fi
}

mkit_run() {
    "$MKIT" "$@" 2>&1 || true
}

# -----------------------------------------------------------------------------
# Prerequisites: openssh-server + openssh-client
# -----------------------------------------------------------------------------
bold "Installing openssh..."
apt-get update -qq >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server openssh-client >/dev/null

MKIT="/src/zig-out/bin/mkit"
[ -x "$MKIT" ] || { red "error: $MKIT not executable — cross-compile first"; exit 1; }
bold "Using mkit binary: $MKIT ($($MKIT version))"

# Put mkit on PATH for the server-side `ssh user@host mkit serve <path>`
# invocation that SshTransport issues. Without this, sshd's non-login shell
# can't find the binary and `mkit serve` never starts — the client reads
# the shell's "command not found" error instead of our framed OP_HELLO
# response and surfaces it as error.IncompatiblePeer.
ln -sf "$MKIT" /usr/local/bin/mkit

# -----------------------------------------------------------------------------
# Start sshd on 127.0.0.1:2222, passwordless pubkey auth
# -----------------------------------------------------------------------------
SSH_DIR=$(mktemp -d)
HOSTKEY="$SSH_DIR/ssh_host_ed25519_key"
CLIENTKEY="$SSH_DIR/id_ed25519"
SSHD_CONFIG="$SSH_DIR/sshd_config"
AUTHORIZED="$SSH_DIR/authorized_keys"
SSHD_PORT=2222

ssh-keygen -q -N '' -t ed25519 -f "$HOSTKEY"
ssh-keygen -q -N '' -t ed25519 -f "$CLIENTKEY"
cp "$CLIENTKEY.pub" "$AUTHORIZED"

# Minimal sshd config — loopback only, pubkey only, ForceCommand not used so
# the client can pass `mkit serve <path>` as the remote command.
cat > "$SSHD_CONFIG" <<EOF
Port $SSHD_PORT
ListenAddress 127.0.0.1
HostKey $HOSTKEY
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile $AUTHORIZED
StrictModes no
UsePAM no
PidFile $SSH_DIR/sshd.pid
LogLevel QUIET
AcceptEnv PATH
EOF

# sshd needs /var/run/sshd
mkdir -p /var/run/sshd

# Start sshd in the background. -D keeps it in the foreground; we background it
# with &; -e sends logs to stderr for debugging.
/usr/sbin/sshd -f "$SSHD_CONFIG" -E "$SSH_DIR/sshd.log"
SSHD_PID=$(cat "$SSH_DIR/sshd.pid")
bold "sshd PID: $SSHD_PID on port $SSHD_PORT"

cleanup() {
    [ -n "${SSHD_PID:-}" ] && kill "$SSHD_PID" 2>/dev/null || true
    rm -rf "$SSH_DIR" "${REPO_A:-}" "${SEED_REPO:-}" "${REMOTE_BARE:-}" 2>/dev/null || true
}
trap cleanup EXIT

# Loopback smoke — confirm we can SSH into ourselves.
USER_NAME=$(id -un)
SSH_BASE="ssh -i $CLIENTKEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $SSHD_PORT"
$SSH_BASE "$USER_NAME@127.0.0.1" true
bold "ssh loopback works"

# -----------------------------------------------------------------------------
# Set up a "bare" remote directory that `mkit serve` will wrap.
#
# `mkit serve <path>` opens a FileTransport at <path>, which expects the
# push-time layout (refs/heads/... and packs/...) — NOT a full working
# repository with a `.mkit/` wrapper. To produce that layout we push from
# a throwaway seed repo via `mkit+file://`.
# -----------------------------------------------------------------------------
SEED_REPO=$(mktemp -d)
REMOTE_BARE=$(mktemp -d)
cd "$SEED_REPO"
$MKIT init >/dev/null
$MKIT keygen >/dev/null
echo "remote-side file" > seed.txt
$MKIT commit -m "seed commit from remote side" >/dev/null
$MKIT remote set "mkit+file://$REMOTE_BARE" >/dev/null
$MKIT push >/dev/null
REMOTE_HEAD=$(cat "$REMOTE_BARE/refs/heads/main" | tr -d '\n\r ')
bold "remote bare seeded: HEAD=${REMOTE_HEAD:0:16}... at $REMOTE_BARE"

# -----------------------------------------------------------------------------
# Phase 1: Clone over mkit+ssh://
#
# The client is a fresh mkit repo that uses sshd on 127.0.0.1:2222 as its
# transport. On connect, sshd invokes `mkit serve $REMOTE_BARE` as the
# remote command (no ForceCommand — plain exec), which wraps the bare
# directory in a FileTransport and replies to our OP_HELLO.
# -----------------------------------------------------------------------------
bold ""
bold "Phase 1: Clone over mkit+ssh://"
REPO_A=$(mktemp -d)
cd "$REPO_A"
$MKIT init >/dev/null
$MKIT keygen >/dev/null
$MKIT config ssh.strict_host_key_checking no >/dev/null
$MKIT config ssh.user_known_hosts_file /dev/null >/dev/null
$MKIT config ssh.identity_file "$CLIENTKEY" >/dev/null

SSH_URL="mkit+ssh://${USER_NAME}@127.0.0.1:${SSHD_PORT}${REMOTE_BARE}"
bold "SSH URL: $SSH_URL"

REMOTE_SET_OUT=$($MKIT remote set "$SSH_URL" 2>&1)
assert "remote set accepts mkit+ssh:// URL" 'echo "$REMOTE_SET_OUT" | grep -q "remote set"'

PULL_OUT=$($MKIT pull 2>&1)
echo "pull output: $PULL_OUT"
assert "ssh pull fetched the remote head" '[ -f .mkit/refs/heads/main ]'
CLONED_HEAD=$(cat .mkit/refs/heads/main 2>/dev/null | tr -d '\n\r ' || echo "")
assert "cloned HEAD matches remote HEAD" '[ "$CLONED_HEAD" = "$REMOTE_HEAD" ]'

# -----------------------------------------------------------------------------
# Phase 2: Push a new commit back over ssh
# -----------------------------------------------------------------------------
bold ""
bold "Phase 2: Push over mkit+ssh://"
echo "client-side file" > client.txt
$MKIT add client.txt >/dev/null
$MKIT commit -m "client-side commit" >/dev/null
NEW_HEAD=$(cat .mkit/refs/heads/main | tr -d '\n\r ')
assert "new commit exists locally" '[ -n "$NEW_HEAD" ] && [ "$NEW_HEAD" != "$REMOTE_HEAD" ]'

SSH_PUSH_OUT=$($MKIT push 2>&1)
echo "push output: $SSH_PUSH_OUT"
assert "ssh push succeeds" 'echo "$SSH_PUSH_OUT" | grep -q "pushed"'

REMOTE_HEAD_AFTER=$(cat "$REMOTE_BARE/refs/heads/main" | tr -d '\n\r ')
assert "remote HEAD advanced after push" '[ "$REMOTE_HEAD_AFTER" = "$NEW_HEAD" ]'
PACK_COUNT=$(ls "$REMOTE_BARE/packs/" | wc -l | tr -d ' ')
assert "remote has >=2 packs" '[ "$PACK_COUNT" -ge 2 ]'

# === Summary ===
echo ""
bold "====================================="
TOTAL=$((PASS + FAIL))
if [ "$FAIL" -eq 0 ]; then
    green "All $TOTAL tests passed!"
else
    red "$FAIL of $TOTAL tests failed"
    exit 1
fi
