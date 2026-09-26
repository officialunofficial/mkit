#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Validate SPEC-SERVER §15 fixtures against the hooks schema and canonical JSON.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
golden_dir="rust/tests/golden/server-hooks"

# Filename-to-message table. Keep in sync with SPEC-SERVER §15.
message_type() {
  local fixture_name="$1" name type
  while read -r name type; do
    if [[ "$name" == "$fixture_name" ]]; then
      printf '%s\n' "$type"
      return 0
    fi
  done <<'TABLE'
authorize.request.json AuthorizeRequest
authorize-allow.response.json AuthorizeResponse
authorize-deny.response.json AuthorizeResponse
admit.request.json AdmitRequest
admit-allow.response.json AdmitResponse
admit-challenge.response.json AdmitResponse
admit-deny.response.json AdmitResponse
inspect.request.json InspectRequest
inspect-pass.response.json InspectResponse
outcome-committed.request.json OutcomeRequest
outcome-aborted.request.json OutcomeRequest
outcome-abandoned.request.json OutcomeRequest
outcome-expired.request.json OutcomeRequest
outcome-read-served.request.json OutcomeRequest
outcome.response.json OutcomeResponse
TABLE
  echo "check-server-hooks-goldens: no message type for $fixture_name" >&2
  return 1
}

for tool in buf jq; do
  command -v "$tool" >/dev/null || {
    echo "check-server-hooks-goldens: $tool is required" >&2
    exit 1
  }
done

count=0
for file in "$golden_dir"/*.request.json "$golden_dir"/*.response.json; do
  [[ -f "$file" ]] || continue
  type="$(message_type "${file##*/}")"
  converted="$(buf convert proto --type "mkit.server.hooks.v1.$type" \
    --from "$file#format=json" --to '-#format=json')"
  expected="$(jq -S . "$file")"
  actual="$(printf '%s\n' "$converted" | jq -S .)"
  if [[ "$expected" != "$actual" ]]; then
    echo "check-server-hooks-goldens: $file changed after schema round-trip" >&2
    diff -u <(printf '%s\n' "$expected") <(printf '%s\n' "$actual") >&2 || true
    exit 1
  fi
  count=$((count + 1))
done

if [[ "$count" -ne 15 ]]; then
  echo "check-server-hooks-goldens: expected 15 mapped fixtures, found $count" >&2
  exit 1
fi
echo "check-server-hooks-goldens: all $count fixtures preserve canonical protobuf JSON"
