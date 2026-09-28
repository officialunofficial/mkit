#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Validate SPEC-SERVER §16 fixtures, signatures, audit chain and proto JSON.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

python3 - <<'PY'
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile

root = Path('rust/tests/golden/admin')
types = {
    'takedown.request.json': 'TakedownRequest',
    'takedown.response.json': 'TakedownResponse',
    'set-lease.request.json': 'SetLeaseRequest',
    'set-lease.response.json': 'SetLeaseResponse',
    'set-suspension.request.json': 'SetSuspensionRequest',
    'set-suspension.response.json': 'SetSuspensionResponse',
    'release-hold.request.json': 'ReleaseHoldRequest',
    'release-hold.response.json': 'ReleaseHoldResponse',
    'read-audit-log.request.json': 'ReadAuditLogRequest',
    'read-audit-log.response.json': 'ReadAuditLogResponse',
}

def digest(data):
    return subprocess.run(['b3sum', '--no-names'], input=data, capture_output=True,
                          check=True).stdout.decode().split()[0]

def check(condition, message):
    if not condition:
        raise SystemExit('check-server-admin-goldens: ' + message)

manifest = {}
for line in (root / 'MANIFEST.txt').read_text().splitlines():
    if line.startswith('#') or not line:
        continue
    name, hash_hex = line.split()
    check(name not in manifest, f'duplicate manifest entry {name}')
    manifest[name] = hash_hex
files = {p.name for p in root.iterdir() if p.is_file() and p.name != 'MANIFEST.txt'}
check(set(manifest) == files, 'manifest coverage mismatch')
for name, hash_hex in manifest.items():
    check(digest((root / name).read_bytes()) == hash_hex, f'manifest hash mismatch: {name}')

for name, message_type in types.items():
    source = json.loads((root / name).read_bytes())
    proc = subprocess.run(['buf', 'convert', 'proto', '--type',
                           'mkit.server.admin.v1.' + message_type,
                           '--from', f'{root / name}#format=json',
                           '--to', '-#format=json'], capture_output=True, check=True)
    check(source == json.loads(proc.stdout), f'proto JSON round-trip changed {name}')

check('receipt' not in json.loads((root / 'set-lease.response.json').read_text()),
      'lease receipt must be disabled in the fixture')
check('receipt' not in json.loads((root / 'set-suspension.response.json').read_text()),
      'suspension receipt must be disabled in the fixture')
check(json.loads((root / 'takedown.request.json').read_text())['reasonToken'] == 'policy',
      'takedown reason token missing')
check(json.loads((root / 'set-suspension.request.json').read_text())['reasonToken'] == 'policy',
      'suspension reason token missing')

vectors = json.loads((root / 'signature.json').read_text())['vectors']
check(len(vectors) == 3, 'expected three signature vectors')
with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
    temp = Path(tmp)
    for v in vectors:
        body = (root / v['body_file']).read_bytes()
        body_digest = 'body:' + digest(body)
        canonical = '\n'.join(['mkit-admin:v1', v['key_id'], v['audience'],
                               v['procedure'], body_digest, v['created_at_ms'],
                               v['expires_at_ms'], v['nonce']])
        check(v['body_utf8'].encode() == body, 'signed body bytes mismatch')
        check(v['body_digest'] == body_digest, 'body digest mismatch')
        check(v['canonical'] == canonical, 'canonical envelope mismatch')
        check(v['canonical_blake3'] == digest(canonical.encode()), 'envelope hash mismatch')
        check(v['test_key_label'].startswith('TEST KEY ONLY:'), 'test key not labelled')
        check(0 < int(v['expires_at_ms']) - int(v['created_at_ms']) <= 300000,
              'invalid validity interval')
        check(len(v['nonce']) == 64 and v['nonce'] == v['nonce'].lower(), 'invalid nonce')
        expected_headers = {
            'X-Mkit-Admin-Version': '1', 'X-Mkit-Admin-Key-Id': v['key_id'],
            'X-Mkit-Admin-Audience': v['audience'],
            'X-Mkit-Admin-Created-At': v['created_at_ms'],
            'X-Mkit-Admin-Expires-At': v['expires_at_ms'],
            'X-Mkit-Admin-Nonce': v['nonce'], 'X-Mkit-Admin-Digest': body_digest,
            'X-Mkit-Admin-Signature': v['signature'],
        }
        check(v['headers'] == expected_headers, 'signature headers mismatch')
        (temp / 'public.der').write_bytes(bytes.fromhex('302a300506032b6570032100' + v['public_key']))
        (temp / 'message.bin').write_bytes(bytes.fromhex(v['canonical_blake3']))
        (temp / 'signature.bin').write_bytes(bytes.fromhex(v['signature']))
        verified = subprocess.run(['openssl', 'pkeyutl', '-verify', '-rawin', '-pubin',
                                   '-inkey', str(temp / 'public.der'), '-keyform', 'DER',
                                   '-sigfile', str(temp / 'signature.bin'),
                                   '-in', str(temp / 'message.bin')], capture_output=True)
        check(verified.returncode == 0, f'Ed25519 verification failed: {v["procedure"]}')
        keys = json.loads((root / 'key-list.json').read_text())['keys']
        check(any(k['keyId'] == v['key_id'] and k['publicKey'] == v['public_key']
                  for k in keys), 'signature key absent from role list')

chain = json.loads((root / 'audit-chain.json').read_text())
entries = chain['entries']
check(len(entries) == 3, 'expected three audit entries')
check(entries[2]['actor'] == vectors[2]['key_id'] and
      entries[2]['result']['code'] == 'permission_denied',
      'wrong-role audit entry must use the lease key')
prev = '00' * 32
for seq, entry in enumerate(entries, 1):
    check(entry['seq'] == str(seq), 'audit sequence gap')
    check(entry['prevHash'] == prev, 'audit previous hash mismatch')
    check(all(field in entry for field in ('actor', 'procedure', 'requestDigest',
          'nonce', 'targets', 'result', 'details', 'prevHash')),
          'required audit field missing')
    check(all(field in entry['result'] for field in ('code', 'message')),
          'audit result incomplete')
    payload = dict(entry)
    del payload['entryHash']
    jcs = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    prev = digest(b'mkit-admin-audit:v1' + jcs)
    check(entry['entryHash'] == prev, 'audit entry hash mismatch')
check(chain['chainHead'] == prev and chain['chainHeadSeq'] == '3', 'audit head mismatch')
response = json.loads((root / 'read-audit-log.response.json').read_text())
check(response['chainHead'] == base64.b64encode(bytes.fromhex(prev)).decode(),
      'export head mismatch')
check(len(response['entries']) == 3, 'export entry count mismatch')
for a, b in zip(entries, response['entries']):
    exported = dict(a)
    for field in ('prevHash', 'entryHash'):
        exported[field] = base64.b64encode(bytes.fromhex(a[field])).decode()
    check(b == exported, 'export entry differs from chained entry')
print('check-server-admin-goldens: schema, manifest, signatures and audit chain pass')
PY
