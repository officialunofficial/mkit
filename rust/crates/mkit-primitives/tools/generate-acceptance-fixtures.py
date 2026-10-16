#!/usr/bin/env python3
"""Explicit offline fixture generator; requires the Python blake3 package.

Run manually when changing the format contract. Tests consume committed bytes
and expected digests; CI must never regenerate its own expected values.
"""
import copy
import json
from pathlib import Path
import struct
import blake3

OUT = Path(__file__).resolve().parents[1] / "fixtures" / "acceptance"
U32 = 2**32 - 1
U64 = 2**64 - 1
CFG = dict(max_envelope_bytes=4096, max_operation_bytes=32, max_heads=4,
           max_head_bytes=32, max_total_head_bytes=96,
           max_external_dependencies=4, ruleset_id=1,
           profile_limits_digest='11' * 32)
BASE = dict(ruleset_id=1, profile_limits_digest='11' * 32,
            repository='22' * 32, operation='', epoch=0,
            pack=dict(id='33' * 32, len=0, object_count=0, delta_count=0,
                      object_set_root='44' * 32), heads=[],
            external_dependencies=[], membership_generation=0,
            removal_version=0, denial_version=0)


# Fixed public signed-object seeds; individual verification is checked in Rust.
VALID_HEADS = json.loads(r'''
[
  {
    "canonical_bytes": "044d4b54310101010101010101010101010101010101010101010101010101010101010101010000000001000000020202020202020202020202020202020202020202020202020202020202020203030303030303030303030303030303030303030303030303030303030303030120002152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db120500000072656d697865000000000000002152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12bbfa68f592f2c8745efc3571b3932d2b7f1e9984a73ee138c0f8b18b633e401b94d640f3da6fa59eb8a4c799fbd4d93c6ad8ac7fe9eda718cb21e443265a810e",
    "kind": 4,
    "object_id": "55b9787fb80307accbe1e4ec4e2ca8dfa6f97a731e15499d369b4050c183ed0e",
    "signature_result": 1,
    "signer": "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"
  },
  {
    "canonical_bytes": "074d4b5431010303030303030303030303030303030303030303030303030303030303030303030600000076312e302e300120002152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db120300000074616766000000000000002152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12db5f94db7b9268a4a2769656f3d85f68d83e1c7ee4e3f297a5643aea3286a2a9aff9de48adcff3d21f55db1283f3ab2055bfcf7e4626e99527d010458986ef04",
    "kind": 7,
    "object_id": "79f93595ed733c808d54a29198cffafb4cfbd892395c91f2a8b1ae47a3a99cf1",
    "signature_result": 1,
    "signer": "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"
  },
  {
    "canonical_bytes": "034d4b5431010101010101010101010101010101010101010101010101010101010101010101000000000120002152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db1206000000636f6d6d697464000000000000002152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db1200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f3f99f5ccf31a7751c495188666a8d7b816dda5dc955c8ef65fbf9d72a1983ebdfb599c1d9bcfa13442ae37c525c3b354c2ce953a61d27051a968ad17c29eb08",
    "kind": 3,
    "object_id": "adbbec0c318adb5759e9bfbe9a8a75d0c2f2567f5f66ef8745c0266111db8540",
    "signature_result": 1,
    "signer": "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"
  }
]
''')


def u32(n):
    return struct.pack('<I', n)


def u64(n):
    return struct.pack('<Q', n)


def head(n, kind=3, data=None):
    return dict(object_id=f'{n:02x}' * 32, kind=kind, signer='55' * 32,
                signature_result=1,
                canonical_bytes=(data if data is not None else bytes([kind])).hex())


def encode(s):
    op = bytes.fromhex(s['operation'])
    p = s['pack']
    b = (b'MKAE' + struct.pack('<H', 1) + u32(s['ruleset_id'])
         + bytes.fromhex(s['profile_limits_digest'])
         + bytes.fromhex(s['repository']) + u32(len(op)) + op
         + u64(s['epoch']) + bytes.fromhex(p['id']) + u64(p['len'])
         + u64(p['object_count']) + u64(p['delta_count'])
         + bytes.fromhex(p['object_set_root']) + u32(len(s['heads'])))
    for h in s['heads']:
        raw = bytes.fromhex(h['canonical_bytes'])
        b += (bytes.fromhex(h['object_id']) + bytes([h['kind']])
              + bytes.fromhex(h['signer']) + bytes([h['signature_result']])
              + u32(len(raw)) + raw)
    b += u32(len(s['external_dependencies']))
    b += b''.join(bytes.fromhex(d) for d in s['external_dependencies'])
    return (b + u64(s['membership_generation']) + u64(s['removal_version'])
            + u64(s['denial_version']))


def emit(name, description, semantic=None, cfg=None, failure=None, raw=None, recheck=None):
    s = copy.deepcopy(BASE if semantic is None else semantic)
    b = encode(s) if raw is None else raw
    config = copy.deepcopy(CFG if cfg is None else cfg)
    expected = dict(decode='error' if failure else 'ok', failure_code=failure)
    if not failure:
        expected['digest'] = blake3.blake3(
            b'mkit-acceptance-evidence:v1\0' + b).hexdigest()
        expected['recheck_heads'] = (recheck if recheck is not None else
                                    ('EvidenceHeadMismatch' if s['heads'] else 'ok'))
    # Decimal strings preserve every u64 exactly in JSON implementations that
    # otherwise round numbers through IEEE-754 doubles.
    semantic = copy.deepcopy(s)
    for field in ('epoch', 'membership_generation', 'removal_version', 'denial_version'):
        semantic[field] = str(semantic[field])
    for field in ('len', 'object_count', 'delta_count'):
        semantic['pack'][field] = str(semantic['pack'][field])
    metadata = dict(description=description, cfg=config, expected=expected,
                    encoded_len=len(b), semantic=semantic)
    (OUT / f'{name}.bin').write_bytes(b)
    (OUT / f'{name}.json').write_text(json.dumps(metadata, indent=2) + '\n')


def case(**changes):
    s = copy.deepcopy(BASE)
    s.update(changes)
    return s


emit('minimal', 'Empty operation, no heads or dependencies, zero counters.')
representative = case(operation=b'job'.hex(), epoch=8,
                      heads=copy.deepcopy(VALID_HEADS),
                      external_dependencies=['66' * 32, '77' * 32],
                      membership_generation=9, removal_version=10, denial_version=11)
representative['pack'].update(len=4096, object_count=12, delta_count=4)
emit('representative', 'Individually signed canonical Commit, Remix, and Tag heads.',
     representative, cfg=dict(CFG, max_head_bytes=1024, max_total_head_bytes=3072),
     recheck='ok')
boundary = case(epoch=U64, heads=[head(1)], operation='ff' * 32,
                membership_generation=U64, removal_version=U64, denial_version=U64)
boundary['pack'].update(len=U64, object_count=U64, delta_count=U64)
emit('boundary', 'Maximum u64 values and operation bytes at the configured cap.', boundary)

# Each cap pair crosses exactly one configured bound.
b = encode(BASE)
for suffix, maximum, failure in [('cap', len(b), None), ('cap-plus-one', len(b)-1, 'ResourceLimit')]:
    cfg = dict(CFG, max_envelope_bytes=maximum)
    emit('envelope-' + suffix, 'Envelope bytes at cap or one byte over cap.', cfg=cfg, failure=failure)
for suffix, size, failure in [('cap', 3, None), ('cap-plus-one', 4, 'ResourceLimit')]:
    emit('operation-' + suffix, 'Operation bytes at cap or one byte over cap.', case(operation='ab'*size), dict(CFG, max_operation_bytes=3), failure)
    emit('heads-' + suffix, 'Head count at cap or one head over cap.', case(heads=[head(i+1) for i in range(size)]), dict(CFG, max_heads=3), failure)
    emit('head-bytes-' + suffix, 'Single head bytes at cap or one byte over cap.', case(heads=[head(1, data=b'\x03'+b'x'*(size-1))]), dict(CFG, max_head_bytes=3), failure)
    emit('total-head-bytes-' + suffix, 'Aggregate head bytes at cap or one byte over cap.', case(heads=[head(1), head(2, data=b'\x03'+b'x'*(size-2))]), dict(CFG, max_total_head_bytes=3), failure)
    emit('dependencies-' + suffix, 'Dependency count at cap or one dependency over cap.', case(external_dependencies=[f'{i+1:02x}'*32 for i in range(size)]), dict(CFG, max_external_dependencies=3), failure)

# Fixed offsets are deliberately visible to make corruption vectors reviewable.
minimal = encode(BASE)
head_start = 178
# Header 74, operation prefix 4, epoch 8, pack facts 88, head count 4.
assert minimal[174:178] == u32(0)
for name, offset, replacement, failure in [
    ('bad-magic', 0, b'NOPE', 'NonCanonicalEvidence'),
    ('unknown-version', 4, b'\x02\x00', 'UnsupportedEvidenceVersion'),
    ('zero-version', 4, b'\x00\x00', 'UnsupportedEvidenceVersion'),
    ('wrong-ruleset', 6, u32(2), 'EvidenceProfileMismatch'),
    ('wrong-profile', 10, b'\xff'*32, 'EvidenceProfileMismatch'),
    ('operation-length-overflow', 74, u32(U32), 'ResourceLimit'),
    ('head-count-overflow', 174, u32(U32), 'ResourceLimit'),
    ('dependency-count-overflow', 178, u32(U32), 'ResourceLimit')]:
    emit(name, 'Malformed field: ' + name + '.', failure=failure,
         raw=minimal[:offset]+replacement+minimal[offset+len(replacement):])
emit('trailing-bytes', 'One trailing byte after the final version.', failure='NonCanonicalEvidence', raw=minimal+b'\0')
s = case(); s['pack']['delta_count'] = 1
emit('delta-count-exceeds-object-count', 'Delta count cannot exceed object count.', s, failure='NonCanonicalEvidence')
for name, heads in [('duplicate-heads', [head(1), head(1)]), ('unordered-heads', [head(2), head(1)])]:
    emit(name, 'Head ids must be unique and strictly ascending.', case(heads=heads), failure='NonCanonicalEvidence')
for name, deps in [('duplicate-dependencies', ['66'*32]*2), ('unordered-dependencies', ['77'*32, '66'*32])]:
    emit(name, 'Dependency ids must be unique and strictly ascending.', case(external_dependencies=deps), failure='NonCanonicalEvidence')
for name, h in [('unknown-head-kind', head(1, 5)), ('unknown-signature-tag', dict(head(1), signature_result=2)), ('zero-signature-tag', dict(head(1), signature_result=0)), ('head-kind-mismatch', head(1, data=b'\x04')), ('empty-head-bytes', head(1, data=b''))]:
    emit(name, 'Malformed head: ' + name + '.', case(heads=[h]), failure='NonCanonicalEvidence')
one_head = encode(case(heads=[head(1)]))
offset = head_start + 66
emit('head-length-overflow', 'Declared head byte length exceeds its configured bound.', failure='ResourceLimit', raw=one_head[:offset]+u32(U32)+one_head[offset+4:])
# With the corresponding limit at u32::MAX, an impossible declared length/count
# must fail on missing input rather than allocating from the declaration.
for name, offset, cfg in [
    ('operation-length-truncated', 74, dict(CFG, max_operation_bytes=U32)),
    ('head-count-truncated', 174, dict(CFG, max_heads=U32)),
    ('dependency-count-truncated', 178, dict(CFG, max_external_dependencies=U32))]:
    emit(name, 'Unbounded-looking declaration with finite maximum, missing input.', cfg=cfg, failure='UnexpectedEof', raw=minimal[:offset]+u32(U32))
emit('head-length-truncated', 'Maximum declared head bytes with missing payload.', cfg=dict(CFG, max_head_bytes=U32), failure='UnexpectedEof', raw=one_head[:head_start+66]+u32(U32))
for name, raw in [('truncated-magic', minimal[:3]), ('truncated-version', minimal[:5]), ('truncated-profile', minimal[:41]), ('truncated-repository', minimal[:73]), ('truncated-operation-prefix', minimal[:77]), ('truncated-pack', minimal[:173]), ('truncated-head', one_head[:head_start+65]), ('truncated-head-payload', one_head[:head_start+70]), ('truncated-dependency', encode(case(external_dependencies=['66'*32]))[:182+31]), ('truncated-witness', minimal[:-1])]:
    emit(name, 'Truncated field: ' + name + '.', failure='UnexpectedEof', raw=raw)
