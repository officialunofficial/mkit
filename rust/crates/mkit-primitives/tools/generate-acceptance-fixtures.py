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


def emit(name, description, semantic=None, cfg=None, failure=None, raw=None):
    s = copy.deepcopy(BASE if semantic is None else semantic)
    b = encode(s) if raw is None else raw
    config = copy.deepcopy(CFG if cfg is None else cfg)
    expected = dict(decode='error' if failure else 'ok', failure_code=failure)
    if not failure:
        expected['digest'] = blake3.blake3(
            b'mkit-acceptance-evidence:v1\0' + b).hexdigest()
        expected['recheck_heads'] = ('EvidenceHeadMismatch' if s['heads'] else 'ok')
    metadata = dict(description=description, cfg=config, expected=expected,
                    encoded_len=len(b), semantic=s)
    (OUT / f'{name}.bin').write_bytes(b)
    (OUT / f'{name}.json').write_text(json.dumps(metadata, indent=2) + '\n')


def case(**changes):
    s = copy.deepcopy(BASE)
    s.update(changes)
    return s


emit('minimal', 'Empty operation, no heads or dependencies, zero counters.')
representative = case(operation=b'job'.hex(), epoch=8,
                      heads=[head(1, 3), head(2, 4), head(3, 7)],
                      external_dependencies=['66' * 32, '77' * 32],
                      membership_generation=9, removal_version=10, denial_version=11)
representative['pack'].update(len=4096, object_count=12, delta_count=4)
emit('representative', 'All supported head kinds; synthetic object bytes exercise only the codec.', representative)
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
