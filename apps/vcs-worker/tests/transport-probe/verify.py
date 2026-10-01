#!/usr/bin/env python3
"""Assert caller transport lifetime in the local Rust/DO contract fixture."""
import argparse
import hashlib
import json
from pathlib import Path
import urllib.parse
import urllib.request

MODES = ['success', 'error_status', 'error_body', 'abort_header', 'abort_body',
         'batch_nested', 'batch_error', 'batch_scanner']

def verify(base):
    assert urllib.parse.urlsplit(base).hostname in ('127.0.0.1', 'localhost', '::1')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    records = []
    for mode in MODES:
        with opener.open(base.rstrip('/') + '/' + mode, timeout=5) as response:
            result = json.load(response)
        assert result['atReturn']['active'] == result['after']['active'] == 0, result
        counters = result['atReturn']
        if mode.startswith('batch_'):
            width = 6 if mode == 'batch_scanner' else 4
            assert counters['peak'] == width, result
            assert counters['starts'] == counters['eof'] == width + (mode != 'batch_error'), result
            assert result['outcome'] == ('unavailable' if mode == 'batch_error' else 'joined+nested'), result
            for event in result['events']:
                if event.get('phase') == 'nested':
                    assert event['activeBefore'] == 0, result
        else:
            assert counters['peak'] == counters['starts'] == 1, result
            if mode in ['success', 'error_status']:
                assert counters['eof'] == 1, result
                assert result['elapsed_ms'] >= (100 if mode == 'error_status' else 300), result
            if mode == 'success':
                assert result['outcome'] == 'ok:complete', result
            if mode in ['error_status', 'error_body']:
                assert result['outcome'] == 'unavailable', result
            if mode == 'error_body':
                assert counters['errors'] == 1, result
            if mode.startswith('abort_'):
                assert result['outcome'] == 'dropped' and result['elapsed_ms'] < 250, result
                assert counters['errors'] + counters['cancel'] == 1, result
        records.append(result)
    return records

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    fixture = Path(__file__).resolve().parent
    pins = {str(p.relative_to(fixture)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in fixture.rglob('*') if p.is_file() and ('build' in p.parts or p.name in
                ['Cargo.toml', 'Cargo.lock', 'lib.rs', 'wrapper.mjs', 'verify.py'])
            and 'target' not in p.parts}
    evidence = {'scope': 'local caller EOF/error/abort; producer work may continue',
                'passes': 8, 'source_and_artifact_sha256': pins, 'records': verify(args.url)}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(evidence, indent=2) + '\n')
    print('PASS 8 local transport contracts; active outgoing zero on return and after drain')
