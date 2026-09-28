#!/usr/bin/env python3
"""Verify SPEC-SERVER §14 fixtures without a server implementation."""

import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent
GOLDEN = ROOT / "rust/tests/golden/redaction"
DETAIL_TYPE = "mkit.transport.v1.RedactionNotice"
PAYLOAD_TYPE = "application/vnd.mkit.redaction-notice.v1+json"


def canonical(value):
    # The pinned fixture uses ASCII keys and values and integer numbers,
    # the subset for which this encoding is JCS byte-for-byte.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def run(*args, input_bytes=None):
    result = subprocess.run(args, input=input_bytes, capture_output=True, check=True)
    return result.stdout


def read_json(name):
    return json.loads((GOLDEN / name).read_bytes())


def verify_manifest():
    listed = {}
    for line in (GOLDEN / "MANIFEST.txt").read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        name, digest = line.split()
        assert name not in listed
        listed[name] = digest
    actual = {path.name for path in GOLDEN.iterdir() if path.name != "MANIFEST.txt"}
    assert set(listed) == actual, (set(listed) ^ actual)
    for name, digest in listed.items():
        got = run("b3sum", str(GOLDEN / name)).decode().split()[0]
        assert got == digest, name


def verify_signature(payload_bytes, envelope):
    seed = bytes.fromhex((GOLDEN / "test-seed.hex").read_text().strip())
    public = bytes.fromhex((GOLDEN / "test-public-key.hex").read_text().strip())
    assert len(seed) == len(public) == 32
    key_id = run("b3sum", input_bytes=public).decode().split()[0]
    assert envelope["signatures"][0]["keyid"] == "blake3:" + key_id
    assert json.loads(payload_bytes)["keyId"] == key_id
    private_der = bytes.fromhex("302e020100300506032b657004220420") + seed
    public_der = bytes.fromhex("302a300506032b6570032100") + public
    derived = run("openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER", input_bytes=private_der)
    assert derived == public_der
    pae = (b"DSSEv1 " + str(len(PAYLOAD_TYPE)).encode() + b" " + PAYLOAD_TYPE.encode()
           + b" " + str(len(payload_bytes)).encode() + b" " + payload_bytes)
    signature = base64.b64decode(envelope["signatures"][0]["sig"], validate=True)
    with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as temp:
        temp = Path(temp)
        (temp / "public.der").write_bytes(public_der)
        (temp / "pae.bin").write_bytes(pae)
        (temp / "signature.bin").write_bytes(signature)
        run("openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(temp / "public.der"),
            "-keyform", "DER", "-rawin", "-in", str(temp / "pae.bin"),
            "-sigfile", str(temp / "signature.bin"))


def verify_proto(name, type_name):
    json_path = GOLDEN / (name + ".json")
    bin_path = GOLDEN / (name + ".bin")
    expected_json = json.loads(json_path.read_bytes())
    canonical_json = run("buf", "convert", "proto", "--type", "mkit.transport.v1." + type_name,
                         "--from", str(bin_path) + "#format=binpb", "--to", "-#format=json")
    assert canonical_json == json_path.read_bytes(), name
    got_json = json.loads(canonical_json)
    assert got_json == expected_json, name
    got_bin = run("buf", "convert", "proto", "--type", "mkit.transport.v1." + type_name,
                  "--from", str(json_path) + "#format=json", "--to", "-#format=binpb")
    assert got_bin == bin_path.read_bytes(), name


def main():
    verify_manifest()
    for prefix in ("notice", "ingest"):
        payload_bytes = (GOLDEN / (prefix + "-payload.jcs.json")).read_bytes()
        envelope_bytes = (GOLDEN / (prefix + "-envelope.dsse.json")).read_bytes()
        payload = json.loads(payload_bytes)
        envelope = json.loads(envelope_bytes)
        assert canonical(payload) == payload_bytes
        assert canonical(envelope) == envelope_bytes
        assert envelope["payloadType"] == PAYLOAD_TYPE
        assert base64.b64decode(envelope["payload"], validate=True) == payload_bytes
        assert len(envelope["signatures"]) == 1
        assert len(envelope_bytes) <= 262144
        assert payload["rewrites"] == sorted(payload["rewrites"], key=lambda row: (row["type"], row["old"]))
        verify_signature(payload_bytes, envelope)
        if prefix == "ingest":
            assert payload["repository"] == "" and payload["rewrites"] == []
            assert payload["takedownId"] == ""
        else:
            assert payload["repository"] and payload["rewrites"]
    for name, type_name in (("detail", "RedactionNotice"), ("read-ref", "ReadRefResponse"),
                            ("list-refs", "ListRefsResponse"),
                            ("ingest-detail", "RedactionNotice")):
        verify_proto(name, type_name)
    detail = read_json("detail.json")
    assert base64.b64decode(detail["envelope"], validate=True) == (GOLDEN / "notice-envelope.dsse.json").read_bytes()
    ingest_detail = read_json("ingest-detail.json")
    assert base64.b64decode(ingest_detail["envelope"], validate=True) == (GOLDEN / "ingest-envelope.dsse.json").read_bytes()
    assert read_json("read-ref.json")["redactionNotices"] == [detail]
    assert read_json("list-refs.json")["refRedactions"] == [{"ref": "refs/heads/main", "notice": detail}]
    for name, code, message in (("ingest-blocked", "permission_denied", "object blocked"),
                                ("open-closure", "invalid_argument", "open closure"),
                                ("delta-base", "failed_precondition", "delta base not available in this repository"),
                                ("superseded-pack", "not_found", "pack not found")):
        body = read_json("error-" + name + ".json")
        detail_file = "ingest-detail.bin" if name == "ingest-blocked" else "detail.bin"
        detail_b64 = base64.b64encode((GOLDEN / detail_file).read_bytes()).decode().rstrip("=")
        assert body == {"code": code, "message": message,
                        "details": [{"type": DETAIL_TYPE, "value": detail_b64}]}, name
    print("check-redaction-goldens: 18 artifacts, signatures, protobuf and Connect bodies verified")


if __name__ == "__main__":
    main()
