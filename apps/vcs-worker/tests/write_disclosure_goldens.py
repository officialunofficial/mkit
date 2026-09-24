"""Gated exact subject JSON/HTTP-contract vectors; normal tests only read."""
import json
import os
from pathlib import Path

import blake3

ROOT = Path(__file__).resolve().parents[3] / "rust/tests/golden/hosted-disclosure"
BASE = "17963c328bb4a65dfffb659125df822a5a8b0aaca309c245c569420e243f8d90"
REQUEST = {"version": 1, "workspace_id": "1" * 64,
           "grant_id": "2" * 64, "grant_generation": "1",
           "expected_ref": "refs/heads/main", "expected_base": BASE,
           "paths": [["shallow.txt"]]}


def compact(value):
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode()


def main():
    if os.environ.get("MKIT_WRITE_GOLDEN") != "1":
        raise SystemExit("set MKIT_WRITE_GOLDEN=1 to rewrite committed vectors")
    ROOT.mkdir(parents=True, exist_ok=True)
    normal = compact(REQUEST)
    wrong_base = compact({**REQUEST, "expected_base": "0" * 64})
    duplicate_path = compact({**REQUEST, "paths": [["shallow.txt"], ["shallow.txt"]]})
    duplicate_field = normal.replace(b'"grant_id":', b'"grant_id":"' + b'2' * 64 + b'","grant_id":', 1)
    bundle = (ROOT.parent / "partial_workspace/plain_file.bin").read_bytes()
    vectors = {
        "get.json": normal,
        "wrong-base.json": wrong_base,
        "duplicate-path.json": duplicate_path,
        "duplicate-field.json": duplicate_field,
        "invalid-argument-response.json": compact({"code": "invalid_argument"}),
        "permission-denied-response.json": compact({"code": "permission_denied"}),
        "conflict-response.json": compact({"code": "conflict"}),
        "resource-exhausted-response.json": compact({"code": "resource_exhausted"}),
        "unavailable-response.json": compact({"code": "unavailable"}),
    }
    meta = {
        "get.meta.json": {"method": "POST", "path": "/mkit/partial/v1/GetWorkspace",
                          "content_type": "application/json", "status": 200,
                          "response_content_type": "application/octet-stream",
                          "response_length": len(bundle),
                          "response_digest": blake3.blake3(bundle).hexdigest(),
                          "response_ref": "../partial_workspace/plain_file.bin",
                          "cache_control": "private, no-store"},
        "wrong-base.meta.json": {"method": "POST", "path": "/mkit/partial/v1/GetWorkspace",
                                 "content_type": "application/json", "status": 409,
                                 "response": "conflict-response.json"},
        "duplicate-path.meta.json": {"method": "POST", "path": "/mkit/partial/v1/GetWorkspace",
                                     "content_type": "application/json", "status": 400,
                                     "response": "invalid-argument-response.json"},
        "duplicate-field.meta.json": {"method": "POST", "path": "/mkit/partial/v1/GetWorkspace",
                                      "content_type": "application/json", "status": 400,
                                      "response": "invalid-argument-response.json"},
    }
    for name, value in meta.items():
        vectors[name] = compact(value)
    for name, value in vectors.items():
        (ROOT / name).write_bytes(value)
    manifest = "# BLAKE3 of exact UTF-8 bytes including final LF; rewrite only with MKIT_WRITE_GOLDEN=1.\n"
    for name, value in sorted(vectors.items()):
        manifest += f"{blake3.blake3(value).hexdigest()}  {name}\n"
    (ROOT / "MANIFEST.txt").write_text(manifest)


if __name__ == "__main__":
    main()
