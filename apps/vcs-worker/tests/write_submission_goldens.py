"""Explicitly gated vectors for the hosted staged-submission wire contract."""
import json
import os
import struct
from pathlib import Path

import blake3

ROOT = Path(__file__).resolve().parents[3] / "rust/tests/golden/hosted-submissions"
OP = "33" * 32
WORKSPACE = "11" * 32
GRANT = "22" * 32
SUBMISSION = "44" * 32


def compact(value):
    return (json.dumps(value, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def progress():
    return dict(inventory_entries="0", base_objects="0", changed_pairs="0",
                required_objects="0", candidate_objects="0", attempts="0",
                reserved_io_bytes="0", r2_operations="0")


REQUESTS = {
    "begin.json": dict(version=1, operation_id=OP, workspace_id=WORKSPACE,
        grant_id=GRANT, grant_generation="1", expected_ref="refs/heads/main",
        expected_base="aa" * 32, update_digest="bb" * 32, update_len="8",
        selected_paths=[["docs", "a.md"], ["src", "main.rs"]]),
    "continue.json": dict(version=1, operation_id=OP, submission_id=SUBMISSION,
        submission_generation="1", expected_revision="0"),
    "get.json": dict(version=1, operation_id=OP),
    "cleanup.json": dict(version=1, expected_cleanup_revision="0", max_rows=64),
}

RESPONSES = {
    "begin-response.json": dict(version=1, operation_id=OP, submission_id=SUBMISSION,
        submission_generation="1", revision="0", state="awaiting_upload", progress=progress()),
    "continue-response.json": dict(version=1, operation_id=OP, submission_id=SUBMISSION,
        submission_generation="1", revision="1", state="validating", progress=progress()),
    "get-response.json": dict(version=1, operation_id=OP, submission_id=SUBMISSION,
        submission_generation="1", revision="0", state="awaiting_upload", progress=progress()),
    "cleanup-response.json": dict(version=1, cleanup_revision="1", affected_rows="0", has_more=False),
}


def binding_digest(begin_body):
    audience = b"https://host.example"
    repository = b"test-repository"
    material = (b"mkit/hosted-submission-binding/v1\0" +
        struct.pack("<I", len(audience)) + audience +
        struct.pack("<I", len(repository)) + repository +
        bytes([0x55]) * 32 + struct.pack("<I", 1) + struct.pack("<I", 1) +
        blake3.blake3(begin_body).digest())
    return blake3.blake3(material).hexdigest()


def main():
    if os.environ.get("MKIT_WRITE_GOLDEN") != "1":
        raise SystemExit("set MKIT_WRITE_GOLDEN=1 to rewrite committed vectors")
    ROOT.mkdir(parents=True, exist_ok=True)
    files = {name: compact(value) for name, value in {**REQUESTS, **RESPONSES}.items()}
    for name, value in REQUESTS.items():
        route = {
            "begin.json": "/mkit/partial/v1/BeginSubmission",
            "continue.json": "/mkit/partial/v1/ContinueSubmission",
            "get.json": "/mkit/partial/v1/GetStagedSubmission",
            "cleanup.json": "/mkit/host/v1/CleanupSubmissions",
        }[name]
        files[name.replace(".json", ".meta.json")] = compact(dict(
            method="POST", path=route,
            response=name.replace(".json", "-response.json"),
            status=200, content_type="application/json"))
    begin = files["begin.json"]
    prefix = (b"MKSU" + bytes([1]) + bytes([0x33]) * 32 + bytes([0x44]) * 32 +
              struct.pack("<Q", 1) + struct.pack("<Q", 8))
    files["upload.bin"] = prefix + b"MKWUdemo"
    files["upload.meta.json"] = compact(dict(
        method="POST", path="/mkit/partial/v1/UploadSubmission",
        content_type="application/octet-stream", prefix_bytes=85,
        offsets=dict(magic=[0, 4], version=[4, 5], operation_id=[5, 37],
                     submission_id=[37, 69], generation_le=[69, 77], carrier_len_le=[77, 85]),
        declared_len="8", carrier_note="Opaque carrier bytes; this decoder does not validate MKWU."))
    files["binding.json"] = compact(dict(audience="https://host.example",
        repository="test-repository", subject_key="55" * 32,
        begin_body_blake3=blake3.blake3(begin).hexdigest(), binding_blake3=binding_digest(begin)))
    for name, body in files.items():
        (ROOT / name).write_bytes(body)
    manifest = "# BLAKE3 of exact bytes; JSON vectors include a final LF. Rewrite only with MKIT_WRITE_GOLDEN=1.\n"
    for name, body in sorted(files.items()):
        manifest += f"{blake3.blake3(body).hexdigest()}  {name}\n"
    (ROOT / "MANIFEST.txt").write_text(manifest)


if __name__ == "__main__":
    main()
