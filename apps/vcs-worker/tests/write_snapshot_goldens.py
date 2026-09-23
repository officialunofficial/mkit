"""Explicitly gated exact owner Snapshot JSON vectors; normal tests only read."""
import json
import os
from pathlib import Path

import blake3

ROOT = Path(__file__).resolve().parents[3] / "rust/tests/golden/hosted-snapshots"
JOB = "1" * 64
HEAD = "4abfdbe86069ccca918d7dc343b9a94195f0bf79e25c27dfd5471934a5862d0e"
TIP = "038c1bf0672fe8b85ddfbc0e3d40fa4fa63bdcd81b26e59ff31dc934fdabadf9"
SELECTED = [
    "8e2184619013163d0857df52c1f08f3c838e2ee1ec020778b9ad3e5e04574ec4",
    "b3d8bce275d8405c07465a037493d32bb3908920974328b3e54e34ac236ee2b9",
    "e0ea1258b14646471d4723dc81f77986d34bb1713683b7b3aaf4ff1490c9d761",
]


def compact(value):
    return (json.dumps(value, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def progress(packs="0", entries="0", objects="0", bytes_="0", work="0",
             attempts="0", reserved="0", operations="0"):
    return dict(catalog_packs=packs, catalog_entries=entries,
                reached_objects=objects, reached_bytes=bytes_, work_units=work,
                attempts=attempts, reserved_io_bytes=reserved,
                r2_operations=operations)


def job(revision, state, counters, generation="1"):
    return dict(version=1, job_id=JOB, job_generation=generation, revision=revision,
                state=state, progress=counters)


REQUESTS = {
    "begin.json": ("BeginSnapshot", dict(version=1, job_id=JOB,
        ref="refs/heads/snapshot-test", expected_head=HEAD, expected_packmap=TIP,
        selected_pack_keys=SELECTED), "begin-response.json", 200),
    "continue.json": ("ContinueSnapshot", dict(version=1, job_id=JOB,
        job_generation="1", expected_revision="0"), "continue-response.json", 200),
    "get.json": ("GetSnapshotJob", dict(version=1, job_id=JOB), "ready-response.json", 200),
    "cancel.json": ("CancelSnapshot", dict(version=1, job_id=JOB,
        job_generation="1", expected_revision="0"), "cancel-response.json", 200),
    "cleanup.json": ("CleanupSnapshots", dict(version=1,
        expected_cleanup_revision="0", max_rows=64), "cleanup-response.json", 200),
    "invalid-decimal.json": ("ContinueSnapshot", dict(version=1, job_id=JOB,
        job_generation="01", expected_revision="0"), "invalid-argument-response.json", 400),
    "invalid-duplicate.json": ("GetSnapshotJob", None, "invalid-argument-response.json", 400),
}

RESPONSES = {
    "begin-response.json": job("0", "catalog", progress()),
    "continue-response.json": job("1", "catalog", progress(attempts="1", reserved="103", operations="2")),
    "ready-response.json": job("10", "ready", progress("3", "4", "4", "2449", "6", "10", "5253", "13")),
    "cancel-response.json": job("0", "cancelled", progress(), generation="2"),
    "cleanup-response.json": dict(version=1, cleanup_revision="1", affected_rows="0", has_more=False),
    "pending-response.json": dict(version=1, code="in_progress", job_id=JOB),
}
for code in ("invalid_argument", "unauthenticated", "not_found", "method_not_allowed",
             "conflict", "resource_exhausted", "unsupported_media_type", "unsupported_profile",
             "unavailable"):
    RESPONSES[code.replace("_", "-") + "-response.json"] = {"code": code}


def main():
    if os.environ.get("MKIT_WRITE_GOLDEN") != "1":
        raise SystemExit("set MKIT_WRITE_GOLDEN=1 to rewrite committed vectors")
    ROOT.mkdir(parents=True, exist_ok=True)
    files = {}
    for name, (method, value, response, status) in REQUESTS.items():
        files[name] = (b'{"version":1,"job_id":"' + JOB.encode() +
                       b'","job_id":"' + JOB.encode() + b'"}\n') if value is None else compact(value)
        files[name.replace(".json", ".meta.json")] = compact(dict(method="POST",
            path="/mkit/host/v1/" + method, status=status, response=response))
    for name, value in RESPONSES.items():
        files[name] = compact(value)
    for name, body in files.items():
        (ROOT / name).write_bytes(body)
    manifest = "# BLAKE3 of exact UTF-8 bytes including final LF; rewrite only with MKIT_WRITE_GOLDEN=1.\n"
    for name, body in sorted(files.items()):
        if not name.endswith(".meta.json"):
            manifest += f"{blake3.blake3(body).hexdigest()}  {name}\n"
    (ROOT / "MANIFEST.txt").write_text(manifest)


if __name__ == "__main__":
    main()
