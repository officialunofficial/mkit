"""Disposable local workerd/SQLite Snapshot fences and bounded cleanup.

Set MKIT_SNAPSHOT_TEST_STATE to an isolated Wrangler --persist-to directory.
Only `--patch-*` modes edit SQLite; stop Wrangler before invoking them.
"""

import json
import os
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import blake3

sys.argv.insert(1, "http://localhost:8791")
from managed_access import admin, expect, make_headers
from managed_data import OWNER, SERVICE, code, field, frame, rpc, send, signed_headers

STATE = os.environ.get("MKIT_SNAPSHOT_TEST_STATE")
if not STATE or not Path(STATE).name.startswith("mkit-c1-workerd."):
    raise RuntimeError("set MKIT_SNAPSHOT_TEST_STATE to disposable mkit-c1-workerd.* state")


def db_path():
    matches = []
    for path in Path(STATE).glob("v3/do/*-RefStore/[0-9a-f]*.sqlite"):
        with sqlite3.connect(path) as db:
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='host_snapshot_jobs'").fetchone():
                matches.append(path)
    assert len(matches) == 1, matches
    return matches[0]


def request(method, value):
    return admin(method, json.dumps(value, separators=(",", ":")).encode())


def state(job):
    return expect(200, request("GetSnapshotJob", {"version": 1, "job_id": job}))


def begin(fixture, suffix, digit):
    return request("BeginSnapshot", {"version": 1, "job_id": digit * 64,
        "ref": "refs/heads/snap-" + suffix,
        "expected_head": fixture["root"], "expected_packmap": fixture["tip"],
        "selected_pack_keys": fixture["selected"]})


def continue_job(job, generation, revision):
    return request("ContinueSnapshot", {"version": 1, "job_id": job,
        "job_generation": generation, "expected_revision": revision})


def saved_rows():
    with sqlite3.connect(db_path()) as db:
        return {name: list(db.execute("SELECT * FROM " + name + " ORDER BY 1"))
                for name in ("authenticated_operations", "host_snapshot_jobs", "host_snapshot_meta")}


def rewrite_job(db, job_id, changes):
    row = db.execute("SELECT document FROM host_snapshot_jobs WHERE job_id=?", (job_id,)).fetchone()
    assert row, job_id
    document = json.loads(row[0])
    document.update(changes)
    encoded = json.dumps(document, separators=(",", ":"))
    checksum = blake3.blake3(b"mkit.host.snapshot.job.v1\0" + encoded.encode()).hexdigest()
    db.execute("UPDATE host_snapshot_jobs SET document=?,checksum=?,state=?,idle_deadline=?,terminal_deadline=? WHERE job_id=?",
               (encoded, checksum, document["state"], document["idle_deadline"],
                document["terminal_deadline"], job_id))


def fixture():
    directory = os.environ.get("MKIT_SNAPSHOT_SMALL_FIXTURE")
    if not directory:
        raise RuntimeError("set MKIT_SNAPSHOT_SMALL_FIXTURE to snapshot_fixture output")
    return json.loads((Path(directory) / "manifest.json").read_bytes())


def seed_live():
    f = fixture()
    assert admin("InitializePolicy", b'{"version":1,"collaborators":[]}')[0] == 200
    for path in sorted(Path(os.environ["MKIT_SNAPSHOT_SMALL_FIXTURE"]).glob("*.pack")):
        payload = path.read_bytes()
        key = path.stem
        assert blake3.blake3(payload).hexdigest() == key
        pack_id = bytes.fromhex(key)
        wire = frame(field(1, field(1, pack_id) + field(2, len(payload))))
        wire += frame(field(2, field(1, pack_id) + field(2, 0) + field(3, payload) + field(4, 1)))
        method = SERVICE + "UploadPack"
        headers = signed_headers(method, b"", OWNER, "pack:" + key + ":" + str(len(payload)),
                                 "application/connect+proto")
        result = send(method, wire, headers)
        assert code(*result[:2]) == "ok", result
    for suffix in "abcd":
        name = "refs/heads/snap-" + suffix
        update = (field(1, name) + field(2, 2) + field(4, bytes.fromhex(f["root"]))
                  + field(5, "refs/mkit/packmap/snap-" + suffix)
                  + field(6, 2) + field(8, bytes.fromhex(f["tip"])))
        response = rpc("AdvanceRefs", update, OWNER)
        assert code(*response[:2]) == "ok", response
    first = expect(200, begin(f, "a", "1"))
    one = saved_rows()
    expect(429, begin(f, "a", "4"))
    assert saved_rows() == one, "per-ref duplicate must not allocate a nonce"
    second = expect(200, begin(f, "b", "2"))
    assert first["job_generation"] == "1" and second["job_generation"] == "2"
    before = saved_rows()
    expect(429, begin(f, "c", "3"))
    assert saved_rows() == before, "rejected Begin must not allocate a nonce"
    print("two live slots full; third Begin 429 without effects")


def patch_idle():
    with sqlite3.connect(db_path()) as db:
        for digit in "12":
            rewrite_job(db, digit * 64, {"idle_deadline": 0})
    print("offline disposable idle deadlines patched")


def verify_idle():
    first = expect(200, request("CleanupSnapshots", {"version": 1,
        "expected_cleanup_revision": "0", "max_rows": 1}))
    assert first == {"version": 1, "cleanup_revision": "1", "affected_rows": "1", "has_more": True}, first
    assert sorted([state(d * 64)["state"] for d in "12"]) == ["catalog", "expired"]
    second = expect(200, request("CleanupSnapshots", {"version": 1,
        "expected_cleanup_revision": "1", "max_rows": 1}))
    assert second["affected_rows"] == "1" and not second["has_more"], second
    assert all(state(d * 64)["state"] == "expired" for d in "12")
    f = fixture()
    third = expect(200, begin(f, "c", "3"))
    assert third["job_generation"] == "5", third
    expect(409, continue_job("1" * 64, "1", "0"))
    print("Cleanup max_rows=1 fenced both idle jobs and restored admission")


def patch_high():
    high = "9007199254740993"
    with sqlite3.connect(db_path()) as db:
        rewrite_job(db, "3" * 64, {"generation": high, "revision": high,
                                  "attempt_seq": high})
        row = json.loads(db.execute("SELECT document FROM host_snapshot_meta WHERE slot=1").fetchone()[0])
        row["generation"] = high
        db.execute("UPDATE host_snapshot_meta SET document=? WHERE slot=1",
                   (json.dumps(row, separators=(",", ":")),))
    print("offline disposable high u64 TEXT fields patched")


def verify_high():
    high = "9007199254740993"
    got = state("3" * 64)
    assert got["job_generation"] == high and got["revision"] == high, got
    result = continue_job("3" * 64, high, high)
    assert result[0] == 200, result
    with sqlite3.connect(db_path()) as db:
        record = json.loads(db.execute("SELECT document FROM host_snapshot_jobs WHERE job_id=?",
                                 ("3" * 64,)).fetchone()[0])
    assert record["attempt_seq"] == str(int(high) + 1), record
    assert result[1]["revision"] == str(int(high) + 1), result
    print("high u64 generation/revision/attempt sequence roundtripped without JS precision loss")


def patch_exhaust():
    with sqlite3.connect(db_path()) as db:
        rewrite_job(db, "3" * 64, {"attempts": 8192, "reserved_io_bytes": 2 * 1024 * 1024 * 1024,
                                  "r2_operations": 8192 * 66, "attempt_deadline": 0})
    print("offline disposable attempt and cumulative budgets patched to cap")


def verify_exhaust():
    job = state("3" * 64)
    before = saved_rows()
    expect(429, continue_job("3" * 64, job["job_generation"], job["revision"]))
    assert saved_rows() == before, "cap rejection must not allocate nonce or mutate job"
    print("8192 attempts/2GiB/540672 R2 ops refused without effects")


def patch_overflow():
    with sqlite3.connect(db_path()) as db:
        rewrite_job(db, "3" * 64, {"attempts": 1, "reserved_io_bytes": 0,
                                  "r2_operations": 0, "attempt_seq": str(2**64 - 1)})
    print("offline disposable attempt_seq patched to u64 maximum")


def verify_overflow():
    job = state("3" * 64)
    before = saved_rows()
    expect(503, continue_job("3" * 64, job["job_generation"], job["revision"]))
    assert saved_rows() == before, "overflow refusal must rollback auth reservation"
    print("u64 attempt_seq overflow fails closed without effects")


def verify_interleave():
    """Run on --seed-live state with SNAPSHOT_TEST_R2_PAUSE_MS=3000."""
    first = state("1" * 64)
    body = json.dumps({"version": 1, "job_id": "1" * 64,
        "job_generation": first["job_generation"],
        "expected_revision": first["revision"]}, separators=(",", ":")).encode()
    headers = make_headers("/mkit/host/v1/ContinueSnapshot", body)
    with ThreadPoolExecutor(max_workers=1) as executor:
        inflight = executor.submit(admin, "ContinueSnapshot", body, signed_headers=headers)
        time.sleep(0.5)
        start = time.perf_counter()
        expect(200, admin("GetPolicy", b'{"version":1}'))
        assert (time.perf_counter() - start) < 1.5, "owner admin blocked by R2 wait"
        pending = expect(202, admin("ContinueSnapshot", body, signed_headers=headers))
        assert pending == {"version": 1, "code": "in_progress", "job_id": "1" * 64}, pending
        second = state("2" * 64)
        expect(429, continue_job("2" * 64, second["job_generation"], second["revision"]))
        cancelled = expect(200, request("CancelSnapshot", {"version": 1,
            "job_id": "1" * 64, "job_generation": first["job_generation"],
            "expected_revision": first["revision"]}))
        assert cancelled["state"] == "cancelled", cancelled
        expect(503, inflight.result(timeout=10))
    assert state("1" * 64)["state"] == "cancelled"
    print("paused R2: owner admin responsive, pending replay bypasses permit,"
          " other heavy claim 429, cancel fences late result")


def verify_request_expiry():
    """Run on a fresh --seed-live state with the same 3000 ms test pause."""
    first = state("1" * 64)
    body = json.dumps({"version": 1, "job_id": "1" * 64,
        "job_generation": first["job_generation"],
        "expected_revision": first["revision"]}, separators=(",", ":")).encode()
    path = "/mkit/host/v1/ContinueSnapshot"
    headers = make_headers(path, body)
    headers["X-Expires-At"] = str(int(headers["X-Created-At"]) + 1000)
    canonical = "\n".join(["mkit-write:v2", headers["X-Audience"],
        headers["X-Repository"], path, headers["X-Content-Commitment"],
        headers["X-Created-At"], headers["X-Expires-At"], headers["Idempotency-Key"]])
    headers["X-Signature"] = OWNER.sign(blake3.blake3(canonical.encode()).digest()).signature.hex()
    expect(503, admin("ContinueSnapshot", body, signed_headers=headers))
    after = state("1" * 64)
    assert after["revision"] == first["revision"] and after["state"] == "catalog", after
    assert int(after["progress"]["reserved_io_bytes"]) > 0, after
    print("signed request expired during R2 wait: reservation retained, no semantic apply")


def patch_corrupt():
    with sqlite3.connect(db_path()) as db:
        db.execute("UPDATE host_snapshot_jobs SET checksum=? WHERE job_id=?",
                   ("0" * 64, "2" * 64))
    print("offline disposable job checksum corrupted")


def verify_corrupt():
    before = saved_rows()
    expect(503, request("GetSnapshotJob", {"version": 1, "job_id": "2" * 64}))
    assert saved_rows() == before, "corruption read must not repair state"
    print("corrupt job checksum fails closed without repair")


def patch_ready_expiry():
    with sqlite3.connect(db_path()) as db:
        rewrite_job(db, "1" * 64, {"terminal_deadline": 0})
    print("offline disposable ready summary deadline patched")


def verify_ready_retention():
    assert state("1" * 64)["state"] == "ready"
    revision = 0
    affected = 0
    for _ in range(5):
        reply = expect(200, request("CleanupSnapshots", {"version": 1,
            "expected_cleanup_revision": str(revision), "max_rows": 64}))
        assert int(reply["affected_rows"]) <= 64, reply
        affected += int(reply["affected_rows"])
        revision += 1
        assert reply["cleanup_revision"] == str(revision)
        if not reply["has_more"]:
            break
    else:
        raise AssertionError("ready summary cleanup made no bounded progress")
    assert request("GetSnapshotJob", {"version": 1, "job_id": "1" * 64})[0] == 404
    with sqlite3.connect(db_path()) as db:
        assert db.execute("SELECT COUNT(*) FROM host_snapshot_certificates").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM host_snapshot_indexes WHERE retired=0").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM host_snapshot_catalog").fetchone()[0] > 0
    print("ready summary removed in bounded", affected, "rows; current catalog/index retained")


MODES = {"--seed-live": seed_live, "--patch-idle-offline": patch_idle,
         "--verify-idle": verify_idle, "--patch-high-offline": patch_high,
         "--verify-high": verify_high, "--patch-exhaust-offline": patch_exhaust,
         "--verify-exhaust": verify_exhaust,
         "--patch-overflow-offline": patch_overflow,
         "--verify-overflow": verify_overflow,
         "--verify-interleave": verify_interleave,
         "--verify-request-expiry": verify_request_expiry,
         "--patch-corrupt-offline": patch_corrupt,
         "--verify-corrupt": verify_corrupt,
         "--patch-ready-expiry-offline": patch_ready_expiry,
         "--verify-ready-retention": verify_ready_retention}

if __name__ == "__main__":
    MODES[sys.argv[2]]()
