"""Seeded, checksum-valid boundaries against a disposable local managed Worker.

Run one mode per fresh Wrangler --persist-to directory. The Worker must be
built with managed-access,test-faults; --attempt additionally needs Wrangler
`--var SUBMISSION_TEST_UPLOAD_PRE_PUT_MS:5000`. No mode writes a cloud bucket or
publishes a candidate. The SQL edits below are test setup, never service APIs.
"""

import json
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

import blake3
from nacl.signing import SigningKey

import managed_submissions_admission as admission

MAX_ATTEMPTS = 8192
MAX_JOB_IO = 2 * 1024 * 1024 * 1024
MAX_JOB_OPS = 540_672
ACTIVE_IDLE_MS = 24 * 60 * 60 * 1000


def connection():
    return sqlite3.connect(admission.database(), timeout=2)


def one(query, params=()):
    with closing(connection()) as db:
        result = db.execute(query, params).fetchall()
    assert len(result) == 1, (query, result)
    return result[0]


def job_row():
    row = one("SELECT document,begin_body,sealed_header,checksum,idle_deadline,state "
              "FROM host_submission_jobs WHERE operation_id=?", (admission.OPERATION.hex(),))
    document, begin, header, checksum, deadline, state = row
    assert job_checksum(document, begin, header) == checksum
    parsed = json.loads(document)
    assert parsed["operation_id"] == admission.OPERATION.hex()
    assert parsed["idle_deadline"] == deadline and parsed["state"] == state
    return parsed


def job_checksum(document, begin_body, sealed_header):
    def part(value):
        encoded = value.encode()
        return len(encoded).to_bytes(4, "little") + encoded
    return blake3.blake3(b"mkit.host.submission.job.v1\0"
                         + part(document) + part(begin_body) + part(sealed_header)).hexdigest()


def seed_job(**changes):
    """Replace only valid Job fields and corresponding indexed columns atomically."""
    op = admission.OPERATION.hex()
    with closing(connection()) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT document,begin_body,sealed_header,checksum FROM "
                         "host_submission_jobs WHERE operation_id=?", (op,)).fetchone()
        assert row is not None and job_checksum(*row[:3]) == row[3]
        job = json.loads(row[0])
        for name, value in changes.items():
            assert name in job and name not in ("operation_id", "submission_id", "generation"), name
            job[name] = value
        encoded = json.dumps(job, separators=(",", ":"))
        db.execute("UPDATE host_submission_jobs SET document=?,checksum=?,idle_deadline=?,"
                   "bulky_deadline=?,state=?,marker_confirmed=? WHERE operation_id=?",
                   (encoded, job_checksum(encoded, row[1], row[2]), job["idle_deadline"],
                    job["bulky_deadline"], job["state"], int(job["marker_confirmed"]), op))
        if "idle_deadline" in changes:
            changed = db.execute("UPDATE host_submission_pins SET expires_at=? WHERE operation_id=?",
                                 (job["idle_deadline"], op)).rowcount
            assert changed == 1, changed
        db.commit()
    assert all(job_row()[name] == value for name, value in changes.items())
    return job


def pin_deadline():
    return one("SELECT expires_at FROM host_submission_pins WHERE operation_id=?",
               (admission.OPERATION.hex(),))[0]


def bootstrap(directory):
    manifest = json.loads((directory / "manifest.json").read_bytes())
    assert manifest["mode"] == "small" and manifest["test_material"] is True
    update = (directory / manifest["update_file"]).read_bytes()
    assert blake3.blake3(update).hexdigest() == manifest["update_digest"]
    subject = SigningKey(bytes.fromhex(manifest["subject_seed_hex"]))
    admission.ready_snapshot(manifest)
    registered = admission.grant_registration(manifest, subject)
    body = admission.begin_body(manifest, registered)
    first = admission.checked(200, admission.subject_request("BeginSubmission", body, subject))
    assert first["state"] == "awaiting_upload" and first["revision"] == "0"
    assert admission.counters(admission.OPERATION.hex())[:3] == (1, 1, 1)
    return manifest, update, subject, body, first


def upload(first, update, subject):
    return admission.subject_request("UploadSubmission",
                                     admission.upload_body(admission.OPERATION, first, update),
                                     subject, content_type="application/octet-stream")


def current(subject):
    return admission.checked(200, admission.current_status(admission.OPERATION, subject))


def assert_unchanged_repo(manifest):
    assert admission.counters(admission.OPERATION.hex())[:3] == (1, 1, 1)
    admission.assert_no_publication(manifest)


def idle(directory):
    manifest, update, subject, body, first = bootstrap(directory)
    old = int(time.time() * 1000) + 5_000
    seed_job(idle_deadline=old)
    assert pin_deadline() == old
    assert current(subject) == first
    assert admission.checked(200, admission.subject_request("BeginSubmission", body, subject)) == first
    assert job_row()["idle_deadline"] == pin_deadline() == old, "reads/replays extended retention"
    uploaded = admission.checked(200, upload(first, update, subject))
    assert uploaded["state"] == "validating" and uploaded["revision"] == "1"
    renewed = job_row()["idle_deadline"]
    assert renewed == pin_deadline() and renewed >= int(time.time() * 1000) + ACTIVE_IDLE_MS - 2_000
    assert renewed > old + ACTIVE_IDLE_MS - 10_000, (old, renewed)
    # Bounded wait makes the old deadline truly past without waiting 24 hours.
    delay = (old - int(time.time() * 1000) + 50) / 1000
    if delay > 0:
        assert delay <= 5.1
        time.sleep(delay)
    assert int(time.time() * 1000) > old
    assert current(subject) == uploaded
    assert job_row()["idle_deadline"] == pin_deadline() == renewed
    assert_unchanged_repo(manifest)
    print("idle/pin renewal passed", {"old": old, "new": renewed})


def budget(directory, kind):
    manifest, update, subject, _, first = bootstrap(directory)
    if kind == "--io-exact":
        old = MAX_JOB_IO - len(update)
        seed_job(reserved_io_bytes=old)
        uploaded = admission.checked(200, upload(first, update, subject))
        assert uploaded["state"] == "validating"
        assert job_row()["reserved_io_bytes"] == MAX_JOB_IO
        terminal = admission.checked(429, admission.subject_request(
            "ContinueSubmission", admission.continue_body(uploaded), subject),
            code_value="resource_exhausted")
    elif kind == "--ops-exact":
        seed_job(r2_operations=MAX_JOB_OPS - 1)
        uploaded = admission.checked(200, upload(first, update, subject))
        assert uploaded["state"] == "validating"
        assert job_row()["r2_operations"] == MAX_JOB_OPS
        terminal = admission.checked(429, admission.subject_request(
            "ContinueSubmission", admission.continue_body(uploaded), subject),
            code_value="resource_exhausted")
    else:
        if kind == "--io-over":
            seed_job(reserved_io_bytes=MAX_JOB_IO - len(update) + 1)
        else:
            assert kind == "--ops-over"
            seed_job(r2_operations=MAX_JOB_OPS)
        before = job_row()
        terminal = admission.checked(429, upload(first, update, subject), code_value="resource_exhausted")
        after = job_row()
        assert after["reserved_io_bytes"] == before["reserved_io_bytes"]
        assert after["r2_operations"] == before["r2_operations"]
        with closing(connection()) as db:
            present = db.execute("SELECT name FROM sqlite_master WHERE name='submission_test_puts'").fetchone()
            if present:
                assert db.execute("SELECT COUNT(*) FROM submission_test_puts").fetchone()[0] == 0
    assert terminal == {"code": "resource_exhausted"}
    saved = current(subject)
    assert saved["state"] == "refused" and saved["code"] == "resource_exhausted", saved
    assert_unchanged_repo(manifest)
    print("budget boundary passed", kind, {"attempts": job_row()["attempts"],
                                           "reserved_io_bytes": job_row()["reserved_io_bytes"],
                                           "r2_operations": job_row()["r2_operations"]})


def nonce_ttl(directory):
    manifest, _, subject, body, first = bootstrap(directory)
    op = admission.OPERATION.hex()
    before = admission.counters(op)
    with closing(connection()) as db:
        rows = db.execute("SELECT scope,fingerprint,expires,reply FROM authenticated_operations "
                          "WHERE reply IS NOT NULL ORDER BY rowid DESC").fetchall()
        old = [row for row in rows if (lambda reply: reply["status"] == 200
               and json.loads(reply["body"]).get("operation_id") == op)(json.loads(row[3]))]
        assert len(old) == 1, old
        old = old[0]
        db.execute("DELETE FROM authenticated_operations WHERE scope=? AND fingerprint=?",
                   old[:2])
        db.commit()
        assert db.execute("SELECT 1 FROM authenticated_operations WHERE scope=?", (old[0],)).fetchone() is None
    assert current(subject) == first  # lost Begin response, op-ID-only recovery
    assert admission.checked(200, admission.subject_request("BeginSubmission", body, subject)) == first
    assert admission.counters(op) == before
    assert_unchanged_repo(manifest)
    print("seeded nonce-ledger removal/operation identity passed", {"scope": old[0],
                                                                  "grant_charge": before[0]})


def certificate(directory):
    manifest, update, subject, _, first = bootstrap(directory)
    uploaded = admission.checked(200, upload(first, update, subject))
    assert uploaded["state"] == "validating"
    old_cert = one("SELECT job_id,generation,head,packmap,catalog_digest FROM "
                   "host_snapshot_certificates WHERE exact_ref=?", (admission.REF,))
    assert old_cert[2:4] == (manifest["base_root"], manifest["base_tip"])
    replacement_job = bytes([0x75]).hex() * 32
    begin = admission.packed({"version": 1, "job_id": replacement_job,
                              "ref": admission.REF, "expected_head": manifest["base_root"],
                              "expected_packmap": manifest["base_tip"],
                              "selected_pack_keys": manifest["selected_pack_keys"]})
    ready = admission.checked(200, admission.admin("BeginSnapshot", begin))
    assert ready["state"] == "catalog"
    for step in range(256):
        command = admission.packed({"version": 1, "job_id": replacement_job,
                                    "job_generation": ready["job_generation"],
                                    "expected_revision": ready["revision"]})
        ready = admission.checked(200, admission.admin("ContinueSnapshot", command))
        if ready["state"] == "ready":
            break
        assert ready["state"] in ("catalog", "walk")
    else:
        raise AssertionError("same-head certificate replacement did not complete in 256 steps")
    new_cert = one("SELECT job_id,generation,head,packmap,catalog_digest FROM "
                   "host_snapshot_certificates WHERE exact_ref=?", (admission.REF,))
    assert new_cert[:2] != old_cert[:2] and new_cert[2:4] == old_cert[2:4], (old_cert, new_cert)
    assert current(subject) == uploaded
    stale_continue = admission.continue_body(uploaded)
    admission.checked(409, admission.subject_request("ContinueSubmission", stale_continue, subject),
                      code_value="conflict")
    admission.checked(409, admission.subject_request("ContinueSubmission", stale_continue, subject),
                      code_value="conflict")
    admission.checked(409, upload(first, update, subject), code_value="conflict")
    assert current(subject) == uploaded
    assert admission.counters(admission.OPERATION.hex())[:3] == (1, 1, 1)
    admission.assert_no_publication(manifest)
    print("certificate-only replacement fence passed", {"old_job": old_cert[0],
                                                        "new_job": new_cert[0], "steps": step + 1})


def attempt(directory):
    manifest, update, subject, _, first = bootstrap(directory)
    seed_job(attempts=MAX_ATTEMPTS - 1)
    with ThreadPoolExecutor(max_workers=1) as pool:
        flight = pool.submit(upload, first, update, subject)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            observed = job_row()
            if observed["attempts"] == MAX_ATTEMPTS and observed["attempt_deadline"] > int(time.time() * 1000):
                break
            assert not flight.done(), "Upload completed before its claimed attempt could be observed"
            time.sleep(0.025)
        else:
            raise AssertionError("no live final Upload attempt observed; check test-fault delay")
        # Continue is JSON ingress, so it reaches the RefStore heavy permit;
        # a second Upload could be refused by the outer transfer permit alone.
        busy = admission.checked(429, admission.subject_request(
            "ContinueSubmission", admission.continue_body(first), subject),
            code_value="resource_exhausted")
        assert busy == {"code": "resource_exhausted"}
        assert current(subject)["state"] == "awaiting_upload"
        assert job_row()["attempts"] == MAX_ATTEMPTS
        uploaded = admission.checked(200, flight.result(timeout=8))
    assert uploaded["state"] == "validating"
    assert job_row()["attempts"] == MAX_ATTEMPTS and job_row()["attempt_deadline"] == 0
    admission.checked(429, admission.subject_request(
        "ContinueSubmission", admission.continue_body(uploaded), subject),
        code_value="resource_exhausted")
    assert current(subject)["state"] == "refused"
    assert job_row()["attempts"] == MAX_ATTEMPTS
    assert_unchanged_repo(manifest)
    print("live final attempt/busy/terminal passed", {"attempts": MAX_ATTEMPTS})


def transient_start(directory):
    """Worker has SUBMISSION_TEST_UPLOAD_TRANSIENT=1 for this first process."""
    manifest, update, subject, _, first = bootstrap(directory)
    admission.checked(503, upload(first, update, subject), code_value="unavailable")
    saved = current(subject)
    assert saved["state"] == "awaiting_upload" and saved["revision"] == first["revision"]
    assert saved["submission_id"] == first["submission_id"]
    after = job_row()
    assert after["state"] == "awaiting_upload" and after["attempts"] == 1
    assert after["attempt_deadline"] == 0 and after["attempt_scope"] == ""
    assert after["reserved_io_bytes"] == len(update) and after["r2_operations"] == 1
    with closing(connection()) as db:
        present = db.execute("SELECT name FROM sqlite_master WHERE name='submission_test_puts'").fetchone()
        if present:
            assert db.execute("SELECT COUNT(*) FROM submission_test_puts").fetchone()[0] == 0
    assert_unchanged_repo(manifest)
    print("transient pre-PUT 503 preserved retryable operation", {
        "attempts": after["attempts"], "reserved_io_bytes": after["reserved_io_bytes"],
        "r2_operations": after["r2_operations"]})


def transient_resume(directory):
    """Restart SAME state without the test-fault variable before this mode."""
    manifest = json.loads((directory / "manifest.json").read_bytes())
    subject = SigningKey(bytes.fromhex(manifest["subject_seed_hex"]))
    update = (directory / manifest["update_file"]).read_bytes()
    before = job_row()
    assert before["state"] == "awaiting_upload" and before["attempts"] == 1
    assert before["attempt_deadline"] == 0 and before["attempt_scope"] == ""
    recovered = current(subject)
    assert recovered["state"] == "awaiting_upload" and recovered["revision"] == "0"
    uploaded = admission.checked(200, upload(recovered, update, subject))
    assert uploaded["state"] == "validating" and uploaded["revision"] == "1"
    after = job_row()
    assert after["attempts"] == 2 and after["attempt_deadline"] == 0
    assert after["reserved_io_bytes"] == before["reserved_io_bytes"] + len(update)
    assert after["r2_operations"] == before["r2_operations"] + 1
    assert admission.counters(admission.OPERATION.hex())[:3] == (1, 1, 1)
    assert_unchanged_repo(manifest)
    print("fresh-nonce retry after transient503 passed", {"attempts": after["attempts"],
                                                       "reserved_io_bytes": after["reserved_io_bytes"],
                                                       "r2_operations": after["r2_operations"]})


def main():
    modes = ("--idle", "--io-exact", "--io-over", "--ops-exact", "--ops-over",
             "--nonce", "--certificate", "--attempt", "--transient-start", "--transient-resume")
    if len(sys.argv) != 5 or sys.argv[4] not in modes:
        raise SystemExit("usage: boundaries.py http://localhost:8791 SMALL_DIR FRESH_STATE_DIR "
                         + "|".join(modes))
    origin, directory, state, mode = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4]
    admission.configure(origin, directory, state)
    # Wrangler may create unrelated DO SQLite before the first request.
    if mode != "--transient-resume":
        assert not list(state.glob("v3/do/mkit-vcs-managed-local-test-RefStore/[0-9a-f]*.sqlite")), (
            "boundary mode requires fresh RefStore state")
    if mode == "--idle":
        idle(directory)
    elif mode == "--nonce":
        nonce_ttl(directory)
    elif mode == "--attempt":
        attempt(directory)
    elif mode == "--certificate":
        certificate(directory)
    elif mode == "--transient-start":
        transient_start(directory)
    elif mode == "--transient-resume":
        transient_resume(directory)
    else:
        budget(directory, mode)


if __name__ == "__main__":
    main()
