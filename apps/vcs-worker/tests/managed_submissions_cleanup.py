"""Owner cleanup against an actual local workerd and disposable Wrangler state.

Run only after the main executor gives an artifact/port go-ahead. This helper
reuses admission fixtures and may seed checksummed deadlines in disposable
SQLite state; route effects still go through signed HTTP requests. Race modes
require a `test-faults` artifact and separate disposable state.
`--race-marker-first` cleans before issuing a late Upload. For
`--race-upload-first`, set `SUBMISSION_TEST_UPLOAD_POST_PUT_MS=1000` to expose
a completed R2 PUT before its delayed SQL apply.
"""

import json
import socket
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import urllib.error
import urllib.request

import blake3
from nacl.signing import SigningKey

socket.setdefaulttimeout(15)


if len(sys.argv) not in (4, 5) or not sys.argv[1].startswith("http://localhost:"):
    raise SystemExit("expected local origin, SMALL fixture directory, disposable Wrangler state, optional race mode")

ORIGIN, FIXTURE_ARG, STATE_ARG = sys.argv[1:4]
FIXTURE = Path(FIXTURE_ARG)
STATE = Path(STATE_ARG)
ROUTE = "/mkit/host/v1/CleanupSubmissions"
MARKER_PROBE = "/__test/host/SubmissionMarkerCreate"
ACTIVE_OPERATION = bytes([0x71]) * 32
TERMINAL_OPERATION = bytes([0x75]) * 32
MODE = sys.argv[4] if len(sys.argv) == 5 else "positive"
if MODE not in ("positive", "--race-marker-first", "--race-upload-first"):
    raise SystemExit("unknown cleanup test mode")

import managed_submissions_admission as admission  # noqa: E402
admission.configure(ORIGIN, FIXTURE, STATE)
import managed_data as wire  # noqa: E402


def packed(value):
    return json.dumps(value, separators=(",", ":")).encode()


def database():
    return admission.database()


def cleanup_body(revision, max_rows):
    return packed({"version": 1, "expected_cleanup_revision": revision, "max_rows": max_rows})


def owner_cleanup(body):
    headers = wire.signed_headers(ROUTE, body, wire.OWNER, content_type="application/json")
    return bounded_send(ROUTE, body, headers)


def bounded_send(path, body, headers):
    request = urllib.request.Request(ORIGIN + path, data=body, headers=headers, method="POST")
    try:
        response = urllib.request.urlopen(request, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    result = (response.status, response.read(), response.headers)
    assert result[2].get("Cache-Control") == "private, no-store", (path, result)
    return result


def decode_reply(result, status=200):
    assert result[0] == status, (status, result[:2])
    assert result[2].get("Cache-Control") == "private, no-store", result[2]
    value = json.loads(result[1])
    if status == 200:
        assert set(value) == {"version", "cleanup_revision", "affected_rows", "has_more"}, value
        assert value["version"] == 1 and isinstance(value["has_more"], bool), value
        for key in ("cleanup_revision", "affected_rows"):
            raw = value[key]
            assert isinstance(raw, str) and raw.isascii() and raw.isdecimal()
            assert str(int(raw)) == raw, value
    else:
        assert set(value) == {"code"}, value
    return value


def table_rows(table):
    with sqlite3.connect(database()) as db:
        return db.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()


def state_rows():
    with sqlite3.connect(database()) as db:
        names = [row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'host_submission_%' ORDER BY name"
        )]
        return {name: db.execute(f"SELECT * FROM {name} ORDER BY 1").fetchall() for name in names}


def seed_job(operation, *, idle_deadline=None, bulky_deadline=None, cleanup_attempts=None):
    """Update a disposable job's indexed/document fields with a valid checksum."""
    assert "/tmp/" in str(STATE.resolve()), "deadline seeding is limited to disposable Wrangler state"
    with sqlite3.connect(database()) as db:
        rows = db.execute(
            "SELECT document,begin_body,sealed_header FROM host_submission_jobs WHERE operation_id=?",
            (operation.hex(),),
        ).fetchall()
        assert len(rows) == 1, (operation.hex(), len(rows))
        document_raw, begin_body, sealed_header = rows[0]
        document = json.loads(document_raw)
        if idle_deadline is not None:
            document["idle_deadline"] = idle_deadline
            db.execute("UPDATE host_submission_jobs SET idle_deadline=? WHERE operation_id=?",
                       (idle_deadline, operation.hex()))
        if bulky_deadline is not None:
            document["bulky_deadline"] = bulky_deadline
            db.execute("UPDATE host_submission_jobs SET bulky_deadline=? WHERE operation_id=?",
                       (bulky_deadline, operation.hex()))
        if cleanup_attempts is not None:
            document["cleanup_attempts"] = cleanup_attempts
        encoded = json.dumps(document, separators=(",", ":"))
        checksum_input = b"mkit.host.submission.job.v1\0"
        for raw in (encoded.encode(), begin_body.encode(), sealed_header.encode()):
            checksum_input += len(raw).to_bytes(4, "little") + raw
        digest = blake3.blake3(checksum_input).hexdigest()
        db.execute("UPDATE host_submission_jobs SET document=?,checksum=? WHERE operation_id=?",
                   (encoded, digest, operation.hex()))


def submit_until_validated(manifest, registered, subject, operation):
    body = admission.begin_body(manifest, registered, operation=operation)
    begin = admission.checked(200, admission.subject_request("BeginSubmission", body, subject))
    assert begin["operation_id"] == operation.hex()
    update = (FIXTURE / manifest["update_file"]).read_bytes()
    upload = admission.upload_body(operation, begin, update)
    result = admission.subject_request("UploadSubmission", upload, subject,
                                       content_type="application/octet-stream")
    if result[0] != 200:
        raise AssertionError(("UploadSubmission", result[:2]))
    state = admission.checked(200, admission.current_status(operation, subject))
    for _ in range(256):
        if state["state"] == "validated":
            return state
        assert state["state"] == "validating", state
        state = admission.checked(200, admission.subject_request(
            "ContinueSubmission", admission.continue_body(state), subject))
    raise AssertionError("submission did not validate within 256 bounded Continue calls")


def current_job(operation):
    with sqlite3.connect(database()) as db:
        rows = db.execute("SELECT document FROM host_submission_jobs WHERE operation_id=?",
                          (operation.hex(),)).fetchall()
    assert len(rows) == 1, (operation.hex(), len(rows))
    return json.loads(rows[0][0])


def expected_marker_digest(operation, generation, update_digest):
    # Reproduce the frozen identity formula independently from Job.carrier_key
    # and the Rust marker() helper. The wire probe then confirms persisted bytes.
    carrier_material = (
        "mkit.host.submission.quarantine.v1\0"
        f"{generation}\0{operation.hex()}\0{update_digest}"
    ).encode()
    carrier_key = blake3.blake3(carrier_material).hexdigest()
    marker_binding = (
        b"mkit.host.submission.retired.v1\0"
        + operation.hex().encode()
        + generation.encode()
        + carrier_key.encode()
    )
    marker_bytes = b"MKST\x01" + blake3.blake3(marker_binding).digest()
    assert len(marker_bytes) == 37
    return blake3.blake3(marker_bytes).hexdigest()


def probe_exact_marker(operation, generation, manifest):
    before = state_rows()
    unknown = packed({"operation_id": operation.hex(), "extra": "reject"})
    unknown_headers = wire.signed_headers(MARKER_PROBE, unknown, wire.OWNER,
                                          content_type="application/json")
    rejected = decode_reply(bounded_send(MARKER_PROBE, unknown, unknown_headers), 400)
    assert rejected["code"] == "invalid_argument", rejected
    assert state_rows() == before, "unknown probe fields must not mutate SQL state"

    body = packed({"operation_id": operation.hex()})
    headers = wire.signed_headers(MARKER_PROBE, body, wire.OWNER,
                                  content_type="application/json")
    response = bounded_send(MARKER_PROBE, body, headers)
    assert response[0] == 200, ("only the exact conditional-PUT-failed/readback-confirmed result passes", response[:2])
    value = json.loads(response[1])
    assert set(value) == {"version", "put_rejected", "marker_digest", "marker_bytes"}, value
    assert value["version"] == 1 and value["put_rejected"] is True, value
    assert value["marker_bytes"] == 37, value
    assert value["marker_digest"] == expected_marker_digest(
        operation, generation, manifest["update_digest"]
    ), value
    assert len(value["marker_digest"]) == 64 and value["marker_digest"] == value["marker_digest"].lower()


def wait_until(predicate, description, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {description}")


def run_put_race(manifest, registered, subject, *, upload_first):
    operation = bytes([0x78 if upload_first else 0x79]) * 32
    body = admission.begin_body(manifest, registered, operation=operation)
    admitted = admission.checked(200, admission.subject_request("BeginSubmission", body, subject))
    update = (FIXTURE / manifest["update_file"]).read_bytes()
    carrier = admission.upload_body(operation, admitted, update)
    path = admission.PATH + "UploadSubmission"
    upload_headers = wire.signed_headers(path, carrier, subject,
                                         content_type="application/octet-stream")
    expired = int(time.time() * 1000) - 10_000

    def issue_upload():
        return bounded_send(path, carrier, upload_headers)

    def put_completed():
        with sqlite3.connect(database()) as db:
            table = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='submission_test_puts'"
            ).fetchone()
            return bool(table and db.execute(
                "SELECT 1 FROM submission_test_puts WHERE operation_id=?", (operation.hex(),)
            ).fetchone())

    if not upload_first:
        seed_job(operation, idle_deadline=expired)
        cleanup_reply = decode_reply(owner_cleanup(cleanup_body("0", 64)))
        assert int(cleanup_reply["affected_rows"]) >= 2, cleanup_reply
        job = current_job(operation)
        assert job["state"] == "expired" and job["marker_confirmed"] is True, job
        assert not put_completed(), "no carrier PUT may complete after marker installation"
        probe_exact_marker(operation, admitted["submission_generation"], manifest)
        late = issue_upload()
        assert late[0] == 409 and json.loads(late[1]) == {"code": "conflict"}, late[:2]
        assert not put_completed(), "denied late Upload must not complete a carrier PUT"
        revision = cleanup_reply["cleanup_revision"]
        print("marker-first case: cleanup confirmed the marker before a later Upload request")
    else:
        with ThreadPoolExecutor(max_workers=2) as pool:
            upload_future = pool.submit(issue_upload)
            wait_until(lambda: bool(current_job(operation).get("attempt_scope")),
                       "durable upload attempt claim")
            wait_until(put_completed, "successful physical create-only R2 PUT")
            seed_job(operation, idle_deadline=expired)
            cleanup_reply = decode_reply(owner_cleanup(cleanup_body("0", 64)))
            assert cleanup_reply["affected_rows"] == "1", cleanup_reply
            fenced = current_job(operation)
            assert fenced["state"] == "expired" and not fenced["marker_confirmed"], fenced
            upload_result = upload_future.result(timeout=4)
            assert upload_result[0] == 409 and json.loads(upload_result[1]) == {"code": "conflict"}, (
                upload_result[:2]
            )
        revision = cleanup_reply["cleanup_revision"]
        marker_reply = decode_reply(owner_cleanup(cleanup_body(revision, 64)))
        assert marker_reply["affected_rows"] == "1", marker_reply
        job = current_job(operation)
        assert job["state"] == "expired" and job["marker_confirmed"] is True, job
        assert put_completed(), "the carrier PUT completed before marker CAS"
        probe_exact_marker(operation, admitted["submission_generation"], manifest)
        revision = marker_reply["cleanup_revision"]
        print("upload-first case: completed carrier PUT was replaced by marker CAS before refund")

    job = current_job(operation)
    assert job["cleanup_ops"] <= 12 and job["cleanup_bytes"] <= 4096, job
    assert admission.counters(operation.hex())[:3] == (1, 1, 1)
    with sqlite3.connect(database()) as db:
        quota = db.execute(
            "SELECT carrier_slots,carrier_bytes FROM host_submission_subjects WHERE subject=?",
            (subject.verify_key.encode().hex(),),
        ).fetchone()
    assert quota == (0, 0), ("physical quota must refund exactly once after marker confirmation", quota)
    assert admission.checked(200, admission.current_status(operation, subject))["state"] == "expired"
    if upload_first:
        replay = decode_reply(owner_cleanup(cleanup_body(revision, 64)))
        assert int(replay["affected_rows"]) <= 64, replay
        with sqlite3.connect(database()) as db:
            quota_after_replay = db.execute(
                "SELECT carrier_slots,carrier_bytes FROM host_submission_subjects WHERE subject=?",
                (subject.verify_key.encode().hex(),),
            ).fetchone()
        assert quota_after_replay == quota == (0, 0), quota_after_replay


def test_put_race(manifest, registered, subject):
    run_put_race(manifest, registered, subject, upload_first=MODE == "--race-upload-first")


def test_owner_gate_and_wire(subject):
    before = state_rows()
    body = cleanup_body("0", 1)
    for label, signer, expected in (
        ("subject", subject, 403),
        ("foreign", wire.STRANGER, 403),
    ):
        headers = wire.signed_headers(ROUTE, body, signer, content_type="application/json")
        result = wire.send(ROUTE, body, headers)
        reply = decode_reply(result, expected)
        assert reply["code"] == "permission_denied", (label, reply)
        assert state_rows() == before, label

    unsigned = wire.send(ROUTE, body, {"Content-Type": "application/json"})
    assert unsigned[0] == 401, unsigned[:2]
    assert state_rows() == before
    invalid = owner_cleanup(cleanup_body("0", 0))
    assert decode_reply(invalid, 400)["code"] == "invalid_argument"
    assert state_rows() == before
    assert admission.counters((bytes([0x76]) * 32).hex()) == (0, 0, 0, None)


def test_expiry_fence_and_terminal_paging(manifest, registered, subject):
    # Validated releases the active-ref slot, so admit it before the idle job.
    terminal = submit_until_validated(manifest, registered, subject, TERMINAL_OPERATION)
    assert terminal["state"] == "validated", terminal
    admission.checked(200, admission.subject_request(
        "BeginSubmission", admission.begin_body(manifest, registered, operation=ACTIVE_OPERATION), subject))
    admission.assert_no_publication(manifest)

    expired = int(time.time() * 1000) - 10_000
    seed_job(ACTIVE_OPERATION, idle_deadline=expired)
    seed_job(TERMINAL_OPERATION, bulky_deadline=expired, cleanup_attempts=8192)
    before_counters = admission.counters(ACTIVE_OPERATION.hex())[:3]
    assert before_counters[0] == 2, before_counters

    # An older exhausted marker candidate must not starve the newly idle
    # active fence. Each state transition consumes one business row.
    first = decode_reply(owner_cleanup(cleanup_body("0", 1)))
    assert first["cleanup_revision"] == "1" and first["affected_rows"] == "1", first
    with sqlite3.connect(database()) as db:
        active_before_retry = db.execute(
            "SELECT state FROM host_submission_jobs WHERE operation_id=?",
            (ACTIVE_OPERATION.hex(),),
        ).fetchone()
        terminal_before_retry = db.execute(
            "SELECT state,marker_confirmed FROM host_submission_jobs WHERE operation_id=?",
            (TERMINAL_OPERATION.hex(),),
        ).fetchone()
        meta_before_retry = json.loads(
            db.execute("SELECT document FROM host_submission_meta WHERE slot=1").fetchone()[0]
        )
    assert active_before_retry == ("expired",) and meta_before_retry["active"] == 0, (
        active_before_retry, meta_before_retry
    )
    assert terminal_before_retry == ("validated", 0), terminal_before_retry

    transitioned = decode_reply(owner_cleanup(cleanup_body("1", 1)))
    assert transitioned["cleanup_revision"] == "2" and transitioned["affected_rows"] == "1", transitioned
    assert transitioned["has_more"] is True, transitioned
    with sqlite3.connect(database()) as db:
        active_row = db.execute(
            "SELECT state,idle_deadline FROM host_submission_jobs WHERE operation_id=?",
            (ACTIVE_OPERATION.hex(),),
        ).fetchone()
        terminal_row = db.execute(
            "SELECT state,marker_confirmed FROM host_submission_jobs WHERE operation_id=?",
            (TERMINAL_OPERATION.hex(),),
        ).fetchone()
        lifetime_row = db.execute(
            "SELECT document FROM host_submission_lifetime WHERE operation_id=?",
            (ACTIVE_OPERATION.hex(),),
        ).fetchone()
        lifetime = json.loads(lifetime_row[0])
        terminal_lifetime_row = db.execute(
            "SELECT document FROM host_submission_lifetime WHERE operation_id=?",
            (TERMINAL_OPERATION.hex(),),
        ).fetchone()
        terminal_lifetime = json.loads(terminal_lifetime_row[0])
        meta = json.loads(db.execute("SELECT document FROM host_submission_meta WHERE slot=1").fetchone()[0])
    assert active_row[0] == "expired" and lifetime["state"] == "expired", (active_row, lifetime)
    assert terminal_row == ("expired", 0), "validated expiry consumes its own row before marker I/O"
    assert meta["active"] == 0, "the fenced active job leaves active quota"
    assert admission.counters(ACTIVE_OPERATION.hex())[:3] == before_counters
    assert lifetime["terminal_progress"] is not None, "terminal progress survives bulky deletion"

    # Expiry can assign a fresh bulky deadline. Re-seed the exhausted terminal
    # row after both transitions and verify it is genuinely the next candidate.
    seed_job(TERMINAL_OPERATION, bulky_deadline=expired, cleanup_attempts=8192)
    with sqlite3.connect(database()) as db:
        oldest = db.execute(
            "SELECT operation_id FROM host_submission_jobs WHERE marker_confirmed=0 "
            "AND state IN ('validated','refused','expired') AND bulky_deadline<=? "
            "ORDER BY bulky_deadline,operation_id LIMIT 1",
            (int(time.time() * 1000),),
        ).fetchone()
    assert oldest == (TERMINAL_OPERATION.hex(),), oldest

    before_exhausted = state_rows()
    exhausted = decode_reply(owner_cleanup(cleanup_body("2", 1)), 429)
    assert exhausted["code"] == "resource_exhausted", exhausted
    assert state_rows() == before_exhausted, "exhausted marker attempts retain identity and quota"
    seed_job(TERMINAL_OPERATION, cleanup_attempts=0)

    # The original subject may recover the saved status after the job fence;
    # that read does not authorize another upload effect.
    fetched = admission.checked(200, admission.current_status(ACTIVE_OPERATION, subject))
    assert fetched["state"] == "expired", fetched
    assert fetched["progress"] == lifetime["terminal_progress"], (fetched, lifetime)

    revision = transitioned["cleanup_revision"]
    seen = 0
    marker_observed = False
    for _ in range(256):
        reply = decode_reply(owner_cleanup(cleanup_body(revision, 1)))
        assert int(reply["cleanup_revision"]) == int(revision) + 1, reply
        assert int(reply["affected_rows"]) <= 1, reply
        revision = reply["cleanup_revision"]
        seen += int(reply["affected_rows"])
        with sqlite3.connect(database()) as db:
            rows = [json.loads(row[0]) for row in db.execute(
                "SELECT document FROM host_submission_jobs WHERE marker_confirmed=1"
            )]
        if rows:
            marker_observed = True
            assert all(row["cleanup_ops"] <= 12 and row["cleanup_bytes"] <= 4096
                       for row in rows), rows
        if not reply["has_more"]:
            break
    else:
        raise AssertionError("bounded max_rows=1 cleanup pagination did not finish")
    assert seen >= 2, seen
    assert marker_observed, "cleanup must confirm a marker before reclaiming bulky state"
    with sqlite3.connect(database()) as db:
        assert db.execute("SELECT 1 FROM host_submission_lifetime WHERE operation_id=?",
                          (ACTIVE_OPERATION.hex(),)).fetchone()
        assert db.execute("SELECT 1 FROM host_submission_lifetime WHERE operation_id=?",
                          (TERMINAL_OPERATION.hex(),)).fetchone()
        assert db.execute("SELECT 1 FROM host_submission_jobs WHERE operation_id=?",
                          (TERMINAL_OPERATION.hex(),)).fetchone() is None
    status = admission.checked(200, admission.current_status(TERMINAL_OPERATION, subject))
    assert status["state"] == "expired", status
    assert status["revision"] == terminal_lifetime["revision"], (status, terminal_lifetime)
    assert status["progress"] == terminal_lifetime["terminal_progress"], (status, terminal_lifetime)
    admission.assert_no_publication(manifest)


def main():
    manifest = json.loads((FIXTURE / "manifest.json").read_bytes())
    assert manifest["mode"] == "small" and manifest["expected_validation"] == "validated", manifest
    subject = SigningKey(bytes.fromhex(manifest["subject_seed_hex"]))
    assert subject.verify_key.encode().hex() == manifest["subject_public_key"]
    admission.ready_snapshot(manifest)
    registered = admission.grant_registration(manifest, subject)
    if MODE == "positive":
        test_owner_gate_and_wire(subject)
        test_expiry_fence_and_terminal_paging(manifest, registered, subject)
        print("local workerd cleanup: owner gate, row budget, fencing, pagination and identity recovery passed")
    else:
        test_put_race(manifest, registered, subject)


if __name__ == "__main__":
    main()
