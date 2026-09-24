"""Actual local workerd admission and replay checks for a SMALL native MKWU.

Run against a fresh, disposable managed Worker state only:

    python apps/vcs-worker/tests/managed_submissions_admission.py \
        http://localhost:8799 /tmp/submission-small /tmp/wrangler-state

The fixture comes from `submission_resource_fixture small`. This test never
publishes its candidate and never uses production keys or a cloud endpoint.
"""

import base64
import json
import sqlite3
import struct
import sys
import time
from pathlib import Path

import blake3
from nacl.signing import SigningKey

import managed_access  # noqa: E402
import managed_data  # noqa: E402
from managed_access import admin, expect, make_headers, send  # noqa: E402
from managed_data import OWNER, STRANGER, code, field, frame, rpc, send as connect_send, signed_headers, SERVICE, varint  # noqa: E402

ORIGIN = None
FIXTURE = None
STATE = None
MODE = "positive"


def configure(origin, fixture, state, mode="positive"):
    """Configure a disposable test run without mutating another module's argv."""
    global ORIGIN, FIXTURE, STATE, MODE
    if not origin.startswith("http://localhost:"):
        raise ValueError("the test requires a local http://localhost origin")
    if mode not in ("positive", "--fence-policy", "--fence-ref", "--fence-packmap", "--quota"):
        raise ValueError("unknown test mode")
    ORIGIN, FIXTURE, STATE, MODE = origin, Path(fixture), Path(state), mode
    managed_access.ORIGIN = origin
    managed_data.ORIGIN = origin

REF = "refs/heads/submission-test"
PACKMAP_REF = "refs/mkit/packmap/submission-test"
WORKSPACE = bytes([0x61]) * 32
OPERATION = bytes([0x71]) * 32
MISSING_OPERATION = bytes([0x72]) * 32
INVALID_OPERATION = bytes([0x74]) * 32
PATH = "/mkit/partial/v1/"


def packed(value):
    return json.dumps(value, separators=(",", ":")).encode()


def subject_request(operation, body, signer, **kwargs):
    return send(PATH + operation, body, signer=signer, **kwargs)


def checked(status, result, *, code_value=None):
    value = expect(status, result)
    if code_value is not None:
        assert value == {"code": code_value}, (status, value)
    elif status == 200 and isinstance(value, dict) and "submission_id" in value:
        expected = {"version", "operation_id", "submission_id", "submission_generation",
                    "revision", "state", "progress"}
        assert set(value) in (expected, expected | {"code"}), value
        assert value["version"] == 1, value
        assert all(len(value[name]) == 64 and value[name] == value[name].lower()
                   and all(ch in "0123456789abcdef" for ch in value[name])
                   for name in ("operation_id", "submission_id")), value
        for name in ("submission_generation", "revision"):
            raw = value[name]
            assert isinstance(raw, str) and raw.isascii() and raw.isdecimal()
            assert str(int(raw)) == raw, value
        assert value["state"] in ("awaiting_upload", "validating", "validated", "refused", "expired")
        progress = value["progress"]
        assert set(progress) == {"inventory_entries", "base_objects", "changed_pairs",
                                 "required_objects", "candidate_objects", "attempts",
                                 "reserved_io_bytes", "r2_operations"}, progress
        assert all(isinstance(raw, str) and raw.isascii() and raw.isdecimal()
                   and str(int(raw)) == raw for raw in progress.values()), progress
    return value


def database():
    files = list(STATE.glob("v3/do/mkit-vcs-managed-local-test-RefStore/[0-9a-f]*.sqlite"))
    assert len(files) == 1, files
    return files[0]


def submission_tables():
    with sqlite3.connect(database()) as db:
        return {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'host_submission_%'"
        )}


def counters(operation_id):
    with sqlite3.connect(database()) as db:
        grant = db.execute(
            "SELECT consumed_operations FROM host_grant_incarnations WHERE workspace_id=? AND grant_generation='1'",
            (WORKSPACE.hex(),),
        ).fetchall()
        assert len(grant) == 1, grant
        table = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='host_submission_meta'").fetchone()
        if table is None:
            return int(grant[0][0]), 0, 0, None
        lifetime = db.execute("SELECT COUNT(*) FROM host_submission_lifetime").fetchone()[0]
        subject = db.execute("SELECT SUM(lifetime) FROM host_submission_subjects").fetchone()[0]
        row = db.execute("SELECT document FROM host_submission_lifetime WHERE operation_id=?",
                         (operation_id,)).fetchone()
        return int(grant[0][0]), lifetime, subject or 0, json.loads(row[0]) if row else None


def test_grant(base, subject, max_operations=8):
    now = int(time.time() * 1000)
    body = bytearray(b"MKHG\x01")
    for value in (ORIGIN, "managed-test", REF):
        raw = value.encode()
        body.extend(varint(len(raw)) + raw)
    body.extend(WORKSPACE)
    for key in (OWNER.verify_key.encode(), subject.verify_key.encode(), STRANGER.verify_key.encode()):
        body.extend(key)
    body.extend(struct.pack(">QQ", 1, 1))
    body.extend(bytes.fromhex(base))
    body.extend(struct.pack(">QQI", now - 1000, now + 3_600_000, max_operations))
    body.extend(varint(1))
    body.extend(varint(1))
    selected = b"selected.txt"
    body.extend(varint(len(selected)) + selected)
    body.append(3)  # READ|REPLACE; the selected file is the only mutation.
    digest = blake3.blake3(b"mkit.hosted-workspace-grant.v1\0" + body).digest()
    body.extend(OWNER.sign(digest).signature)
    return base64.urlsafe_b64encode(body).decode().rstrip("=")


def upload_pack(key, payload):
    assert blake3.blake3(payload).hexdigest() == key
    identifier = bytes.fromhex(key)
    header = field(1, identifier) + field(2, len(payload))
    chunk = field(1, identifier) + field(2, 0) + field(3, payload) + field(4, 1)
    wire = frame(field(1, header)) + frame(field(2, chunk))
    route = SERVICE + "UploadPack"
    headers = signed_headers(route, b"", OWNER, "pack:" + key + ":" + str(len(payload)),
                             "application/connect+proto")
    result = connect_send(route, wire, headers)
    assert code(*result[:2]) == "ok", (key, result[:2])


def ready_snapshot(manifest):
    checked(200, admin("InitializePolicy", b'{"version":1,"collaborators":[]}'))
    for key, filename in manifest["output_files"]["base_packs_and_tip"].items():
        upload_pack(key, (FIXTURE / filename).read_bytes())
    advance = (field(1, REF) + field(2, 2) + field(4, bytes.fromhex(manifest["base_root"]))
               + field(5, PACKMAP_REF) + field(6, 2) + field(8, bytes.fromhex(manifest["base_tip"])))
    result = rpc("AdvanceRefs", advance, OWNER)
    assert code(*result[:2]) == "ok", result[:2]
    job_id = bytes([0x73]).hex() * 32
    begin = packed({"version": 1, "job_id": job_id, "ref": REF,
                    "expected_head": manifest["base_root"], "expected_packmap": manifest["base_tip"],
                    "selected_pack_keys": manifest["selected_pack_keys"]})
    state = checked(200, admin("BeginSnapshot", begin))
    assert state["state"] == "catalog" and state["revision"] == "0", state
    for attempt in range(256):
        request = packed({"version": 1, "job_id": job_id,
                          "job_generation": state["job_generation"],
                          "expected_revision": state["revision"]})
        state = checked(200, admin("ContinueSnapshot", request))
        if state["state"] == "ready":
            break
        assert state["state"] in ("catalog", "walk"), state
    else:
        raise AssertionError("small base did not become certified in 256 bounded steps")
    assert int(state["progress"]["reached_bytes"]) == manifest["base_unique_canonical_bytes"], state
    return state


def grant_registration(manifest, subject, max_operations=8):
    credential = test_grant(manifest["base_root"], subject, max_operations)
    request = packed({"version": 1, "expected_grant_generation": "0", "grant": credential})
    result = checked(200, admin("RegisterGrant", request))
    assert result["workspace_id"] == WORKSPACE.hex() and result["grant_generation"] == "1", result
    return result


def begin_body(manifest, registered, *, operation=OPERATION):
    return packed({"version": 1, "operation_id": operation.hex(),
                   "workspace_id": WORKSPACE.hex(), "grant_id": registered["grant_id"],
                   "grant_generation": "1", "expected_ref": REF,
                   "expected_base": manifest["base_root"],
                   "update_digest": manifest["update_digest"],
                   "update_len": str(manifest["update_len"]),
                   "selected_paths": manifest["selected_paths"]})


def upload_body(operation, admitted, update):
    prefix = (b"MKSU\x01" + operation + bytes.fromhex(admitted["submission_id"])
              + int(admitted["submission_generation"]).to_bytes(8, "little")
              + len(update).to_bytes(8, "little"))
    assert len(prefix) == 85
    return prefix + update


def current_status(operation, signer):
    return subject_request("GetStagedSubmission", packed({"version": 1, "operation_id": operation.hex()}), signer)


def continue_body(admitted):
    return packed({"version": 1, "operation_id": admitted["operation_id"],
                   "submission_id": admitted["submission_id"],
                   "submission_generation": admitted["submission_generation"],
                   "expected_revision": admitted["revision"]})


def assert_no_publication(manifest):
    ref = rpc("ReadRef", field(1, REF), OWNER)
    assert code(*ref[:2]) == "ok", ref[:2]
    with sqlite3.connect(database()) as db:
        refs = db.execute("SELECT path,value FROM refs WHERE path IN (?,?)", (REF, PACKMAP_REF)).fetchall()
        assert len(refs) == 2, refs
        assert dict(refs) == {REF: manifest["base_root"], PACKMAP_REF: manifest["base_tip"]}, refs
    candidate_pack = rpc("DownloadPack", field(1, bytes.fromhex(manifest["embedded_pack_key"])),
                         OWNER, streaming=True)
    assert code(*candidate_pack[:2], streaming=True) == "not_found", candidate_pack[:2]


def main():
    manifest = json.loads((FIXTURE / "manifest.json").read_bytes())
    assert manifest["mode"] == "small" and manifest["test_material"] is True, manifest
    assert manifest["selected_paths"] == [["selected.txt"]], manifest["selected_paths"]
    update = (FIXTURE / manifest["update_file"]).read_bytes()
    assert blake3.blake3(update).hexdigest() == manifest["update_digest"]
    assert len(update) == manifest["update_len"] <= 4 * 1024 * 1024
    assert manifest["supplied_pack_bytes"] <= 3 * 1024 * 1024
    subject = SigningKey(bytes.fromhex(manifest["subject_seed_hex"]))
    assert subject.verify_key.encode().hex() == manifest["subject_public_key"]
    ready_snapshot(manifest)
    registered = grant_registration(manifest, subject, 1 if MODE == "--quota" else 8)
    assert not submission_tables(), "Begin must bootstrap an absent submission schema"

    # A correctly signed carrier for an operation that has never begun must
    # remain an opaque denial. It must not bootstrap submission storage or
    # charge the grant merely because the surrounding repository is healthy.
    unbegun = upload_body(OPERATION, {"submission_id": "0" * 64,
                                       "submission_generation": "1"}, update)
    checked(403, subject_request("UploadSubmission", unbegun, subject,
                                 content_type="application/octet-stream"),
            code_value="permission_denied")
    assert not submission_tables(), "pre-Begin Upload must not bootstrap submission schema"
    assert counters(OPERATION.hex()) == (0, 0, 0, None)

    body = begin_body(manifest, registered)
    malformed = packed(json.loads(body) | {"update_len": "0"})
    checked(400, subject_request("BeginSubmission", malformed, subject), code_value="invalid_argument")
    foreign = packed(json.loads(body) | {"grant_id": "f" * 64})
    checked(403, subject_request("BeginSubmission", foreign, subject), code_value="permission_denied")
    assert not submission_tables(), "pre-admission rejection must not create schema"
    assert counters(OPERATION.hex()) == (0, 0, 0, None)

    first = subject_request("BeginSubmission", body, subject)
    admitted = checked(200, first)
    assert admitted["state"] == "awaiting_upload" and admitted["revision"] == "0", admitted
    assert admitted["operation_id"] == OPERATION.hex()
    assert counters(OPERATION.hex())[:3] == (1, 1, 1)
    # Treat the first reply as lost: Get by op ID alone recovers random ID/generation.
    assert checked(200, current_status(OPERATION, subject)) == admitted
    assert checked(200, subject_request("BeginSubmission", body, subject)) == admitted
    assert checked(200, send(PATH + "BeginSubmission", body, signed_headers=first[3])) == admitted
    assert counters(OPERATION.hex())[:3] == (1, 1, 1)
    checked(409, subject_request("BeginSubmission", body + b" ", subject), code_value="conflict")
    assert counters(OPERATION.hex())[:3] == (1, 1, 1)

    missing = checked(403, current_status(MISSING_OPERATION, subject), code_value="permission_denied")
    alien = checked(403, current_status(OPERATION, STRANGER), code_value="permission_denied")
    assert missing == alien
    checked(403, subject_request("BeginSubmission", body + b" ", STRANGER), code_value="permission_denied")
    assert counters(OPERATION.hex())[:3] == (1, 1, 1)

    wire = upload_body(OPERATION, admitted, update)
    missing_wire = upload_body(MISSING_OPERATION, admitted, update)
    denied_upload_missing = checked(403, subject_request(
        "UploadSubmission", missing_wire, subject, content_type="application/octet-stream"),
        code_value="permission_denied")
    denied_upload_foreign = checked(403, subject_request(
        "UploadSubmission", wire, STRANGER, content_type="application/octet-stream"),
        code_value="permission_denied")
    assert denied_upload_missing == denied_upload_foreign
    missing_continue = packed(json.loads(continue_body(admitted)) | {"operation_id": MISSING_OPERATION.hex()})
    denied_continue_missing = checked(403, subject_request(
        "ContinueSubmission", missing_continue, subject), code_value="permission_denied")
    denied_continue_foreign = checked(403, subject_request(
        "ContinueSubmission", continue_body(admitted), STRANGER), code_value="permission_denied")
    assert denied_continue_missing == denied_continue_foreign
    assert counters(OPERATION.hex())[:3] == (1, 1, 1)
    if MODE.startswith("--fence-"):
        if MODE == "--fence-policy":
            changed = packed({"version": 1, "expected_generation": "1", "collaborators": []})
            checked(200, admin("ReplacePolicy", changed))
        else:
            target = REF if MODE == "--fence-ref" else PACKMAP_REF
            new_id = bytes([0x75 if MODE == "--fence-ref" else 0x76]) * 32
            result = rpc("UpdateRef", field(1, target) + field(2, 1) + field(4, new_id), OWNER)
            assert code(*result[:2]) == "ok", result[:2]
        checked(409, subject_request("BeginSubmission", body, subject), code_value="conflict")
        checked(409, send(PATH + "BeginSubmission", body, signed_headers=first[3]),
                code_value="conflict")
        checked(409, subject_request("UploadSubmission", wire, subject,
                                     content_type="application/octet-stream"), code_value="conflict")
        checked(409, subject_request("ContinueSubmission", continue_body(admitted), subject),
                code_value="conflict")
        assert checked(200, current_status(OPERATION, subject)) == admitted
        assert counters(OPERATION.hex())[:3] == (1, 1, 1)
        print("actual workerd: signed", MODE, "fenced live effects but preserved historical Get")
        return

    before = counters(OPERATION.hex())
    checked(400, subject_request("UploadSubmission", b"BAD!" + wire[4:], subject,
                                 content_type="application/octet-stream"), code_value="invalid_argument")
    checked(400, subject_request("UploadSubmission", wire[:4] + b"\x02" + wire[5:], subject,
                                 content_type="application/octet-stream"), code_value="invalid_argument")
    checked(400, subject_request("UploadSubmission", wire + b"!", subject,
                                 content_type="application/octet-stream"), code_value="invalid_argument")
    upload_path = PATH + "UploadSubmission"
    signed = make_headers(upload_path, wire, signer=subject,
                          content_type="application/octet-stream")
    checked(401, send(upload_path, wire[:-1] + bytes([wire[-1] ^ 1]),
                      signed_headers=signed), code_value="unauthenticated")
    checked(415, subject_request("UploadSubmission", wire, subject,
                                 content_type="application/octet-stream", encoding="gzip"),
            code_value="unsupported_media_type")
    changed = wire[:-1] + bytes([wire[-1] ^ 1])
    checked(409, subject_request("UploadSubmission", changed, subject,
                                 content_type="application/octet-stream"), code_value="conflict")
    assert counters(OPERATION.hex()) == before
    upload_result = subject_request("UploadSubmission", wire, subject,
                                    content_type="application/octet-stream")
    uploaded = checked(200, upload_result)
    assert uploaded["state"] == "validating" and int(uploaded["revision"]) > 0, uploaded
    assert counters(OPERATION.hex())[:3] == (1, 1, 1)

    saved_replay = None
    inventory_reupload_checked = False
    for attempt in range(256):
        request = continue_body(uploaded)
        result = subject_request("ContinueSubmission", request, subject)
        next_state = checked(200, result)
        assert int(next_state["revision"]) == int(uploaded["revision"]) + 1, (uploaded, next_state)
        if saved_replay is None:
            saved_replay = (request, result[3], next_state)
        uploaded = next_state
        if not inventory_reupload_checked and int(uploaded["progress"]["inventory_entries"]) > 0:
            before_reupload = counters(OPERATION.hex())
            assert checked(200, subject_request("UploadSubmission", wire, subject,
                                                content_type="application/octet-stream")) == uploaded
            assert checked(200, current_status(OPERATION, subject)) == uploaded
            assert counters(OPERATION.hex()) == before_reupload
            inventory_reupload_checked = True
        if uploaded["state"] in ("validated", "refused"):
            break
        assert uploaded["state"] == "validating", uploaded
    else:
        raise AssertionError("small staged validation did not finish in 256 steps")
    assert uploaded["state"] == "validated", uploaded
    assert inventory_reupload_checked, "fresh-nonce Upload after inventory page was not exercised"
    replay_body, replay_headers, replay_state = saved_replay
    assert checked(200, send(PATH + "ContinueSubmission", replay_body,
                             signed_headers=replay_headers)) == replay_state
    checked(409, subject_request("ContinueSubmission", replay_body, subject), code_value="conflict")
    assert checked(200, current_status(OPERATION, subject)) == uploaded
    assert counters(OPERATION.hex())[:3] == (1, 1, 1)

    if MODE == "--quota":
        with sqlite3.connect(database()) as db:
            meta = json.loads(db.execute("SELECT document FROM host_submission_meta WHERE slot=1").fetchone()[0])
        assert meta["active"] == 0, meta  # The per-ref active-job limit is no longer binding.
        assert checked(200, subject_request("BeginSubmission", body, subject)) == uploaded
        second = begin_body(manifest, registered, operation=INVALID_OPERATION)
        checked(429, subject_request("BeginSubmission", second, subject),
                code_value="resource_exhausted")
        assert counters(OPERATION.hex())[:3] == (1, 1, 1)
        assert counters(INVALID_OPERATION.hex())[3] is None
        checked(403, current_status(INVALID_OPERATION, subject), code_value="permission_denied")
        assert_no_publication(manifest)
        print("actual workerd: signed max_operations=1 exact boundary; new identity refused without charge")
        return

    # A correctly bound but invalid carrier is a charged, saved terminal
    # refusal. The earlier mismatch/trailing cases above were pre-admission
    # refusals for an already admitted identity and could not alter it.
    invalid_update = update[:-1] + bytes([update[-1] ^ 1])
    invalid_manifest = manifest | {"update_digest": blake3.blake3(invalid_update).hexdigest()}
    invalid_begin = begin_body(invalid_manifest, registered, operation=INVALID_OPERATION)
    invalid_admitted = checked(200, subject_request("BeginSubmission", invalid_begin, subject))
    assert counters(INVALID_OPERATION.hex())[:3] == (2, 2, 2)
    invalid_wire = upload_body(INVALID_OPERATION, invalid_admitted, invalid_update)
    rejected = subject_request("UploadSubmission", invalid_wire, subject,
                               content_type="application/octet-stream")
    checked(422, rejected, code_value="unsupported_profile")
    invalid_status = checked(200, current_status(INVALID_OPERATION, subject))
    assert invalid_status["state"] == "refused" and invalid_status["code"] == "unsupported_profile"
    assert counters(INVALID_OPERATION.hex())[:3] == (2, 2, 2)

    revoke = packed({"version": 1, "workspace_id": WORKSPACE.hex(),
                     "expected_grant_generation": "1", "grant_id": registered["grant_id"]})
    checked(200, admin("RevokeGrant", revoke))
    assert checked(200, current_status(OPERATION, subject)) == uploaded
    assert checked(200, current_status(INVALID_OPERATION, subject)) == invalid_status
    checked(403, subject_request("BeginSubmission", body, subject), code_value="permission_denied")
    checked(403, send(PATH + "BeginSubmission", body, signed_headers=first[3]),
            code_value="permission_denied")
    checked(409, subject_request("UploadSubmission", wire, subject,
                                 content_type="application/octet-stream"), code_value="conflict")
    checked(409, send(PATH + "UploadSubmission", wire, signed_headers=upload_result[3]),
            code_value="conflict")
    checked(409, subject_request("ContinueSubmission", continue_body(uploaded), subject),
            code_value="conflict")
    checked(409, send(PATH + "ContinueSubmission", replay_body,
                      signed_headers=replay_headers), code_value="conflict")
    assert counters(OPERATION.hex())[:3] == (2, 2, 2)
    assert_no_publication(manifest)
    print("actual workerd: SMALL validation, two exact charges, terminal refusal, revocation, retries, no publication")


if __name__ == "__main__":
    if len(sys.argv) not in (4, 5):
        raise SystemExit("expected local origin, SMALL fixture directory, disposable Wrangler state, optional fence mode")
    configure(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) == 5 else "positive")
    main()
