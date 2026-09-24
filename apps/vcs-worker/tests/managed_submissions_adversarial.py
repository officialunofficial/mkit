"""Actual-workerd staged-origin and complete-selection profile cases.

Each invocation requires a fresh disposable Wrangler state and one native
submission_adversarial_fixture output directory. This is functional evidence,
not a memory or production-provider capacity measurement.
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

import managed_submissions_admission as admission
from managed_access import admin
from managed_data import OWNER, STRANGER, varint


def grant(manifest, subject):
    now = int(time.time() * 1000)
    body = bytearray(b"MKHG\x01")
    for value in (admission.ORIGIN, "managed-test", admission.REF):
        raw = value.encode()
        body.extend(varint(len(raw)) + raw)
    body.extend(admission.WORKSPACE)
    for key in (OWNER.verify_key.encode(), subject.verify_key.encode(), STRANGER.verify_key.encode()):
        body.extend(key)
    body.extend(struct.pack(">QQ", 1, 1))
    body.extend(bytes.fromhex(manifest["base_root"]))
    body.extend(struct.pack(">QQI", now - 1000, now + 3_600_000, 8))
    body.extend(varint(len(manifest["selected_paths"])))
    for path in manifest["selected_paths"]:
        assert len(path) == 1
        body.extend(varint(1))
        component = path[0].encode()
        body.extend(varint(len(component)) + component)
        body.append(3)  # READ|REPLACE, including unchanged selected files.
    digest = blake3.blake3(b"mkit.hosted-workspace-grant.v1\0" + body).digest()
    body.extend(OWNER.sign(digest).signature)
    return base64.urlsafe_b64encode(body).decode().rstrip("=")


def run(origin, fixture, state):
    admission.configure(origin, fixture, state)
    manifest = json.loads((Path(fixture) / "manifest.json").read_bytes())
    assert manifest["test_material"] is True
    update = (Path(fixture) / manifest["update_file"]).read_bytes()
    assert len(update) == manifest["update_len"]
    assert blake3.blake3(update).hexdigest() == manifest["update_digest"]
    subject = SigningKey(bytes.fromhex(manifest["subject_seed_hex"]))
    assert subject.verify_key.encode().hex() == manifest["subject_public_key"]
    ready = admission.ready_snapshot(manifest)
    assert ready["state"] == "ready"
    credential = grant(manifest, subject)
    registered = admission.checked(200, admin("RegisterGrant", admission.packed({
        "version": 1, "expected_grant_generation": "0", "grant": credential,
    })))
    assert not admission.submission_tables()
    begin = admission.begin_body(manifest, registered)
    admitted = admission.checked(200, admission.subject_request("BeginSubmission", begin, subject))
    assert admitted["state"] == "awaiting_upload"
    assert admission.counters(admission.OPERATION.hex())[:3] == (1, 1, 1)
    wire = admission.upload_body(admission.OPERATION, admitted, update)
    upload_response = admission.subject_request(
        "UploadSubmission", wire, subject, content_type="application/octet-stream")
    upload_status, upload_payload = upload_response[:2]
    if upload_status == 200:
        current = admission.checked(200, upload_response)
        assert current["state"] == "validating", current
    else:
        assert upload_status == 422, (upload_status, upload_payload)
        assert admission.checked(422, upload_response,
                                 code_value=manifest["expected_code"])
        current = admission.checked(200, admission.current_status(admission.OPERATION, subject))
    for step in range(256):
        if current["state"] in ("validated", "refused"):
            break
        assert current["state"] == "validating", current
        response = admission.subject_request("ContinueSubmission", admission.continue_body(current), subject)
        if response[0] == 200:
            next_state = admission.checked(200, response)
            assert int(next_state["revision"]) == int(current["revision"]) + 1
            current = next_state
        else:
            assert response[0] in (422, 429), response[:2]
            admission.checked(response[0], response, code_value=manifest["expected_code"])
            current = admission.checked(200, admission.current_status(admission.OPERATION, subject))
    else:
        raise AssertionError("adversarial case did not terminate in 256 pages")
    assert current["state"] == manifest["expected_validation"], current
    if current["state"] == "refused":
        assert current["code"] == manifest["expected_code"], current
    if manifest["mode"].startswith("fit_"):
        # The exact/+1 boundary differs in one selected positional byte only.
        assert manifest["selected_post_edit_bytes"] == 1024 * 1024 + (manifest["mode"] == "fit_over")
    assert admission.counters(admission.OPERATION.hex())[:3] == (1, 1, 1)
    with sqlite3.connect(admission.database()) as db:
        refs = dict(db.execute("SELECT path,value FROM refs WHERE path IN (?,?)",
                               (admission.REF, admission.PACKMAP_REF)).fetchall())
    assert refs == {admission.REF: manifest["base_root"],
                    admission.PACKMAP_REF: manifest["base_tip"]}, refs
    print("actual workerd adversarial", manifest["mode"], "passed in", step,
          "Continue pages; final", current["state"], current.get("code"))


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("expected local origin, adversarial fixture directory, disposable Wrangler state")
    run(*sys.argv[1:])
