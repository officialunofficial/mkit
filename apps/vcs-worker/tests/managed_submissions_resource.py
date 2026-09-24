"""Actual local workerd >128 MiB staged-submission resource exercise.

Use the native `submission_resource_fixture large` output and a fresh disposable
Wrangler --persist-to directory. Run `--start`, stop only that Wrangler process,
restart it with the SAME directory, then run `--resume`. R2 fixture seeding uses
Wrangler's LOCAL Explorer and deliberately bypasses ordinary UploadPack's
separate write-window quota; every enrollment and admission step uses signed
service requests. The two modes never manufacture SQL validation state.
"""

import json
import sqlite3
import sys
import time
import urllib.parse
import urllib.request
from contextlib import closing
from pathlib import Path

import blake3
from nacl.signing import SigningKey

import managed_submissions_admission as admission

MIB = 1024 * 1024
BUCKET = "mkit-vcs-managed-local-test"
JOB_ID = bytes([0x73]).hex() * 32
MAX_ENROLL_STEPS = 8192
MAX_SUBMISSION_STEPS = 8192
MAX_WALL_SECONDS = 1800


def fixture_manifest(directory):
    manifest = json.loads((directory / "manifest.json").read_bytes())
    assert manifest["mode"] == "large" and manifest["test_material"] is True
    assert manifest["base_unique_canonical_bytes"] > 128 * MIB
    assert len(manifest["base_inventory"]) == manifest["base_object_count"]
    assert len(manifest["selected_pack_keys"]) == manifest["base_pack_count"] <= 128
    assert manifest["selected_paths"] == [["selected.txt"]]
    assert manifest["update_len"] <= 4 * MIB and manifest["supplied_pack_bytes"] <= 3 * MIB
    assert manifest["supplied_object_count"] == len(manifest["supplied_inventory"])
    assert blake3.blake3((directory / manifest["update_file"]).read_bytes()).hexdigest() == manifest["update_digest"]
    base = {entry["id"]: entry["canonical_bytes"] for entry in manifest["base_inventory"]}
    assert len(base) == manifest["base_object_count"]
    assert sum(base.values()) == manifest["base_unique_canonical_bytes"]
    hidden = {entry["id"]: entry["canonical_bytes"] for entry in manifest["base_inventory"]
              if entry["type"] == "Blob" and entry["canonical_bytes"] > MIB}
    assert len(hidden) == 132 and sum(hidden.values()) > 128 * MIB
    old_selected = [entry for entry in manifest["base_inventory"]
                    if entry["type"] == "Blob" and entry["canonical_bytes"] < 1024]
    assert len(old_selected) == 1
    assert sum(entry["type"] == "Tree" for entry in manifest["base_inventory"]) == 1
    assert sum(entry["type"] == "Commit" for entry in manifest["base_inventory"]) == 1
    supplied = {entry["id"]: entry["canonical_bytes"] for entry in manifest["supplied_inventory"]}
    assert len(supplied) == manifest["supplied_object_count"] == 3
    assert not set(hidden) & set(supplied)
    candidate = hidden | supplied
    assert len(candidate) == manifest["base_object_count"] == 135
    assert sum(candidate.values()) > 128 * MIB
    assert manifest["candidate_root"] in supplied
    return manifest, base, supplied, candidate


def rows(query, params=()):
    # sqlite3's connection context manager commits; it does not close. A
    # per-step diagnostic open must close explicitly across hundreds of pages.
    with closing(sqlite3.connect(admission.database(), timeout=2)) as db:
        return db.execute(query, params).fetchall()


def ledger_map(table, phase=None):
    assert table in ("host_snapshot_seen", "host_submission_seen", "host_submission_supplied",
                     "host_submission_required", "host_submission_inventory")
    if table == "host_snapshot_seen":
        query = "SELECT object_id,canonical_len FROM host_snapshot_seen WHERE job_id=?"
        params = (JOB_ID,)
    elif table == "host_submission_seen":
        assert phase in ("base_walk", "candidate_walk")
        query = "SELECT object_id,canonical_len FROM host_submission_seen WHERE operation_id=? AND phase=?"
        params = (admission.OPERATION.hex(), phase)
    else:
        query = f"SELECT object_id,canonical_len FROM {table} WHERE operation_id=?"
        params = (admission.OPERATION.hex(),)
    entries = rows(query, params)
    result = {identifier: length for identifier, length in entries}
    assert len(result) == len(entries), (table, len(entries), len(result))
    return result


def job_document():
    result = rows("SELECT document FROM host_submission_jobs WHERE operation_id=?",
                  (admission.OPERATION.hex(),))
    assert len(result) == 1, result
    return json.loads(result[0][0])


def seed_local_r2(key, payload):
    """Write only to the disposable Wrangler local Explorer, never cloud R2."""
    assert blake3.blake3(payload).hexdigest() == key
    assert len(payload) <= 4 * MIB
    object_key = urllib.parse.quote("packs/" + key, safe="")
    url = (admission.ORIGIN + "/cdn-cgi/local/explorer/api/r2/buckets/" + BUCKET
           + "/objects/" + object_key)
    request = urllib.request.Request(url, data=payload, method="PUT",
                                     headers={"Content-Type": "application/octet-stream"})
    with urllib.request.urlopen(request, timeout=60) as response:
        result = json.load(response)
    assert result["success"] and result["result"]["size"] == len(payload), (key, result)


def enroll_large(directory, manifest, expected_base):
    admission.checked(200, admission.admin("InitializePolicy", b'{"version":1,"collaborators":[]}'))
    pack_files = manifest["output_files"]["base_packs_and_tip"]
    assert len(pack_files) == manifest["base_pack_count"] + 1
    physical = 0
    started = time.monotonic()
    for key, filename in sorted(pack_files.items()):
        payload = (directory / filename).read_bytes()
        seed_local_r2(key, payload)
        physical += len(payload)
    assert physical <= 256 * MIB, physical
    advance = (admission.field(1, admission.REF) + admission.field(2, 2)
               + admission.field(4, bytes.fromhex(manifest["base_root"]))
               + admission.field(5, admission.PACKMAP_REF) + admission.field(6, 2)
               + admission.field(8, bytes.fromhex(manifest["base_tip"])))
    result = admission.rpc("AdvanceRefs", advance, admission.OWNER)
    assert admission.code(*result[:2]) == "ok", result[:2]
    begin = admission.packed({"version": 1, "job_id": JOB_ID, "ref": admission.REF,
                              "expected_head": manifest["base_root"],
                              "expected_packmap": manifest["base_tip"],
                              "selected_pack_keys": manifest["selected_pack_keys"]})
    state = admission.checked(200, admission.admin("BeginSnapshot", begin))
    assert state["state"] == "catalog" and state["revision"] == "0", state
    steps = 0
    while steps < MAX_ENROLL_STEPS and time.monotonic() - started < MAX_WALL_SECONDS:
        command = admission.packed({"version": 1, "job_id": JOB_ID,
                                    "job_generation": state["job_generation"],
                                    "expected_revision": state["revision"]})
        state = admission.checked(200, admission.admin("ContinueSnapshot", command))
        steps += 1
        if steps % 64 == 0 or state["state"] == "ready":
            print("C1 enrollment", steps, state["state"], state["progress"], flush=True)
        if state["state"] == "ready":
            break
        assert state["state"] in ("catalog", "walk"), state
    else:
        raise AssertionError("large C1 enrollment did not reach ready within bounded steps/time")
    assert int(state["progress"]["reached_bytes"]) == sum(expected_base.values()), state
    assert int(state["progress"]["reached_objects"]) == len(expected_base), state
    assert int(state["progress"]["catalog_entries"]) == len(expected_base), state
    assert ledger_map("host_snapshot_seen") == expected_base
    return steps, physical, time.monotonic() - started, state


def start(directory, manifest, expected_base):
    steps, physical, elapsed, ready = enroll_large(directory, manifest, expected_base)
    subject = SigningKey(bytes.fromhex(manifest["subject_seed_hex"]))
    assert subject.verify_key.encode().hex() == manifest["subject_public_key"]
    registered = admission.grant_registration(manifest, subject)
    assert admission.counters(admission.OPERATION.hex()) == (0, 0, 0, None)
    begin = admission.begin_body(manifest, registered)
    admitted = admission.checked(200, admission.subject_request("BeginSubmission", begin, subject))
    assert admitted["state"] == "awaiting_upload" and admitted["revision"] == "0"
    assert admission.counters(admission.OPERATION.hex())[:3] == (1, 1, 1)
    update = (directory / manifest["update_file"]).read_bytes()
    carrier = admission.upload_body(admission.OPERATION, admitted, update)
    uploaded = admission.checked(200, admission.subject_request(
        "UploadSubmission", carrier, subject, content_type="application/octet-stream"))
    assert uploaded["state"] == "validating" and uploaded["revision"] == "1", uploaded
    # One real bounded Continue before process restart. Get-only recovery is
    # enough to resume; no client-secret submission ID file is written.
    first = admission.checked(200, admission.subject_request(
        "ContinueSubmission", admission.continue_body(uploaded), subject))
    assert first["state"] == "validating" and first["revision"] == "2", first
    assert int(first["progress"]["attempts"]) >= 2
    assert admission.counters(admission.OPERATION.hex())[:3] == (1, 1, 1)
    print("large start ready for controlled Worker restart", json.dumps({
        "distinct_base_bytes": sum(expected_base.values()), "base_objects": len(expected_base),
        "base_packs": manifest["base_pack_count"], "local_r2_seed_bytes": physical,
        "enrollment_steps": steps, "setup_and_enrollment_wall_s": round(elapsed, 3),
        "enrollment_progress": ready["progress"], "staged": first,
    }, separators=(",", ":")), flush=True)


def resume(manifest, expected_base, supplied, candidate):
    subject = SigningKey(bytes.fromhex(manifest["subject_seed_hex"]))
    state = admission.checked(200, admission.current_status(admission.OPERATION, subject))
    assert state["state"] == "validating" and int(state["revision"]) >= 2, state
    assert int(state["progress"]["attempts"]) >= 2
    assert admission.counters(admission.OPERATION.hex())[:3] == (1, 1, 1)
    previous = {key: int(state["progress"][key]) for key in
                ("attempts", "reserved_io_bytes", "r2_operations")}
    maxima = {"frontier_rows": 0, "frontier_bytes": 0, "step_ms": 0}
    started = time.monotonic()
    steps = 0
    while steps < MAX_SUBMISSION_STEPS and time.monotonic() - started < MAX_WALL_SECONDS:
        began = time.monotonic()
        next_state = admission.checked(200, admission.subject_request(
            "ContinueSubmission", admission.continue_body(state), subject))
        elapsed_ms = int((time.monotonic() - began) * 1000)
        assert int(next_state["revision"]) == int(state["revision"]) + 1, (state, next_state)
        for key, old in previous.items():
            now = int(next_state["progress"][key])
            assert now >= old, (key, old, now)
            previous[key] = now
        job = job_document()
        maxima["frontier_rows"] = max(maxima["frontier_rows"], job["frontier_rows"])
        maxima["frontier_bytes"] = max(maxima["frontier_bytes"], job["frontier_bytes"])
        maxima["step_ms"] = max(maxima["step_ms"], elapsed_ms)
        state = next_state
        steps += 1
        if steps % 64 == 0 or state["state"] in ("validated", "refused"):
            print("staged validation", steps, state["state"], state["progress"], flush=True)
        if state["state"] == "validated":
            break
        assert state["state"] == "validating", state
    else:
        raise AssertionError("large staged validation did not reach validated within bounded steps/time")
    assert admission.checked(200, admission.current_status(admission.OPERATION, subject)) == state
    assert ledger_map("host_submission_seen", "base_walk") == expected_base
    assert ledger_map("host_submission_seen", "candidate_walk") == candidate
    assert ledger_map("host_submission_supplied") == supplied
    assert ledger_map("host_submission_required") == supplied
    assert ledger_map("host_submission_inventory") == supplied
    assert len(rows("SELECT change_index FROM host_submission_matched WHERE operation_id=?",
                    (admission.OPERATION.hex(),))) == 1
    job = job_document()
    assert job["state"] == "validated" and job["phase"] == "terminal", job
    assert job["base_objects"] == len(expected_base), job
    assert job["candidate_objects"] == len(candidate), job
    assert job["required_objects"] == len(supplied), job
    assert job["supplied_objects"] == len(supplied), job
    assert job["fit_attempts"] >= 1 and job["fit_io_bytes"] <= 32 * MIB, job
    assert job["usage"]["base_walk"]["canonical_bytes"] == sum(expected_base.values()), job
    assert job["usage"]["candidate_walk"]["canonical_bytes"] == sum(candidate.values()), job
    assert sum(candidate.values()) > 128 * MIB
    assert admission.counters(admission.OPERATION.hex())[:3] == (1, 1, 1)
    admission.assert_no_publication(manifest)
    print("large actual workerd validated", json.dumps({
        "distinct_base_bytes": sum(expected_base.values()),
        "distinct_candidate_bytes": sum(candidate.values()),
        "base_objects": len(expected_base), "candidate_objects": len(candidate),
        "supplied_objects": len(supplied), "resume_steps_this_process": steps,
        "resume_wall_s_this_process": round(time.monotonic() - started, 3),
        "max_observed_post_step_this_process": maxima, "progress": state["progress"],
        "fit_attempts": job["fit_attempts"], "fit_reserved_io_bytes": job["fit_io_bytes"],
        "fit_reserved_r2_operations": job["fit_operations"],
        "charged_io_not_actual_observed_io": True,
    }, separators=(",", ":")), flush=True)


def main():
    if len(sys.argv) != 5 or sys.argv[4] not in ("--start", "--resume"):
        raise SystemExit("usage: resource.py http://localhost:8791 LARGE_DIR STATE_DIR --start|--resume")
    origin, directory, state, mode = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4]
    admission.configure(origin, directory, state)
    manifest, base, supplied, candidate = fixture_manifest(directory)
    if mode == "--start":
        start(directory, manifest, base)
    else:
        resume(manifest, base, supplied, candidate)


if __name__ == "__main__":
    main()
