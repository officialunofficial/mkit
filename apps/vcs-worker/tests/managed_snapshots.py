"""Owner Snapshot enrollment against disposable local workerd/R2/SQLite state.

Generate a fixture with `cargo run --example snapshot_fixture -- DIR COUNT BYTES`.
For the >128 MiB unique-reachable case, use COUNT=65 and BYTES=2097142.
"""

import json
import os
import sys
import urllib.parse
import urllib.request
from pathlib import Path

import blake3

# The shared signed-admin helper takes its origin from argv[1].
sys.argv.insert(1, "http://localhost:8791")
from managed_access import admin, expect
from managed_data import OWNER, code, field, frame, rpc, send, signed_headers, SERVICE


def upload_pack(key, payload):
    pack_id = bytes.fromhex(key)
    assert blake3.blake3(payload).digest() == pack_id
    header = field(1, pack_id) + field(2, len(payload))
    chunk = field(1, pack_id) + field(2, 0) + field(3, payload) + field(4, 1)
    wire = frame(field(1, header)) + frame(field(2, chunk))
    path = SERVICE + "UploadPack"
    headers = signed_headers(path, b"", OWNER, "pack:" + key + ":" + str(len(payload)), "application/connect+proto")
    status, body, _ = send(path, wire, headers)
    assert code(status, body) == "ok", (key, status, body)


def seed_local_r2(key, payload):
    """Fixture setup only: Wrangler's local Explorer writes actual emulated R2.

    This bypasses the separate managed UploadPack write-window quota; the
    enrollment service still reads and verifies all bytes through real R2.
    """
    assert blake3.blake3(payload).hexdigest() == key
    object_key = urllib.parse.quote("packs/" + key, safe="")
    bucket = os.environ.get("MKIT_SNAPSHOT_R2_BUCKET", "mkit-vcs-objects")
    url = ("http://localhost:8791/cdn-cgi/local/explorer/api/r2/buckets/"
           + bucket + "/objects/" + object_key)
    request = urllib.request.Request(url, data=payload, method="PUT",
                                     headers={"Content-Type": "application/octet-stream"})
    with urllib.request.urlopen(request, timeout=30) as response:
        result = json.load(response)
    assert result["success"] and result["result"]["size"] == len(payload), (key, result)


def request(method, value, **kwargs):
    body = json.dumps(value, separators=(",", ":")).encode()
    response = admin(method, body, **kwargs)
    return response, body


def run(directory):
    fixture = json.loads((directory / "manifest.json").read_bytes())
    selected = fixture["selected"]
    if "--large" in sys.argv:
        assert fixture["unique_canonical_bytes"] > 128 * 1024 * 1024
        assert len(selected) <= 128
    initialized = admin("InitializePolicy", b'{"version":1,"collaborators":[]}')
    assert initialized[0] in (200, 409), initialized
    expect(200, admin("GetPolicy", b'{"version":1}'))
    for path in sorted(directory.glob("*.pack")):
        payload = path.read_bytes()
        if "--local-r2-seed" in sys.argv:
            seed_local_r2(path.stem, payload)
        else:
            upload_pack(path.stem, payload)
    name = "refs/heads/snapshot-test"
    packmap_ref = "refs/mkit/packmap/snapshot-test"
    update = (field(1, name) + field(2, 2) + field(4, bytes.fromhex(fixture["root"]))
              + field(5, packmap_ref) + field(6, 2) + field(8, bytes.fromhex(fixture["tip"])))
    result = rpc("AdvanceRefs", update, OWNER)
    assert code(*result[:2]) == "ok", result
    job_id = "1" * 64
    begin, raw = request("BeginSnapshot", {
        "version": 1, "job_id": job_id, "ref": name,
        "expected_head": fixture["root"], "expected_packmap": fixture["tip"],
        "selected_pack_keys": selected,
    })
    state = expect(200, begin)
    assert state["state"] == "catalog" and state["revision"] == "0", state
    assert expect(200, admin("BeginSnapshot", raw, signed_headers=begin[3])) == state
    expect(409, request("BeginSnapshot", {"version": 1, "job_id": job_id, "ref": name,
        "expected_head": fixture["root"], "expected_packmap": fixture["tip"],
        "selected_pack_keys": selected})[0])
    seen_states = []
    for attempt in range(256):
        command = {"version": 1, "job_id": job_id,
                   "job_generation": state["job_generation"], "expected_revision": state["revision"]}
        response, body = request("ContinueSnapshot", command)
        if fixture.get("unsupported_profile") and attempt == 1:
            assert expect(422, response) == {"code": "unsupported_profile"}
            assert expect(422, admin("ContinueSnapshot", body, signed_headers=response[3])) == {"code": "unsupported_profile"}
            assert expect(200, request("GetSnapshotJob", {"version": 1, "job_id": job_id})[0])["state"] == "failed"
            print("actual workerd well-framed nonraw pack terminal 422")
            return
        state = expect(200, response)
        assert state["job_generation"] == command["job_generation"]
        assert int(state["revision"]) == int(command["expected_revision"]) + 1
        assert expect(200, admin("ContinueSnapshot", body, signed_headers=response[3])) == state
        seen_states.append(state["state"])
        if state["state"] == "ready":
            break
        assert state["state"] in ("catalog", "walk"), state
        if attempt % 16 == 0:
            print("continue", attempt, state["state"], state["progress"], flush=True)
    else:
        raise AssertionError("job did not complete in bounded attempts")
    current = expect(200, request("GetSnapshotJob", {"version": 1, "job_id": job_id})[0])
    assert current == state
    assert int(state["progress"]["reached_bytes"]) == fixture["unique_canonical_bytes"], state
    expected_objects = fixture["blob_count"] + 2 + int(bool(fixture.get("editable_path")))
    assert int(state["progress"]["reached_objects"]) == expected_objects, state
    assert int(state["progress"]["catalog_entries"]) == expected_objects, state
    assert set(seen_states) == {"catalog", "walk", "ready"}
    print("actual workerd enrollment ready", fixture["unique_canonical_bytes"], state["progress"])


if __name__ == "__main__":
    run(Path(sys.argv[2]))
