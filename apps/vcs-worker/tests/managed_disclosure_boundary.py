"""Read one enrolled 256 KiB/256 KiB+1 file through actual managed workerd."""
import json
import sys
from pathlib import Path

from managed_disclosure import WORKSPACE, REF, admin, credential, expect, post


def main(directory, expected):
    fixture = json.loads((directory / "manifest.json").read_bytes())
    assert fixture["blob_count"] == 1
    assert fixture["blob_bytes"] in (256 * 1024, 256 * 1024 + 1)
    signed, grant_id = credential(fixture["root"])
    expect(200, admin("RegisterGrant", json.dumps({
        "version": 1, "expected_grant_generation": "0", "grant": signed,
    }, separators=(",", ":")).encode()))
    request = {"version": 1, "workspace_id": WORKSPACE.hex(), "grant_id": grant_id,
               "grant_generation": "1", "expected_ref": REF,
               "expected_base": fixture["root"], "paths": [["file0000"]]}
    result = post(request)
    assert result[0] == expected, result
    if expected == 200:
        assert result[4].startswith(b"MKWB") and len(result[4]) <= 4 * 1024 * 1024
    else:
        assert result[1] == {"code": "resource_exhausted"}, result
        assert not result[4].startswith(b"MKWB")
    print("actual workerd file bytes", fixture["blob_bytes"], "status", result[0],
          "response bytes", len(result[4]))


if __name__ == "__main__":
    main(Path(sys.argv[-2]), int(sys.argv[-1]))
