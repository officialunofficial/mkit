"""Local workerd replay, quota, and revocation faults; requires test-faults build."""
import json
import secrets
import sqlite3
import sys
from pathlib import Path

import blake3
import managed_data as m

state = Path(sys.argv[1])
database = next(path for path in state.glob("v3/do/mkit-vcs-managed-local-test-RefStore/*.sqlite") if path.name != "metadata.sqlite")


def snapshot():
    with sqlite3.connect(database) as db:
        key = m.WRITER.verify_key.encode().hex()
        quota = db.execute("SELECT ops,bytes FROM write_quota WHERE author=?", (key,)).fetchone() or (0, 0)
        ledger = db.execute("SELECT count(*),sum(reply IS NULL) FROM authenticated_operations").fetchone()
        return quota, ledger


def write_effects():
    """Compare full persistent write state, not only one author's counters."""
    with sqlite3.connect(database) as db:
        return tuple(tuple(db.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall())
                     for table in ("write_quota", "authenticated_operations", "refs"))


def replace(members):
    current = json.loads(m.admin("GetPolicy", b'{"version":1}')[1])
    result = m.admin("ReplacePolicy", m.policy(members, int(current["generation"])))
    assert result[0] == 200, result[:2]


def upload(payload, stage=None):
    pack_id = blake3.blake3(payload).digest()
    header = m.field(1, pack_id) + m.field(2, len(payload))
    chunk = m.field(1, pack_id) + m.field(2, 0) + m.field(3, payload) + m.field(4, 1)
    body = m.frame(m.field(1, header)) + m.frame(m.field(2, chunk))
    headers = m.signed_headers(m.SERVICE + "UploadPack", b"", m.WRITER,
                               "pack:" + pack_id.hex() + ":" + str(len(payload)),
                               "application/connect+proto")
    if stage:
        headers["X-Mkit-Test-Fault"] = stage
    return pack_id, body, headers


def send(body, headers):
    response = m.send(m.SERVICE + "UploadPack", body, headers)
    return m.code(*response[:2])


def exists(pack_id):
    response = m.rpc("PackExists", m.field(1, pack_id), m.OWNER)
    assert response[0] == 200, response[:2]
    return response[1] == b"\x08\x01"


def main():
    replace([(m.READER, "reader"), (m.WRITER, "writer")])
    for label, signer, denied in [
        ("anonymous", None, "unauthenticated"),
        ("stranger", m.STRANGER, "permission_denied"),
        ("reader", m.READER, "permission_denied"),
    ]:
        candidate = label.encode() + b"-fresh-denied-" + secrets.token_bytes(16)
        pack_id, body, _ = upload(candidate)
        assert not exists(pack_id), label
        before = write_effects()
        headers = ({"Content-Type": "application/connect+proto"} if signer is None else
                   m.signed_headers(m.SERVICE + "UploadPack", b"", signer,
                                    "pack:" + pack_id.hex() + ":" + str(len(candidate)),
                                    "application/connect+proto"))
        assert send(body, headers) == denied, label
        assert not exists(pack_id), label
        assert write_effects() == before, (label, before, write_effects())
        print(label, "fresh upload denied without R2/quota/replay/ref effect")

    pack_id, body, headers = upload(b"valid-identical-resume" + secrets.token_bytes(8))
    before = snapshot()
    assert send(body, headers) == "ok"
    after_first = snapshot()
    assert send(body, headers) == "ok"
    after_retry = snapshot()
    assert after_first == after_retry, (after_first, after_retry)
    assert after_first[0][0] == before[0][0] + 1
    assert exists(pack_id)

    for stage in ["after-reserve", "before-put", "after-put"]:
        pack_id, body, headers = upload(stage.encode() + b"-revocation" + secrets.token_bytes(8), stage)
        before = snapshot()
        fault_result = send(body, headers)
        assert fault_result == "internal", (stage, fault_result)
        faulted = snapshot()
        assert faulted[0][0] == before[0][0] + 1, (stage, before, faulted)
        assert faulted[1][1] == before[1][1] + 1, (stage, before, faulted)
        assert exists(pack_id) == (stage == "after-put"), stage
        replace([(m.READER, "reader")])
        revoked_state = snapshot()
        without_fault = headers.copy()
        without_fault.pop("X-Mkit-Test-Fault")
        assert send(body, without_fault) == "permission_denied", stage
        assert snapshot() == revoked_state, (stage, revoked_state, snapshot())
        assert exists(pack_id) == (stage == "after-put"), stage
        replace([(m.READER, "reader"), (m.WRITER, "writer")])
        assert send(body, without_fault) == "ok", stage
        completed = snapshot()
        assert completed[0] == faulted[0], (stage, faulted, completed)
        assert completed[1][1] == faulted[1][1] - 1
        assert exists(pack_id)
        print(stage, "revoked resume denied; one quota charge; completion after regrant")


if __name__ == "__main__":
    main()
