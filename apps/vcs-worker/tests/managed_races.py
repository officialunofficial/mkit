"""Race managed ref CAS against policy replacement in real local workerd."""
import json
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import managed_data as m


def replace(members):
    current = json.loads(m.admin("GetPolicy", b'{"version":1}')[1])
    result = m.admin("ReplacePolicy", m.policy(members, int(current["generation"])))
    assert result[0] == 200, result[:2]


def read(name, value):
    response = m.rpc("ReadRef", m.field(1, name), m.OWNER)
    assert response[0] == 200, response[:2]
    return value in response[1]


def race(method, delay_write):
    replace([(m.READER, "reader"), (m.WRITER, "writer")])
    suffix = secrets.token_hex(8)
    head = "refs/heads/race-" + suffix
    packmap = "refs/mkit/packmap/race-" + suffix
    head_id = secrets.token_bytes(32)
    packmap_id = secrets.token_bytes(32)
    message = m.field(1, head) + m.field(2, 2) + m.field(4, head_id)
    if method == "AdvanceRefs":
        message += m.field(5, packmap) + m.field(6, 2) + m.field(8, packmap_id)
    barrier = threading.Barrier(2)

    def write():
        barrier.wait()
        if delay_write:
            time.sleep(0.05)
        response = m.rpc(method, message, m.WRITER)
        return m.code(*response[:2])

    def revoke():
        barrier.wait()
        replace([(m.READER, "reader")])

    with ThreadPoolExecutor(max_workers=2) as pool:
        written = pool.submit(write)
        revoked = pool.submit(revoke)
        result = written.result()
        revoked.result()
    assert result in ("ok", "permission_denied"), (method, result)
    assert read(head, head_id) == (result == "ok"), (method, result)
    if method == "AdvanceRefs":
        assert read(packmap, packmap_id) == (result == "ok"), (method, result)
    print(method, result, "consistent")


if __name__ == "__main__":
    for procedure in ["UpdateRef", "AdvanceRefs"]:
        for index in range(8):
            race(procedure, index % 2 == 1)
