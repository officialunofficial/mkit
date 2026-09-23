"""Real local workerd check for the unchanged default public service profile."""
import base64
import json
import urllib.request
import uuid

import managed_access as wire

wire.REPO = "default"
path = "/mkit.transport.v1.TransportService/"
name = "refs/heads/default-compat-" + str(uuid.uuid4())
read = json.dumps({"name": name}).encode()
def unsigned_read():
    request = urllib.request.Request(wire.ORIGIN + path + "ReadRef", data=read, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request) as response:
        return response.status, json.load(response)

status, body = unsigned_read()
assert status == 200 and body.get("exists") is False, (status, body)
value = base64.b64encode(bytes([5] * 32)).decode()
update = json.dumps({"name": name, "newId": value, "expectation": "REF_EXPECTATION_ANY"}).encode()
status, body, _, _, _ = wire.send(path + "UpdateRef", update)
assert status == 200, (status, body)
status, body = unsigned_read()
assert status == 200 and body.get("objectId") == value, (status, body)
print("default workerd: unsigned read and signed write unchanged")
