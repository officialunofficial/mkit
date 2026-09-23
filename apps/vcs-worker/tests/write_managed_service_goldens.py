"""Regenerate managed service framing vectors only with explicit opt-in."""
import json
import os
from pathlib import Path

import blake3

ROOT = Path(__file__).resolve().parents[3] / "rust/tests/golden/managed-service"


def field(number, value):
    return bytes([(number << 3) | 2, len(value)]) + value


def frame(message):
    return b"\x00" + len(message).to_bytes(4, "big") + message


def main():
    if os.environ.get("MKIT_WRITE_GOLDEN") != "1":
        raise SystemExit("set MKIT_WRITE_GOLDEN=1 to regenerate managed service vectors")
    vectors = {}
    for method, message in [
        ("ReadRef", field(1, b"refs/heads/main")),
        ("DownloadPack", field(1, bytes(32))),
    ]:
        vectors[method] = {
            "procedure": "/mkit.transport.v1.TransportService/" + method,
            "message_hex": message.hex(),
            "framed_hex": frame(message).hex(),
            "digest": blake3.blake3(message).hexdigest(),
            "framed_digest": blake3.blake3(frame(message)).hexdigest(),
            "negative": ["missing_signature", "wrong_audience", "wrong_repository", "wrong_procedure", "wrong_message"],
        }
    vectors["DownloadPack"]["negative"] += ["extra_frame", "trailing_byte", "compressed_frame", "compressed_body"]
    ROOT.mkdir(parents=True, exist_ok=True)
    content = json.dumps({"version": 1, "vectors": vectors}, indent=2, sort_keys=True) + "\n"
    (ROOT / "examples.json").write_text(content)
    (ROOT / "MANIFEST.txt").write_text(blake3.blake3(content.encode()).hexdigest() + "  examples.json\n")


if __name__ == "__main__":
    main()
