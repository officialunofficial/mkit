# Replay fixtures

The classifier matrix covers authoritative absence, committed results,
resumable and nonresumable in-flight records, each with matching and different
fingerprints. A committed result is returned exactly. The host checks the
current envelope before lookup; record retention does not extend validity.
Signed reads bypass the ledger.

The code matrix pins all sixteen Connect refusal codes plus an unknown code.
Only the seven listed permanent codes can be stored. Admission challenges
are excluded even when their transport code is permission_denied. Membership
lag, pending verification, and unavailable inspection are unavailable and
are never stored. These are semantic fixtures under
SPEC-TRANSPORT-CONNECT §7.1, not a replay row encoding.
