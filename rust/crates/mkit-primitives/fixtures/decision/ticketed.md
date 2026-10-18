# Ticket and reservation decision fixtures

These are semantic inputs, not a new wire encoding. Each case uses repository
`01` repeated 32 times, revision `02` repeated 32 times, operation `06` repeated
32 times and instant 500 ms. The canonical packmap/head pair starts at `03`
repeated 32 times and advances to `04` repeated 32 times. The signer is `05`
repeated 32 times. Ticket `42` repeated 32 times binds reservation `c2` repeated
32 times, a 1,066-byte pack, creation 10 ms and expiry 1,000 ms. Its upload proof
is Ready except in cleanup, where it is PackMissing. Storage counting is disabled.

Accept consumes one ticket and emits its committed reservation and durable
outcome with the exact pair and byte counts. Cleanup emits only a PackMissing
abort with detail `pack missing`. Settle emits Internal with empty detail;
repeating with the terminal observed emits no second settlement or outcome.
Replay returns the saved empty Applied result before revalidating tickets.
Proof-refused uses invalid_argument (`invalid pack`), while proof-late uses
failed_precondition (`proof arrived too late`). Both attach the exact pending
reservation `09` repeated 32 times (created 5 ms, reconcile 9,000 ms, Write),
abort it once and store no terminal replay. Pending verification has no admission
reservation and returns a retry with no durable effects. Guards are checked
against the exact observations; changing a sealed observation must reject apply.

The fixture runner pins terminal identities, reasons, ref payloads and accounting.
The existing ref_decisions fuzz target also drives the ticketed model through
all three entry points, bounded replay/proof states, guard mutation and lost-reply
settlement. Stable seed replay runs without libFuzzer.
