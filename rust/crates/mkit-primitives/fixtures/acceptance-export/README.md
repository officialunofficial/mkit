# Acceptance export semantic vectors

These vectors exercise in-memory evidence export. They add no wire encoding and
do not change any acceptance evidence format 1 fixture.

`heads-root.json` pins the closure's existing head-sequence commitment for empty,
single, ordered, reversed, and duplicate sequences. Each ID is 32 raw bytes.
The commitment is BLAKE3 over the existing closure domain framing: little-endian
u16 domain length, domain bytes, little-endian u64 occurrence count, and IDs in
the original requested order. This is the closure commitment, not an additional
evidence digest domain. Envelope heads are independently sorted and unique.

Expected roots were calculated independently of the Rust helper. Tests consume
these files read-only; changes require explicit review.
