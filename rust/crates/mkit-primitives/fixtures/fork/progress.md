# Fork progress semantic fixtures

These in-memory decisions implement SPEC-SERVER §9.9. Each row names the
logical phase, recorded/current authority equality, grant-epoch equality,
reservation equality, explicit time, and expected decision. Construction
expires at time 100 inclusive. Accepted clearance retains its original result
and proceeds after construction protection ends. Terminal jobs never advance.

The fixtures define no encoded protocol type. Stable tests consume them without
regeneration. Membership activation tests separately mutate every witness and
proof field, retained inventory, accepted result, and guard snapshot.
