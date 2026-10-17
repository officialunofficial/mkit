# Ref decision semantic fixtures

These are language-independent semantic inputs, not a protocol encoding.
`old` and `new` denote distinct 32-byte object identities. `match` expects
`old`. Each row declares its decision class and whether the observed ref value
must be guarded. `any` remains unconditional unless another rule depends on it.

The Rust fixture test consumes every row. The frozen server planner additionally
checks paired precedence, grant presence, immutable admission, signed replay,
and complete physical batch equality. Mutation tests cover exact dependencies
and omissions within the same guard category.
