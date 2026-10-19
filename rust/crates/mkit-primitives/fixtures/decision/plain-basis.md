# Plain ref acceptance basis

The semantic fixture uses a paired ref write and one newly accepted pack.
The host attestation names that pack by identity and exact length. A different
identity or length, or an omitted basis, fails closed with `InvalidResponse`.
An attestation with an empty pack list explicitly covers any pack, following
the ticketed acceptance rule. Successful attachment preserves the write effects.

The fixture runs in `plain_basis_coverage_uses_exact_pack_identity_and_length`.
The adjacent tests mutate every carried fact, omit each lowered guard, compare
plain and ticketed basis guards, and exercise duplicate and contradictory facts.
No byte encoding or new refusal code is defined.
