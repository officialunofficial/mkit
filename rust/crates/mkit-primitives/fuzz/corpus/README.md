# Stable seed replay

`replay_seeds` supplies empty, zero-filled, truncated, and high-bit boundary
inputs to each decoder or transition body. Bodies land with their owning module
and use the same function under libFuzzer and stable tests. Inputs are capped at
64 KiB; each body must also bound work and allocation through its finite config.
Add minimized failures to the portable fixture manifest. Large generated corpora
stay outside the repository.

`closure_steps` drives a bounded eight-ID graph with stale, partial, duplicate,
foreign, unavailable, corrupt-page and misacknowledgement plans.
`closure_pages` authenticates arbitrary state/witness/missing bytes before strict
parsing. Its stable seeds include the frozen closure fixtures, every truncation,
and single-byte mutations. The stable bodies bound transitions/work and compare
deterministic outcomes. Scheduled libFuzzer smoke runs use the same bodies.
