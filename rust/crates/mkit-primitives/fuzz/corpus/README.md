# Stable seed replay

`replay_seeds` supplies empty, zero-filled, truncated, and high-bit boundary
inputs to each decoder or transition body. Bodies land with their owning module
and use the same function under libFuzzer and stable tests. Inputs are capped at
64 KiB; each body must also bound work and allocation through its finite config.
Add minimized failures to the portable fixture manifest. Large generated corpora
stay outside the repository.
