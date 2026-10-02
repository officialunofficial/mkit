# Takedown-on publication and reader performance

Implement claims 1–6 from the local evidence report on `feat/mkit-server-next`. Uno keeps takedown off until this work is reviewed. No changes to `mkit-server-native`.

1. Document closure and object-index budgets admitting at least nine canonical 1 MiB blobs and 32 distinct chunks. Resource exhaustion must be typed and never diagnosed as open closure. Resume bounded publication verification through existing timer 12 and verification state, before accepting unchecked refs. No new timer.
2. Replace foreground scans of 4,096 empty content partitions with an authoritative descriptor directory. The user approved a new subkey under existing `b`, with DIRECTORY_SHARDS=16, routed by object-id prefix over existing ContentShard(0..15). Reserve with Absent/CAS before local activation, resolve uncertain reservation by a strong exact read, retain entries monotonically, and support fresh stores only. Strong proofs read all sixteen directory first pages with bounded concurrency, then referenced local descriptors. Missing/failed/corrupt/incomplete reads fail closed; every proof starts after plan time and retains the 10 s NotAfter cut. Remove another proof only if redundant in the same attempt. Assert empty, N-descriptor and page-boundary call counts. Record allocation in the next free plan row and PR body.
3. Add a caller byte cap to canonical object reads, returning typed ResourceExhausted.
4. Add metadata with kind, canonical length and logical length. Deprecate the public mixed-semantics object_sizes method while preserving its results.
5. Deliver one or two PRs into `feat/mkit-server-next`, each at most 3,000 production lines. Add the native repro fixtures as regressions, plus a local Wrangler takedown-on push of at least 9 MiB and a chunked file. Report measured calls and timings.

Apply the executor conventions, full gates and adversarial review, with public-repository hygiene: use repo-relative references and summarized local evidence only. No deployment or cloud mutation. The directory allocation and ordering have user approval; an additional key/timer/protocol/spec change requires review.
