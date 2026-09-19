# Empty selected-file bundles

`empty_blob.mkwb` and `empty_chunked.mkwb` are valid `MKWB` v1 snapshots for a
single empty regular file. They are produced by `build_partial_snapshot` over
an in-memory store (`mkit-wasm` `empty_file_bundle` helper): one is an inline
Blob of length 0, the other is `ChunkedBlob { total_size: 0, chunks: [] }`.
Existing `partial_workspace` goldens are unchanged.
