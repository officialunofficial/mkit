//! Streaming primitives — `FastCDC` chunker, chunked-blob manifest,
//! SPEC-DELTA encoding, and Bao verified-streaming (outboard / slice /
//! verify), plus the result structs they return.

use wasm_bindgen::prelude::*;

use mkit_core::chunker::{AVG_SIZE, ChunkIterator, FastCdc, MAX_SIZE, MIN_SIZE};
use mkit_core::delta;
use mkit_core::hash::{hash, to_hex};

use std::io::Read;

use crate::common::{js_err, js_vec_count, js_vec_get, parse_hash_hex};

// Frozen v1 chunker constants are well under u32::MAX (max = 256 KiB).
// Lift them to module-level `u32` constants so the `as` cast is pinned
// once behind a compile-time assert, rather than being re-justified at
// each call site.
#[allow(clippy::cast_possible_truncation)]
const CHUNKER_AVG_U32: u32 = AVG_SIZE as u32;
#[allow(clippy::cast_possible_truncation)]
const CHUNKER_MIN_U32: u32 = MIN_SIZE as u32;
#[allow(clippy::cast_possible_truncation)]
const CHUNKER_MAX_U32: u32 = MAX_SIZE as u32;
const _: () = assert!(MAX_SIZE <= u32::MAX as usize);

/// Run the frozen v1 `FastCDC` chunker over `bytes` and return
/// `{ chunks: [{ offset, len, hash_hex }], avg, min, max }`.
///
/// Each `hash_hex` is BLAKE3 of the chunk payload — handy for colouring
/// chips in the web demo when an edit shifts boundaries.
#[wasm_bindgen]
pub fn chunk_boundaries(bytes: &[u8]) -> Result<ChunkerResult, JsValue> {
    let cdc = FastCdc::v1();
    let mut chunks: Vec<ChunkInfo> = Vec::new();
    for b in ChunkIterator::new(cdc, bytes) {
        let offset = u32::try_from(b.offset).map_err(|_| js_err("chunk offset exceeds u32"))?;
        let len = u32::try_from(b.length).map_err(|_| js_err("chunk length exceeds u32"))?;
        let h = hash(&bytes[b.offset..b.offset + b.length]);
        chunks.push(ChunkInfo {
            offset,
            len,
            hash_hex: to_hex(&h),
        });
    }
    Ok(ChunkerResult {
        chunks,
        avg: CHUNKER_AVG_U32,
        min: CHUNKER_MIN_U32,
        max: CHUNKER_MAX_U32,
    })
}

/// Build a `ChunkedBlob` manifest from raw bytes: chunk with `FastCDC` v1 and
/// return `{ root_hash_hex, chunks: [{ offset, len, hash_hex }], bytes_len }`.
///
/// `root_hash_hex` is the object's content id — the BMT root of the manifest,
/// whose leaves are the per-chunk **Blob object ids** (built via the shared
/// `worktree::chunked_blob_from_bytes`), so it equals the id the native store
/// keys the `ChunkedBlob` under. Each chunk's `hash_hex` is the **raw**
/// BLAKE3 of the chunk payload — for UI colouring/dedup, distinct from the
/// manifest leaf. `chunk_size` is `0` (the CDC marker, SPEC-OBJECTS §13.7).
#[wasm_bindgen]
pub fn chunked_blob_encode(bytes: &[u8]) -> Result<ChunkedBlobJs, JsValue> {
    let bytes_len = u32::try_from(bytes.len()).map_err(|_| js_err("bytes length exceeds u32"))?;
    // Per-chunk display info: offset, length, and the raw chunk-content hash
    // (the UI colours and dedups by this — it is NOT the manifest leaf).
    let mut infos: Vec<ChunkInfo> = Vec::new();
    for b in ChunkIterator::new(FastCdc::v1(), bytes) {
        let offset = u32::try_from(b.offset).map_err(|_| js_err("chunk offset exceeds u32"))?;
        let len = u32::try_from(b.length).map_err(|_| js_err("chunk length exceeds u32"))?;
        infos.push(ChunkInfo {
            offset,
            len,
            hash_hex: to_hex(&hash(&bytes[b.offset..b.offset + b.length])),
        });
    }
    // The manifest addresses each chunk by its Blob object id (not the raw
    // chunk hash), exactly as the native store does, so root_hash_hex matches
    // the store's key. Single source of the recipe: chunked_blob_from_bytes.
    let cb = mkit_core::worktree::chunked_blob_from_bytes(bytes)
        .map_err(|e| js_err(format!("chunk: {e}")))?;
    let root_hash_hex = to_hex(&mkit_core::merkle::compute_chunked_id(&cb));
    Ok(ChunkedBlobJs {
        root_hash_hex,
        chunks: infos,
        bytes_len,
    })
}

/// Build a SPEC-DELTA v1 stream of `base -> target` and return a
/// structural summary: `{ ops, bytes_on_wire, full_size }`.
///
/// `ops` contains one entry per opcode — `{ kind: "copy", offset, len }`
/// or `{ kind: "insert", len }` — without the insert payloads, so the
/// whole thing stays cheap to pass across the JS boundary. `bytes_on_wire`
/// is the total delta stream length; `full_size` is `target.len()` for
/// easy delta-savings calculation.
#[wasm_bindgen]
pub fn delta_encode(base: &[u8], target: &[u8]) -> Result<DeltaSummary, JsValue> {
    let stream = delta::encode(base, target).map_err(|e| js_err(format!("delta encode: {e}")))?;
    let bytes_on_wire =
        u32::try_from(stream.len()).map_err(|_| js_err("delta stream exceeds u32"))?;
    let full_size = u32::try_from(target.len()).map_err(|_| js_err("target length exceeds u32"))?;

    // Walk the stream ourselves so we can report each op individually
    // without re-encoding. The header layout + opcodes are in
    // `mkit_core::delta` (`HEADER_LEN`, `OP_COPY`, 0x01..=0x7F = INSERT).
    let mut ops: Vec<DeltaOp> = Vec::new();
    let mut pos = delta::HEADER_LEN;
    while pos < stream.len() {
        let op = stream[pos];
        pos += 1;
        if op & 0x80 != 0 {
            // COPY [u32 LE offset][u16 LE length]
            if pos + 6 > stream.len() {
                return Err(js_err("truncated COPY op"));
            }
            let offset = u32::from_le_bytes(
                stream[pos..pos + 4]
                    .try_into()
                    .map_err(|_| js_err("bad offset"))?,
            );
            pos += 4;
            let length = u16::from_le_bytes(
                stream[pos..pos + 2]
                    .try_into()
                    .map_err(|_| js_err("bad length"))?,
            );
            pos += 2;
            ops.push(DeltaOp {
                kind: "copy".to_string(),
                offset: Some(offset),
                len: u32::from(length),
            });
        } else if op > 0 {
            let length = op as usize;
            if pos + length > stream.len() {
                return Err(js_err("truncated INSERT op"));
            }
            pos += length;
            ops.push(DeltaOp {
                kind: "insert".to_string(),
                offset: None,
                len: u32::from(op), // INSERT length is always in 1..=127
            });
        } else {
            return Err(js_err("reserved 0x00 opcode"));
        }
    }

    Ok(DeltaSummary {
        ops,
        bytes_on_wire,
        full_size,
    })
}

/// Encode `bytes` in Bao outboard mode and return `{ hash_hex, outboard }`.
/// Outboard keeps the encoded tree proof separate from the payload so
/// the demo can stream the original bytes on one track and the proof on
/// another.
#[wasm_bindgen]
pub fn bao_encode(bytes: &[u8]) -> Result<BaoEncoded, JsValue> {
    // `bao::encode::outboard` takes `AsRef<[u8]>` and returns
    // `(Vec<u8>, blake3::Hash)`. Equivalent to the streaming Encoder
    // with `new_outboard`, but all-at-once matches the demo's needs.
    let (outboard, h) = bao::encode::outboard(bytes);
    Ok(BaoEncoded {
        hash_hex: hex::encode(h.as_bytes()),
        outboard,
    })
}

/// Extract a proof-carrying slice from a Bao outboard encoding. The
/// returned bytes are in the format `bao::decode::SliceDecoder`
/// consumes — the original payload plus just enough tree proof to
/// verify it against the root hash.
#[wasm_bindgen]
pub fn bao_slice(
    outboard: &[u8],
    bytes: &[u8],
    offset: u32,
    len: u32,
) -> Result<Box<[u8]>, JsValue> {
    let mut extractor = bao::encode::SliceExtractor::new_outboard(
        std::io::Cursor::new(bytes),
        std::io::Cursor::new(outboard),
        u64::from(offset),
        u64::from(len),
    );
    let mut out = Vec::new();
    extractor
        .read_to_end(&mut out)
        .map_err(|e| js_err(format!("slice extract: {e}")))?;
    Ok(out.into_boxed_slice())
}

/// Verify a Bao slice against a root hash. On success returns
/// `{ ok: true, bytes }` with the verified payload. On tamper returns
/// `{ ok: false, error }` with the error message — a convenience over
/// throwing, since the demo wants to render both outcomes side-by-side.
#[wasm_bindgen]
pub fn bao_verify_slice(
    hash_hex: &str,
    slice_bytes: &[u8],
    offset: u32,
    len: u32,
) -> Result<BaoVerify, JsValue> {
    let h_bytes = parse_hash_hex(hash_hex)?;
    let h: bao::Hash = h_bytes.into();
    let mut decoder = bao::decode::SliceDecoder::new(
        std::io::Cursor::new(slice_bytes),
        &h,
        u64::from(offset),
        u64::from(len),
    );
    let mut out = Vec::new();
    match decoder.read_to_end(&mut out) {
        Ok(_) => Ok(BaoVerify {
            ok: true,
            bytes: Some(out.into_boxed_slice()),
            error: None,
        }),
        Err(e) => Ok(BaoVerify {
            ok: false,
            bytes: None,
            error: Some(e.to_string()),
        }),
    }
}

// ---------------------------------------------------------------------
// Result structs (plain JS objects via wasm-bindgen getters)
// ---------------------------------------------------------------------

/// One `FastCDC` chunk boundary plus its BLAKE3.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct ChunkInfo {
    offset: u32,
    len: u32,
    hash_hex: String,
}

// `len` is a field exposed across the JS boundary (spec says
// `{ offset, len, hash_hex }`). `is_empty` wouldn't be meaningful here —
// every chunk has a positive length. Suppress the lint at the impl block.
#[allow(clippy::len_without_is_empty)]
#[wasm_bindgen]
impl ChunkInfo {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn offset(&self) -> u32 {
        self.offset
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn len(&self) -> u32 {
        self.len
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn hash_hex(&self) -> String {
        self.hash_hex.clone()
    }
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct ChunkerResult {
    chunks: Vec<ChunkInfo>,
    avg: u32,
    min: u32,
    max: u32,
}

#[wasm_bindgen]
impl ChunkerResult {
    /// Number of chunks. The `chunk(i)` getter returns each one by index,
    /// which is cheaper than materialising a JS array of opaque handles
    /// when the web caller only wants a few.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn chunk_count(&self) -> u32 {
        js_vec_count(&self.chunks)
    }
    #[wasm_bindgen]
    #[must_use]
    pub fn chunk(&self, i: u32) -> Option<ChunkInfo> {
        js_vec_get(&self.chunks, i)
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn avg(&self) -> u32 {
        self.avg
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn min(&self) -> u32 {
        self.min
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn max(&self) -> u32 {
        self.max
    }
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct ChunkedBlobJs {
    root_hash_hex: String,
    chunks: Vec<ChunkInfo>,
    bytes_len: u32,
}

#[wasm_bindgen]
impl ChunkedBlobJs {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn root_hash_hex(&self) -> String {
        self.root_hash_hex.clone()
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn chunk_count(&self) -> u32 {
        js_vec_count(&self.chunks)
    }
    #[wasm_bindgen]
    #[must_use]
    pub fn chunk(&self, i: u32) -> Option<ChunkInfo> {
        js_vec_get(&self.chunks, i)
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn bytes_len(&self) -> u32 {
        self.bytes_len
    }
}

/// One entry in the delta summary. `offset` is populated only for `copy` ops.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct DeltaOp {
    kind: String,
    offset: Option<u32>,
    len: u32,
}

// Same rationale as `ChunkInfo` — `len` mirrors the agreed JSON shape.
#[allow(clippy::len_without_is_empty)]
#[wasm_bindgen]
impl DeltaOp {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn kind(&self) -> String {
        self.kind.clone()
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn offset(&self) -> Option<u32> {
        self.offset
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn len(&self) -> u32 {
        self.len
    }
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct DeltaSummary {
    ops: Vec<DeltaOp>,
    bytes_on_wire: u32,
    full_size: u32,
}

#[wasm_bindgen]
impl DeltaSummary {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn op_count(&self) -> u32 {
        js_vec_count(&self.ops)
    }
    #[wasm_bindgen]
    #[must_use]
    pub fn op(&self, i: u32) -> Option<DeltaOp> {
        js_vec_get(&self.ops, i)
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn bytes_on_wire(&self) -> u32 {
        self.bytes_on_wire
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn full_size(&self) -> u32 {
        self.full_size
    }
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct BaoEncoded {
    hash_hex: String,
    outboard: Vec<u8>,
}

#[wasm_bindgen]
impl BaoEncoded {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn hash_hex(&self) -> String {
        self.hash_hex.clone()
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn outboard(&self) -> Box<[u8]> {
        self.outboard.clone().into_boxed_slice()
    }
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct BaoVerify {
    ok: bool,
    bytes: Option<Box<[u8]>>,
    error: Option<String>,
}

#[wasm_bindgen]
impl BaoVerify {
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn ok(&self) -> bool {
        self.ok
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn bytes(&self) -> Option<Box<[u8]>> {
        self.bytes.clone()
    }
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn error(&self) -> Option<String> {
        self.error.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `chunked_blob_encode` must emit the id the **native store** keys the
    /// `ChunkedBlob` under — `worktree::hash_file_object` (the change-detection
    /// path, itself pinned to `store_file_object`). This cross-checks the real
    /// addressing path, not a same-recipe reconstruction; in particular the
    /// manifest leaves must be per-chunk **Blob object ids**, not the raw
    /// chunk-content hashes the UI displays.
    #[test]
    fn chunked_blob_encode_id_matches_native_store() {
        // > CHUNK_THRESHOLD (1 MiB) so the native store actually chunks it,
        // with byte variation so FastCDC cuts real content-defined boundaries.
        let data: Vec<u8> = (0..2_500_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
            .collect();
        let wasm_id = chunked_blob_encode(&data)
            .expect("chunked blob encodes")
            .root_hash_hex();

        let native_id = to_hex(&mkit_core::worktree::hash_file_object(&data).unwrap());
        assert_eq!(
            wasm_id, native_id,
            "wasm chunked id must equal the native store id"
        );

        // Guard against regressing to a manifest of raw chunk-content hashes
        // (the prior bug): those leaves are not resolvable Blob ids.
        let raw_chunks: Vec<[u8; 32]> = ChunkIterator::new(FastCdc::v1(), &data)
            .map(|b| hash(&data[b.offset..b.offset + b.length]))
            .collect();
        let raw_cb = mkit_core::object::ChunkedBlob {
            total_size: data.len() as u64,
            chunk_size: 0,
            chunks: raw_chunks,
        };
        let raw_root = to_hex(&mkit_core::merkle::compute_chunked_id(&raw_cb));
        assert_ne!(
            wasm_id, raw_root,
            "manifest must use Blob object ids, not raw chunk hashes"
        );
    }
}
