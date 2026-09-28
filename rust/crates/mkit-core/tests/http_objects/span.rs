//! Test-local MKDS reference verifier; no product code or private MKDP types.
use super::*;

type Result<T> = std::result::Result<T, &'static str>;

#[derive(Debug)]
pub(super) struct Span {
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub leaf: Hash,
    pub path: Vec<Vec<u8>>,
    pub signature_valid: bool,
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.0.len() {
            return Err("span_encoding");
        }
        let (bytes, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(bytes)
    }
    fn number(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn length(&mut self, cap: usize) -> Result<usize> {
        let mut value = 0u32;
        for i in 0..5 {
            let byte = self.take(1)?[0];
            if (i > 0 && byte == 0) || (i == 4 && byte > 15) {
                return Err("span_encoding");
            }
            value |= u32::from(byte & 127) << (7 * i);
            if byte & 128 == 0 {
                let n = value as usize;
                return if n <= cap {
                    Ok(n)
                } else {
                    Err("span_encoding")
                };
            }
        }
        Err("span_encoding")
    }
    fn vector(&mut self) -> Result<&'a [u8]> {
        let n = self.length(CAP.min(self.0.len()))?;
        self.take(n)
    }
}

struct Decoded<'a> {
    commit: Hash,
    offset: u64,
    len: u64,
    anchor_bytes: &'a [u8],
    chunks: Vec<&'a [u8]>,
}

fn decode(input: &[u8]) -> Result<Decoded<'_>> {
    if input.len() > CAP {
        return Err("span_too_large");
    }
    let mut r = Reader(input);
    if r.take(4)? != b"MKDS" {
        return Err("span_magic");
    }
    if r.take(1)? != [1] {
        return Err("span_version");
    }
    let commit: Hash = r.take(32)?.try_into().unwrap();
    let offset = r.number()?;
    let len = r.number()?;
    let anchor_bytes = r.vector()?;
    let count = r.length(1_000_000)?;
    // Bound allocations by both the declared count and actual remaining input.
    if count > r.0.len() {
        return Err("span_encoding");
    }
    let mut chunks = Vec::with_capacity(count);
    for _ in 0..count {
        chunks.push(r.vector()?);
    }
    if !r.0.is_empty() {
        return Err("span_trailing_bytes");
    }
    Ok(Decoded {
        commit,
        offset,
        len,
        anchor_bytes,
        chunks,
    })
}

fn slice_content(
    content: &[Vec<u8>],
    total: u64,
    start: u64,
    offset: u64,
    end: u64,
) -> Result<Vec<u8>> {
    let mut span_end = start;
    let mut last_start = start;
    for b in content {
        last_start = span_end;
        span_end = span_end
            .checked_add(b.len() as u64)
            .ok_or("span_range_outside")?;
    }
    let first_end = start
        .checked_add(content[0].len() as u64)
        .ok_or("span_range_outside")?;
    if span_end > total || offset < start || offset >= first_end || end > span_end {
        return Err("span_range_outside");
    }
    if end <= last_start {
        return Err("span_last_unneeded");
    }
    let all = content.concat();
    Ok(
        all[usize::try_from(offset - start).unwrap()..usize::try_from(end - start).unwrap()]
            .to_vec(),
    )
}

pub(super) fn verify(trusted: &Hash, input: &[u8]) -> Result<Span> {
    let Decoded {
        commit,
        offset,
        len,
        anchor_bytes,
        chunks,
    } = decode(input)?;
    let count = chunks.len();
    if &commit != trusted {
        return Err("span_commit");
    }
    let end = offset
        .checked_add(len)
        .filter(|_| len != 0)
        .ok_or("span_range_arithmetic")?;
    if count < 2 {
        return Err("span_chunk_count");
    }
    let anchor = verify_disclosure(trusted, anchor_bytes).map_err(|_| "span_anchor_invalid")?;
    let DisclosedPayload::Range {
        blob_id,
        chunk: Some((first, total, chunk_size)),
        offset_in_blob: 0,
        absolute_offset,
        bytes,
    } = &anchor.payload
    else {
        return Err("span_anchor_selector");
    };
    if bytes.len() != 1 {
        return Err("span_anchor_selector");
    }
    let start = absolute_offset.ok_or("span_anchor_offset")?;
    // Validate in passes, preserving the specification's first-failure order.
    let disclosed: Vec<Disclosed> = chunks
        .iter()
        .map(|b| verify_disclosure(trusted, b).map_err(|_| "span_inner_invalid"))
        .collect::<Result<_>>()?;
    let mut parsed = Vec::with_capacity(count);
    for d in &disclosed {
        let DisclosedPayload::Chunk {
            total_size,
            chunk_size,
            index,
            bytes,
        } = &d.payload
        else {
            return Err("span_chunk_selector");
        };
        parsed.push((*total_size, *chunk_size, *index, bytes));
    }
    if disclosed
        .iter()
        .any(|d| d.path != anchor.path || d.leaf_id != anchor.leaf_id)
    {
        return Err("span_leaf_context");
    }
    if disclosed.iter().zip(&parsed).any(|(d, p)| {
        p.0 != *total || p.1 != *chunk_size || d.chunk_inner_root != anchor.chunk_inner_root
    }) {
        return Err("span_chunk_context");
    }
    if parsed
        .iter()
        .enumerate()
        .any(|(i, p)| first.checked_add(u32::try_from(i).unwrap()) != Some(p.2))
    {
        return Err("span_chunk_order");
    }
    let content: Vec<Vec<u8>> = parsed
        .iter()
        .map(
            |p| match deserialize(p.3).map_err(|_| "span_chunk_bytes")? {
                Object::Blob(b) if !b.data.is_empty() => Ok(b.data),
                _ => Err("span_chunk_bytes"),
            },
        )
        .collect::<Result<_>>()?;
    if hash(parsed[0].3) != *blob_id || content[0][0] != bytes[0] {
        return Err("span_anchor_binding");
    }
    let output = slice_content(&content, *total, start, offset, end)?;
    Ok(Span {
        offset,
        bytes: output,
        leaf: anchor.leaf_id,
        path: anchor.path.iter().map(|(name, _)| name.clone()).collect(),
        signature_valid: anchor.signature_valid,
    })
}
