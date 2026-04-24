//! `mkit serve <path>` — speak the 7-verb SSH transport wire protocol
//! on stdin/stdout against a local repository. Port of the Zig
//! `cmdServe` in `src/main.zig` plus `src/transport/ssh.zig::serve`.
//!
//! The backing repo is accessed via `FileTransport`, which already
//! implements [`mkit_core::protocol::Transport`]. Frame encoding is
//! [`mkit_core::protocol::encode_frame`] / `decode_frame`; per-verb
//! payload shapes are inlined here to match the wire format shipped
//! by `mkit-transport-ssh` (its decoders are crate-private).

use std::io::{Read, Write};

use mkit_core::hash::Hash;
use mkit_core::protocol::{
    self, FRAME_HEADER_LEN, HELLO_NAME_MAX, HELLO_VERSION_MAX, MAX_PAYLOAD_LEN, OP_CLOSE,
    OP_DOWNLOAD_PACK, OP_HELLO, OP_LIST_REFS, OP_PACK_EXISTS, OP_READ_REF, OP_UPDATE_REF,
    OP_UPLOAD_PACK, OP_WRITE_REF, PackKey, RefWriteCondition, SSH_BINARY_NAME, SSH_PROTO_VERSION,
    STATUS_ERROR, STATUS_NULL, STATUS_OK, STATUS_UNSUPPORTED, Transport,
};
use mkit_transport_file::FileTransport;

use crate::cli::CLI_VERSION;
use crate::exit;

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let Some(path) = args.first() else {
        return super::usage_error("usage: mkit serve <path>");
    };
    let tx = FileTransport::new(std::path::Path::new(path));

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut r = stdin.lock();
    let mut w = stdout.lock();

    if !handshake(&mut r, &mut w) {
        return exit::PROTOCOL_ERROR;
    }
    while let Some((op, payload)) = read_frame(&mut r) {
        if op == OP_CLOSE {
            break;
        }
        let (status, body) = dispatch(&tx, op, &payload);
        if write_status(&mut w, status, &body).is_err() {
            break;
        }
    }
    exit::OK
}

fn handshake(r: &mut impl Read, w: &mut impl Write) -> bool {
    let Some((op, payload)) = read_frame(r) else {
        return false;
    };
    if op != OP_HELLO {
        let _ = write_status(w, STATUS_ERROR, b"hello required");
        return false;
    }
    let Some(hello) = decode_hello_request(&payload) else {
        let _ = write_status(w, STATUS_ERROR, b"hello decode error");
        return false;
    };
    if hello.binary_name != SSH_BINARY_NAME {
        let _ = write_status(w, STATUS_ERROR, b"binary name mismatch");
        return false;
    }
    if hello.proto_version != SSH_PROTO_VERSION {
        let _ = write_status(w, STATUS_UNSUPPORTED, b"unsupported proto version");
        return false;
    }
    let Ok(server_hello) = protocol::encode_hello_payload(
        SSH_PROTO_VERSION,
        SSH_BINARY_NAME,
        &format!("mkit {CLI_VERSION}"),
    ) else {
        return false;
    };
    write_status(w, STATUS_OK, &server_hello).is_ok()
}

fn dispatch(tx: &FileTransport, op: u8, payload: &[u8]) -> (u8, Vec<u8>) {
    match op {
        OP_UPLOAD_PACK => match decode_upload_pack(payload) {
            Some((data, key)) => match tx.upload_pack(data, &key) {
                Ok(()) => (STATUS_OK, Vec::new()),
                Err(_) => (STATUS_ERROR, b"upload failed".to_vec()),
            },
            None => (STATUS_ERROR, b"decode error".to_vec()),
        },
        OP_DOWNLOAD_PACK => match decode_hash32(payload) {
            Some(h) => match tx.download_pack(&PackKey(h)) {
                Ok(bytes) => (STATUS_OK, bytes),
                Err(_) => (STATUS_NULL, Vec::new()),
            },
            None => (STATUS_ERROR, b"decode error".to_vec()),
        },
        OP_PACK_EXISTS => match decode_hash32(payload) {
            Some(h) => {
                let present = tx.pack_exists(&PackKey(h)).unwrap_or(false);
                (STATUS_OK, vec![u8::from(present)])
            }
            None => (STATUS_ERROR, b"decode error".to_vec()),
        },
        OP_WRITE_REF => match decode_write_ref(payload) {
            Some((name, hash)) => match tx.write_ref(&name, &hash) {
                Ok(()) => (STATUS_OK, Vec::new()),
                Err(_) => (STATUS_ERROR, b"write ref failed".to_vec()),
            },
            None => (STATUS_ERROR, b"decode error".to_vec()),
        },
        OP_UPDATE_REF => match decode_update_ref(payload) {
            Some((name, cond, hash)) => match tx.update_ref(&name, cond, &hash) {
                Ok(()) => (STATUS_OK, Vec::new()),
                Err(_) => (STATUS_ERROR, b"update ref failed".to_vec()),
            },
            None => (STATUS_ERROR, b"decode error".to_vec()),
        },
        OP_READ_REF => match decode_name(payload) {
            Some(name) => match tx.read_ref(&name) {
                Ok(Some(h)) => (STATUS_OK, h.to_vec()),
                Ok(None) => (STATUS_NULL, Vec::new()),
                Err(_) => (STATUS_ERROR, b"read ref failed".to_vec()),
            },
            None => (STATUS_ERROR, b"decode error".to_vec()),
        },
        OP_LIST_REFS => match decode_name(payload) {
            Some(prefix) => match tx.list_refs(&prefix) {
                Ok(refs) => (STATUS_OK, encode_ref_list(&refs)),
                Err(_) => (STATUS_ERROR, b"list refs failed".to_vec()),
            },
            None => (STATUS_ERROR, b"decode error".to_vec()),
        },
        _ => (STATUS_UNSUPPORTED, Vec::new()),
    }
}

// -- Frame I/O ---------------------------------------------------------------

fn read_frame(r: &mut impl Read) -> Option<(u8, Vec<u8>)> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    r.read_exact(&mut header).ok()?;
    let op = header[0];
    let len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if len > MAX_PAYLOAD_LEN {
        return None;
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        r.read_exact(&mut payload).ok()?;
    }
    Some((op, payload))
}

fn write_status(w: &mut impl Write, status: u8, payload: &[u8]) -> std::io::Result<()> {
    match protocol::encode_frame(status, payload) {
        Ok(frame) => {
            w.write_all(&frame)?;
            w.flush()
        }
        Err(_) => Err(std::io::Error::other("encode frame")),
    }
}

// -- Verb payload decoders (mirrors mkit-transport-ssh internals) ------------

struct HelloRequest<'a> {
    proto_version: u8,
    binary_name: &'a str,
}

fn decode_hello_request(p: &[u8]) -> Option<HelloRequest<'_>> {
    if p.len() < 2 {
        return None;
    }
    let proto_version = p[0];
    let name_len = p[1] as usize;
    if name_len > HELLO_NAME_MAX || 2 + name_len + 1 > p.len() {
        return None;
    }
    let name = std::str::from_utf8(&p[2..2 + name_len]).ok()?;
    let ver_len = p[2 + name_len] as usize;
    if ver_len > HELLO_VERSION_MAX || 2 + name_len + 1 + ver_len > p.len() {
        return None;
    }
    Some(HelloRequest {
        proto_version,
        binary_name: name,
    })
}

fn decode_upload_pack(p: &[u8]) -> Option<(&[u8], PackKey)> {
    if p.len() < 32 {
        return None;
    }
    let split = p.len() - 32;
    let data = &p[..split];
    let mut k = [0u8; 32];
    k.copy_from_slice(&p[split..]);
    Some((data, PackKey(k)))
}

fn decode_hash32(p: &[u8]) -> Option<Hash> {
    if p.len() != 32 {
        return None;
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(p);
    Some(h)
}

fn decode_name(p: &[u8]) -> Option<String> {
    if p.len() < 2 {
        return None;
    }
    let name_len = u16::from_le_bytes([p[0], p[1]]) as usize;
    if 2 + name_len != p.len() {
        return None;
    }
    std::str::from_utf8(&p[2..]).ok().map(str::to_string)
}

fn decode_write_ref(p: &[u8]) -> Option<(String, Hash)> {
    if p.len() < 2 + 32 {
        return None;
    }
    let name_len = u16::from_le_bytes([p[0], p[1]]) as usize;
    if 2 + name_len + 32 != p.len() {
        return None;
    }
    let name = std::str::from_utf8(&p[2..2 + name_len]).ok()?.to_string();
    let mut h = [0u8; 32];
    h.copy_from_slice(&p[2 + name_len..2 + name_len + 32]);
    Some((name, h))
}

fn decode_update_ref(p: &[u8]) -> Option<(String, RefWriteCondition, Hash)> {
    if p.is_empty() {
        return None;
    }
    let cond_byte = p[0];
    let (cond, rest) = match cond_byte {
        protocol::COND_ANY => (RefWriteCondition::Any, &p[1..]),
        protocol::COND_MISSING => (RefWriteCondition::Missing, &p[1..]),
        protocol::COND_MATCH => {
            if p.len() < 1 + 32 {
                return None;
            }
            let mut expected = [0u8; 32];
            expected.copy_from_slice(&p[1..33]);
            (RefWriteCondition::Match(expected), &p[33..])
        }
        _ => return None,
    };
    if rest.len() < 2 + 32 {
        return None;
    }
    let name_len = u16::from_le_bytes([rest[0], rest[1]]) as usize;
    if 2 + name_len + 32 != rest.len() {
        return None;
    }
    let name = std::str::from_utf8(&rest[2..2 + name_len])
        .ok()?
        .to_string();
    let mut h = [0u8; 32];
    h.copy_from_slice(&rest[2 + name_len..]);
    Some((name, cond, h))
}

fn encode_ref_list(refs: &[mkit_core::refs::Ref]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + refs.len() * (2 + 32));
    let count = u32::try_from(refs.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&count.to_le_bytes());
    for r in refs {
        let name_bytes = r.name.as_bytes();
        let name_len = u16::try_from(name_bytes.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(&r.hash.unwrap_or([0u8; 32]));
    }
    out
}
