//! `mkit serve <path>` — speak the 7-verb SSH transport wire protocol
//! on stdin/stdout against a local repository.
//!
//! The backing repo is accessed via `FileTransport`, which already
//! implements [`mkit_core::protocol::Transport`]. Frame encoding is
//! [`mkit_core::protocol::encode_frame`] / `decode_frame`; per-verb
//! payload decoders are provided by `mkit-transport-ssh` so this file
//! does not need inlined copies.

use std::io::{Read, Write};

use mkit_core::protocol::{
    self, FRAME_HEADER_LEN, HELLO_NAME_MAX, HELLO_VERSION_MAX, MAX_PAYLOAD_LEN, OP_CLOSE,
    OP_DOWNLOAD_PACK, OP_HELLO, OP_LIST_REFS, OP_PACK_EXISTS, OP_READ_REF, OP_UPDATE_REF,
    OP_UPLOAD_PACK, OP_WRITE_REF, PackKey, SSH_BINARY_NAME, SSH_PROTO_VERSION, STATUS_ERROR,
    STATUS_NULL, STATUS_OK, STATUS_UNSUPPORTED, Transport,
};
use mkit_transport_file::FileTransport;
use mkit_transport_ssh::{
    decode_download_pack, decode_list_refs, decode_pack_exists, decode_read_ref, decode_update_ref,
    decode_upload_pack, decode_write_ref, encode_ref_list,
};

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
            Ok(req) => match tx.upload_pack(&req.data, &PackKey(req.digest)) {
                Ok(()) => (STATUS_OK, Vec::new()),
                Err(_) => (STATUS_ERROR, b"upload failed".to_vec()),
            },
            Err(_) => (STATUS_ERROR, b"decode error".to_vec()),
        },
        OP_DOWNLOAD_PACK => match decode_download_pack(payload) {
            Ok(h) => match tx.download_pack(&PackKey(h)) {
                Ok(bytes) => (STATUS_OK, bytes),
                Err(_) => (STATUS_NULL, Vec::new()),
            },
            Err(_) => (STATUS_ERROR, b"decode error".to_vec()),
        },
        OP_PACK_EXISTS => match decode_pack_exists(payload) {
            Ok(h) => {
                let present = tx.pack_exists(&PackKey(h)).unwrap_or(false);
                (STATUS_OK, vec![u8::from(present)])
            }
            Err(_) => (STATUS_ERROR, b"decode error".to_vec()),
        },
        OP_WRITE_REF => match decode_write_ref(payload) {
            Ok(req) => match tx.write_ref(&req.name, &req.hash) {
                Ok(()) => (STATUS_OK, Vec::new()),
                Err(_) => (STATUS_ERROR, b"write ref failed".to_vec()),
            },
            Err(_) => (STATUS_ERROR, b"decode error".to_vec()),
        },
        OP_UPDATE_REF => match decode_update_ref(payload) {
            Ok(req) => match tx.update_ref(&req.name, req.condition, &req.hash) {
                Ok(()) => (STATUS_OK, Vec::new()),
                Err(_) => (STATUS_ERROR, b"update ref failed".to_vec()),
            },
            Err(_) => (STATUS_ERROR, b"decode error".to_vec()),
        },
        OP_READ_REF => match decode_read_ref(payload) {
            Ok(name) => match tx.read_ref(&name) {
                Ok(Some(h)) => (STATUS_OK, h.to_vec()),
                Ok(None) => (STATUS_NULL, Vec::new()),
                Err(_) => (STATUS_ERROR, b"read ref failed".to_vec()),
            },
            Err(_) => (STATUS_ERROR, b"decode error".to_vec()),
        },
        OP_LIST_REFS => match decode_list_refs(payload) {
            Ok(prefix) => match tx.list_refs(&prefix) {
                Ok(refs) => (STATUS_OK, encode_ref_list(&refs)),
                Err(_) => (STATUS_ERROR, b"list refs failed".to_vec()),
            },
            Err(_) => (STATUS_ERROR, b"decode error".to_vec()),
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

// -- HELLO handshake decoder (serve-side only; not exported from ssh crate) --

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

// -- Public-decoder reachability test ----------------------------------------

#[cfg(test)]
mod tests {
    /// Compile-time reachability check: assert each public per-verb decoder
    /// symbol is accessible from outside `mkit-transport-ssh`.  No runtime
    /// logic needed — if the crate compiles this function, the symbols exist.
    #[test]
    fn public_decoders_exist() {
        let _ = mkit_transport_ssh::decode_upload_pack as fn(&[u8]) -> _;
        let _ = mkit_transport_ssh::decode_download_pack as fn(&[u8]) -> _;
        let _ = mkit_transport_ssh::decode_pack_exists as fn(&[u8]) -> _;
        let _ = mkit_transport_ssh::decode_write_ref as fn(&[u8]) -> _;
        let _ = mkit_transport_ssh::decode_update_ref as fn(&[u8]) -> _;
        let _ = mkit_transport_ssh::decode_read_ref as fn(&[u8]) -> _;
        let _ = mkit_transport_ssh::decode_list_refs as fn(&[u8]) -> _;
        let _ = mkit_transport_ssh::decode_ref_list as fn(&[u8]) -> _;
        let _ = mkit_transport_ssh::encode_write_ref as fn(&str, &_) -> _;
        let _ = mkit_transport_ssh::encode_update_ref as fn(&str, _, &_) -> _;
        let _ = mkit_transport_ssh::encode_read_ref as fn(&str) -> _;
        let _ = mkit_transport_ssh::encode_list_refs as fn(&str) -> _;
    }
}
