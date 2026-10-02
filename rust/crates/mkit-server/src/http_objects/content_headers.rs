//! Derived ref-path file headers (SPEC-HTTP-OBJECTS §5.1).

/// Only this fixed allowlist can change the default binary media type.
pub(crate) fn media_type(name: &[u8]) -> (&'static str, &'static str) {
    let extension = name.rsplit(|b| *b == b'.').next().unwrap_or_default();
    if !name.contains(&b'.') {
        return ("application/octet-stream", "attachment");
    }
    for (ext, media, disposition) in [
        (b"png".as_slice(), "image/png", "inline"),
        (b"jpg", "image/jpeg", "inline"),
        (b"jpeg", "image/jpeg", "inline"),
        (b"gif", "image/gif", "inline"),
        (b"webp", "image/webp", "inline"),
        (b"avif", "image/avif", "inline"),
        (b"txt", "text/plain; charset=utf-8", "inline"),
        (b"json", "application/json", "attachment"),
        (b"pdf", "application/pdf", "inline"),
    ] {
        if extension.eq_ignore_ascii_case(ext) {
            return (media, disposition);
        }
    }
    ("application/octet-stream", "attachment")
}

/// Derived and fully percent-encoded outside RFC 5987 attr-char. The ASCII
/// fallback is sanitized separately; neither interpolates raw request text.
/// The route parser bounds the decoded path to 1024 bytes.
pub(crate) fn disposition(name: &[u8], kind: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let fallback: String = name
        .iter()
        .take(255)
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"._-".contains(b) {
                char::from(*b)
            } else {
                '_'
            }
        })
        .collect();
    let mut out = format!("{kind}; filename=\"{fallback}\"; filename*=UTF-8''");
    for b in name {
        if b.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(b) {
            out.push(char::from(*b));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(*b >> 4)]));
            out.push(char::from(HEX[usize::from(*b & 15)]));
        }
    }
    out
}
