//! Ref-path file headers leave byte, authorization and validator semantics intact.
use super::*;

#[test]
fn filenames_are_encoded_without_header_injection_and_fallback_is_bounded() {
    for (name, fallback, encoded) in [
        ("café.txt", "caf__.txt", "caf%C3%A9.txt"),
        ("a\";\r\nb.txt", "a____b.txt", "a%22%3B%0D%0Ab.txt"),
        ("a'%*.txt", "a___.txt", "a%27%25%2A.txt"),
        ("a!#$&+^`|~.txt", "a_________.txt", "a!#$&+^`|~.txt"),
    ] {
        let got = crate::http_objects::content_headers::disposition(name.as_bytes(), "inline");
        assert_eq!(
            got,
            format!("inline; filename=\"{fallback}\"; filename*=UTF-8''{encoded}")
        );
        assert!(!got.contains(['\r', '\n']));
    }
    let got = crate::http_objects::content_headers::disposition(&[b'a'; 1024], "attachment");
    assert!(got.starts_with(&format!("attachment; filename=\"{}\";", "a".repeat(255))));
    assert!(got.ends_with(&"a".repeat(1024)));
    let got = crate::http_objects::content_headers::disposition(b"nonutf8-\xff.txt", "inline");
    assert!(got.ends_with("nonutf8-%FF.txt"));
}

#[test]
fn ref_file_headers_follow_only_the_last_extension_and_preserve_bytes() {
    let fx = fixture();
    let file = blob(b"<html>no sniffing</html>");
    let cases = [
        ("png", "image/png", "inline"),
        ("jpg", "image/jpeg", "inline"),
        ("jpeg", "image/jpeg", "inline"),
        ("gif", "image/gif", "inline"),
        ("webp", "image/webp", "inline"),
        ("avif", "image/avif", "inline"),
        ("txt", "text/plain; charset=utf-8", "inline"),
        ("json", "application/json", "attachment"),
        ("pdf", "application/pdf", "inline"),
        ("svg", "application/octet-stream", "attachment"),
        ("html", "application/octet-stream", "attachment"),
        ("htm", "application/octet-stream", "attachment"),
        ("xhtml", "application/octet-stream", "attachment"),
        ("xml", "application/octet-stream", "attachment"),
        ("js", "application/octet-stream", "attachment"),
        ("mjs", "application/octet-stream", "attachment"),
        ("css", "application/octet-stream", "attachment"),
    ];
    let mut names = vec![
        "png".to_owned(),
        "no-extension".to_owned(),
        "image.png.exe".to_owned(),
    ];
    for (ext, _, _) in cases {
        names.extend([
            format!("file.{ext}"),
            format!("many.dots.{}", ext.to_ascii_uppercase()),
        ]);
    }
    names.sort();
    let entries: Vec<_> = names
        .iter()
        .map(|n| (n.as_str(), EntryMode::Blob, &file))
        .collect();
    let root = tree(&entries);
    let head = commit(&root, &[], "headers");
    fx.push("room", &[&file, &root, &head], id(&head), None);
    for name in names {
        let expected = cases
            .iter()
            .find(|(ext, _, _)| name.to_ascii_lowercase().ends_with(&format!(".{ext}")));
        let (media, kind) = expected.map_or(
            ("application/octet-stream", "attachment"),
            |(_, media, kind)| (*media, *kind),
        );
        let got = fx.get(&fx.ref_url("room", "main", &name));
        assert_eq!(got.status, 200, "{name}");
        assert_eq!(got.header("Content-Type"), Some(media), "{name}");
        assert_eq!(
            got.header("Content-Disposition"),
            Some(format!("{kind}; filename=\"{name}\"; filename*=UTF-8''{name}").as_str())
        );
        assert_eq!(got.body, b"<html>no sniffing</html>");
        for (header, value) in [
            ("X-Content-Type-Options", "nosniff"),
            ("Content-Security-Policy", "sandbox; default-src 'none'"),
            ("Referrer-Policy", "no-referrer"),
        ] {
            assert_eq!(got.header(header), Some(value));
        }
    }
}

#[test]
fn ordinary_ref_headers_cover_head_ranges_both_file_types_and_exclude_other_responses() {
    let (fx, d) = published();
    for name in ["small.txt", "chunked.bin"] {
        let path = fx.ref_url("room", "main", name);
        let full = fx.get(&path);
        for method in ["GET", "HEAD"] {
            let partial = read(fx.request(method, &path, None, &[("range", "bytes=1-2")]));
            assert_eq!(partial.status, 206);
            assert_eq!(partial.header("Content-Type"), full.header("Content-Type"));
            assert_eq!(
                partial.header("Content-Disposition"),
                full.header("Content-Disposition")
            );
            assert_eq!(
                partial.body,
                if method == "HEAD" {
                    vec![]
                } else {
                    full.body[1..3].to_vec()
                }
            );
            let head = read(fx.request("HEAD", &path, None, &[]));
            assert_eq!(head.status, 200);
            assert_eq!(
                head.header("Content-Disposition"),
                full.header("Content-Disposition")
            );
            assert!(head.body.is_empty());
        }
        let etag = full.header("ETag").unwrap();
        for headers in [[("if-none-match", etag)], [("range", "bytes=999999-")]] {
            let got = fx.get_with(&path, &headers);
            assert!(matches!(got.status, 304 | 416));
            assert_eq!(got.header("Content-Disposition"), None);
            assert_eq!(got.header("Content-Type"), None);
        }
    }
    for object in [&d.small, &d.manifest, &d.root, &d.commit] {
        let got = fx.get(&fx.object_url("room", &id(object)));
        assert_eq!(got.status, 200);
        assert_eq!(got.header("Content-Disposition"), None);
    }
    for path in ["", "dir"] {
        let got = fx.get(&fx.ref_url("room", "main", path));
        assert_eq!(
            got.header("Content-Type"),
            Some("application/vnd.mkit.object")
        );
        assert_eq!(got.header("Content-Disposition"), None);
    }
    let paid = with_seams(fixture(), |s| {
        s.admission = Arc::new(Admit {
            seen: Mutex::default(),
            ended: Arc::default(),
            challenge: true,
        });
    });
    paid.push("room", &d.refs(), d.head(), None);
    let got = paid.get(&paid.ref_url("room", "main", "small.txt"));
    assert_eq!(got.status, 402);
    assert_eq!(got.header("Content-Disposition"), None);
}
