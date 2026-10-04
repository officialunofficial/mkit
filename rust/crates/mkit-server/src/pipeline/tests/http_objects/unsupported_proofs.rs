//! Unsupported proofs retain access checks and stop before representation work.
use super::*;

pub(super) fn assert_missing(got: &Got, method: &str) {
    if method == "HEAD" {
        assert_eq!(got.status, 404);
        assert_eq!(got.header("Cache-Control"), Some("no-store"));
        assert!(got.body.is_empty());
        assert!(got.header("ETag").is_none());
    } else {
        assert_uniform_404(got);
    }
}

#[test]
fn unsupported_get_head_validate_syntax_before_storage() {
    let (fx, d) = published();
    for method in ["GET", "HEAD"] {
        for query in [
            "proof=0",
            "proof=1",
            "proof=1&commit=bad&path=x",
            "proof=1&range=2-1",
            "proof=1&range=0-18446744073709551616",
            "proof=1&proof=1",
            "proof=1&path=%ZZ",
        ] {
            fx.pipe.meta.seen.lock().unwrap().clear();
            fx.calls.lock().unwrap().clear();
            let got = read(fx.request(
                method,
                &fx.object_url("room", &id(&d.small)),
                Some(query),
                &[],
            ));
            assert_eq!(got.status, 400, "{method} {query}");
            assert!(fx.pipe.meta.seen().is_empty());
            assert!(fx.calls.lock().unwrap().is_empty());
            if method == "HEAD" {
                assert!(got.body.is_empty());
            }
        }
    }
}

#[test]
fn unsupported_proofs_replace_304_and_skip_context_metadata_and_body() {
    let (fx, d) = published();
    let admit = Arc::new(Admit {
        seen: Mutex::default(),
        ended: Arc::default(),
        challenge: false,
    });
    let fx = with_seams(fx, |s| s.admission = admit.clone());
    // A warm ordinary leaf needs no tree walk; neither the selected leaf's
    // canonical metadata nor an unrelated proof context is read after access.
    let object = fx.object_url("room", &id(&d.manifest));
    assert_eq!(fx.get(&object).status, 200);
    admit.seen.lock().unwrap().clear();
    admit.ended.lock().unwrap().clear();
    let query = format!(
        "proof=1&commit={}&path=missing&range=0-18446744073709551615",
        to_hex(&[99; 32])
    );
    for method in ["GET", "HEAD"] {
        fx.calls.lock().unwrap().clear();
        let response = fx.request(method, &object, Some(&query), &[("if-none-match", "*")]);
        assert!(!matches!(response.body, HttpBody::Stream { .. }));
        let got = read(response);
        assert_eq!(got.status, 416);
        assert_eq!(got.header("Cache-Control"), Some("no-store"));
        assert!(got.header("ETag").is_none());
        assert!(got.header("Content-Range").is_none());
        assert!(fx.calls.lock().unwrap().is_empty());
        for selector in [
            "proof=1",
            "proof=1&range=0-0",
            "proof=1&range=999999-999999",
        ] {
            let got = read(fx.request(
                method,
                &fx.ref_url("room", "main", "chunked.bin"),
                Some(selector),
                &[("if-none-match", "*"), ("range", "bytes=0-0")],
            ));
            assert_eq!(got.status, 416);
            assert!(got.header("ETag").is_none());
            if method == "HEAD" {
                assert!(got.body.is_empty());
            }
        }
    }
    assert!(admit.seen.lock().unwrap().is_empty());
    assert!(admit.ended.lock().unwrap().is_empty());
}

#[test]
fn unsupported_proofs_keep_missing_private_and_authorizer_denials() {
    let az = Arc::new(Scripted::default());
    let fx = fixture_with(scripted(&az), http_cfg());
    let d = data();
    fx.push("room", &d.refs(), d.head(), None);
    let query = format!("proof=1&commit={}&path=small.txt", to_hex(&d.head()));
    for method in ["GET", "HEAD"] {
        let path = fx.object_url("room", &id(&d.small));
        *az.verdict.lock().unwrap() = Some(Code::PermissionDenied);
        assert_eq!(
            read(fx.request(method, &path, Some(&query), &[])).status,
            403
        );
        *az.verdict.lock().unwrap() = Some(Code::NotFound);
        assert_missing(&read(fx.request(method, &path, Some(&query), &[])), method);
        *az.verdict.lock().unwrap() = None;
        assert_missing(
            &read(fx.request(method, &fx.object_url("room", &[99; 32]), Some(&query), &[])),
            method,
        );
    }
    fx.make_private("room");
    for method in ["GET", "HEAD"] {
        for suffix in ["", "&token=invalid"] {
            let query = format!("{query}{suffix}");
            let private = read(fx.request(
                method,
                &fx.object_url("room", &id(&d.small)),
                Some(&query),
                &[],
            ));
            let missing = read(fx.request(
                method,
                &fx.object_url("missing", &id(&d.small)),
                Some(&query),
                &[],
            ));
            assert_missing(&private, method);
            assert_eq!(
                (private.status, private.headers, private.body),
                (missing.status, missing.headers, missing.body)
            );
        }
    }
}
