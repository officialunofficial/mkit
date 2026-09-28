//! Declarative HTTP response contract and a URL-only reference parser.
use super::*;

fn id(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn repo(s: &str, single: bool) -> bool {
    let parts: Vec<_> = s.split('/').collect();
    let name = if parts.len() == 1 && single {
        parts[0]
    } else if let [namespace, name] = parts.as_slice() {
        let valid = namespace.strip_prefix("ed25519-").is_some_and(id)
            || namespace.strip_prefix("0x").is_some_and(|s| {
                s.len() == 40
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            });
        if !valid {
            return false;
        }
        name
    } else {
        return false;
    };
    !name.is_empty()
        && name.len() <= 100
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}
fn path(s: &str) -> Option<Vec<Vec<u8>>> {
    if s.is_empty() {
        return Some(vec![]);
    }
    let mut names = vec![];
    for part in s.split('/') {
        let raw = part.as_bytes();
        let mut out = vec![];
        let mut i = 0;
        while i < raw.len() {
            if raw[i] == b'%' {
                let digits = raw.get(i + 1..i + 3)?;
                if !digits.iter().all(u8::is_ascii_hexdigit) {
                    return None;
                }
                let h = std::str::from_utf8(digits).ok()?;
                out.push(u8::from_str_radix(h, 16).ok()?);
                i += 3;
            } else {
                if !raw[i].is_ascii_alphanumeric() && !b"-._~".contains(&raw[i]) {
                    return None;
                }
                out.push(raw[i]);
                i += 1;
            }
        }
        if !TreeEntry::validate_name(&out) {
            return None;
        }
        names.push(out);
    }
    let total: usize = names.iter().map(Vec::len).sum::<usize>() + names.len() - 1;
    (total <= 1024).then_some(names)
}
fn parse(url: &str, single: bool) -> Option<Value> {
    if url.contains('#') {
        return None;
    }
    let (route, query) = url
        .split_once('?')
        .map_or((url, None), |(r, q)| (r, Some(q)));
    let (repository, form) = route.split_once("/-/")?;
    let repository = if repository.is_empty() {
        if !single {
            return None;
        }
        None
    } else {
        let r = repository.strip_prefix('/')?;
        if !repo(r, single) {
            return None;
        }
        Some(r)
    };
    let mut params = BTreeMap::new();
    if let Some(q) = query {
        if q.is_empty() {
            return None;
        }
        for param in q.split('&') {
            let (key, val) = param.split_once('=')?;
            if !["proof", "range", "commit", "path", "token"].contains(&key)
                || params.insert(key, val).is_some()
            {
                return None;
            }
            match key {
                "proof" if val != "1" => return None,
                "commit" if !id(val) => return None,
                "path" if path(val).is_none() => return None,
                "range" => {
                    let (a, b) = val.split_once('-')?;
                    if a.is_empty()
                        || b.is_empty()
                        || !a.bytes().chain(b.bytes()).all(|b| b.is_ascii_digit())
                    {
                        return None;
                    }
                    if a.parse::<u64>().ok()? > b.parse::<u64>().ok()? {
                        return None;
                    }
                }
                _ => {}
            }
        }
    }
    if params.contains_key("range") && !params.contains_key("proof") {
        return None;
    }
    if let Some(object) = form.strip_prefix("objects/") {
        if !id(object) {
            return None;
        }
        if params.contains_key("proof")
            && (!params.contains_key("commit") || !params.contains_key("path"))
        {
            return None;
        }
        Some(
            json!({"repository": repository, "kind": "object", "object": object,
            "proof": params.contains_key("proof"), "query": params}),
        )
    } else {
        let (reference, file) = form.split_once("/-/")?;
        if !reference.starts_with("refs/") || !mkit_core::refs::validate_ref_name(reference) {
            return None;
        }
        let names = path(file)?;
        Some(
            json!({"repository": repository, "kind": "ref", "ref": reference,
            "path_hex": names.iter().map(|b| hex(b)).collect::<Vec<_>>(), "proof": params.contains_key("proof"), "query": params}),
        )
    }
}

#[allow(clippy::too_many_lines)] // Declarative URL cases.
pub(super) fn urls() -> Value {
    let h = "b0145b689c72cfb1b8b1e7ec756c2c4a1e0b4f0469393e4ff4a30d8c3d6a0d6f";
    let base = "/-/refs/heads/main/-/";
    let mut cases = vec![];
    let mut add = |name: &str, url: String, single: bool, status: u16| {
        let parsed = parse(&url, single);
        assert_eq!(parsed.is_some(), status == 200, "{name}");
        cases.push(json!({"name": name, "request": {"url": url, "single_repository": single}, "expect": {"status": status, "parsed": parsed}}));
    };
    for (name, url, single) in [
        ("single_id", format!("/-/objects/{h}"), true),
        ("explicit_bare", format!("/demo/-/objects/{h}"), true),
        (
            "namespace_ed25519",
            format!("/ed25519-{h}/demo/-/objects/{h}"),
            false,
        ),
        (
            "namespace_address",
            format!("/0x{}/demo/-/objects/{h}", &h[..40]),
            false,
        ),
        ("root", base.into(), true),
        ("nested", format!("{base}sub/deep/deep.txt"), true),
        ("dash_file", format!("{base}-"), true),
        (
            "dash_ref_delimits",
            "/-/refs/heads/-/topic/-/x".into(),
            true,
        ),
        (
            "dash_embedded",
            "/-/refs/heads/feature-a/-/file".into(),
            true,
        ),
        (
            "escaped_names",
            format!("{base}a%25b%3Fc%23d%20e/%FF"),
            true,
        ),
        ("one_decode", format!("{base}%252F"), true),
        ("ref_uppercase", "/-/refs/heads/Main/-/file".into(), true),
        (
            "ref_max",
            format!("/-/refs/{}/-/file", "a".repeat(507)),
            true,
        ),
        (
            "path_max",
            format!(
                "{base}{}/{}/{}/{}/a",
                "a".repeat(255),
                "a".repeat(255),
                "a".repeat(255),
                "a".repeat(254)
            ),
            true,
        ),
        ("proof_ref", format!("{base}shallow.txt?proof=1"), true),
        (
            "proof_range",
            format!("{base}chunked.bin?proof=1&range=001-020"),
            true,
        ),
        (
            "proof_root_id",
            format!("/-/objects/{h}?proof=1&commit={h}&path="),
            true,
        ),
        (
            "proof_object_context",
            format!("/-/objects/{h}?path=sub/file&commit={h}&proof=1"),
            true,
        ),
        ("unused_context", format!("{base}?commit={h}&path=a"), true),
        (
            "max_endpoint_syntax",
            format!("{base}range.bin?proof=1&range=0-18446744073709551615"),
            true,
        ),
    ] {
        add(name, url, single, 200);
    }
    for (name, url, single) in [
        ("missing_repo_multi", format!("/-/objects/{h}"), false),
        ("bare_repo_multi", format!("/demo/-/objects/{h}"), false),
        ("uppercase_repo", format!("/Demo/-/objects/{h}"), true),
        (
            "uppercase_namespace",
            format!("/ed25519-{}/demo/-/objects/{h}", h.to_uppercase()),
            false,
        ),
        (
            "unknown_namespace",
            format!("/user/demo/-/objects/{h}"),
            false,
        ),
        (
            "long_repo",
            format!("/{}/-/objects/{h}", "a".repeat(101)),
            true,
        ),
        ("bad_repo_lead", format!("/.demo/-/objects/{h}"), true),
        ("escaped_repo", format!("/de%6do/-/objects/{h}"), true),
        (
            "uppercase_id",
            format!("/-/objects/{}", h.to_uppercase()),
            true,
        ),
        ("short_id", format!("/-/objects/{}", &h[..63]), true),
        ("nonhex_id", format!("/-/objects/{}g", &h[..63]), true),
        ("id_trailing_slash", format!("/-/objects/{h}/"), true),
        ("missing_ref_delimiter", "/-/refs/heads/main".into(), true),
        ("outside_refs", "/-/heads/main/-/file".into(), true),
        ("escaped_ref", "/-/refs/heads/ma%69n/-/file".into(), true),
        ("ref_empty_segment", "/-/refs//main/-/file".into(), true),
        ("ref_dot_segment", "/-/refs/heads/.main/-/file".into(), true),
        ("ref_lock", "/-/refs/heads/main.lock/-/file".into(), true),
        ("ref_head", "/-/refs/heads/HEAD/-/file".into(), true),
        (
            "ref_long",
            format!("/-/refs/{}/-/file", "a".repeat(508)),
            true,
        ),
        ("path_empty_segment", format!("{base}a//b"), true),
        ("path_trailing_slash", format!("{base}a/"), true),
        ("path_leading_slash", format!("{base}/a"), true),
        ("invalid_escape", format!("{base}a%GG"), true),
        ("escape_with_sign", format!("{base}a%+1b"), true),
        ("truncated_escape", format!("{base}a%2"), true),
        ("decoded_slash", format!("{base}a%2Fb"), true),
        ("decoded_backslash", format!("{base}a%5Cb"), true),
        ("decoded_nul", format!("{base}a%00b"), true),
        ("dot_entry", format!("{base}%2E"), true),
        ("dotdot_entry", format!("{base}.."), true),
        ("metadata_entry", format!("{base}.mkit"), true),
        ("reserved_entry", format!("{base}CON.txt"), true),
        ("trailing_space", format!("{base}a%20"), true),
        ("trailing_dot", format!("{base}a."), true),
        ("raw_plus", format!("{base}a+b"), true),
        ("raw_space", format!("{base}a b"), true),
        ("entry_long", format!("{base}{}", "a".repeat(256)), true),
        (
            "path_long",
            format!(
                "{base}{}/{}/{}/{}/aa",
                "a".repeat(255),
                "a".repeat(255),
                "a".repeat(255),
                "a".repeat(254)
            ),
            true,
        ),
        ("empty_query", format!("{base}?"), true),
        ("unknown_parameter", format!("{base}?foo=1"), true),
        (
            "repeated_parameter",
            format!("{base}?proof=1&proof=1"),
            true,
        ),
        ("empty_parameter", format!("{base}?proof=1&"), true),
        ("escaped_parameter", format!("{base}?%70roof=1"), true),
        ("proof_value", format!("{base}?proof=0"), true),
        ("range_without_proof", format!("{base}?range=0-1"), true),
        ("range_reverse", format!("{base}?proof=1&range=2-1"), true),
        (
            "range_overflow",
            format!("{base}?proof=1&range=0-18446744073709551616"),
            true,
        ),
        ("range_empty", format!("{base}?proof=1&range=0-"), true),
        ("range_sign", format!("{base}?proof=1&range=+0-1"), true),
        (
            "proof_missing_context",
            format!("/-/objects/{h}?proof=1"),
            true,
        ),
        (
            "proof_missing_path",
            format!("/-/objects/{h}?proof=1&commit={h}"),
            true,
        ),
        (
            "proof_missing_commit",
            format!("/-/objects/{h}?proof=1&path=a"),
            true,
        ),
        (
            "uppercase_commit",
            format!("{base}?commit={}", h.to_uppercase()),
            true,
        ),
        ("bad_context_path", format!("{base}?path=a%2Fb"), true),
    ] {
        add(name, url, single, 400);
    }
    json!({"schema_version": 1, "cases": cases})
}

#[allow(clippy::too_many_lines)] // Declarative status/header matrix.
pub(super) fn responses() -> Value {
    let h = "b0145b689c72cfb1b8b1e7ec756c2c4a1e0b4f0469393e4ff4a30d8c3d6a0d6f";
    let commit = "1d8c6225d142427a5791e289bb616393f299292880d59b43cbbebcb6d2c9b145";
    let etag = format!("\"{h}\"");
    let security = json!({"X-Content-Type-Options":"nosniff", "Content-Security-Policy":"sandbox; default-src 'none'", "Referrer-Policy":"no-referrer", "Access-Control-Allow-Origin":"*"});
    let mut cases = vec![];
    let mut add = |name: &str, request: Value, status: u16, headers: Value, absent: Value| {
        let mut hdr = security.clone();
        for (k, v) in headers.as_object().unwrap() {
            hdr[k] = v.clone();
        }
        cases.push(json!({"name":name, "request":request, "expect":{"status":status,"headers":hdr,"absent_headers":absent}}));
    };
    add(
        "preflight_before_auth",
        json!({"method":"OPTIONS","malformed_url":true,"bearer_required":true,"repository_missing":true,"admission":"challenge"}),
        204,
        json!({"Access-Control-Allow-Methods":"GET, HEAD, OPTIONS","Access-Control-Allow-Headers":"Range, If-None-Match, If-Range, Payment-Authorization, PAYMENT-SIGNATURE, Authorization, Accept-Payment","Cache-Control":"private"}),
        json!(["Access-Control-Allow-Credentials"]),
    );
    add(
        "method_before_syntax",
        json!({"method":"POST","malformed_url":true}),
        405,
        json!({"Allow":"GET, HEAD, OPTIONS","Cache-Control":"no-store"}),
        json!([]),
    );
    add(
        "syntax_before_bearer",
        json!({"method":"GET","malformed_url":true,"bearer_required":true}),
        400,
        json!({"Cache-Control":"private, no-store"}),
        json!([]),
    );
    add(
        "bearer_before_repo",
        json!({"method":"GET","bearer_required":true,"repository_missing":true}),
        401,
        json!({"Cache-Control":"private, no-store"}),
        json!([]),
    );
    for (name, reason) in [
        ("missing_repository", "repository_missing"),
        ("private_missing_token", "private_missing_token"),
        ("private_invalid_token", "private_invalid_token"),
        ("authorizer_private", "authorizer_private"),
        ("authorizer_not_found", "authorizer_not_found"),
        ("missing_ref", "missing_ref"),
        ("non_tree", "non_tree"),
        ("missing_entry", "missing_entry"),
        ("unreachable_commit", "unreachable_commit"),
        ("wrong_leaf", "wrong_leaf"),
        ("nonmember", "nonmember"),
        ("unreachable_id", "unreachable_id"),
        ("pending", "pending"),
    ] {
        add(
            name,
            json!({"method":"GET","failure":reason,"if_none_match":etag,"admission":"challenge"}),
            404,
            json!({"Cache-Control":"no-store"}),
            json!(["ETag", "X-Mkit-Object", "X-Mkit-Commit"]),
        );
    }
    add(
        "authorizer_public",
        json!({"method":"GET","failure":"authorizer_deny"}),
        403,
        json!({"Cache-Control":"no-store"}),
        json!([]),
    );
    add(
        "tombstone_before_304_and_admission",
        json!({"method":"GET","route":"ref","published_reachable":true,"repository_tombstone":true,"if_none_match":etag,"admission":"challenge"}),
        451,
        json!({"Content-Type":"application/json","Cache-Control":"no-store","Link":"<https://vcs.example.test>; rel=\"blocked-by\""}),
        json!(["ETag", "X-Mkit-*", "Content-Range"]),
    );
    add(
        "tombstone_head_no_body",
        json!({"method":"HEAD","route":"object","published_reachable":true,"repository_tombstone":true}),
        451,
        json!({"Content-Type":"application/json","Cache-Control":"no-store","Link":"<https://vcs.example.test>; rel=\"blocked-by\""}),
        json!(["ETag", "X-Mkit-*", "Content-Range"]),
    );
    add(
        "global_block_without_repository_tombstone",
        json!({"method":"GET","route":"object","published_reachable":true,"global_block":true,"repository_tombstone":false}),
        404,
        json!({"Cache-Control":"no-store"}),
        json!(["ETag", "X-Mkit-*"]),
    );
    add(
        "chunk_only_under_tombstoned_manifest",
        json!({"method":"GET","route":"object","chunk_only_under_tombstoned_manifest":true,"repository_tombstone":false}),
        404,
        json!({"Cache-Control":"no-store"}),
        json!(["ETag", "X-Mkit-*"]),
    );
    add(
        "not_modified_before_range_admission",
        json!({"method":"GET","route":"ref","if_none_match":etag,"range":"bytes=200-300","size":100,"admission":"challenge"}),
        304,
        json!({"ETag":etag,"Cache-Control":"private, no-cache","X-Mkit-Object":h,"X-Mkit-Object-Type":"blob","X-Mkit-Commit":commit}),
        json!(["PAYMENT-REQUIRED"]),
    );
    add(
        "not_modified_paid_policy",
        json!({"method":"GET","if_none_match":etag,"admission_configured":true,"admission_called":false}),
        304,
        json!({"ETag":etag,"Cache-Control":"private, max-age=31536000, immutable","X-Mkit-Object":h,"X-Mkit-Object-Type":"blob"}),
        json!(["PAYMENT-REQUIRED"]),
    );
    add(
        "not_modified_proof_paid_policy",
        json!({"method":"GET","route":"object","proof":true,"if_none_match":format!("\"{commit}.{h}.object\""),"admission_configured":true,"admission_called":false}),
        304,
        json!({"ETag":format!("\"{commit}.{h}.object\""),"Cache-Control":"private, max-age=31536000, immutable","X-Mkit-Object":h,"X-Mkit-Object-Type":"chunked_blob","X-Mkit-Commit":commit}),
        json!(["PAYMENT-REQUIRED"]),
    );
    add(
        "infrastructure_failure",
        json!({"method":"GET","failure":"hook_unavailable"}),
        503,
        json!({"Cache-Control":"no-store"}),
        json!([]),
    );
    add(
        "public_token_ignored",
        json!({"method":"GET","public":true,"token_valid":false}),
        200,
        json!({"Cache-Control":"public, max-age=31536000, immutable"}),
        json!([]),
    );
    add(
        "bearer_gated_public_id",
        json!({"method":"GET","route":"object","public":true,"bearer_required":true,"bearer_valid":true}),
        200,
        json!({"ETag":etag,"Cache-Control":"private, max-age=31536000, immutable","X-Mkit-Object":h,"X-Mkit-Object-Type":"blob"}),
        json!([]),
    );
    add(
        "unsatisfiable_before_admission",
        json!({"method":"GET","range":"bytes=100-200","size":100,"admission":"challenge"}),
        416,
        json!({"Cache-Control":"no-store","Content-Range":"bytes */100"}),
        json!([]),
    );
    for reason in [
        "outside_content",
        "proof_content_cap",
        "proof_encoded_cap",
        "unsupported_leaf",
    ] {
        add(
            reason,
            json!({"method":"GET","proof":true,"range_failure":reason,"admission":"challenge"}),
            416,
            json!({"Cache-Control":"no-store"}),
            json!([]),
        );
    }
    add(
        "challenge",
        json!({"method":"GET","admission":"challenge"}),
        402,
        json!({"Cache-Control":"no-store","Content-Type":"application/json","WWW-Authenticate":"Payment example","PAYMENT-REQUIRED":"opaque-challenge"}),
        json!([
            "ETag",
            "X-Mkit-*",
            "X-Mkit-Object",
            "X-Mkit-Object-Type",
            "X-Mkit-Commit",
            "Content-Range"
        ]),
    );
    add(
        "admission_deny",
        json!({"method":"GET","admission":"deny"}),
        403,
        json!({"Cache-Control":"no-store"}),
        json!([]),
    );
    for (name, request, status, cache, media, length, range) in [
        (
            "public_id",
            json!({"method":"GET","route":"object","public":true}),
            200,
            "public, max-age=31536000, immutable",
            "application/octet-stream",
            100,
            None,
        ),
        (
            "public_ref",
            json!({"method":"GET","route":"ref","public":true}),
            200,
            "public, no-cache",
            "application/octet-stream",
            100,
            None,
        ),
        (
            "private_id",
            json!({"method":"GET","route":"object","public":false,"token_remaining_seconds":60}),
            200,
            "private, max-age=60, immutable",
            "application/octet-stream",
            100,
            None,
        ),
        (
            "private_ref",
            json!({"method":"GET","route":"ref","public":false}),
            200,
            "private, no-cache",
            "application/octet-stream",
            100,
            None,
        ),
        (
            "paid",
            json!({"method":"GET","route":"object","admission":"allow","public":true}),
            200,
            "private, max-age=31536000, immutable",
            "application/octet-stream",
            100,
            None,
        ),
        (
            "paid_ref",
            json!({"method":"GET","route":"ref","admission":"allow","public":true}),
            200,
            "private, no-cache",
            "application/octet-stream",
            100,
            None,
        ),
        (
            "head",
            json!({"method":"HEAD","route":"object","admission":"allow","declared_bytes":100,"bytes_served":0}),
            200,
            "private, max-age=31536000, immutable",
            "application/octet-stream",
            100,
            None,
        ),
        (
            "chunked_content",
            json!({"method":"GET","type":"chunked_blob","reassembled":true}),
            200,
            "public, max-age=31536000, immutable",
            "application/octet-stream",
            100,
            None,
        ),
        (
            "canonical_tree",
            json!({"method":"GET","type":"tree"}),
            200,
            "public, max-age=31536000, immutable",
            "application/vnd.mkit.object",
            100,
            None,
        ),
        (
            "single_range",
            json!({"method":"GET","range":"bytes=10-19","size":100}),
            206,
            "public, max-age=31536000, immutable",
            "application/octet-stream",
            10,
            Some("bytes 10-19/100"),
        ),
        (
            "if_range_match",
            json!({"method":"GET","range":"bytes=10-19","if_range":etag,"size":100}),
            206,
            "public, max-age=31536000, immutable",
            "application/octet-stream",
            10,
            Some("bytes 10-19/100"),
        ),
        (
            "if_range_miss",
            json!({"method":"GET","range":"bytes=10-19","if_range":"\"different\"","size":100}),
            200,
            "public, max-age=31536000, immutable",
            "application/octet-stream",
            100,
            None,
        ),
        (
            "multi_range",
            json!({"method":"GET","range":"bytes=0-1,5-6","size":100}),
            200,
            "public, max-age=31536000, immutable",
            "application/octet-stream",
            100,
            None,
        ),
    ] {
        let mut headers = json!({"ETag":etag,"Accept-Ranges":"bytes","Cache-Control":cache,"Content-Type":media,"Content-Length":length.to_string(),"X-Mkit-Object":h,"X-Mkit-Object-Type":request["type"].as_str().unwrap_or("blob")});
        if request["route"] == "ref" {
            headers["X-Mkit-Commit"] = json!(commit);
        }
        if let Some(r) = range {
            headers["Content-Range"] = json!(r);
        }
        add(
            name,
            request,
            status,
            headers,
            json!(["Access-Control-Allow-Credentials"]),
        );
    }
    for (name, route, kind, selector, cache) in [
        (
            "proof_object",
            "object",
            "MKDP",
            "object",
            "public, max-age=31536000, immutable",
        ),
        ("proof_ref", "ref", "MKDP", "object", "public, no-cache"),
        (
            "proof_blob_range",
            "ref",
            "MKDP",
            "range-10-19",
            "public, no-cache",
        ),
        (
            "proof_span",
            "object",
            "MKDS",
            "range-10-19",
            "public, max-age=31536000, immutable",
        ),
        (
            "proof_private",
            "object",
            "MKDP",
            "object",
            "private, max-age=60, immutable",
        ),
        (
            "proof_paid",
            "object",
            "MKDS",
            "range-10-19",
            "private, max-age=31536000, immutable",
        ),
    ] {
        add(
            name,
            json!({"method":"GET","proof":true,"route":route,"kind":kind,"range_header":"bytes=1-2","selector":selector,"public":name!="proof_private","admission":if name=="proof_paid" {"allow"} else {"off"},"token_remaining_seconds":60}),
            200,
            json!({"Content-Type":if kind=="MKDS" {"application/vnd.mkit.disclosure-span"}else{"application/vnd.mkit.disclosure"},"Accept-Ranges":"none","ETag":format!("\"{commit}.{h}.{selector}\""),"Cache-Control":cache,"X-Mkit-Commit":commit,"X-Mkit-Object":h,"X-Mkit-Object-Type":if name=="proof_blob_range" {"blob"} else {"chunked_blob"}}),
            json!(["Content-Range"]),
        );
    }
    add(
        "receipt",
        json!({"method":"GET","route":"object","receipt":true}),
        200,
        json!({"Cache-Control":"private, max-age=31536000, immutable","Payment-Receipt":"opaque-receipt","PAYMENT-RESPONSE":"opaque-response"}),
        json!([]),
    );
    add(
        "public_redirect",
        json!({"method":"GET","route":"ref","redirects":true,"public":true}),
        302,
        json!({"Location":format!("/-/objects/{h}"),"Cache-Control":"no-cache"}),
        json!([]),
    );
    add(
        "admitted_ref_served_directly",
        json!({"method":"GET","route":"ref","redirects":true,"public":true,"admission_configured":true,"admission":"allow"}),
        200,
        json!({"ETag":etag,"Cache-Control":"private, no-cache","X-Mkit-Object":h,"X-Mkit-Object-Type":"blob","X-Mkit-Commit":commit}),
        json!(["Location"]),
    );
    add(
        "cors_configured",
        json!({"method":"GET","origin":"https://viewer.example"}),
        200,
        json!({"Access-Control-Allow-Origin":"https://viewer.example","Vary":"Origin","Access-Control-Expose-Headers":"ETag, Content-Range, Accept-Ranges, Content-Length, X-Mkit-Commit, X-Mkit-Object, X-Mkit-Object-Type, WWW-Authenticate, Payment-Receipt, PAYMENT-REQUIRED, PAYMENT-RESPONSE, Link"}),
        json!(["Access-Control-Allow-Credentials"]),
    );
    add(
        "key_document_exempt",
        json!({"method":"GET","route":"/.well-known/mkit-url-token-keys.json","bearer_required":true}),
        200,
        json!({"Content-Type":"application/json","Cache-Control":"public, max-age=300"}),
        json!([]),
    );
    for row in &mut cases {
        if row["expect"]["status"] == 404 {
            row["expect"]["body_equivalence_group"] = json!("uniform_404");
        }
        if row["request"]["method"] == "HEAD"
            || [204, 304].iter().any(|n| row["expect"]["status"] == *n)
        {
            row["expect"]["body_bytes"] = json!(0);
        }
        if row["expect"]["status"] == 451 && row["request"]["method"] == "GET" {
            row["expect"]["body_fixture"] = json!("redaction/detail.json");
            row["expect"]["body_bytes"] =
                json!(include_bytes!("../../../../tests/golden/redaction/detail.json").len());
        }
        if row["name"] == "head" {
            row["expect"]["outcome"] = json!({"kind":"ReadServed","bytes_served":0});
        }
        if row["name"] == "challenge" {
            let body = json!({"challenges":[{"scheme":"example","value":"opaque-challenge"}],"description":"Admission required"});
            row["request"]["admission_challenge"] = body.clone();
            row["expect"]["body_json"] = body;
        }
    }
    json!({"schema_version":1,"cases":cases,"notes":{"451":"Only a repository tombstone with published-tree reachability returns 451; prior 404 checks win.","opaque":"No object routes mounted.","uniform_404":"Missing repository and missing/invalid private token use identical headers and body.","402_body":"AdmissionChallenge canonical protobuf JSON; HEAD has no body."}})
}

#[allow(clippy::too_many_lines)] // Checks the full URL and response golden tables together.
pub(super) fn check(dir: &std::path::Path) {
    fn assert_id(value: &str) {
        assert!(id(value), "expected 64 lowercase hex characters: {value}");
    }
    let table: Value =
        serde_json::from_slice(&fs::read(dir.join("url-parse.json")).unwrap()).unwrap();
    assert_eq!(table["schema_version"], 1);
    for row in table["cases"].as_array().unwrap() {
        let got = parse(
            row["request"]["url"].as_str().unwrap(),
            row["request"]["single_repository"].as_bool().unwrap(),
        );
        assert_eq!(
            got.is_some(),
            row["expect"]["status"] == 200,
            "{}",
            row["name"]
        );
        assert_eq!(json!(got), row["expect"]["parsed"]);
        let parsed = &row["expect"]["parsed"];
        if let Some(value) = parsed["object"].as_str() {
            assert_id(value);
        }
        if let Some(value) = parsed["query"]["commit"].as_str() {
            assert_id(value);
        }
    }
    let table: Value =
        serde_json::from_slice(&fs::read(dir.join("response-cases.json")).unwrap()).unwrap();
    assert_eq!(table["schema_version"], 1);
    let rows = table["cases"].as_array().unwrap();
    assert!(rows.len() >= 40);
    for row in rows {
        let status = row["expect"]["status"].as_u64().unwrap();
        let headers = &row["expect"]["headers"];
        if status == 451 {
            assert_eq!(row["request"]["repository_tombstone"], true);
            assert_eq!(row["request"]["published_reachable"], true);
            assert_eq!(headers["Content-Type"], "application/json");
            assert_eq!(
                headers["Link"],
                "<https://vcs.example.test>; rel=\"blocked-by\""
            );
            assert_eq!(headers["Cache-Control"], "no-store");
            if row["request"]["method"] == "HEAD" {
                assert_eq!(row["expect"]["body_bytes"], 0);
            } else {
                assert_eq!(row["expect"]["body_fixture"], "redaction/detail.json");
                assert_eq!(
                    row["expect"]["body_bytes"],
                    include_bytes!("../../../../tests/golden/redaction/detail.json").len()
                );
            }
        }
        if status >= 400 {
            assert!(
                headers["Cache-Control"]
                    .as_str()
                    .unwrap()
                    .contains("no-store")
            );
        }
        for absent in row["expect"]["absent_headers"].as_array().unwrap() {
            let name = absent.as_str().unwrap();
            if let Some(prefix) = name.strip_suffix('*') {
                assert!(
                    headers
                        .as_object()
                        .unwrap()
                        .keys()
                        .all(|key| !key.starts_with(prefix))
                );
            } else {
                assert!(headers.get(name).is_none());
            }
        }
        assert_eq!(headers["X-Content-Type-Options"], "nosniff");
        for name in ["X-Mkit-Object", "X-Mkit-Commit"] {
            if let Some(value) = headers[name].as_str() {
                assert_id(value);
            }
        }
        if let Some(location) = headers["Location"].as_str() {
            assert_id(location.rsplit('/').next().unwrap());
        }
        if let Some(value) = headers["ETag"].as_str() {
            let inner = value.strip_prefix('"').unwrap().strip_suffix('"').unwrap();
            let mut parts = inner.split('.');
            assert_id(parts.next().unwrap());
            if let Some(leaf) = parts.next() {
                assert_id(leaf);
                assert!(
                    parts.next().is_some_and(
                        |selector| selector == "object" || selector.starts_with("range-")
                    )
                );
                assert!(parts.next().is_none());
            }
        }
    }
    let get = |name: &str| rows.iter().find(|r| r["name"] == name).unwrap();
    assert_eq!(
        get("missing_repository")["expect"],
        get("private_missing_token")["expect"]
    );
    assert_eq!(
        get("missing_repository")["expect"],
        get("private_invalid_token")["expect"]
    );
    for name in [
        "paid",
        "head",
        "proof_paid",
        "not_modified_paid_policy",
        "not_modified_proof_paid_policy",
    ] {
        assert_eq!(
            get(name)["expect"]["headers"]["Cache-Control"],
            "private, max-age=31536000, immutable"
        );
    }
    assert_eq!(
        get("paid_ref")["expect"]["headers"]["Cache-Control"],
        "private, no-cache"
    );
    assert_eq!(get("admitted_ref_served_directly")["expect"]["status"], 200);
    assert_eq!(
        get("bearer_gated_public_id")["expect"]["headers"]["Cache-Control"],
        "private, max-age=31536000, immutable"
    );
}
