//! RFC 9110 challenge lists: commas separate parameters or challenges.
use std::collections::BTreeMap;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Challenge {
    pub(crate) scheme: String,
    pub(crate) params: BTreeMap<String, String>,
    pub(crate) token68: Option<String>,
}

fn token(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
}

fn parameter_value(raw: &str) -> Result<String, &'static str> {
    Ok(
        if let Some(quoted) = raw.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
            let mut decoded = String::new();
            let mut chars = quoted.chars();
            while let Some(c) = chars.next() {
                if c == '"' {
                    return Err("unescaped auth-param quote");
                }
                let c = if c == '\\' {
                    chars.next().ok_or("invalid quoted pair")?
                } else {
                    c
                };
                decoded.push(c);
            }
            decoded
        } else if !raw.is_empty() && raw.bytes().all(token) {
            raw.into()
        } else {
            return Err("invalid auth-param value");
        },
    )
}

/// Parse bounded fields without mistaking quoted commas or auth-params for challenges.
pub(crate) fn parse(value: &str) -> Result<Vec<Challenge>, &'static str> {
    if value.len() > 65_536 || !value.is_ascii() {
        return Err("challenge list bounds");
    }
    let mut pieces = Vec::new();
    let (mut start, mut quoted, mut escaped) = (0, false, false);
    for (i, c) in value.bytes().enumerate() {
        if c < 32 && c != b'\t' || c == 127 {
            return Err("challenge list control byte");
        }
        if escaped {
            escaped = false;
        } else if quoted && c == b'\\' {
            escaped = true;
        } else if c == b'"' {
            quoted = !quoted;
        } else if c == b',' && !quoted {
            pieces.push(&value[start..i]);
            start = i + 1;
        }
    }
    if quoted || escaped {
        return Err("unterminated challenge quote");
    }
    pieces.push(&value[start..]);
    let mut result: Vec<Challenge> = Vec::new();
    for piece in pieces {
        let piece = piece.trim();
        if piece.is_empty() {
            continue; // RFC list recipients ignore empty members.
        }
        let end = piece.bytes().take_while(|c| token(*c)).count();
        if end == 0 {
            return Err("challenge token missing");
        }
        let rest = piece[end..].trim_start();
        let param = if rest.starts_with('=') {
            piece
        } else {
            if !rest.is_empty() && !piece.as_bytes()[end].is_ascii_whitespace() {
                return Err("challenge scheme separator");
            }
            result.push(Challenge {
                scheme: piece[..end].into(),
                params: BTreeMap::new(),
                token68: None,
            });
            if result.len() > 8 {
                return Err("challenge count bound");
            }
            rest
        };
        if param.is_empty() {
            continue;
        }
        let current = result.last_mut().ok_or("parameter before challenge")?;
        let n = param.bytes().take_while(|c| token(*c)).count();
        let suffix = param[n..].trim_start();
        // token68 permits trailing '=' padding, not an auth-param value.
        let core = param.trim_end_matches('=');
        if !core.is_empty()
            && core
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-._~+/".contains(&c))
        {
            if !current.params.is_empty() || current.token68.is_some() {
                return Err("invalid token68 challenge");
            }
            current.token68 = Some(param.into());
            continue;
        }
        let raw = suffix
            .strip_prefix('=')
            .ok_or("auth-param equals missing")?
            .trim();
        let decoded = parameter_value(raw)?;
        if n == 0
            || current.token68.is_some()
            || current
                .params
                .insert(param[..n].to_ascii_lowercase(), decoded)
                .is_some()
        {
            return Err("duplicate or invalid auth-param");
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_and_combined_lists_are_equivalent_with_quoted_commas() {
        let a = r#"Payment id="a,b", request="x,y", realm="a\"b""#;
        let b = r#"Basic realm="second""#;
        let mut separate = parse(a).unwrap();
        separate.extend(parse(b).unwrap());
        let combined = parse(&format!("{a}, {b}")).unwrap();
        assert_eq!(combined, separate);
        assert_eq!(combined[0].params["id"], "a,b");
        assert_eq!(combined[0].params["realm"], "a\"b");
        assert_eq!(combined[1].scheme, "Basic");
    }

    #[test]
    fn token68_empty_members_and_parameter_whitespace() {
        let list =
            parse(r#", Basic YWJj/Z+A==, , Payment id = "one", request="a,b", Negotiate"#).unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].token68.as_deref(), Some("YWJj/Z+A=="));
        assert_eq!(list[1].params["request"], "a,b");
        assert!(list[2].params.is_empty());
    }

    #[test]
    fn malformed_lists_are_rejected_without_echoing_input() {
        for value in [
            r#"Payment id="unterminated"#,
            "id=one",
            "Payment id=, request=one",
            "Payment id=one, ID=two",
            "Payment id=one\r\n",
        ] {
            assert!(parse(value).is_err());
        }
    }
}
