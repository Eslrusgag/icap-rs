use crate::error::{Error, IcapResult};
use http::HeaderValue;

pub fn validate_istag(raw: &str) -> IcapResult<()> {
    let s = raw.trim();

    let mut val = String::new();
    let quoted = s.starts_with('"');
    if quoted {
        if !s.ends_with('"') || s.len() < 2 {
            return Err(Error::invalid_istag("unterminated quoted ISTag"));
        }
        let inner = &s[1..s.len() - 1];
        let mut it = inner.chars();
        while let Some(c) = it.next() {
            if c == '\\' {
                if let Some(esc) = it.next() {
                    val.push(esc);
                } else {
                    return Err(Error::invalid_istag("dangling escape in quoted ISTag"));
                }
            } else {
                if c.is_control() {
                    return Err(Error::invalid_istag("control char in quoted ISTag"));
                }
                val.push(c);
            }
        }
    } else {
        val.push_str(s);
    }

    if val.len() > 32 {
        return Err(Error::invalid_istag(format!(
            "too long: {} bytes (max 32)",
            val.len()
        )));
    }
    if quoted {
        return Ok(());
    }

    if !val.chars().all(is_http_token_char) {
        return Err(Error::invalid_istag(format!(
            "invalid unquoted ISTag: {raw} (use quoted-string to allow extra symbols)"
        )));
    }

    Ok(())
}

pub fn istag_header_value(istag: &str) -> IcapResult<HeaderValue> {
    validate_istag(istag)?;
    let trimmed = istag.trim();
    if trimmed.starts_with('"') {
        return Ok(HeaderValue::from_str(trimmed)?);
    }
    Ok(HeaderValue::from_str(&format!("\"{trimmed}\""))?)
}

#[inline]
fn is_http_token_char(c: char) -> bool {
    // Accept '/' and '=' for compatibility with c-icap, which can send
    // unquoted base64-like ISTag values.
    c.is_ascii()
        && !c.is_control()
        && !matches!(
            c,
            '(' | ')'
                | '<'
                | '>'
                | '@'
                | ','
                | ';'
                | ':'
                | '\\'
                | '"'
                | '['
                | ']'
                | '?'
                | '{'
                | '}'
                | ' '
                | '\t'
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("ok-Tag.123".to_string(), true)]
    #[case("helloo.1755855904-1755855904181".to_string(), true)]
    #[case("x".to_string(), true)]
    #[case("A".repeat(32), true)]
    #[case(r#""5BDEEEA9-12E4-2""#.to_string(), true)]
    #[case(r#""ABC"#.to_string(), false)]
    #[case(format!(r#""{}""#, "A".repeat(33)), false)]
    #[case(r#""ABC_DEF""#.to_string(), true)]
    #[case(r#""QUJDREUrLw==""#.to_string(), true)]
    #[case("QUJDREUrLw==".to_string(), true)]
    #[case("TAG 1".to_string(), false)]
    #[case("TAG_1".to_string(), true)]
    #[case("TAG+1".to_string(), true)]
    #[case("TAG/1".to_string(), true)]
    #[case("TAG#1".to_string(), true)]
    #[case("TAG@1".to_string(), false)]
    fn validate_istag_cases(#[case] value: String, #[case] ok: bool) {
        assert_eq!(
            validate_istag(&value).is_ok(),
            ok,
            "validate_istag failed for value={value:?}"
        );
    }
}
