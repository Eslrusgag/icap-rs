use crate::error::{Error, IcapResult};
use http::HeaderValue;

pub fn validate_istag(raw: &str) -> IcapResult<()> {
    let s = raw.trim();

    let mut val = String::new();
    let quoted = s.starts_with('"');
    if quoted {
        if !s.ends_with('"') || s.len() < 2 {
            return Err(Error::InvalidISTag("unterminated quoted ISTag".into()));
        }
        let inner = &s[1..s.len() - 1];
        let mut it = inner.chars();
        while let Some(c) = it.next() {
            if c == '\\' {
                if let Some(esc) = it.next() {
                    val.push(esc);
                } else {
                    return Err(Error::InvalidISTag(
                        "dangling escape in quoted ISTag".into(),
                    ));
                }
            } else {
                if c.is_control() {
                    return Err(Error::InvalidISTag("control char in quoted ISTag".into()));
                }
                val.push(c);
            }
        }
    } else {
        val.push_str(s);
    }

    if val.len() > 32 {
        return Err(Error::InvalidISTag(format!(
            "too long: {} bytes (max 32)",
            val.len()
        )));
    }
    if quoted {
        return Ok(());
    }

    if !val.chars().all(is_http_token_char) {
        return Err(Error::InvalidISTag(format!(
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
