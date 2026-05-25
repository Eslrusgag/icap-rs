use crate::error::{Error, IcapResult};

/// Offsets parsed from the `Encapsulated` header.
///
/// Offsets are **relative to the start of the encapsulated area**
/// (i.e., immediately after the ICAP headers CRLFCRLF).
#[derive(Debug, Clone, Copy, Default)]
pub struct Encapsulated {
    pub req_hdr: Option<usize>,
    pub res_hdr: Option<usize>,
    pub req_body: Option<usize>,
    pub res_body: Option<usize>,
    pub opt_body: Option<usize>,
    pub null_body: Option<usize>,
}

/// Parse only the value of the `Encapsulated:` header.
pub fn parse_encapsulated_value(val: &str) -> IcapResult<Encapsulated> {
    if val.trim().is_empty() {
        return Err(Error::missing_header("Encapsulated"));
    }

    let mut enc = Encapsulated::default();
    let mut offsets: Vec<usize> = Vec::new();

    for part in val.split(',') {
        let p = part.trim();
        let (name_raw, off_raw) = p
            .split_once('=')
            .ok_or_else(|| Error::header(format!("invalid Encapsulated token: {p}")))?;

        let name = name_raw.trim().to_ascii_lowercase();
        let off: usize = off_raw
            .trim()
            .parse()
            .map_err(|_| Error::header(format!("invalid Encapsulated offset: {off_raw}")))?;

        let slot = match name.as_str() {
            "req-hdr" => &mut enc.req_hdr,
            "res-hdr" => &mut enc.res_hdr,
            "req-body" => &mut enc.req_body,
            "res-body" => &mut enc.res_body,
            "opt-body" => &mut enc.opt_body,
            "null-body" => &mut enc.null_body,
            _ => {
                return Err(Error::header(format!(
                    "invalid Encapsulated part name: {}",
                    name_raw.trim()
                )));
            }
        };

        if slot.replace(off).is_some() {
            return Err(Error::header(format!(
                "duplicate Encapsulated part name: {}",
                name_raw.trim()
            )));
        }
        offsets.push(off);
    }

    for w in offsets.windows(2) {
        if w[1] < w[0] {
            return Err(Error::header(format!(
                "Encapsulated offsets not monotonic: {} -> {}",
                w[0], w[1]
            )));
        }
    }

    Ok(enc)
}

/// Parse the `Encapsulated:` header from raw headers text.
pub fn parse_encapsulated_header(headers_text: &str) -> IcapResult<Encapsulated> {
    for line in headers_text.lines() {
        let Some((name, val)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("Encapsulated") {
            continue;
        }
        return parse_encapsulated_value(val);
    }
    Ok(Encapsulated::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_encapsulated_value_variants() {
        let e = parse_encapsulated_value("req-hdr=0, req-body=123").expect("parse");
        assert_eq!(e.req_hdr, Some(0));
        assert_eq!(e.req_body, Some(123));

        let e2 = parse_encapsulated_value("res-hdr=0,res-body=42").expect("parse");
        assert_eq!(e2.res_hdr, Some(0));
        assert_eq!(e2.res_body, Some(42));
    }

    #[test]
    fn parse_encapsulated_value_rejects_invalid_tokens() {
        let err = parse_encapsulated_value("req-hdr=0, bad=10").unwrap_err();
        assert!(err.to_string().to_lowercase().contains("encapsulated"));
    }

    #[test]
    fn parse_encapsulated_value_rejects_non_monotonic_offsets() {
        let err = parse_encapsulated_value("req-hdr=10, req-body=5").unwrap_err();
        assert!(err.to_string().to_lowercase().contains("offset"));
    }
}
