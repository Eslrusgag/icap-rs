use crate::error::IcapResult;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

/// ICAP Status Codes
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IcapStatusCode {
    Continue100,
    Ok200,
    NoContent204,
    BadRequest400,
    NotFound404,
    MethodNotAllowed405,
    RequestEntityTooLarge413,
    InternalServerError500,
    ServiceUnavailable503,
    GatewayTimeout504,
}

impl fmt::Display for IcapStatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IcapStatusCode::Continue100 => write!(f, "100"),
            IcapStatusCode::Ok200 => write!(f, "200"),
            IcapStatusCode::NoContent204 => write!(f, "204"),
            IcapStatusCode::BadRequest400 => write!(f, "400"),
            IcapStatusCode::NotFound404 => write!(f, "404"),
            IcapStatusCode::MethodNotAllowed405 => write!(f, "405"),
            IcapStatusCode::RequestEntityTooLarge413 => write!(f, "413"),
            IcapStatusCode::InternalServerError500 => write!(f, "500"),
            IcapStatusCode::ServiceUnavailable503 => write!(f, "503"),
            IcapStatusCode::GatewayTimeout504 => write!(f, "504"),
        }
    }
}

impl FromStr for IcapStatusCode {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "100" => Ok(IcapStatusCode::Continue100),
            "200" => Ok(IcapStatusCode::Ok200),
            "204" => Ok(IcapStatusCode::NoContent204),
            "400" => Ok(IcapStatusCode::BadRequest400),
            "404" => Ok(IcapStatusCode::NotFound404),
            "405" => Ok(IcapStatusCode::MethodNotAllowed405),
            "413" => Ok(IcapStatusCode::RequestEntityTooLarge413),
            "500" => Ok(IcapStatusCode::InternalServerError500),
            "503" => Ok(IcapStatusCode::ServiceUnavailable503),
            "504" => Ok(IcapStatusCode::GatewayTimeout504),
            _ => Err("Invalid ICAP status code"),
        }
    }
}

/// ICAP Response structure
#[derive(Debug, Clone)]
pub struct IcapResponse {
    pub version: String,
    pub status_code: IcapStatusCode,
    pub status_text: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl IcapResponse {
    /// Create a new ICAP response
    pub fn new(status_code: IcapStatusCode, status_text: &str) -> Self {
        Self {
            version: "ICAP/1.0".to_string(),
            status_code,
            status_text: status_text.to_string(),
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }

    /// Create a new 204 No Content response
    ///
    /// This is used when the ICAP server determines that no modification
    /// is needed for the HTTP message being processed.
    pub fn no_content() -> Self {
        Self {
            version: "ICAP/1.0".to_string(),
            status_code: IcapStatusCode::NoContent204,
            status_text: "No Content".to_string(),
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }

    /// Create a new 204 No Content response with additional headers
    pub fn no_content_with_headers(headers: HashMap<String, String>) -> Self {
        Self {
            version: "ICAP/1.0".to_string(),
            status_code: IcapStatusCode::NoContent204,
            status_text: "No Content".to_string(),
            headers,
            body: Vec::new(),
        }
    }

    /// Add a header to the response
    pub fn add_header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(name.to_string(), value.to_string());
        self
    }

    /// Add multiple headers from a string
    pub fn add_headers_from_string(mut self, headers_str: &str) -> Self {
        for line in headers_str.lines() {
            if let Some(colon_pos) = line.find(':') {
                let name = line[..colon_pos].trim();
                let value = line[colon_pos + 1..].trim();
                if !name.is_empty() && !value.is_empty() {
                    self.headers.insert(name.to_string(), value.to_string());
                }
            }
        }
        self
    }

    /// Set the response body
    pub fn with_body(mut self, body: &[u8]) -> Self {
        self.body = body.to_vec();
        self
    }

    /// Set the response body from string
    pub fn with_body_string(mut self, body: &str) -> Self {
        self.body = body.as_bytes().to_vec();
        self
    }

    /// Convert response to raw bytes
    pub fn to_raw(&self) -> Vec<u8> {
        crate::parser::serialize_icap_response(self).unwrap_or_else(|_| Vec::new())
    }

    /// Parse ICAP response from raw bytes
    pub fn from_raw(raw: &[u8]) -> IcapResult<Self> {
        crate::parser::parse_icap_response(raw)
    }

    /// Get header value
    pub fn get_header(&self, name: &str) -> Option<&String> {
        self.headers.get(name)
    }

    /// Check if response has a specific header
    pub fn has_header(&self, name: &str) -> bool {
        self.headers.contains_key(name)
    }

    /// Remove a header
    pub fn remove_header(&mut self, name: &str) -> Option<String> {
        self.headers.remove(name)
    }

    /// Check if response is successful
    pub fn is_success(&self) -> bool {
        matches!(
            self.status_code,
            IcapStatusCode::Ok200 | IcapStatusCode::NoContent204
        )
    }

    /// Check if response indicates an error
    pub fn is_error(&self) -> bool {
        matches!(
            self.status_code,
            IcapStatusCode::BadRequest400
                | IcapStatusCode::NotFound404
                | IcapStatusCode::MethodNotAllowed405
                | IcapStatusCode::RequestEntityTooLarge413
                | IcapStatusCode::InternalServerError500
                | IcapStatusCode::ServiceUnavailable503
                | IcapStatusCode::GatewayTimeout504
        )
    }
}

impl Default for IcapResponse {
    fn default() -> Self {
        Self {
            version: "ICAP/1.0".to_string(),
            status_code: IcapStatusCode::Ok200,
            status_text: "OK".to_string(),
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }
}

impl fmt::Display for IcapResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.version, self.status_code, self.status_text
        )?;

        for (name, value) in &self.headers {
            write!(f, "\n{}: {}", name, value)?;
        }

        if !self.body.is_empty() {
            write!(f, "\n\n{}", String::from_utf8_lossy(&self.body))?;
        }

        Ok(())
    }
}

/// Builder for ICAP responses
#[derive(Debug)]
pub struct IcapResponseBuilder {
    response: IcapResponse,
}

impl IcapResponseBuilder {
    /// Create a new response builder
    pub fn new(status_code: IcapStatusCode, status_text: &str) -> Self {
        Self {
            response: IcapResponse::new(status_code, status_text),
        }
    }

    /// Add a header
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.response = self.response.add_header(name, value);
        self
    }

    /// Add multiple headers from string
    pub fn headers_from_string(mut self, headers_str: &str) -> Self {
        self.response = self.response.add_headers_from_string(headers_str);
        self
    }

    /// Set the body
    pub fn body(mut self, body: &[u8]) -> Self {
        self.response = self.response.with_body(body);
        self
    }

    /// Set the body from string
    pub fn body_string(mut self, body: &str) -> Self {
        self.response = self.response.with_body_string(body);
        self
    }

    /// Build the final response
    pub fn build(self) -> IcapResponse {
        self.response
    }
}
