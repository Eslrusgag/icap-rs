use crate::error::IcapResult;
use crate::http::HttpSession;
use crate::icap_response::IcapResponse;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug)]
pub struct IcapClient {
    builder: IcapClientBuilder,
}

impl IcapClient {
    pub fn builder() -> IcapClientBuilder {
        IcapClientBuilder::new()
    }

    /// Send the ICAP request and return the response
    pub async fn send(&self) -> IcapResult<IcapResponse> {
        self.builder.send().await
    }

    /// Get the generated ICAP request without sending it
    pub fn get_request(&self) -> IcapResult<Vec<u8>> {
        self.builder.build_icap_request()
    }
}

impl From<IcapClientBuilder> for IcapClient {
    fn from(builder: IcapClientBuilder) -> Self {
        IcapClient { builder }
    }
}

#[derive(Default, Debug, Clone)]
pub struct IcapClientBuilder {
    pub(crate) host: String,
    pub(crate) icap_port: Option<u16>,
    service: Option<String>,
    icap_headers: Option<String>,
    http_headers: Option<String>,
    icap_method: Option<String>,
    http_session: Option<HttpSession>,
    no_preview: bool,
}

impl IcapClientBuilder {
    pub fn new() -> Self {
        IcapClientBuilder::default()
    }

    pub fn set_host(mut self, host: &str) -> Self {
        self.host = host.to_string();
        self
    }

    pub fn set_port(mut self, port: u16) -> Self {
        self.icap_port = Some(port);
        self
    }

    pub fn set_service(mut self, service: &str) -> Self {
        // Normalize service path
        let normalized_service = if service.starts_with('/') {
            service.to_string()
        } else {
            format!("/{service}")
        };
        self.service = Some(normalized_service);
        self
    }

    pub fn set_icap_headers(mut self, headers: &str) -> Self {
        self.icap_headers = Some(headers.to_string());
        self
    }

    pub fn set_icap_method(mut self, method: &str) -> Self {
        self.icap_method = Some(method.to_string());
        self
    }

    /// Set HTTP session using HttpSession struct
    pub fn with_http_session(mut self, session: HttpSession) -> Self {
        self.http_session = Some(session);
        self
    }

    /// Set no preview flag
    pub fn no_preview(mut self, no_preview: bool) -> Self {
        self.no_preview = no_preview;
        self
    }

    /// Build IcapClient from current builder
    pub fn build(self) -> IcapClient {
        IcapClient::from(self)
    }

    fn build_http_session(&self) -> Vec<u8> {
        // Use HttpSession if provided
        if let Some(ref session) = self.http_session {
            return session.to_raw();
        }

        // Fallback to headers-only approach
        let mut effective_headers = String::new();
        if let Some(ref hdrs) = self.http_headers {
            let trimmed = hdrs.trim();
            if !trimmed.is_empty() {
                effective_headers.push_str(trimmed);
                if !trimmed.ends_with("\r\n") {
                    effective_headers.push_str("\r\n");
                }
            }
        }

        // If no headers provided, return empty session
        if effective_headers.is_empty() {
            return Vec::new();
        }

        let mut session: Vec<u8> = Vec::new();
        session.extend_from_slice(effective_headers.as_bytes());

        session
    }

    pub fn build_icap_request(&self) -> IcapResult<Vec<u8>> {
        let mut request = Vec::new();

        // ICAP request line
        let method = self.icap_method.as_ref().ok_or("ICAP method not set")?;
        let service = self.service.as_ref().ok_or("Service not set")?;

        // Use full ICAP URI for REQMOD/RESPMOD requests
        let uri = if (method == "REQMOD" || method == "RESPMOD") && !service.starts_with("icap://")
        {
            let port = self.icap_port.unwrap_or(1344);
            format!("icap://{}:{}{}", self.host, port, service)
        } else {
            service.clone()
        };

        let request_line = format!("{} {} ICAP/1.0\r\n", method, uri);
        request.extend_from_slice(request_line.as_bytes());

        // ICAP headers
        let mut icap_headers = String::new();
        if let Some(ref headers) = self.icap_headers {
            icap_headers.push_str(headers);
            if !headers.ends_with("\r\n") {
                icap_headers.push_str("\r\n");
            }
        }

        // Ensure Host header is present
        if !icap_headers.contains("Host:") {
            let host_header = format!("Host: {}\r\n", self.host);
            icap_headers = host_header + &icap_headers;
        } else {
            // Replace existing Host header with correct one
            let lines: Vec<&str> = icap_headers.lines().collect();
            let mut new_headers = Vec::new();
            let mut host_replaced = false;

            for line in lines {
                if line.trim().starts_with("Host:") && !host_replaced {
                    new_headers.push(format!("Host: {}", self.host));
                    host_replaced = true;
                } else {
                    new_headers.push(line.to_string());
                }
            }

            if !host_replaced {
                new_headers.insert(0, format!("Host: {}", self.host));
            }

            icap_headers = new_headers.join("\r\n") + "\r\n";
        }

        // Add x-icap-url header for REQMOD/RESPMOD requests
        if (method == "REQMOD" || method == "RESPMOD") && !icap_headers.contains("x-icap-url:") {
            let port = self.icap_port.unwrap_or(1344);
            let icap_url = format!("icap://{}:{}{}", self.host, port, service);
            icap_headers.push_str(&format!("x-icap-url: {}\r\n", icap_url));
        }

        // Add required headers for REQMOD/RESPMOD requests
        if method == "REQMOD" || method == "RESPMOD" {
            // Only add Preview header if not already present and not explicitly disabled
            if !icap_headers.contains("Preview:") && !self.no_preview {
                icap_headers.push_str("Preview: 0\r\n");
            }
            if !icap_headers.contains("Allow:") {
                icap_headers.push_str("Allow: 204\r\n");
            }
            if !icap_headers.contains("Connection:") {
                icap_headers.push_str("Connection: close\r\n");
            }
        }

        // HTTP session (if provided)
        let http_session = self.build_http_session();

        // Add Encapsulated header for REQMOD/RESPMOD requests
        if (method == "REQMOD" || method == "RESPMOD") && !icap_headers.contains("Encapsulated:") {
            if !http_session.is_empty() {
                // Find the position where HTTP headers end (after double CRLF)
                let http_headers_end = http_session
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .unwrap_or(http_session.len());

                icap_headers.push_str("Encapsulated: req-hdr=0, req-body=");
                icap_headers.push_str(&(http_headers_end + 4).to_string());
                icap_headers.push_str("\r\n");
            } else {
                // For REQMOD/RESPMOD without HTTP session, still need Encapsulated header
                icap_headers.push_str("Encapsulated: req-hdr=0\r\n");
            }
        }

        request.extend_from_slice(icap_headers.as_bytes());

        // Add empty line after ICAP headers
        request.extend_from_slice(b"\r\n");

        // HTTP session (if provided)
        if !http_session.is_empty() {
            request.extend_from_slice(&http_session);
        }

        // End of request with proper termination
        if method == "REQMOD" || method == "RESPMOD" {
            request.extend_from_slice(b"0; ieof\r\n\r\n");
        } else {
            // For OPTIONS requests, just end with double CRLF
            request.extend_from_slice(b"\r\n");
        }

        Ok(request)
    }

    pub async fn send(&self) -> IcapResult<IcapResponse> {
        if self.host.is_empty() {
            return Err("Host not set".into());
        }
        let host = &self.host;
        let port = self.icap_port.unwrap_or(1344);
        let addr = format!("{}:{}", host, port);

        let mut stream = TcpStream::connect(&addr).await?;
        let request = self.build_icap_request()?;

        // Отправляем запрос
        stream.write_all(&request).await?;
        stream.flush().await?;

        // Читаем ответ до EOF (когда сервер закроет соединение)
        let mut response = Vec::new();
        loop {
            let mut buffer = [0; 1024];
            match stream.read(&mut buffer).await {
                Ok(0) => break, // Сервер закрыл соединение — считаем, что ответ полный
                Ok(n) => response.extend_from_slice(&buffer[..n]),
                Err(e) => return Err(format!("Failed to read response: {}", e).into()),
            }
        }

        if response.is_empty() {
            return Err("No response received from server".into());
        }

        // Парсим ICAP ответ
        crate::parser::parse_icap_response(&response)
    }
}
