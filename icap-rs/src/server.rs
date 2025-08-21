//! ICAP server (work in progress).
//!
//! Minimal ICAP server with per-service handlers. It:
//! - Accepts OPTIONS / REQMOD / RESPMOD;
//! - Lets you register handlers by service name;
//! - Crucially: reads encapsulated *chunked* bodies to completion before parsing,
//!   so clients (e.g. c-icap-client) don't see "connection terminated" mid-upload.
//!
//! Status: experimental; APIs may change.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::str;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{error, trace, warn};

use crate::error::IcapResult;
use crate::{
    IcapMethod, OptionsConfig, Request, Response, StatusCode, parse_icap_request,
    serialize_icap_response,
};

/// Per-service ICAP handler.
pub type RequestHandler = Box<
    dyn Fn(
            Request,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = IcapResult<Response>> + Send + Sync>,
        > + Send
        + Sync,
>;

/// ICAP server (minimal).
pub struct Server {
    listener: TcpListener,
    services: Arc<RwLock<HashMap<String, RequestHandler>>>,
    options_configs: Arc<RwLock<HashMap<String, OptionsConfig>>>,
}

impl Server {
    /// New builder.
    pub fn builder() -> ServerBuilder {
        ServerBuilder::new()
    }

    /// Main accept loop.
    pub async fn run(self) -> IcapResult<()> {
        let local_addr = self.listener.local_addr()?;
        trace!("ICAP server started on {}", local_addr);

        loop {
            let (socket, addr) = self.listener.accept().await?;
            trace!("New connection from {}", addr);

            let services = Arc::clone(&self.services);
            let options_configs = Arc::clone(&self.options_configs);
            tokio::spawn(async move {
                if let Err(e) =
                    Self::handle_connection(socket, addr, services, options_configs).await
                {
                    error!("Error handling connection {}: {}", addr, e);
                }
            });
        }
    }

    /// Handle a single client connection (persistent / keep-alive).
    ///
    /// We can receive multiple ICAP messages over the same TCP connection:
    ///  - Read one full ICAP message (headers + encapsulated body if any),
    ///  - Parse and dispatch it,
    ///  - Send the ICAP response,
    ///  - Repeat until the peer closes or a fatal error occurs.
    ///
    /// Message boundary rules:
    ///  - ICAP headers end at CRLFCRLF;
    ///  - If `Encapsulated` contains `req-body`/`res-body`, the body that follows
    ///    is ICAP-chunked; we must drain it to the terminating zero chunk
    ///    (`0[;ext]\r\n\r\n`) to know where the message ends;
    ///  - If there is no body, the ICAP message ends at the ICAP headers CRLFCRLF.
    async fn handle_connection(
        mut socket: TcpStream,
        addr: SocketAddr,
        services: Arc<RwLock<HashMap<String, RequestHandler>>>,
        options_configs: Arc<RwLock<HashMap<String, OptionsConfig>>>,
    ) -> IcapResult<()> {
        let mut buf: Vec<u8> = Vec::with_capacity(16 * 1024);
        let mut tmp = [0u8; 8192];

        loop {
            // Ensure we have at least ICAP headers (up to CRLFCRLF).
            let h_end = loop {
                if let Some(end) = headers_end(&buf) {
                    break end;
                }
                let n = socket.read(&mut tmp).await?;
                if n == 0 {
                    // Peer closed; if nothing buffered, just exit.
                    if buf.is_empty() {
                        return Ok(());
                    } else {
                        return Err("EOF before complete ICAP headers".into());
                    }
                }
                buf.extend_from_slice(&tmp[..n]);
            };

            // Parse Encapsulated from the headers block.
            let hdr_text =
                std::str::from_utf8(&buf[..h_end]).map_err(|_| "Invalid ICAP headers utf8")?;
            let enc = crate::parser::parse_encapsulated_header(hdr_text);

            // Compute the end of this ICAP message in `buf`.
            // Start with the headers-only case; extend if there is a chunked body.
            let mut msg_end = h_end;

            if let Some(body_rel) = enc.req_body.or(enc.res_body) {
                // Absolute position where ICAP chunked body starts (immediately after embedded HTTP headers).
                let body_abs = h_end + body_rel;

                // Make sure we have reached at least the beginning of the chunk stream.
                while buf.len() < body_abs {
                    let n = socket.read(&mut tmp).await?;
                    if n == 0 {
                        return Err("Unexpected EOF before start of ICAP body".into());
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }

                // Drain the whole ICAP-chunked body to the terminating zero chunk.
                // The function returns absolute offset right *after* the final CRLF.
                msg_end = read_chunked_to_end(&mut socket, &mut buf, body_abs).await?;
            }

            // We now have one full ICAP message in buf[..msg_end].
            let req = parse_icap_request(&buf[..msg_end])?;
            trace!("Received {} to service '{}'", req.method, req.service);

            // Determine service name (last segment).
            let service_name = req
                .service
                .rsplit('/')
                .next()
                .unwrap_or(&req.service)
                .to_string();

            // Dispatch: OPTIONS or service handler.
            let resp = if req.method.eq_ignore_ascii_case("OPTIONS") {
                let options_guard = options_configs.read().await;
                if let Some(cfg) = options_guard.get(&service_name) {
                    cfg.build_response()
                } else {
                    warn!(
                        "OPTIONS config for '{}' not found, using default",
                        service_name
                    );
                    Self::build_default_options_response(&service_name)
                }
            } else {
                let services_guard = services.read().await;
                if let Some(handler) = services_guard.get(&service_name) {
                    handler(req).await?
                } else {
                    warn!("Service '{}' not found", service_name);
                    Response::new(StatusCode::NotFound404, "Service Not Found")
                        .add_header("Content-Length", "0")
                }
            };

            // Send ICAP response. (ICAP connections are persistent by default.)
            let bytes = serialize_icap_response(&resp)?;
            socket.write_all(&bytes).await?;
            socket.flush().await?;
            trace!("Response sent for service: {}", service_name);

            // Remove the processed ICAP message from the buffer.
            buf.drain(..msg_end);

            // If there's already pipelined data for the next request in `buf`,
            // the loop will parse it immediately in the next iteration.
            // Otherwise we'll read more from the socket above.
        }
    }

    /// Default OPTIONS response for services without an explicit config.
    fn build_default_options_response(service_name: &str) -> Response {
        let cfg = OptionsConfig::new(
            vec![IcapMethod::RespMod],
            &format!("{}-default-1.0", service_name),
        )
        .with_service(&format!("Default ICAP Service for {}", service_name))
        .with_max_connections(100)
        .with_options_ttl(3600)
        .add_allow("204");
        cfg.build_response()
    }
}

/// Builder for [`Server`].
pub struct ServerBuilder {
    bind_addr: Option<String>,
    services: HashMap<String, RequestHandler>,
    options_configs: HashMap<String, OptionsConfig>,
}

impl ServerBuilder {
    pub fn new() -> Self {
        Self {
            bind_addr: None,
            services: HashMap::new(),
            options_configs: HashMap::new(),
        }
    }

    pub fn bind(mut self, addr: &str) -> Self {
        self.bind_addr = Some(addr.to_string());
        self
    }

    pub fn add_service<F, Fut>(mut self, name: &str, handler: F) -> Self
    where
        F: Fn(Request) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = IcapResult<Response>> + Send + Sync + 'static,
    {
        let h: RequestHandler = Box::new(move |req| Box::pin(handler(req)));
        self.services.insert(name.to_string(), h);
        self
    }

    pub fn add_options_config(mut self, name: &str, config: OptionsConfig) -> Self {
        self.options_configs.insert(name.to_string(), config);
        self
    }

    pub async fn build(self) -> IcapResult<Server> {
        let bind_addr = self
            .bind_addr
            .unwrap_or_else(|| "127.0.0.1:1344".to_string());
        let listener = TcpListener::bind(&bind_addr).await?;
        Ok(Server {
            listener,
            services: Arc::new(RwLock::new(self.services)),
            options_configs: Arc::new(RwLock::new(self.options_configs)),
        })
    }
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Find the end of the ICAP header block.
fn headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Parse a single ICAP chunk at `from`.
/// Returns (next_pos, is_final_zero_chunk, chunk_size).
fn parse_one_chunk(buf: &[u8], from: usize) -> Option<(usize, bool, usize)> {
    let mut i = from;
    while i + 1 < buf.len() {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' {
            // size line: "<hex>[;ext]\r\n"
            let size_line = &buf[from..i];
            let size_hex = size_line.split(|&b| b == b';').next().unwrap_or(size_line);
            let size_str = std::str::from_utf8(size_hex).ok()?.trim();
            let size = usize::from_str_radix(size_str, 16).ok()?;
            let after_size = i + 2;
            let need = after_size + size + 2; // +CRLF after chunk data
            if buf.len() < need {
                return None;
            }
            if size == 0 {
                // zero chunk; trailing CRLF for (empty) trailers must follow
                if buf.len() < after_size + 2 {
                    return None;
                }
                return Some((after_size, true, 0));
            }
            return Some((need, false, size));
        }
        i += 1;
    }
    None
}

/// Read an ICAP chunked body to the terminating zero chunk and return
/// the absolute offset in `buf` **right after** the final CRLF.
/// `pos` must point to the first byte of the first chunk-size line.
async fn read_chunked_to_end(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    mut pos: usize,
) -> IcapResult<usize> {
    loop {
        match parse_one_chunk(buf, pos) {
            Some((next_pos, is_final_zero, _size)) => {
                if is_final_zero {
                    // After size line CRLF of the zero-chunk.
                    pos = next_pos;
                    // Ensure we have the trailing CRLF for (empty) trailers.
                    while buf.len() < pos + 2 {
                        let mut tmp = [0u8; 4096];
                        let n = stream.read(&mut tmp).await?;
                        if n == 0 {
                            return Err("Unexpected EOF after zero chunk".into());
                        }
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    if &buf[pos..pos + 2] != b"\r\n" {
                        return Err("Invalid ICAP chunked terminator".into());
                    }
                    // Return absolute end-of-message offset.
                    return Ok(pos + 2);
                } else {
                    pos = next_pos;
                }
            }
            None => {
                let mut tmp = [0u8; 4096];
                let n = stream.read(&mut tmp).await?;
                if n == 0 {
                    return Err("Unexpected EOF while reading ICAP chunked body".into());
                }
                buf.extend_from_slice(&tmp[..n]);
            }
        }
    }
}
