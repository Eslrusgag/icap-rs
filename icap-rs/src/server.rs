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
use std::str;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, Semaphore};
use tracing::{error, trace, warn};

use crate::error::IcapResult;
use crate::parser::{find_double_crlf, read_chunked_to_end, serialize_icap_response};
use crate::request::parse_icap_request;
use crate::{IcapMethod, OptionsConfig, Request, Response, StatusCode};

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
    conn_limit: Option<Arc<Semaphore>>,
    advertised_max_conn: Option<u32>,
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
            let (mut socket, addr) = self.listener.accept().await?;
            trace!("New connection from {}", addr);

            let maybe_permit = if let Some(sem) = &self.conn_limit {
                match sem.clone().try_acquire_owned() {
                    Ok(p) => Some(p),
                    Err(_) => {
                        warn!(
                            "Refusing connection from {}: too many concurrent connections",
                            addr
                        );

                        let resp =
                            Response::new(StatusCode::ServiceUnavailable503, "Service Unavailable")
                                .add_header("Encapsulated", "null-body=0")
                                .add_header("Content-Length", "0");

                        if let Ok(bytes) = serialize_icap_response(&resp) {
                            if let Err(e) = socket.write_all(&bytes).await {
                                warn!("Failed to send 503 to {}: {}", addr, e);
                            }
                            // по желанию: явное закрытие полудуплекса записи
                            let _ = socket.shutdown().await;
                        }

                        continue; // не спавним таск, соединение закрыто
                    }
                }
            } else {
                None
            };

            let services = Arc::clone(&self.services);
            let options_configs = Arc::clone(&self.options_configs);
            let advertised_max = self.advertised_max_conn;
            tokio::spawn(async move {
                let _permit = maybe_permit;
                if let Err(e) =
                    Self::handle_connection(socket, services, options_configs, advertised_max).await
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
        services: Arc<RwLock<HashMap<String, RequestHandler>>>,
        options_configs: Arc<RwLock<HashMap<String, OptionsConfig>>>,
        advertised_max_conn: Option<u32>,
    ) -> IcapResult<()> {
        let mut buf: Vec<u8> = Vec::with_capacity(16 * 1024);
        let mut tmp = [0u8; 8192];

        loop {
            let h_end = loop {
                if let Some(end) = find_double_crlf(&buf) {
                    break end;
                }
                let n = socket.read(&mut tmp).await?;
                if n == 0 {
                    return if buf.is_empty() {
                        Ok(())
                    } else {
                        Err("EOF before complete ICAP headers".into())
                    };
                }
                buf.extend_from_slice(&tmp[..n]);
            };

            let hdr_text =
                std::str::from_utf8(&buf[..h_end]).map_err(|_| "Invalid ICAP headers utf8")?;
            let enc = crate::parser::parse_encapsulated_header(hdr_text);
            let mut msg_end = h_end;

            if let Some(body_rel) = enc.req_body.or(enc.res_body) {
                let body_abs = h_end + body_rel;
                while buf.len() < body_abs {
                    let n = socket.read(&mut tmp).await?;
                    if n == 0 {
                        return Err("Unexpected EOF before start of ICAP body".into());
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                msg_end = read_chunked_to_end(&mut socket, &mut buf, body_abs).await?;
            }

            let req = parse_icap_request(&buf[..msg_end])?;
            trace!("Received {} to service '{}'", req.method, req.service);

            let service_name = req
                .service
                .rsplit('/')
                .next()
                .unwrap_or(&req.service)
                .to_string();

            let resp = if req.method.eq_ignore_ascii_case("OPTIONS") {
                let options_guard = options_configs.read().await;
                if let Some(cfg) = options_guard.get(&service_name) {
                    let mut c = cfg.clone();
                    if let (Some(n), None) = (advertised_max_conn, c.max_connections) {
                        c.with_max_connections(n);
                    }
                    c.build_response()
                } else {
                    warn!(
                        "OPTIONS config for '{}' not found, using default",
                        service_name
                    );
                    Self::build_default_options_response(&service_name, advertised_max_conn)
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

            let bytes = serialize_icap_response(&resp)?;
            socket.write_all(&bytes).await?;
            socket.flush().await?;
            trace!("Response sent for service: {}", service_name);

            buf.drain(..msg_end);
        }
    }

    /// Default OPTIONS response for services without an explicit config.
    fn build_default_options_response(service_name: &str, advertised_max: Option<u32>) -> Response {
        let mut cfg = OptionsConfig::new(
            vec![IcapMethod::RespMod],
            &format!("{}-default-1.0", service_name),
        )
        .with_service(&format!("Default ICAP Service for {}", service_name))
        .with_options_ttl(3600)
        .add_allow("204");

        if let Some(n) = advertised_max {
            cfg.with_max_connections(n);
        }

        cfg.build_response()
    }
}

/// Builder for [`Server`].
pub struct ServerBuilder {
    bind_addr: Option<String>,
    services: HashMap<String, RequestHandler>,
    options_configs: HashMap<String, OptionsConfig>,
    max_connections_global: Option<usize>,
}

impl ServerBuilder {
    pub fn new() -> Self {
        Self {
            bind_addr: None,
            services: HashMap::new(),
            options_configs: HashMap::new(),
            max_connections_global: None,
        }
    }

    pub fn bind(mut self, addr: &str) -> Self {
        self.bind_addr = Some(addr.to_string());
        self
    }

    pub fn with_max_connections(mut self, n: usize) -> Self {
        self.max_connections_global = Some(n.max(1));
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

        let conn_limit = self
            .max_connections_global
            .map(|n| Arc::new(Semaphore::new(n)));
        let advertised_max_conn = self.max_connections_global.map(|n| n as u32);

        Ok(Server {
            listener,
            services: Arc::new(RwLock::new(self.services)),
            options_configs: Arc::new(RwLock::new(self.options_configs)),
            conn_limit,
            advertised_max_conn,
        })
    }
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}
